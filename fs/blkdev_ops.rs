//! Block device files (Linux block/fops.c, block/ioctl.c)
//!
//! Reads and writes go through the device's page cache: the page cache
//! of its inode in the bdev pseudo filesystem (`BlockDevice.bd_inode`,
//! Linux bd_mapping), in buffer heads of the soft block size
//! (`BdevAops`, Linux def_blk_aops), shared with filesystems' metadata
//! on the device (vfat), written back by fsync, sync, BLKFLSBUF and the
//! last close, which also drops it (Linux blkdev_flush_mapping). mmap
//! maps it.
//! O_DIRECT I/O from user memory bypasses it (`block::dio`): the range
//! is written back first, and for a write dropped before and after;
//! what the bios could not take goes through the cache. Buffered reads
//! and writes hold the bdev inode's i_rwsem shared, which
//! `set_blocksize` takes for writing (Linux blkdev_read_iter,
//! blkdev_write_iter); direct I/O takes none.
//! The open file holds its block device (`File.private`, a `BdevFile`),
//! counted as an opener (BLKRRPART, BLKBSZGET's initial value), and
//! with O_EXCL claimed for its exclusive use (Linux blkdev_open: holder
//! the file; EBUSY while a mounted filesystem, active swap or another
//! O_EXCL file has it). BLKBSZSET needs such a claim: the file's own,
//! else one it takes for the call (Linux blkdev_bszset).

use alloc::sync::Arc;

use crate::block::DevId;
use crate::block::blkdev::{
    BlockDevice, HdGeometry, SECTOR_SHIFT, blkdev_issue_flush, get_blkdev, invalidate_bdev,
    set_blocksize, sync_blockdev,
};
use crate::block::claim::Holder;
use crate::block::genhd;
use crate::fs::inode::{Inode, InodeMode, InodeRef, Timespec};
use crate::mm::filemap::{self, Aops, PAGE_SIZE};
use crate::uaccess::{copy_to_user, get_user, put_user};
use crate::util::error::KernelError;

use super::buffer::{self, BufferHead};
use super::file::{File, FileOps, RwFlags, generic_write_sync, seek};
use super::iov_iter::{IovDest, IovSource};
use crate::block::dio;

/// Block device ioctls (Linux include/uapi/linux/fs.h, hdreg.h)
pub mod ioc {
    pub const HDIO_GETGEO: u32 = 0x0301;
    pub const BLKROSET: u32 = 0x125d;
    pub const BLKROGET: u32 = 0x125e;
    pub const BLKRRPART: u32 = 0x125f;
    pub const BLKGETSIZE: u32 = 0x1260;
    pub const BLKFLSBUF: u32 = 0x1261;
    pub const BLKSECTGET: u32 = 0x1267;
    pub const BLKSSZGET: u32 = 0x1268;
    pub const BLKBSZGET: u32 = 0x8008_1270;
    pub const BLKBSZSET: u32 = 0x4008_1271;
    pub const BLKGETSIZE64: u32 = 0x8008_1272;
    pub const BLKIOMIN: u32 = 0x1278;
    pub const BLKIOOPT: u32 = 0x1279;
    pub const BLKALIGNOFF: u32 = 0x127a;
    pub const BLKPBSZGET: u32 = 0x127b;
}

/// Block device file operations
pub struct BlockFileOps;

/// Static block file ops instance
pub static BLOCK_FILE_OPS: BlockFileOps = BlockFileOps;

/// An open block device file's state (Linux the file's bdev and its
/// private_data holder)
pub struct BdevFile {
    pub bdev: Arc<BlockDevice>,
    /// Opened O_EXCL: claimed, its holder this state's address
    excl: bool,
}

impl BdevFile {
    /// Its claim's holder, if opened O_EXCL
    fn holder(&self) -> Option<Holder> {
        self.excl.then(|| core::ptr::from_ref(self) as usize)
    }
}

fn bdev_file(file: &File) -> Result<&BdevFile, KernelError> {
    file.private_ref::<BdevFile>()
        .ok_or(KernelError::NoDeviceOrAddress)
}

fn bdev(file: &File) -> Result<Arc<BlockDevice>, KernelError> {
    bdev_file(file).map(|f| f.bdev.clone())
}

/// Read at `pos` through the cache: short at the end, 0 past it (Linux
/// blkdev_read_iter); with RWF_NOWAIT only what is cached already
fn read_at(
    file: &File,
    to: &mut IovDest<'_>,
    pos: u64,
    nowait: bool,
) -> Result<usize, KernelError> {
    let b = bdev(file)?;
    let size = b.capacity();
    if pos >= size || to.is_empty() {
        return Ok(0);
    }
    to.truncate((size - pos).min(usize::MAX as u64) as usize);
    cache_read(&b, to, pos, nowait)
}

/// Linux filemap_read, with IOCB_NOWAIT for `nowait`, under the bdev
/// inode's i_rwsem shared (Linux blkdev_read_iter: no `set_blocksize`
/// meanwhile)
fn cache_read(
    b: &BlockDevice,
    to: &mut IovDest<'_>,
    pos: u64,
    nowait: bool,
) -> Result<usize, KernelError> {
    let _g = b.bd_inode.lock_shared();
    if nowait {
        filemap::read_iter_nowait(&b.bd_inode, to, pos)
    } else {
        filemap::read_iter(&b.bd_inode, to, pos)
    }
}

/// O_DIRECT read at `pos` (Linux blkdev_read_iter with IOCB_DIRECT): the
/// cache over the range written back first, then bios into the caller's
/// pinned pages (`dio::direct_io`); what they could not take (a buffer
/// that could not be pinned to its end) is read through the cache.
/// RWF_NOWAIT: EAGAIN where that would wait.
fn dio_read(
    file: &File,
    to: &mut IovDest<'_>,
    pos: u64,
    flags: RwFlags,
) -> Result<usize, KernelError> {
    let b = bdev(file)?;
    let size = b.capacity();
    if pos >= size {
        return Ok(0);
    }
    to.truncate((size - pos).min(usize::MAX as u64) as usize);
    let count = to.len();
    if count == 0 {
        return Ok(0);
    }
    write_and_wait(&b, pos, count, flags.nowait())?;
    let n = dio::direct_io(&b, to, pos, flags)?;
    if n == count {
        return Ok(n);
    }
    match cache_read(&b, to, pos + n as u64, flags.nowait()) {
        Ok(m) => Ok(n + m),
        Err(e) if n == 0 => Err(e),
        Err(_) => Ok(n),
    }
}

/// O_DIRECT I/O of `io`'s pinned memory at `pos`, started without
/// waiting (Linux blkdev_read_iter / blkdev_write_iter with an async
/// IOCB_DIRECT kiocb: blkdev_direct_IO -> -EIOCBQUEUED): the checks of
/// a read (0 at or past the end) or write (`write_ok`), cut at the end
/// of the device, the cache over the range written back (a write: and
/// dropped) first, then the bios (`dio::submit_async`). RWF_NOWAIT:
/// EAGAIN where that would wait. A write whose range cannot be dropped
/// from the cache goes through it at once (`cache_fallback`)
fn dio_submit_async(
    file: &File,
    io: Arc<dyn dio::AsyncIo>,
    pos: u64,
    write: bool,
    flags: RwFlags,
) -> Result<Option<usize>, KernelError> {
    nowait_ok(file, flags)?;
    let len: usize = io.segs().iter().map(|s| s.len as usize).sum();
    let b = bdev(file)?;
    if write {
        if !write_ok(file, len, pos)? {
            return Ok(Some(0));
        }
    } else if pos >= b.capacity() || len == 0 {
        return Ok(Some(0));
    }
    let count = len.min((b.capacity() - pos).min(usize::MAX as u64) as usize);
    if write {
        match invalidate_pages(&b, pos, count, flags.nowait()) {
            Err(KernelError::Busy) => {
                return cache_fallback(file, &b, &*io, pos, count, flags).map(Some);
            }
            r => r?,
        }
    } else {
        write_and_wait(&b, pos, count, flags.nowait())?;
    }
    dio::submit_async(&b, io, pos, count, write, flags).map(|()| None)
}

/// An asynchronous O_DIRECT write of `count` bytes of `io`'s memory at
/// `pos` whose range could not be dropped from the cache, done now
/// through it, written back and dropped (Linux blkdev_direct_write
/// returns 0 on EBUSY, and blkdev_write_iter's direct_write_fallback
/// does the whole write buffered; then generic_write_sync): the bytes
fn cache_fallback(
    file: &File,
    b: &BlockDevice,
    io: &dyn dio::AsyncIo,
    pos: u64,
    count: usize,
    flags: RwFlags,
) -> Result<usize, KernelError> {
    let mut from = IovSource::async_io(io);
    from.truncate(count);
    let n = write_fallback(b, &mut from, pos, 0, flags.nowait())?;
    generic_write_sync(file, pos, n, flags)
}

/// Last byte of `count` (> 0) bytes at `pos`
fn last(pos: u64, count: usize) -> u64 {
    pos + count as u64 - 1
}

/// Write back the cached pages over the `count` bytes at `pos` before
/// direct I/O there (Linux kiocb_write_and_wait); RWF_NOWAIT: EAGAIN if
/// that needs I/O
fn write_and_wait(
    b: &BlockDevice,
    pos: u64,
    count: usize,
    nowait: bool,
) -> Result<(), KernelError> {
    let end = last(pos, count);
    if !nowait {
        return filemap::write_and_wait_range(&b.bd_inode, pos, end);
    }
    if filemap::range_needs_writeback(&b.bd_inode.i_data, pos, end) {
        return Err(KernelError::WouldBlock);
    }
    Ok(())
}

/// Write back and drop the cached pages over the `count` bytes at `pos`
/// before a direct write there (Linux kiocb_invalidate_pages); RWF_NOWAIT:
/// EAGAIN if a page is cached. EBUSY if one could not be dropped.
fn invalidate_pages(
    b: &BlockDevice,
    pos: u64,
    count: usize,
    nowait: bool,
) -> Result<(), KernelError> {
    let end = last(pos, count);
    if nowait {
        if filemap::range_has_page(&b.bd_inode.i_data, pos, end) {
            return Err(KernelError::WouldBlock);
        }
    } else {
        filemap::write_and_wait_range(&b.bd_inode, pos, end)?;
    }
    let p = PAGE_SIZE as u64;
    filemap::invalidate_pages2(&b.bd_inode, pos / p, end / p)
}

/// Drop what a read cached over the range during a direct write (Linux
/// kiocb_invalidate_post_direct_write): a page left is not the write's
/// error but the mapping's (`filemap::dio_warn_stale_pagecache`)
fn invalidate_post(b: &BlockDevice, pos: u64, count: usize) {
    let p = PAGE_SIZE as u64;
    if b.bd_inode.i_data.nrpages() != 0
        && filemap::invalidate_pages2(&b.bd_inode, pos / p, last(pos, count) / p).is_err()
    {
        filemap::dio_warn_stale_pagecache(&b.bd_inode);
    }
}

/// The direct part of an O_DIRECT write (Linux blkdev_direct_write): the
/// range dropped from the cache first (a page that cannot be: 0 bytes,
/// all left to the cache), the bios, the range dropped again
fn direct_write(
    b: &BlockDevice,
    from: &mut IovSource<'_>,
    pos: u64,
    flags: RwFlags,
) -> Result<usize, KernelError> {
    let count = from.len();
    match invalidate_pages(b, pos, count, flags.nowait()) {
        Err(KernelError::Busy) => return Ok(0),
        r => r?,
    }
    let n = dio::direct_io(b, from, pos, flags)?;
    if n > 0 {
        invalidate_post(b, pos, count);
    }
    Ok(n)
}

/// The rest of an O_DIRECT write after `direct` bytes, through the cache,
/// then written back and dropped so it still bypasses it (Linux
/// direct_write_fallback over blkdev_buffered_write): all the bytes, or
/// the direct ones if this part failed (its error if there were none)
fn write_fallback(
    b: &BlockDevice,
    from: &mut IovSource<'_>,
    pos: u64,
    direct: usize,
    nowait: bool,
) -> Result<usize, KernelError> {
    let short = |e| if direct > 0 { Ok(direct) } else { Err(e) };
    let at = pos + direct as u64;
    // RWF_NOWAIT holds for the buffered part too (Linux
    // blkdev_buffered_write: IOCB_NOWAIT)
    let r = if nowait {
        filemap::write_iter_nowait(&b.bd_inode, from, at)
    } else {
        filemap::write_iter(&b.bd_inode, from, at)
    };
    let n = match r {
        Ok(0) => return Ok(direct),
        Ok(n) => n,
        Err(e) => return short(e),
    };
    let end = last(at, n);
    if let Err(e) = filemap::write_and_wait_range(&b.bd_inode, at, end) {
        return short(e);
    }
    let p = PAGE_SIZE as u64;
    filemap::invalidate_clean(&b.bd_inode, at / p, end / p);
    Ok(direct + n)
}

/// O_DIRECT write at `pos` (Linux blkdev_write_iter with IOCB_DIRECT):
/// bios from the caller's pinned pages, the rest through the cache
fn dio_write(
    file: &File,
    from: &mut IovSource<'_>,
    pos: u64,
    flags: RwFlags,
) -> Result<usize, KernelError> {
    let b = bdev(file)?;
    let n = direct_write(&b, from, pos, flags)?;
    if from.is_empty() {
        return Ok(n);
    }
    write_fallback(&b, from, pos, n, flags.nowait())
}

/// The checks of a write of `len` bytes at `pos` (Linux
/// blkdev_write_iter): EPERM if read-only, ETXTBSY for an active swap
/// partition, then false (nothing to do) for no bytes, ENOSPC at or past
/// the end
fn write_ok(file: &File, len: usize, pos: u64) -> Result<bool, KernelError> {
    let b = bdev(file)?;
    if b.ro() {
        return Err(KernelError::NotPermitted);
    }
    // An active swap partition (Linux blkdev_write_iter: IS_SWAPFILE)
    if b.bd_inode.is_swapfile() {
        return Err(KernelError::TextBusy);
    }
    if len == 0 {
        return Ok(false);
    }
    if pos >= b.capacity() {
        return Err(KernelError::NoSpace);
    }
    Ok(true)
}

/// A block device's cache in buffer heads (Linux def_blk_aops with
/// CONFIG_BUFFER_HEAD): pages read and written block by block, the
/// device's soft block size each (`fs::buffer`), so writeback writes
/// only the dirty buffers: a filesystem's metadata buffers (vfat) dirty
/// just their blocks of a page that may also hold its file data
struct BdevAops;

/// The bdev inode's device: its own, never another one registered
/// under the same number later; EIO once it is removed
pub(crate) fn inode_bdev(inode: &Inode) -> Result<Arc<BlockDevice>, KernelError> {
    let b = inode_owner(inode).ok_or(KernelError::Io)?;
    if b.is_dead() {
        return Err(KernelError::Io);
    }
    Ok(b)
}

/// The block device whose inode `inode` is (Linux I_BDEV), removed or
/// not; None for another inode or one whose device is gone
pub(crate) fn inode_owner(inode: &Inode) -> Option<Arc<BlockDevice>> {
    let p = inode.get_private()?;
    p.as_any()
        .downcast_ref::<BdevOwner>()
        .and_then(|o| o.0.upgrade())
}

/// A bdev inode's back reference to its device (set at registration)
pub struct BdevOwner(pub alloc::sync::Weak<BlockDevice>);

impl crate::fs::inode::InodeData for BdevOwner {}

impl crate::fs::inode::AsAny for BdevOwner {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

/// Block `iblock` of the device is its own block (Linux
/// blkdev_get_block)
fn blkdev_get_block(
    inode: &Inode,
    iblock: u64,
    bh: &BufferHead,
    _create: bool,
) -> Result<(), KernelError> {
    let b = inode_bdev(inode)?;
    bh.set_bdev(&b);
    bh.set_blocknr(iblock);
    bh.set_mapped();
    Ok(())
}

impl Aops for BdevAops {
    /// Linux block_dirty_folio
    fn dirty_folio(&self, m: &filemap::AddressSpace, phys: u64) {
        buffer::block_dirty_folio(m, phys);
    }

    /// Linux blkdev_read_folio: block_read_full_folio, which unlocks the
    /// page when the read ends; hk's ->read_folio returns it locked, so
    /// it is locked again once the read has ended. The device is held
    /// meanwhile.
    fn read_folio(&self, inode: &Inode, phys: u64, _index: u64) -> Result<(), KernelError> {
        let _b = inode_bdev(inode)?;
        buffer::block_read_full_folio(inode, phys, blkdev_get_block);
        crate::mm::page::lock_page(phys);
        if filemap::uptodate(phys) {
            Ok(())
        } else {
            Err(KernelError::Io)
        }
    }

    /// Linux blkdev_writepages: block_write_full_folio, the dirty
    /// buffers only
    fn writepage(&self, inode: &Inode, phys: u64, _index: u64) -> Result<(), KernelError> {
        let _b = inode_bdev(inode)?;
        buffer::block_write_full_folio(inode, phys, blkdev_get_block)
    }

    /// Linux blkdev_buffered_write's iomap_write_begin with
    /// IOMAP_F_BUFFER_HEAD: the blocks the write covers in part read in
    fn write_begin(&self, inode: &Inode, pos: u64, len: usize) -> Result<u64, KernelError> {
        buffer::block_write_begin(inode, pos, len, blkdev_get_block)
    }

    /// Linux iomap_write_end with IOMAP_F_BUFFER_HEAD: block_write_end,
    /// the written buffers dirty (a short copy into a page not uptodate
    /// takes nothing); the device's size is fixed
    fn write_end(&self, _inode: &Inode, pos: u64, len: usize, copied: usize, phys: u64) -> usize {
        let n = buffer::block_write_end(phys, pos, len, copied);
        crate::mm::page::unlock_page(phys);
        filemap::put_page(phys);
        n
    }

    /// The page without waiting (Linux FGP_NOWAIT), then its blocks: a
    /// page it returns is uptodate or wholly written, so no block is
    /// read
    fn write_begin_nowait(&self, inode: &Inode, pos: u64, len: usize) -> Result<u64, KernelError> {
        let phys = filemap::grab_nowait(inode, pos, len)?;
        if let Err(e) = buffer::block_write_begin_int(inode, phys, pos, len, blkdev_get_block) {
            crate::mm::page::unlock_page(phys);
            filemap::put_page(phys);
            return Err(e);
        }
        Ok(phys)
    }

    /// Linux block_invalidate_folio
    fn invalidate_folio(&self, m: &filemap::AddressSpace, phys: u64, offset: usize, len: usize) {
        buffer::block_invalidate_folio(m, phys, offset, len);
    }
}

static BDEV_AOPS: BdevAops = BdevAops;

/// The bdev pseudo filesystem's inode of device `dev` with `size`
/// bytes (Linux bdev_alloc: new_inode on blockdev_superblock, numbered
/// by the device), on the superblock's `s_inodes`, unhashed until the
/// device is added; ENOMEM
pub fn bdev_inode(dev: DevId, size: u64) -> Result<InodeRef, KernelError> {
    let sb = crate::fs::pseudo::BDEV.sb()?;
    let inode = Inode::alloc(Inode::new_device(
        u64::from(dev.encode()),
        InodeMode::blockdev(0o600),
        0,
        0,
        dev,
        Timespec::ZERO,
        Arc::downgrade(&sb),
        &BDEV_INODE_OPS,
    ))?;
    inode.set_size(size);
    inode.i_data.set_aops(&BDEV_AOPS, Some(&inode));
    Ok(inode)
}

/// The bdev inode's operations: its page cache maps (mmap of the node)
struct BdevInodeOps;

impl crate::fs::inode::InodeOps for BdevInodeOps {
    fn lookup(&self, _dir: &Inode, _name: &[u8]) -> Result<InodeRef, KernelError> {
        Err(KernelError::NotDirectory)
    }

    fn maps_cache(&self) -> bool {
        true
    }
}

static BDEV_INODE_OPS: BdevInodeOps = BdevInodeOps;

fn put_int(arg: u64, v: i32) -> Result<i64, KernelError> {
    put_user::<i32>(arg, v).map_err(|_| KernelError::BadAddress)?;
    Ok(0)
}

fn put_u16(arg: u64, v: u16) -> Result<i64, KernelError> {
    put_user::<u16>(arg, v).map_err(|_| KernelError::BadAddress)?;
    Ok(0)
}

fn put_u64(arg: u64, v: u64) -> Result<i64, KernelError> {
    put_user::<u64>(arg, v).map_err(|_| KernelError::BadAddress)?;
    Ok(0)
}

fn need_admin() -> Result<(), KernelError> {
    if crate::task::capable(crate::task::CAP_SYS_ADMIN) {
        Ok(())
    } else {
        Err(KernelError::PermissionDenied)
    }
}

/// BLKROSET (Linux blkdev_roset): no driver has a set_read_only hook
fn roset(b: &BlockDevice, arg: u64) -> Result<i64, KernelError> {
    need_admin()?;
    let n = get_user::<i32>(arg).map_err(|_| KernelError::BadAddress)?;
    b.set_ro(n != 0);
    Ok(0)
}

/// HDIO_GETGEO (Linux blkdev_getgeo): the driver's geometry, `start`
/// the device's first sector unless the driver overrides it; ENOTTY
/// if the driver has none
fn getgeo(b: &BlockDevice, arg: u64) -> Result<i64, KernelError> {
    if arg == 0 {
        return Err(KernelError::InvalidArgument);
    }
    let f = b.disk.getgeo.get().ok_or(KernelError::NotTty)?;
    let mut geo = HdGeometry {
        start: b.start,
        ..HdGeometry::default()
    };
    f(&b.disk, &mut geo)?;
    copy_to_user(arg, &geo.to_bytes()).map_err(|_| KernelError::BadAddress)?;
    Ok(0)
}

/// BLKSECTGET: the largest request in sectors, capped to a u16 (Linux
/// queue_max_sectors, USHRT_MAX)
fn sectget(b: &BlockDevice, arg: u64) -> Result<i64, KernelError> {
    let n = b.disk.queue.limits.max_sectors.min(u32::from(u16::MAX));
    put_u16(arg, n as u16)
}

/// BLKBSZSET (Linux blkdev_bszset): through an O_EXCL file's claim,
/// else a claim taken for the call (EBUSY if another holder has the
/// device: a mounted filesystem, active swap, an O_EXCL file)
fn bszset(f: &BdevFile, arg: u64) -> Result<i64, KernelError> {
    need_admin()?;
    if arg == 0 {
        return Err(KernelError::InvalidArgument);
    }
    let n = get_user::<i32>(arg).map_err(|_| KernelError::BadAddress)?;
    if f.excl {
        return set_blocksize(&f.bdev, f.holder(), n).map(|()| 0);
    }
    // Linux holder &dev: an address unique for the call
    let dev = f.bdev.dev;
    let excl = f
        .bdev
        .open_handle(Some(core::ptr::from_ref(&dev) as usize))
        .map_err(|_| KernelError::Busy)?;
    set_blocksize(&excl, excl.holder(), n).map(|()| 0)
}

/// Linux blkdev_common_ioctl / blkdev_ioctl subset
fn blkdev_ioctl(f: &BdevFile, cmd: u32, arg: u64) -> Result<i64, KernelError> {
    let b = &*f.bdev;
    match cmd {
        ioc::HDIO_GETGEO => getgeo(b, arg),
        ioc::BLKROSET => roset(b, arg),
        ioc::BLKROGET => put_int(arg, i32::from(b.ro())),
        ioc::BLKSSZGET => put_int(arg, b.logical_block_size() as i32),
        ioc::BLKPBSZGET => put_int(arg, b.physical_block_size() as i32),
        ioc::BLKIOMIN => put_int(arg, b.io_min() as i32),
        ioc::BLKIOOPT => put_int(arg, b.io_opt() as i32),
        ioc::BLKALIGNOFF => put_int(arg, b.alignment_offset() as i32),
        ioc::BLKSECTGET => sectget(b, arg),
        ioc::BLKBSZGET => put_int(arg, b.block_size() as i32),
        ioc::BLKGETSIZE => put_u64(arg, b.nr_sects()),
        ioc::BLKGETSIZE64 => put_u64(arg, b.nr_sects() << SECTOR_SHIFT),
        ioc::BLKBSZSET => bszset(f, arg),
        ioc::BLKRRPART => {
            need_admin()?;
            genhd::rescan(b, f.excl).map(|()| 0)
        }
        // Write the cache back and drop its clean pages (Linux
        // blkdev_flushbuf: sync_blockdev, invalidate_bdev)
        ioc::BLKFLSBUF => {
            need_admin()?;
            sync_blockdev(b)?;
            invalidate_bdev(b);
            Ok(0)
        }
        _ => Err(KernelError::NotTty),
    }
}

/// RWF_NOWAIT on a device whose queue cannot honor it is EOPNOTSUPP
/// (Linux: bdev_open sets FMODE_NOWAIT only for bdev_nowait, and
/// kiocb_set_rw_flags refuses RWF_NOWAIT without it)
fn nowait_ok(file: &File, flags: RwFlags) -> Result<(), KernelError> {
    if flags.nowait() && !bdev(file)?.disk.queue.nowait() {
        return Err(KernelError::OperationNotSupported);
    }
    Ok(())
}

impl FileOps for BlockFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    /// No poll (Linux def_blk_fops)
    fn can_poll(&self, _file: &File) -> bool {
        false
    }

    /// Always (Linux bdev_open sets FMODE_CAN_ODIRECT)
    fn can_odirect(&self, _file: &File) -> bool {
        true
    }

    /// Always (Linux __blkdev_direct_IO_async)
    fn can_async_dio(&self, _file: &File) -> bool {
        true
    }

    /// The asynchronous O_DIRECT path (`dio_submit_async`)
    fn dio_submit(
        &self,
        file: &File,
        io: Arc<dyn dio::AsyncIo>,
        pos: u64,
        write: bool,
        flags: RwFlags,
    ) -> Result<Option<usize>, KernelError> {
        dio_submit_async(file, io, pos, write, flags)
    }

    /// Always (Linux def_blk_fops.iopoll)
    fn can_iopoll(&self, _file: &File) -> bool {
        true
    }

    /// Its disk's poll queues (Linux iocb_bio_iopoll -> bio_poll)
    fn iopoll(&self, file: &File) -> bool {
        bdev(file).is_ok_and(|b| b.disk.queue.poll())
    }

    /// The device's page cache maps (Linux blkdev_mmap); a read-only
    /// device only privately or through a read-only file (Linux
    /// generic_file_readonly_mmap: no shared mapping that may write)
    fn mmap(&self, file: &File, shared: bool) -> Result<(), KernelError> {
        if shared && file.is_writable() && bdev(file)?.ro() {
            return Err(KernelError::InvalidArgument);
        }
        Ok(())
    }

    /// Bind the file to its block device (Linux blkdev_open): O_EXCL
    /// claims it, the file's state the holder
    fn open(&self, file: &File) -> Result<(), KernelError> {
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        let b = get_blkdev(inode.rdev).ok_or(KernelError::NoDeviceOrAddress)?;
        let excl = file.get_flags() & super::file::flags::O_EXCL != 0;
        let f = crate::util::kalloc::try_arc(BdevFile { bdev: b, excl })?;
        f.bdev.open(f.holder())?;
        file.private.call_once(|| f);
        Ok(())
    }

    fn release(&self, file: &File) -> Result<(), KernelError> {
        if let Ok(f) = bdev_file(file) {
            f.bdev.release(f.holder());
        }
        Ok(())
    }

    /// O_DIRECT from user memory straight into it (`dio_read`), else
    /// through the device's page cache; RWF_NOWAIT where nothing waits
    /// (Linux blkdev_read_iter, FMODE_NOWAIT)
    fn read_iter(
        &self,
        file: &File,
        to: &mut IovDest<'_>,
        at: Option<u64>,
        flags: RwFlags,
    ) -> Result<usize, KernelError> {
        nowait_ok(file, flags)?;
        let pos = at.unwrap_or_else(|| file.get_pos());
        let n = if flags.contains(RwFlags::DIRECT) && to.pinnable() {
            dio_read(file, to, pos, flags)?
        } else {
            read_at(file, to, pos, flags.nowait())?
        };
        if at.is_none() {
            file.advance_pos(n as u64);
        }
        Ok(n)
    }

    /// O_DIRECT from user memory straight out of it (`dio_write`), else
    /// through the device's page cache (RWF_NOWAIT: EOPNOTSUPP); on the
    /// disk before return for O_DSYNC, O_SYNC, RWF_DSYNC and RWF_SYNC
    /// (Linux blkdev_write_iter: generic_write_sync). The buffered write
    /// holds the bdev inode's i_rwsem shared, as Linux.
    fn write_iter(
        &self,
        file: &File,
        from: &mut IovSource<'_>,
        at: Option<u64>,
        flags: RwFlags,
    ) -> Result<usize, KernelError> {
        nowait_ok(file, flags)?;
        let pos = at.unwrap_or_else(|| file.get_pos());
        if !write_ok(file, from.len(), pos)? {
            return Ok(0);
        }
        let direct = flags.contains(RwFlags::DIRECT) && from.pinnable();
        if flags.nowait() && !direct {
            return Err(KernelError::OperationNotSupported);
        }
        let b = bdev(file)?;
        from.truncate((b.capacity() - pos).min(usize::MAX as u64) as usize);
        let n = if direct {
            dio_write(file, from, pos, flags)?
        } else {
            // Its dirtied pages mark the device's inode dirty, for its
            // periodic writeback (`filemap::dirty_page`); i_rwsem shared
            // keeps `set_blocksize` out (Linux blkdev_write_iter)
            let _g = b.bd_inode.lock_shared();
            filemap::write_iter(&b.bd_inode, from, pos)?
        };
        if at.is_none() {
            file.advance_pos(n as u64);
        }
        generic_write_sync(file, pos, n, flags)
    }

    /// Positions within the device only (Linux fixed_size_llseek)
    fn llseek(&self, file: &File, offset: i64, whence: i32) -> Result<u64, KernelError> {
        let size = bdev(file)?.capacity() as i64;
        if whence == seek::SEEK_CUR && offset == 0 {
            return Ok(file.get_pos());
        }
        let base = match whence {
            seek::SEEK_SET => 0,
            seek::SEEK_CUR => file.get_pos() as i64,
            seek::SEEK_END => size,
            _ => return Err(KernelError::InvalidArgument),
        };
        let pos = base
            .checked_add(offset)
            .filter(|p| (0..=size).contains(p))
            .ok_or(KernelError::InvalidArgument)?;
        file.set_pos(pos as u64);
        Ok(pos as u64)
    }

    /// Write back the cache over bytes [start, end], then flush the
    /// disk's write cache (Linux blkdev_fsync:
    /// file_write_and_wait_range, blkdev_issue_flush; EOPNOTSUPP from
    /// the flush is success)
    fn fsync(&self, file: &File, start: u64, end: u64, _datasync: bool) -> Result<(), KernelError> {
        let b = bdev(file)?;
        filemap::file_write_and_wait_range(file, start, end)?;
        match blkdev_issue_flush(&b) {
            Err(KernelError::OperationNotSupported) => Ok(()),
            r => r,
        }
    }

    fn ioctl(&self, file: &File, cmd: u32, arg: u64) -> Result<i64, KernelError> {
        blkdev_ioctl(bdev_file(file)?, cmd, arg)
    }
}

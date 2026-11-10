//! Block device files (Linux block/fops.c, block/ioctl.c)
//!
//! Reads and writes go through the device's page cache: the page cache
//! of its inode in the bdev pseudo filesystem (`BlockDevice.bd_inode`,
//! Linux bd_mapping), shared with filesystems' metadata on the device
//! (vfat), written back by fsync, sync, BLKFLSBUF and the last close,
//! which also drops it (Linux blkdev_flush_mapping). mmap maps it.
//! O_DIRECT I/O from user memory bypasses it (`block::dio`): the range
//! is written back first, and for a write dropped before and after;
//! what the bios could not take goes through the cache. No i_rwsem, as
//! Linux (block devices are not regular files).
//! The open file holds its block device (`File.private`), counted as an
//! opener (BLKRRPART, BLKBSZGET's initial value).

use alloc::sync::Arc;

use crate::block::DevId;
use crate::block::blkdev::{
    BioOp, BlockDevice, SECTOR_SHIFT, bdev_rw_bytes, bdev_rw_frame, blkdev_issue_flush, get_blkdev,
    sync_blockdev,
};
use crate::block::genhd;
use crate::fs::inode::{Inode, InodeMode, Timespec};
use crate::mm::filemap::{self, Aops, PAGE_SIZE};
use crate::uaccess::{get_user, put_user};
use crate::util::error::KernelError;
use core::sync::atomic::Ordering;

use super::file::{File, FileOps, RwFlags, generic_write_sync, seek};
use super::iov_iter::{IovDest, IovSource};
use crate::block::dio;
use crate::util::kalloc::arc_nofail;

/// Block device ioctls (Linux include/uapi/linux/fs.h)
pub mod ioc {
    pub const BLKROGET: u32 = 0x125e;
    pub const BLKRRPART: u32 = 0x125f;
    pub const BLKGETSIZE: u32 = 0x1260;
    pub const BLKFLSBUF: u32 = 0x1261;
    pub const BLKSSZGET: u32 = 0x1268;
    pub const BLKBSZGET: u32 = 0x8008_1270;
    pub const BLKBSZSET: u32 = 0x4008_1271;
    pub const BLKGETSIZE64: u32 = 0x8008_1272;
    pub const BLKPBSZGET: u32 = 0x127b;
}

/// Block device file operations
pub struct BlockFileOps;

/// Static block file ops instance
pub static BLOCK_FILE_OPS: BlockFileOps = BlockFileOps;

fn bdev(file: &File) -> Result<Arc<BlockDevice>, KernelError> {
    file.private_arc::<BlockDevice>()
        .ok_or(KernelError::NoDeviceOrAddress)
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

/// Linux filemap_read, with IOCB_NOWAIT for `nowait`
fn cache_read(
    b: &BlockDevice,
    to: &mut IovDest<'_>,
    pos: u64,
    nowait: bool,
) -> Result<usize, KernelError> {
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
/// kiocb_invalidate_post_direct_write): a page left is reported (Linux
/// dio_warn_stale_pagecache), not an error
fn invalidate_post(b: &BlockDevice, pos: u64, count: usize) {
    let p = PAGE_SIZE as u64;
    if b.bd_inode.i_data.nrpages() != 0
        && filemap::invalidate_pages2(&b.bd_inode, pos / p, last(pos, count) / p).is_err()
    {
        crate::printkln!(
            "Page cache invalidation failure on direct I/O.  Possible data corruption due to collision with buffered I/O!"
        );
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
    if b.bd_inode.i_swapfile.load(Ordering::Acquire) {
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

/// The pages of a block device's inode are its sectors (Linux
/// def_blk_aops: blkdev_read_folio, blkdev_writepages), read and
/// written a page per bio straight into the cache frame
struct BdevAops;

/// The bdev inode's device: its own, never another one registered
/// under the same number later; EIO once it is removed
fn inode_bdev(inode: &Inode) -> Result<Arc<BlockDevice>, KernelError> {
    let p = inode.get_private().ok_or(KernelError::Io)?;
    let b = p
        .as_any()
        .downcast_ref::<BdevOwner>()
        .and_then(|o| o.0.upgrade())
        .ok_or(KernelError::Io)?;
    if b.is_dead() {
        return Err(KernelError::Io);
    }
    Ok(b)
}

/// A bdev inode's back reference to its device (set at registration)
pub struct BdevOwner(pub alloc::sync::Weak<BlockDevice>);

impl crate::fs::inode::InodeData for BdevOwner {}

impl crate::fs::inode::AsAny for BdevOwner {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

/// Dirty 512-byte sectors of a device-cache page (`Page.private` bits,
/// Linux's dirty buffer heads): metadata writes mark just what they
/// change, and writeback writes only those, since the page may also
/// hold blocks the device cache does not own (vfat file-data clusters
/// smaller than a page, written from the file's own cache). No bits:
/// the whole page (device-node writes).
const SECTORS: usize = PAGE_SIZE / 512;

fn page_struct(phys: u64) -> Result<&'static crate::mm::page::Page, KernelError> {
    crate::mm::page::phys_to_page(phys).ok_or(KernelError::Io)
}

/// Write `buf` at byte `pos` of the device into its cache, dirtying
/// only the sectors it touches (Linux mark_buffer_dirty); written back
/// by fsync, sync, umount (the last close) and the periodic writeback
pub fn bdev_write_meta(b: &BlockDevice, pos: u64, buf: &[u8]) -> Result<(), KernelError> {
    let inode = &b.bd_inode;
    let mut done = 0;
    while done < buf.len() {
        let at = pos + done as u64;
        let index = at / PAGE_SIZE as u64;
        let off = (at % PAGE_SIZE as u64) as usize;
        let n = (PAGE_SIZE - off).min(buf.len() - done);
        let phys = filemap::grab(&inode.i_data, index)?;
        let r = if filemap::uptodate(phys) {
            Ok(())
        } else {
            BDEV_AOPS.read_folio(inode, phys, index)
        };
        if let Err(e) = r {
            filemap::remove(&inode.i_data, phys);
            crate::mm::page::unlock_page(phys);
            filemap::put_page(phys);
            return Err(e);
        }
        // The locked, uptodate page with our reference
        // SAFETY: the locked page with our reference
        let bytes = unsafe { crate::mm::page::frame_bytes(phys) };
        bytes[off..off + n].copy_from_slice(&buf[done..done + n]);
        let bits: u64 = (off / 512..(off + n).div_ceil(512)).fold(0, |a, s| a | 1 << s);
        page_struct(phys)?.private.fetch_or(bits, Ordering::Relaxed);
        // Not through the aops: they mark the whole page
        filemap::dirty_folio(&inode.i_data, phys);
        crate::mm::page::unlock_page(phys);
        filemap::put_page(phys);
        done += n;
    }
    b.disk.bdi.kick(b.dev_id());
    Ok(())
}

impl Aops for BdevAops {
    /// A whole-page dirtying (a device-node write, a store through a
    /// mapping): every sector is written back, whatever metadata
    /// marked before
    fn dirty_folio(&self, m: &filemap::AddressSpace, phys: u64) {
        if let Ok(p) = page_struct(phys) {
            p.private.fetch_or((1u64 << SECTORS) - 1, Ordering::Relaxed);
        }
        filemap::dirty_folio(m, phys);
    }

    fn read_folio(&self, inode: &Inode, phys: u64, index: u64) -> Result<(), KernelError> {
        let b = inode_bdev(inode)?;
        bdev_rw_frame(&b, BioOp::Read, index << (12 - SECTOR_SHIFT), phys)?;
        filemap::set_uptodate(phys);
        Ok(())
    }

    fn writepage(&self, inode: &Inode, phys: u64, index: u64) -> Result<(), KernelError> {
        let b = inode_bdev(inode)?;
        if b.ro() {
            return Err(KernelError::NotPermitted);
        }
        let bits = page_struct(phys)?.private.swap(0, Ordering::Relaxed);
        if bits == 0 {
            return bdev_rw_frame(&b, BioOp::Write, index << (12 - SECTOR_SHIFT), phys);
        }
        // Just the dirty sectors, in runs rounded out to logical blocks
        let lbs = (b.logical_block_size() as usize / 512).clamp(1, SECTORS);
        // The locked page with our reference
        // SAFETY: the locked page with our reference
        let page = unsafe { crate::mm::page::frame_bytes(phys) };
        let base = index * PAGE_SIZE as u64;
        let mut s = 0;
        while s < SECTORS {
            if bits & 1 << s == 0 {
                s += 1;
                continue;
            }
            let mut e = s;
            while e < SECTORS && bits & 1 << e != 0 {
                e += 1;
            }
            let (a, z) = (s / lbs * lbs, e.next_multiple_of(lbs).min(SECTORS));
            let r = bdev_rw_bytes(
                &b,
                BioOp::Write,
                base + a as u64 * 512,
                &mut page[a * 512..z * 512],
            );
            if r.is_err() {
                // Keep what was not written dirty
                page_struct(phys)?.private.fetch_or(bits, Ordering::Relaxed);
                return r;
            }
            s = z;
        }
        Ok(())
    }
}

static BDEV_AOPS: BdevAops = BdevAops;

/// The bdev pseudo filesystem's inode of device `dev` with `size`
/// bytes (Linux bdev_alloc): unhashed, no superblock
pub fn bdev_inode(dev: DevId, size: u64) -> Arc<Inode> {
    let inode = arc_nofail(Inode::new_device(
        0,
        InodeMode::blockdev(0o600),
        0,
        0,
        dev,
        Timespec::ZERO,
        alloc::sync::Weak::new(),
        &BDEV_INODE_OPS,
    ));
    inode.set_size(size);
    inode.i_data.set_aops(&BDEV_AOPS);
    inode
}

/// The bdev inode's operations: its page cache maps (mmap of the node)
struct BdevInodeOps;

impl crate::fs::inode::InodeOps for BdevInodeOps {
    fn lookup(&self, _dir: &Inode, _name: &[u8]) -> Result<Arc<Inode>, KernelError> {
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

/// Linux blkdev_common_ioctl / blkdev_ioctl subset
fn blkdev_ioctl(b: &BlockDevice, cmd: u32, arg: u64) -> Result<i64, KernelError> {
    match cmd {
        ioc::BLKROGET => put_int(arg, i32::from(b.ro())),
        ioc::BLKSSZGET => put_int(arg, b.logical_block_size() as i32),
        ioc::BLKPBSZGET => put_int(arg, b.physical_block_size() as i32),
        ioc::BLKBSZGET => put_int(arg, b.block_size() as i32),
        ioc::BLKGETSIZE => put_u64(arg, b.nr_sects()),
        ioc::BLKGETSIZE64 => put_u64(arg, b.nr_sects() << SECTOR_SHIFT),
        ioc::BLKBSZSET => {
            need_admin()?;
            if arg == 0 {
                return Err(KernelError::InvalidArgument);
            }
            let n = get_user::<i32>(arg).map_err(|_| KernelError::BadAddress)?;
            b.set_block_size(n).map(|()| 0)
        }
        ioc::BLKRRPART => {
            need_admin()?;
            genhd::rescan(b).map(|()| 0)
        }
        // No buffer cache to write back or drop yet
        // Write the cache back and drop it (Linux blkdev_flushbuf)
        ioc::BLKFLSBUF => {
            need_admin()?;
            sync_blockdev(b)?;
            filemap::invalidate(&b.bd_inode);
            Ok(0)
        }
        _ => Err(KernelError::NotTty),
    }
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

    /// The device's page cache maps (Linux blkdev_mmap); a read-only
    /// device only privately or through a read-only file (Linux
    /// generic_file_readonly_mmap: no shared mapping that may write)
    fn mmap(&self, file: &File, shared: bool) -> Result<(), KernelError> {
        if shared && file.is_writable() && bdev(file)?.ro() {
            return Err(KernelError::InvalidArgument);
        }
        Ok(())
    }

    /// Bind the file to its block device (Linux blkdev_open)
    fn open(&self, file: &File) -> Result<(), KernelError> {
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        let b = get_blkdev(inode.rdev).ok_or(KernelError::NoDeviceOrAddress)?;
        b.open()?;
        file.private.call_once(|| b);
        Ok(())
    }

    fn release(&self, file: &File) -> Result<(), KernelError> {
        if let Some(b) = file.private_arc::<BlockDevice>() {
            b.release();
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
        let pos = at.unwrap_or_else(|| file.get_pos());
        let n = if flags.contains(RwFlags::DIRECT) && to.user_backed() {
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
    /// (Linux blkdev_write_iter: generic_write_sync). No i_rwsem, as
    /// Linux.
    fn write_iter(
        &self,
        file: &File,
        from: &mut IovSource<'_>,
        at: Option<u64>,
        flags: RwFlags,
    ) -> Result<usize, KernelError> {
        let pos = at.unwrap_or_else(|| file.get_pos());
        if !write_ok(file, from.len(), pos)? {
            return Ok(0);
        }
        let direct = flags.contains(RwFlags::DIRECT) && from.user_backed();
        if flags.nowait() && !direct {
            return Err(KernelError::OperationNotSupported);
        }
        let b = bdev(file)?;
        from.truncate((b.capacity() - pos).min(usize::MAX as u64) as usize);
        let n = if direct {
            dio_write(file, from, pos, flags)?
        } else {
            filemap::write_iter(&b.bd_inode, from, pos)?
        };
        if at.is_none() {
            file.advance_pos(n as u64);
        }
        generic_write_sync(file, pos, n, flags.contains(RwFlags::DSYNC))
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

    /// Write the whole cache back, then flush the disk's write cache
    fn fsync(&self, file: &File) -> Result<(), KernelError> {
        self.fsync_range(file, 0, u64::MAX)
    }

    /// Write back the cache over bytes [start, end], then flush the
    /// disk's write cache (Linux blkdev_fsync:
    /// file_write_and_wait_range, blkdev_issue_flush)
    fn fsync_range(&self, file: &File, start: u64, end: u64) -> Result<(), KernelError> {
        let b = bdev(file)?;
        filemap::write_and_wait_range(&b.bd_inode, start, end)?;
        blkdev_issue_flush(&b)
    }

    fn ioctl(&self, file: &File, cmd: u32, arg: u64) -> Result<i64, KernelError> {
        blkdev_ioctl(&*bdev(file)?, cmd, arg)
    }
}

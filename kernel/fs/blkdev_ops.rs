//! Block device files (Linux block/fops.c, block/ioctl.c)
//!
//! Reads and writes go through the device's page cache: the page cache
//! of its inode in the bdev pseudo filesystem (`BlockDevice.bd_inode`,
//! Linux bd_mapping), shared with filesystems' metadata on the device
//! (vfat), written back by fsync, sync, BLKFLSBUF and the last close,
//! which also drops it (Linux blkdev_flush_mapping). mmap maps it.
//! The open file holds its block device (`File.private`), counted as an
//! opener (BLKRRPART, BLKBSZGET's initial value).

use alloc::sync::Arc;

use crate::arch::Uaccess;
use crate::error::KernelError;
use crate::fs::inode::{Inode, InodeMode, Timespec};
use crate::mm::filemap::{self, Aops};
use crate::storage::DevId;
use crate::storage::blkdev::{
    BioOp, BlockDevice, SECTOR_SHIFT, bdev_rw_frame, blkdev_issue_flush, get_blkdev, sync_blockdev,
};
use crate::storage::genhd;
use crate::uaccess::{get_user, put_user};

use super::file::{File, FileOps, seek};

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

/// Read at `pos`: short at the end, 0 past it (Linux blkdev_read_iter)
fn read_at(file: &File, buf: &mut [u8], pos: u64) -> Result<usize, KernelError> {
    let b = bdev(file)?;
    let size = b.capacity();
    if pos >= size || buf.is_empty() {
        return Ok(0);
    }
    let n = buf.len().min((size - pos) as usize);
    filemap::read(&b.bd_inode, &mut buf[..n], pos)
}

/// Write at `pos`: EPERM if read-only, ENOSPC at or past the end, short
/// at it (Linux blkdev_write_iter)
fn write_at(file: &File, buf: &[u8], pos: u64) -> Result<usize, KernelError> {
    let b = bdev(file)?;
    if b.ro() {
        return Err(KernelError::NotPermitted);
    }
    if buf.is_empty() {
        return Ok(0);
    }
    let size = b.capacity();
    if pos >= size {
        return Err(KernelError::NoSpace);
    }
    let n = buf.len().min((size - pos) as usize);
    filemap::perform_write(&b.bd_inode, &buf[..n], pos)
}

/// The pages of a block device's inode are its sectors (Linux
/// def_blk_aops: blkdev_read_folio, blkdev_writepages), read and
/// written a page per bio straight into the cache frame
struct BdevAops;

fn inode_bdev(inode: &Inode) -> Result<Arc<BlockDevice>, KernelError> {
    get_blkdev(inode.rdev).ok_or(KernelError::Io)
}

impl Aops for BdevAops {
    fn read_folio(&self, inode: &Inode, phys: u64, index: u64) -> Result<(), KernelError> {
        let b = inode_bdev(inode)?;
        bdev_rw_frame(&b, BioOp::Read, index << (12 - SECTOR_SHIFT), phys)?;
        filemap::set_uptodate(phys);
        Ok(())
    }

    fn writepage(&self, inode: &Inode, phys: u64, index: u64) -> Result<(), KernelError> {
        let b = inode_bdev(inode)?;
        bdev_rw_frame(&b, BioOp::Write, index << (12 - SECTOR_SHIFT), phys)
    }
}

static BDEV_AOPS: BdevAops = BdevAops;

/// The bdev pseudo filesystem's inode of device `dev` with `size`
/// bytes (Linux bdev_alloc): unhashed, no superblock
pub fn bdev_inode(dev: DevId, size: u64) -> Arc<Inode> {
    let inode = Arc::new(Inode::new_device(
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
    fn lookup(&self, _dir: &Inode, _name: &str) -> Result<Arc<Inode>, KernelError> {
        Err(KernelError::NotDirectory)
    }

    fn maps_cache(&self) -> bool {
        true
    }
}

static BDEV_INODE_OPS: BdevInodeOps = BdevInodeOps;

fn put_int(arg: u64, v: i32) -> Result<i64, KernelError> {
    put_user::<Uaccess, i32>(arg, v).map_err(|_| KernelError::BadAddress)?;
    Ok(0)
}

fn put_u64(arg: u64, v: u64) -> Result<i64, KernelError> {
    put_user::<Uaccess, u64>(arg, v).map_err(|_| KernelError::BadAddress)?;
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
        ioc::BLKROGET => put_int(arg, b.ro() as i32),
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
            let n = get_user::<Uaccess, i32>(arg).map_err(|_| KernelError::BadAddress)?;
            b.set_block_size(n).map(|_| 0)
        }
        ioc::BLKRRPART => {
            need_admin()?;
            genhd::rescan(b).map(|_| 0)
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

    /// The device's page cache maps (Linux blkdev_mmap)
    fn mmap(&self, _file: &File) -> Result<(), KernelError> {
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

    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize, KernelError> {
        let n = read_at(file, buf, file.get_pos())?;
        file.advance_pos(n as u64);
        Ok(n)
    }

    fn write(&self, file: &File, buf: &[u8]) -> Result<usize, KernelError> {
        let n = write_at(file, buf, file.get_pos())?;
        file.advance_pos(n as u64);
        Ok(n)
    }

    fn pread(&self, file: &File, buf: &mut [u8], offset: u64) -> Result<usize, KernelError> {
        read_at(file, buf, offset)
    }

    fn pwrite(&self, file: &File, buf: &[u8], offset: u64) -> Result<usize, KernelError> {
        write_at(file, buf, offset)
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

    /// Write the cache back, then flush the disk's write cache (Linux
    /// blkdev_fsync)
    fn fsync(&self, file: &File) -> Result<(), KernelError> {
        let b = bdev(file)?;
        sync_blockdev(&b)?;
        blkdev_issue_flush(&b)
    }

    fn ioctl(&self, file: &File, cmd: u32, arg: u64) -> Result<i64, KernelError> {
        blkdev_ioctl(&*bdev(file)?, cmd, arg)
    }
}

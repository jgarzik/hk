//! Syncing and cache advice (Linux fs/sync.c, mm/fadvise.c,
//! mm/readahead.c ksys_readahead)
//!
//! sync, syncfs, fsync, fdatasync and sync_file_range write dirty page
//! cache to the disk (`fs_writeback`, `filemap::write_and_wait`);
//! fadvise and readahead act on a file's page cache. All I/O here is
//! synchronous: a write that was asked for has completed on return.

use alloc::sync::Arc;

use super::file::File;
use super::inode::Inode;
use super::syscall::current_fd_table;
use crate::mm::filemap::{self, PAGE_SIZE};
use crate::util::error::KernelError;

/// The open file `fd`, or EBADF
fn fd_file(fd: i32) -> Result<Arc<File>, KernelError> {
    current_fd_table().lock().get(fd).ok_or(KernelError::BadFd)
}

/// sync(2) (Linux ksys_sync): every filesystem's dirty inodes, then
/// every block device's cache, written and waited for
pub fn sys_sync() -> i64 {
    crate::mm::writeback::sync_all();
    0
}

/// fsync(2): the file's data and metadata (Linux vfs_fsync -> ->fsync)
pub fn sys_fsync(fd: i32) -> i64 {
    let file = match fd_file(fd) {
        Ok(f) => f,
        Err(e) => return e.sysret(),
    };
    match file.f_op.fsync(&file) {
        Ok(()) => 0,
        Err(KernelError::Io) => KernelError::Io.sysret(),
        Err(_) => KernelError::InvalidArgument.sysret(),
    }
}

/// fdatasync(2): as fsync (hk's filesystems write no metadata that
/// fdatasync could skip)
pub fn sys_fdatasync(fd: i32) -> i64 {
    sys_fsync(fd)
}

/// syncfs(2) (Linux sync_filesystem of the file's superblock): its
/// dirty inodes, then its device's cache; a write error is returned
pub fn sys_syncfs(fd: i32) -> i64 {
    let file = match fd_file(fd) {
        Ok(f) => f,
        Err(e) => return e.sysret(),
    };
    let Some(sb) = file.get_inode().and_then(|i| i.superblock()) else {
        return 0;
    };
    match super::fs_writeback::writeback_sb(&sb) {
        Ok(()) => 0,
        Err(_) => KernelError::Io.sysret(),
    }
}

/// sync_file_range flags (Linux include/uapi/linux/fs.h)
pub const SYNC_FILE_RANGE_WAIT_BEFORE: u32 = 1;
pub const SYNC_FILE_RANGE_WRITE: u32 = 2;
pub const SYNC_FILE_RANGE_WAIT_AFTER: u32 = 4;

/// The page indexes [first, last] of bytes [offset, offset + nbytes)
/// (nbytes 0: to the end of the file)
fn page_range(offset: u64, nbytes: u64) -> (u64, u64) {
    let first = offset / PAGE_SIZE as u64;
    let last = match nbytes {
        0 => u64::MAX,
        n => offset.saturating_add(n - 1) / PAGE_SIZE as u64,
    };
    (first, last)
}

/// sync_file_range(2) (Linux ksys_sync_file_range): with
/// SYNC_FILE_RANGE_WRITE, write the dirty pages of the range; the waits
/// have nothing to wait for (hk's writeback is synchronous). No
/// metadata and no disk flush, as on Linux.
pub fn sys_sync_file_range(fd: i32, offset: i64, nbytes: i64, flags: u32) -> i64 {
    let all = SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER;
    if flags & !all != 0 || offset < 0 || nbytes < 0 || offset.checked_add(nbytes).is_none() {
        return KernelError::InvalidArgument.sysret();
    }
    let file = match fd_file(fd) {
        Ok(f) => f,
        Err(e) => return e.sysret(),
    };
    let Some(inode) = file.get_inode() else {
        return KernelError::IllegalSeek.sysret();
    };
    let m = inode.mode();
    if !m.is_file() && !m.is_blkdev() && !m.is_dir() && !m.is_symlink() {
        return KernelError::IllegalSeek.sysret();
    }
    if flags & SYNC_FILE_RANGE_WRITE == 0 {
        return 0;
    }
    let Some(host) = file.mapping_inode() else {
        return 0;
    };
    let (first, last) = page_range(offset as u64, nbytes as u64);
    match filemap::write_range(&host, first, last) {
        Ok(()) => 0,
        Err(_) => KernelError::Io.sysret(),
    }
}

/// fadvise advice (Linux include/uapi/linux/fadvise.h; DONTNEED and
/// NOREUSE are 4 and 5 on 64-bit architectures)
pub const POSIX_FADV_NORMAL: i32 = 0;
pub const POSIX_FADV_RANDOM: i32 = 1;
pub const POSIX_FADV_SEQUENTIAL: i32 = 2;
pub const POSIX_FADV_WILLNEED: i32 = 3;
pub const POSIX_FADV_DONTNEED: i32 = 4;
pub const POSIX_FADV_NOREUSE: i32 = 5;

/// Read the pages [first, last] of `inode` into its cache, up to EOF
/// (Linux force_page_cache_readahead); errors are dropped, as advice
fn willneed(inode: &Inode, first: u64, last: u64) {
    let end = inode.get_size().div_ceil(PAGE_SIZE as u64);
    for index in first..end.min(last.saturating_add(1)) {
        match filemap::read_page(inode, index) {
            Ok(p) => filemap::put_page(p),
            Err(_) => return,
        }
    }
}

/// fadvise64(2) (Linux generic_fadvise): WILLNEED reads the range into
/// the cache, DONTNEED writes back and drops its whole pages that no one
/// maps; the access-pattern hints are accepted (hk has no readahead
/// window to tune). A pipe is ESPIPE.
pub fn sys_fadvise64(fd: i32, offset: i64, len: i64, advice: i32) -> i64 {
    let file = match fd_file(fd) {
        Ok(f) => f,
        Err(e) => return e.sysret(),
    };
    let inode = file.get_inode();
    if inode.as_ref().is_none_or(|i| i.mode().is_fifo()) {
        return KernelError::IllegalSeek.sysret();
    }
    if !(POSIX_FADV_NORMAL..=POSIX_FADV_NOREUSE).contains(&advice) || len < 0 {
        return KernelError::InvalidArgument.sysret();
    }
    let Some(host) = file.mapping_inode() else {
        return 0;
    };
    let off = offset.max(0) as u64;
    let (first, last) = page_range(off, len as u64);
    match advice {
        POSIX_FADV_WILLNEED => willneed(&host, first, last),
        POSIX_FADV_DONTNEED => {
            let _ = filemap::write_range(&host, first, last);
            // Only pages wholly inside the range (Linux rounds the
            // start up and the end down)
            let start = off.div_ceil(PAGE_SIZE as u64);
            let end = match len {
                0 => u64::MAX,
                _ => off.saturating_add(len as u64) / PAGE_SIZE as u64,
            };
            if start < end {
                filemap::invalidate_clean(&host, start, end - 1);
            }
        }
        _ => {}
    }
    0
}

/// readahead(2) (Linux ksys_readahead): a regular file or block device
/// open for reading; reads the range into the cache (WILLNEED)
pub fn sys_readahead(fd: i32, offset: i64, count: usize) -> i64 {
    let file = match fd_file(fd) {
        Ok(f) => f,
        Err(e) => return e.sysret(),
    };
    if !file.is_readable() {
        return KernelError::BadFd.sysret();
    }
    let Some(inode) = file.get_inode() else {
        return KernelError::InvalidArgument.sysret();
    };
    let m = inode.mode();
    // The count reaches fadvise as a loff_t: past i64::MAX it is a
    // negative length, EINVAL (Linux vfs_fadvise)
    if (!m.is_file() && !m.is_blkdev()) || offset < 0 || (count as i64) < 0 {
        return KernelError::InvalidArgument.sysret();
    }
    if let Some(host) = file.mapping_inode() {
        let (first, last) = page_range(offset as u64, count as u64);
        willneed(&host, first, last);
    }
    0
}

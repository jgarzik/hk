//! read/write family (Linux fs/read_write.c): read, write, lseek,
//! pread64, pwrite64 and the shared core used by the vectored calls

use alloc::sync::Arc;

use crate::arch::Uaccess;
use crate::fs::{File, KernelError, RwFlags};
use crate::uaccess::UaccessArch;

use super::iov_iter::{IovDest, IovSource};

use super::iov::IoVec;
use super::syscall::{MAX_RW_COUNT, current_fd_table};

/// The current task's file at `fd`, or EBADF (Linux fget/fdget): the
/// fd table lock is dropped before return
pub fn fget(fd: i32) -> Result<Arc<File>, KernelError> {
    current_fd_table().lock().get(fd).ok_or(KernelError::BadFd)
}

/// Bytes the segments cover, capped at MAX_RW_COUNT
pub fn seg_len(segs: &[IoVec]) -> usize {
    let total = segs
        .iter()
        .fold(0usize, |t, s| t.saturating_add(s.iov_len as usize));
    total.min(MAX_RW_COUNT)
}

/// Read from `file` into `segs` at `at` (None: the file position)
/// (Linux vfs_readv)
pub fn file_readv(
    file: &File,
    segs: &[IoVec],
    at: Option<u64>,
    flags: RwFlags,
) -> Result<usize, KernelError> {
    file.read_iter(&mut IovDest::user(segs, MAX_RW_COUNT), at, flags)
}

/// Write `segs` to `file` as one write (see `File::write_iter`)
pub fn file_writev(
    file: &File,
    segs: &[IoVec],
    at: Option<u64>,
    flags: RwFlags,
    append: Option<bool>,
) -> Result<usize, KernelError> {
    file.write_iter(&mut IovSource::user(segs, MAX_RW_COUNT), at, flags, append)
}

/// Files with a position (regular, block device)
fn reads_fully(file: &File) -> bool {
    file.get_inode()
        .is_some_and(|i| i.mode().is_file() || i.mode().is_blkdev())
}

/// Linux rw_verify_area: on a file with a position (regular, block
/// device), `pos + count` must stay a valid offset (EINVAL)
pub fn verify_area(file: &File, at: Option<u64>, count: usize) -> Result<(), KernelError> {
    if !reads_fully(file) {
        return Ok(());
    }
    let pos = at.unwrap_or_else(|| file.get_pos());
    match pos.checked_add(count as u64) {
        Some(end) if end <= i64::MAX as u64 => Ok(()),
        _ => Err(KernelError::InvalidArgument),
    }
}

/// errno for a failed read/write: no access is EBADF, a missing op is
/// ESPIPE for positioned I/O and EINVAL otherwise (EOPNOTSUPP stays for
/// RWF_NOWAIT)
fn rw_err(e: KernelError, at: Option<u64>, flags: RwFlags) -> i64 {
    match e {
        KernelError::PermissionDenied => KernelError::BadFd.sysret(),
        KernelError::OperationNotSupported if !flags.nowait => match at {
            Some(_) => KernelError::IllegalSeek.sysret(),
            None => KernelError::InvalidArgument.sysret(),
        },
        e => e.sysret(),
    }
}

/// Read from `fd` into `segs` at `at`, or at the file position (under
/// f_pos_lock, Linux fdget_pos) when None (Linux vfs_readv)
pub fn do_readv(fd: i32, segs: &[IoVec], at: Option<u64>, flags: RwFlags) -> i64 {
    let file = match fget(fd) {
        Ok(f) => f,
        Err(e) => return e.sysret(),
    };
    if file.is_dir() {
        return KernelError::IsDirectory.sysret();
    }
    let _pos = at.is_none().then(|| file.pos_lock());
    if let Err(e) = verify_area(&file, at, seg_len(segs)) {
        return e.sysret();
    }
    match file_readv(&file, segs, at, flags) {
        Ok(n) => n as i64,
        Err(e) => rw_err(e, at, flags),
    }
}

/// Write `segs` to `fd` as one write at `at`, or at the file position
/// (under f_pos_lock) when None (Linux vfs_writev); `append` as for
/// `File::write_at`
pub fn do_writev(
    fd: i32,
    segs: &[IoVec],
    at: Option<u64>,
    flags: RwFlags,
    append: Option<bool>,
) -> i64 {
    let file = match fget(fd) {
        Ok(f) => f,
        Err(e) => return e.sysret(),
    };
    if file.is_dir() {
        return KernelError::IsDirectory.sysret();
    }
    let _pos = at.is_none().then(|| file.pos_lock());
    if let Err(e) = verify_area(&file, at, seg_len(segs)) {
        return e.sysret();
    }
    match file_writev(&file, segs, at, flags, append) {
        Ok(n) => n as i64,
        Err(e) => rw_err(e, at, flags),
    }
}

/// One user buffer as a segment, cut to MAX_RW_COUNT, after the EFAULT
/// check (Linux import_ubuf)
pub fn import_ubuf(buf: u64, count: u64) -> Result<[IoVec; 1], KernelError> {
    let count = (count as usize).min(MAX_RW_COUNT);
    if !Uaccess::access_ok(buf, count) {
        return Err(KernelError::BadAddress);
    }
    Ok([IoVec {
        iov_base: buf,
        iov_len: count as u64,
    }])
}

/// [`import_ubuf`] with the errno
fn one_seg(buf: u64, count: u64) -> Result<[IoVec; 1], i64> {
    import_ubuf(buf, count).map_err(KernelError::sysret)
}

/// Explicit offset of pread/pwrite: negative is EINVAL
fn pos_arg(offset: i64) -> Result<u64, i64> {
    u64::try_from(offset).map_err(|_| KernelError::InvalidArgument.sysret())
}

/// sys_read - read from a file descriptor
pub fn sys_read(fd: i32, buf: u64, count: u64) -> i64 {
    match one_seg(buf, count) {
        Ok(s) => do_readv(fd, &s, None, RwFlags::empty()),
        Err(e) => e,
    }
}

/// sys_write - write to a file descriptor
pub fn sys_write(fd: i32, buf: u64, count: u64) -> i64 {
    match one_seg(buf, count) {
        Ok(s) => do_writev(fd, &s, None, RwFlags::empty(), None),
        Err(e) => e,
    }
}

/// sys_pread64 - read at an offset without moving the file position
pub fn sys_pread64(fd: i32, buf: u64, count: u64, offset: i64) -> i64 {
    match (pos_arg(offset), one_seg(buf, count)) {
        (Ok(o), Ok(s)) => do_readv(fd, &s, Some(o), RwFlags::empty()),
        (Err(e), _) | (_, Err(e)) => e,
    }
}

/// sys_pwrite64 - write at an offset without moving the file position
/// (an O_APPEND file still appends, like Linux)
pub fn sys_pwrite64(fd: i32, buf: u64, count: u64, offset: i64) -> i64 {
    match (pos_arg(offset), one_seg(buf, count)) {
        (Ok(o), Ok(s)) => do_writev(fd, &s, Some(o), RwFlags::empty(), None),
        (Err(e), _) | (_, Err(e)) => e,
    }
}

/// sys_lseek - reposition the file offset (under f_pos_lock)
pub fn sys_lseek(fd: i32, offset: i64, whence: i32) -> i64 {
    let file = match fget(fd) {
        Ok(f) => f,
        Err(e) => return e.sysret(),
    };
    let _pos = file.pos_lock();
    match file.lseek(offset, whence) {
        Ok(new_pos) => new_pos as i64,
        Err(KernelError::OperationNotSupported) => KernelError::IllegalSeek.sysret(),
        Err(e) => e.sysret(),
    }
}

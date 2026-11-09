//! read/write family (Linux fs/read_write.c): read, write, lseek,
//! pread64, pwrite64 and the shared core used by the vectored calls

use alloc::sync::Arc;

use crate::fs::{File, KernelError, RwFlags};
use crate::uaccess::{UserPtr, access_ok};
use crate::util::error::KernelResult;

use super::iov_iter::{IovDest, IovSource};

use super::iov::IoVec;
use super::syscall::{MAX_RW_COUNT, current_fd_table};

/// The current task's file at `fd`, or EBADF, a path-only (O_PATH)
/// one included (Linux fget/fdget): the fd table lock is dropped before
/// return
pub fn fget(fd: i32) -> Result<Arc<File>, KernelError> {
    fget_raw(fd).and_then(|f| {
        if f.is_path() {
            Err(KernelError::BadFd)
        } else {
            Ok(f)
        }
    })
}

/// As `fget`, a path-only file too (Linux fget_raw/fdget_raw): for the
/// calls that only need where the file is (fstat, fstatfs, fchdir)
pub fn fget_raw(fd: i32) -> Result<Arc<File>, KernelError> {
    current_fd_table().lock().get(fd).ok_or(KernelError::BadFd)
}

/// Install `file` at the current task's lowest free descriptor with fd
/// flags `flags` (Linux get_unused_fd_flags + fd_install): EMFILE past
/// RLIMIT_NOFILE, ENOMEM if the table cannot grow
pub fn fd_install(file: Arc<File>, flags: u32) -> Result<i32, KernelError> {
    let nofile = super::syscall::get_nofile_limit();
    current_fd_table()
        .lock()
        .alloc_with_flags(file, flags, nofile)
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
fn rw_err(e: KernelError, at: Option<u64>, flags: RwFlags) -> KernelError {
    match e {
        KernelError::PermissionDenied => KernelError::BadFd,
        KernelError::OperationNotSupported if !flags.nowait => match at {
            Some(_) => KernelError::IllegalSeek,
            None => KernelError::InvalidArgument,
        },
        e => e,
    }
}

/// Read from `fd` into `segs` at `at`, or at the file position (under
/// f_pos_lock, Linux fdget_pos) when None (Linux vfs_readv)
pub fn do_readv(fd: i32, segs: &[IoVec], at: Option<u64>, flags: RwFlags) -> KernelResult<usize> {
    let file = fget(fd)?;
    if file.is_dir() {
        return Err(KernelError::IsDirectory);
    }
    let _pos = at.is_none().then(|| file.pos_lock());
    verify_area(&file, at, seg_len(segs))?;
    file_readv(&file, segs, at, flags).map_err(|e| rw_err(e, at, flags))
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
) -> KernelResult<usize> {
    let file = fget(fd)?;
    if file.is_dir() {
        return Err(KernelError::IsDirectory);
    }
    let _pos = at.is_none().then(|| file.pos_lock());
    verify_area(&file, at, seg_len(segs))?;
    file_writev(&file, segs, at, flags, append).map_err(|e| rw_err(e, at, flags))
}

/// One user buffer as a segment, cut to MAX_RW_COUNT, after the EFAULT
/// check (Linux import_ubuf)
pub fn import_ubuf(buf: UserPtr<u8>, count: u64) -> Result<[IoVec; 1], KernelError> {
    let count = (count as usize).min(MAX_RW_COUNT);
    if !access_ok(buf.addr(), count) {
        return Err(KernelError::BadAddress);
    }
    Ok([IoVec {
        iov_base: buf.addr(),
        iov_len: count as u64,
    }])
}

/// Explicit offset of pread/pwrite: negative is EINVAL
pub(super) fn pos_arg(offset: i64) -> KernelResult<u64> {
    u64::try_from(offset).map_err(|_| KernelError::InvalidArgument)
}

/// sys_read - read from a file descriptor
pub fn sys_read(fd: i32, buf: UserPtr<u8>, count: u64) -> KernelResult<usize> {
    do_readv(fd, &import_ubuf(buf, count)?, None, RwFlags::empty())
}

/// sys_write - write to a file descriptor
pub fn sys_write(fd: i32, buf: UserPtr<u8>, count: u64) -> KernelResult<usize> {
    do_writev(fd, &import_ubuf(buf, count)?, None, RwFlags::empty(), None)
}

/// sys_pread64 - read at an offset without moving the file position
pub fn sys_pread64(fd: i32, buf: UserPtr<u8>, count: u64, offset: i64) -> KernelResult<usize> {
    let at = pos_arg(offset)?;
    do_readv(fd, &import_ubuf(buf, count)?, Some(at), RwFlags::empty())
}

/// sys_pwrite64 - write at an offset without moving the file position
/// (an O_APPEND file still appends, like Linux)
pub fn sys_pwrite64(fd: i32, buf: UserPtr<u8>, count: u64, offset: i64) -> KernelResult<usize> {
    let at = pos_arg(offset)?;
    do_writev(
        fd,
        &import_ubuf(buf, count)?,
        Some(at),
        RwFlags::empty(),
        None,
    )
}

/// sys_lseek - reposition the file offset (under f_pos_lock)
pub fn sys_lseek(fd: i32, offset: i64, whence: i32) -> KernelResult<u64> {
    let file = fget(fd)?;
    let _pos = file.pos_lock();
    file.lseek(offset, whence).map_err(|e| match e {
        KernelError::OperationNotSupported => KernelError::IllegalSeek,
        e => e,
    })
}

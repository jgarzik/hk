//! read/write family (Linux fs/read_write.c): read, write, lseek,
//! pread64, pwrite64 and the shared core used by the vectored calls

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::arch::Uaccess;
use crate::fs::{File, KernelError, RwFlags};
use crate::uaccess::{UaccessArch, copy_from_user, copy_to_user};

use super::iov::IoVec;
use super::syscall::{MAX_RW_COUNT, current_fd_table};

/// File of `fd`
fn fget(fd: i32) -> Result<Arc<File>, KernelError> {
    current_fd_table().lock().get(fd).ok_or(KernelError::BadFd)
}

/// Bytes the segments cover, capped at MAX_RW_COUNT
fn seg_len(segs: &[IoVec]) -> usize {
    let total = segs.iter().map(|s| s.iov_len as usize).sum::<usize>();
    total.min(MAX_RW_COUNT)
}

/// Copy the user segments into one kernel buffer (at most MAX_RW_COUNT)
fn gather(segs: &[IoVec]) -> Result<Vec<u8>, KernelError> {
    let mut buf = vec![0u8; seg_len(segs)];
    let mut off = 0;
    for s in segs {
        let n = (s.iov_len as usize).min(buf.len() - off);
        if n == 0 {
            continue;
        }
        copy_from_user::<Uaccess>(&mut buf[off..off + n], s.iov_base, n)
            .map_err(|_| KernelError::BadAddress)?;
        off += n;
    }
    Ok(buf)
}

/// Copy `data` out to the user segments in order
fn scatter(segs: &[IoVec], data: &[u8]) -> Result<(), KernelError> {
    let mut off = 0;
    for s in segs {
        let n = (s.iov_len as usize).min(data.len() - off);
        if n == 0 {
            continue;
        }
        copy_to_user::<Uaccess>(s.iov_base, &data[off..off + n])
            .map_err(|_| KernelError::BadAddress)?;
        off += n;
    }
    Ok(())
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
    let mut buf = vec![0u8; seg_len(segs)];
    let _pos = at.is_none().then(|| file.pos_lock());
    let r = match at {
        None => file.read_with_flags(&mut buf, flags),
        Some(o) => file.pread_with_flags(&mut buf, o, flags),
    };
    match r {
        Ok(n) => match scatter(segs, &buf[..n]) {
            Ok(()) => n as i64,
            Err(e) => e.sysret(),
        },
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
    let buf = match gather(segs) {
        Ok(b) => b,
        Err(e) => return e.sysret(),
    };
    let _pos = at.is_none().then(|| file.pos_lock());
    match file.write_at(&buf, at, flags, append) {
        Ok(n) => n as i64,
        Err(e) => rw_err(e, at, flags),
    }
}

/// One user buffer as a segment, after the EFAULT check
fn one_seg(buf: u64, count: u64) -> Result<[IoVec; 1], i64> {
    let count = (count as usize).min(MAX_RW_COUNT);
    if !Uaccess::access_ok(buf, count) {
        return Err(KernelError::BadAddress.sysret());
    }
    Ok([IoVec {
        iov_base: buf,
        iov_len: count as u64,
    }])
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

//! Scatter/gather I/O syscalls (readv, writev, preadv, pwritev, preadv2, pwritev2)

use alloc::vec::Vec;
use core::mem::size_of_val;

use crate::fs::{KernelError, RwFlags};
use crate::uaccess::{UserPtr, UserSlice, access_ok};
use crate::util::error::KernelResult;
use crate::util::kmem::try_vec;

use super::io::{do_readv, do_writev, pos_arg, seg_len};
use super::syscall::{
    MAX_RW_COUNT, RWF_APPEND, RWF_ATOMIC, RWF_DONTCACHE, RWF_DSYNC, RWF_HIPRI, RWF_NOAPPEND,
    RWF_NOWAIT, RWF_SUPPORTED, RWF_SYNC, UIO_MAXIOV,
};

/// Linux iovec structure for scatter/gather I/O
///
/// Used by readv/writev syscalls to specify multiple buffers
/// in a single system call.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct IoVec {
    /// Base address of the buffer (void* in userspace)
    pub iov_base: u64,
    /// Length of the buffer in bytes (size_t)
    pub iov_len: u64,
}
crate::pod!(IoVec { iov_base, iov_len });

/// Copy `iov.len()` iovecs in from `uvec` (Linux copy_iovec_from_user):
/// EFAULT for an array outside user space or a fault, EINVAL for a
/// length negative as ssize_t, element by element in order
fn copy_iovec_from_user(iov: &mut [IoVec], uvec: UserPtr<IoVec>) -> KernelResult<()> {
    let size = size_of_val(iov);
    if !access_ok(uvec.addr(), size) {
        return Err(KernelError::BadAddress);
    }
    let mut r = UserSlice::new(uvec.addr(), size).reader();
    for v in iov {
        *v = r.read::<IoVec>()?;
        if (v.iov_len as i64) < 0 {
            return Err(KernelError::InvalidArgument);
        }
    }
    Ok(())
}

/// The `nr_segs` iovecs at `uvec`, copied in but not checked against
/// user space (Linux iovec_from_user): none for 0, EINVAL above
/// UIO_MAXIOV, then as copy_iovec_from_user
pub fn iovec_from_user(uvec: UserPtr<IoVec>, nr_segs: usize) -> KernelResult<Vec<IoVec>> {
    if nr_segs == 0 {
        return Ok(Vec::new());
    }
    if nr_segs > UIO_MAXIOV {
        return Err(KernelError::InvalidArgument);
    }
    let mut iov = try_vec(nr_segs, IoVec::default())?;
    copy_iovec_from_user(&mut iov, uvec)?;
    Ok(iov)
}

/// The `iovcnt` iovecs at `uvec`, checked and cut to MAX_RW_COUNT in
/// total (Linux import_iovec): EINVAL for a count outside
/// 0..=UIO_MAXIOV or a length negative as ssize_t, EFAULT for a bad
/// array or buffer
pub fn import_iovec(uvec: UserPtr<IoVec>, iovcnt: i32) -> KernelResult<Vec<IoVec>> {
    let n = usize::try_from(iovcnt).map_err(|_| KernelError::InvalidArgument)?;
    let mut iov = iovec_from_user(uvec, n)?;
    // One segment is cut to MAX_RW_COUNT, then checked (Linux
    // __import_iovec_ubuf -> import_ubuf); several are checked whole,
    // then cut so the total stays within MAX_RW_COUNT (__import_iovec)
    let single = iov.len() == 1;
    let mut total = 0usize;
    for v in &mut iov {
        let mut len = v.iov_len as usize;
        if single {
            len = len.min(MAX_RW_COUNT);
        }
        if len != 0 && !access_ok(v.iov_base, len) {
            return Err(KernelError::BadAddress);
        }
        len = len.min(MAX_RW_COUNT - total);
        v.iov_len = len as u64;
        total += len;
    }
    Ok(iov)
}

/// sys_readv - scatter read at the file position
pub fn sys_readv(fd: i32, iov: UserPtr<IoVec>, iovcnt: i32) -> KernelResult<usize> {
    do_readv(
        fd,
        &import_iovec(iov, iovcnt)?,
        None,
        RwFlags::empty(),
        true,
    )
}

/// sys_writev - gather write at the file position (one write: atomic
/// for regular files like Linux)
pub fn sys_writev(fd: i32, iov: UserPtr<IoVec>, iovcnt: i32) -> KernelResult<usize> {
    do_writev(
        fd,
        &import_iovec(iov, iovcnt)?,
        None,
        RwFlags::empty(),
        None,
        true,
    )
}

/// sys_preadv - scatter read at an offset
pub fn sys_preadv(fd: i32, iov: UserPtr<IoVec>, iovcnt: i32, offset: i64) -> KernelResult<usize> {
    let at = pos_arg(offset)?;
    do_readv(
        fd,
        &import_iovec(iov, iovcnt)?,
        Some(at),
        RwFlags::empty(),
        true,
    )
}

/// sys_pwritev - gather write at an offset (O_APPEND still appends)
pub fn sys_pwritev(fd: i32, iov: UserPtr<IoVec>, iovcnt: i32, offset: i64) -> KernelResult<usize> {
    let at = pos_arg(offset)?;
    do_writev(
        fd,
        &import_iovec(iov, iovcnt)?,
        Some(at),
        RwFlags::empty(),
        None,
        true,
    )
}

/// The RWF_* flags of preadv2/pwritev2 as I/O flags (Linux
/// kiocb_set_rw_flags): unknown or unsupported ones are EOPNOTSUPP,
/// RWF_APPEND with RWF_NOAPPEND EINVAL; RWF_SYNC implies RWF_DSYNC.
/// RWF_APPEND and RWF_NOAPPEND go to `File::write_iter`'s `append`.
pub fn rwf_check(flags: i32) -> KernelResult<RwFlags> {
    if flags & !RWF_SUPPORTED != 0 {
        return Err(KernelError::OperationNotSupported);
    }
    if flags & (RWF_APPEND | RWF_NOAPPEND) == RWF_APPEND | RWF_NOAPPEND {
        return Err(KernelError::InvalidArgument);
    }
    if flags & (RWF_ATOMIC | RWF_DONTCACHE) != 0 {
        return Err(KernelError::OperationNotSupported);
    }
    let mut f = RwFlags::empty();
    for (rwf, iocb) in [
        (RWF_HIPRI, RwFlags::HIPRI),
        (RWF_DSYNC, RwFlags::DSYNC),
        (RWF_SYNC, RwFlags::DSYNC | RwFlags::SYNC),
        (RWF_NOWAIT, RwFlags::NOWAIT),
    ] {
        if flags & rwf != 0 {
            f |= iocb;
        }
    }
    Ok(f)
}

/// What RWF_APPEND / RWF_NOAPPEND say of O_APPEND for one write
pub fn rwf_append(flags: i32) -> Option<bool> {
    if flags & RWF_APPEND != 0 {
        Some(true)
    } else if flags & RWF_NOAPPEND != 0 {
        Some(false)
    } else {
        None
    }
}

/// `flags` (a file's I/O flags, its O_APPEND as APPEND) with the
/// RWF_APPEND / RWF_NOAPPEND of `rwf` over APPEND (Linux
/// kiocb_set_rw_flags: IOCB_APPEND set, or cleared), for an I/O that
/// carries its flags whole (an asynchronous O_DIRECT one)
pub fn rwf_set_append(mut flags: RwFlags, rwf: i32) -> RwFlags {
    if let Some(a) = rwf_append(rwf) {
        flags.set(RwFlags::APPEND, a);
    }
    flags
}

/// Offset of preadv2/pwritev2: -1 is the file position
fn pos2(offset: i64) -> KernelResult<Option<u64>> {
    if offset == -1 {
        Ok(None)
    } else {
        pos_arg(offset).map(Some)
    }
}

/// sys_preadv2 - preadv with RWF_* flags (offset -1: file position)
pub fn sys_preadv2(
    fd: i32,
    iov: UserPtr<IoVec>,
    iovcnt: i32,
    offset: i64,
    flags: i32,
) -> KernelResult<usize> {
    let at = pos2(offset)?;
    let segs = import_iovec(iov, iovcnt)?;
    // Nothing to read is 0 before the flags are looked at (Linux
    // vfs_readv before kiocb_set_rw_flags)
    let f = if seg_len(&segs) == 0 {
        RwFlags::empty()
    } else {
        rwf_check(flags)?
    };
    do_readv(fd, &segs, at, f, true)
}

/// sys_pwritev2 - pwritev with RWF_* flags (offset -1: file position;
/// RWF_APPEND / RWF_NOAPPEND override O_APPEND; RWF_SYNC/DSYNC make the
/// write synchronous where O_DSYNC would)
pub fn sys_pwritev2(
    fd: i32,
    iov: UserPtr<IoVec>,
    iovcnt: i32,
    offset: i64,
    flags: i32,
) -> KernelResult<usize> {
    let append = rwf_append(flags);
    let at = pos2(offset)?;
    let segs = import_iovec(iov, iovcnt)?;
    // As in sys_preadv2 (Linux vfs_writev)
    let f = if seg_len(&segs) == 0 {
        RwFlags::empty()
    } else {
        rwf_check(flags)?
    };
    do_writev(fd, &segs, at, f, append, true)
}

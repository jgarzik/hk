//! Scatter/gather I/O syscalls (readv, writev, preadv, pwritev, preadv2, pwritev2)

use alloc::vec;

use crate::fs::{KernelError, RwFlags};
use crate::uaccess::{UserPtr, access_ok, copy_from_user};
use crate::util::error::KernelResult;

use super::io::{do_readv, do_writev, pos_arg};
use super::syscall::{
    IOV_MAX, MAX_RW_COUNT, RWF_APPEND, RWF_ATOMIC, RWF_DONTCACHE, RWF_DSYNC, RWF_NOAPPEND,
    RWF_NOWAIT, RWF_SUPPORTED, RWF_SYNC, sys_fsync,
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

/// The `iovcnt` iovecs at `iov_ptr`, checked and cut to MAX_RW_COUNT
/// in total (Linux import_iovec): EINVAL for a count outside
/// 0..=IOV_MAX or a length negative as ssize_t, EFAULT for a bad array
/// or buffer
pub fn import_iovec(
    iov: UserPtr<IoVec>,
    iovcnt: i32,
) -> Result<alloc::vec::Vec<IoVec>, KernelError> {
    let iov_ptr = iov.addr();
    // Check iovcnt bounds
    if iovcnt < 0 {
        return Err(KernelError::InvalidArgument);
    }
    if iovcnt == 0 {
        return Ok(alloc::vec::Vec::new());
    }
    if iovcnt as usize > IOV_MAX {
        return Err(KernelError::InvalidArgument);
    }

    let iovcnt = iovcnt as usize;
    let iov_size = core::mem::size_of::<IoVec>();
    let total_size = iovcnt * iov_size;

    // Validate iovec array pointer
    if !access_ok(iov_ptr, total_size) {
        return Err(KernelError::BadAddress);
    }

    // Copy iovec array from user space
    let mut iovecs = vec![IoVec::default(); iovcnt];
    // SAFETY: IoVec is repr(C) plain data; the byte view covers exactly the
    // `iovcnt` initialized elements of `iovecs`.
    let bytes =
        unsafe { core::slice::from_raw_parts_mut(iovecs.as_mut_ptr().cast::<u8>(), total_size) };
    if copy_from_user(bytes, iov_ptr, total_size).is_err() {
        return Err(KernelError::BadAddress);
    }

    // A length negative as ssize_t is EINVAL, for any segment before
    // any address is checked (Linux copy_iovec_from_user)
    if iovecs.iter().any(|v| (v.iov_len as i64) < 0) {
        return Err(KernelError::InvalidArgument);
    }
    // One segment is cut to MAX_RW_COUNT, then checked (Linux
    // import_ubuf); several are checked whole, then cut so the total
    // stays within MAX_RW_COUNT (__import_iovec)
    let single = iovecs.len() == 1;
    let mut total = 0usize;
    for iov in &mut iovecs {
        let mut len = iov.iov_len as usize;
        if single {
            len = len.min(MAX_RW_COUNT);
        }
        if len != 0 && !access_ok(iov.iov_base, len) {
            return Err(KernelError::BadAddress);
        }
        len = len.min(MAX_RW_COUNT - total);
        iov.iov_len = len as u64;
        total += len;
    }

    Ok(iovecs)
}

/// sys_readv - scatter read at the file position
pub fn sys_readv(fd: i32, iov: UserPtr<IoVec>, iovcnt: i32) -> KernelResult<usize> {
    do_readv(fd, &import_iovec(iov, iovcnt)?, None, RwFlags::empty())
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
    )
}

/// sys_preadv - scatter read at an offset
pub fn sys_preadv(fd: i32, iov: UserPtr<IoVec>, iovcnt: i32, offset: i64) -> KernelResult<usize> {
    let at = pos_arg(offset)?;
    do_readv(fd, &import_iovec(iov, iovcnt)?, Some(at), RwFlags::empty())
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
    )
}

/// RWF_* validation shared by preadv2/pwritev2: unknown or unsupported
/// flags are EOPNOTSUPP
fn rwf_check(flags: i32) -> KernelResult<RwFlags> {
    if flags & !RWF_SUPPORTED != 0 || flags & (RWF_ATOMIC | RWF_DONTCACHE) != 0 {
        return Err(KernelError::OperationNotSupported);
    }
    Ok(if flags & RWF_NOWAIT != 0 {
        RwFlags::with_nowait()
    } else {
        RwFlags::empty()
    })
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
    let f = rwf_check(flags)?;
    let at = pos2(offset)?;
    do_readv(fd, &import_iovec(iov, iovcnt)?, at, f)
}

/// sys_pwritev2 - pwritev with RWF_* flags (offset -1: file position;
/// RWF_APPEND / RWF_NOAPPEND override O_APPEND; RWF_SYNC/DSYNC sync)
pub fn sys_pwritev2(
    fd: i32,
    iov: UserPtr<IoVec>,
    iovcnt: i32,
    offset: i64,
    flags: i32,
) -> KernelResult<usize> {
    let append = if flags & RWF_APPEND != 0 {
        Some(true)
    } else if flags & RWF_NOAPPEND != 0 {
        Some(false)
    } else {
        None
    };
    let f = rwf_check(flags)?;
    let at = pos2(offset)?;
    let n = do_writev(fd, &import_iovec(iov, iovcnt)?, at, f, append)?;
    if n > 0 && flags & (RWF_SYNC | RWF_DSYNC) != 0 {
        let _ = sys_fsync(fd);
    }
    Ok(n)
}

//! Scatter/gather I/O syscalls (readv, writev, preadv, pwritev, preadv2, pwritev2)

use alloc::vec;

use crate::arch::Uaccess;
use crate::fs::{KernelError, RwFlags};
use crate::uaccess::{UaccessArch, copy_from_user};

use super::io::{do_readv, do_writev};
use super::syscall::{
    IOV_MAX, RWF_APPEND, RWF_ATOMIC, RWF_DONTCACHE, RWF_DSYNC, RWF_NOAPPEND, RWF_NOWAIT,
    RWF_SUPPORTED, RWF_SYNC, sys_fsync,
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

/// Validate an iovec array from user space
///
/// Copies and validates the iovec array. Returns the validated iovecs
/// or an error code.
///
/// # Arguments
/// * `iov_ptr` - User pointer to array of iovec structures
/// * `iovcnt` - Number of iovec structures
///
/// # Returns
/// * `Ok(Vec<IoVec>)` - Validated iovec array
/// * `Err(errno)` - Error code (EINVAL, EFAULT)
fn validate_iovec_array(iov_ptr: u64, iovcnt: i32) -> Result<alloc::vec::Vec<IoVec>, i64> {
    // Check iovcnt bounds
    if iovcnt < 0 {
        return Err(KernelError::InvalidArgument.sysret());
    }
    if iovcnt == 0 {
        return Ok(alloc::vec::Vec::new());
    }
    if iovcnt as usize > IOV_MAX {
        return Err(KernelError::InvalidArgument.sysret());
    }

    let iovcnt = iovcnt as usize;
    let iov_size = core::mem::size_of::<IoVec>();
    let total_size = iovcnt * iov_size;

    // Validate iovec array pointer
    if !Uaccess::access_ok(iov_ptr, total_size) {
        return Err(KernelError::BadAddress.sysret());
    }

    // Copy iovec array from user space
    let mut iovecs = vec![IoVec::default(); iovcnt];
    // SAFETY: IoVec is repr(C) plain data; the byte view covers exactly the
    // `iovcnt` initialized elements of `iovecs`.
    let bytes =
        unsafe { core::slice::from_raw_parts_mut(iovecs.as_mut_ptr() as *mut u8, total_size) };
    if copy_from_user::<Uaccess>(bytes, iov_ptr, total_size).is_err() {
        return Err(KernelError::BadAddress.sysret());
    }

    // Validate each iovec buffer (non-zero length only)
    for iov in &iovecs {
        if iov.iov_len == 0 {
            continue;
        }
        // Validate buffer address
        if !Uaccess::access_ok(iov.iov_base, iov.iov_len as usize) {
            return Err(KernelError::BadAddress.sysret());
        }
    }

    Ok(iovecs)
}

/// Offset argument of preadv/pwritev: negative is EINVAL
fn pos_arg(offset: i64) -> Result<u64, i64> {
    u64::try_from(offset).map_err(|_| KernelError::InvalidArgument.sysret())
}

/// sys_readv - scatter read at the file position
pub fn sys_readv(fd: i32, iov_ptr: u64, iovcnt: i32) -> i64 {
    match validate_iovec_array(iov_ptr, iovcnt) {
        Ok(v) => do_readv(fd, &v, None, RwFlags::empty()),
        Err(e) => e,
    }
}

/// sys_writev - gather write at the file position (one write: atomic
/// for regular files like Linux)
pub fn sys_writev(fd: i32, iov_ptr: u64, iovcnt: i32) -> i64 {
    match validate_iovec_array(iov_ptr, iovcnt) {
        Ok(v) => do_writev(fd, &v, None, RwFlags::empty(), None),
        Err(e) => e,
    }
}

/// sys_preadv - scatter read at an offset
pub fn sys_preadv(fd: i32, iov_ptr: u64, iovcnt: i32, offset: i64) -> i64 {
    match (pos_arg(offset), validate_iovec_array(iov_ptr, iovcnt)) {
        (Ok(o), Ok(v)) => do_readv(fd, &v, Some(o), RwFlags::empty()),
        (Err(e), _) | (_, Err(e)) => e,
    }
}

/// sys_pwritev - gather write at an offset (O_APPEND still appends)
pub fn sys_pwritev(fd: i32, iov_ptr: u64, iovcnt: i32, offset: i64) -> i64 {
    match (pos_arg(offset), validate_iovec_array(iov_ptr, iovcnt)) {
        (Ok(o), Ok(v)) => do_writev(fd, &v, Some(o), RwFlags::empty(), None),
        (Err(e), _) | (_, Err(e)) => e,
    }
}

/// RWF_* validation shared by preadv2/pwritev2: unknown or unsupported
/// flags are EOPNOTSUPP
fn rwf_check(flags: i32) -> Result<RwFlags, i64> {
    if flags & !RWF_SUPPORTED != 0 || flags & (RWF_ATOMIC | RWF_DONTCACHE) != 0 {
        return Err(KernelError::OperationNotSupported.sysret());
    }
    Ok(if flags & RWF_NOWAIT != 0 {
        RwFlags::with_nowait()
    } else {
        RwFlags::empty()
    })
}

/// Offset of preadv2/pwritev2: -1 is the file position
fn pos2(offset: i64) -> Result<Option<u64>, i64> {
    if offset == -1 {
        Ok(None)
    } else {
        pos_arg(offset).map(Some)
    }
}

/// sys_preadv2 - preadv with RWF_* flags (offset -1: file position)
pub fn sys_preadv2(fd: i32, iov_ptr: u64, iovcnt: i32, offset: i64, flags: i32) -> i64 {
    let r = rwf_check(flags).and_then(|f| {
        let at = pos2(offset)?;
        let v = validate_iovec_array(iov_ptr, iovcnt)?;
        Ok(do_readv(fd, &v, at, f))
    });
    r.unwrap_or_else(|e| e)
}

/// sys_pwritev2 - pwritev with RWF_* flags (offset -1: file position;
/// RWF_APPEND / RWF_NOAPPEND override O_APPEND; RWF_SYNC/DSYNC sync)
pub fn sys_pwritev2(fd: i32, iov_ptr: u64, iovcnt: i32, offset: i64, flags: i32) -> i64 {
    let append = if flags & RWF_APPEND != 0 {
        Some(true)
    } else if flags & RWF_NOAPPEND != 0 {
        Some(false)
    } else {
        None
    };
    let r = rwf_check(flags).and_then(|f| {
        let at = pos2(offset)?;
        let v = validate_iovec_array(iov_ptr, iovcnt)?;
        Ok(do_writev(fd, &v, at, f, append))
    });
    let n = r.unwrap_or_else(|e| e);
    if n > 0 && flags & (RWF_SYNC | RWF_DSYNC) != 0 {
        let _ = sys_fsync(fd);
    }
    n
}

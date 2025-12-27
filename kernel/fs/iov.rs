//! Scatter/gather I/O syscalls (readv, writev, preadv, pwritev, preadv2, pwritev2)

use alloc::vec;

use crate::arch::Uaccess;
use crate::console::console_write;
use crate::fs::{KernelError, RwFlags};
use crate::uaccess::{UaccessArch, copy_to_user};

use super::syscall::{
    IOV_MAX, MAX_RW_COUNT, RWF_APPEND, RWF_ATOMIC, RWF_DONTCACHE, RWF_DSYNC, RWF_NOWAIT,
    RWF_SUPPORTED, RWF_SYNC, SMALL_BUF_SIZE, current_fd_table, sys_fsync,
};

/// Linux iovec structure for scatter/gather I/O
///
/// Used by readv/writev syscalls to specify multiple buffers
/// in a single system call.
#[repr(C)]
#[derive(Copy, Clone)]
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
    let mut iovecs = alloc::vec::Vec::with_capacity(iovcnt);

    unsafe {
        Uaccess::user_access_begin();
        for i in 0..iovcnt {
            let iov = core::ptr::read((iov_ptr as *const IoVec).add(i));
            iovecs.push(iov);
        }
        Uaccess::user_access_end();
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

/// sys_readv - scatter read from a file descriptor
///
/// Reads data from fd into multiple buffers (scatter I/O).
///
/// # Arguments
/// * `fd` - File descriptor to read from
/// * `iov_ptr` - User pointer to array of iovec structures
/// * `iovcnt` - Number of iovec structures
///
/// # Returns
/// Total bytes read on success, negative errno on error.
pub fn sys_readv(fd: i32, iov_ptr: u64, iovcnt: i32) -> i64 {
    // Validate and copy iovec array
    let iovecs = match validate_iovec_array(iov_ptr, iovcnt) {
        Ok(v) => v,
        Err(e) => return e,
    };

    // Empty iovec array - return 0
    if iovecs.is_empty() {
        return 0;
    }

    // Handle special fds (stdin)
    if fd == 0 {
        return 0; // stdin not implemented
    }

    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    // Check if trying to read a directory
    if file.is_dir() {
        return KernelError::IsDirectory.sysret();
    }

    let mut total_read: usize = 0;

    // Process each iovec
    for iov in &iovecs {
        if iov.iov_len == 0 {
            continue;
        }

        // Limit to MAX_RW_COUNT - total already read
        let remaining_allowed = MAX_RW_COUNT.saturating_sub(total_read);
        if remaining_allowed == 0 {
            break;
        }

        let count = core::cmp::min(iov.iov_len as usize, remaining_allowed);

        // Use stack buffer for small reads, heap for large
        if count <= SMALL_BUF_SIZE {
            let mut stack_buf = [0u8; SMALL_BUF_SIZE];
            let read_buf = &mut stack_buf[..count];

            let bytes_read = match file.read(read_buf) {
                Ok(n) => n,
                Err(KernelError::IsDirectory) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        KernelError::IsDirectory.sysret()
                    };
                }
                Err(KernelError::PermissionDenied) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        KernelError::BadFd.sysret()
                    };
                }
                Err(_) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        KernelError::InvalidArgument.sysret()
                    };
                }
            };

            if bytes_read > 0
                && copy_to_user::<Uaccess>(iov.iov_base, &read_buf[..bytes_read]).is_err()
            {
                return if total_read > 0 {
                    total_read as i64
                } else {
                    KernelError::BadAddress.sysret()
                };
            }

            total_read += bytes_read;

            // Short read means EOF or no more data - stop
            if bytes_read < count {
                break;
            }
        } else {
            let mut kernel_buf = vec![0u8; count];

            let bytes_read = match file.read(&mut kernel_buf) {
                Ok(n) => n,
                Err(KernelError::IsDirectory) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        KernelError::IsDirectory.sysret()
                    };
                }
                Err(KernelError::PermissionDenied) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        KernelError::BadFd.sysret()
                    };
                }
                Err(_) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        KernelError::InvalidArgument.sysret()
                    };
                }
            };

            if bytes_read > 0
                && copy_to_user::<Uaccess>(iov.iov_base, &kernel_buf[..bytes_read]).is_err()
            {
                return if total_read > 0 {
                    total_read as i64
                } else {
                    KernelError::BadAddress.sysret()
                };
            }

            total_read += bytes_read;

            if bytes_read < count {
                break;
            }
        }
    }

    total_read as i64
}

/// Helper for writev to stdout/stderr (console)
///
/// Gathers data from all iovecs and writes to console.
fn writev_console(iovecs: &[IoVec]) -> i64 {
    let mut total_written: usize = 0;

    for iov in iovecs {
        if iov.iov_len == 0 {
            continue;
        }

        let count = core::cmp::min(iov.iov_len as usize, MAX_RW_COUNT - total_written);
        if count == 0 {
            break;
        }

        // Validate user buffer (already validated in validate_iovec_array, but double-check)
        if !Uaccess::access_ok(iov.iov_base, count) {
            return if total_written > 0 {
                total_written as i64
            } else {
                KernelError::BadAddress.sysret()
            };
        }

        if count <= SMALL_BUF_SIZE {
            let mut stack_buf = [0u8; SMALL_BUF_SIZE];
            let buf = &mut stack_buf[..count];

            unsafe {
                Uaccess::user_access_begin();
                core::ptr::copy_nonoverlapping(iov.iov_base as *const u8, buf.as_mut_ptr(), count);
                Uaccess::user_access_end();
            }

            console_write(buf);
        } else {
            let mut kernel_buf = vec![0u8; count];

            unsafe {
                Uaccess::user_access_begin();
                core::ptr::copy_nonoverlapping(
                    iov.iov_base as *const u8,
                    kernel_buf.as_mut_ptr(),
                    count,
                );
                Uaccess::user_access_end();
            }

            console_write(&kernel_buf);
        }

        total_written += count;
    }

    total_written as i64
}

/// sys_writev - gather write to a file descriptor
///
/// Writes data from multiple buffers to fd (gather I/O).
///
/// # Arguments
/// * `fd` - File descriptor to write to
/// * `iov_ptr` - User pointer to array of iovec structures
/// * `iovcnt` - Number of iovec structures
///
/// # Returns
/// Total bytes written on success, negative errno on error.
pub fn sys_writev(fd: i32, iov_ptr: u64, iovcnt: i32) -> i64 {
    // Validate and copy iovec array
    let iovecs = match validate_iovec_array(iov_ptr, iovcnt) {
        Ok(v) => v,
        Err(e) => return e,
    };

    // Empty iovec array - return 0
    if iovecs.is_empty() {
        return 0;
    }

    // Handle special fds (stdout, stderr) - gather all data first
    if fd == 1 || fd == 2 {
        return writev_console(&iovecs);
    }

    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    let mut total_written: usize = 0;

    // Process each iovec
    for iov in &iovecs {
        if iov.iov_len == 0 {
            continue;
        }

        // Limit to MAX_RW_COUNT - total already written
        let remaining_allowed = MAX_RW_COUNT.saturating_sub(total_written);
        if remaining_allowed == 0 {
            break;
        }

        let count = core::cmp::min(iov.iov_len as usize, remaining_allowed);

        // Use stack buffer for small writes, heap for large
        if count <= SMALL_BUF_SIZE {
            let mut stack_buf = [0u8; SMALL_BUF_SIZE];
            let write_buf = &mut stack_buf[..count];

            // Copy from user space
            unsafe {
                Uaccess::user_access_begin();
                core::ptr::copy_nonoverlapping(
                    iov.iov_base as *const u8,
                    write_buf.as_mut_ptr(),
                    count,
                );
                Uaccess::user_access_end();
            }

            let bytes_written = match file.write(write_buf) {
                Ok(n) => n,
                Err(KernelError::PermissionDenied) => {
                    return if total_written > 0 {
                        total_written as i64
                    } else {
                        KernelError::BadFd.sysret()
                    };
                }
                Err(_) => {
                    return if total_written > 0 {
                        total_written as i64
                    } else {
                        KernelError::InvalidArgument.sysret()
                    };
                }
            };

            total_written += bytes_written;

            // Short write - stop
            if bytes_written < count {
                break;
            }
        } else {
            let mut kernel_buf = vec![0u8; count];

            unsafe {
                Uaccess::user_access_begin();
                core::ptr::copy_nonoverlapping(
                    iov.iov_base as *const u8,
                    kernel_buf.as_mut_ptr(),
                    count,
                );
                Uaccess::user_access_end();
            }

            let bytes_written = match file.write(&kernel_buf) {
                Ok(n) => n,
                Err(KernelError::PermissionDenied) => {
                    return if total_written > 0 {
                        total_written as i64
                    } else {
                        KernelError::BadFd.sysret()
                    };
                }
                Err(_) => {
                    return if total_written > 0 {
                        total_written as i64
                    } else {
                        KernelError::InvalidArgument.sysret()
                    };
                }
            };

            total_written += bytes_written;

            if bytes_written < count {
                break;
            }
        }
    }

    total_written as i64
}

/// sys_preadv - positioned scatter read from a file descriptor
///
/// Reads data from fd at the given offset into multiple buffers (scatter I/O)
/// without modifying the file position.
///
/// # Arguments
/// * `fd` - File descriptor to read from
/// * `iov_ptr` - User pointer to array of iovec structures
/// * `iovcnt` - Number of iovec structures
/// * `offset` - File offset to read from
///
/// # Returns
/// Total bytes read on success, negative errno on error.
/// Returns -ESPIPE if fd refers to a non-seekable file (pipe, socket).
pub fn sys_preadv(fd: i32, iov_ptr: u64, iovcnt: i32, offset: i64) -> i64 {
    // Validate offset
    if offset < 0 {
        return KernelError::InvalidArgument.sysret();
    }
    let mut current_offset = offset as u64;

    // Validate and copy iovec array
    let iovecs = match validate_iovec_array(iov_ptr, iovcnt) {
        Ok(v) => v,
        Err(e) => return e,
    };

    // Empty iovec array - return 0
    if iovecs.is_empty() {
        return 0;
    }

    // Handle stdin - pipes don't support positioned I/O
    if fd == 0 {
        return KernelError::IllegalSeek.sysret();
    }

    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    // Cannot preadv from directory
    if file.is_dir() {
        return KernelError::IsDirectory.sysret();
    }

    let mut total_read: usize = 0;

    // Process each iovec
    for iov in &iovecs {
        if iov.iov_len == 0 {
            continue;
        }

        // Limit to MAX_RW_COUNT - total already read
        let remaining_allowed = MAX_RW_COUNT.saturating_sub(total_read);
        if remaining_allowed == 0 {
            break;
        }

        let count = core::cmp::min(iov.iov_len as usize, remaining_allowed);

        // Use stack buffer for small reads, heap for large
        if count <= SMALL_BUF_SIZE {
            let mut stack_buf = [0u8; SMALL_BUF_SIZE];
            let read_buf = &mut stack_buf[..count];

            // Use positioned read (doesn't modify file position)
            let bytes_read = match file.pread(read_buf, current_offset) {
                Ok(n) => n,
                Err(KernelError::OperationNotSupported) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        KernelError::IllegalSeek.sysret() // non-seekable file
                    };
                }
                Err(KernelError::PermissionDenied) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        KernelError::BadFd.sysret()
                    };
                }
                Err(_) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        KernelError::InvalidArgument.sysret()
                    };
                }
            };

            // Copy to user space
            unsafe {
                Uaccess::user_access_begin();
                core::ptr::copy_nonoverlapping(
                    read_buf.as_ptr(),
                    iov.iov_base as *mut u8,
                    bytes_read,
                );
                Uaccess::user_access_end();
            }

            total_read += bytes_read;
            current_offset += bytes_read as u64;

            // Short read (EOF or partial) - stop
            if bytes_read < count {
                break;
            }
        } else {
            let mut kernel_buf = vec![0u8; count];

            // Use positioned read (doesn't modify file position)
            let bytes_read = match file.pread(&mut kernel_buf, current_offset) {
                Ok(n) => n,
                Err(KernelError::OperationNotSupported) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        KernelError::IllegalSeek.sysret()
                    };
                }
                Err(KernelError::PermissionDenied) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        KernelError::BadFd.sysret()
                    };
                }
                Err(_) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        KernelError::InvalidArgument.sysret()
                    };
                }
            };

            // Copy to user space
            unsafe {
                Uaccess::user_access_begin();
                core::ptr::copy_nonoverlapping(
                    kernel_buf.as_ptr(),
                    iov.iov_base as *mut u8,
                    bytes_read,
                );
                Uaccess::user_access_end();
            }

            total_read += bytes_read;
            current_offset += bytes_read as u64;

            if bytes_read < count {
                break;
            }
        }
    }

    total_read as i64
}

/// sys_pwritev - positioned gather write to a file descriptor
///
/// Writes data from multiple buffers to fd at the given offset (gather I/O)
/// without modifying the file position.
///
/// # Arguments
/// * `fd` - File descriptor to write to
/// * `iov_ptr` - User pointer to array of iovec structures
/// * `iovcnt` - Number of iovec structures
/// * `offset` - File offset to write to
///
/// # Returns
/// Total bytes written on success, negative errno on error.
/// Returns -ESPIPE if fd refers to a non-seekable file (pipe, socket).
pub fn sys_pwritev(fd: i32, iov_ptr: u64, iovcnt: i32, offset: i64) -> i64 {
    // Validate offset
    if offset < 0 {
        return KernelError::InvalidArgument.sysret();
    }
    let mut current_offset = offset as u64;

    // Validate and copy iovec array
    let iovecs = match validate_iovec_array(iov_ptr, iovcnt) {
        Ok(v) => v,
        Err(e) => return e,
    };

    // Empty iovec array - return 0
    if iovecs.is_empty() {
        return 0;
    }

    // Handle stdout/stderr - these don't support positioned I/O
    if fd == 1 || fd == 2 {
        return KernelError::IllegalSeek.sysret();
    }

    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    // Cannot pwritev to directory
    if file.is_dir() {
        return KernelError::IsDirectory.sysret();
    }

    let mut total_written: usize = 0;

    // Process each iovec
    for iov in &iovecs {
        if iov.iov_len == 0 {
            continue;
        }

        // Limit to MAX_RW_COUNT - total already written
        let remaining_allowed = MAX_RW_COUNT.saturating_sub(total_written);
        if remaining_allowed == 0 {
            break;
        }

        let count = core::cmp::min(iov.iov_len as usize, remaining_allowed);

        // Use stack buffer for small writes, heap for large
        if count <= SMALL_BUF_SIZE {
            let mut stack_buf = [0u8; SMALL_BUF_SIZE];
            let write_buf = &mut stack_buf[..count];

            // Copy from user space
            unsafe {
                Uaccess::user_access_begin();
                core::ptr::copy_nonoverlapping(
                    iov.iov_base as *const u8,
                    write_buf.as_mut_ptr(),
                    count,
                );
                Uaccess::user_access_end();
            }

            // Use positioned write (doesn't modify file position)
            let bytes_written = match file.pwrite(write_buf, current_offset) {
                Ok(n) => n,
                Err(KernelError::OperationNotSupported) => {
                    return if total_written > 0 {
                        total_written as i64
                    } else {
                        KernelError::IllegalSeek.sysret() // non-seekable file
                    };
                }
                Err(KernelError::PermissionDenied) => {
                    return if total_written > 0 {
                        total_written as i64
                    } else {
                        KernelError::BadFd.sysret()
                    };
                }
                Err(_) => {
                    return if total_written > 0 {
                        total_written as i64
                    } else {
                        KernelError::InvalidArgument.sysret()
                    };
                }
            };

            total_written += bytes_written;
            current_offset += bytes_written as u64;

            // Short write - stop
            if bytes_written < count {
                break;
            }
        } else {
            let mut kernel_buf = vec![0u8; count];

            unsafe {
                Uaccess::user_access_begin();
                core::ptr::copy_nonoverlapping(
                    iov.iov_base as *const u8,
                    kernel_buf.as_mut_ptr(),
                    count,
                );
                Uaccess::user_access_end();
            }

            // Use positioned write (doesn't modify file position)
            let bytes_written = match file.pwrite(&kernel_buf, current_offset) {
                Ok(n) => n,
                Err(KernelError::OperationNotSupported) => {
                    return if total_written > 0 {
                        total_written as i64
                    } else {
                        KernelError::IllegalSeek.sysret()
                    };
                }
                Err(KernelError::PermissionDenied) => {
                    return if total_written > 0 {
                        total_written as i64
                    } else {
                        KernelError::BadFd.sysret()
                    };
                }
                Err(_) => {
                    return if total_written > 0 {
                        total_written as i64
                    } else {
                        KernelError::InvalidArgument.sysret()
                    };
                }
            };

            total_written += bytes_written;
            current_offset += bytes_written as u64;

            if bytes_written < count {
                break;
            }
        }
    }

    total_written as i64
}

/// sys_preadv2 - positioned scatter read with flags
///
/// Enhanced version of preadv that supports per-I/O flags (RWF_*).
///
/// # Arguments
/// * `fd` - File descriptor to read from
/// * `iov_ptr` - User pointer to array of iovec structures
/// * `iovcnt` - Number of iovec structures
/// * `offset` - File offset to read from, or -1 to use current file position
/// * `flags` - RWF_* flags for this I/O operation
///
/// # Returns
/// Total bytes read on success, negative errno on error.
/// Returns -EOPNOTSUPP for unsupported flags.
pub fn sys_preadv2(fd: i32, iov_ptr: u64, iovcnt: i32, offset: i64, flags: i32) -> i64 {
    // Validate flags - unknown flags return EOPNOTSUPP
    if flags & !RWF_SUPPORTED != 0 {
        return KernelError::OperationNotSupported.sysret();
    }

    // Unsupported flags - return EOPNOTSUPP
    if flags & (RWF_ATOMIC | RWF_DONTCACHE) != 0 {
        return KernelError::OperationNotSupported.sysret();
    }

    // If RWF_NOWAIT not set, delegate to existing syscalls
    if flags & RWF_NOWAIT == 0 {
        if offset == -1 {
            return sys_readv(fd, iov_ptr, iovcnt);
        }
        return sys_preadv(fd, iov_ptr, iovcnt, offset);
    }

    // RWF_NOWAIT handling - use *_with_flags methods
    let rw_flags = RwFlags::with_nowait();

    // Validate and copy iovec array
    let iovecs = match validate_iovec_array(iov_ptr, iovcnt) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if iovecs.is_empty() {
        return 0;
    }

    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    if file.is_dir() {
        return KernelError::IsDirectory.sysret();
    }

    // For offset == -1, use current file position
    let use_position = offset == -1;
    let mut current_offset = if use_position {
        file.get_pos()
    } else {
        offset as u64
    };

    let mut total_read: usize = 0;

    for iov in &iovecs {
        if iov.iov_len == 0 {
            continue;
        }

        let remaining_allowed = MAX_RW_COUNT.saturating_sub(total_read);
        if remaining_allowed == 0 {
            break;
        }

        let count = core::cmp::min(iov.iov_len as usize, remaining_allowed);

        if count <= SMALL_BUF_SIZE {
            let mut stack_buf = [0u8; SMALL_BUF_SIZE];
            let read_buf = &mut stack_buf[..count];

            let result = if use_position {
                file.read_with_flags(read_buf, rw_flags)
            } else {
                file.pread_with_flags(read_buf, current_offset, rw_flags)
            };

            let bytes_read = match result {
                Ok(n) => n,
                Err(KernelError::WouldBlock) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        KernelError::WouldBlock.sysret()
                    };
                }
                Err(KernelError::OperationNotSupported) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        KernelError::OperationNotSupported.sysret()
                    };
                }
                Err(KernelError::PermissionDenied) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        KernelError::BadFd.sysret()
                    };
                }
                Err(_) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        KernelError::InvalidArgument.sysret()
                    };
                }
            };

            if bytes_read > 0
                && copy_to_user::<Uaccess>(iov.iov_base, &read_buf[..bytes_read]).is_err()
            {
                return if total_read > 0 {
                    total_read as i64
                } else {
                    KernelError::BadAddress.sysret()
                };
            }

            total_read += bytes_read;
            current_offset += bytes_read as u64;

            if bytes_read < count {
                break;
            }
        } else {
            let mut kernel_buf = vec![0u8; count];

            let result = if use_position {
                file.read_with_flags(&mut kernel_buf, rw_flags)
            } else {
                file.pread_with_flags(&mut kernel_buf, current_offset, rw_flags)
            };

            let bytes_read = match result {
                Ok(n) => n,
                Err(KernelError::WouldBlock) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        KernelError::WouldBlock.sysret()
                    };
                }
                Err(KernelError::OperationNotSupported) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        KernelError::OperationNotSupported.sysret()
                    };
                }
                Err(KernelError::PermissionDenied) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        KernelError::BadFd.sysret()
                    };
                }
                Err(_) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        KernelError::InvalidArgument.sysret()
                    };
                }
            };

            if bytes_read > 0
                && copy_to_user::<Uaccess>(iov.iov_base, &kernel_buf[..bytes_read]).is_err()
            {
                return if total_read > 0 {
                    total_read as i64
                } else {
                    KernelError::BadAddress.sysret()
                };
            }

            total_read += bytes_read;
            current_offset += bytes_read as u64;

            if bytes_read < count {
                break;
            }
        }
    }

    // Update file position if using current position
    if use_position && total_read > 0 {
        file.advance_pos(total_read as u64);
    }

    total_read as i64
}

/// sys_pwritev2 - positioned gather write with flags
///
/// Enhanced version of pwritev that supports per-I/O flags (RWF_*).
///
/// # Arguments
/// * `fd` - File descriptor to write to
/// * `iov_ptr` - User pointer to array of iovec structures
/// * `iovcnt` - Number of iovec structures
/// * `offset` - File offset to write to, or -1 to use current file position
/// * `flags` - RWF_* flags for this I/O operation
///
/// # Returns
/// Total bytes written on success, negative errno on error.
/// Returns -EOPNOTSUPP for unsupported flags.
pub fn sys_pwritev2(fd: i32, iov_ptr: u64, iovcnt: i32, offset: i64, flags: i32) -> i64 {
    // Validate flags - unknown flags return EOPNOTSUPP
    if flags & !RWF_SUPPORTED != 0 {
        return KernelError::OperationNotSupported.sysret();
    }

    // Unsupported flags - return EOPNOTSUPP
    if flags & (RWF_ATOMIC | RWF_DONTCACHE) != 0 {
        return KernelError::OperationNotSupported.sysret();
    }

    // If RWF_NOWAIT not set, delegate to existing syscalls
    if flags & RWF_NOWAIT == 0 {
        if offset == -1 {
            let result = sys_writev(fd, iov_ptr, iovcnt);
            if result > 0 && (flags & (RWF_SYNC | RWF_DSYNC)) != 0 {
                let _ = sys_fsync(fd);
            }
            return result;
        }

        // RWF_APPEND: get file size as offset
        let actual_offset = if flags & RWF_APPEND != 0 {
            let file = match current_fd_table().lock().get(fd) {
                Some(f) => f,
                None => return KernelError::BadFd.sysret(),
            };
            file.get_inode().map(|i| i.get_size() as i64).unwrap_or(0)
        } else {
            offset
        };

        let result = sys_pwritev(fd, iov_ptr, iovcnt, actual_offset);
        if result > 0 && (flags & (RWF_SYNC | RWF_DSYNC)) != 0 {
            let _ = sys_fsync(fd);
        }
        return result;
    }

    // RWF_NOWAIT handling - use *_with_flags methods
    let rw_flags = RwFlags::with_nowait();

    // Validate and copy iovec array
    let iovecs = match validate_iovec_array(iov_ptr, iovcnt) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if iovecs.is_empty() {
        return 0;
    }

    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    if file.is_dir() {
        return KernelError::IsDirectory.sysret();
    }

    // For offset == -1, use current file position
    let use_position = offset == -1;

    // RWF_APPEND: get file size as offset
    let mut current_offset = if use_position {
        file.get_pos()
    } else if flags & RWF_APPEND != 0 {
        file.get_inode().map(|i| i.get_size()).unwrap_or(0)
    } else {
        offset as u64
    };

    let mut total_written: usize = 0;

    for iov in &iovecs {
        if iov.iov_len == 0 {
            continue;
        }

        let remaining_allowed = MAX_RW_COUNT.saturating_sub(total_written);
        if remaining_allowed == 0 {
            break;
        }

        let count = core::cmp::min(iov.iov_len as usize, remaining_allowed);

        if count <= SMALL_BUF_SIZE {
            let mut stack_buf = [0u8; SMALL_BUF_SIZE];
            let write_buf = &mut stack_buf[..count];

            // Copy from user space
            unsafe {
                Uaccess::user_access_begin();
                core::ptr::copy_nonoverlapping(
                    iov.iov_base as *const u8,
                    write_buf.as_mut_ptr(),
                    count,
                );
                Uaccess::user_access_end();
            }

            let result = if use_position {
                file.write_with_flags(write_buf, rw_flags)
            } else {
                file.pwrite_with_flags(write_buf, current_offset, rw_flags)
            };

            let bytes_written = match result {
                Ok(n) => n,
                Err(KernelError::WouldBlock) => {
                    return if total_written > 0 {
                        total_written as i64
                    } else {
                        KernelError::WouldBlock.sysret()
                    };
                }
                Err(KernelError::OperationNotSupported) => {
                    return if total_written > 0 {
                        total_written as i64
                    } else {
                        KernelError::OperationNotSupported.sysret()
                    };
                }
                Err(KernelError::PermissionDenied) => {
                    return if total_written > 0 {
                        total_written as i64
                    } else {
                        KernelError::BadFd.sysret()
                    };
                }
                Err(KernelError::BrokenPipe) => {
                    return if total_written > 0 {
                        total_written as i64
                    } else {
                        KernelError::BrokenPipe.sysret()
                    };
                }
                Err(_) => {
                    return if total_written > 0 {
                        total_written as i64
                    } else {
                        KernelError::InvalidArgument.sysret()
                    };
                }
            };

            total_written += bytes_written;
            current_offset += bytes_written as u64;

            if bytes_written < count {
                break;
            }
        } else {
            let mut kernel_buf = vec![0u8; count];

            // Copy from user space
            unsafe {
                Uaccess::user_access_begin();
                core::ptr::copy_nonoverlapping(
                    iov.iov_base as *const u8,
                    kernel_buf.as_mut_ptr(),
                    count,
                );
                Uaccess::user_access_end();
            }

            let result = if use_position {
                file.write_with_flags(&kernel_buf, rw_flags)
            } else {
                file.pwrite_with_flags(&kernel_buf, current_offset, rw_flags)
            };

            let bytes_written = match result {
                Ok(n) => n,
                Err(KernelError::WouldBlock) => {
                    return if total_written > 0 {
                        total_written as i64
                    } else {
                        KernelError::WouldBlock.sysret()
                    };
                }
                Err(KernelError::OperationNotSupported) => {
                    return if total_written > 0 {
                        total_written as i64
                    } else {
                        KernelError::OperationNotSupported.sysret()
                    };
                }
                Err(KernelError::PermissionDenied) => {
                    return if total_written > 0 {
                        total_written as i64
                    } else {
                        KernelError::BadFd.sysret()
                    };
                }
                Err(KernelError::BrokenPipe) => {
                    return if total_written > 0 {
                        total_written as i64
                    } else {
                        KernelError::BrokenPipe.sysret()
                    };
                }
                Err(_) => {
                    return if total_written > 0 {
                        total_written as i64
                    } else {
                        KernelError::InvalidArgument.sysret()
                    };
                }
            };

            total_written += bytes_written;
            current_offset += bytes_written as u64;

            if bytes_written < count {
                break;
            }
        }
    }

    // Update file position if using current position
    if use_position && total_written > 0 {
        file.advance_pos(total_written as u64);
    }

    // RWF_SYNC/RWF_DSYNC: sync after successful write
    if total_written > 0 && (flags & (RWF_SYNC | RWF_DSYNC)) != 0 {
        let _ = sys_fsync(fd);
    }

    total_written as i64
}

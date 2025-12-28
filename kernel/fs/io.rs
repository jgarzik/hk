//! Basic file I/O syscalls (read, write, lseek, pread64, pwrite64)

use alloc::vec;

use crate::arch::Uaccess;
use crate::console::console_write;
use crate::fs::KernelError;
use crate::uaccess::{UaccessArch, copy_to_user};

use super::syscall::{MAX_RW_COUNT, SMALL_BUF_SIZE, check_fsize_limit, current_fd_table};

/// sys_read - read from a file descriptor
///
/// Returns number of bytes read, 0 on EOF, negative errno on error.
pub fn sys_read(fd: i32, buf_ptr: u64, count: u64) -> i64 {
    // Limit count to prevent allocation failure
    let count = core::cmp::min(count as usize, MAX_RW_COUNT);

    // Validate user buffer address
    if !Uaccess::access_ok(buf_ptr, count) {
        return KernelError::BadAddress.sysret();
    }

    // Handle special fds (stdin)
    if fd == 0 {
        // stdin - not implemented yet
        return 0;
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

    // Use stack buffer for small reads to avoid heap allocation
    if count <= SMALL_BUF_SIZE {
        let mut stack_buf = [0u8; SMALL_BUF_SIZE];
        let read_buf = &mut stack_buf[..count];

        // Perform read into stack buffer
        let bytes_read = match file.read(read_buf) {
            Ok(n) => n,
            Err(KernelError::IsDirectory) => return KernelError::IsDirectory.sysret(),
            Err(KernelError::PermissionDenied) => return KernelError::BadFd.sysret(),
            Err(KernelError::WouldBlock) => return KernelError::WouldBlock.sysret(),
            Err(_) => return KernelError::InvalidArgument.sysret(),
        };

        // Copy from kernel buffer to user space
        if bytes_read > 0 && copy_to_user::<Uaccess>(buf_ptr, &read_buf[..bytes_read]).is_err() {
            return KernelError::BadAddress.sysret();
        }

        bytes_read as i64
    } else {
        // Allocate a kernel buffer for large reads
        let mut kernel_buf = vec![0u8; count];

        // Perform read into kernel buffer
        let bytes_read = match file.read(&mut kernel_buf) {
            Ok(n) => n,
            Err(KernelError::IsDirectory) => return KernelError::IsDirectory.sysret(),
            Err(KernelError::PermissionDenied) => return KernelError::BadFd.sysret(),
            Err(KernelError::WouldBlock) => return KernelError::WouldBlock.sysret(),
            Err(_) => return KernelError::InvalidArgument.sysret(),
        };

        // Copy from kernel buffer to user space
        if bytes_read > 0 && copy_to_user::<Uaccess>(buf_ptr, &kernel_buf[..bytes_read]).is_err() {
            return KernelError::BadAddress.sysret();
        }

        bytes_read as i64
    }
}

/// sys_write - write to a file descriptor
///
/// Returns number of bytes written, negative errno on error.
pub fn sys_write(fd: i32, buf_ptr: u64, count: u64) -> i64 {
    // Limit count to prevent allocation failure
    let count = core::cmp::min(count as usize, MAX_RW_COUNT);

    // Validate user buffer address
    if !Uaccess::access_ok(buf_ptr, count) {
        return KernelError::BadAddress.sysret();
    }

    // Handle special fds (stdout, stderr) - no RLIMIT_FSIZE check needed
    if fd == 1 || fd == 2 {
        // Use stack buffer for small writes
        if count <= SMALL_BUF_SIZE {
            let mut stack_buf = [0u8; SMALL_BUF_SIZE];
            let write_buf = &mut stack_buf[..count];
            unsafe {
                Uaccess::user_access_begin();
                core::ptr::copy_nonoverlapping(buf_ptr as *const u8, write_buf.as_mut_ptr(), count);
                Uaccess::user_access_end();
            }
            console_write(write_buf);
        } else {
            let mut kernel_buf = vec![0u8; count];
            unsafe {
                Uaccess::user_access_begin();
                core::ptr::copy_nonoverlapping(
                    buf_ptr as *const u8,
                    kernel_buf.as_mut_ptr(),
                    count,
                );
                Uaccess::user_access_end();
            }
            console_write(&kernel_buf);
        }
        return count as i64;
    }

    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    // Check RLIMIT_FSIZE for regular files (files with inodes)
    // Pipes and special files don't have size limits
    if file.get_inode().is_some()
        && let Err(e) = check_fsize_limit(file.get_pos(), count)
    {
        return e;
    }

    // Use stack buffer for small writes to avoid heap allocation
    if count <= SMALL_BUF_SIZE {
        let mut stack_buf = [0u8; SMALL_BUF_SIZE];
        let write_buf = &mut stack_buf[..count];

        // Copy from user space to kernel buffer
        unsafe {
            Uaccess::user_access_begin();
            core::ptr::copy_nonoverlapping(buf_ptr as *const u8, write_buf.as_mut_ptr(), count);
            Uaccess::user_access_end();
        }

        // Perform write
        match file.write(write_buf) {
            Ok(n) => n as i64,
            Err(KernelError::PermissionDenied) => KernelError::BadFd.sysret(),
            Err(e) => e.sysret(),
        }
    } else {
        // Allocate a kernel buffer for large writes
        let mut kernel_buf = vec![0u8; count];

        // Copy from user space to kernel buffer
        unsafe {
            Uaccess::user_access_begin();
            core::ptr::copy_nonoverlapping(buf_ptr as *const u8, kernel_buf.as_mut_ptr(), count);
            Uaccess::user_access_end();
        }

        // Perform write
        match file.write(&kernel_buf) {
            Ok(n) => n as i64,
            Err(KernelError::PermissionDenied) => KernelError::BadFd.sysret(),
            Err(e) => e.sysret(),
        }
    }
}

/// sys_lseek - reposition read/write file offset
///
/// Repositions the file offset of the open file description associated with
/// the file descriptor fd to the argument offset according to the directive
/// whence.
///
/// # Arguments
/// * `fd` - File descriptor
/// * `offset` - New offset (interpretation depends on whence)
/// * `whence` - SEEK_SET (0), SEEK_CUR (1), or SEEK_END (2)
///
/// # Returns
/// The resulting offset location from the beginning of the file on success,
/// or negative errno on error.
pub fn sys_lseek(fd: i32, offset: i64, whence: i32) -> i64 {
    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    // Perform the seek
    match file.lseek(offset, whence) {
        Ok(new_pos) => new_pos as i64,
        Err(KernelError::InvalidArgument) => KernelError::InvalidArgument.sysret(),
        Err(KernelError::OperationNotSupported) => -29, // ESPIPE - illegal seek (e.g., on pipe)
        Err(_) => KernelError::InvalidArgument.sysret(),
    }
}

/// sys_pread64 - read from file at given offset without changing file position
///
/// Like read(), but reads at an explicit offset without modifying the file position.
/// Returns -ESPIPE for files that don't support positioned I/O (pipes, sockets).
///
/// # Arguments
/// * `fd` - File descriptor
/// * `buf_ptr` - User buffer to read into
/// * `count` - Number of bytes to read
/// * `offset` - File offset to read from
///
/// # Returns
/// Number of bytes read, 0 on EOF, negative errno on error.
pub fn sys_pread64(fd: i32, buf_ptr: u64, count: u64, offset: i64) -> i64 {
    // Check offset validity (Linux returns -EINVAL for negative offsets)
    if offset < 0 {
        return KernelError::InvalidArgument.sysret();
    }
    let offset = offset as u64;

    // Limit count to prevent allocation failure
    let count = core::cmp::min(count as usize, MAX_RW_COUNT);

    // Validate user buffer address
    if !Uaccess::access_ok(buf_ptr, count) {
        return KernelError::BadAddress.sysret();
    }

    // Handle special fds (stdin) - not supported for pread
    if fd == 0 {
        return KernelError::IllegalSeek.sysret(); // stdin is not seekable
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

    // Use stack buffer for small reads to avoid heap allocation
    if count <= SMALL_BUF_SIZE {
        let mut stack_buf = [0u8; SMALL_BUF_SIZE];
        let read_buf = &mut stack_buf[..count];

        // Perform positioned read into stack buffer
        let bytes_read = match file.pread(read_buf, offset) {
            Ok(n) => n,
            Err(KernelError::IsDirectory) => return KernelError::IsDirectory.sysret(),
            Err(KernelError::PermissionDenied) => return KernelError::BadFd.sysret(),
            Err(KernelError::OperationNotSupported) => return KernelError::IllegalSeek.sysret(), // Not seekable
            Err(_) => return KernelError::InvalidArgument.sysret(),
        };

        // Copy from kernel buffer to user space
        if bytes_read > 0 && copy_to_user::<Uaccess>(buf_ptr, &read_buf[..bytes_read]).is_err() {
            return KernelError::BadAddress.sysret();
        }

        bytes_read as i64
    } else {
        // Allocate a kernel buffer for large reads
        let mut kernel_buf = vec![0u8; count];

        // Perform positioned read into kernel buffer
        let bytes_read = match file.pread(&mut kernel_buf, offset) {
            Ok(n) => n,
            Err(KernelError::IsDirectory) => return KernelError::IsDirectory.sysret(),
            Err(KernelError::PermissionDenied) => return KernelError::BadFd.sysret(),
            Err(KernelError::OperationNotSupported) => return KernelError::IllegalSeek.sysret(), // Not seekable
            Err(_) => return KernelError::InvalidArgument.sysret(),
        };

        // Copy from kernel buffer to user space
        if bytes_read > 0 && copy_to_user::<Uaccess>(buf_ptr, &kernel_buf[..bytes_read]).is_err() {
            return KernelError::BadAddress.sysret();
        }

        bytes_read as i64
    }
}

/// sys_pwrite64 - write to file at given offset without changing file position
///
/// Like write(), but writes at an explicit offset without modifying the file position.
/// Returns -ESPIPE for files that don't support positioned I/O (pipes, sockets).
///
/// # Arguments
/// * `fd` - File descriptor
/// * `buf_ptr` - User buffer containing data to write
/// * `count` - Number of bytes to write
/// * `offset` - File offset to write to
///
/// # Returns
/// Number of bytes written, negative errno on error.
pub fn sys_pwrite64(fd: i32, buf_ptr: u64, count: u64, offset: i64) -> i64 {
    // Check offset validity (Linux returns -EINVAL for negative offsets)
    if offset < 0 {
        return KernelError::InvalidArgument.sysret();
    }
    let offset = offset as u64;

    // Limit count to prevent allocation failure
    let count = core::cmp::min(count as usize, MAX_RW_COUNT);

    // Validate user buffer address
    if !Uaccess::access_ok(buf_ptr, count) {
        return KernelError::BadAddress.sysret();
    }

    // Handle special fds (stdout, stderr) - not supported for pwrite
    if fd == 1 || fd == 2 {
        return KernelError::IllegalSeek.sysret(); // stdout/stderr are not seekable
    }

    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    // Check RLIMIT_FSIZE for regular files (pwrite uses explicit offset)
    if file.get_inode().is_some()
        && let Err(e) = check_fsize_limit(offset, count)
    {
        return e;
    }

    // Use stack buffer for small writes to avoid heap allocation
    if count <= SMALL_BUF_SIZE {
        let mut stack_buf = [0u8; SMALL_BUF_SIZE];
        let write_buf = &mut stack_buf[..count];

        // Copy from user space to kernel buffer
        unsafe {
            Uaccess::user_access_begin();
            core::ptr::copy_nonoverlapping(buf_ptr as *const u8, write_buf.as_mut_ptr(), count);
            Uaccess::user_access_end();
        }

        // Perform positioned write
        match file.pwrite(write_buf, offset) {
            Ok(n) => n as i64,
            Err(KernelError::PermissionDenied) => KernelError::BadFd.sysret(),
            Err(KernelError::OperationNotSupported) => KernelError::IllegalSeek.sysret(), // Not seekable
            Err(_) => KernelError::InvalidArgument.sysret(),
        }
    } else {
        // Allocate a kernel buffer for large writes
        let mut kernel_buf = vec![0u8; count];

        // Copy from user space to kernel buffer
        unsafe {
            Uaccess::user_access_begin();
            core::ptr::copy_nonoverlapping(buf_ptr as *const u8, kernel_buf.as_mut_ptr(), count);
            Uaccess::user_access_end();
        }

        // Perform positioned write
        match file.pwrite(&kernel_buf, offset) {
            Ok(n) => n as i64,
            Err(KernelError::PermissionDenied) => KernelError::BadFd.sysret(),
            Err(KernelError::OperationNotSupported) => KernelError::IllegalSeek.sysret(), // Not seekable
            Err(_) => KernelError::InvalidArgument.sysret(),
        }
    }
}

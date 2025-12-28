//! File descriptor manipulation syscalls
//!
//! This module contains syscalls for file descriptor operations:
//! - dup, dup2, dup3 (file descriptor duplication)
//! - fcntl (file control operations)
//! - truncate, ftruncate (file size modification)
//! - pipe, pipe2 (pipe creation)

use alloc::sync::Arc;

use crate::arch::Uaccess;
use crate::fs::{KernelError, LookupFlags, lookup_path_flags};
use crate::task::percpu::current_tid;
use crate::uaccess::{copy_from_user, copy_to_user, strncpy_from_user};

use super::posix_lock::{Flock, posix_getlk, posix_setlk, posix_setlkw};
use super::syscall::{PATH_MAX, current_fd_table, get_nofile_limit};

// =============================================================================
// truncate, ftruncate syscalls
// =============================================================================

/// Helper to perform truncate on an inode with RLIMIT and error handling
fn do_truncate(inode: &Arc<super::Inode>, length: u64) -> i64 {
    // Check RLIMIT_FSIZE when extending the file
    let current_size = inode.get_size();
    if length > current_size {
        let limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_FSIZE);
        if limit != crate::rlimit::RLIM_INFINITY && length > limit {
            let tid = current_tid();
            crate::signal::send_signal(tid, crate::signal::SIGXFSZ);
            return KernelError::FileTooLarge.sysret();
        }
    }

    // Perform truncate
    match inode.i_op.truncate(inode, length) {
        Ok(()) => 0,
        Err(KernelError::IsDirectory) => KernelError::IsDirectory.sysret(),
        Err(KernelError::OperationNotSupported) => KernelError::InvalidArgument.sysret(),
        Err(KernelError::PermissionDenied) => KernelError::PermissionDenied.sysret(),
        Err(KernelError::FileTooLarge) => KernelError::FileTooLarge.sysret(),
        Err(_) => KernelError::InvalidArgument.sysret(),
    }
}

/// sys_ftruncate - truncate a file to a specified length
///
/// Truncates the file referred to by fd to the specified length.
/// If the file was larger, the extra data is discarded.
/// If the file was shorter, it is extended with null bytes.
///
/// # Arguments
/// * `fd` - File descriptor (must be open for writing)
/// * `length` - New file length
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_ftruncate(fd: i32, length: i64) -> i64 {
    if length < 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    // Check file is writable
    if !file.is_writable() {
        return KernelError::InvalidArgument.sysret(); // EBADF or EINVAL depending on interpretation
    }

    // Get the inode
    let inode = match file.get_inode() {
        Some(i) => i,
        None => return KernelError::BadFd.sysret(),
    };

    do_truncate(&inode, length as u64)
}

/// sys_truncate - truncate a file to a specified length by path
///
/// # Arguments
/// * `path_ptr` - User pointer to path string
/// * `length` - New file length
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_truncate(path_ptr: u64, length: i64) -> i64 {
    if length < 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Read path from user space
    let path = match strncpy_from_user::<Uaccess>(path_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    if path.is_empty() {
        return KernelError::NotFound.sysret();
    }

    // Look up the file (follow symlinks for truncate)
    let dentry = match lookup_path_flags(&path, LookupFlags::open()) {
        Ok(d) => d,
        Err(KernelError::NotFound) => return KernelError::NotFound.sysret(),
        Err(KernelError::NotDirectory) => return KernelError::NotDirectory.sysret(),
        Err(_) => return KernelError::InvalidArgument.sysret(),
    };

    // Get the inode
    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return KernelError::NotFound.sysret(),
    };

    do_truncate(&inode, length as u64)
}

// =============================================================================
// dup, dup2, dup3 syscalls
// =============================================================================

/// sys_dup - duplicate a file descriptor
///
/// Creates a copy of the file descriptor oldfd, using the lowest-numbered
/// unused file descriptor for the new descriptor.
///
/// # Arguments
/// * `oldfd` - File descriptor to duplicate
///
/// # Returns
/// New file descriptor on success, negative errno on error.
pub fn sys_dup(oldfd: i32) -> i64 {
    let fd_table = current_fd_table();
    let mut table = fd_table.lock();
    let file = match table.get(oldfd) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    // Allocate fd (RLIMIT_NOFILE enforced inside alloc)
    match table.alloc(file, get_nofile_limit()) {
        Ok(newfd) => newfd as i64,
        Err(e) => -(e as i64),
    }
}

/// sys_dup2 - duplicate a file descriptor to a specific number
///
/// Makes newfd be a copy of oldfd, closing newfd first if necessary.
/// If oldfd == newfd, just checks that oldfd is valid.
///
/// # Arguments
/// * `oldfd` - File descriptor to duplicate
/// * `newfd` - Target file descriptor number
///
/// # Returns
/// newfd on success, negative errno on error.
pub fn sys_dup2(oldfd: i32, newfd: i32) -> i64 {
    if newfd < 0 {
        return KernelError::BadFd.sysret();
    }

    // If oldfd == newfd, just verify oldfd is valid
    if oldfd == newfd {
        let fd_table = current_fd_table();
        let table = fd_table.lock();
        return if table.is_valid(oldfd) {
            newfd as i64
        } else {
            KernelError::BadFd.sysret()
        };
    }

    let fd_table = current_fd_table();
    let mut table = fd_table.lock();
    let file = match table.get(oldfd) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    // Close newfd if open (silently ignore errors)
    table.close(newfd);

    // Allocate at specific fd (RLIMIT_NOFILE enforced inside)
    match table.alloc_at_with_flags(newfd, file, 0, get_nofile_limit()) {
        Ok(()) => newfd as i64,
        Err(e) => -(e as i64),
    }
}

/// sys_dup3 - duplicate a file descriptor with flags
///
/// Like dup2, but with additional flags. Currently only O_CLOEXEC is supported.
/// Unlike dup2, returns EINVAL if oldfd == newfd.
///
/// # Arguments
/// * `oldfd` - File descriptor to duplicate
/// * `newfd` - Target file descriptor number
/// * `flags` - Flags (only O_CLOEXEC supported)
///
/// # Returns
/// newfd on success, negative errno on error.
pub fn sys_dup3(oldfd: i32, newfd: i32, flags: u32) -> i64 {
    // dup3 requires oldfd != newfd (unlike dup2)
    if oldfd == newfd {
        return KernelError::InvalidArgument.sysret();
    }
    if newfd < 0 {
        return KernelError::BadFd.sysret();
    }

    // Only O_CLOEXEC is valid for dup3
    if flags & !super::file::flags::O_CLOEXEC != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    let fd_table = current_fd_table();
    let mut table = fd_table.lock();
    let file = match table.get(oldfd) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    // Close newfd if open
    table.close(newfd);

    // Convert O_CLOEXEC to FD_CLOEXEC
    let fd_flags = if flags & super::file::flags::O_CLOEXEC != 0 {
        crate::task::FD_CLOEXEC
    } else {
        0
    };

    // Allocate at specific fd (RLIMIT_NOFILE enforced inside)
    match table.alloc_at_with_flags(newfd, file, fd_flags, get_nofile_limit()) {
        Ok(()) => newfd as i64,
        Err(e) => -(e as i64),
    }
}

// =============================================================================
// pipe, pipe2 syscalls
// =============================================================================

/// pipe - create a pipe
///
/// Creates a pipe, a unidirectional data channel that can be used for
/// interprocess communication. The array pipefd is used to return two
/// file descriptors referring to the ends of the pipe.
///
/// # Arguments
/// * `pipefd` - Pointer to int[2] array. pipefd[0] = read end, pipefd[1] = write end
///
/// # Returns
/// * 0 on success
/// * -EFAULT if pipefd is invalid
/// * -EMFILE if too many file descriptors
pub fn sys_pipe(pipefd: u64) -> i64 {
    sys_pipe2(pipefd, 0)
}

/// pipe2 - create a pipe with flags
///
/// Like pipe(), but additionally allows flags to be specified.
///
/// # Arguments
/// * `pipefd` - Pointer to int[2] array
/// * `flags` - O_CLOEXEC | O_NONBLOCK
///
/// # Returns
/// * 0 on success
/// * -EFAULT if pipefd is invalid
/// * -EINVAL if invalid flags
/// * -EMFILE if too many file descriptors
pub fn sys_pipe2(pipefd: u64, flags: u32) -> i64 {
    use crate::fs::file::flags::{O_CLOEXEC, O_NONBLOCK};
    use crate::pipe::{FD_CLOEXEC, create_pipe};
    use crate::uaccess::copy_to_user;

    // Validate flags - only O_CLOEXEC and O_NONBLOCK are allowed
    const VALID_FLAGS: u32 = O_CLOEXEC | O_NONBLOCK;
    if flags & !VALID_FLAGS != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Validate user pointer
    if pipefd == 0 {
        return KernelError::BadAddress.sysret();
    }

    // Create the pipe
    let (read_file, write_file) = match create_pipe(flags & O_NONBLOCK) {
        Ok((r, w)) => (r, w),
        Err(_) => return KernelError::OutOfMemory.sysret(),
    };

    // Allocate file descriptors (RLIMIT_NOFILE enforced inside alloc)
    // Following Linux pattern: each get_unused_fd_flags() call checks limit
    let fd_table = current_fd_table();
    let mut table = fd_table.lock();
    let nofile = get_nofile_limit();

    // Determine fd flags
    let fd_flags = if flags & O_CLOEXEC != 0 {
        FD_CLOEXEC
    } else {
        0
    };

    let read_fd = match table.alloc_with_flags(read_file, fd_flags, nofile) {
        Ok(fd) => fd,
        Err(e) => return -(e as i64),
    };

    let write_fd = match table.alloc_with_flags(write_file, fd_flags, nofile) {
        Ok(fd) => fd,
        Err(e) => {
            // Clean up read fd on failure
            table.close(read_fd);
            return -(e as i64);
        }
    };

    drop(table);

    // Write file descriptors to user space
    let fds: [i32; 2] = [read_fd, write_fd];
    let fds_bytes = unsafe {
        core::slice::from_raw_parts(fds.as_ptr() as *const u8, core::mem::size_of::<[i32; 2]>())
    };

    match copy_to_user::<Uaccess>(pipefd, fds_bytes) {
        Ok(_) => 0,
        Err(_) => {
            // Clean up on error
            let mut table = fd_table.lock();
            table.close(read_fd);
            table.close(write_fd);
            KernelError::BadAddress.sysret()
        }
    }
}

// =============================================================================
// fcntl syscall
// =============================================================================

/// fcntl command constants
mod fcntl_cmd {
    pub const F_DUPFD: i32 = 0;
    pub const F_GETFD: i32 = 1;
    pub const F_SETFD: i32 = 2;
    pub const F_GETFL: i32 = 3;
    pub const F_SETFL: i32 = 4;
    // POSIX advisory lock commands
    pub const F_GETLK: i32 = 5;
    pub const F_SETLK: i32 = 6;
    pub const F_SETLKW: i32 = 7;
    pub const F_DUPFD_CLOEXEC: i32 = 1030;
}

/// sys_fcntl - file control operations
///
/// Performs various operations on file descriptors.
///
/// # Arguments
/// * `fd` - File descriptor to operate on
/// * `cmd` - Operation to perform (F_DUPFD, F_GETFD, etc.)
/// * `arg` - Optional argument (meaning depends on cmd)
///
/// # Returns
/// * F_DUPFD/F_DUPFD_CLOEXEC: new fd on success
/// * F_GETFD: fd flags (FD_CLOEXEC)
/// * F_GETFL: file status flags
/// * F_SETFD/F_SETFL: 0 on success
/// * negative errno on error
pub fn sys_fcntl(fd: i32, cmd: i32, arg: u64) -> i64 {
    use fcntl_cmd::*;

    let fd_table = current_fd_table();
    let mut table = fd_table.lock();

    let nofile = get_nofile_limit();

    match cmd {
        F_DUPFD => {
            // Duplicate fd to lowest available >= arg
            let file = match table.get(fd) {
                Some(f) => f,
                None => return KernelError::BadFd.sysret(),
            };
            let min_fd = arg as i32;
            if min_fd < 0 {
                return KernelError::InvalidArgument.sysret();
            }
            // Linux: if (from >= nofile) return -EINVAL
            if (min_fd as u64) >= nofile {
                return KernelError::InvalidArgument.sysret();
            }
            // RLIMIT_NOFILE enforced inside alloc_at_or_above
            match table.alloc_at_or_above(file, min_fd, 0, nofile) {
                Ok(new_fd) => new_fd as i64,
                Err(e) => -(e as i64),
            }
        }

        F_DUPFD_CLOEXEC => {
            // Duplicate fd with FD_CLOEXEC set
            let file = match table.get(fd) {
                Some(f) => f,
                None => return KernelError::BadFd.sysret(),
            };
            let min_fd = arg as i32;
            if min_fd < 0 {
                return KernelError::InvalidArgument.sysret();
            }
            // Linux: if (from >= nofile) return -EINVAL
            if (min_fd as u64) >= nofile {
                return KernelError::InvalidArgument.sysret();
            }
            // RLIMIT_NOFILE enforced inside alloc_at_or_above
            match table.alloc_at_or_above(file, min_fd, crate::task::FD_CLOEXEC, nofile) {
                Ok(new_fd) => new_fd as i64,
                Err(e) => -(e as i64),
            }
        }

        F_GETFD => {
            // Get fd flags (FD_CLOEXEC)
            if !table.is_valid(fd) {
                return KernelError::BadFd.sysret();
            }
            table.get_fd_flags(fd) as i64
        }

        F_SETFD => {
            // Set fd flags (only FD_CLOEXEC is valid)
            if !table.set_fd_flags(fd, arg as u32) {
                return KernelError::BadFd.sysret();
            }
            0
        }

        F_GETFL => {
            // Get file status flags
            let file = match table.get(fd) {
                Some(f) => f,
                None => return KernelError::BadFd.sysret(),
            };
            file.get_flags() as i64
        }

        F_SETFL => {
            // Set file status flags (only O_APPEND, O_NONBLOCK can be changed)
            let file = match table.get(fd) {
                Some(f) => f,
                None => return KernelError::BadFd.sysret(),
            };
            file.set_status_flags(arg as u32);
            0
        }

        F_GETLK => {
            // Get lock info - test if a lock would block
            let file = match table.get(fd) {
                Some(f) => f,
                None => return KernelError::BadFd.sysret(),
            };
            drop(table); // Release FD table lock before copying

            // Copy flock from user
            let mut flock = Flock::default();
            let flock_size = core::mem::size_of::<Flock>();
            let flock_bytes = unsafe {
                core::slice::from_raw_parts_mut(&mut flock as *mut Flock as *mut u8, flock_size)
            };
            if copy_from_user::<Uaccess>(flock_bytes, arg, flock_size).is_err() {
                return KernelError::BadAddress.sysret();
            }

            // Do the getlk
            if let Err(e) = posix_getlk(&file, &mut flock) {
                return e.sysret();
            }

            // Copy result back
            let flock_bytes = unsafe {
                core::slice::from_raw_parts(&flock as *const Flock as *const u8, flock_size)
            };
            if copy_to_user::<Uaccess>(arg, flock_bytes).is_err() {
                return KernelError::BadAddress.sysret();
            }

            0
        }

        F_SETLK => {
            // Set lock (non-blocking)
            let file = match table.get(fd) {
                Some(f) => f,
                None => return KernelError::BadFd.sysret(),
            };
            drop(table);

            // Copy flock from user
            let mut flock = Flock::default();
            let flock_size = core::mem::size_of::<Flock>();
            let flock_bytes = unsafe {
                core::slice::from_raw_parts_mut(&mut flock as *mut Flock as *mut u8, flock_size)
            };
            if copy_from_user::<Uaccess>(flock_bytes, arg, flock_size).is_err() {
                return KernelError::BadAddress.sysret();
            }

            match posix_setlk(&file, &flock) {
                Ok(()) => 0,
                Err(e) => e.sysret(),
            }
        }

        F_SETLKW => {
            // Set lock (blocking - but we don't actually block, like flock)
            let file = match table.get(fd) {
                Some(f) => f,
                None => return KernelError::BadFd.sysret(),
            };
            drop(table);

            // Copy flock from user
            let mut flock = Flock::default();
            let flock_size = core::mem::size_of::<Flock>();
            let flock_bytes = unsafe {
                core::slice::from_raw_parts_mut(&mut flock as *mut Flock as *mut u8, flock_size)
            };
            if copy_from_user::<Uaccess>(flock_bytes, arg, flock_size).is_err() {
                return KernelError::BadAddress.sysret();
            }

            match posix_setlkw(&file, &flock) {
                Ok(()) => 0,
                Err(e) => e.sysret(),
            }
        }

        _ => KernelError::InvalidArgument.sysret(),
    }
}

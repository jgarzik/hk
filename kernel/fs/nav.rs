//! Directory navigation syscalls (chdir, fchdir, chroot, getcwd)

use crate::arch::Uaccess;
use crate::fs::{KernelError, LookupFlags, Path, lookup_path_at};
use crate::uaccess::{UaccessArch, copy_to_user, strncpy_from_user};

use super::syscall::{PATH_MAX, current_fd_table};

/// sys_chdir - change working directory
///
/// # Arguments
/// * `path_ptr` - User pointer to path string
///
/// # Returns
/// 0 on success, negative errno on error.
pub fn sys_chdir(path_ptr: u64) -> i64 {
    // Read path from user space
    let path_str = match strncpy_from_user::<Uaccess>(path_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Get current task's cwd as starting point for relative paths
    let start = crate::task::percpu::current_cwd();

    // Look up the path (must be a directory)
    let dentry = match lookup_path_at(start, &path_str, LookupFlags::opendir()) {
        Ok(d) => d,
        Err(KernelError::NotFound) => return KernelError::NotFound.sysret(),
        Err(KernelError::NotDirectory) => return KernelError::NotDirectory.sysret(),
        Err(_) => return KernelError::InvalidArgument.sysret(),
    };

    // Verify it's a directory
    if let Some(inode) = dentry.get_inode() {
        if !inode.mode().is_dir() {
            return KernelError::NotDirectory.sysret();
        }
    } else {
        return KernelError::NotFound.sysret();
    }

    // Create new Path and update FsStruct
    if let Some(fs) = crate::task::percpu::current_fs()
        && let Some(new_pwd) = Path::from_dentry(dentry)
    {
        fs.set_pwd(new_pwd);
    }

    0
}

/// sys_fchdir - change working directory via file descriptor
///
/// # Arguments
/// * `fd` - File descriptor of a directory
///
/// # Returns
/// 0 on success, negative errno on error.
pub fn sys_fchdir(fd: i32) -> i64 {
    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    // Must be a directory
    if !file.is_dir() {
        return KernelError::NotDirectory.sysret();
    }

    // Create new Path and update FsStruct
    if let Some(fs) = crate::task::percpu::current_fs()
        && let Some(new_pwd) = Path::from_dentry(file.dentry.clone())
    {
        fs.set_pwd(new_pwd);
    }

    0
}

/// sys_chroot - change root directory
///
/// Changes the root directory of the calling process to the directory
/// specified in path. This call does not change the current working directory.
///
/// # Arguments
/// * `path_ptr` - User pointer to null-terminated path string
///
/// # Returns
/// 0 on success, negative errno on error.
///
/// # Errors
/// * EFAULT - Invalid user pointer
/// * ENOENT - Path not found
/// * ENOTDIR - Path is not a directory
/// * EACCES - No execute permission on path
/// * EPERM - Caller lacks CAP_SYS_CHROOT capability
pub fn sys_chroot(path_ptr: u64) -> i64 {
    // Check capability (must be root or have CAP_SYS_CHROOT)
    if !crate::task::capable(crate::task::CAP_SYS_CHROOT) {
        return KernelError::NotPermitted.sysret();
    }

    // Copy path from user space
    let path_str = match strncpy_from_user::<Uaccess>(path_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Start from current working directory for relative paths
    let start = crate::task::percpu::current_cwd();

    // Look up the path - must be a directory and we must follow symlinks
    let dentry = match lookup_path_at(start, &path_str, LookupFlags::opendir()) {
        Ok(d) => d,
        Err(KernelError::NotFound) => return KernelError::NotFound.sysret(),
        Err(KernelError::NotDirectory) => return KernelError::NotDirectory.sysret(),
        Err(KernelError::PermissionDenied) => return KernelError::PermissionDenied.sysret(),
        Err(_) => return KernelError::InvalidArgument.sysret(),
    };

    // Verify it's a directory (should be guaranteed by opendir() flags, but check anyway)
    if let Some(inode) = dentry.get_inode() {
        if !inode.mode().is_dir() {
            return KernelError::NotDirectory.sysret();
        }
    } else {
        return KernelError::NotFound.sysret();
    }

    // Update the root directory
    if let Some(fs) = crate::task::percpu::current_fs()
        && let Some(new_root) = Path::from_dentry(dentry)
    {
        fs.set_root(new_root);
    } else {
        return KernelError::InvalidArgument.sysret();
    }

    0
}

/// sys_getcwd - get current working directory
///
/// Returns the absolute pathname of the current working directory.
///
/// # Arguments
/// * `buf` - User buffer to store the pathname
/// * `size` - Size of the buffer
///
/// # Returns
/// Length of the pathname (including null terminator) on success,
/// negative errno on error:
/// - EFAULT: Invalid buffer address
/// - ENOENT: Current directory doesn't exist
/// - ERANGE: Buffer too small for pathname
pub fn sys_getcwd(buf: u64, size: u64) -> i64 {
    // Get current task's filesystem context
    let fs = match crate::task::percpu::current_fs() {
        Some(fs) => fs,
        None => return KernelError::NotFound.sysret(),
    };

    // Get pwd and build path string
    let pwd = fs.get_pwd();
    let path_str = pwd.dentry.full_path();

    // Need space for path + null terminator
    let path_len = path_str.len() + 1;

    // Check buffer size
    if size < path_len as u64 {
        return KernelError::Range.sysret();
    }

    // Validate user buffer address
    if !Uaccess::access_ok(buf, path_len) {
        return KernelError::BadAddress.sysret();
    }

    // Copy path to user buffer (with null terminator)
    let mut path_bytes = path_str.into_bytes();
    path_bytes.push(0); // null terminator

    if copy_to_user::<Uaccess>(buf, &path_bytes).is_err() {
        return KernelError::BadAddress.sysret();
    }

    path_len as i64
}

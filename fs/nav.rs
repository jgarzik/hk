//! Directory navigation syscalls (chdir, fchdir, chroot, getcwd)

use crate::arch::Uaccess;
use crate::fs::dac::{self, MAY_CHDIR, MAY_EXEC};
use crate::fs::namei::path_lookupat;
use crate::fs::{Dentry, KernelError, LookupFlags};
use crate::uaccess::{UaccessArch, copy_to_user};

use super::syscall::current_fd_table;

/// chdir/fchdir/chroot target: a directory with search permission
/// (MAY_EXEC | MAY_CHDIR)
fn may_chdir(d: &Dentry) -> Result<(), KernelError> {
    let inode = d.get_inode().ok_or(KernelError::NotFound)?;
    if !inode.mode().is_dir() {
        return Err(KernelError::NotDirectory);
    }
    dac::permission(&inode, MAY_EXEC | MAY_CHDIR)
}

/// sys_chdir - change working directory
///
/// # Arguments
/// * `path_ptr` - User pointer to path string
///
/// # Returns
/// 0 on success, negative errno on error.
pub fn sys_chdir(path_ptr: u64) -> i64 {
    // Read path from user space
    let path_str = match crate::fs::namei::getname(path_ptr, false) {
        Ok(p) => p,
        Err(e) => return e.sysret(),
    };

    // Get current task's cwd as starting point for relative paths
    let start = crate::task::percpu::current_cwd();

    // Look up the path (must be a directory), then search permission
    let path = match path_lookupat(start, &path_str, LookupFlags::opendir()) {
        Ok(p) => p,
        Err(e) => return e.sysret(),
    };
    if let Err(e) = may_chdir(&path.dentry) {
        return e.sysret();
    }

    // Create new Path and update FsStruct
    if let Some(fs) = crate::task::percpu::current_fs() {
        fs.set_pwd(path);
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
    let Some(file) = current_fd_table().lock().get(fd) else {
        return KernelError::BadFd.sysret();
    };

    // Must be a searchable directory
    if let Err(e) = may_chdir(&file.dentry) {
        return e.sysret();
    }

    // Create new Path and update FsStruct
    if let Some(fs) = crate::task::percpu::current_fs()
        && let Some(new_pwd) = file.f_path()
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
    // Copy path from user space
    let path_str = match crate::fs::namei::getname(path_ptr, false) {
        Ok(p) => p,
        Err(e) => return e.sysret(),
    };

    // Start from current working directory for relative paths
    let start = crate::task::percpu::current_cwd();

    // Look up the path: a searchable directory
    let path = match path_lookupat(start, &path_str, LookupFlags::opendir()) {
        Ok(p) => p,
        Err(e) => return e.sysret(),
    };
    if let Err(e) = may_chdir(&path.dentry) {
        return e.sysret();
    }
    // CAP_SYS_CHROOT is checked after the lookup, like Linux
    if !crate::task::capable(crate::task::CAP_SYS_CHROOT) {
        return KernelError::NotPermitted.sysret();
    }

    // Update the root directory
    if let Some(fs) = crate::task::percpu::current_fs() {
        fs.set_root(path);
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
    let Some(fs) = crate::task::percpu::current_fs() else {
        return KernelError::NotFound.sysret();
    };

    // Linux getcwd: ENOENT for a removed directory; one outside the
    // root (a chroot escape, a detached mount) is "(unreachable)..."
    let pwd = fs.get_pwd();
    if pwd.dentry.is_unhashed() {
        return KernelError::NotFound.sysret();
    }
    let root = match crate::fs::namei::nd_root() {
        Ok(r) => r,
        Err(e) => return e.sysret(),
    };
    // Past PATH_MAX (the NUL included) is ENAMETOOLONG (Linux getcwd)
    let (mut path_str, reached) = match crate::fs::dentry::try_d_path(&pwd, &root) {
        Ok(r) => r,
        Err(e) => return e.sysret(),
    };
    if !reached {
        const UNREACHABLE: &[u8] = b"(unreachable)";
        if path_str.len() + UNREACHABLE.len() >= crate::fs::dentry::PATH_MAX {
            return KernelError::NameTooLong.sysret();
        }
        path_str.splice(0..0, UNREACHABLE.iter().copied());
    }

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
    let mut path_bytes = path_str;
    path_bytes.push(0); // null terminator

    if copy_to_user::<Uaccess>(buf, &path_bytes).is_err() {
        return KernelError::BadAddress.sysret();
    }

    path_len as i64
}

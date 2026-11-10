//! Directory navigation syscalls (chdir, fchdir, chroot, getcwd)

use crate::fs::dac::{self, MAY_CHDIR, MAY_EXEC};
use crate::fs::namei::{getname, path_lookupat};
use crate::fs::{Dentry, KernelError, LookupFlags, Path};
use crate::task::percpu::{current_cwd, current_fs};
use crate::uaccess::{UserPtr, copy_to_user};
use crate::util::error::KernelResult;

use super::io::fget_raw;

/// chdir/fchdir/chroot target: a directory with search permission
/// (MAY_EXEC | MAY_CHDIR)
fn may_chdir(d: &Dentry) -> Result<(), KernelError> {
    let inode = d.get_inode().ok_or(KernelError::NotFound)?;
    if !inode.mode().is_dir() {
        return Err(KernelError::NotDirectory);
    }
    dac::permission(&inode, MAY_EXEC | MAY_CHDIR)
}

/// The searchable directory `path_ptr` names, from the cwd
fn chdir_target(path_ptr: UserPtr<u8>) -> KernelResult<Path> {
    let name = getname(path_ptr, false)?;
    let path = path_lookupat(current_cwd(), &name, LookupFlags::opendir())?;
    may_chdir(&path.dentry)?;
    Ok(path)
}

/// sys_chdir - change working directory
pub fn sys_chdir(path_ptr: UserPtr<u8>) -> KernelResult<()> {
    let path = chdir_target(path_ptr)?;
    if let Some(fs) = current_fs() {
        fs.set_pwd(path);
    }
    Ok(())
}

/// sys_fchdir - change working directory via file descriptor
pub fn sys_fchdir(fd: i32) -> KernelResult<()> {
    let file = fget_raw(fd)?;
    may_chdir(&file.dentry)?;
    if let Some(fs) = current_fs()
        && let Some(new_pwd) = file.f_path()
    {
        fs.set_pwd(new_pwd);
    }
    Ok(())
}

/// sys_chroot - change root directory
///
/// Changes the root directory of the calling process to the directory
/// specified in path. This call does not change the current working directory.
///
/// # Errors
/// * EFAULT - Invalid user pointer
/// * ENOENT - Path not found
/// * ENOTDIR - Path is not a directory
/// * EACCES - No execute permission on path
/// * EPERM - Caller lacks CAP_SYS_CHROOT capability
pub fn sys_chroot(path_ptr: UserPtr<u8>) -> KernelResult<()> {
    let path = chdir_target(path_ptr)?;
    // CAP_SYS_CHROOT is checked after the lookup, like Linux
    if !crate::task::capable(crate::task::CAP_SYS_CHROOT) {
        return Err(KernelError::NotPermitted);
    }
    current_fs()
        .ok_or(KernelError::InvalidArgument)?
        .set_root(path);
    Ok(())
}

/// sys_getcwd - get current working directory
///
/// Returns the absolute pathname of the current working directory.
///
/// # Returns
/// Length of the pathname (including null terminator); errors:
/// - EFAULT: Invalid buffer address
/// - ENOENT: Current directory doesn't exist
/// - ERANGE: Buffer too small for pathname
pub fn sys_getcwd(buf: UserPtr<u8>, size: u64) -> KernelResult<usize> {
    let fs = current_fs().ok_or(KernelError::NotFound)?;

    // Linux getcwd: ENOENT for a removed directory; one outside the
    // root (a chroot escape, a detached mount) is "(unreachable)..."
    let pwd = fs.get_pwd();
    if pwd.dentry.is_unhashed() {
        return Err(KernelError::NotFound);
    }
    let root = crate::fs::namei::nd_root()?;
    // Past PATH_MAX (the NUL included) is ENAMETOOLONG (Linux getcwd)
    let (mut path_str, reached) = crate::fs::dentry::try_d_path(&pwd, &root)?;
    if !reached {
        const UNREACHABLE: &[u8] = b"(unreachable)";
        if path_str.len() + UNREACHABLE.len() >= crate::fs::dentry::PATH_MAX {
            return Err(KernelError::NameTooLong);
        }
        path_str.splice(0..0, UNREACHABLE.iter().copied());
    }

    // Need space for path + null terminator
    let path_len = path_str.len() + 1;
    if size < path_len as u64 {
        return Err(KernelError::Range);
    }

    // Copy path to user buffer (with null terminator)
    let mut path_bytes = path_str;
    path_bytes.push(0);
    copy_to_user(buf.addr(), &path_bytes)?;
    Ok(path_len)
}

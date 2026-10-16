//! File linking syscalls (symlink, readlink, link, unlink, rename)
//!
//! This module contains syscalls for creating, reading, and removing
//! filesystem links, as well as renaming files.

use alloc::sync::Arc;

use crate::arch::Uaccess;
use crate::fs::path::{create_entry, delete_entry};
use crate::fs::{
    Dentry, Inode, KernelError, LookupFlags, MAY_WRITE, Path, dac, is_subdir, lock_rename,
    lookup_one, lookup_path_at, unlock_rename,
};
use crate::uaccess::{UaccessArch, copy_to_user, strncpy_from_user};

use super::syscall::{AT_FDCWD, PATH_MAX, current_fd_table, lookup_parent_at};

// =============================================================================
// symlink, symlinkat syscalls
// =============================================================================

/// sys_symlink - create a symbolic link
///
/// Creates a symbolic link named linkpath pointing to target.
///
/// # Arguments
/// * `target_ptr` - User pointer to target path string
/// * `linkpath_ptr` - User pointer to link path string
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_symlink(target_ptr: u64, linkpath_ptr: u64) -> i64 {
    sys_symlinkat(target_ptr, AT_FDCWD, linkpath_ptr)
}

/// sys_symlinkat - create a symbolic link relative to directory fd
///
/// # Arguments
/// * `target_ptr` - User pointer to target path string
/// * `newdirfd` - Directory fd for linkpath, or AT_FDCWD
/// * `linkpath_ptr` - User pointer to link path string
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_symlinkat(target_ptr: u64, newdirfd: i32, linkpath_ptr: u64) -> i64 {
    // Read target from user space
    let target = match strncpy_from_user::<Uaccess>(target_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Read linkpath from user space
    let linkpath = match strncpy_from_user::<Uaccess>(linkpath_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    if target.is_empty() || linkpath.is_empty() {
        return KernelError::NotFound.sysret();
    }

    let (parent, name) = match lookup_parent_at(newdirfd, &linkpath) {
        Ok(p) => p,
        Err(e) => return e,
    };
    match create_entry(&parent, &name, |dir, _| {
        dir.i_op.symlink(dir, &name, &target)
    }) {
        Ok(_) => 0,
        Err(KernelError::OperationNotSupported) => KernelError::NotPermitted.sysret(),
        Err(e) => e.sysret(),
    }
}

// =============================================================================
// readlink, readlinkat syscalls
// =============================================================================

/// sys_readlink - read value of a symbolic link
///
/// Reads the target of a symbolic link into a buffer.
///
/// # Arguments
/// * `path_ptr` - User pointer to path string
/// * `buf_ptr` - User buffer to store the target
/// * `bufsiz` - Size of the buffer
///
/// # Returns
/// Number of bytes placed in buffer (not null-terminated), negative errno on error
pub fn sys_readlink(path_ptr: u64, buf_ptr: u64, bufsiz: u64) -> i64 {
    sys_readlinkat(AT_FDCWD, path_ptr, buf_ptr, bufsiz)
}

/// sys_readlinkat - read value of a symbolic link relative to directory fd
///
/// # Arguments
/// * `dirfd` - Directory fd for relative paths, or AT_FDCWD
/// * `path_ptr` - User pointer to path string
/// * `buf_ptr` - User buffer to store the target
/// * `bufsiz` - Size of the buffer
///
/// # Returns
/// Number of bytes placed in buffer (not null-terminated), negative errno on error
pub fn sys_readlinkat(dirfd: i32, path_ptr: u64, buf_ptr: u64, bufsiz: u64) -> i64 {
    // Read path from user space
    let path = match strncpy_from_user::<Uaccess>(path_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    let bufsiz = bufsiz as usize;
    if bufsiz == 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Validate user buffer address
    if !Uaccess::access_ok(buf_ptr, bufsiz) {
        return KernelError::BadAddress.sysret();
    }

    // Determine starting path for relative paths
    let start: Option<Path> = if path.starts_with('/') {
        None
    } else if dirfd == AT_FDCWD {
        crate::task::percpu::current_cwd()
    } else {
        let file = match current_fd_table().lock().get(dirfd) {
            Some(f) => f,
            None => return KernelError::BadFd.sysret(),
        };
        if !file.is_dir() {
            return KernelError::NotDirectory.sysret();
        }
        Path::from_dentry(file.dentry.clone())
    };

    // Look up the path without following the final symlink
    let mut flags = LookupFlags::open();
    flags.follow = false;

    let dentry = match lookup_path_at(start, &path, flags) {
        Ok(d) => d,
        Err(e) => return e.sysret(),
    };

    // Get inode
    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return KernelError::NotFound.sysret(),
    };

    // Must be a symlink
    if !inode.mode().is_symlink() {
        return KernelError::InvalidArgument.sysret();
    }

    // Read the symlink target
    let target = match inode.i_op.readlink(&inode) {
        Ok(t) => t,
        Err(KernelError::OperationNotSupported) => return KernelError::InvalidArgument.sysret(),
        // e.g. /proc/<pid>/exe: EACCES, ENOENT (Linux returns the
        // get_link error)
        Err(e) => return e.sysret(),
    };

    // Copy to user buffer (without null terminator)
    let copy_len = core::cmp::min(target.len(), bufsiz);
    if copy_to_user::<Uaccess>(buf_ptr, &target.as_bytes()[..copy_len]).is_err() {
        return KernelError::BadAddress.sysret();
    }

    copy_len as i64
}

// =============================================================================
// link, linkat syscalls
// =============================================================================

/// sys_link - create a hard link
///
/// Creates a new name for an existing file.
///
/// # Arguments
/// * `oldpath_ptr` - User pointer to existing path
/// * `newpath_ptr` - User pointer to new path
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_link(oldpath_ptr: u64, newpath_ptr: u64) -> i64 {
    sys_linkat(AT_FDCWD, oldpath_ptr, AT_FDCWD, newpath_ptr, 0)
}

/// sys_linkat - create a hard link relative to directory fds
///
/// # Arguments
/// * `olddirfd` - Directory fd for oldpath, or AT_FDCWD
/// * `oldpath_ptr` - User pointer to existing path
/// * `newdirfd` - Directory fd for newpath, or AT_FDCWD
/// * `newpath_ptr` - User pointer to new path
/// * `flags` - AT_SYMLINK_FOLLOW to follow symlinks in oldpath
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_linkat(
    olddirfd: i32,
    oldpath_ptr: u64,
    newdirfd: i32,
    newpath_ptr: u64,
    flags: i32,
) -> i64 {
    // Read oldpath from user space
    let oldpath = match strncpy_from_user::<Uaccess>(oldpath_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Read newpath from user space
    let newpath = match strncpy_from_user::<Uaccess>(newpath_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    if oldpath.is_empty() || newpath.is_empty() {
        return KernelError::NotFound.sysret();
    }

    // AT_SYMLINK_FOLLOW (0x400) means follow symlinks in oldpath
    let follow = flags & 0x400 != 0;

    // Look up the target file
    let old_start: Option<Path> = if oldpath.starts_with('/') {
        None
    } else if olddirfd == AT_FDCWD {
        crate::task::percpu::current_cwd()
    } else {
        let file = match current_fd_table().lock().get(olddirfd) {
            Some(f) => f,
            None => return KernelError::BadFd.sysret(),
        };
        if !file.is_dir() {
            return KernelError::NotDirectory.sysret();
        }
        Path::from_dentry(file.dentry.clone())
    };

    let mut lookup_flags = LookupFlags::open();
    lookup_flags.follow = follow;

    let old_dentry = match lookup_path_at(old_start, &oldpath, lookup_flags) {
        Ok(d) => d,
        Err(e) => return e.sysret(),
    };
    let Some(old_inode) = old_dentry.get_inode() else {
        return KernelError::NotFound.sysret();
    };

    let (parent, name) = match lookup_parent_at(newdirfd, &newpath) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if old_dentry.superblock().map(|s| s.dev_id) != parent.superblock().map(|s| s.dev_id) {
        return KernelError::CrossDevice.sysret();
    }

    // vfs_link: may_create on the new parent, then no directories
    // (fs.protected_hardlinks is not implemented: its kernel default is 0)
    let r = create_entry(&parent, &name, |dir, _| {
        if old_inode.mode().is_dir() {
            return Err(KernelError::NotPermitted);
        }
        dir.i_op.link(dir, &name, &old_inode)?;
        Ok(old_inode.clone())
    });
    match r {
        Ok(_) => 0,
        Err(KernelError::OperationNotSupported) => KernelError::NotPermitted.sysret(),
        Err(e) => e.sysret(),
    }
}

// =============================================================================
// unlink, unlinkat syscalls
// =============================================================================

/// AT_REMOVEDIR flag for unlinkat - perform rmdir instead of unlink
const AT_REMOVEDIR: i32 = 0x200;

/// sys_unlink - delete a name from the filesystem
///
/// Removes a directory entry for a file. If this was the last link to the file
/// and no processes have it open, the file is deleted.
///
/// # Arguments
/// * `pathname_ptr` - User pointer to path string
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_unlink(pathname_ptr: u64) -> i64 {
    sys_unlinkat(AT_FDCWD, pathname_ptr, 0)
}

/// sys_unlinkat - delete a name relative to a directory file descriptor
///
/// If AT_REMOVEDIR is specified in flags, performs rmdir instead of unlink.
///
/// # Arguments
/// * `dirfd` - Directory file descriptor, or AT_FDCWD for current directory
/// * `pathname_ptr` - User pointer to path string
/// * `flags` - Flags (AT_REMOVEDIR to remove directory)
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_unlinkat(dirfd: i32, pathname_ptr: u64, flags: i32) -> i64 {
    // Read path from user space
    let path = match strncpy_from_user::<Uaccess>(pathname_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    if path.is_empty() {
        return KernelError::NotFound.sysret();
    }

    if flags & AT_REMOVEDIR != 0 {
        return super::dir::do_rmdir(dirfd, &path);
    }
    let (parent, name) = match lookup_parent_at(dirfd, &path) {
        Ok(p) => p,
        Err(e) => return e,
    };
    match delete_entry(&parent, &name, false) {
        Ok(()) => 0,
        Err(e) => e.sysret(),
    }
}

// =============================================================================
// rename, renameat, renameat2 syscalls
// =============================================================================

/// sys_rename - rename a file
///
/// # Arguments
/// * `oldpath_ptr` - User pointer to existing path
/// * `newpath_ptr` - User pointer to new path
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_rename(oldpath_ptr: u64, newpath_ptr: u64) -> i64 {
    sys_renameat2(AT_FDCWD, oldpath_ptr, AT_FDCWD, newpath_ptr, 0)
}

/// sys_renameat - rename a file relative to directory fds
///
/// # Arguments
/// * `olddirfd` - Directory fd for oldpath, or AT_FDCWD
/// * `oldpath_ptr` - User pointer to existing path
/// * `newdirfd` - Directory fd for newpath, or AT_FDCWD
/// * `newpath_ptr` - User pointer to new path
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_renameat(olddirfd: i32, oldpath_ptr: u64, newdirfd: i32, newpath_ptr: u64) -> i64 {
    sys_renameat2(olddirfd, oldpath_ptr, newdirfd, newpath_ptr, 0)
}

/// sys_renameat2 - rename a file with flags
///
/// # Arguments
/// * `olddirfd` - Directory fd for oldpath, or AT_FDCWD
/// * `oldpath_ptr` - User pointer to existing path
/// * `newdirfd` - Directory fd for newpath, or AT_FDCWD
/// * `newpath_ptr` - User pointer to new path
/// * `flags` - RENAME_NOREPLACE, RENAME_EXCHANGE, etc.
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_renameat2(
    olddirfd: i32,
    oldpath_ptr: u64,
    newdirfd: i32,
    newpath_ptr: u64,
    flags: u32,
) -> i64 {
    // Read oldpath from user space
    let oldpath = match strncpy_from_user::<Uaccess>(oldpath_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Read newpath from user space
    let newpath = match strncpy_from_user::<Uaccess>(newpath_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    if oldpath.is_empty() || newpath.is_empty() {
        return KernelError::NotFound.sysret();
    }

    // Extract final components for validation
    let old_basename = oldpath.rsplit('/').next().unwrap_or(&oldpath);
    let new_basename = newpath.rsplit('/').next().unwrap_or(&newpath);

    // Cannot rename "." or ".." - these are special directory entries
    if old_basename == "." || old_basename == ".." {
        return KernelError::InvalidArgument.sysret();
    }
    // Cannot rename TO "." or ".." either
    if new_basename == "." || new_basename == ".." {
        return KernelError::InvalidArgument.sysret();
    }

    // Look up parent of oldpath and get the filename
    let (old_parent_dentry, old_name) = match lookup_parent_at(olddirfd, &oldpath) {
        Ok(p) => p,
        Err(e) => return e,
    };

    // Look up parent of newpath and get the filename
    let (new_parent_dentry, new_name) = match lookup_parent_at(newdirfd, &newpath) {
        Ok(p) => p,
        Err(e) => return e,
    };

    // Check same filesystem
    let old_sb = old_parent_dentry.superblock();
    let new_sb = new_parent_dentry.superblock();
    if old_sb.map(|s| s.dev_id) != new_sb.map(|s| s.dev_id) {
        return KernelError::CrossDevice.sysret();
    }

    // Get parent inodes
    let old_parent_inode = match old_parent_dentry.get_inode() {
        Some(i) => i,
        None => return KernelError::NotFound.sysret(),
    };

    let new_parent_inode = match new_parent_dentry.get_inode() {
        Some(i) => i,
        None => return KernelError::NotFound.sysret(),
    };

    // Write access, then lock directories (Linux do_renameat2)
    let _w = match super::dac::want_write(&old_parent_inode) {
        Ok(w) => w,
        Err(e) => return e.sysret(),
    };
    let _trap = lock_rename(&old_parent_dentry, &new_parent_dentry);
    let r = rename_locked(
        (&old_parent_dentry, &old_parent_inode, &old_name),
        (&new_parent_dentry, &new_parent_inode, &new_name),
        flags,
    );
    unlock_rename(&old_parent_dentry, &new_parent_dentry);
    match r {
        Ok(()) => 0,
        Err(KernelError::OperationNotSupported) => KernelError::InvalidArgument.sysret(),
        Err(e) => e.sysret(),
    }
}

/// Parent dentry, parent inode and name of one side of a rename
type Side<'a> = (&'a Arc<Dentry>, &'a Arc<Inode>, &'a str);

/// The rename itself with both parents locked (Linux do_renameat2 trap
/// check + vfs_rename): may_delete of the source, may_create or
/// may_delete of the target, and write permission on a directory that
/// changes parent (its ".." is rewritten)
fn rename_locked(old: Side, new: Side, flags: u32) -> Result<(), KernelError> {
    const RENAME_EXCHANGE: u32 = 2;
    let (op, odir, oname) = old;
    let (np, ndir, nname) = new;
    let src = lookup_one(op, oname)?;
    let sinode = src.get_inode().ok_or(KernelError::NotFound)?;
    let dinode = lookup_one(np, nname).ok().and_then(|d| d.get_inode());
    let is_dir = sinode.mode().is_dir();

    // Moving a directory into its own subtree
    if is_dir && is_subdir(np, &src) {
        return Err(KernelError::InvalidArgument);
    }
    // Same inode: nothing to do (vfs_rename "source == target")
    if dinode.as_ref().is_some_and(|d| d.ino == sinode.ino) {
        return Ok(());
    }

    let c = dac::cred();
    dac::may_delete(&c, odir, &sinode, is_dir)?;
    let exchange = flags & RENAME_EXCHANGE != 0;
    match &dinode {
        None => dac::may_create(&c, ndir)?,
        Some(d) => dac::may_delete(
            &c,
            ndir,
            d,
            if exchange { d.mode().is_dir() } else { is_dir },
        )?,
    }
    if !Arc::ptr_eq(odir, ndir) {
        if is_dir {
            dac::permission_as(&c, &sinode, MAY_WRITE)?;
        }
        if let Some(d) = dinode.as_ref().filter(|d| exchange && d.mode().is_dir()) {
            dac::permission_as(&c, d, MAY_WRITE)?;
        }
    }

    odir.i_op.rename(odir, oname, ndir, nname, flags)?;
    // New lookups re-create both dentries
    op.remove_child(oname);
    np.remove_child(nname);
    Ok(())
}

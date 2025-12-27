//! File linking syscalls (symlink, readlink, link, unlink, rename)
//!
//! This module contains syscalls for creating, reading, and removing
//! filesystem links, as well as renaming files.

use alloc::sync::Arc;

use crate::arch::Uaccess;
use crate::fs::{
    Dentry, KernelError, LookupFlags, Path, is_subdir, lock_rename, lookup_path_at, unlock_rename,
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

    // Look up parent directory of the new symlink
    let (parent_dentry, name) = match lookup_parent_at(newdirfd, &linkpath) {
        Ok(p) => p,
        Err(e) => return e,
    };

    // Get parent inode
    let parent_inode = match parent_dentry.get_inode() {
        Some(i) => i,
        None => return KernelError::NotFound.sysret(),
    };

    // Lock parent directory (Linux i_rwsem pattern)
    parent_inode.inode_lock();

    // Check if name already exists (with lock held)
    if parent_dentry.lookup_child(&name).is_some() {
        unsafe { parent_inode.inode_unlock() };
        return KernelError::AlreadyExists.sysret();
    }

    // Create the symlink
    let new_inode = match parent_inode.i_op.symlink(&parent_inode, &name, &target) {
        Ok(i) => i,
        Err(e) => {
            unsafe { parent_inode.inode_unlock() };
            return match e {
                KernelError::AlreadyExists => KernelError::AlreadyExists.sysret(),
                KernelError::PermissionDenied => KernelError::PermissionDenied.sysret(),
                KernelError::OperationNotSupported => KernelError::NotPermitted.sysret(),
                _ => KernelError::InvalidArgument.sysret(),
            };
        }
    };

    // Create dentry for the symlink
    let new_dentry = Arc::new(Dentry::new(name, Some(new_inode), parent_dentry.sb.clone()));
    new_dentry.set_parent(&parent_dentry);
    parent_dentry.add_child(new_dentry);

    // Unlock parent directory
    unsafe { parent_inode.inode_unlock() };

    0
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
        Err(KernelError::NotFound) => return KernelError::NotFound.sysret(),
        Err(KernelError::NotDirectory) => return KernelError::NotDirectory.sysret(),
        Err(KernelError::TooManySymlinks) => return KernelError::TooManySymlinks.sysret(),
        Err(_) => return KernelError::InvalidArgument.sysret(),
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
        Err(_) => return KernelError::InvalidArgument.sysret(),
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
        Err(KernelError::NotFound) => return KernelError::NotFound.sysret(),
        Err(KernelError::NotDirectory) => return KernelError::NotDirectory.sysret(),
        Err(KernelError::TooManySymlinks) => return KernelError::TooManySymlinks.sysret(),
        Err(_) => return KernelError::InvalidArgument.sysret(),
    };

    let old_inode = match old_dentry.get_inode() {
        Some(i) => i,
        None => return KernelError::NotFound.sysret(),
    };

    // Cannot hard link directories
    if old_inode.mode().is_dir() {
        return KernelError::NotPermitted.sysret();
    }

    // Look up parent directory of the new link
    let (parent_dentry, name) = match lookup_parent_at(newdirfd, &newpath) {
        Ok(p) => p,
        Err(e) => return e,
    };

    // Check same filesystem
    let old_sb = old_dentry.superblock();
    let new_sb = parent_dentry.superblock();
    if old_sb.map(|s| s.dev_id) != new_sb.map(|s| s.dev_id) {
        return KernelError::CrossDevice.sysret();
    }

    // Get parent inode
    let parent_inode = match parent_dentry.get_inode() {
        Some(i) => i,
        None => return KernelError::NotFound.sysret(),
    };

    // Lock parent directory (Linux i_rwsem pattern)
    parent_inode.inode_lock();

    // Check if name already exists (with lock held)
    if parent_dentry.lookup_child(&name).is_some() {
        unsafe { parent_inode.inode_unlock() };
        return KernelError::AlreadyExists.sysret();
    }

    // Create the hard link
    let result = parent_inode.i_op.link(&parent_inode, &name, &old_inode);

    match result {
        Ok(()) => {
            // Create dentry for the new link
            let new_dentry = Arc::new(Dentry::new(name, Some(old_inode), parent_dentry.sb.clone()));
            new_dentry.set_parent(&parent_dentry);
            parent_dentry.add_child(new_dentry);
            unsafe { parent_inode.inode_unlock() };
            0
        }
        Err(e) => {
            unsafe { parent_inode.inode_unlock() };
            match e {
                KernelError::AlreadyExists => KernelError::AlreadyExists.sysret(),
                KernelError::PermissionDenied => KernelError::PermissionDenied.sysret(),
                KernelError::OperationNotSupported => KernelError::NotPermitted.sysret(),
                _ => KernelError::InvalidArgument.sysret(),
            }
        }
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

    // If AT_REMOVEDIR is set, perform rmdir instead
    if flags & AT_REMOVEDIR != 0 {
        // For AT_REMOVEDIR, delegate to rmdir-like logic
        return sys_unlinkat_rmdir(dirfd, &path);
    }

    // Look up parent directory and name
    let (parent_dentry, name) = match lookup_parent_at(dirfd, &path) {
        Ok(p) => p,
        Err(e) => return e,
    };

    // Get parent inode
    let parent_inode = match parent_dentry.get_inode() {
        Some(i) => i,
        None => return KernelError::NotFound.sysret(),
    };

    // Lock parent directory (Linux i_rwsem pattern)
    parent_inode.inode_lock();

    // Check that target exists (with lock held)
    let target_dentry = match parent_dentry.lookup_child(&name) {
        Some(d) => d,
        None => {
            unsafe { parent_inode.inode_unlock() };
            return KernelError::NotFound.sysret();
        }
    };

    // Verify it's NOT a directory (use rmdir for directories)
    if let Some(target_inode) = target_dentry.get_inode()
        && target_inode.mode().is_dir()
    {
        unsafe { parent_inode.inode_unlock() };
        return KernelError::IsDirectory.sysret();
    }

    // Call unlink on the parent
    let result = parent_inode.i_op.unlink(&parent_inode, &name);

    match result {
        Ok(()) => {
            // Remove dentry from parent's children
            parent_dentry.remove_child(&name);
            unsafe { parent_inode.inode_unlock() };
            0
        }
        Err(e) => {
            unsafe { parent_inode.inode_unlock() };
            match e {
                KernelError::NotFound => KernelError::NotFound.sysret(),
                KernelError::PermissionDenied => KernelError::PermissionDenied.sysret(),
                KernelError::IsDirectory => KernelError::IsDirectory.sysret(),
                _ => KernelError::InvalidArgument.sysret(),
            }
        }
    }
}

/// Helper for unlinkat with AT_REMOVEDIR flag
fn sys_unlinkat_rmdir(dirfd: i32, path: &str) -> i64 {
    // Look up parent directory and name
    let (parent_dentry, name) = match lookup_parent_at(dirfd, path) {
        Ok(p) => p,
        Err(e) => return e,
    };

    // Get parent inode
    let parent_inode = match parent_dentry.get_inode() {
        Some(i) => i,
        None => return KernelError::NotFound.sysret(),
    };

    // Lock parent directory (Linux i_rwsem pattern)
    parent_inode.inode_lock();

    // Check that target exists (with lock held)
    let target_dentry = match parent_dentry.lookup_child(&name) {
        Some(d) => d,
        None => {
            unsafe { parent_inode.inode_unlock() };
            return KernelError::NotFound.sysret();
        }
    };

    // Verify it's a directory
    if let Some(target_inode) = target_dentry.get_inode()
        && !target_inode.mode().is_dir()
    {
        unsafe { parent_inode.inode_unlock() };
        return KernelError::NotDirectory.sysret();
    }

    // Call rmdir on the parent
    let result = parent_inode.i_op.rmdir(&parent_inode, &name);

    match result {
        Ok(()) => {
            // Remove dentry from parent's children
            parent_dentry.remove_child(&name);
            unsafe { parent_inode.inode_unlock() };
            0
        }
        Err(e) => {
            unsafe { parent_inode.inode_unlock() };
            match e {
                KernelError::NotFound => KernelError::NotFound.sysret(),
                KernelError::NotDirectory => KernelError::NotDirectory.sysret(),
                KernelError::DirectoryNotEmpty => KernelError::DirectoryNotEmpty.sysret(),
                KernelError::PermissionDenied => KernelError::PermissionDenied.sysret(),
                KernelError::Busy => -16, // EBUSY
                _ => KernelError::InvalidArgument.sysret(),
            }
        }
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

    // Lock directories for rename (Linux lock_rename pattern)
    // This ensures proper lock ordering to prevent deadlocks:
    // - If one directory is ancestor of other: lock ancestor first
    // - Otherwise: lock by address order
    let _trap = lock_rename(&old_parent_dentry, &new_parent_dentry);

    // Look up the source dentry for cycle detection and same-file check
    let old_dentry = old_parent_dentry.lookup_child(&old_name);

    // Look up target dentry for same-file check
    let new_dentry = new_parent_dentry.lookup_child(&new_name);

    // Same-inode check: if source and target are the same file, return success
    // (Linux vfs_rename: "if (source == target) return 0;")
    if let Some(ref src_dentry) = old_dentry
        && let Some(ref dst_dentry) = new_dentry
        && let (Some(src_inode), Some(dst_inode)) = (src_dentry.get_inode(), dst_dentry.get_inode())
        && src_inode.ino == dst_inode.ino
    {
        unlock_rename(&old_parent_dentry, &new_parent_dentry);
        return 0;
    }

    // Cycle detection: prevent moving a directory into its own subtree
    // This would create an unreachable directory loop
    if let Some(ref src_dentry) = old_dentry
        && let Some(src_inode) = src_dentry.get_inode()
        && src_inode.mode().is_dir()
        // Check if new_parent is a subdirectory of source
        // If so, this rename would create a cycle
        && is_subdir(&new_parent_dentry, src_dentry)
    {
        unlock_rename(&old_parent_dentry, &new_parent_dentry);
        return KernelError::InvalidArgument.sysret();
    }

    // Perform the rename via inode ops
    let result = old_parent_inode.i_op.rename(
        &old_parent_inode,
        &old_name,
        &new_parent_inode,
        &new_name,
        flags,
    );

    // Unlock directories
    unlock_rename(&old_parent_dentry, &new_parent_dentry);

    // Handle result
    match result {
        Ok(()) => {}
        Err(KernelError::NotFound) => return KernelError::NotFound.sysret(),
        Err(KernelError::AlreadyExists) => return KernelError::AlreadyExists.sysret(),
        Err(KernelError::DirectoryNotEmpty) => return KernelError::DirectoryNotEmpty.sysret(),
        Err(KernelError::OperationNotSupported) => return KernelError::InvalidArgument.sysret(),
        Err(KernelError::InvalidArgument) => return KernelError::InvalidArgument.sysret(),
        Err(_) => return KernelError::InvalidArgument.sysret(),
    }

    // Update dentry cache:
    // Remove old dentry from old parent - new lookup will re-create it
    // For cross-directory renames or name changes, also remove target dentry
    old_parent_dentry.remove_child(&old_name);
    new_parent_dentry.remove_child(&new_name);

    0
}

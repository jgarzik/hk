//! Virtual filesystem and filesystem implementations
//!
//! This module provides the VFS layer and filesystem implementations
//! including CPIO (initramfs), ramfs, and procfs.

// Core VFS modules
pub mod blkdev_ops;
pub mod dentry;
pub mod file;
pub mod fsstruct;
pub mod inode;
pub mod mount;
pub mod path;
pub mod path_ref;
pub mod superblock;
pub mod syscall;

// Filesystem implementations
pub mod cpio;
pub mod procfs;
pub mod ramfs;
pub mod vfat;

// Legacy VFS (kept for compatibility)
pub mod vfs;

// Re-exports for convenience
pub use blkdev_ops::BLOCK_FILE_OPS;
pub use cpio::unpack_cpio;
pub use dentry::{DCACHE, Dentry, DentryCache, is_subdir};
pub use file::{CHAR_FILE_OPS, DirEntry, File, FileOps, flags, seek};
pub use fsstruct::{FsStruct, clone_task_fs, exit_task_fs, get_task_fs, init_task_fs};
pub use inode::{DevId, DeviceType, FileType, Gid, Inode, InodeAttr, InodeMode, InodeOps, Uid};
pub use mount::{
    MOUNT_NS, Mount, MountNamespace, do_mount, do_mount_dev, do_umount, follow_mount,
    mount_at_path, umount_flags,
};
pub use path::{
    LookupFlags, MAY_EXEC, MAY_READ, MAY_WRITE, create_dir, create_file, inode_permission,
    lookup_path, lookup_path_at, lookup_path_flags,
};
pub use path_ref::Path;
pub use procfs::{PROCFS_FILE_OPS, PROCFS_TYPE};
pub use ramfs::{
    RAMFS_FILE_OPS, RAMFS_INODE_OPS, RAMFS_TYPE, RamfsInodeData, ramfs_create_blkdev,
    ramfs_create_chrdev, ramfs_create_dir, ramfs_create_dir_with_owner,
    ramfs_create_dir_with_timestamp, ramfs_create_file_with_timestamp, ramfs_mkpath_with_timestamp,
};
pub use superblock::{
    FileSystemType, SuperBlock, SuperOps, find_filesystem, init_fs_registry, register_filesystem,
};
pub use vfat::{VFAT_FILE_OPS, VFAT_TYPE};
pub use vfs::{FileMetadata, FileSystem, FsError, Vfs};

/// Filesystem error types (extending the original FsError)
impl FsError {
    /// Operation not supported
    pub const fn not_supported() -> Self {
        FsError::NotSupported
    }
}

// Add additional error variants
impl From<&str> for FsError {
    fn from(_: &str) -> Self {
        FsError::IoError
    }
}

use alloc::sync::Arc;

/// Open a file for kernel use (kernel-internal open for execution)
///
/// This is a kernel-internal helper that opens a file by path using the VFS.
/// It checks for execute permission and returns an Arc<File> suitable for reading.
///
/// # Arguments
/// * `path` - Path to the file to open
///
/// # Returns
/// * `Ok(Arc<File>)` - File handle for reading
/// * `Err(i32)` - Negative errno on error (ENOENT, EACCES, etc.)
pub fn kernel_open_exec(path: &str) -> Result<Arc<File>, i32> {
    const ENOENT: i32 = 2;
    const EACCES: i32 = 13;

    // Look up the path
    let dentry = lookup_path_flags(path, LookupFlags::open()).map_err(|e| match e {
        FsError::NotFound => ENOENT,
        FsError::NotADirectory => ENOENT,
        FsError::PermissionDenied => EACCES,
        _ => ENOENT,
    })?;

    // Get the inode
    let inode = dentry.get_inode().ok_or(ENOENT)?;

    // Must be a regular file
    if !inode.mode().is_file() {
        return Err(EACCES);
    }

    // Check execute permission (mode has S_IXUSR, S_IXGRP, S_IXOTH)
    // For now, root bypasses this - real implementation would check credentials
    let mode = inode.mode().perm();
    if mode & 0o111 == 0 {
        // No execute permission bits set
        return Err(EACCES);
    }

    // Get the file operations from the filesystem type via superblock
    let f_op: &'static dyn FileOps = dentry
        .superblock()
        .map(|sb| sb.fs_type.file_ops)
        .unwrap_or(&ramfs::RAMFS_FILE_OPS);

    // Create file object with read-only access
    let file = Arc::new(File::new(dentry, flags::O_RDONLY, f_op));

    Ok(file)
}

// ============================================================================
// Rename locking helpers (Linux lock_rename pattern from fs/namei.c)
// ============================================================================

/// Lock two directories for rename operation
///
/// This implements Linux's lock_rename() pattern from fs/namei.c.
///
/// For cross-directory renames, acquires the per-superblock s_vfs_rename_mutex
/// first to prevent tree topology changes during ancestor checks. This matches
/// Linux's lock_rename() which serializes all cross-directory renames on the
/// same filesystem.
///
/// Lock ordering:
/// 1. If cross-directory: acquire SuperBlock.s_vfs_rename_mutex
/// 2. If same directory: single lock only
/// 3. If p1 is ancestor of p2: lock p1 first, then p2
/// 4. If p2 is ancestor of p1: lock p2 first, then p1
/// 5. Otherwise: lock by address order (lower address first)
///
/// Returns the "trap" dentry if one is an ancestor of the other, else None.
/// The trap is used by callers to detect when the source is being moved
/// into its own subtree.
///
/// # Arguments
/// * `p1` - First directory dentry (typically old_parent)
/// * `p2` - Second directory dentry (typically new_parent)
///
/// # Returns
/// * `Some(trap)` - If one directory is ancestor of the other
/// * `None` - If directories are unrelated or the same
pub fn lock_rename(p1: &Arc<Dentry>, p2: &Arc<Dentry>) -> Option<Arc<Dentry>> {
    // Same directory - single lock, no need for superblock mutex
    if Arc::ptr_eq(p1, p2) {
        p1.rename_lock();
        return None;
    }

    // Cross-directory: acquire superblock mutex first
    // This prevents tree topology changes during ancestor check
    // (matches Linux's s_vfs_rename_mutex pattern)
    if let Some(sb) = p1.superblock() {
        // Acquire s_vfs_rename_mutex - prevents any other rename
        // from modifying tree topology during our ancestor check
        let guard = sb.s_vfs_rename_mutex.lock();
        core::mem::forget(guard); // Hold across function calls
    }

    // Now safe to check ancestor relationships - topology is stable
    // because we hold s_vfs_rename_mutex

    // Check if p1 is ancestor of p2
    if is_subdir(p2, p1) {
        // p1 is ancestor - lock it first (parent before child)
        p1.rename_lock();
        p2.rename_lock();
        return Some(p1.clone());
    }

    // Check if p2 is ancestor of p1
    if is_subdir(p1, p2) {
        // p2 is ancestor - lock it first (parent before child)
        p2.rename_lock();
        p1.rename_lock();
        return Some(p2.clone());
    }

    // No ancestor relationship - use address ordering to prevent deadlock
    let p1_ptr = Arc::as_ptr(p1) as usize;
    let p2_ptr = Arc::as_ptr(p2) as usize;

    if p1_ptr < p2_ptr {
        p1.rename_lock();
        p2.rename_lock();
    } else {
        p2.rename_lock();
        p1.rename_lock();
    }

    None
}

/// Unlock directories after rename operation
///
/// Must be called after lock_rename() to release the locks.
/// Unlocks in reverse order of acquisition:
/// 1. Release dentry rename_locks
/// 2. Release SuperBlock.s_vfs_rename_mutex (for cross-directory only)
///
/// # Safety
/// Must only be called after a successful lock_rename() call on the same dentries.
pub fn unlock_rename(p1: &Arc<Dentry>, p2: &Arc<Dentry>) {
    // Safety: caller guarantees we acquired these locks via lock_rename()
    unsafe {
        // Always unlock p2 first (it was locked second in most cases)
        p2.rename_unlock();

        // Only unlock p1 and release superblock mutex if cross-directory
        if !Arc::ptr_eq(p1, p2) {
            p1.rename_unlock();

            // Release superblock mutex for cross-directory case
            if let Some(sb) = p1.superblock() {
                sb.s_vfs_rename_mutex.force_unlock();
            }
        }
    }
}

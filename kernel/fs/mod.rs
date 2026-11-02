//! Virtual filesystem and filesystem implementations
//!
//! This module provides the VFS layer and filesystem implementations
//! including CPIO (initramfs), ramfs, and procfs.

// Core VFS modules
pub mod blkdev_ops;
pub mod dac;
pub mod dentry;
pub mod file;
pub mod fsstruct;
pub mod inode;
pub mod mount;
pub mod path;
pub mod path_ref;
pub mod splice;
pub mod superblock;
pub mod syscall;

// Syscall implementation modules
pub mod anon_inodes;
pub mod dir;
pub mod fd;
pub mod flock;
pub mod fs_writeback;
pub mod icache;
pub mod io;
pub mod iov;
pub mod link;
pub mod locks;
pub mod misc;
pub mod nav;
pub mod open;
pub mod perm;
#[path = "poll.rs"]
pub mod pollsys;
pub mod posix_lock;
pub mod stat;
pub mod sync;

// Filesystem implementations
pub mod cgroupfs;
pub mod cpio;
pub mod devtmpfs;
mod proc_array;
pub mod procfs;
pub mod ramfs;
pub mod vfat;

// Re-exports for convenience
pub use crate::error::KernelError;
pub use blkdev_ops::BLOCK_FILE_OPS;
pub use cgroupfs::{CGROUPFS_FILE_OPS, CGROUPFS_TYPE};
pub use cpio::unpack_cpio;
pub use dac::{MAY_EXEC, MAY_READ, MAY_WRITE};
pub use dentry::{DCACHE, Dentry, DentryCache, is_subdir};
pub use file::{CHAR_FILE_OPS, DirContext, DirEntry, File, FileOps, RwFlags, flags, seek};
pub use fsstruct::{FsStruct, clone_task_fs, exit_task_fs, get_task_fs, init_task_fs};
pub use inode::{DevId, DeviceType, FileType, Gid, Inode, InodeAttr, InodeMode, InodeOps, Uid};
pub use mount::{Mount, do_mount, do_umount, follow_mount, mount_at_path, umount_flags};
pub use path::{LookupFlags, lookup_one, lookup_path, lookup_path_at, lookup_path_flags};
pub use path_ref::Path;
pub use procfs::{
    NamespaceType, PROCFS_FILE_OPS, PROCFS_TYPE, ProcfsInodeData, ProcfsInodeWrapper,
};
pub use ramfs::{
    RAMFS_FILE_OPS, RAMFS_INODE_OPS, RAMFS_TYPE, RamfsInodeData, ramfs_create_blkdev,
    ramfs_create_chrdev, ramfs_create_dir, ramfs_create_dir_with_owner,
    ramfs_create_dir_with_timestamp, ramfs_create_file_with_timestamp, ramfs_mkpath_with_timestamp,
};
pub use superblock::{
    FileSystemType, LinuxStatFs, MSDOS_SUPER_MAGIC, PROC_SUPER_MAGIC, RAMFS_MAGIC, StatFs,
    SuperBlock, SuperOps, find_filesystem, init_fs_registry, register_filesystem,
};
pub use vfat::{VFAT_FILE_OPS, VFAT_TYPE};

use alloc::sync::Arc;

/// Open a file for execve (Linux do_open_execat): the walk's search
/// checks, then may_open for MAY_EXEC (x permission; CAP_DAC_OVERRIDE
/// only if some x bit is set; directories and devices EACCES) and a
/// regular file. Kernel-internal callers (init) have root credentials.
///
/// Returns a read-only file, or a positive errno (ENOENT, EACCES, ...).
pub fn kernel_open_exec(path: &str) -> Result<Arc<File>, i32> {
    let dentry = lookup_path_flags(path, LookupFlags::open()).map_err(|e| e as i32)?;
    open_exec(dentry)
}

/// The checks and open of kernel_open_exec on a dentry already looked up
/// (execveat: relative to a dirfd, the dirfd's own file, or a final
/// symlink not followed, which is ELOOP like Linux's may_open)
pub fn open_exec(dentry: Arc<Dentry>) -> Result<Arc<File>, i32> {
    let inode = dentry.get_inode().ok_or(KernelError::NotFound as i32)?;
    if inode.mode().is_symlink() {
        return Err(KernelError::TooManySymlinks as i32);
    }
    // may_open: no exec from a noexec mount (path_noexec). A file
    // keeps no mount, so it is looked up in the caller's namespace; one
    // not found there (an fd from another namespace) fails closed
    if inode.mode().is_file() {
        let mnt = crate::ns::current_mnt_ns().find_mount_for_dentry(&dentry);
        if mnt.is_none_or(|m| m.flags() & mount::MNT_NOEXEC != 0) {
            return Err(KernelError::PermissionDenied as i32);
        }
    }
    dac::may_open(&dac::cred(), &inode, MAY_EXEC, flags::O_RDONLY).map_err(|e| e as i32)?;
    if !inode.mode().is_file() {
        return Err(KernelError::PermissionDenied as i32);
    }
    let f_op: &'static dyn FileOps = dentry
        .superblock()
        .map(|sb| sb.fs_type.file_ops)
        .unwrap_or(&ramfs::RAMFS_FILE_OPS);
    Ok(Arc::new(File::new(dentry, flags::O_RDONLY, f_op)))
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
/// Returns the held locks; `trap()` is the parent that is an ancestor
/// of the other, if one is: the source may not move into its own
/// subtree.
///
/// # Arguments
/// * `p1` - First directory dentry (typically old_parent)
/// * `p2` - Second directory dentry (typically new_parent)
pub fn lock_rename(p1: &Arc<Dentry>, p2: &Arc<Dentry>) -> RenameLock {
    let lock = |d: &Arc<Dentry>| d.get_inode().map(|i| i.lock_arc());
    let mut g = RenameLock {
        trap: None,
        locks: [None, None],
        sb: None,
    };
    // Same directory - single lock, no need for superblock mutex
    if same_dir(p1, p2) {
        g.locks[0] = lock(p1);
        return g;
    }

    // Cross-directory: the superblock mutex first, so the tree's shape
    // cannot change during the ancestor checks (Linux s_vfs_rename_mutex)
    if let Some(sb) = p1.superblock() {
        sb.s_vfs_rename_mutex.lock_raw(); // released by RenameLock's drop
        g.sb = Some(sb);
    }

    // Ancestor first (parent before child), else by address
    let first_p1 = if is_subdir(p2, p1) {
        g.trap = Some(p1.clone());
        true
    } else if is_subdir(p1, p2) {
        g.trap = Some(p2.clone());
        false
    } else {
        Arc::as_ptr(p1) < Arc::as_ptr(p2)
    };
    let (a, b) = if first_p1 { (p1, p2) } else { (p2, p1) };
    g.locks[0] = lock(a);
    g.locks[1] = lock(b);
    g
}

/// The locks of [`lock_rename`]: released in reverse, then the
/// superblock's rename mutex (Linux unlock_rename)
#[must_use]
pub struct RenameLock {
    trap: Option<Arc<Dentry>>,
    /// The parents' i_rwsem, in the order taken
    locks: [Option<inode::InodeLockArc>; 2],
    /// Its s_vfs_rename_mutex is held (cross-directory)
    sb: Option<Arc<SuperBlock>>,
}

impl RenameLock {
    /// The parent that is an ancestor of the other, if one is
    pub fn trap(&self) -> Option<&Arc<Dentry>> {
        self.trap.as_ref()
    }
}

impl Drop for RenameLock {
    fn drop(&mut self) {
        self.locks[1].take();
        self.locks[0].take();
        if let Some(sb) = self.sb.take() {
            // SAFETY: taken in lock_rename for this guard, released once
            unsafe { sb.s_vfs_rename_mutex.unlock_raw() };
        }
    }
}

/// Same directory for lock_rename: the same dentry, or two dentries of
/// one inode (bind mounts) - its i_rwsem must be taken once
fn same_dir(p1: &Arc<Dentry>, p2: &Arc<Dentry>) -> bool {
    Arc::ptr_eq(p1, p2)
        || matches!((p1.get_inode(), p2.get_inode()), (Some(a), Some(b)) if Arc::ptr_eq(&a, &b))
}

/// The non-directories of `a` and `b`, each once, lowest address first
/// (Linux lock_two_nondirectories order)
fn nondirs<'a>(
    a: Option<&'a Arc<Inode>>,
    b: Option<&'a Arc<Inode>>,
) -> [Option<&'a Arc<Inode>>; 2] {
    let nd = |i: Option<&'a Arc<Inode>>| i.filter(|i| !i.mode().is_dir());
    let (a, b) = (nd(a), nd(b));
    match (a, b) {
        (Some(x), Some(y)) if Arc::ptr_eq(x, y) => [Some(x), None],
        (Some(x), Some(y)) if Arc::as_ptr(y) < Arc::as_ptr(x) => [Some(y), Some(x)],
        _ => [a, b],
    }
}

/// Lock the inodes whose link count a rename changes, inside the parents'
/// locks (Linux vfs_rename -> lock_two_nondirectories): the non-directory
/// source and target, by address. Directories are skipped: they have no
/// hard links to race with.
pub fn lock_two_nondirs<'a>(
    a: Option<&'a Arc<Inode>>,
    b: Option<&'a Arc<Inode>>,
) -> NondirsLock<'a> {
    let [x, y] = nondirs(a, b);
    let first = x.map(|i| i.lock());
    NondirsLock([first, y.map(|i| i.lock())])
}

/// The locks of [`lock_two_nondirs`], released in reverse order
#[must_use]
pub struct NondirsLock<'a>([Option<inode::InodeLock<'a>>; 2]);

impl Drop for NondirsLock<'_> {
    fn drop(&mut self) {
        self.0[1].take();
        self.0[0].take();
    }
}

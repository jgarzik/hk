//! Mount - filesystem mount infrastructure
//!
//! Manages the mount tree that connects filesystems into a unified namespace.

use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use crate::sync::spin::RwLock;
use ::core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::KernelError;
use super::dentry::Dentry;
use super::inode::{FileType, Inode};
use super::superblock::{FileSystemType, SuperBlock};

use crate::storage::get_blkdev;

/// Ignore set-user/group-ID bits on exec (Linux MNT_NOSUID)
pub const MNT_NOSUID: u32 = 0x1;
/// No access to device nodes (Linux MNT_NODEV)
pub const MNT_NODEV: u32 = 0x2;
/// No program execution (Linux MNT_NOEXEC)
pub const MNT_NOEXEC: u32 = 0x4;

/// A mount point in the namespace
///
/// This struct mirrors Linux's `struct vfsmount`. The reference count
/// (`mnt_count`) tracks users of this mount - each open file that references
/// this mount holds a reference via `mntget()`.
pub struct Mount {
    /// The mounted filesystem's superblock
    pub sb: Arc<SuperBlock>,

    /// Root dentry of the mounted filesystem
    pub root: Arc<Dentry>,

    /// The dentry where this filesystem is mounted (mount point)
    /// None for the root mount
    pub mountpoint: RwLock<Option<Arc<Dentry>>>,

    /// Parent mount (None for root)
    pub parent: RwLock<Option<Weak<Mount>>>,

    /// Child mounts (filesystems mounted under this one)
    pub children: RwLock<Vec<Arc<Mount>>>,

    /// Per-mount MNT_* flags (Linux mnt_flags): MNT_NOSUID, MNT_NODEV,
    /// MNT_NOEXEC
    mnt_flags: AtomicU32,

    /// Reference count for this mount (like Linux mnt_count)
    ///
    /// Tracks active users of this mount. Each open file holds a reference
    /// via mntget(). Incremented by mntget(), decremented by mntput().
    /// The mount cannot be unmounted while mnt_count > 0 (unless MNT_FORCE/MNT_DETACH).
    mnt_count: AtomicU64,
}

impl Mount {
    /// Create a new mount
    pub fn new(sb: Arc<SuperBlock>, root: Arc<Dentry>, flags: u32) -> Arc<Self> {
        Arc::new(Self {
            sb,
            root,
            mountpoint: RwLock::new(None),
            parent: RwLock::new(None),
            children: RwLock::new(Vec::new()),
            mnt_flags: AtomicU32::new(flags),
            mnt_count: AtomicU64::new(0),
        })
    }

    /// MNT_* flags
    pub fn flags(&self) -> u32 {
        self.mnt_flags.load(Ordering::Relaxed)
    }

    /// Replace the MNT_* flags (mount, remount)
    pub fn set_flags(&self, f: u32) {
        self.mnt_flags.store(f, Ordering::Relaxed);
    }

    /// Option string for /proc/mounts ("ro,nosuid,nodev,noexec")
    pub fn opts(&self) -> String {
        let mut o = String::from(if self.sb.rdonly() { "ro" } else { "rw" });
        let f = self.flags();
        for (bit, name) in [
            (MNT_NOSUID, ",nosuid"),
            (MNT_NODEV, ",nodev"),
            (MNT_NOEXEC, ",noexec"),
        ] {
            if f & bit != 0 {
                o.push_str(name);
            }
        }
        o
    }

    /// Increment mount reference count (like Linux mntget)
    ///
    /// Called when a file is opened on this filesystem.
    /// The caller should hold an Arc<Mount> reference and call this
    /// to indicate active use of the mount.
    pub fn mntget(&self) {
        self.mnt_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement mount reference count (like Linux mntput)
    ///
    /// Called when a file is closed.
    pub fn mntput(&self) {
        self.mnt_count.fetch_sub(1, Ordering::Relaxed);
    }

    /// Get current mount reference count (like Linux mnt_get_count)
    ///
    /// Returns the number of active users of this mount.
    pub fn mnt_get_count(&self) -> u64 {
        self.mnt_count.load(Ordering::Relaxed)
    }

    /// Get the mount point dentry
    pub fn get_mountpoint(&self) -> Option<Arc<Dentry>> {
        self.mountpoint.read().clone()
    }

    /// Set the mount point
    pub fn set_mountpoint(&self, dentry: Arc<Dentry>) {
        dentry.set_mountpoint(true);
        *self.mountpoint.write() = Some(dentry);
    }

    /// Get parent mount
    pub fn get_parent(&self) -> Option<Arc<Mount>> {
        self.parent
            .read()
            .as_ref()
            .and_then(|w: &Weak<Mount>| w.upgrade())
    }

    /// Set parent mount
    pub fn set_parent(&self, parent: &Arc<Mount>) {
        *self.parent.write() = Some(Arc::downgrade(parent));
    }

    /// Add a child mount
    pub fn add_child(&self, child: Arc<Mount>) {
        self.children.write().push(child);
    }

    /// Find a child mount at the given dentry
    pub fn find_child_at(&self, dentry: &Dentry) -> Option<Arc<Mount>> {
        let children = self.children.read();
        for child in children.iter() {
            let mp: Option<Arc<Dentry>> = child.get_mountpoint();
            if let Some(mp) = mp {
                // Compare by checking if mountpoint's inode matches
                let mp_ino: Option<Arc<Inode>> = mp.get_inode();
                let d_ino: Option<Arc<Inode>> = dentry.get_inode();
                if let (Some(mp_i), Some(d_i)) = (mp_ino, d_ino)
                    && mp_i.ino == d_i.ino
                {
                    return Some(child.clone());
                }
            }
        }
        None
    }

    /// Remove a child mount from this mount's children list
    pub fn remove_child(&self, child: &Arc<Mount>) -> bool {
        let mut children = self.children.write();
        if let Some(pos) = children.iter().position(|c| Arc::ptr_eq(c, child)) {
            children.remove(pos);
            true
        } else {
            false
        }
    }

    /// Check if this mount has any child mounts
    pub fn has_children(&self) -> bool {
        !self.children.read().is_empty()
    }

    /// Deep clone a mount tree for a new namespace
    ///
    /// Creates a copy of the entire mount tree rooted at this mount.
    /// Each mount in the new tree references the same superblock/dentry
    /// as the original (the filesystem data is shared), but the mount
    /// structures themselves are independent.
    ///
    /// This is used by CLONE_NEWNS to give a new mount namespace its
    /// own view of the mount hierarchy.
    pub fn clone_tree(root: &Arc<Mount>) -> Result<Arc<Mount>, i32> {
        // Clone the root mount
        let new_root = Arc::new(Mount {
            sb: root.sb.clone(),
            root: root.root.clone(),
            mountpoint: RwLock::new(None), // Root has no mountpoint
            parent: RwLock::new(None),     // Root has no parent
            children: RwLock::new(Vec::new()),
            mnt_flags: AtomicU32::new(root.flags()),
            mnt_count: AtomicU64::new(0),
        });

        // Recursively clone children
        for child in root.children.read().iter() {
            Self::clone_subtree(&new_root, child)?;
        }

        Ok(new_root)
    }

    /// Clone a subtree and attach it to a parent
    fn clone_subtree(new_parent: &Arc<Mount>, old_mount: &Arc<Mount>) -> Result<(), i32> {
        // Clone this mount
        let new_mount = Arc::new(Mount {
            sb: old_mount.sb.clone(),
            root: old_mount.root.clone(),
            mountpoint: RwLock::new(old_mount.mountpoint.read().clone()),
            parent: RwLock::new(Some(Arc::downgrade(new_parent))),
            children: RwLock::new(Vec::new()),
            mnt_flags: AtomicU32::new(old_mount.flags()),
            mnt_count: AtomicU64::new(0),
        });

        // Add to parent's children
        new_parent.children.write().push(new_mount.clone());

        // Recursively clone this mount's children
        for child in old_mount.children.read().iter() {
            Self::clone_subtree(&new_mount, child)?;
        }

        Ok(())
    }
}

// Mount is Send + Sync
unsafe impl Send for Mount {}
unsafe impl Sync for Mount {}

/// Mount a filesystem at a path
///
/// If path is None or "/", this becomes the root mount.
///
/// Uses the current task's mount namespace, or init namespace if no task context.
pub fn do_mount(
    fs_type: &'static FileSystemType,
    mountpoint: Option<Arc<Dentry>>,
) -> Result<Arc<Mount>, KernelError> {
    let sb = (fs_type.mount)(fs_type)?;
    attach(sb, mountpoint, 0, false)
}

/// Mount `sb` on `mountpoint` (None: as the namespace root) with MNT_*
/// flags `mnt_flags` and read-only state `ro`, which are set before the
/// mount becomes visible (Linux do_new_mount: no window with weaker
/// flags)
pub fn attach(
    sb: Arc<SuperBlock>,
    mountpoint: Option<Arc<Dentry>>,
    mnt_flags: u32,
    ro: bool,
) -> Result<Arc<Mount>, KernelError> {
    let root = sb.get_root().ok_or(KernelError::InvalidArgument)?;
    if ro {
        sb.make_rdonly()?;
    }
    let mount = Mount::new(sb, root, mnt_flags);
    let mnt_ns = crate::ns::current_mnt_ns();
    if let Some(mp) = mountpoint {
        // Under the mountpoint's i_rwsem (Linux lock_mount), which rmdir
        // and a rename replacing it hold: a directory removed meanwhile
        // is refused, one being removed sees this mount (EBUSY)
        let dir = mp.get_inode().ok_or(KernelError::NotFound)?;
        dir.inode_lock();
        if dir.is_dead() {
            unsafe { dir.inode_unlock() };
            return Err(KernelError::NotFound);
        }
        mount.set_mountpoint(mp.clone());
        // For simplicity, add to the root mount's children
        if let Some(root_mount) = mnt_ns.get_root() {
            mount.set_parent(&root_mount);
            root_mount.add_child(mount.clone());
        }
        unsafe { dir.inode_unlock() };
    } else {
        mnt_ns.set_root(mount.clone());
    }
    Ok(mount)
}

/// Mount a filesystem at a path string
pub fn mount_at_path(
    fs_type: &'static FileSystemType,
    path: &str,
) -> Result<Arc<Mount>, KernelError> {
    if path == "/" || path.is_empty() {
        // Root mount
        do_mount(fs_type, None)
    } else {
        // Look up the mount point
        let dentry = super::path::lookup_path(path)?;
        do_mount(fs_type, Some(dentry))
    }
}

/// Superblock of a device-backed filesystem (vfat, ...) on the block
/// device at `source` (e.g. "/dev/rd1"); mount it with `attach`
pub fn dev_super(
    fs_type: &'static FileSystemType,
    source: &str,
) -> Result<Arc<SuperBlock>, KernelError> {
    // The filesystem must support device mounting
    let mount_dev_fn = fs_type
        .mount_dev
        .ok_or(KernelError::OperationNotSupported)?;

    // Look up the source device path
    let source_dentry = super::path::lookup_path(source)?;
    let source_inode = source_dentry.get_inode().ok_or(KernelError::NotFound)?;

    // Verify it's a block device
    if source_inode.mode().file_type() != Some(FileType::BlockDev) {
        return Err(KernelError::NotBlockDevice);
    }

    // Get the BlockDevice from the registry using the inode's rdev
    let bdev = get_blkdev(source_inode.rdev).ok_or(KernelError::NoDevice)?;

    // Call the filesystem's mount_dev function
    mount_dev_fn(fs_type, bdev)
}

// ============================================================================
// Umount Support
// ============================================================================

/// Umount flags (from Linux)
pub mod umount_flags {
    /// Force unmount even if busy
    pub const MNT_FORCE: i32 = 1;
    /// Lazy unmount - detach now, cleanup later
    pub const MNT_DETACH: i32 = 2;
    /// Don't follow symlinks in path
    pub const UMOUNT_NOFOLLOW: i32 = 8;
}

/// Check if a mount is busy (has open files or child mounts)
///
/// This mirrors Linux's may_umount() / vfs_is_busy() logic:
/// - Check for child mounts
/// - Check mnt_count for active file references
fn is_mount_busy(mount: &Arc<Mount>) -> bool {
    // Check for child mounts - can't unmount if there are filesystems mounted under us
    if mount.has_children() {
        return true;
    }

    // Check for open files on this mount
    // Each open File holds a reference via mntget()
    if mount.mnt_get_count() > 0 {
        return true;
    }

    false
}

/// Unmount a filesystem
///
/// # Arguments
/// * `mount` - The mount to unmount
/// * `flags` - Umount flags (MNT_FORCE, MNT_DETACH, etc.)
///
/// # Errors
/// * `KernelError::Busy` - Mount is busy and MNT_FORCE/MNT_DETACH not specified
/// * `KernelError::InvalidArgument` - Trying to unmount root filesystem
pub fn do_umount(mount: Arc<Mount>, flags: i32) -> Result<(), KernelError> {
    // Cannot unmount the root filesystem
    if mount.get_mountpoint().is_none() {
        return Err(KernelError::InvalidArgument);
    }

    // Check if busy (unless force or detach)
    let force = (flags & umount_flags::MNT_FORCE) != 0;
    let detach = (flags & umount_flags::MNT_DETACH) != 0;

    if !force && !detach && is_mount_busy(&mount) {
        return Err(KernelError::Busy);
    }

    // Clear the mountpoint flag on the dentry
    if let Some(mp) = mount.get_mountpoint() {
        mp.set_mountpoint(false);
    }

    // Remove from parent's children list
    if let Some(parent) = mount.get_parent() {
        parent.remove_child(&mount);
    }

    // Clear parent reference
    *mount.parent.write() = None;

    // Clear mountpoint reference
    *mount.mountpoint.write() = None;

    Ok(())
}

/// Something is mounted on `d` in the caller's mount namespace (Linux
/// is_local_mountpoint): a walk of the namespace's mounts for one whose
/// mountpoint is `d`'s inode (same superblock and number, the key
/// follow_mount uses), so a dentry rebuilt after its old one was
/// dropped (a rename of an ancestor) still counts
pub fn is_local_mountpoint(d: &Arc<Dentry>) -> bool {
    let Some(inode) = d.get_inode() else {
        return false;
    };
    let Some(root) = crate::ns::current_mnt_ns().get_root() else {
        return false;
    };
    let same = |mp: Arc<Dentry>| {
        mp.get_inode()
            .is_some_and(|i| i.ino == inode.ino && i.sb.ptr_eq(&inode.sb))
    };
    let mut todo = alloc::vec![root];
    while let Some(m) = todo.pop() {
        for c in m.children.read().iter() {
            if c.get_mountpoint().is_some_and(same) {
                return true;
            }
            todo.push(c.clone());
        }
    }
    false
}

/// MNT_* flags of the mount `dentry` belongs to (0 if none)
pub fn mnt_flags_of(dentry: &Arc<Dentry>) -> u32 {
    crate::ns::current_mnt_ns()
        .find_mount_for_dentry(dentry)
        .map_or(0, |m| m.flags())
}

/// Check if a dentry is a mount point and get the mounted filesystem's root
pub fn follow_mount(dentry: &Arc<Dentry>) -> Arc<Dentry> {
    if !dentry.is_mountpoint() {
        return dentry.clone();
    }

    // Find the mount at this dentry using current namespace
    let mnt_ns = crate::ns::current_mnt_ns();
    if let Some(root_mount) = mnt_ns.get_root() {
        // Check children for a mount at this dentry
        let children = root_mount.children.read();
        for child in children.iter() {
            let mp: Option<Arc<Dentry>> = child.get_mountpoint();
            if let Some(mp) = mp {
                let mp_ino: Option<Arc<Inode>> = mp.get_inode();
                let d_ino: Option<Arc<Inode>> = dentry.get_inode();
                if let (Some(mp_i), Some(d_i)) = (mp_ino, d_ino)
                    && mp_i.ino == d_i.ino
                {
                    return child.root.clone();
                }
            }
        }
    }

    dentry.clone()
}

//! Mount - filesystem mount infrastructure
//!
//! Manages the mount tree that connects filesystems into a unified namespace.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use ::core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

use super::KernelError;
use super::dentry::Dentry;
use super::inode::{FileType, Inode};
use super::superblock::{FileSystemType, SuperBlock};

use crate::storage::get_blkdev;

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

    /// Mount flags
    pub flags: u32,

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
            flags,
            mnt_count: AtomicU64::new(0),
        })
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
            flags: root.flags,
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
            flags: old_mount.flags,
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

/// Mount namespace - the global mount tree
pub struct MountNamespace {
    /// Root mount of the namespace
    root: RwLock<Option<Arc<Mount>>>,
}

impl MountNamespace {
    /// Create a new empty namespace
    pub const fn new() -> Self {
        Self {
            root: RwLock::new(None),
        }
    }

    /// Find which mount a dentry belongs to
    ///
    /// Given a dentry, returns the mount whose filesystem contains it.
    /// This walks up the mount tree to find the appropriate mount.
    pub fn find_mount_for(&self, dentry: &Arc<Dentry>) -> Option<Arc<Mount>> {
        let root = self.get_root()?;

        // Check if dentry belongs to root mount's filesystem
        if let Some(dentry_sb) = dentry.superblock() {
            // First check root mount
            if dentry_sb.dev_id == root.sb.dev_id {
                return Some(root.clone());
            }

            // Check children recursively
            self.find_mount_for_recursive(&root, dentry_sb.dev_id)
        } else {
            // Fall back to root mount
            Some(root)
        }
    }

    fn find_mount_for_recursive(&self, mount: &Arc<Mount>, dev_id: u64) -> Option<Arc<Mount>> {
        for child in mount.children.read().iter() {
            if child.sb.dev_id == dev_id {
                return Some(child.clone());
            }
            if let Some(found) = self.find_mount_for_recursive(child, dev_id) {
                return Some(found);
            }
        }
        None
    }

    /// Set the root mount
    pub fn set_root(&self, mount: Arc<Mount>) {
        *self.root.write() = Some(mount);
    }

    /// Get the root mount
    pub fn get_root(&self) -> Option<Arc<Mount>> {
        self.root.read().clone()
    }

    /// Get the root dentry
    pub fn get_root_dentry(&self) -> Option<Arc<Dentry>> {
        self.get_root().map(|m| m.root.clone())
    }

    /// Find mount whose root dentry matches the given dentry
    ///
    /// This is used by umount to find the mount at a given path.
    pub fn find_mount_at(&self, dentry: &Arc<Dentry>) -> Option<Arc<Mount>> {
        let root = self.get_root()?;

        // Check if this is the root mount
        if Arc::ptr_eq(&root.root, dentry) {
            return Some(root);
        }

        // Check if dentry matches root mount's root by inode
        if let (Some(root_ino), Some(d_ino)) = (root.root.get_inode(), dentry.get_inode())
            && root_ino.ino == d_ino.ino
            && root.root.superblock().map(|s| s.dev_id) == dentry.superblock().map(|s| s.dev_id)
        {
            return Some(root);
        }

        // Search children recursively
        self.find_mount_recursive(&root, dentry)
    }

    fn find_mount_recursive(&self, mount: &Arc<Mount>, dentry: &Arc<Dentry>) -> Option<Arc<Mount>> {
        for child in mount.children.read().iter() {
            // Check if child's root dentry matches the target
            if Arc::ptr_eq(&child.root, dentry) {
                return Some(child.clone());
            }

            // Also check by inode number + device ID
            if let (Some(child_ino), Some(d_ino)) = (child.root.get_inode(), dentry.get_inode())
                && child_ino.ino == d_ino.ino
                && child.root.superblock().map(|s| s.dev_id)
                    == dentry.superblock().map(|s| s.dev_id)
            {
                return Some(child.clone());
            }

            // Recurse into child's children
            if let Some(found) = self.find_mount_recursive(child, dentry) {
                return Some(found);
            }
        }
        None
    }
}

impl Default for MountNamespace {
    fn default() -> Self {
        Self::new()
    }
}

/// Get the current task's mount namespace
///
/// Uses the namespace from the current task's nsproxy.
/// Falls back to init mount namespace if no task context.
pub fn current_mnt_ns() -> Arc<crate::ns::MntNamespace> {
    crate::ns::current_mnt_ns()
}

/// Get the init mount namespace
///
/// Use for early boot before task context is set up.
pub fn init_mnt_ns() -> Arc<crate::ns::MntNamespace> {
    crate::ns::init_mnt_ns()
}

/// Mount a filesystem at a path
///
/// If path is None or "/", this becomes the root mount.
///
/// Uses the current task's mount namespace, or init namespace if no task context.
pub fn do_mount(
    fs_type: &'static FileSystemType,
    mountpoint: Option<Arc<Dentry>>,
) -> Result<Arc<Mount>, KernelError> {
    // Create the superblock by calling the filesystem's mount function
    let sb = (fs_type.mount)(fs_type)?;

    // Get the root dentry from the superblock
    let root = sb.get_root().ok_or(KernelError::InvalidArgument)?;

    // Create the mount
    let mount = Mount::new(sb, root, 0);

    // Get the current mount namespace (falls back to init for early boot)
    let mnt_ns = current_mnt_ns();

    // If there's a mount point, set up the relationship
    if let Some(mp) = mountpoint {
        mount.set_mountpoint(mp.clone());

        // Find parent mount and add as child
        if let Some(root_mount) = mnt_ns.get_root() {
            // For simplicity, add to root mount's children
            // A real implementation would walk the mount tree
            mount.set_parent(&root_mount);
            root_mount.add_child(mount.clone());
        }
    } else {
        // This is the root mount - set in namespace
        mnt_ns.set_root(mount.clone());
    }

    Ok(mount)
}

/// Mount a filesystem at a path string
pub fn mount_at_path(fs_type: &'static FileSystemType, path: &str) -> Result<Arc<Mount>, KernelError> {
    if path == "/" || path.is_empty() {
        // Root mount
        do_mount(fs_type, None)
    } else {
        // Look up the mount point
        let dentry = super::path::lookup_path(path)?;
        do_mount(fs_type, Some(dentry))
    }
}

/// Mount a device-backed filesystem
///
/// Used for filesystems that require a backing block device (ext4, vfat, etc.).
///
/// Uses the current task's mount namespace.
///
/// # Arguments
/// * `fs_type` - Filesystem type (must have mount_dev function)
/// * `source` - Path to the block device (e.g., "/dev/rd1")
/// * `mountpoint` - Dentry where to mount (None for root)
///
/// # Returns
/// The created mount on success
pub fn do_mount_dev(
    fs_type: &'static FileSystemType,
    source: &str,
    mountpoint: Option<Arc<Dentry>>,
) -> Result<Arc<Mount>, KernelError> {
    // The filesystem must support device mounting
    let mount_dev_fn = fs_type.mount_dev.ok_or(KernelError::OperationNotSupported)?;

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
    let sb = mount_dev_fn(fs_type, bdev)?;

    // Get the root dentry from the superblock
    let root = sb.get_root().ok_or(KernelError::InvalidArgument)?;

    // Create the mount
    let mount = Mount::new(sb, root, 0);

    // Get the current mount namespace
    let mnt_ns = current_mnt_ns();

    // If there's a mount point, set up the relationship
    if let Some(mp) = mountpoint {
        mount.set_mountpoint(mp.clone());

        // Find parent mount and add as child
        if let Some(root_mount) = mnt_ns.get_root() {
            mount.set_parent(&root_mount);
            root_mount.add_child(mount.clone());
        }
    } else {
        // This is the root mount - set in namespace
        mnt_ns.set_root(mount.clone());
    }

    Ok(mount)
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

/// Check if a dentry is a mount point and get the mounted filesystem's root
pub fn follow_mount(dentry: &Arc<Dentry>) -> Arc<Dentry> {
    if !dentry.is_mountpoint() {
        return dentry.clone();
    }

    // Find the mount at this dentry using current namespace
    let mnt_ns = current_mnt_ns();
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

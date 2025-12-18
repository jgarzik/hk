//! Dentry - directory entry cache
//!
//! A dentry represents a name-to-inode mapping in the directory tree.
//! The dentry cache (dcache) speeds up path lookups by caching these mappings.
//!
//! ## Locking Model
//!
//! Following Linux's `d_lock` pattern, each dentry has a single RwLock (`d_lock`)
//! that protects all mutable state. This simplifies lock ordering and matches
//! the proven Linux design.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use spin::{Mutex, RwLock};

use super::inode::Inode;
use super::superblock::SuperBlock;

/// Dentry flags
#[derive(Debug, Clone, Copy, Default)]
pub struct DentryFlags {
    /// This is a mount point
    pub mounted: bool,
    /// Negative dentry (cached failed lookup)
    pub negative: bool,
}

/// Inner mutable state protected by d_lock
///
/// All fields here are protected by the parent Dentry's single RwLock,
/// following Linux's d_lock pattern.
struct DentryInner {
    /// The inode this dentry points to (None for negative dentry)
    inode: Option<Arc<Inode>>,
    /// Parent dentry (None for root)
    parent: Option<Weak<Dentry>>,
    /// Children dentries (for directories)
    children: BTreeMap<String, Arc<Dentry>>,
    /// Dentry flags
    flags: DentryFlags,
}

/// A directory entry - maps a name to an inode
///
/// ## Locking
///
/// Uses a single `d_lock` RwLock protecting all mutable state, following
/// the Linux kernel's dentry locking model. The `name` and `sb` fields
/// are immutable after creation and don't need locking.
///
/// Additionally, `rename_lock` is used by lock_rename()/unlock_rename()
/// to coordinate directory locking during rename operations, following
/// Linux's lock_rename() pattern in fs/namei.c.
pub struct Dentry {
    /// Name of this entry (empty string for root) - immutable after creation
    pub name: String,

    /// Back pointer to superblock - immutable after creation
    pub sb: Weak<SuperBlock>,

    /// Single lock protecting all mutable state (like Linux d_lock)
    d_lock: RwLock<DentryInner>,

    /// Lock for rename coordination (used by lock_rename/unlock_rename)
    /// This is separate from d_lock to allow holding across function calls
    rename_lock: Mutex<()>,
}

impl Dentry {
    /// Create a new dentry
    pub fn new(name: String, inode: Option<Arc<Inode>>, sb: Weak<SuperBlock>) -> Self {
        Self {
            name,
            sb,
            d_lock: RwLock::new(DentryInner {
                inode,
                parent: None,
                children: BTreeMap::new(),
                flags: DentryFlags::default(),
            }),
            rename_lock: Mutex::new(()),
        }
    }

    /// Create root dentry for a filesystem
    pub fn new_root(inode: Arc<Inode>, sb: Weak<SuperBlock>) -> Self {
        Self {
            name: String::new(),
            sb,
            d_lock: RwLock::new(DentryInner {
                inode: Some(inode),
                parent: None,
                children: BTreeMap::new(),
                flags: DentryFlags::default(),
            }),
            rename_lock: Mutex::new(()),
        }
    }

    /// Create an anonymous dentry (for pipes, sockets, etc.)
    ///
    /// Anonymous dentries have no superblock and are not part of any filesystem.
    /// They exist solely to provide a File's required dentry reference.
    pub fn new_anonymous(name: String, inode: Option<Arc<Inode>>) -> Self {
        Self {
            name,
            sb: Weak::new(), // No superblock for anonymous dentries
            d_lock: RwLock::new(DentryInner {
                inode,
                parent: None,
                children: BTreeMap::new(),
                flags: DentryFlags::default(),
            }),
            rename_lock: Mutex::new(()),
        }
    }

    /// Get the inode this dentry points to
    pub fn get_inode(&self) -> Option<Arc<Inode>> {
        self.d_lock.read().inode.clone()
    }

    /// Set the inode for this dentry
    pub fn set_inode(&self, inode: Arc<Inode>) {
        self.d_lock.write().inode = Some(inode);
    }

    /// Check if this is a negative (failed lookup) dentry
    pub fn is_negative(&self) -> bool {
        self.d_lock.read().inode.is_none()
    }

    /// Get parent dentry
    pub fn get_parent(&self) -> Option<Arc<Dentry>> {
        self.d_lock
            .read()
            .parent
            .as_ref()
            .and_then(|w: &Weak<Dentry>| w.upgrade())
    }

    /// Set parent dentry
    pub fn set_parent(&self, parent: &Arc<Dentry>) {
        self.d_lock.write().parent = Some(Arc::downgrade(parent));
    }

    /// Look up a child dentry by name
    pub fn lookup_child(&self, name: &str) -> Option<Arc<Dentry>> {
        self.d_lock.read().children.get(name).cloned()
    }

    /// Add a child dentry
    pub fn add_child(&self, child: Arc<Dentry>) {
        let name = child.name.clone();
        self.d_lock.write().children.insert(name, child);
    }

    /// Remove a child dentry by name
    pub fn remove_child(&self, name: &str) -> Option<Arc<Dentry>> {
        self.d_lock.write().children.remove(name)
    }

    /// Check if this dentry is a mount point
    pub fn is_mountpoint(&self) -> bool {
        self.d_lock.read().flags.mounted
    }

    /// Mark this dentry as a mount point
    pub fn set_mountpoint(&self, mounted: bool) {
        self.d_lock.write().flags.mounted = mounted;
    }

    /// Get the superblock this dentry belongs to
    pub fn superblock(&self) -> Option<Arc<SuperBlock>> {
        self.sb.upgrade()
    }

    // ========================================================================
    // Rename locking (Linux lock_rename pattern)
    // ========================================================================

    /// Acquire rename lock on this dentry
    ///
    /// Used by lock_rename() to coordinate directory locking during rename.
    /// This lock is held across the entire rename operation.
    ///
    /// # Safety
    /// Caller must ensure rename_unlock() is called to release the lock.
    /// Using lock_rename()/unlock_rename() helpers is preferred.
    pub fn rename_lock(&self) {
        // Acquire the mutex - this will spin until acquired
        // We use forget() to prevent the guard from being dropped,
        // allowing us to hold the lock across function calls
        let guard = self.rename_lock.lock();
        core::mem::forget(guard);
    }

    /// Release rename lock on this dentry
    ///
    /// # Safety
    /// Must only be called after a successful rename_lock() call.
    /// The lock must have been acquired by this thread.
    pub unsafe fn rename_unlock(&self) {
        // Force unlock the mutex
        // Safety: caller guarantees we hold the lock
        unsafe { self.rename_lock.force_unlock() };
    }

    /// Get the full path from root to this dentry
    pub fn full_path(&self) -> String {
        let mut components = Vec::new();
        let mut current = Some(self as *const Dentry);

        // Walk up to root
        while let Some(ptr) = current {
            // Safety: we're just reading the name, not storing the pointer
            let dentry = unsafe { &*ptr };
            if !dentry.name.is_empty() {
                components.push(dentry.name.clone());
            }
            current = dentry.get_parent().map(|p| Arc::as_ptr(&p));
        }

        // Build path from root to leaf
        components.reverse();
        if components.is_empty() {
            String::from("/")
        } else {
            let mut path = String::new();
            for comp in components {
                path.push('/');
                path.push_str(&comp);
            }
            path
        }
    }

    /// Iterate over children (for readdir)
    pub fn for_each_child<F>(&self, mut f: F)
    where
        F: FnMut(&str, &Arc<Dentry>),
    {
        let inner = self.d_lock.read();
        for (name, dentry) in inner.children.iter() {
            f(name, dentry);
        }
    }

    /// Get number of children
    pub fn num_children(&self) -> usize {
        self.d_lock.read().children.len()
    }
}

// Dentry is Send + Sync because all interior mutability is through a single lock
unsafe impl Send for Dentry {}
unsafe impl Sync for Dentry {}

/// Global dentry cache
/// For now, this is simple - dentries are cached implicitly via Arc references.
/// A more sophisticated implementation would use an LRU cache with hash table.
pub struct DentryCache {
    /// Root dentry of the namespace
    root: RwLock<Option<Arc<Dentry>>>,
}

impl DentryCache {
    /// Create a new empty dentry cache
    pub const fn new() -> Self {
        Self {
            root: RwLock::new(None),
        }
    }

    /// Set the root dentry
    pub fn set_root(&self, root: Arc<Dentry>) {
        *self.root.write() = Some(root);
    }

    /// Get the root dentry
    pub fn get_root(&self) -> Option<Arc<Dentry>> {
        self.root.read().clone()
    }
}

impl Default for DentryCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Global dentry cache instance
pub static DCACHE: DentryCache = DentryCache::new();

// ============================================================================
// Rename locking helpers (Linux lock_rename pattern)
// ============================================================================

/// Check if `ancestor` is an ancestor of `child` in the directory tree
///
/// Returns true if:
/// - ancestor and child are the same dentry, OR
/// - ancestor is a parent (or grandparent, etc.) of child
///
/// This is used by lock_rename() to determine lock ordering and by
/// sys_renameat2() to prevent creating directory cycles.
///
/// Following Linux's is_subdir() in fs/dcache.c
pub fn is_subdir(child: &Arc<Dentry>, ancestor: &Arc<Dentry>) -> bool {
    // Same dentry - trivially true
    if Arc::ptr_eq(child, ancestor) {
        return true;
    }

    // Walk up the parent chain from child
    let mut current = child.get_parent();
    while let Some(parent) = current {
        if Arc::ptr_eq(&parent, ancestor) {
            return true;
        }
        current = parent.get_parent();
    }

    false
}

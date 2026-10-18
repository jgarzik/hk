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

use crate::sync::spin::RwLock;

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
pub struct Dentry {
    /// Name of this entry (empty string for root) - immutable after creation
    pub name: String,

    /// Back pointer to superblock - immutable after creation
    pub sb: Weak<SuperBlock>,

    /// Single lock protecting all mutable state (like Linux d_lock)
    d_lock: RwLock<DentryInner>,
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

    /// lock_rename() step: lock this directory's inode (i_rwsem), the
    /// same lock every other directory operation takes (Linux
    /// lock_rename uses inode_lock_nested)
    pub fn rename_lock(&self) {
        if let Some(inode) = self.get_inode() {
            inode.inode_lock();
        }
    }

    /// Release rename_lock()
    ///
    /// # Safety
    /// Must only be called after rename_lock() on this dentry by this thread.
    pub unsafe fn rename_unlock(&self) {
        if let Some(inode) = self.get_inode() {
            unsafe { inode.inode_unlock() };
        }
    }

    /// Get the full path from root to this dentry
    ///
    /// Each parent is held by its Arc while its name is read.
    pub fn full_path(&self) -> String {
        let mut components = Vec::new();
        if !self.name.is_empty() {
            components.push(self.name.clone());
        }
        let mut cur = self.get_parent();
        while let Some(d) = cur {
            if !d.name.is_empty() {
                components.push(d.name.clone());
            }
            cur = d.get_parent();
        }
        if components.is_empty() {
            return String::from("/");
        }
        let mut path = String::new();
        for comp in components.iter().rev() {
            path.push('/');
            path.push_str(comp);
        }
        path
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

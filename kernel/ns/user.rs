//! User namespace implementation
//!
//! User namespaces provide isolation of security-related identifiers and
//! attributes, including UID/GID mappings. Each user namespace has its own
//! set of UIDs and GIDs that map to a (potentially different) set of IDs
//! in the parent namespace.
//!
//! ## Key Concepts
//!
//! - **UID/GID mapping**: Maps IDs from this namespace to parent namespace IDs
//! - **Capability set**: A process has all capabilities within its user namespace
//! - **Owner**: The user who created the namespace (in the parent namespace)
//!
//! ## Linux Compatibility
//!
//! We follow Linux's user namespace semantics:
//! - A new user namespace starts with an unmapped state
//! - UID/GID maps are set via `/proc/<pid>/uid_map` and `/proc/<pid>/gid_map`
//! - Mappings can only be set once
//! - A process is root (UID 0) in its own user namespace
//!
//! ## Locking
//!
//! - `UserNamespace.uid_map.extents`: RwLock
//! - `UserNamespace.gid_map.extents`: RwLock

use crate::sync::spin::RwLock;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Lazy;

use crate::task::percpu;

/// Maximum user namespace nesting level (same as Linux)
pub const MAX_USER_NS_LEVEL: u32 = 32;

/// UID/GID mapping extent
///
/// Maps a range of IDs from this namespace to the parent namespace.
#[derive(Debug, Clone, Copy)]
pub struct UidGidExtent {
    /// First ID in this namespace
    pub first: u32,
    /// First ID in the parent namespace
    pub lower_first: u32,
    /// Number of consecutive IDs in the range
    pub count: u32,
}

/// UID/GID map
///
/// Contains a set of extents that define the mapping between
/// IDs in this namespace and IDs in the parent namespace.
pub struct UidGidMap {
    /// Mapping extents (Linux allows up to 340)
    extents: RwLock<Vec<UidGidExtent>>,
}

impl UidGidMap {
    /// Create a new empty UID/GID map
    pub fn new() -> Self {
        Self {
            extents: RwLock::new(Vec::new()),
        }
    }

    /// Create an identity map (for init namespace)
    ///
    /// Maps all IDs to themselves (0→0, 1→1, etc.)
    pub fn new_identity() -> Self {
        let map = Self::new();
        // Set identity mapping covering all possible IDs
        let _ = map.set_mapping(alloc::vec![UidGidExtent {
            first: 0,
            lower_first: 0,
            count: u32::MAX,
        }]);
        map
    }

    /// Map an ID from this namespace to the parent namespace
    ///
    /// Returns None if the ID is not mapped.
    pub fn map_id_down(&self, id: u32) -> Option<u32> {
        let extents = self.extents.read();
        for ext in extents.iter() {
            if id >= ext.first && id < ext.first.saturating_add(ext.count) {
                return Some(ext.lower_first.saturating_add(id - ext.first));
            }
        }
        None
    }

    /// Map an ID from the parent namespace to this namespace
    ///
    /// Returns None if the ID is not mapped.
    pub fn map_id_up(&self, id: u32) -> Option<u32> {
        let extents = self.extents.read();
        for ext in extents.iter() {
            if id >= ext.lower_first && id < ext.lower_first.saturating_add(ext.count) {
                return Some(ext.first.saturating_add(id - ext.lower_first));
            }
        }
        None
    }

    /// Set the mapping (can only be done once)
    ///
    /// # Arguments
    /// * `new_extents` - Vector of mapping extents
    ///
    /// # Returns
    /// * `Ok(())` - Mapping set successfully
    /// * `Err(errno)` - If mapping already set or invalid
    pub fn set_mapping(&self, new_extents: Vec<UidGidExtent>) -> Result<(), i32> {
        let mut extents = self.extents.write();
        if !extents.is_empty() {
            return Err(1); // EPERM - already set
        }
        *extents = new_extents;
        Ok(())
    }

    /// Check if the map has any extents defined
    pub fn is_set(&self) -> bool {
        !self.extents.read().is_empty()
    }
}

impl Default for UidGidMap {
    fn default() -> Self {
        Self::new()
    }
}

/// User namespace
///
/// Provides isolation of user and group IDs.
pub struct UserNamespace {
    /// UID mapping
    pub uid_map: UidGidMap,

    /// GID mapping
    pub gid_map: UidGidMap,

    /// Nesting level (0 = init_user_ns, increases with each child)
    pub level: u32,

    /// Parent namespace (None for init_user_ns)
    pub parent: Option<Arc<UserNamespace>>,

    /// Creator's UID in the parent namespace
    pub owner: u32,

    /// Creator's GID in the parent namespace
    pub group: u32,
}

impl UserNamespace {
    /// Create the initial (root) user namespace
    fn new_init() -> Arc<Self> {
        Arc::new(Self {
            uid_map: UidGidMap::new_identity(),
            gid_map: UidGidMap::new_identity(),
            level: 0,
            parent: None,
            owner: 0,
            group: 0,
        })
    }

    /// Clone this namespace (create a child namespace)
    ///
    /// Called when a process unshares or clones with CLONE_NEWUSER.
    /// The child namespace starts with no UID/GID mappings.
    ///
    /// # Arguments
    /// * `parent` - The parent namespace (self as Arc)
    ///
    /// # Returns
    /// * `Ok(Arc<UserNamespace>)` - New child namespace
    /// * `Err(errno)` - If max nesting level exceeded
    pub fn clone_ns(parent: &Arc<UserNamespace>) -> Result<Arc<Self>, i32> {
        // Check nesting level
        if parent.level >= MAX_USER_NS_LEVEL {
            return Err(11); // EAGAIN - max nesting exceeded
        }

        // Get creator's credentials
        let cred = percpu::current_cred();

        Ok(Arc::new(Self {
            uid_map: UidGidMap::new(),
            gid_map: UidGidMap::new(),
            level: parent.level + 1,
            parent: Some(parent.clone()),
            owner: cred.uid,
            group: cred.gid,
        }))
    }

    /// Check if this namespace is an ancestor of another
    pub fn is_ancestor_of(&self, other: &UserNamespace) -> bool {
        let self_ptr = self as *const UserNamespace;
        let mut current = other.parent.as_ref();

        while let Some(ns) = current {
            if Arc::as_ptr(ns) == self_ptr {
                return true;
            }
            current = ns.parent.as_ref();
        }

        false
    }

    /// Get the effective UID in the init namespace
    ///
    /// Maps the given UID through all ancestor namespaces to get
    /// the kernel-visible UID.
    pub fn from_kuid(&self, kuid: u32) -> Option<u32> {
        self.uid_map.map_id_up(kuid)
    }

    /// Get the kernel UID from a namespace UID
    ///
    /// Maps a UID from this namespace through to the init namespace.
    pub fn to_kuid(&self, uid: u32) -> Option<u32> {
        self.uid_map.map_id_down(uid)
    }

    /// Get the effective GID in the init namespace
    pub fn from_kgid(&self, kgid: u32) -> Option<u32> {
        self.gid_map.map_id_up(kgid)
    }

    /// Get the kernel GID from a namespace GID
    pub fn to_kgid(&self, gid: u32) -> Option<u32> {
        self.gid_map.map_id_down(gid)
    }
}

/// Initial (root) user namespace
///
/// All processes belong to this namespace unless they create child namespaces.
/// This namespace has an identity UID/GID mapping.
pub static INIT_USER_NS: Lazy<Arc<UserNamespace>> = Lazy::new(UserNamespace::new_init);

/// Check if a user can set UID/GID maps for a target process
///
/// Per Linux semantics:
/// - Must have CAP_SETUID/CAP_SETGID in the target's user namespace
/// - Or be the target process itself (and have appropriate permissions)
pub fn can_set_uid_gid_map(_target_ns: &UserNamespace) -> bool {
    // For now, only allow root (euid 0) to set mappings
    let cred = percpu::current_cred();
    cred.euid == 0
}

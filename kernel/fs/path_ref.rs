//! Refcounted path structure (mount + dentry pair)
//!
//! Mirrors Linux's struct path. Both mount and dentry are refcounted,
//! and Path owns references to both. This is the fundamental type for
//! representing filesystem locations in the kernel.
//!
//! Reference counting is handled automatically via Arc:
//! - `path.clone()` is equivalent to Linux's `path_get()`
//! - `drop(path)` is equivalent to Linux's `path_put()`

use alloc::sync::Arc;

use super::dentry::Dentry;
use super::mount::Mount;

/// A filesystem path - pair of (mount, dentry)
///
/// This struct owns references to both the mount and dentry.
/// When cloned, reference counts are incremented.
/// When dropped, reference counts are decremented.
///
/// This mirrors Linux's `struct path`:
/// ```c
/// struct path {
///     struct vfsmount *mnt;
///     struct dentry *dentry;
/// };
/// ```
#[derive(Clone)]
pub struct Path {
    /// The mount point this path is on
    pub mnt: Arc<Mount>,
    /// The dentry within that mount
    pub dentry: Arc<Dentry>,
}

impl Path {
    /// Create a new Path, taking ownership of the provided Arc references
    pub fn new(mnt: Arc<Mount>, dentry: Arc<Dentry>) -> Self {
        Self { mnt, dentry }
    }

    /// Create a Path from a dentry, using the root mount
    ///
    /// Falls back to root mount since we don't track per-dentry mounts yet.
    pub fn from_dentry(dentry: Arc<Dentry>) -> Option<Self> {
        let mnt = super::mount::current_mnt_ns().get_root()?;
        Some(Self { mnt, dentry })
    }

    /// Check if this path points to a directory
    pub fn is_dir(&self) -> bool {
        self.dentry
            .get_inode()
            .map(|i| i.mode().is_dir())
            .unwrap_or(false)
    }

    /// Get the dentry
    pub fn dentry(&self) -> &Arc<Dentry> {
        &self.dentry
    }

    /// Get the mount
    pub fn mnt(&self) -> &Arc<Mount> {
        &self.mnt
    }

    /// Get the inode (if any)
    pub fn get_inode(&self) -> Option<Arc<super::inode::Inode>> {
        self.dentry.get_inode()
    }
}

// Note: Arc already handles refcounting via Clone/Drop
// path_get() equivalent = path.clone()
// path_put() equivalent = drop(path)

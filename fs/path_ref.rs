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

use super::dentry::DentryRef;
use super::mount::MountRef;

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
    pub mnt: MountRef,
    /// The dentry within that mount
    pub dentry: DentryRef,
}

impl Path {
    /// Create a new Path, taking ownership of the provided Arc references
    pub fn new(mnt: MountRef, dentry: DentryRef) -> Self {
        Self { mnt, dentry }
    }

    /// A dentry of the mount "/" lands on (the rootfs) as a Path
    /// (boot-time objects, internal files)
    pub fn from_dentry(dentry: DentryRef) -> Option<Self> {
        let mnt = crate::ns::current_mnt_ns().root_path()?.mnt.clone();
        Some(Self { mnt, dentry })
    }

    /// The same mount and dentry (Linux path_equal)
    pub fn same(&self, o: &Path) -> bool {
        MountRef::ptr_eq(&self.mnt, &o.mnt) && DentryRef::ptr_eq(&self.dentry, &o.dentry)
    }

    /// Check if this path points to a directory
    pub fn is_dir(&self) -> bool {
        self.dentry
            .get_inode()
            .map(|i| i.mode().is_dir())
            .unwrap_or(false)
    }

    /// Get the dentry
    pub fn dentry(&self) -> &DentryRef {
        &self.dentry
    }

    /// Get the mount
    pub fn mnt(&self) -> &MountRef {
        &self.mnt
    }

    /// The mount and dentry (path_get of both, then path_put of this)
    pub fn into_parts(self) -> (MountRef, DentryRef) {
        (self.mnt.clone(), self.dentry.clone())
    }

    /// The mount, dropping the rest without counting as a use of it: an
    /// MNT_EXPIRE mark stays (Linux mntput_no_expire, for umount's own
    /// lookup)
    pub fn into_mnt_noexpire(self) -> MountRef {
        let p = core::mem::ManuallyDrop::new(self);
        // SAFETY: `p` is never dropped or used again, so each field is
        // read out exactly once and its reference moves to the copy
        let (mnt, dentry) = unsafe {
            (
                core::ptr::read(&raw const p.mnt),
                core::ptr::read(&raw const p.dentry),
            )
        };
        drop(dentry);
        mnt
    }

    /// Get the inode (if any)
    pub fn get_inode(&self) -> Option<Arc<super::inode::Inode>> {
        self.dentry.get_inode()
    }
}

// Note: Arc already handles refcounting via Clone/Drop
// path_get() equivalent = path.clone()
// path_put() equivalent = drop(path)

/// path_put: a use of the mount clears its MNT_EXPIRE mark (Linux mntput)
impl Drop for Path {
    fn drop(&mut self) {
        self.mnt.clear_expiry();
    }
}

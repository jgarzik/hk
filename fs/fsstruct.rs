//! Per-task filesystem context (fs_struct equivalent)
//!
//! Holds the current working directory (pwd), root directory,
//! and umask for a task. Can be shared between threads (CLONE_FS).
//!
//! This mirrors Linux's `struct fs_struct`:
//! ```c
//! struct fs_struct {
//!     int users;           // refcount
//!     spinlock_t lock;
//!     seqcount_t seq;
//!     int umask;
//!     int in_exec;
//!     struct path root;    // process root (for chroot)
//!     struct path pwd;     // current working directory
//! };
//! ```
//!
//! In our Rust implementation, Arc provides the reference counting,
//! and Mutex provides the locking.

use alloc::sync::Arc;

use crate::sync::spin::Mutex;

use super::path_ref::Path;
use crate::task::Tid;

/// Per-task filesystem context
///
/// This is reference-counted via Arc. Multiple tasks can share
/// the same FsStruct when CLONE_FS is used.
pub struct FsStruct {
    /// Lock protecting pwd, root, umask modifications
    inner: Mutex<FsStructInner>,
    /// Tasks using it (Linux fs->users): setns into a mount namespace
    /// needs it unshared
    pub users: core::sync::atomic::AtomicUsize,
}

/// A path the fs struct holds: its mount is busy while it does (Linux
/// path_get: an umount of a mount someone stands in is EBUSY)
struct Pinned(Path);

impl Pinned {
    fn new(p: Path) -> Self {
        p.mnt.mntget();
        Self(p)
    }
}

impl Drop for Pinned {
    fn drop(&mut self) {
        self.0.mnt.mntput();
    }
}

struct FsStructInner {
    /// Current working directory
    pwd: Pinned,
    /// Root directory (for chroot support, usually same as global root)
    root: Pinned,
    /// File creation mask
    umask: u16,
}

impl FsStruct {
    /// Create a new FsStruct with the given root and pwd
    pub fn new(root: Path, pwd: Path) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(FsStructInner {
                pwd: Pinned::new(pwd),
                root: Pinned::new(root),
                umask: 0o022,
            }),
            users: core::sync::atomic::AtomicUsize::new(1),
        })
    }

    /// Create a new FsStruct at where "/" lands in the namespace: the
    /// rootfs (Linux init_mount_tree: root and pwd on the mutable
    /// rootfs, not the nullfs under it)
    pub fn new_root() -> Option<Arc<Self>> {
        let root = crate::ns::current_mnt_ns().root_path()?;
        Some(Self::new(root.clone(), root))
    }

    /// Get current working directory (returns cloned Path with bumped refs)
    pub fn get_pwd(&self) -> Path {
        self.inner.lock().pwd.0.clone()
    }

    /// Get root directory (returns cloned Path with bumped refs)
    pub fn get_root(&self) -> Path {
        self.inner.lock().root.0.clone()
    }

    /// Get umask
    pub fn get_umask(&self) -> u16 {
        self.inner.lock().umask
    }

    /// Set current working directory
    ///
    /// Takes a new Path reference. The old pwd is dropped after
    /// releasing the lock (two-phase ref management).
    pub fn set_pwd(&self, new_pwd: Path) {
        let old = {
            let mut inner = self.inner.lock();
            core::mem::replace(&mut inner.pwd, Pinned::new(new_pwd))
        };
        // old Path dropped here, decrementing refcounts
        drop(old);
    }

    /// Set root directory
    pub fn set_root(&self, new_root: Path) {
        let old = {
            let mut inner = self.inner.lock();
            core::mem::replace(&mut inner.root, Pinned::new(new_root))
        };
        drop(old);
    }

    /// After a mount namespace copy: root and pwd move to the copies of
    /// their mounts (Linux copy_mnt_ns, for the new task's fs)
    pub fn repoint(&self, map: &crate::fs::mount::MountMap) {
        let swap = |p: &Path| {
            map.iter()
                .find(|(old, _)| Arc::ptr_eq(old, &p.mnt))
                .map(|(_, new)| Path::new(new.clone(), p.dentry.clone()))
        };
        let old = {
            let mut inner = self.inner.lock();
            let (root, pwd) = (swap(&inner.root.0), swap(&inner.pwd.0));
            (
                root.map(|r| core::mem::replace(&mut inner.root, Pinned::new(r))),
                pwd.map(|p| core::mem::replace(&mut inner.pwd, Pinned::new(p))),
            )
        };
        drop(old);
    }

    /// Set umask, returns old umask
    pub fn set_umask(&self, new_umask: u16) -> u16 {
        let mut inner = self.inner.lock();
        let old = inner.umask;
        inner.umask = new_umask;
        old
    }

    /// Copy this FsStruct (for fork without CLONE_FS)
    ///
    /// Creates a new FsStruct with the same pwd/root/umask,
    /// but independent (changes don't affect original).
    /// The underlying mount/dentry objects are still shared via Arc.
    pub fn copy(&self) -> Arc<Self> {
        let inner = self.inner.lock();
        Arc::new(Self {
            inner: Mutex::new(FsStructInner {
                pwd: Pinned::new(inner.pwd.0.clone()),
                root: Pinned::new(inner.root.0.clone()),
                umask: inner.umask,
            }),
            users: core::sync::atomic::AtomicUsize::new(1),
        })
    }
}

// =============================================================================
// Global task -> FsStruct mapping
// =============================================================================

// =============================================================================
// Task FS accessors - Task.fs under its alloc_lock (Linux task_lock)
// =============================================================================

use crate::task::percpu::{current, with_task_lock};

/// Initialize filesystem context for a new task (the task itself, or
/// its creator before it runs); the old one is dropped after the lock
pub fn init_task_fs(tid: Tid, fs: Arc<FsStruct>) {
    let old = with_task_lock(tid, |a| a.set_fs(Some(fs))).flatten();
    if let Some(o) = &old {
        o.users.fetch_sub(1, core::sync::atomic::Ordering::SeqCst);
    }
    drop(old);
}

/// Get the FsStruct for a task (returns cloned Arc; lock-free for the
/// current task, Linux current->fs)
pub fn get_task_fs(tid: Tid) -> Option<Arc<FsStruct>> {
    let me = current();
    if me.tid() == tid {
        return me.fs();
    }
    with_task_lock(tid, |a| a.fs().cloned()).flatten()
}

/// Remove filesystem context when task exits
///
/// This decrements the Arc refcount. If this was the last reference
/// (no other tasks sharing this FsStruct), the FsStruct is dropped,
/// which in turn drops the Path references to pwd and root (after
/// the task's alloc_lock is released: nothing is released under it).
pub fn exit_task_fs(tid: Tid) {
    let fs = with_task_lock(tid, |a| a.set_fs(None)).flatten();
    if let Some(o) = &fs {
        o.users.fetch_sub(1, core::sync::atomic::Ordering::SeqCst);
    }
    drop(fs);
}

/// Clone filesystem context for fork/clone
///
/// If `share` is true (CLONE_FS), the child shares the parent's FsStruct.
/// If `share` is false (normal fork), the child gets a copy.
pub fn clone_task_fs(parent_tid: Tid, child_tid: Tid, share: bool) {
    let child_fs = if share {
        // CLONE_FS: share the same Arc<FsStruct>
        get_task_fs(parent_tid).inspect(|fs| {
            fs.users.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        })
    } else {
        // Normal fork: copy the FsStruct
        get_task_fs(parent_tid).map(|fs| fs.copy())
    };

    if let Some(fs) = child_fs {
        init_task_fs(child_tid, fs);
    } else {
        // Fallback: create new FsStruct at root
        if let Some(fs) = FsStruct::new_root() {
            init_task_fs(child_tid, fs);
        }
    }
}

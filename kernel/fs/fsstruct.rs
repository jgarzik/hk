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

use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use spin::Mutex;

use super::path_ref::Path;
use crate::task::Tid;

/// Per-task filesystem context
///
/// This is reference-counted via Arc. Multiple tasks can share
/// the same FsStruct when CLONE_FS is used.
pub struct FsStruct {
    /// Lock protecting pwd, root, umask modifications
    inner: Mutex<FsStructInner>,
}

struct FsStructInner {
    /// Current working directory
    pwd: Path,
    /// Root directory (for chroot support, usually same as global root)
    root: Path,
    /// File creation mask
    umask: u16,
}

impl FsStruct {
    /// Create a new FsStruct with the given root and pwd
    pub fn new(root: Path, pwd: Path) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(FsStructInner {
                pwd,
                root,
                umask: 0o022,
            }),
        })
    }

    /// Create a new FsStruct initialized to the filesystem root
    pub fn new_root() -> Option<Arc<Self>> {
        let mnt_ns = super::mount::current_mnt_ns();
        let root_dentry = mnt_ns.get_root_dentry()?;
        let root_mnt = mnt_ns.get_root()?;
        let root_path = Path::new(root_mnt.clone(), root_dentry.clone());
        let pwd_path = Path::new(root_mnt, root_dentry);
        Some(Self::new(root_path, pwd_path))
    }

    /// Get current working directory (returns cloned Path with bumped refs)
    pub fn get_pwd(&self) -> Path {
        self.inner.lock().pwd.clone()
    }

    /// Get root directory (returns cloned Path with bumped refs)
    pub fn get_root(&self) -> Path {
        self.inner.lock().root.clone()
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
            core::mem::replace(&mut inner.pwd, new_pwd)
        };
        // old Path dropped here, decrementing refcounts
        drop(old);
    }

    /// Set root directory
    pub fn set_root(&self, new_root: Path) {
        let old = {
            let mut inner = self.inner.lock();
            core::mem::replace(&mut inner.root, new_root)
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
                pwd: inner.pwd.clone(),   // bumps refcounts on mount/dentry
                root: inner.root.clone(), // bumps refcounts on mount/dentry
                umask: inner.umask,
            }),
        })
    }
}

// =============================================================================
// Global task -> FsStruct mapping
// =============================================================================

/// Global table mapping TID -> FsStruct
///
/// This is used to track the filesystem context for each task.
/// Multiple tasks can share the same Arc<FsStruct> when CLONE_FS is used.
static TASK_FS: Mutex<BTreeMap<Tid, Arc<FsStruct>>> = Mutex::new(BTreeMap::new());

/// Initialize filesystem context for a new task
pub fn init_task_fs(tid: Tid, fs: Arc<FsStruct>) {
    TASK_FS.lock().insert(tid, fs);
}

/// Get the FsStruct for a task (returns cloned Arc)
pub fn get_task_fs(tid: Tid) -> Option<Arc<FsStruct>> {
    TASK_FS.lock().get(&tid).cloned()
}

/// Remove filesystem context when task exits
///
/// This decrements the Arc refcount. If this was the last reference
/// (no other tasks sharing this FsStruct), the FsStruct is dropped,
/// which in turn drops the Path references to pwd and root.
pub fn exit_task_fs(tid: Tid) {
    TASK_FS.lock().remove(&tid);
}

/// Clone filesystem context for fork/clone
///
/// If `share` is true (CLONE_FS), the child shares the parent's FsStruct.
/// If `share` is false (normal fork), the child gets a copy.
pub fn clone_task_fs(parent_tid: Tid, child_tid: Tid, share: bool) {
    let child_fs = if share {
        // CLONE_FS: share the same Arc<FsStruct>
        get_task_fs(parent_tid)
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

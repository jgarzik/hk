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
use crate::util::error::KernelError;
use crate::util::kalloc::{arc_nofail, try_arc};

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
        arc_nofail(Self {
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
    pub fn copy(&self) -> Result<Arc<Self>, KernelError> {
        let inner = self.inner.lock();
        try_arc(Self {
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

/// The fs_struct every kernel thread shares (Linux init_task.fs, 7.3+):
/// root and cwd on the private nullfs instance `knullfs`, in no mount
/// namespace and read-only, so a kernel thread resolves no user path
/// and nothing is mounted or written through it. Not installed in the
/// threads (one may already run, and only a task itself replaces its
/// fs): [`get_task_fs`] gives it to a kernel thread that has none.
/// Boot code before pid 1 has an fs resolves from the namespace
/// instead (namei::nd_root).
static KTHREAD_FS: spin::Once<Arc<FsStruct>> = spin::Once::new();

/// Set up [`KTHREAD_FS`] on `knullfs` (Linux init_mount_tree)
pub fn kthread_fs_init(knullfs: Arc<super::Mount>) {
    let root = Path::new(knullfs.clone(), knullfs.root.clone());
    KTHREAD_FS.call_once(|| FsStruct::new(root.clone(), root));
}

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
/// current task, Linux current->fs); a kernel thread's is
/// [`KTHREAD_FS`]
pub fn get_task_fs(tid: Tid) -> Option<Arc<FsStruct>> {
    let me = current();
    let fs = if me.tid() == tid {
        me.fs()
    } else {
        with_task_lock(tid, |a| a.fs().cloned()).flatten()
    };
    fs.or_else(|| {
        crate::task::kthread::is_kthread_tid(tid)
            .then(|| KTHREAD_FS.get().cloned())
            .flatten()
    })
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

/// The fs context a child of `parent_tid` gets (Linux copy_fs): the
/// parent's own with CLONE_FS, else a copy (a parent without one: a new
/// one at the root). Nothing is counted yet, so a fork that fails
/// afterwards just drops it. ENOMEM if the copy cannot be made.
pub fn fork_fs(parent_tid: Tid, share: bool) -> Result<Option<Arc<FsStruct>>, KernelError> {
    Ok(match get_task_fs(parent_tid) {
        Some(fs) if share => Some(fs),
        Some(fs) => Some(fs.copy()?),
        None => FsStruct::new_root(),
    })
}

/// Give the child its fork-time fs context, counting one more sharer
/// for CLONE_FS (Linux fs->users++)
pub fn install_fork_fs(child_tid: Tid, fs: Arc<FsStruct>, shared: bool) {
    if shared {
        fs.users.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    }
    init_task_fs(child_tid, fs);
}

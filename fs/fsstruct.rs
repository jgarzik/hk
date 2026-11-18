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
//! The paths and umask are under `seq`, a spin lock with a sequence
//! (Linux fs->seq, a seqlock_t): writers take its write side, which
//! moves the sequence (set_fs_root, set_fs_pwd, chroot_fs_refs, a
//! namespace copy's repoint); a reader taking references takes its
//! locking read (get_fs_root, get_fs_pwd, copy_fs_struct). An RCU path
//! walk reads root and pwd with no lock and no reference under the
//! sequence (Linux set_root, path_init: `root_rcu`, `pwd_rcu`): their
//! addresses are kept in atomics beside the owned paths, stored in the
//! same write section; a dentry or mount is freed only a grace period
//! after its last reference goes, so one read under an RCU read guard
//! stays allocated while the guard is held, and the walk takes its
//! references later (legitimize_root) only if the dentry's and the
//! mount tree's sequences say nothing moved.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::sync::SeqLock;
use crate::sync::rcu::RcuReadGuard;

use super::dentry::{Dentry, DentryRef};
use super::mount::{Mount, MountRef};
use super::path_ref::Path;
use crate::util::error::KernelError;
use crate::util::kalloc::{arc_nofail, try_arc};

/// Per-task filesystem context
///
/// This is reference-counted via Arc. Multiple tasks can share
/// the same FsStruct when CLONE_FS is used.
pub struct FsStruct {
    /// Root, cwd and umask (Linux fs->seq: lock and sequence)
    seq: SeqLock<FsStructInner>,
    /// `root`'s mount and dentry, for RCU walks (no reference: the
    /// locked path holds them); stored under `seq`'s write side
    root_rcu: PathPtrs,
    /// `pwd`'s, likewise
    pwd_rcu: PathPtrs,
    /// Tasks using it (Linux fs->users): setns into a mount namespace
    /// needs it unshared
    pub users: core::sync::atomic::AtomicUsize,
}

struct FsStructInner {
    /// Current working directory
    pwd: Path,
    /// Root directory (for chroot support, usually same as global root)
    root: Path,
    /// File creation mask
    umask: u16,
}

/// A path's mount and dentry addresses, read by RCU walks under the
/// fs_struct's sequence (Linux reads fs->root and fs->pwd themselves)
struct PathPtrs {
    mnt: AtomicPtr<Mount>,
    dentry: AtomicPtr<Dentry>,
}

impl PathPtrs {
    fn new(p: &Path) -> Self {
        Self {
            mnt: AtomicPtr::new(MountRef::as_ptr(&p.mnt).cast_mut()),
            dentry: AtomicPtr::new(DentryRef::as_ptr(&p.dentry).cast_mut()),
        }
    }

    /// Point at `p`, under the write side of the fs_struct's sequence
    fn set(&self, p: &Path) {
        self.mnt
            .store(MountRef::as_ptr(&p.mnt).cast_mut(), Ordering::Release);
        self.dentry
            .store(DentryRef::as_ptr(&p.dentry).cast_mut(), Ordering::Release);
    }

    /// The mount and dentry, borrowed for `g`
    fn get<'g>(&self, _g: &'g RcuReadGuard) -> (&'g Mount, &'g Dentry) {
        let m = self.mnt.load(Ordering::Acquire);
        let d = self.dentry.load(Ordering::Acquire);
        // SAFETY: each is the address of a mount and a dentry the
        // fs_struct's locked paths held when it was stored (`new`,
        // `set`, never null), published before the path it replaced is
        // put (after the write section); a mount and a dentry are freed
        // only a grace period after their last reference goes, which
        // waits for `_g`, taken before this load
        unsafe { (&*m, &*d) }
    }
}

/// What an RCU walk reads of root or pwd (Linux nd->path / nd->root
/// with nd->seq / nd->root_seq): borrowed, with no reference, the
/// dentry's `d_seq` sampled in the same read of the fs_struct
pub type PathRcu<'g> = (&'g Mount, &'g Dentry, u32);

impl FsStruct {
    /// Create a new FsStruct with the given root and pwd
    pub fn new(root: Path, pwd: Path) -> Arc<Self> {
        arc_nofail(Self::with(root, pwd, 0o022))
    }

    fn with(root: Path, pwd: Path, umask: u16) -> Self {
        Self {
            root_rcu: PathPtrs::new(&root),
            pwd_rcu: PathPtrs::new(&pwd),
            seq: SeqLock::new(FsStructInner { pwd, root, umask }),
            users: core::sync::atomic::AtomicUsize::new(1),
        }
    }

    /// Create a new FsStruct at where "/" lands in the namespace: the
    /// rootfs (Linux init_mount_tree: root and pwd on the mutable
    /// rootfs, not the nullfs under it)
    pub fn new_root() -> Option<Arc<Self>> {
        let root = crate::ns::current_mnt_ns().root_path()?;
        Some(Self::new(root.clone(), root))
    }

    /// The current working directory, a reference (Linux get_fs_pwd)
    pub fn get_pwd(&self) -> Path {
        self.seq.read_excl().pwd.clone()
    }

    /// The root directory, a reference (Linux get_fs_root)
    pub fn get_root(&self) -> Path {
        self.seq.read_excl().root.clone()
    }

    /// The root for an RCU walk (Linux set_root under LOOKUP_RCU: read
    /// under fs->seq, root_seq from its d_seq), no reference
    pub fn root_rcu<'g>(&'g self, g: &'g RcuReadGuard) -> PathRcu<'g> {
        self.read_rcu(&self.root_rcu, g)
    }

    /// The cwd for an RCU walk (Linux path_init's AT_FDCWD under
    /// LOOKUP_RCU), no reference
    pub fn pwd_rcu<'g>(&'g self, g: &'g RcuReadGuard) -> PathRcu<'g> {
        self.read_rcu(&self.pwd_rcu, g)
    }

    /// `p` and its dentry's `d_seq`, read again if a writer raced
    /// (read_seqbegin .. read_seqretry)
    fn read_rcu<'g>(&'g self, p: &'g PathPtrs, g: &'g RcuReadGuard) -> PathRcu<'g> {
        loop {
            let s = self.seq.read_begin();
            let (m, d) = p.get(g);
            let seq = d.d_seq_begin();
            if !self.seq.read_retry(s) {
                return (m, d, seq);
            }
        }
    }

    /// Get umask
    pub fn get_umask(&self) -> u16 {
        self.seq.read_excl().umask
    }

    /// Set the cwd (Linux set_fs_pwd): the old one is put after the
    /// write section
    pub fn set_pwd(&self, new_pwd: Path) {
        let old = {
            let mut inner = self.seq.write();
            self.pwd_rcu.set(&new_pwd);
            core::mem::replace(&mut inner.pwd, new_pwd)
        };
        drop(old);
    }

    /// Set the root (Linux set_fs_root), likewise
    pub fn set_root(&self, new_root: Path) {
        let old = {
            let mut inner = self.seq.write();
            self.root_rcu.set(&new_root);
            core::mem::replace(&mut inner.root, new_root)
        };
        drop(old);
    }

    /// Root and cwd at `old` move to `new` in one write section (Linux
    /// chroot_fs_refs' replace_path for one fs_struct)
    pub fn replace_refs(&self, old: &Path, new: &Path) {
        let olds = {
            let mut inner = self.seq.write();
            let root = inner.root.same(old).then(|| {
                self.root_rcu.set(new);
                core::mem::replace(&mut inner.root, new.clone())
            });
            let pwd = inner.pwd.same(old).then(|| {
                self.pwd_rcu.set(new);
                core::mem::replace(&mut inner.pwd, new.clone())
            });
            (root, pwd)
        };
        drop(olds);
    }

    /// After a mount namespace copy: root and pwd move to the copies of
    /// their mounts (Linux copy_mnt_ns, for the new task's fs)
    pub fn repoint(&self, map: &crate::fs::mount::MountMap) {
        let swap = |p: &Path| {
            map.iter()
                .find(|(old, _)| MountRef::ptr_eq(old, &p.mnt))
                .map(|(_, new)| Path::new(new.clone(), p.dentry.clone()))
        };
        let old = {
            let mut inner = self.seq.write();
            let (root, pwd) = (swap(&inner.root), swap(&inner.pwd));
            if let Some(r) = &root {
                self.root_rcu.set(r);
            }
            if let Some(p) = &pwd {
                self.pwd_rcu.set(p);
            }
            (
                root.map(|r| core::mem::replace(&mut inner.root, r)),
                pwd.map(|p| core::mem::replace(&mut inner.pwd, p)),
            )
        };
        drop(old);
    }

    /// Set umask, returns old umask (Linux xchg: the sequence does not
    /// move)
    pub fn set_umask(&self, new_umask: u16) -> u16 {
        let mut inner = self.seq.read_excl();
        core::mem::replace(&mut inner.umask, new_umask)
    }

    /// Copy this FsStruct (for fork without CLONE_FS)
    ///
    /// Creates a new FsStruct with the same pwd/root/umask,
    /// but independent (changes don't affect original).
    /// The underlying mount/dentry objects are still shared via Arc.
    ///
    /// The paths (references) and umask are read under the locking
    /// read, the new struct allocated after it (Linux copy_fs_struct
    /// allocates, then copies under read_seqlock_excl)
    pub fn copy(&self) -> Result<Arc<Self>, KernelError> {
        // The mount count, an atomic, no allocation
        let (pwd, root, umask) = {
            let inner = self.seq.read_excl();
            (inner.pwd.clone(), inner.root.clone(), inner.umask)
        };
        try_arc(Self::with(root, pwd, umask))
    }
}

// =============================================================================
// Global task -> FsStruct mapping
// =============================================================================

// =============================================================================
// Task FS accessors - Task.fs under its alloc_lock (Linux task_lock)
// =============================================================================

use crate::task::Task;

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
pub fn kthread_fs_init(knullfs: MountRef) {
    let root = Path::new(knullfs.clone(), (*knullfs.root).clone());
    KTHREAD_FS.call_once(|| FsStruct::new(root.clone(), root));
}

/// Initialize filesystem context for task `t` (the task itself, or
/// its creator before it runs); the old one is dropped after the lock
pub fn init_task_fs(t: &Task, fs: Arc<FsStruct>) {
    let old = t.task_lock().set_fs(Some(fs));
    if let Some(o) = &old {
        o.users.fetch_sub(1, core::sync::atomic::Ordering::SeqCst);
    }
    drop(old);
}

/// The fs context of task `t` (a cloned Arc, under its alloc_lock; the
/// current task's is `percpu::current_fs()`, lock-free); a kernel
/// thread's is [`KTHREAD_FS`]
pub fn get_task_fs(t: &Task) -> Option<Arc<FsStruct>> {
    let fs = t.task_lock().fs().cloned();
    fs.or_else(|| kthread_fs(t))
}

/// [`KTHREAD_FS`] for a kernel thread `t`, borrowed
pub fn kthread_fs_ref(t: &Task) -> Option<&'static FsStruct> {
    matches!(t.kind, crate::task::TaskKind::KernelThread)
        .then(|| KTHREAD_FS.get().map(|f| &**f))
        .flatten()
}

/// [`KTHREAD_FS`] for a kernel thread `t`, which has no fs of its own
pub fn kthread_fs(t: &Task) -> Option<Arc<FsStruct>> {
    matches!(t.kind, crate::task::TaskKind::KernelThread)
        .then(|| KTHREAD_FS.get().cloned())
        .flatten()
}

/// Remove filesystem context when task exits
///
/// This decrements the Arc refcount. If this was the last reference
/// (no other tasks sharing this FsStruct), the FsStruct is dropped,
/// which in turn drops the Path references to pwd and root (after
/// the task's alloc_lock is released: nothing is released under it).
pub fn exit_task_fs(t: &Task) {
    let fs = t.task_lock().set_fs(None);
    if let Some(o) = &fs {
        o.users.fetch_sub(1, core::sync::atomic::Ordering::SeqCst);
    }
    drop(fs);
}

/// The fs context a child of the caller gets (Linux copy_fs, reading
/// current->fs lock-free): the caller's own with CLONE_FS, else a copy
/// (a caller without one: a new one at the root). Nothing is counted
/// yet, so a fork that fails afterwards just drops it. ENOMEM if the
/// copy cannot be made.
pub fn fork_fs(share: bool) -> Result<Option<Arc<FsStruct>>, KernelError> {
    Ok(match crate::task::percpu::current().fs() {
        Some(fs) if share => Some(fs),
        Some(fs) => Some(fs.copy()?),
        None => FsStruct::new_root(),
    })
}

/// Give `child` its fork-time fs context, counting one more sharer
/// for CLONE_FS (Linux fs->users++)
pub fn install_fork_fs(child: &Task, fs: Arc<FsStruct>, shared: bool) {
    if shared {
        fs.users.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    }
    init_task_fs(child, fs);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(m: &MountRef) -> Path {
        Path::new(m.clone(), (*m.root).clone())
    }

    /// An RCU walk reads the paths the fs_struct holds, with no
    /// reference: each write section moves what it reads, and the
    /// counts are the locked paths' alone
    #[test]
    fn rcu_reads_follow_writes() {
        let (a, b) = (crate::fs::mount::test_mnt(), crate::fs::mount::test_mnt());
        let fs = FsStruct::new(at(&a), at(&a));
        let n = DentryRef::count(&b.root);
        let same = |p: PathRcu<'_>, m: &MountRef| {
            core::ptr::eq(p.0, MountRef::as_ptr(m))
                && core::ptr::eq(p.1, DentryRef::as_ptr(&m.root))
        };
        let g = crate::sync::rcu::read_lock();
        assert!(same(fs.root_rcu(&g), &a) && same(fs.pwd_rcu(&g), &a));
        drop(g);
        fs.set_pwd(at(&b));
        let g = crate::sync::rcu::read_lock();
        assert!(same(fs.root_rcu(&g), &a) && same(fs.pwd_rcu(&g), &b));
        assert_eq!(DentryRef::count(&b.root), n + 1);
        drop(g);
        fs.replace_refs(&at(&a), &at(&b));
        let g = crate::sync::rcu::read_lock();
        assert!(same(fs.root_rcu(&g), &b) && same(fs.pwd_rcu(&g), &b));
        drop(g);
        assert!(fs.get_root().same(&at(&b)));
    }
}

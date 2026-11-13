//! Mount references (Linux mntget, mntput, mntput_no_expire,
//! cleanup_mnt, delayed_mntput)
//!
//! A [`MountRef`] is a counted reference to a mount (Linux a `struct
//! vfsmount *` holding mnt_count): paths, namespace roots, a parent's
//! list of its submounts. A link that must not keep its mount (a
//! submount's parent, a peer group's members, the superblock's
//! s_mounts) is a `Weak`, and takes a reference with
//! [`MountRef::try_get`]; a plain `Arc<Mount>` never escapes this module
//! except as a counted list entry ([`MountRef::into_counted`]).
//!
//! The last reference's drop never tears the mount down where it is:
//! the teardown (Linux cleanup_mnt: submounts, mountpoint, root dentry,
//! superblock, any of which may sleep) runs later with nothing held, in
//! the dropping task on its way back to user mode (task_work, so an
//! umount(2) is complete when it returns), or from interrupt context, a
//! kernel thread or a task past `exit_task_work` in the system
//! workqueue (Linux delayed_mntput_work). A put is safe under any lock.
//!
//! Locking: `DELAYED_MNTPUT` is an IrqSpinlock leaf. The teardown takes
//! NAMESPACE_SEM and MOUNT_LOCK (submounts) and `s_mounts`, with
//! nothing else held.

use alloc::sync::{Arc, Weak};
use core::cell::UnsafeCell;
use core::mem::ManuallyDrop;
use core::sync::atomic::{Ordering, fence};

use super::mount::Mount;
use crate::sync::IrqSpinlock;
use crate::task::task_work::{CallbackHead, CbAdapter, Twa, task_work_add};
use crate::task::workqueue::{DelayedWork, SYSTEM_WQ};
use crate::util::list::List;

/// `Mount.mnt_count` once the mount is torn down (or being torn down):
/// no reference can be taken again
pub(super) const MNT_REF_DEAD: usize = usize::MAX;

/// A counted reference to a mount (Linux mntget'd `struct vfsmount *`):
/// a clone takes one, the last one's drop queues the teardown
///
/// # Invariants
/// Holds one strong count of its `Arc` and one of the mount's
/// `mnt_count`.
pub struct MountRef(ManuallyDrop<Arc<Mount>>);

impl MountRef {
    /// The first reference to a new mount, whose count is one
    pub(super) fn first(m: Arc<Mount>) -> Self {
        debug_assert_eq!(m.mnt_count.load(Ordering::Relaxed), 1);
        Self(ManuallyDrop::new(m))
    }

    /// A reference to the mount `w` names, unless its last one is gone
    /// (Linux legitimize_mnt / mnt_add_count on a mount not doomed). A
    /// failure briefly holds an `Arc` that may drop the mount's memory;
    /// that drop does no teardown (the teardown owns its own `Arc`)
    pub fn try_get(w: &Weak<Mount>) -> Option<Self> {
        Self::try_from_arc(w.upgrade()?)
    }

    /// A reference to the mount `m`, unless its last one is gone
    fn try_from_arc(m: Arc<Mount>) -> Option<Self> {
        let mut n = m.mnt_count.load(Ordering::Relaxed);
        loop {
            if n == 0 || n == MNT_REF_DEAD {
                return None;
            }
            match m
                .mnt_count
                .compare_exchange_weak(n, n + 1, Ordering::Acquire, Ordering::Relaxed)
            {
                Ok(_) => return Some(Self(ManuallyDrop::new(m))),
                Err(v) => n = v,
            }
        }
    }

    /// A reference to a list entry handed out by
    /// [`MountRef::into_counted`] while it is on the list (the caller
    /// holds the lock that keeps it there), so it is live: None (and a
    /// debug assertion) only if that was broken
    pub(super) fn from_entry(m: Arc<Mount>) -> Option<Self> {
        let r = Self::try_from_arc(m);
        debug_assert!(r.is_some(), "mount: dead entry on a counted list");
        r
    }

    /// The reference as a plain `Arc` that keeps its count, for a list
    /// that holds counted entries (a parent's submounts); given back by
    /// [`MountRef::from_counted`]
    pub(super) fn into_counted(self) -> Arc<Mount> {
        let mut me = ManuallyDrop::new(self);
        // SAFETY: taken once; `me` is never dropped
        unsafe { ManuallyDrop::take(&mut me.0) }
    }

    /// The reference an entry from [`MountRef::into_counted`] holds
    ///
    /// # Safety
    /// `m` came from `into_counted` and its count was not taken back.
    pub(super) unsafe fn from_counted(m: Arc<Mount>) -> Self {
        Self(ManuallyDrop::new(m))
    }

    /// The mount `w` names still has a reference (none can be taken
    /// once the last is gone, though its teardown may not have run)
    pub fn is_live(w: &Weak<Mount>) -> bool {
        w.upgrade().is_some_and(|m| m.is_live())
    }

    /// A non-owning link to the mount (no reference)
    pub fn downgrade(this: &Self) -> Weak<Mount> {
        Arc::downgrade(&this.0)
    }

    /// The mount's address (its identity)
    pub fn as_ptr(this: &Self) -> *const Mount {
        Arc::as_ptr(&this.0)
    }

    /// Both are the same mount
    pub fn ptr_eq(a: &Self, b: &Self) -> bool {
        Arc::ptr_eq(&a.0, &b.0)
    }

    /// Drop the reference: its `Arc` back for the teardown if it was the
    /// last
    fn put(self) -> Option<Arc<Mount>> {
        let m = self.into_counted();
        if m.mnt_count.fetch_sub(1, Ordering::Release) != 1 {
            return None;
        }
        // Every other holder's use comes before the teardown
        fence(Ordering::Acquire);
        // No reference can be taken from here on (try_get sees 0 until
        // then, and refuses it too)
        m.mnt_count.store(MNT_REF_DEAD, Ordering::Relaxed);
        Some(m)
    }
}

impl Clone for MountRef {
    /// Another reference (Linux mntget)
    fn clone(&self) -> Self {
        self.0.mnt_count.fetch_add(1, Ordering::Relaxed);
        Self(self.0.clone())
    }
}

impl core::ops::Deref for MountRef {
    type Target = Mount;
    fn deref(&self) -> &Mount {
        &self.0
    }
}

impl Drop for MountRef {
    /// mntput: the last reference queues the teardown
    fn drop(&mut self) {
        // SAFETY: taken once, here; `put` owns it from now on
        let r = MountRef(ManuallyDrop::new(unsafe {
            ManuallyDrop::take(&mut self.0)
        }));
        if let Some(m) = r.put() {
            mntput_deferred(m);
        }
    }
}

impl Mount {
    /// It still has a counted reference (Linux: not MNT_DOOMED)
    pub(super) fn is_live(&self) -> bool {
        let n = self.mnt_count.load(Ordering::Acquire);
        n != 0 && n != MNT_REF_DEAD
    }
}

/// Queue the teardown of `m` (Linux mntput_no_expire's task_work_add,
/// else delayed_mntput_list)
fn mntput_deferred(m: Arc<Mount>) {
    let me = crate::task::percpu::current();
    let p = Arc::into_raw(m);
    if !crate::sync::in_interrupt() && !me.is_kthread() {
        // SAFETY: `p` is live; its head is on no list (queued once, by
        // the last reference's drop); the task's list keeps the `Arc`
        // until `__cleanup_mnt`
        if unsafe { task_work_add(&me, &raw const (*p).mnt_task_work, Twa::Resume) }.is_ok() {
            return;
        }
        // Past exit_task_work: the delayed list takes it
    }
    let first = {
        let mut l = DELAYED_MNTPUT.lock();
        let first = l.is_empty();
        // SAFETY: as above; the delayed list keeps the `Arc` until
        // `delayed_mntput`
        unsafe { l.push_back(&raw const (*p).mnt_task_work) };
        first
    };
    if first && let Some(w) = DELAYED_MNTPUT_WORK.get() {
        // One tick later (Linux schedule_delayed_work(.., 1))
        SYSTEM_WQ.queue_delayed_work(w.clone(), 1);
    }
}

/// The teardown callback of a mount queued by `mntput_deferred` (Linux
/// __cleanup_mnt)
///
/// # Safety
/// `cb` is the `mnt_task_work` of a mount whose `Arc` was handed to the
/// list it came off (`Arc::into_raw`).
pub(super) unsafe fn __cleanup_mnt(cb: *const CallbackHead) {
    let off = core::mem::offset_of!(Mount, mnt_task_work);
    // SAFETY: the caller's contract: `cb` is inside a Mount, and its
    // `Arc` is ours
    let m = unsafe { Arc::from_raw(cb.cast::<u8>().sub(off).cast::<Mount>()) };
    crate::sync::might_sleep();
    // SAFETY: the count is MNT_REF_DEAD (`put`): no reference exists
    // or can be made, and this runs once per mount
    unsafe { m.cleanup() };
}

/// Mounts whose teardown waits for the system workqueue (Linux
/// delayed_mntput_list): their `mnt_task_work` heads, each holding its
/// mount's `Arc`. IrqSpinlock leaf: added to from any context.
static DELAYED_MNTPUT: IrqSpinlock<List<CbAdapter>> = IrqSpinlock::new(List::new());

/// The work item that drains `DELAYED_MNTPUT` (Linux
/// delayed_mntput_work), made by `mnt_init`
static DELAYED_MNTPUT_WORK: spin::Once<Arc<IrqSpinlock<DelayedWork>>> = spin::Once::new();

/// Tear down the mounts on the delayed list (Linux delayed_mntput):
/// those there now; ones their teardowns drop are queued again
fn delayed_mntput() {
    let mut l = core::mem::replace(&mut *DELAYED_MNTPUT.lock(), List::new());
    while let Some(cb) = l.pop_front() {
        // SAFETY: taken off the delayed list, which held its `Arc`
        unsafe { CallbackHead::run(cb) };
    }
}

/// Make the delayed list's work item (Linux mnt_init): before the first
/// mount
pub fn mnt_init() {
    let w = DELAYED_MNTPUT_WORK.call_once(|| {
        crate::util::kalloc::arc_nofail(IrqSpinlock::new(DelayedWork::new(delayed_mntput)))
    });
    // Teardowns queued before the work existed found none to schedule
    if !DELAYED_MNTPUT.lock().is_empty() {
        SYSTEM_WQ.queue_delayed_work(w.clone(), 1);
    }
}

/// A mount's field its teardown releases while the mount's memory may
/// still be reachable (Linux cleanup_mnt's dput of mnt_root and
/// deactivate_super of mnt_sb, before the RCU free): read through any
/// reference to the mount, taken once by the teardown
pub struct MntOwned<T>(UnsafeCell<ManuallyDrop<T>>);

// SAFETY: shared access is `&T` only (Deref), as for `T` itself; the one
// mutation (`take`) has exclusive use by its contract
unsafe impl<T: Sync + Send> Sync for MntOwned<T> {}
// SAFETY: owns a `T`
unsafe impl<T: Send> Send for MntOwned<T> {}

impl<T> MntOwned<T> {
    pub(super) const fn new(v: T) -> Self {
        Self(UnsafeCell::new(ManuallyDrop::new(v)))
    }

    /// Release the value
    ///
    /// # Safety
    /// Called once; no reference to the value exists or is made later:
    /// the mount has no counted reference left (`MNT_REF_DEAD`) and is
    /// off every list that hands out a borrowed one.
    pub(super) unsafe fn take(&self) -> T {
        // SAFETY: the caller's contract gives exclusive use
        unsafe { ManuallyDrop::take(&mut *self.0.get()) }
    }
}

impl<T> core::ops::Deref for MntOwned<T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: `take` runs only once no reference is left that could
        // reach this (its contract)
        unsafe { &*self.0.get() }
    }
}

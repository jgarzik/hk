//! Mount references (Linux mnt_pcp, mntget, mntput, mntput_no_expire,
//! legitimize_mnt, cleanup_mnt, delayed_mntput)
//!
//! A [`MountRef`] is a counted reference to a mount (Linux a `struct
//! vfsmount *` holding mnt_count): paths, open files, namespace roots,
//! a parent's list of its submounts. The count is per CPU (Linux
//! mnt_pcp): a clone adds one to the calling CPU's part, lock-free. A
//! link that must not keep its mount (a submount's parent, a peer
//! group's members, the superblock's s_mounts) is a `Weak` (it keeps
//! the memory only) and takes a reference with [`MountRef::try_get`].
//!
//! While the mount is in a namespace (`Mount.mnt_ns` set; a kernel
//! mount carries `MNT_NS_INTERNAL`), the tree holds a reference to it
//! (its parent's list entry, or the namespace root), so no count can
//! reach zero: a put only takes from its CPU's part, under an RCU read
//! guard (Linux mntput_no_expire's fast path). Taking a mount out of
//! its namespace clears `mnt_ns`, waits out a grace period
//! (`rcu::synchronize`), then puts the tree's references (Linux
//! umount_tree, then namespace_unlock), so no fast put that saw the
//! namespace still runs. From then on a put is exact: under MOUNT_LOCK
//! write it takes from its part and sums them all; the one that reaches
//! zero marks the mount doomed (Linux MNT_DOOMED) and queues its
//! teardown. [`MountRef::try_get`] from a `Weak` is a fast add while the
//! mount is in a namespace, else refused once doomed, under MOUNT_LOCK
//! (Linux legitimize_mnt).
//!
//! The teardown (Linux cleanup_mnt: submounts, mountpoint, root dentry,
//! superblock, any of which may sleep) runs later with nothing held, in
//! the dropping task on its way back to user mode (task_work, so an
//! umount(2) is complete when it returns), or from interrupt context, a
//! kernel thread or a task past `exit_task_work` in the system
//! workqueue (Linux delayed_mntput_work). A put is safe under any lock
//! but MOUNT_LOCK.
//!
//! The mount's memory is an `Arc`: one strong count stands for all its
//! references, taken back by the teardown, which drops it a grace
//! period later (Linux delayed_free_vfsmnt), so an RCU walk may read a
//! mount it reached with no reference; list entries and `Weak`s keep
//! the rest.
//!
//! Locking: a put's exact path and a `try_get` outside a namespace take
//! MOUNT_LOCK (write, locking read): no put of a mount outside a
//! namespace under it.
//! `DELAYED_MNTPUT` is an IrqSpinlock leaf. The teardown takes
//! NAMESPACE_SEM and MOUNT_LOCK (submounts) and `s_mounts`, with nothing
//! else held.

use alloc::sync::{Arc, Weak};
use core::cell::UnsafeCell;
use core::mem::ManuallyDrop;
use core::ptr::NonNull;
use core::sync::atomic::{Ordering, fence};

use super::mount::{MOUNT_LOCK, Mount};

/// `Mount.mnt_ns` of a kernel mount, in no namespace of its own (Linux
/// MNT_NS_INTERNAL): its puts take the fast path, and it is never
/// released
pub(super) const MNT_NS_INTERNAL: u64 = u64::MAX;
use crate::sync::IrqSpinlock;
use crate::task::task_work::{CallbackHead, CbAdapter, Twa, task_work_add};
use crate::task::workqueue::{DelayedWork, SYSTEM_WQ};
use crate::util::list::List;

/// This CPU is set up to take an RCU read guard and queue callbacks
/// (not in host unit tests, nor at the start of boot)
fn have_cpu() -> bool {
    !cfg!(test) && crate::cpu::try_this_id().is_some()
}

impl Mount {
    /// Add `n` to this CPU's part (Linux mnt_add_count): another CPU's
    /// part would do (they are atomics), only slower
    fn pcp_add(&self, n: isize) {
        self.mnt_pcp.add(n);
    }

    /// Its references, summed (Linux mnt_get_count): exact once out of
    /// its namespace, approximate while fast puts may run
    pub(super) fn mnt_get_count(&self) -> isize {
        self.mnt_pcp.sum()
    }

    /// It still has a reference (Linux: not MNT_DOOMED)
    pub(super) fn is_live(&self) -> bool {
        !self.doomed.load(Ordering::Acquire)
    }
}

/// A counted reference to a mount (Linux mntget'd `struct vfsmount *`):
/// a clone takes one, the last one's drop queues the teardown
///
/// # Invariants
/// Holds one of its mount's references (its parts' sum, Linux
/// mnt_count), which keep the `Arc` that the mount's references share.
pub struct MountRef(NonNull<Mount>);

// SAFETY: a counted reference to a Sync mount, usable from any thread
unsafe impl Send for MountRef {}
// SAFETY: as above; `&MountRef` only reads the mount
unsafe impl Sync for MountRef {}

impl MountRef {
    /// The first reference to a new mount: its `Arc` becomes the one
    /// its references share
    pub(super) fn first(m: Arc<Mount>) -> Self {
        m.pcp_add(1);
        // SAFETY: from `Arc::into_raw`, never null
        Self(unsafe { NonNull::new_unchecked(Arc::into_raw(m).cast_mut()) })
    }

    fn mount(&self) -> &Mount {
        // SAFETY: the type invariant keeps the mount alive
        unsafe { self.0.as_ref() }
    }

    /// The shared `Arc`, borrowed
    fn arc(&self) -> ManuallyDrop<Arc<Mount>> {
        // SAFETY: the shared strong count is held while a reference is
        // (type invariant); ManuallyDrop keeps it from being dropped
        ManuallyDrop::new(unsafe { Arc::from_raw(self.0.as_ptr()) })
    }

    /// A reference to the mount `w` names, unless its last one is gone
    /// (Linux legitimize_mnt): an add while it is long-term, else
    /// decided under MOUNT_LOCK, where a mount is doomed
    pub fn try_get(w: &Weak<Mount>) -> Option<Self> {
        let a = w.upgrade()?;
        Self::try_get_mnt(&a)
        // `a` dropped: never the last strong count while a reference is
        // held; after the teardown, only memory goes
    }

    /// [`MountRef::try_get`] for a mount whose memory the caller's lock
    /// keeps (Linux legitimize_mnt on mnt_parent under namespace_sem)
    pub fn try_get_mnt(a: &Mount) -> Option<Self> {
        let p = NonNull::from(a);
        if have_cpu() {
            let _g = crate::sync::rcu::read_lock();
            // In a namespace: taking it out clears `mnt_ns` and puts the
            // tree's reference only after a grace period, so this add is
            // counted first
            if a.ns() != 0 {
                a.pcp_add(1);
                return Some(Self(p));
            }
        }
        // In no namespace: no fast put runs, and the count reaches zero
        // only with `doomed` set, under the write side
        let _ml = MOUNT_LOCK.read_excl();
        if a.doomed.load(Ordering::Acquire) {
            return None;
        }
        a.pcp_add(1);
        Some(Self(p))
    }

    /// A reference to `m`, reached under an RCU read guard with
    /// MOUNT_LOCK's sequence `seq` sampled before (Linux
    /// __legitimize_mnt): the add first, then the sequence. Unmoved, no
    /// link to `m` changed since the sample, so the tree still holds its
    /// reference and the add is counted. Moved: under MOUNT_LOCK, an add
    /// to a doomed mount is taken back (`Err(None)`), else the caller
    /// gets the reference to put, with the guard released, before it
    /// retries (`Err(Some)`).
    pub(super) fn legitimize(m: &Mount, seq: u32) -> Result<Self, Option<Self>> {
        if MOUNT_LOCK.read_retry(seq) {
            return Err(None);
        }
        m.pcp_add(1);
        // Pairs with `put_slow`'s: its sum sees this add, or this sees
        // the write section that took the tree's reference away
        fence(Ordering::SeqCst);
        let r = Self(NonNull::from(m));
        if !MOUNT_LOCK.read_retry(seq) {
            return Ok(r);
        }
        let _ml = MOUNT_LOCK.read_excl();
        if m.doomed.load(Ordering::Acquire) {
            // Its count reached zero without this add: never a reference
            core::mem::forget(r);
            m.pcp_add(-1);
            return Err(None);
        }
        Err(Some(r))
    }

    /// Another reference to a list entry (by [`MountRef::into_entry`])
    /// while it is on the list (the caller holds the lock that keeps it
    /// there), which holds one
    pub(super) fn entry_ref(m: &Mount) -> Self {
        debug_assert!(m.is_live(), "mount: doomed entry on a list");
        m.pcp_add(1);
        Self(NonNull::from(m))
    }

    /// The reference, as the `Arc` an intrusive list keeps (an entry of
    /// a parent's `mnt_mounts`); back by [`MountRef::from_entry`]
    pub(super) fn into_entry(self) -> Arc<Mount> {
        let me = ManuallyDrop::new(self);
        Arc::clone(&me.arc())
    }

    /// The reference a list entry holds
    ///
    /// # Safety
    /// `a` came from [`MountRef::into_entry`] and was not given back.
    pub(super) unsafe fn from_entry(a: Arc<Mount>) -> Self {
        let p = NonNull::from(a.as_ref());
        drop(a);
        Self(p)
    }

    /// The mount `w` names is not doomed (a reference can still be
    /// taken)
    pub fn is_live(w: &Weak<Mount>) -> bool {
        w.upgrade().is_some_and(|m| m.is_live())
    }

    /// A non-owning link to the mount (no reference)
    pub fn downgrade(this: &Self) -> Weak<Mount> {
        Arc::downgrade(&this.arc())
    }

    /// The shared `Arc`, another strong count (an entry of the mount
    /// hash, which holds one)
    pub(super) fn arc_of(this: &Self) -> Arc<Mount> {
        Arc::clone(&this.arc())
    }

    /// The mount's address (its identity)
    pub fn as_ptr(this: &Self) -> *const Mount {
        this.0.as_ptr()
    }

    /// Both are the same mount
    pub fn ptr_eq(a: &Self, b: &Self) -> bool {
        a.0 == b.0
    }

    /// The exact put (Linux mntput_no_expire after its fast path):
    /// under MOUNT_LOCK write, the last reference dooms the mount
    fn put_slow(self) {
        let me = ManuallyDrop::new(self);
        let m = me.mount();
        let last = {
            let _ml = MOUNT_LOCK.write();
            // With the grace period after `mnt_ns` was cleared: every
            // fast put that saw it is in the parts (Linux smp_mb)
            fence(Ordering::SeqCst);
            m.pcp_add(-1);
            let count = m.mnt_get_count();
            debug_assert!(count >= 0, "mount: count below zero");
            let last = count == 0 && !m.doomed.load(Ordering::Relaxed);
            if last {
                m.doomed.store(true, Ordering::Release);
            }
            last
        };
        if last {
            // SAFETY: the shared strong count, which the references held
            // and the teardown now owns
            mntput_deferred(unsafe { Arc::from_raw(me.0.as_ptr()) });
        }
    }
}

impl Clone for MountRef {
    /// Another reference (Linux mntget): the caller's keeps the count
    /// above zero, so an add is enough
    fn clone(&self) -> Self {
        self.mount().pcp_add(1);
        Self(self.0)
    }
}

impl core::ops::Deref for MountRef {
    type Target = Mount;
    fn deref(&self) -> &Mount {
        self.mount()
    }
}

impl Drop for MountRef {
    /// mntput: a take from this CPU's part while the mount is in a
    /// namespace, else the exact put
    fn drop(&mut self) {
        if have_cpu() {
            let _g = crate::sync::rcu::read_lock();
            let m = self.mount();
            if m.ns() != 0 {
                m.pcp_add(-1);
                return;
            }
        }
        MountRef(self.0).put_slow();
    }
}

/// Queue the teardown of `m` (Linux mntput_no_expire's task_work_add,
/// else delayed_mntput_list)
fn mntput_deferred(m: Arc<Mount>) {
    let p = Arc::into_raw(m);
    // No task before per-CPU data (or in host unit tests): the delayed
    // list, drained once `mnt_init` made its work
    let me = have_cpu().then(crate::task::percpu::current);
    if let Some(me) = me
        && !crate::sync::in_interrupt()
        && !me.is_kthread()
    {
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
    // SAFETY: the mount is doomed (`put_slow`): no reference exists or
    // can be made, and this runs once per mount
    unsafe { m.cleanup() };
    // An RCU walk that reached it before its links were cleared may
    // still read it (Linux cleanup_mnt's call_rcu of
    // delayed_free_vfsmnt)
    if have_cpu() {
        crate::sync::rcu::kfree_rcu(m);
    }
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
    /// the mount is doomed (or never had a reference) and is off every
    /// list that hands out a borrowed one.
    pub(super) unsafe fn take(&self) -> T {
        // SAFETY: the caller's contract: this is the one release. A raw
        // read, no `&mut`: the bits stay, for `stale`
        unsafe { ManuallyDrop::into_inner(core::ptr::read(self.0.get())) }
    }

    /// The value's bits, which `take` leaves in place (Linux: the
    /// pointer fields of a mount torn down but not yet freed): for an
    /// RCU walk that may reach the mount after its teardown, to compare
    /// addresses, never to use the value
    pub(super) fn stale(&self) -> *const T {
        self.0.get().cast::<T>()
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

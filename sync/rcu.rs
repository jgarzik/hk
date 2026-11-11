//! Read-copy update (Linux kernel/rcu/tree.c, include/linux/rcupdate.h;
//! the non-preemptible flavor, one flat level)
//!
//! A reader holds an [`RcuReadGuard`] (Linux rcu_read_lock): preemption
//! off, so it never sleeps, and its CPU passes no quiescent state while
//! it holds one. An updater publishes a new version ([`RcuArc::replace`])
//! and frees the old one only after a grace period: every CPU online
//! when it began has passed a quiescent state, so no reader still sees
//! the old version.
//!
//! Quiescent states (Linux rcu_qs, rcu_sched_clock_irq): a context
//! switch, the idle loop, and a clock interrupt that arrived with
//! preemption on and no interrupt beneath it (Linux
//! rcu_flavor_sched_clock_irq's preempt_count() == HARDIRQ_OFFSET):
//! user mode and kernel code outside any spin lock or reader. A switch
//! only records that the CPU passed one (it runs under the rq lock); the
//! next clock interrupt or idle pass reports it.
//!
//! Grace periods (Linux rcu_gp_kthread): `GP_SEQ` counts them, odd while
//! one runs. `rcu_gp` starts one when `synchronize` asks (`GP_REQ`): it
//! fills `NODE` with the online CPUs, then makes `GP_SEQ` odd; each
//! CPU notices it at a quiescent state and clears its bit; the last one
//! wakes `rcu_gp`, which makes `GP_SEQ` even and wakes the waiters.
//! One flat mask, where Linux has a tree of rcu_node masks.
//!
//! Callbacks (Linux call_rcu, kfree_rcu): an object with an embedded
//! [`RcuHead`] is released after a grace period without the updater
//! waiting ([`kfree_rcu`], [`RcuRetired::defer`], `RcuUnlinked::defer`);
//! [`put_rcu`] drops references to an object with an embedded
//! [`RcuPuts`], queueable again before an earlier one ran
//! (`NullsUnlinked::defer`). Each CPU queues its callbacks, stamped with the grace period they
//! wait for, on its own list; its clock interrupt wakes its `rcuc/N`
//! once the first is ready, which runs them with preemption off.
//! [`rcu_barrier`] waits for every callback queued before it.
//!
//! ## Locking (doc/LOCKING.md 1.4.2)
//! `NODE` (IrqSpinlock leaf, Linux rcu_node.lock) holds the mask of CPUs
//! still owing a quiescent state; `GP_SEQ` changes only under it, so a
//! report checks under it that the grace period it saw is still the one
//! running (Linux rcu_report_qs_rdp's gp_seq check), and a stale one (a
//! context switch in an earlier grace period) clears nothing. Lockless
//! fast paths read `GP_SEQ` (Acquire); SeqCst fences order a CPU's
//! readers before its report and a grace period's ends around the
//! updates (Linux smp_mb__after_unlock_lock). Per-CPU state is touched
//! only by its CPU with interrupts off; wakeups come after `NODE` is
//! released. A CPU joins `ONLINE` when its scheduler
//! starts and never leaves (no CPU hotplug); every CPU takes the clock
//! interrupt every tick (no NOHZ), so idle CPUs report too.
//! `RcuData.cbs` (IrqSpinlock leaf, Linux the rdp's callback list) holds
//! a CPU's callbacks; nothing is taken under it and callbacks run after
//! it is released.

use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering, fence};

use crate::sync::IrqSpinlock;
use crate::sync::waitqueue::WaitQueue;
use crate::util::cpumask::{CpuMask, CpuSet};

#[cfg(not(test))]
use crate::arch as percpu;

/// Host unit tests run in userspace: no per-CPU data or preemption
#[cfg(test)]
mod percpu {
    pub fn preempt_disable() {}
    pub fn preempt_enable() {}
    pub fn preempt_count() -> u32 {
        0
    }
}

/// Grace periods, Linux rcu_seq: twice the number completed, odd while
/// one runs; written under `NODE`
static GP_SEQ: AtomicU64 = AtomicU64::new(0);
/// The `GP_SEQ` value the latest `synchronize` waits for
static GP_REQ: AtomicU64 = AtomicU64::new(0);
/// CPUs that have not passed a quiescent state in this grace period
/// (Linux rcu_node.qsmask)
static NODE: IrqSpinlock<CpuSet> = IrqSpinlock::new(CpuSet::new());
/// CPUs that take part (their scheduler runs)
static ONLINE: CpuMask = CpuMask::new();
/// `rcu_gp` runs: started while the boot CPU is the only one online,
/// so grace periods run whenever several are
static STARTED: AtomicBool = AtomicBool::new(false);
/// `rcu_gp` waits here for a request or for the last report
static GP_KICK: WaitQueue = WaitQueue::new();
/// `synchronize` callers wait here for their grace period's end
static GP_DONE: WaitQueue = WaitQueue::new();

/// A CPU's view (Linux struct rcu_data): the grace period in which a
/// context switch passed a quiescent state (written by its CPU with
/// interrupts off)
static SWITCHED: crate::cpu::PerCpu<AtomicU64> = crate::percpu![AtomicU64::new(0)];

/// `GP_SEQ` value after which a grace period begun after now has ended
/// (Linux rcu_seq_snap)
fn snap(seq: u64) -> u64 {
    (seq + 3) & !1
}

/// `a` is at or past `b` (Linux rcu_seq_done; counters never wrap)
fn done(a: u64, b: u64) -> bool {
    a >= b
}

/// A read-side critical section (Linux rcu_read_lock): preemption off
/// until the guard drops, so the holder must not sleep (`might_sleep`
/// reports it) and its CPU passes no quiescent state meanwhile.
#[must_use]
pub struct RcuReadGuard {
    /// Preemption is off on this CPU: the guard stays on it
    _not_send: PhantomData<*const ()>,
}

/// Enter a read-side critical section (Linux rcu_read_lock)
#[cfg_attr(feature = "lockdep", track_caller)]
pub fn read_lock() -> RcuReadGuard {
    percpu::preempt_disable();
    crate::sync::lockdep::rcu_lock(core::panic::Location::caller());
    RcuReadGuard {
        _not_send: PhantomData,
    }
}

impl Drop for RcuReadGuard {
    fn drop(&mut self) {
        crate::sync::lockdep::rcu_unlock();
        percpu::preempt_enable();
    }
}

/// This CPU takes part in grace periods (its scheduler starts; before
/// it runs any reader)
pub fn cpu_online(cpu: u32) {
    ONLINE.set(cpu);
}

/// Report a quiescent state for this CPU if the running grace period
/// wants one (interrupts off). `now`: this very point is quiescent; it
/// comes after the grace period began, which this CPU saw (`GP_SEQ`
/// odd, Acquire), as did a context switch that recorded it.
fn report(now: bool) {
    let Some(cpu) = crate::cpu::try_this_id() else {
        return;
    };
    let g = GP_SEQ.load(Ordering::Acquire);
    if g & 1 == 0 || !(now || SWITCHED.get(cpu).load(Ordering::Relaxed) == g) {
        return;
    }
    // The readers this CPU ran before are over before the report is
    // seen (Linux rcu_report_qs_rdp)
    fence(Ordering::SeqCst);
    let last = {
        let mut n = NODE.lock();
        // Still the grace period seen, and this CPU still owes it
        if GP_SEQ.load(Ordering::Relaxed) != g || !n.test(cpu) {
            return;
        }
        n.clear(cpu);
        n.is_empty()
    };
    if last {
        GP_KICK.wake_all();
    }
}

/// The clock interrupt (any CPU, interrupt context): a quiescent state
/// if it arrived with preemption on, outside any other interrupt (Linux
/// rcu_sched_clock_irq)
pub fn clock_irq() {
    use crate::arch::{CurrentArch, PerCpuOps};
    let quiet = crate::arch::preempt_count() == 0 && CurrentArch::interrupt_depth() == 1;
    report(quiet);
    if let Some(cpu) = crate::cpu::try_this_id() {
        cbs_ready_irq(cpu);
    }
}

/// A context switch passed a quiescent state (Linux
/// rcu_note_context_switch; rq lock held: reported later)
pub fn note_context_switch() {
    let Some(cpu) = crate::cpu::try_this_id() else {
        return;
    };
    let g = GP_SEQ.load(Ordering::Acquire);
    if g & 1 != 0 {
        SWITCHED.get(cpu).store(g, Ordering::Relaxed);
    }
}

/// The idle loop, preemptible and holding nothing: a quiescent state
pub fn idle() {
    let f = crate::sync::local_irq_save();
    report(true);
    crate::sync::local_irq_restore(f);
}

/// Wait until every reader that might be running now has finished
/// (Linux synchronize_rcu). With one CPU online (boot, before the APs
/// get schedulers), returning is itself a grace period (Linux
/// rcu_blocking_is_gp).
pub fn synchronize() {
    crate::sync::might_sleep();
    // A reader of this CPU would wait for itself, or (one CPU) not at
    // all: a use after free in the caller
    assert!(
        percpu::preempt_count() == 0 && !crate::sync::irqs_disabled(),
        "synchronize_rcu in atomic context"
    );
    if ONLINE.snapshot().count() <= 1 {
        fence(Ordering::SeqCst);
        return;
    }
    // Several CPUs run only after `start` (else this would return early
    // while another CPU's reader still sees the old version)
    assert!(
        STARTED.load(Ordering::Acquire),
        "synchronize_rcu before rcu_gp"
    );
    let want = snap(GP_SEQ.load(Ordering::Acquire));
    GP_REQ.fetch_max(want, Ordering::SeqCst);
    GP_KICK.wake_all();
    GP_DONE.wait_event(|| done(GP_SEQ.load(Ordering::Acquire), want));
}

/// One grace period (Linux rcu_gp_init, rcu_gp_cleanup)
fn grace_period() {
    // The updates before the request are seen by every CPU's readers
    // that start after it notices (Linux smp_mb in rcu_gp_init)
    fence(Ordering::SeqCst);
    {
        let mut n = NODE.lock();
        *n = ONLINE.snapshot();
        GP_SEQ.fetch_add(1, Ordering::Release);
    }
    fence(Ordering::SeqCst);
    GP_KICK.wait_event(|| NODE.lock().is_empty());
    // Every reader that saw the old state is over before anything
    // after the grace period
    fence(Ordering::SeqCst);
    {
        let _n = NODE.lock();
        GP_SEQ.fetch_add(1, Ordering::Release);
    }
    GP_DONE.wake_all();
}

/// `rcu_gp` (Linux rcu_gp_kthread): grace periods while requested
fn gp_kthread(_: usize) {
    loop {
        GP_KICK.wait_event(|| {
            !done(
                GP_SEQ.load(Ordering::Acquire),
                GP_REQ.load(Ordering::Acquire),
            )
        });
        grace_period();
    }
}

/// Start `rcu_gp` once the boot CPU's scheduler runs, before any other
/// CPU's (Linux rcu_spawn_gp_kthread, an early_initcall before smp_init)
pub fn start() {
    match crate::task::kthread::kthread_run_prio(
        "rcu_gp",
        gp_kthread,
        0,
        None,
        crate::task::PRIORITY_HIGH,
    ) {
        Ok(_) => STARTED.store(true, Ordering::Release),
        Err(e) => panic!("rcu: cannot start rcu_gp: {:?}", e),
    }
}

/// An RCU-protected `Arc` (Linux `struct foo __rcu *`): readers see the
/// current version under an [`RcuReadGuard`]; [`replace`](Self::replace)
/// publishes a new one and hands back the old, freed after a grace
/// period. Updaters serialize under their own lock.
pub struct RcuArc<T> {
    /// `Arc::into_raw` of the current version, or null
    ptr: AtomicPtr<T>,
}

// SAFETY: an `Arc<T>` moves between threads and is shared through it
unsafe impl<T: Send + Sync> Send for RcuArc<T> {}
// SAFETY: as above
unsafe impl<T: Send + Sync> Sync for RcuArc<T> {}

impl<T> RcuArc<T> {
    /// Holding `v`
    pub fn new(v: Arc<T>) -> Self {
        Self {
            ptr: AtomicPtr::new(Arc::into_raw(v).cast_mut()),
        }
    }

    /// The current version, valid while `g` is held (Linux
    /// rcu_dereference)
    pub fn read<'a>(&'a self, _g: &'a RcuReadGuard) -> Option<&'a T> {
        let p = self.ptr.load(Ordering::Acquire);
        // SAFETY: a published `Arc` stays allocated until a grace period
        // after it is replaced (`RcuRetired`), and `_g` keeps that grace
        // period from ending while the borrow lives
        unsafe { p.as_ref() }
    }

    /// A reference to the current version (no allocation)
    pub fn get(&self) -> Option<Arc<T>> {
        let g = read_lock();
        let p = self.ptr.load(Ordering::Acquire);
        if p.is_null() {
            return None;
        }
        // SAFETY: `p` is a live `Arc::into_raw` (see `read`; `g` held)
        let a = unsafe {
            Arc::increment_strong_count(p);
            Arc::from_raw(p)
        };
        drop(g);
        Some(a)
    }

    /// Publish `new` (Linux rcu_assign_pointer); the old version is
    /// released after a grace period, when the result drops
    pub fn replace(&self, new: Option<Arc<T>>) -> RcuRetired<T> {
        let n = new.map_or(core::ptr::null_mut(), |a| Arc::into_raw(a).cast_mut());
        let old = self.ptr.swap(n, Ordering::AcqRel);
        // SAFETY: `old` was published by `new`/`replace` and the swap
        // took it out: this is its one owner
        RcuRetired(core::ptr::NonNull::new(old).map(|p| unsafe { Arc::from_raw(p.as_ptr()) }))
    }
}

impl<T> Drop for RcuArc<T> {
    fn drop(&mut self) {
        let p = *self.ptr.get_mut();
        if !p.is_null() {
            // SAFETY: no reader borrows `self` any more (`&mut`), so the
            // current version has its one owner here
            drop(unsafe { Arc::from_raw(p) });
        }
    }
}

/// A version taken out by [`RcuArc::replace`]: dropping it waits for a
/// grace period, then releases it (Linux synchronize_rcu; kfree)
#[must_use]
pub struct RcuRetired<T>(Option<Arc<T>>);

impl<T: HasRcuHead + Send + Sync> RcuRetired<T> {
    /// Release it after a grace period without waiting for one (Linux
    /// kfree_rcu instead of synchronize_rcu + kfree): the drop runs in
    /// `rcuc/N` ([`kfree_rcu`]'s rules)
    pub fn defer(mut self) {
        if let Some(a) = self.0.take() {
            kfree_rcu(a);
        }
    }
}

impl<T> Drop for RcuRetired<T> {
    fn drop(&mut self) {
        if let Some(a) = self.0.take() {
            synchronize();
            drop(a);
        }
    }
}

// ============================================================================
// Callbacks (Linux call_rcu, kfree_rcu, rcu_do_batch, rcu_barrier)
// ============================================================================

/// A callback's place on a CPU's callback list (Linux struct rcu_head),
/// embedded in the object it releases ([`HasRcuHead`]). Queued at most
/// once at a time: a second queueing while the first waits is a bug
/// (Linux debug_rcu_head_queue), stopped by an assert.
///
/// # Invariants
/// `next` is `IDLE` while the head is on no list; `func` is written only
/// by the one queueing that claimed the head (`next` from `IDLE` to
/// null), before it is linked under its list's lock, and read only by
/// the `rcuc/N` that took it off under that lock, before it sets `next`
/// back to `IDLE` (Release; a claim is an Acquire).
pub struct RcuHead {
    next: AtomicPtr<RcuHead>,
    /// The `GP_SEQ` value it waits for (rcu_seq_snap when queued)
    gp: AtomicU64,
    /// What to run, on what (an object reference taken by the queueing)
    func: UnsafeCell<Option<(RcuFn, *const ())>>,
}

// SAFETY: `func` is touched only by the claimant, then by the runner,
// ordered by the list lock (type invariant); the rest are atomics
unsafe impl Sync for RcuHead {}
// SAFETY: as above
unsafe impl Send for RcuHead {}

/// A callback: run once, after a grace period, on its argument
///
/// # Safety
/// (Of each such fn) its argument is the one queued with it.
pub type RcuFn = unsafe fn(*const ());

/// The `next` of a head on no list (never a head's address)
const IDLE: *mut RcuHead = core::ptr::dangling_mut();

impl RcuHead {
    pub const fn new() -> Self {
        Self {
            next: AtomicPtr::new(IDLE),
            gp: AtomicU64::new(0),
            func: UnsafeCell::new(None),
        }
    }
}

impl Default for RcuHead {
    fn default() -> Self {
        Self::new()
    }
}

/// A type that embeds an [`RcuHead`] for its deferred release (Linux
/// kfree_rcu(ptr, rhf)); implemented with [`rcu_head!`](crate::rcu_head)
///
/// # Safety
/// `rcu_head` returns a field of `self`, used for nothing else.
pub unsafe trait HasRcuHead {
    fn rcu_head(&self) -> &RcuHead;
}

/// `rcu_head!(Type, field)`: `Type.field` is its [`HasRcuHead`]
#[macro_export]
macro_rules! rcu_head {
    ($t:ty, $field:ident) => {
        // SAFETY: a field of the item, named for this use only
        unsafe impl $crate::sync::rcu::HasRcuHead for $t {
            fn rcu_head(&self) -> &$crate::sync::rcu::RcuHead {
                &self.$field
            }
        }
    };
}

/// A CPU's callbacks in queueing order (Linux rcu_segcblist, one
/// segment: each head carries its own grace period)
///
/// # Invariants
/// `head` through `next` to `tail` are the claimed heads queued here,
/// each holding the object reference its `func` releases; `pending`
/// counts them plus those taken off and not yet run (Linux
/// rcu_segcblist_n_cbs).
struct CbList {
    head: *mut RcuHead,
    tail: *mut RcuHead,
    pending: usize,
}

// SAFETY: the heads are reached only under the list's lock
unsafe impl Send for CbList {}

/// A CPU's callback state (Linux struct rcu_data)
struct RcuData {
    /// Its callbacks (IrqSpinlock leaf: call_rcu may run in an
    /// interrupt handler)
    cbs: IrqSpinlock<CbList>,
    /// The grace period the first callback waits for (u64::MAX: none),
    /// written under `cbs`, read by the clock interrupt
    next_gp: AtomicU64,
    /// `rcuc/N` waits here
    wq: WaitQueue,
}

static RDP: crate::cpu::PerCpu<RcuData> = crate::percpu![RcuData {
    cbs: IrqSpinlock::new(CbList {
        head: core::ptr::null_mut(),
        tail: core::ptr::null_mut(),
        pending: 0,
    }),
    next_gp: AtomicU64::new(u64::MAX),
    wq: WaitQueue::new(),
}];

/// Callbacks run per batch at least (Linux DEFAULT_RCU_BLIMIT)
const BLIMIT: usize = 10;
/// Past this many pending, a batch runs them all (Linux qhimark)
const QHIMARK: usize = 10_000;
/// A batch runs at least pending >> this (Linux rcu_divisor)
const DIVISOR: u32 = 7;

impl CbList {
    /// Link a claimed head at the tail
    ///
    /// # Safety
    /// `h` is claimed (`next` null) by the caller, live until its
    /// callback runs.
    unsafe fn push(&mut self, h: *mut RcuHead) {
        // SAFETY: the tail is a queued head (type invariant), `h` the
        // caller's
        match unsafe { self.tail.as_ref() } {
            Some(t) => t.next.store(h, Ordering::Relaxed),
            None => self.head = h,
        }
        // INVARIANT: `h` is queued, with its reference
        self.tail = h;
        self.pending += 1;
    }

    /// The grace period of the first head (u64::MAX: none)
    fn first_gp(&self) -> u64 {
        // SAFETY: a queued head (type invariant)
        unsafe { self.head.as_ref() }.map_or(u64::MAX, |h| h.gp.load(Ordering::Relaxed))
    }

    /// Take off up to `max` heads from the front whose grace period is
    /// over by `seq`, as a chain ending in null; how many
    fn take_ready(&mut self, seq: u64, max: usize) -> (*mut RcuHead, usize) {
        let first = self.head;
        let mut last: *mut RcuHead = core::ptr::null_mut();
        let mut n = 0;
        let mut cur = self.head;
        // SAFETY: queued heads (type invariant)
        while let Some(h) = unsafe { cur.as_ref() } {
            if n == max || !done(seq, h.gp.load(Ordering::Relaxed)) {
                break;
            }
            last = cur;
            cur = h.next.load(Ordering::Relaxed);
            n += 1;
        }
        if n == 0 {
            return (core::ptr::null_mut(), 0);
        }
        // SAFETY: `last` is a queued head; the chain from `first` to it
        // leaves the list (still counted in `pending` until run)
        unsafe { (*last).next.store(core::ptr::null_mut(), Ordering::Relaxed) };
        // INVARIANT: the rest of the list starts at `cur`
        self.head = cur;
        if cur.is_null() {
            self.tail = core::ptr::null_mut();
        }
        (first, n)
    }
}

/// Queue `func(arg)` to run after a grace period (Linux call_rcu):
/// `arg` is a reference to the object `h` is embedded in, which `func`
/// releases. Any context; never sleeps, never allocates. Panics if `h`
/// is queued already.
///
/// # Safety
/// `h` lives until `func(arg)` runs (it is in the object `arg` keeps),
/// and `func(arg)` may run on any CPU with preemption off.
pub unsafe fn call_rcu(h: &RcuHead, func: RcuFn, arg: *const ()) {
    let claimed = h
        .next
        .compare_exchange(
            IDLE,
            core::ptr::null_mut(),
            Ordering::Acquire,
            Ordering::Relaxed,
        )
        .is_ok();
    assert!(claimed, "call_rcu: head already queued");
    // SAFETY: claimed: only this queueing writes it (type invariant)
    unsafe { *h.func.get() = Some((func, arg)) };
    let d = RDP.this();
    let want = {
        let mut l = d.cbs.lock();
        // The caller's unlink is seen before the grace period sampled
        // (Linux's full barrier in __call_rcu_common)
        fence(Ordering::SeqCst);
        let want = snap(GP_SEQ.load(Ordering::Acquire));
        h.gp.store(want, Ordering::Relaxed);
        let first = l.head.is_null();
        // SAFETY: claimed above, live until its callback (the caller)
        unsafe { l.push(core::ptr::from_ref(h).cast_mut()) };
        if first {
            d.next_gp.store(want, Ordering::Release);
        }
        want
    };
    // Ask rcu_gp for the grace period (Linux rcu_start_this_gp)
    if GP_REQ.fetch_max(want, Ordering::SeqCst) < want {
        GP_KICK.wake_all();
    }
}

/// Release one reference to `a` after a grace period (Linux
/// kfree_rcu): its readers may still hold `&T` under a guard. The drop
/// runs in `rcuc/N`, preemption off: it must not sleep, and allocates
/// only with a GFP named.
pub fn kfree_rcu<T: HasRcuHead + Send + Sync>(a: Arc<T>) {
    /// The reference queued, dropped
    ///
    /// # Safety
    /// `p` is the `Arc::into_raw` queued with it.
    unsafe fn put<T>(p: *const ()) {
        // SAFETY: `Arc::into_raw` of `kfree_rcu`, taken back once
        drop(unsafe { Arc::from_raw(p.cast::<T>()) });
    }
    let h = core::ptr::from_ref(a.rcu_head());
    let p = Arc::into_raw(a).cast::<()>();
    // SAFETY: the head is a field of the object (HasRcuHead), kept by
    // the reference `p` until `put` drops it; T is Send + Sync
    unsafe { call_rcu(&*h, put::<T>, p) };
}

/// Deferred reference drops that may be queued again before earlier
/// ones ran ([`put_rcu`]), embedded in the object ([`HasRcuPuts`]):
/// an entry of a `util::hlist_nulls` table can be unhashed, hashed again
/// and unhashed again within one grace period, so one [`RcuHead`] queued
/// per drop ([`kfree_rcu`]) would be queued twice.
///
/// # Invariants
/// `n` counts the references handed to `put_rcu` and not yet dropped,
/// each leaked (`Arc::into_raw`); `head` is queued, or its callback is
/// running, exactly while `n` > 0 (its callback re-queues it when the
/// count it leaves is not zero).
pub struct RcuPuts {
    head: RcuHead,
    n: AtomicUsize,
}

impl RcuPuts {
    pub const fn new() -> Self {
        Self {
            head: RcuHead::new(),
            n: AtomicUsize::new(0),
        }
    }

    /// One more reference handed over: true if none was pending, so
    /// the caller queues `head` (otherwise it is queued or its callback
    /// runs and will re-queue it: the RMWs on `n` are totally ordered)
    fn get(&self) -> bool {
        self.n.fetch_add(1, Ordering::AcqRel) == 0
    }

    /// One reference dropped by the callback: true if more remain, put
    /// after the callback was queued (its grace period may have begun
    /// before them), so the callback queues `head` again
    fn put(&self) -> bool {
        self.n.fetch_sub(1, Ordering::AcqRel) > 1
    }
}

impl Default for RcuPuts {
    fn default() -> Self {
        Self::new()
    }
}

/// A type that embeds an [`RcuPuts`]; implemented with
/// [`rcu_puts!`](crate::rcu_puts)
///
/// # Safety
/// `rcu_puts` returns a field of `self`, used for nothing else.
pub unsafe trait HasRcuPuts {
    fn rcu_puts(&self) -> &RcuPuts;
}

/// `rcu_puts!(Type, field)`: `Type.field` is its [`HasRcuPuts`]
#[macro_export]
macro_rules! rcu_puts {
    ($t:ty, $field:ident) => {
        // SAFETY: a field of the item, named for this use only
        unsafe impl $crate::sync::rcu::HasRcuPuts for $t {
            fn rcu_puts(&self) -> &$crate::sync::rcu::RcuPuts {
                &self.$field
            }
        }
    };
}

/// Drop one reference to `a` at least a grace period from now, without
/// waiting (Linux kfree_rcu, but queueable again on the same object
/// before an earlier one ran). Any context; never sleeps or allocates.
/// The reference is counted in the object's [`RcuPuts`]; the first one
/// queues its head, and each callback drops one reference and queues
/// the head again while more are counted, so the k-th reference goes
/// in the k-th callback, queued after the k-th was handed over. The
/// drop runs in `rcuc/N`, preemption off: the object's last drop must
/// not sleep, and allocates only with a GFP named.
pub fn put_rcu<T: HasRcuPuts + Send + Sync>(a: Arc<T>) {
    let h = core::ptr::from_ref(a.rcu_puts());
    // INVARIANT: leaked here, counted below
    let p = Arc::into_raw(a).cast::<()>();
    // SAFETY: a field of the object (HasRcuPuts), kept by `p`
    let puts = unsafe { &*h };
    if puts.get() {
        // SAFETY: the head is idle (`n` was 0: type invariant), a field
        // of the object kept by the counted references until the last
        // callback drops them; T is Send + Sync
        unsafe { call_rcu(&puts.head, puts_cb::<T>, p) };
    }
}

/// [`put_rcu`]'s callback: one counted reference dropped, the head
/// queued again if more remain (it is idle: `do_batch` reset it)
///
/// # Safety
/// `p` is an `Arc::into_raw` of a `T` counted in its `RcuPuts`, a grace
/// period after the head was queued.
unsafe fn puts_cb<T: HasRcuPuts + Send + Sync>(p: *const ()) {
    let t = p.cast::<T>();
    // SAFETY: a counted reference (the caller's) keeps it until the
    // drop below
    let puts = unsafe { &*t }.rcu_puts();
    if puts.put() {
        // SAFETY: references remain counted (leaked), so the object and
        // its head live until a later callback; the head is idle again
        unsafe { call_rcu(&puts.head, puts_cb::<T>, p) };
    }
    // SAFETY: one of the counted references (all clones of one Arc,
    // so which is fungible), taken back once
    drop(unsafe { Arc::from_raw(t) });
}

/// The clock interrupt of `cpu`: wake its `rcuc/N` if its first
/// callback's grace period is over (Linux rcu_pending ->
/// invoke_rcu_core)
fn cbs_ready_irq(cpu: u32) {
    let d = RDP.get(cpu);
    if done(
        GP_SEQ.load(Ordering::Acquire),
        d.next_gp.load(Ordering::Acquire),
    ) {
        d.wq.wake_all();
    }
}

/// Run a batch of `d`'s ready callbacks (Linux rcu_do_batch):
/// preemption off, as Linux runs them with bottom halves off
fn do_batch(d: &RcuData) {
    let seq = GP_SEQ.load(Ordering::Acquire);
    // Readers that saw the objects are over before they are released
    fence(Ordering::SeqCst);
    let (mut cur, n) = {
        let mut l = d.cbs.lock();
        let bl = if l.pending > QHIMARK {
            usize::MAX
        } else {
            BLIMIT.max(l.pending >> DIVISOR)
        };
        let r = l.take_ready(seq, bl);
        d.next_gp.store(l.first_gp(), Ordering::Release);
        r
    };
    percpu::preempt_disable();
    // SAFETY: the chain just taken off: claimed heads, each live until
    // its callback runs (call_rcu's contract)
    while let Some(h) = unsafe { cur.as_ref() } {
        cur = h.next.load(Ordering::Relaxed);
        // SAFETY: the claimant wrote it before queueing; this runner
        // took the head off under the lock (type invariant)
        let f = unsafe { (*h.func.get()).take() };
        // INVARIANT: on no list again; `h` is not touched after this
        // (the callback may free it)
        h.next.store(IDLE, Ordering::Release);
        if let Some((func, arg)) = f {
            // SAFETY: call_rcu's contract: a grace period has passed
            // since it was queued, preemption is off
            unsafe { func(arg) };
        }
    }
    percpu::preempt_enable();
    d.cbs.lock().pending -= n;
}

/// `rcuc/N` (Linux rcu_cpu_kthread): CPU N's ready callbacks
fn rcuc(cpu: usize) {
    let d = RDP.get(cpu as u32);
    loop {
        d.wq.wait_event(|| {
            done(
                GP_SEQ.load(Ordering::Acquire),
                d.next_gp.load(Ordering::Acquire),
            )
        });
        do_batch(d);
        crate::task::percpu::cond_resched();
    }
}

/// Start `rcuc/N` on every CPU with a scheduler (Linux
/// rcu_spawn_core_kthreads); callbacks queued before wait for it
pub fn spawn_core_kthreads() {
    for cpu in 0..crate::cpu::nr_cpu_ids() {
        if !crate::task::percpu::cpu_has_scheduler(cpu) {
            continue;
        }
        let name = alloc::format!("rcuc/{}", cpu);
        if let Err(e) = crate::task::kthread::kthread_run(&name, rcuc, cpu as usize, Some(cpu)) {
            panic!("rcu: cannot start {}: {:?}", name, e);
        }
    }
}

/// `rcu_barrier` callers, one at a time (Linux rcu_state.barrier_mutex)
static BARRIER_MUTEX: crate::sync::Mutex<()> = crate::sync::Mutex::new(());
/// Barrier callbacks not yet run, plus one held by `rcu_barrier` while
/// it queues them (Linux barrier_cpu_count)
static BARRIER_LEFT: AtomicUsize = AtomicUsize::new(0);
static BARRIER_DONE: crate::sync::completion::Completion =
    crate::sync::completion::Completion::new();
/// Each CPU's barrier callback (Linux rcu_data.barrier_head)
static BARRIER_HEAD: crate::cpu::PerCpu<RcuHead> = crate::percpu![RcuHead::new()];

/// A barrier callback ran
///
/// # Safety
/// None beyond [`RcuFn`]'s: the argument is unused.
unsafe fn barrier_cb(_: *const ()) {
    if BARRIER_LEFT.fetch_sub(1, Ordering::AcqRel) == 1 {
        BARRIER_DONE.complete();
    }
}

/// Queue `cpu`'s barrier callback behind its last callback, if it has
/// any (Linux rcu_barrier_entrain): it runs after all of them
fn barrier_entrain(cpu: u32) {
    let d = RDP.get(cpu);
    let h = BARRIER_HEAD.get(cpu);
    {
        let mut l = d.cbs.lock();
        if l.pending == 0 {
            return;
        }
        BARRIER_LEFT.fetch_add(1, Ordering::AcqRel);
        let claimed = h
            .next
            .compare_exchange(
                IDLE,
                core::ptr::null_mut(),
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_ok();
        assert!(claimed, "rcu_barrier: barrier head queued");
        // SAFETY: claimed just now (type invariant)
        unsafe { *h.func.get() = Some((barrier_cb, core::ptr::null())) };
        // The last one's grace period, or none if all were taken off
        // to run: then it is ready at once
        // SAFETY: the tail is a queued head (CbList invariant)
        let gp = unsafe { l.tail.as_ref() }.map_or(0, |t| t.gp.load(Ordering::Relaxed));
        h.gp.store(gp, Ordering::Relaxed);
        let first = l.head.is_null();
        // SAFETY: claimed, and a static
        unsafe { l.push(core::ptr::from_ref(h).cast_mut()) };
        if first {
            d.next_gp.store(gp, Ordering::Release);
        }
    }
    d.wq.wake_all();
}

/// Wait until every callback queued before this call has run (Linux
/// rcu_barrier); thread context, may sleep
pub fn rcu_barrier() {
    crate::sync::might_sleep();
    let _m = BARRIER_MUTEX.lock();
    BARRIER_LEFT.store(1, Ordering::Release);
    for (cpu, _) in RDP.for_each_possible() {
        barrier_entrain(cpu);
    }
    if BARRIER_LEFT.fetch_sub(1, Ordering::AcqRel) == 1 {
        BARRIER_DONE.complete();
    }
    BARRIER_DONE.wait();
}

/// Boot check: a grace period ends, and a version replaced is released
/// only after it, waiting for it or by a callback
pub fn selftest() -> bool {
    let a = crate::util::kalloc::try_arc(1u32).ok();
    let Some(a) = a else {
        return false;
    };
    let cell = RcuArc::new(a.clone());
    let before = GP_SEQ.load(Ordering::Acquire);
    let read_ok = {
        let g = read_lock();
        cell.read(&g) == Some(&1)
    };
    drop(cell.replace(None));
    let after = GP_SEQ.load(Ordering::Acquire);
    // Only our reference is left; with several CPUs a grace period ran
    let gp_ok = ONLINE.snapshot().count() <= 1 || done(after, snap(before));
    read_ok && Arc::strong_count(&a) == 1 && cell.get().is_none() && gp_ok && callback_selftest()
}

/// The callback half of [`selftest`]: a version retired with `defer`
/// is dropped by `rcuc/N`, preemption off, after a grace period, by the
/// time `rcu_barrier` returns
fn callback_selftest() -> bool {
    /// GP_SEQ when the probe was retired
    static RETIRED: AtomicU64 = AtomicU64::new(0);
    /// 0: not dropped, 1: dropped wrongly, 2: dropped after a grace
    /// period in atomic context
    static FREED: AtomicU64 = AtomicU64::new(0);
    struct Probe {
        rcu: RcuHead,
    }
    crate::rcu_head!(Probe, rcu);
    impl Drop for Probe {
        fn drop(&mut self) {
            let gp = done(
                GP_SEQ.load(Ordering::Acquire),
                snap(RETIRED.load(Ordering::Acquire)),
            );
            let atomic = percpu::preempt_count() > 0;
            FREED.store(1 + u64::from(gp && atomic), Ordering::Release);
        }
    }
    FREED.store(0, Ordering::Release);
    let Ok(p) = crate::util::kalloc::try_arc(Probe {
        rcu: RcuHead::new(),
    }) else {
        return false;
    };
    let cell = RcuArc::new(p);
    let seen = cell.read(&read_lock()).is_some();
    // Retired with the cell's reference, the last
    let old = cell.replace(None);
    RETIRED.store(GP_SEQ.load(Ordering::Acquire), Ordering::Release);
    old.defer();
    rcu_barrier();
    seen && FREED.load(Ordering::Acquire) == 2
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A claimed head waiting for `gp`
    fn head(gp: u64) -> RcuHead {
        let h = RcuHead::new();
        h.next.store(core::ptr::null_mut(), Ordering::Relaxed);
        h.gp.store(gp, Ordering::Relaxed);
        h
    }

    fn chain(mut cur: *mut RcuHead) -> alloc::vec::Vec<u64> {
        let mut v = alloc::vec::Vec::new();
        // SAFETY: heads of the test, alive on its stack
        while let Some(h) = unsafe { cur.as_ref() } {
            v.push(h.gp.load(Ordering::Relaxed));
            cur = h.next.load(Ordering::Relaxed);
        }
        v
    }

    /// put_rcu's count: only the first of a run of puts queues the head;
    /// each callback drops one and queues again while puts remain, the
    /// last one (count back to 0) not, and a later put starts over
    #[test]
    fn puts_count() {
        let p = RcuPuts::new();
        assert!(p.get());
        assert!(!p.get() && !p.get());
        // Callback 1 and 2 re-queue; a put lands while 3 is pending
        assert!(p.put() && p.put());
        assert!(!p.get());
        assert!(p.put());
        assert!(!p.put());
        assert_eq!(p.n.load(Ordering::Relaxed), 0);
        assert!(p.get());
    }

    /// Ready callbacks leave from the front, in order, up to the batch
    /// limit, stopping at the first whose grace period is not over; the
    /// taken ones stay counted until they run
    #[test]
    fn take_ready_front_in_order() {
        let hs = [head(2), head(4), head(4), head(6)];
        let mut l = CbList {
            head: core::ptr::null_mut(),
            tail: core::ptr::null_mut(),
            pending: 0,
        };
        for h in &hs {
            // SAFETY: claimed, alive for the test
            unsafe { l.push(core::ptr::from_ref(h).cast_mut()) };
        }
        assert_eq!(l.first_gp(), 2);
        let (c, n) = l.take_ready(4, 2);
        assert_eq!((chain(c), n), (alloc::vec![2, 4], 2));
        assert_eq!(l.first_gp(), 4);
        assert_eq!(l.take_ready(3, 10).1, 0);
        let (c, n) = l.take_ready(5, 10);
        assert_eq!((chain(c), n), (alloc::vec![4], 1));
        let (c, _) = l.take_ready(6, 10);
        assert_eq!(chain(c), [6]);
        assert!(l.head.is_null() && l.tail.is_null());
        assert_eq!((l.first_gp(), l.pending), (u64::MAX, 4));
    }
}

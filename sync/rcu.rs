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

use alloc::sync::Arc;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering, fence};

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

impl<T> Drop for RcuRetired<T> {
    fn drop(&mut self) {
        if let Some(a) = self.0.take() {
            synchronize();
            drop(a);
        }
    }
}

/// Boot check: a grace period ends, and a version replaced is released
/// only after it
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
    read_ok && Arc::strong_count(&a) == 1 && cell.get().is_none() && gp_ok
}

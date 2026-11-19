//! Sleeping locks (Linux kernel/locking): `Mutex` (struct mutex) and
//! `RwSem` (struct rw_semaphore)
//!
//! A contended lock sleeps on a wait queue instead of spinning, so a
//! holder may block (page locks, block I/O, user page faults). Rules:
//! thread context only, never taken in IRQ context or while holding a
//! spinlock (`might_sleep` checks the preempt count, which every spin
//! lock raises); sleeping locks order above every spinlock. Before
//! scheduling is enabled (early boot) a contended lock spins.

pub mod completion;
pub mod waitqueue;

mod irqflags;
mod irqspin;
pub mod lockdep;
mod locked_by;
mod mutex;
pub mod qrwlock;
pub mod qspinlock;
mod racy;
pub mod rcu;
mod rwsem;
mod seqlock;
mod sole;
pub mod spin;

pub use irqflags::{IrqFlags, irqs_disabled, local_irq_restore, local_irq_save};
pub use irqspin::{IrqRwLock, IrqRwReadGuard, IrqRwWriteGuard, IrqSpinlock, IrqSpinlockGuard};
pub use locked_by::{
    InstanceCell, InstanceGuard, InstanceLock, InstanceRef, InstanceRefMut, LockedBy, LockedByBoth,
    LockedByEither, LockedCell, UniqueOwner,
};
pub use mutex::{Mutex, MutexGuard};
pub use racy::RacyCell;
pub use rwsem::{RwSem, RwSemReadGuard, RwSemWriteGuard};
pub use seqlock::{SeqCount, SeqCountGuard, SeqLock, SeqWriteGuard};
pub use sole::{Sole, SoleCell, Word};

/// What the sleeping locks take from the scheduler
#[cfg(not(test))]
mod sched {
    pub use crate::sync::waitqueue::signal_pending_state;
    use crate::task::Task;
    pub use crate::task::percpu::{TaskRef, get_ticks, schedule, set_current_state};
    pub use crate::task::wake_q::WakeQ;

    /// The caller is a task that may sleep (not tid 0: an idle task or
    /// the boot context, which never contend for a sleeping lock)
    pub fn can_sleep() -> bool {
        crate::task::percpu::can_sleep()
    }

    /// The current task, queued as a sleeping lock's waiter
    pub fn waiter_task() -> *const Task {
        &raw const *crate::task::percpu::current()
    }

    /// The current task's identity as a sleeping lock's owner (Linux
    /// `current` in mutex->owner): its address, fixed for its life (a
    /// tid is not: a non-leader's exec takes its leader's), its low
    /// three bits clear (a `Task` is 8-aligned)
    pub fn current_owner() -> u64 {
        const _: () = assert!(core::mem::align_of::<Task>() >= 8);
        waiter_task().addr() as u64
    }

    /// The current task has an RT policy (rwsem handoff at once)
    pub fn current_rt() -> bool {
        crate::task::is_rt_policy(crate::task::percpu::current().se.policy())
    }

    /// A reference to a waiter's task, to wake it after the wait lock
    ///
    /// # Safety
    /// `t` is a `waiter_task()` whose waiter is still queued (the caller
    /// holds the lock's wait lock), so the task is alive.
    pub unsafe fn waiter_ref(t: *const Task) -> TaskRef {
        // SAFETY: alive (the caller); a waiter is never the boot task
        crate::task::percpu::task_ref(unsafe { &*t })
    }
}

/// Host unit tests: each thread is a task that never truly sleeps
/// (`schedule` yields, so waiters poll) and is never signalled; a
/// waiter's task is a tag that wakeups record
#[cfg(test)]
mod sched {
    extern crate std;
    use crate::task::Task;
    use crate::task::percpu::SleepState;
    use core::sync::atomic::{AtomicU64, Ordering};

    pub type TaskRef = *const Task;

    pub fn can_sleep() -> bool {
        true
    }

    /// A tid per thread
    pub fn current_tid() -> u64 {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        std::thread_local!(static TID: u64 = NEXT.fetch_add(1, Ordering::Relaxed));
        TID.with(|t| *t)
    }

    /// Ticks advance on every look, so waits expire
    pub fn get_ticks() -> u64 {
        static TICKS: AtomicU64 = AtomicU64::new(0);
        TICKS.fetch_add(1, Ordering::Relaxed)
    }

    pub fn schedule() {
        std::thread::yield_now();
    }

    pub fn set_current_state(_: SleepState) {}

    pub fn signal_pending_state(_: SleepState) -> bool {
        false
    }

    /// A per-thread owner identity, its low three bits clear
    pub fn current_owner() -> u64 {
        current_tid() << 3
    }

    pub fn waiter_task() -> *const Task {
        core::ptr::null()
    }

    pub fn current_rt() -> bool {
        false
    }

    /// # Safety
    /// None needed: a tag
    pub unsafe fn waiter_ref(t: *const Task) -> TaskRef {
        t
    }

    /// Records whom it would wake
    #[derive(Default)]
    pub struct WakeQ {
        pub woken: std::vec::Vec<TaskRef>,
    }

    impl WakeQ {
        pub fn new() -> Self {
            Self::default()
        }
        pub fn is_empty(&self) -> bool {
            self.woken.is_empty()
        }
        pub fn add_safe(&mut self, t: TaskRef) {
            self.woken.push(t);
        }
        pub fn wake(&mut self) {
            self.woken.clear();
        }
    }
}

/// Linux might_sleep (CONFIG_DEBUG_ATOMIC_SLEEP): no spin lock may be
/// held (every `IrqSpinlock` and `sync::spin` lock raises the preempt
/// count), interrupts must be on and no interrupt handler may run where
/// the caller can sleep: sleeping locks, `schedule`, wait queues, socket
/// waits, user copies. The first violation is reported as
/// `MIGHT_SLEEP:FAIL` (the boot tests fail on it); lockdep builds report
/// each call site, with the tracked locks held.
#[track_caller]
#[inline]
pub fn might_sleep() {
    #[cfg(feature = "lockdep")]
    lockdep::might_sleep();
    // Host unit tests have no CPU state to check. An interrupt handler
    // is checked whatever task it interrupted, the idle task included
    // (Linux __might_resched: preempt_count() is the hardirq's there)
    #[cfg(not(any(feature = "lockdep", test)))]
    if (sched::can_sleep() || in_interrupt()) && crate::system_state::checks_apply() && in_atomic()
    {
        atomic_sleep(core::panic::Location::caller());
    }
}

/// In an interrupt handler (Linux in_interrupt; hk has no softirq
/// context: its bottom halves run in threads). Host unit tests run in
/// none.
pub fn in_interrupt() -> bool {
    #[cfg(not(test))]
    {
        use crate::arch::{CurrentArch, PerCpuOps};
        CurrentArch::interrupt_depth() != 0
    }
    #[cfg(test)]
    false
}

/// Spin lock held, interrupts off or in an interrupt handler: this
/// context must not sleep (Linux preempt_count() != 0 || irqs_disabled())
pub fn in_atomic() -> bool {
    use crate::arch::{CurrentArch, PerCpuOps};
    crate::arch::preempt_count() != 0 || irqs_disabled() || CurrentArch::interrupt_depth() != 0
}

/// A page allocation of 2^`order` pages whose GFP may sleep (direct
/// reclaim): in atomic context it is a bug (Linux prepare_alloc_pages
/// -> might_alloc -> might_sleep_if). Reported once per call site (up
/// to 16) as `MIGHT_ALLOC:FAIL` with the caller and this CPU's stack, in
/// every build; the allocation goes on without reclaim. Exempt as
/// `lockdep::might_alloc`: interrupt handlers, reclaim, tasks that
/// cannot sleep, outside Scheduling and Running.
#[track_caller]
#[inline]
pub fn might_alloc_pages(order: u32) {
    #[cfg(not(test))]
    if in_atomic()
        && !in_interrupt()
        && crate::cpu::try_this_id().is_some()
        && crate::system_state::checks_apply()
        && sched::can_sleep()
        && !crate::task::percpu::current().has_flag(crate::task::pf::MEMALLOC)
    {
        alloc_pages_fail(order, core::panic::Location::caller());
    }
    #[cfg(test)]
    let _ = order;
}

#[cfg(not(test))]
#[cold]
#[inline(never)]
fn alloc_pages_fail(order: u32, at: &'static core::panic::Location<'static>) {
    use crate::arch::{CurrentArch, HaltOps};
    use core::sync::atomic::{AtomicPtr, Ordering};
    /// Call sites reported (each once; past the table, none more)
    static SEEN: [AtomicPtr<core::panic::Location<'static>>; 16] =
        [const { AtomicPtr::new(core::ptr::null_mut()) }; 16];
    let me = core::ptr::from_ref(at).cast_mut();
    let new = SEEN.iter().find_map(|s| {
        match s.compare_exchange(
            core::ptr::null_mut(),
            me,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => Some(true),
            Err(p) if p == me => Some(false),
            Err(_) => None,
        }
    });
    if new != Some(true) {
        return;
    }
    crate::printkln!(
        "MIGHT_ALLOC:FAIL page allocation of order {} with a GFP that may sleep \
         in atomic context at {} (preempt count {}, irqs off {}, tid {})",
        order,
        at,
        crate::arch::preempt_count(),
        irqs_disabled(),
        crate::task::percpu::current_tid()
    );
    CurrentArch::dump_stack();
}

/// A heap allocation made in atomic context with no GFP named
/// (`lockdep::might_alloc` without the feature): `MIGHT_ALLOC:FAIL`, the
/// context and this CPU's stack (Linux __might_resched's report and
/// dump_stack). The first `REPORTS` of a boot (no call site to tell
/// them apart without lockdep; one fix need not hide the next), counted
/// before printing (printing may allocate)
#[cfg(not(any(feature = "lockdep", test)))]
#[cold]
#[inline(never)]
pub fn might_alloc_fail(size: usize, align: usize) {
    use crate::arch::{CurrentArch, HaltOps};
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    const REPORTS: u32 = 8;
    static REPORTED: AtomicU32 = AtomicU32::new(0);
    /// A report in progress: one the printing makes is not reported
    static BUSY: AtomicBool = AtomicBool::new(false);
    if BUSY.swap(true, Ordering::Acquire) {
        return;
    }
    if REPORTED.fetch_add(1, Ordering::Relaxed) >= REPORTS {
        BUSY.store(false, Ordering::Release);
        return;
    }
    crate::printkln!(
        "MIGHT_ALLOC:FAIL heap allocation of {} (align {}) in atomic context \
         with no GFP named (preempt count {}, irqs off {}, tid {})",
        size,
        align,
        crate::arch::preempt_count(),
        irqs_disabled(),
        crate::task::percpu::current_tid()
    );
    CurrentArch::dump_stack();
    BUSY.store(false, Ordering::Release);
}

#[cfg(not(any(feature = "lockdep", test)))]
#[cold]
fn atomic_sleep(at: &'static core::panic::Location<'static>) {
    use crate::arch::{CurrentArch, PerCpuOps};
    use core::sync::atomic::{AtomicBool, Ordering};
    static REPORTED: AtomicBool = AtomicBool::new(false);
    if REPORTED.swap(true, Ordering::Relaxed) {
        return;
    }
    crate::printkln!(
        "MIGHT_SLEEP:FAIL sleeping function called from invalid context at {} \
         (preempt count {}, irqs off {}, irq depth {}, tid {})",
        at,
        crate::arch::preempt_count(),
        irqs_disabled(),
        CurrentArch::interrupt_depth(),
        crate::task::percpu::current_tid()
    );
}

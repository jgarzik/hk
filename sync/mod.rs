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
mod racy;
pub mod rcu;
mod rwsem;
mod seqlock;
pub mod spin;

pub use irqflags::{IrqFlags, irqs_disabled, local_irq_restore, local_irq_save};
pub use irqspin::{IrqSpinlock, IrqSpinlockGuard};
pub use locked_by::{LockedBy, LockedByEither, UniqueOwner};
pub use mutex::{Mutex, MutexGuard};
pub use racy::RacyCell;
pub use rwsem::{RwSem, RwSemReadGuard, RwSemWriteGuard};
pub use seqlock::{SeqCount, SeqCountGuard, SeqRwLock, SeqRwWriteGuard};

/// What the sleeping locks take from the scheduler
#[cfg(not(test))]
mod sched {
    pub use crate::sync::waitqueue::signal_pending_state;
    use crate::task::Task;
    pub use crate::task::percpu::{TaskRef, current_tid, get_ticks, schedule, set_current_state};
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
    // Host unit tests have no CPU state to check
    #[cfg(not(any(feature = "lockdep", test)))]
    if sched::can_sleep() && crate::system_state::checks_apply() && in_atomic() {
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

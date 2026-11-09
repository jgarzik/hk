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
mod rwsem;
mod seqlock;
pub mod spin;

pub use irqflags::{IrqFlags, irqs_disabled, local_irq_restore, local_irq_save};
pub use irqspin::{IrqSpinlock, IrqSpinlockGuard};
pub use locked_by::{LockedBy, UniqueOwner};
pub use mutex::{Mutex, MutexGuard};
pub use racy::RacyCell;
pub use rwsem::{RwSem, RwSemReadGuard, RwSemWriteGuard};
pub use seqlock::{SeqLock, SeqWriteGuard};

/// The caller is a task that may sleep (not tid 0: an idle task or the
/// boot context, which never contend for a sleeping lock)
#[cfg(not(test))]
fn can_sleep() -> bool {
    crate::task::percpu::can_sleep()
}

/// Host unit tests have no tasks: a contended sleeping lock spins
#[cfg(test)]
fn can_sleep() -> bool {
    false
}

/// The current task, queued as a sleeping lock's waiter
#[cfg(not(test))]
fn waiter_task() -> *const crate::task::Task {
    &raw const *crate::task::percpu::current()
}

/// Host unit tests have no tasks (their waiters are never woken)
#[cfg(test)]
fn waiter_task() -> *const crate::task::Task {
    core::ptr::null()
}

/// Wake a sleeping lock's waiter (Linux wake_up_process)
///
/// # Safety
/// `t` is a `waiter_task()` whose waiter stays queued, or is granted
/// the lock but cannot see it, until this returns (the caller holds the
/// lock's wait lock), so the task cannot exit meanwhile.
#[cfg(not(test))]
unsafe fn wake_waiter(t: *const crate::task::Task) {
    use crate::task::percpu::{WakeMode, try_to_wake_up};
    // SAFETY: live until this returns (the caller)
    try_to_wake_up(unsafe { &*t }, WakeMode::Any);
}

/// Host unit tests: nobody to wake
#[cfg(test)]
unsafe fn wake_waiter(_: *const crate::task::Task) {}

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
    #[cfg(not(feature = "lockdep"))]
    if can_sleep() && in_atomic() {
        atomic_sleep(core::panic::Location::caller());
    }
}

/// Spin lock held, interrupts off or in an interrupt handler: this
/// context must not sleep (Linux preempt_count() != 0 || irqs_disabled())
pub fn in_atomic() -> bool {
    use crate::arch::{CurrentArch, PerCpuOps};
    crate::arch::preempt_count() != 0 || irqs_disabled() || CurrentArch::interrupt_depth() != 0
}

#[cfg(not(feature = "lockdep"))]
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

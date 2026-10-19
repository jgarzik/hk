//! Sleeping locks (Linux kernel/locking): `Mutex` (struct mutex) and
//! `RwSem` (struct rw_semaphore)
//!
//! A contended lock sleeps on a wait queue instead of spinning, so a
//! holder may block (page locks, block I/O, user page faults). Rules:
//! thread context only, never taken in IRQ context or while holding a
//! spinlock (`might_sleep` checks the preempt count, which every spin
//! lock raises); sleeping locks order above every spinlock. Before
//! scheduling is enabled (early boot) a contended lock spins.

pub mod lockdep;
mod mutex;
mod rwsem;
pub mod spin;

pub use mutex::{Mutex, MutexGuard};
pub use rwsem::{RwSem, RwSemReadGuard, RwSemWriteGuard};

use core::sync::atomic::Ordering;

use crate::task::percpu::SCHEDULING_ENABLED;

/// True once tasks can sleep
fn can_sleep() -> bool {
    SCHEDULING_ENABLED.load(Ordering::Acquire)
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
    #[cfg(not(feature = "lockdep"))]
    if can_sleep() && in_atomic() {
        atomic_sleep(core::panic::Location::caller());
    }
}

/// Spin lock held, interrupts off or in an interrupt handler: this
/// context must not sleep (Linux preempt_count() != 0 || irqs_disabled())
pub fn in_atomic() -> bool {
    use crate::arch::{CurrentArch, PerCpuOps};
    crate::arch::preempt_count() != 0
        || crate::arch::irqs_disabled()
        || CurrentArch::interrupt_depth() != 0
}

#[cfg(not(feature = "lockdep"))]
#[cold]
fn atomic_sleep(at: &'static core::panic::Location<'static>) {
    use crate::arch::{CurrentArch, PerCpuOps};
    use core::sync::atomic::AtomicBool;
    static REPORTED: AtomicBool = AtomicBool::new(false);
    if REPORTED.swap(true, Ordering::Relaxed) {
        return;
    }
    crate::printkln!(
        "MIGHT_SLEEP:FAIL sleeping function called from invalid context at {} \
         (preempt count {}, irqs off {}, irq depth {}, tid {})",
        at,
        crate::arch::preempt_count(),
        crate::arch::irqs_disabled(),
        CurrentArch::interrupt_depth(),
        crate::task::percpu::current_tid()
    );
}

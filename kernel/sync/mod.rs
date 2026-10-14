//! Sleeping locks (Linux kernel/locking): `Mutex` (struct mutex) and
//! `RwSem` (struct rw_semaphore)
//!
//! A contended lock sleeps on a wait queue instead of spinning, so a
//! holder may block (page locks, block I/O, user page faults). Rules:
//! thread context only, never taken in IRQ context or while holding a
//! spinlock (`might_sleep` checks the preempt count in debug builds);
//! sleeping locks order above every spinlock. Before scheduling is
//! enabled (early boot) a contended lock spins.

mod mutex;
mod rwsem;

pub use mutex::{Mutex, MutexGuard};
pub use rwsem::RwSem;

use core::sync::atomic::Ordering;

use crate::task::percpu::SCHEDULING_ENABLED;

/// True once tasks can sleep
fn can_sleep() -> bool {
    SCHEDULING_ENABLED.load(Ordering::Acquire)
}

/// Linux might_sleep: no spinlock (IrqSpinlock raises the preempt
/// count) may be held where a sleeping lock is taken
fn might_sleep() {
    debug_assert!(
        !can_sleep() || crate::arch::preempt_count() == 0,
        "sleeping lock taken in atomic context"
    );
}

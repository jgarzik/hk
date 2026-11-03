//! Completions (Linux include/linux/completion.h, kernel/sched/completion.c)
//!
//! A one-shot (or counted) event: `wait` sleeps until another context
//! calls `complete`. Typical use: a thread submits I/O and waits; the
//! driver's interrupt handler completes it.
//!
//! ## Locking
//!
//! `done` is an `IrqSpinlock` (Linux `wait.lock`), so `complete` is safe
//! in hardirq context. The waker increments `done` and issues the wakeup
//! under it; a waiter only sees `done` change under the same lock, after
//! the waker has released it. So once `wait` returns, the waker no longer
//! touches the completion and it may live on the waiter's stack.
//! Order: `done` -> wait queue head -> run-queue lock (the wake path).

use crate::arch::IrqSpinlock;
use crate::waitqueue::WaitQueue;

/// `complete_all` marks the completion done for every present and
/// future waiter (Linux UINT_MAX)
const ALL: u32 = u32::MAX;

pub struct Completion {
    done: IrqSpinlock<u32>,
    wait: WaitQueue,
}

impl Completion {
    pub const fn new() -> Self {
        Self {
            done: IrqSpinlock::new(0),
            wait: WaitQueue::new(),
        }
    }

    /// Signal one waiter (any context, including IRQ handlers)
    pub fn complete(&self) {
        let mut d = self.done.lock();
        if *d != ALL {
            *d += 1;
        }
        self.wait.wake_one();
    }

    /// Signal every waiter, now and later
    pub fn complete_all(&self) {
        let mut d = self.done.lock();
        *d = ALL;
        self.wait.wake_all();
    }

    /// Consume one completion if there is one (Linux try_wait_for_completion)
    pub fn try_wait(&self) -> bool {
        let mut d = self.done.lock();
        if *d == 0 {
            return false;
        }
        if *d != ALL {
            *d -= 1;
        }
        true
    }

    /// True if `wait` would not sleep (Linux completion_done)
    pub fn is_done(&self) -> bool {
        *self.done.lock() != 0
    }

    /// Sleep (uninterruptibly) until completed, then consume it (thread
    /// context, no spinlock held)
    pub fn wait(&self) {
        self.wait.wait_event_exclusive(|| self.try_wait());
    }
}

impl Default for Completion {
    fn default() -> Self {
        Self::new()
    }
}

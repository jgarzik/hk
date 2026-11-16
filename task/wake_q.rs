//! Deferred wakeups (Linux wake_q, kernel/sched/core.c wake_q_add and
//! wake_up_q)
//!
//! A lock's waker queues the tasks to wake while it holds the lock's
//! wait lock and wakes them after dropping it, so the wakeups (pi_lock,
//! run-queue locks, IPIs) stay out of the wait lock. Each queued task
//! is pinned by a reference taken before the waiter can see its grant,
//! so the waiter may leave (its on-stack waiter node gone) and even exit
//! before the wakeup. The queue links through the tasks' own `wake_q`
//! field: nothing allocates, and a task is on at most one queue. A task
//! already on another queue is not added again: that queue's wakeup
//! comes after the caller's store (both sides have full barriers), so
//! the task sees it.

use alloc::sync::Arc;
use core::marker::PhantomData;
use core::sync::atomic::{Ordering, fence};

use super::Task;
use super::percpu::{TaskRef, WakeMode, try_to_wake_up};

/// `Task.wake_q` of the last task queued (Linux WAKE_Q_TAIL): non-null,
/// never a task's address
const TAIL: *mut Task = core::ptr::dangling_mut();

/// Tasks to wake, each holding a reference (Linux struct wake_q_head);
/// lives on the waker's stack. Dropping it wakes them.
#[must_use]
pub struct WakeQ {
    /// First queued task (null: empty)
    first: *const Task,
    /// Last queued task (null: empty)
    last: *const Task,
    /// Woken by the task that queued them
    _not_send: PhantomData<*const ()>,
}

impl WakeQ {
    pub const fn new() -> Self {
        Self {
            first: core::ptr::null(),
            last: core::ptr::null(),
            _not_send: PhantomData,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.first.is_null()
    }

    /// Queue `t`, whose reference the caller took before making the
    /// condition it waits for true (Linux wake_q_add_safe); if it is
    /// already on a queue, that one wakes it and the reference goes
    pub fn add_safe(&mut self, t: TaskRef) {
        // Order the caller's condition store before the claim: a failed
        // claim leaves the wakeup to the other queue, which is issued
        // after it (Linux smp_mb__before_atomic)
        fence(Ordering::SeqCst);
        if t.wake_q
            .compare_exchange(
                core::ptr::null_mut(),
                TAIL,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_err()
        {
            return;
        }
        let p = Arc::into_raw(t);
        // SAFETY: `last` is a task this queue holds a reference to
        match unsafe { self.last.as_ref() } {
            Some(l) => l.wake_q.store(p.cast_mut(), Ordering::Relaxed),
            None => self.first = p,
        }
        self.last = p;
    }

    /// Wake every queued task and drop its reference (Linux wake_up_q);
    /// the queue is empty again
    pub fn wake(&mut self) {
        let mut p = core::mem::replace(&mut self.first, core::ptr::null());
        self.last = core::ptr::null();
        while !p.is_null() && p != TAIL.cast_const() {
            // SAFETY: `add_safe` turned this reference into `p`
            let t = unsafe { Arc::from_raw(p) };
            p = t.wake_q.load(Ordering::Relaxed);
            // Another waker may queue it again from here on
            t.wake_q.store(core::ptr::null_mut(), Ordering::Relaxed);
            // Full barrier (pi_lock and its fence) pairs with a failed
            // claim in `add_safe`
            try_to_wake_up(&t, WakeMode::Any);
        }
    }
}

impl Drop for WakeQ {
    fn drop(&mut self) {
        self.wake();
    }
}

//! Per-CPU reference counts with a kill (Linux lib/percpu-refcount.c)
//!
//! A [`PercpuRef`] counts the users of an object that its owner can
//! shut down: while live, [`PercpuRef::tryget_live`] adds one to the
//! calling CPU's part and [`PercpuRef::put`] takes one from its own
//! part, lock-free. [`PercpuRef::kill`] marks it dead, so later trygets
//! fail, and waits out a grace period: every tryget that saw it live
//! has added by then (Linux percpu_ref_kill, whose switch to atomic
//! mode waits for one). From then on no add happens, every part only
//! shrinks, and a sum of zero is final. [`PercpuRef::wait`] sleeps
//! until it is (Linux percpu_ref_kill's release callback completing
//! the owner's wait, or wait_event on percpu_ref_is_zero), so the owner
//! tears the object down in its own sleepable context afterwards, never
//! in a user's put.
//!
//! A tryget and a put run under an RCU read guard; a put that sees the
//! count dead wakes the waiter from inside it, and the wait ends with a
//! grace period, so no put still touches the object once `wait`
//! returns.
//!
//! Locking: none of its own beyond the wait queue head (an IrqSpinlock
//! leaf); a tryget or put is safe under any lock, in thread context.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::sync::rcu;
use crate::sync::waitqueue::WaitQueue;
use crate::util::error::KernelError;
use crate::util::percpu_alloc::PcpSlot;

/// Users of an object its owner can kill (Linux struct percpu_ref)
pub struct PercpuRef {
    /// References, summed over every CPU's part
    count: PcpSlot,
    /// No new reference (Linux __PERCPU_REF_DEAD)
    dead: AtomicBool,
    /// The owner waiting for the last put
    drained: WaitQueue,
}

impl PercpuRef {
    /// A live count with no reference (Linux percpu_ref_init); ENOMEM
    pub fn new() -> Result<Self, KernelError> {
        Ok(Self {
            count: PcpSlot::new()?,
            dead: AtomicBool::new(false),
            drained: WaitQueue::new(),
        })
    }

    /// Take a reference unless killed (Linux percpu_ref_tryget_live)
    pub fn tryget_live(&self) -> bool {
        let _g = rcu::read_lock();
        // Killed: refused. Else counted before `kill`'s grace period ends
        if self.dead.load(Ordering::Acquire) {
            return false;
        }
        self.count.add(1);
        true
    }

    /// Give a reference back (Linux percpu_ref_put)
    pub fn put(&self) {
        let _g = rcu::read_lock();
        self.count.add(-1);
        // Under the guard: `wait` ends with a grace period, so the
        // object outlives this wake
        if self.dead.load(Ordering::Acquire) {
            self.drained.wake_all();
        }
    }

    /// Refuse new references and wait until every tryget that saw the
    /// count live has added (Linux percpu_ref_kill, then
    /// synchronize_rcu). Sleeps; no spinlock held.
    pub fn kill(&self) {
        self.dead.store(true, Ordering::Release);
        rcu::synchronize();
    }

    /// No reference is left (Linux percpu_ref_is_zero): final once
    /// killed
    pub fn is_zero(&self) -> bool {
        self.dead.load(Ordering::Acquire) && self.count.sum() == 0
    }

    /// Sleep (uninterruptibly) until the last reference of a killed
    /// count is put, and that put has left the count (Linux
    /// wait_for_completion on the release callback's completion)
    pub fn wait(&self) {
        debug_assert!(
            self.dead.load(Ordering::Relaxed),
            "percpu_ref: wait before kill"
        );
        self.drained.wait_event(|| self.is_zero());
        rcu::synchronize();
    }
}

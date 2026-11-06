//! Fault injection (Linux lib/fault-inject.c, the fail_nth interface of
//! Documentation/fault-injection/fault-injection.rst): writing N to
//! /proc/thread-self/fail-nth makes this task's Nth fallible
//! allocation from then on fail, once. A test loops N = 1, 2, ... over a
//! syscall until fail-nth reads back nonzero (it finished without
//! reaching an Nth allocation), so every ENOMEM path of it runs.
//!
//! The fallible allocation paths ask [`should_fail`]: `kalloc::try_box`,
//! `try_arc`, `try_arc_cyclic` and `kmem`'s growth. The `*_nofail`
//! forms never fail (Linux __GFP_NOFAIL).

use core::sync::atomic::Ordering::Relaxed;

/// This allocation should fail: the task's countdown reached it
pub fn should_fail() -> bool {
    if cfg!(test) {
        return false;
    }
    let t = crate::task::percpu::current();
    let n = t.fail_nth.load(Relaxed);
    if n == 0 {
        return false;
    }
    t.fail_nth.store(n - 1, Relaxed);
    n == 1
}

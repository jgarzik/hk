//! Fault injection (Linux lib/fault-inject.c, mm/failslab.c,
//! mm/fail_page_alloc.c; Documentation/fault-injection/): writing N to
//! /proc/thread-self/fail-nth makes the task's Nth call of an injection
//! point from then on fail, once (`should_fail_ex`, task context only).
//! A test loops N = 1, 2, ... over a syscall until fail-nth reads back
//! nonzero (it finished without reaching an Nth call), so every ENOMEM
//! path of it runs.
//!
//! The injection points are Linux's two allocation ones:
//! - failslab ([`should_failslab`]): the heap's fallible allocations
//!   (`kalloc::try_box`, `try_arc`, `try_arc_cyclic`, `kmem`'s growth;
//!   Linux slab_pre_alloc_hook). The `*_nofail` forms never get there
//!   (Linux __GFP_NOFAIL).
//! - fail_page_alloc ([`should_fail_alloc_page`]): the page allocator
//!   (Linux prepare_alloc_pages), coherent DMA memory included (Linux
//!   dma-direct allocates pages).
//!
//! Each skips what Linux's skips by default: an allocation that may
//! sleep (`Gfp::RECLAIM`: ignore-gfp-wait Y), and for pages one below
//! min-order 1 or of user data (`Gfp::HIGHMEM`: ignore-gfp-highmem Y).
//! The knobs are debugfs files (`init_debugfs`): failslab/ignore-gfp-wait,
//! fail_page_alloc/{ignore-gfp-wait,ignore-gfp-highmem,min-order}.
//!
//! ## Locking
//!
//! The knobs are atomics read lock-free on every allocation (Linux plain
//! bools read without a lock); the countdown is the task's own.

use core::sync::atomic::Ordering::Relaxed;
use core::sync::atomic::{AtomicBool, AtomicU32};

use crate::mm::page_alloc::Gfp;

/// Linux failslab's knobs
struct FailSlab {
    ignore_gfp_reclaim: AtomicBool,
}

static FAILSLAB: FailSlab = FailSlab {
    ignore_gfp_reclaim: AtomicBool::new(true),
};

/// Linux fail_page_alloc's knobs
struct FailPageAlloc {
    ignore_gfp_highmem: AtomicBool,
    ignore_gfp_reclaim: AtomicBool,
    min_order: AtomicU32,
}

static FAIL_PAGE_ALLOC: FailPageAlloc = FailPageAlloc {
    ignore_gfp_highmem: AtomicBool::new(true),
    ignore_gfp_reclaim: AtomicBool::new(true),
    min_order: AtomicU32::new(1),
};

/// Linux should_fail_ex's fail-nth part: in task context, the task's
/// countdown, the call that takes it to 0 failing. hk has no
/// probability, interval, times or space knobs (each 0 or unset in
/// Linux's default attr), so nothing else fails.
fn should_fail_ex() -> bool {
    if cfg!(test) || crate::cpu::try_this_id().is_none() || crate::sync::in_interrupt() {
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

/// A heap allocation should fail (Linux should_failslab): not one that
/// may sleep unless failslab/ignore-gfp-wait is N. Its GFP is the
/// heap's for this context (a named one, GFP_ATOMIC in an interrupt
/// handler, else GFP_KERNEL).
pub fn should_failslab() -> bool {
    let gfp = crate::mm::slab::heap_gfp();
    if gfp.has(Gfp::NOFAIL) {
        return false;
    }
    if FAILSLAB.ignore_gfp_reclaim.load(Relaxed) && gfp.has(Gfp::RECLAIM) {
        return false;
    }
    should_fail_ex()
}

/// A page allocation of 2^`order` pages with `gfp` should fail (Linux
/// should_fail_alloc_page)
pub fn should_fail_alloc_page(gfp: Gfp, order: u32) -> bool {
    let f = &FAIL_PAGE_ALLOC;
    if order < f.min_order.load(Relaxed) {
        return false;
    }
    if gfp.has(Gfp::NOFAIL) {
        return false;
    }
    if f.ignore_gfp_highmem.load(Relaxed) && gfp.has(Gfp::HIGHMEM) {
        return false;
    }
    if f.ignore_gfp_reclaim.load(Relaxed) && gfp.has(Gfp::RECLAIM) {
        return false;
    }
    should_fail_ex()
}

/// The knobs' debugfs files, 0600 (Linux failslab_debugfs_init and
/// fail_page_alloc_debugfs, late initcalls; fault_create_debugfs_attr's
/// generic files are not made: BUGS.md)
pub fn init_debugfs() {
    use crate::fs::debugfs::{create_bool, create_dir, create_u32};
    const MODE: u16 = 0o600;
    if let Ok(d) = create_dir(b"failslab", None) {
        let _ = create_bool(
            b"ignore-gfp-wait",
            MODE,
            Some(&d),
            &FAILSLAB.ignore_gfp_reclaim,
        );
    }
    let f = &FAIL_PAGE_ALLOC;
    if let Ok(d) = create_dir(b"fail_page_alloc", None) {
        let _ = create_bool(b"ignore-gfp-wait", MODE, Some(&d), &f.ignore_gfp_reclaim);
        let _ = create_bool(b"ignore-gfp-highmem", MODE, Some(&d), &f.ignore_gfp_highmem);
        let _ = create_u32(b"min-order", MODE, Some(&d), &f.min_order);
    }
}

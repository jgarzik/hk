//! Soft lockup detector (Linux kernel/watchdog.c, softlockup part)
//!
//! Every `watchdog_thresh * 2 / 5` seconds each CPU's tick queues a
//! touch on its stopper (`migration/N`, the highest priority): it runs
//! only once the CPU reaches a scheduling point. A touch older than
//! `2 * watchdog_thresh` seconds means the CPU ran kernel code that long
//! without scheduling (a task in user mode is preempted at its return):
//! reported once per stall as `BUG: soft lockup`. `watchdog_thresh=N`
//! on the command line sets it (Linux default 10; 0 turns it off).
//!
//! Locking: per-CPU atomics, written by that CPU's tick (interrupt
//! context) and its stopper.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::cpu::PerCpu;

/// Seconds (Linux watchdog_thresh)
static THRESH: AtomicU32 = AtomicU32::new(10);

/// One CPU's detector state
struct Cpu {
    /// Last time its stopper ran a touch (ns, monotonic; 0: not yet)
    touched: AtomicU64,
    /// Last time its tick queued one
    kicked: AtomicU64,
    /// This stall was reported
    reported: AtomicBool,
}

static CPUS: PerCpu<Cpu> = crate::percpu![Cpu {
    touched: AtomicU64::new(0),
    kicked: AtomicU64::new(0),
    reported: AtomicBool::new(false),
}];

/// `watchdog_thresh=` (Linux: 0..=60 seconds)
pub fn set_thresh(s: u32) {
    THRESH.store(s.min(60), Ordering::Relaxed);
}

/// On the stopper: the CPU scheduled (Linux softlockup_fn)
fn touch(cpu: usize) {
    let c = CPUS.get(cpu as u32);
    c.touched
        .store(crate::time::monotonic_ns(), Ordering::Relaxed);
    c.reported.store(false, Ordering::Relaxed);
}

/// From this CPU's tick (interrupt context; Linux
/// watchdog_timer_fn)
pub fn tick() {
    let thresh = THRESH.load(Ordering::Relaxed) as u64 * 1_000_000_000;
    let Some(cpu) = crate::cpu::try_this_id() else {
        return;
    };
    if thresh == 0 || !crate::time::TIMEKEEPER.is_initialized() {
        return;
    }
    let c = CPUS.get(cpu);
    let now = crate::time::monotonic_ns();
    if now.saturating_sub(c.kicked.load(Ordering::Relaxed)) >= thresh * 2 / 5
        && crate::task::stop_machine::stop_one_cpu_nowait(cpu, touch, cpu as usize)
    {
        c.kicked.store(now, Ordering::Relaxed);
        if c.touched.load(Ordering::Relaxed) == 0 {
            c.touched.store(now, Ordering::Relaxed);
        }
    }
    let touched = c.touched.load(Ordering::Relaxed);
    let stuck = now.saturating_sub(touched);
    if touched != 0 && stuck > 2 * thresh && !c.reported.swap(true, Ordering::Relaxed) {
        let me = crate::task::percpu::current();
        crate::printkln!(
            "BUG: soft lockup - CPU#{} stuck for {}s! [tid {}{}]",
            cpu,
            stuck / 1_000_000_000,
            me.tid(),
            if me.has_flag(crate::task::pf::KTHREAD) {
                ", kernel thread"
            } else {
                ""
            }
        );
    }
}

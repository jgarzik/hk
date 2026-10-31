//! Load average (Linux kernel/sched/loadavg.c)
//!
//! Every LOAD_FREQ (5 s + 1 tick) CPU 0's tick folds the number of
//! active tasks, the runnable ones (`nr_running` of every run queue) and
//! those in uninterruptible or killable sleep (`nr_uninterruptible`),
//! into three exponentially decaying averages, 11-bit fixed point
//! (`avenrun`): the 1, 5 and 15 minute loads of /proc/loadavg and
//! sysinfo.
//!
//! Locking: atomics; written by CPU 0's tick only.

use core::sync::atomic::{AtomicU64, Ordering};

/// Bits of fraction (Linux FSHIFT)
pub const FSHIFT: u32 = 11;
/// 1.0 (Linux FIXED_1)
const FIXED_1: u64 = 1 << FSHIFT;
/// 1/exp(5s/1min), 1/exp(5s/5min), 1/exp(5s/15min) (Linux EXP_1/5/15)
const EXP: [u64; 3] = [1884, 2014, 2037];
/// Ticks between samples (Linux LOAD_FREQ: 5 * HZ + 1)
const LOAD_FREQ: u64 = 5 * (1000 / super::percpu::TICK_MS) + 1;

static AVENRUN: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];

/// One decay step (Linux calc_load)
fn calc_load(load: u64, exp: u64, active: u64) -> u64 {
    let mut new = load * exp + active * (FIXED_1 - exp);
    if active >= load {
        new += FIXED_1 - 1;
    }
    new / FIXED_1
}

/// From CPU 0's tick with the tick count (Linux calc_global_load)
pub fn tick(ticks: u64) {
    if !ticks.is_multiple_of(LOAD_FREQ) {
        return;
    }
    let active = super::percpu::nr_active() * FIXED_1;
    for (avg, exp) in AVENRUN.iter().zip(EXP) {
        avg.store(
            calc_load(avg.load(Ordering::Relaxed), exp, active),
            Ordering::Relaxed,
        );
    }
}

/// The 1, 5 and 15 minute averages, FSHIFT fixed point (Linux avenrun)
pub fn avenrun() -> [u64; 3] {
    [0, 1, 2].map(|i| AVENRUN[i].load(Ordering::Relaxed))
}

/// The last pid handed out in the reader's pid namespace (Linux
/// idr_get_cursor(&task_active_pid_ns(current)->idr) - 1): a reader in
/// a child namespace learns nothing of its parent's
fn last_pid() -> u32 {
    let tid = super::percpu::current_tid();
    let table = super::percpu::TASKLIST.read();
    table
        .get(tid)
        .and_then(|t| t.thread_pid.as_ref().map(|p| p.ns().map.last()))
        .unwrap_or_else(|| crate::ns::INIT_PID_NS.map.last())
}

/// /proc/loadavg (Linux loadavg_proc_show): the three loads with two
/// decimals, runnable/total tasks, the last pid handed out
pub fn proc_loadavg() -> alloc::vec::Vec<u8> {
    let part = |a: u64| (a >> FSHIFT, ((a & (FIXED_1 - 1)) * 100) >> FSHIFT);
    let [a, b, c] = avenrun().map(part);
    alloc::format!(
        "{}.{:02} {}.{:02} {}.{:02} {}/{} {}\n",
        a.0,
        a.1,
        b.0,
        b.1,
        c.0,
        c.1,
        super::percpu::nr_running_all(),
        super::percpu::task_count(),
        last_pid()
    )
    .into_bytes()
}

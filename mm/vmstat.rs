//! Page-state counters (Linux mm/vmstat.c): a global count plus a
//! difference per CPU, folded into the global once it passes a
//! threshold. An update touches only its CPU's word (interrupts off, a
//! load and a store) and the shared line once per threshold changes;
//! a read is one load of the global, off by at most the threshold per
//! CPU (Linux global_node_page_state).

use core::sync::atomic::{AtomicI64, Ordering};

use crate::cpu::PerCpu;

/// A counter (Linux one item of vm_node_stat with its vm_node_stat_diff)
pub struct VmStat {
    /// The folded count (Linux vm_node_stat[item])
    global: AtomicI64,
    /// Each CPU's unfolded part (Linux pcp->vm_node_stat_diff[item]):
    /// written by its CPU alone, interrupts off
    diff: &'static PerCpu<AtomicI64>,
}

impl VmStat {
    pub const fn new(diff: &'static PerCpu<AtomicI64>) -> Self {
        Self {
            global: AtomicI64::new(0),
            diff,
        }
    }

    /// Add `d` (Linux mod_node_page_state)
    pub fn add(&self, d: i64) {
        let irq = crate::sync::local_irq_save();
        let w = self.diff.this();
        let v = w.load(Ordering::Relaxed) + d;
        if v.abs() > threshold() {
            self.global.fetch_add(v, Ordering::Relaxed);
            w.store(0, Ordering::Relaxed);
        } else {
            w.store(v, Ordering::Relaxed);
        }
        crate::sync::local_irq_restore(irq);
    }

    /// The count, unfolded parts left out, never below 0 (Linux
    /// global_node_page_state)
    pub fn read(&self) -> u64 {
        self.global.load(Ordering::Relaxed).max(0) as u64
    }
}

/// A CPU's part folds past this (Linux calculate_normal_threshold:
/// 2 * fls(CPUs) * (1 + fls(memory in 128 MiB units)), at most 125),
/// fixed once the CPUs and memory are known
fn threshold() -> i64 {
    static T: spin::Once<i64> = spin::Once::new();
    *T.call_once(|| {
        let cpus = u64::from(crate::cpu::nr_possible());
        let mem = crate::FRAME_ALLOCATOR.stats().total_bytes >> 27;
        calc_threshold(cpus, mem)
    })
}

fn fls(v: u64) -> i64 {
    i64::from(u64::BITS - v.leading_zeros())
}

fn calc_threshold(cpus: u64, mem_128m: u64) -> i64 {
    (2 * fls(cpus) * (1 + fls(mem_128m))).min(125)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_as_linux() {
        // 4 CPUs, 2 GiB: 2 * 3 * (1 + 5) = 36
        assert_eq!(calc_threshold(4, 16), 36);
        // 1 CPU, 64 MiB: 2 * 1 * (1 + 0) = 2
        assert_eq!(calc_threshold(1, 0), 2);
        // Many CPUs and much memory: capped
        assert_eq!(calc_threshold(512, 4096), 125);
    }
}

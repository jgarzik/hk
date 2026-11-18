//! Page-state counters (Linux mm/vmstat.c, node_stat_item): a global
//! count per item plus a difference per CPU, folded into the global once
//! it passes a threshold, and every second by its CPU's tick (Linux
//! vmstat_update every sysctl_stat_interval). An update touches only its
//! CPU's word (interrupts off, a load and a store) and the shared line
//! once per threshold changes; a read is one load of the global, off by
//! at most the threshold per CPU for at most a second (Linux
//! global_node_page_state).

use core::sync::atomic::{AtomicI64, AtomicU32, Ordering};

/// A counter (Linux enum node_stat_item)
#[derive(Clone, Copy)]
pub enum Item {
    /// Page-cache pages (NR_FILE_PAGES)
    FilePages,
    /// Dirty page-cache pages (NR_FILE_DIRTY)
    FileDirty,
    /// Pages of unevictable mappings (NR_UNEVICTABLE)
    Unevictable,
    /// tmpfs and shared memory pages (NR_SHMEM)
    Shmem,
}

const N: usize = 4;

/// The folded counts (Linux vm_node_stat)
static GLOBAL: [AtomicI64; N] = [const { AtomicI64::new(0) }; N];

/// A CPU's unfolded parts and tick count: written by its CPU alone,
/// interrupts off (Linux per_cpu_nodestat.vm_node_stat_diff)
struct Diff {
    d: [AtomicI64; N],
    ticks: AtomicU32,
}

crate::percpu! {
    static DIFF: Diff = Diff {
        d: [const { AtomicI64::new(0) }; N],
        ticks: AtomicU32::new(0),
    };
}

/// Add `v` to `item` (Linux mod_node_page_state)
pub fn add(item: Item, v: i64) {
    let irq = crate::sync::local_irq_save();
    let w = &DIFF.this().d[item as usize];
    let x = w.load(Ordering::Relaxed) + v;
    if x.abs() > threshold() {
        GLOBAL[item as usize].fetch_add(x, Ordering::Relaxed);
        w.store(0, Ordering::Relaxed);
    } else {
        w.store(x, Ordering::Relaxed);
    }
    crate::sync::local_irq_restore(irq);
}

/// `item`, unfolded parts left out, never below 0 (Linux
/// global_node_page_state)
pub fn read(item: Item) -> u64 {
    GLOBAL[item as usize].load(Ordering::Relaxed).max(0) as u64
}

/// Ticks between folds: a second (Linux sysctl_stat_interval = HZ)
const FOLD_TICKS: u32 = 100;

/// This CPU's tick (interrupts off): every second, fold its parts into
/// the globals (Linux vmstat_update -> refresh_cpu_vm_stats)
pub fn tick() {
    let me = DIFF.this();
    let t = me.ticks.load(Ordering::Relaxed) + 1;
    if t < FOLD_TICKS {
        me.ticks.store(t, Ordering::Relaxed);
        return;
    }
    me.ticks.store(0, Ordering::Relaxed);
    for (w, g) in me.d.iter().zip(&GLOBAL) {
        let x = w.load(Ordering::Relaxed);
        if x != 0 {
            g.fetch_add(x, Ordering::Relaxed);
            w.store(0, Ordering::Relaxed);
        }
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

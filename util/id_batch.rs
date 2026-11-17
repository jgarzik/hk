//! Ids handed out in per-CPU batches (Linux get_next_ino, shmem's
//! ino_batch): each CPU takes `BATCH` numbers from a shared counter at
//! a time and gives them out one by one from its own word, so the
//! shared line is written once per batch instead of once per id. Ids
//! are unique, increasing per CPU, not across CPUs.

use core::sync::atomic::{AtomicIsize, AtomicU64, Ordering};

use crate::util::percpu_alloc::PcpSlot;

/// Numbers one CPU takes at a time (Linux LAST_INO_BATCH)
pub const BATCH: u64 = 1024;

/// A source of unique ids from 1 on, batched per CPU
pub struct IdBatch {
    /// The next batch's start
    shared: AtomicU64,
    /// Each CPU's last id handed out (0: take a new batch; Linux
    /// alloc_percpu(ino_t))
    last: PcpSlot,
}

impl IdBatch {
    /// Made where allocation cannot fail (a superblock)
    pub fn new() -> Self {
        Self {
            shared: AtomicU64::new(0),
            last: PcpSlot::new_nofail(),
        }
    }

    /// The next id (never 0)
    pub fn next(&self) -> u64 {
        next_from(&self.shared, |c| self.last.word(c), PcpSlot::nr_words())
    }
}

impl Default for IdBatch {
    fn default() -> Self {
        Self::new()
    }
}

/// The next id from `shared` through this CPU's word (`part`, among
/// `len` per-CPU words): a load and a store on its own word with
/// interrupts off (Linux get_cpu_var), the shared counter only to start
/// a batch; a CPU without its own word takes single ids from `shared`
pub fn next_from<'a>(
    shared: &AtomicU64,
    part: impl Fn(usize) -> Option<&'a AtomicIsize>,
    len: usize,
) -> u64 {
    let Some(w) = crate::cpu::own_slot(len).and_then(part) else {
        return shared.fetch_add(1, Ordering::Relaxed) + 1;
    };
    let irq = crate::sync::local_irq_save();
    let mut res = w.load(Ordering::Relaxed) as u64;
    if res.is_multiple_of(BATCH) {
        res = shared.fetch_add(BATCH, Ordering::Relaxed);
    }
    res += 1;
    w.store(res as isize, Ordering::Relaxed);
    crate::sync::local_irq_restore(irq);
    res
}

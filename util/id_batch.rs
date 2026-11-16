//! Ids handed out in per-CPU batches (Linux get_next_ino, shmem's
//! ino_batch): each CPU takes `BATCH` numbers from a shared counter at
//! a time and gives them out one by one from its own word, so the
//! shared line is written once per batch instead of once per id. Ids
//! are unique, increasing per CPU, not across CPUs.

use alloc::boxed::Box;
use core::sync::atomic::{AtomicU64, Ordering};

/// Numbers one CPU takes at a time (Linux LAST_INO_BATCH)
pub const BATCH: u64 = 1024;

/// One CPU's last id handed out (0: take a new batch), on a cache line
/// of its own
#[repr(align(64))]
struct Part(AtomicU64);

/// A source of unique ids from 1 on, batched per CPU
pub struct IdBatch {
    /// The next batch's start
    shared: AtomicU64,
    parts: Box<[Part]>,
}

impl IdBatch {
    /// A part per possible CPU (made where allocation cannot fail: a
    /// superblock)
    pub fn new() -> Self {
        let n = crate::cpu::nr_possible() as usize;
        let mut v = alloc::vec::Vec::with_capacity(n);
        v.resize_with(n, || Part(AtomicU64::new(0)));
        Self {
            shared: AtomicU64::new(0),
            parts: v.into_boxed_slice(),
        }
    }

    /// The next id (never 0)
    pub fn next(&self) -> u64 {
        next_from(
            &self.shared,
            |cpu| self.parts.get(cpu).map(|p| &p.0),
            self.parts.len(),
        )
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
    part: impl Fn(usize) -> Option<&'a AtomicU64>,
    len: usize,
) -> u64 {
    let Some(w) = crate::cpu::own_slot(len).and_then(part) else {
        return shared.fetch_add(1, Ordering::Relaxed) + 1;
    };
    let irq = crate::sync::local_irq_save();
    let mut res = w.load(Ordering::Relaxed);
    if res.is_multiple_of(BATCH) {
        res = shared.fetch_add(BATCH, Ordering::Relaxed);
    }
    res += 1;
    w.store(res, Ordering::Relaxed);
    crate::sync::local_irq_restore(irq);
    res
}

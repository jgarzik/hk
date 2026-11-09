//! A counter summed over per-CPU parts (Linux lib/percpu_counter.c)
//!
//! Adds go to the calling CPU's part, an atomic of its own cache line;
//! a part that reaches `batch` folds into the global count under the
//! lock. A read of the exact value (`sum`) takes the lock and adds every
//! part. `limited_add` (Linux percpu_counter_limited_add) adds only if
//! the result stays within a limit: without the lock while the global
//! count plus the most the parts can hold is clearly inside it, else
//! decided exactly under the lock.
//!
//! Locking: `lock` is an IrqSpinlock leaf (adds may come from any
//! context, e.g. an inode's last reference) under which `count` changes;
//! `count` is read without it where an estimate does (Linux reads
//! fbc->count unlocked). The parts are atomics, so a fold from another
//! CPU never tears one. Choosing the calling CPU's part, reading,
//! checking and adding to it run with interrupts off (Linux
//! local_irq_save in percpu_counter_limited_add), so no interrupt or
//! migration on that CPU can slip an add in between and push the part
//! past the batch, the bound `limited_add` relies on.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicI64, Ordering};

use crate::sync::IrqSpinlock;
use crate::sync::{IrqFlags, local_irq_restore, local_irq_save};
use crate::util::error::KernelError;

/// One CPU's part, alone on its cache line
#[repr(align(64))]
#[derive(Default)]
struct Part(AtomicI64);

impl Clone for Part {
    fn clone(&self) -> Self {
        Self(AtomicI64::new(self.0.load(Ordering::Relaxed)))
    }
}

/// Interrupts off on this CPU until dropped (Linux local_irq_save /
/// local_irq_restore around a part's read-check-add)
struct IrqOff(Option<IrqFlags>);

impl IrqOff {
    fn new() -> Self {
        Self(Some(local_irq_save()))
    }
}

impl Drop for IrqOff {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            local_irq_restore(f);
        }
    }
}

/// A per-CPU counter (Linux struct percpu_counter)
pub struct PercpuCounter {
    lock: IrqSpinlock<()>,
    /// The folded parts (Linux fbc->count): changed under `lock`
    count: AtomicI64,
    parts: Vec<Part>,
    /// A part folds at this magnitude (Linux percpu_counter_batch:
    /// max(32, 2 * CPUs))
    batch: i64,
}

impl PercpuCounter {
    /// A counter at 0 with a part per possible CPU; ENOMEM
    pub fn new() -> Result<Self, KernelError> {
        let n = crate::cpu::nr_cpu_ids() as usize;
        Ok(Self {
            lock: IrqSpinlock::new(()),
            count: AtomicI64::new(0),
            parts: crate::util::kmem::try_vec(n, Part::default())?,
            batch: (2 * n as i64).max(32),
        })
    }

    /// The calling CPU's part (None for a CPU past the parts: a counter
    /// made before every CPU was up; it adds under the lock)
    fn part(&self) -> Option<&AtomicI64> {
        self.parts.get(crate::cpu::this_id() as usize).map(|p| &p.0)
    }

    /// Add `amount` (Linux percpu_counter_add_batch)
    pub fn add(&self, amount: i64) {
        let _irq = IrqOff::new();
        if let Some(p) = self.part() {
            let v = p.fetch_add(amount, Ordering::Relaxed) + amount;
            if v.abs() < self.batch {
                return;
            }
            let _l = self.lock.lock();
            self.count
                .fetch_add(p.swap(0, Ordering::Relaxed), Ordering::Relaxed);
        } else {
            let _l = self.lock.lock();
            self.count.fetch_add(amount, Ordering::Relaxed);
        }
    }

    /// The exact value (Linux percpu_counter_sum)
    pub fn sum(&self) -> i64 {
        let _l = self.lock.lock();
        self.count.load(Ordering::Relaxed) + self.parts_sum()
    }

    fn parts_sum(&self) -> i64 {
        self.parts.iter().map(|p| p.0.load(Ordering::Relaxed)).sum()
    }

    /// Add `amount` (> 0) only if the value stays at most `limit` (Linux
    /// percpu_counter_limited_add); false if it would not
    pub fn limited_add(&self, limit: i64, amount: i64) -> bool {
        if amount == 0 {
            return true;
        }
        let unknown = self.batch * self.parts.len() as i64;
        let _irq = IrqOff::new();
        let part = self.part();
        // Clearly inside: the calling CPU's part, no lock
        if let Some(p) = part {
            let local = p.load(Ordering::Relaxed);
            let global = self.count.load(Ordering::Relaxed);
            if (local + amount).abs() < self.batch && global + unknown <= limit {
                p.fetch_add(amount, Ordering::Relaxed);
                return true;
            }
        }
        let _l = self.lock.lock();
        let mut v = self.count.load(Ordering::Relaxed) + amount;
        if v - unknown > limit {
            return false;
        }
        if v + unknown > limit {
            // Close to the limit: decide on the exact value
            v += self.parts_sum();
            if v > limit {
                return false;
            }
        }
        // Fold the calling CPU's part with the amount
        let folded = amount + part.map_or(0, |p| p.swap(0, Ordering::Relaxed));
        self.count.fetch_add(folded, Ordering::Relaxed);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limited() {
        let c = PercpuCounter::new().unwrap();
        assert!(c.limited_add(3, 2));
        assert!(!c.limited_add(3, 2));
        assert!(c.limited_add(3, 1));
        assert_eq!(c.sum(), 3);
        c.add(-3);
        assert_eq!(c.sum(), 0);
        for _ in 0..100 {
            assert!(c.limited_add(1000, 1));
        }
        assert_eq!(c.sum(), 100);
    }
}

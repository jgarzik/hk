//! CPU masks (Linux include/linux/cpumask.h)
//!
//! [`CpuMask`] is a shared, atomically updated set of logical CPU ids
//! (an mm's cpumask, the active CPUs); [`CpuSet`] is a plain snapshot
//! of one, to iterate or pass to `smp::smp_call_function_many`.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::{CurrentArch, PerCpuOps};

/// Logical CPU ids are below this
pub const NR_CPUS: usize = <CurrentArch as PerCpuOps>::MAX_CPUS;

const WORDS: usize = NR_CPUS.div_ceil(64);

/// An atomic set of CPUs
pub struct CpuMask([AtomicU64; WORDS]);

/// A snapshot of a [`CpuMask`]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct CpuSet([u64; WORDS]);

fn bit(cpu: u32) -> (usize, u64) {
    debug_assert!((cpu as usize) < NR_CPUS);
    (cpu as usize / 64, 1u64 << (cpu % 64))
}

impl CpuMask {
    pub const fn new() -> Self {
        Self([const { AtomicU64::new(0) }; WORDS])
    }

    /// Add `cpu` (Relaxed: callers order it with their own barriers)
    pub fn set(&self, cpu: u32) {
        let (w, b) = bit(cpu);
        self.0[w].fetch_or(b, Ordering::Relaxed);
    }

    /// Remove `cpu`
    pub fn clear(&self, cpu: u32) {
        let (w, b) = bit(cpu);
        self.0[w].fetch_and(!b, Ordering::Relaxed);
    }

    pub fn test(&self, cpu: u32) -> bool {
        let (w, b) = bit(cpu);
        self.0[w].load(Ordering::Relaxed) & b != 0
    }

    /// The CPUs in the mask now
    pub fn snapshot(&self) -> CpuSet {
        let mut s = CpuSet::default();
        for (d, w) in s.0.iter_mut().zip(&self.0) {
            *d = w.load(Ordering::Relaxed);
        }
        s
    }
}

impl Default for CpuMask {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuSet {
    /// Every CPU below `n`
    pub fn first(n: u32) -> Self {
        let mut s = CpuSet::default();
        for cpu in 0..(n as usize).min(NR_CPUS) as u32 {
            s.set(cpu);
        }
        s
    }

    pub fn set(&mut self, cpu: u32) {
        let (w, b) = bit(cpu);
        self.0[w] |= b;
    }

    pub fn clear(&mut self, cpu: u32) {
        let (w, b) = bit(cpu);
        self.0[w] &= !b;
    }

    pub fn test(&self, cpu: u32) -> bool {
        let (w, b) = bit(cpu);
        self.0[w] & b != 0
    }

    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|&w| w == 0)
    }

    /// The CPUs in both sets
    pub fn and(&self, other: &CpuSet) -> CpuSet {
        let mut s = *self;
        for (d, o) in s.0.iter_mut().zip(&other.0) {
            *d &= o;
        }
        s
    }

    /// The CPUs in the set, in increasing order
    pub fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        (0..NR_CPUS as u32).filter(move |&c| self.test(c))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_set_clear_snapshot() {
        let m = CpuMask::new();
        m.set(0);
        m.set(3);
        m.clear(0);
        let s = m.snapshot();
        assert!(!s.test(0) && s.test(3));
        assert_eq!(s.iter().collect::<alloc::vec::Vec<_>>(), [3]);
    }

    #[test]
    fn set_ops() {
        let a = CpuSet::first(3);
        let mut b = CpuSet::default();
        b.set(2);
        b.set(5 % NR_CPUS as u32);
        assert!(a.and(&b).test(2));
        assert!(!CpuSet::default().iter().any(|_| true));
        assert!(CpuSet::default().is_empty());
    }
}

//! CPU masks (Linux include/linux/cpumask.h)
//!
//! [`CpuMask`] is a shared, atomically updated set of logical CPU ids
//! (an mm's cpumask, the active CPUs); [`CpuSet`] is a plain set: a
//! snapshot of one, a task's allowed CPUs (`sched_setaffinity`), or the
//! targets of `smp::smp_call_function_many`.

use alloc::string::String;
use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering};

/// Logical CPU ids are below this (Linux CONFIG_NR_CPUS); the CPUs found
/// at boot are `cpu::nr_cpu_ids()`
pub const NR_CPUS: usize = 256;

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

    /// A mask holding the CPUs of `s`
    pub fn from_set(s: &CpuSet) -> Self {
        let m = Self::new();
        m.assign(s);
        m
    }

    /// Make the mask `s` (word by word: a concurrent reader may see a mix
    /// unless the caller's locks exclude it)
    pub fn assign(&self, s: &CpuSet) {
        for (w, v) in self.0.iter().zip(&s.0) {
            w.store(*v, Ordering::Relaxed);
        }
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
    /// Every possible CPU (Linux CPU_MASK_ALL)
    pub fn all() -> Self {
        Self::first(NR_CPUS as u32)
    }

    /// Only `cpu`
    pub fn one(cpu: u32) -> Self {
        let mut s = CpuSet::default();
        s.set(cpu);
        s
    }

    /// From the words of a user `unsigned long` bitmap (bit n of word
    /// n/64 is CPU n); bits past NR_CPUS are dropped
    pub fn from_words(words: &[u64]) -> Self {
        let mut s = CpuSet::default();
        for (d, w) in s.0.iter_mut().zip(words) {
            *d = *w;
        }
        s
    }

    /// As user bitmap words
    pub fn words(&self) -> &[u64; WORDS] {
        &self.0
    }

    /// Number of CPUs in the set
    pub fn count(&self) -> u32 {
        self.0.iter().map(|w| w.count_ones()).sum()
    }

    /// The first `nbits` bits as Linux "%*pb": hex, a comma between
    /// 32-bit groups, most significant first
    pub fn fmt_hex(&self, nbits: u32) -> String {
        let nbits = nbits.clamp(1, NR_CPUS as u32);
        let digits = nbits.div_ceil(4);
        let mut out = String::new();
        for d in (0..digits).rev() {
            let mut nib = ((self.0[(d / 16) as usize] >> ((d % 16) * 4)) & 0xf) as u32;
            if (d + 1) * 4 > nbits {
                nib &= (1 << (nbits - d * 4)) - 1;
            }
            let _ = write!(out, "{nib:x}");
            if d > 0 && d % 8 == 0 {
                out.push(',');
            }
        }
        out
    }

    /// Linux "%*pbl": the set as a range list ("0-3,5")
    pub fn fmt_list(&self) -> String {
        let mut out = String::new();
        let mut cpu = 0u32;
        while (cpu as usize) < NR_CPUS {
            if !self.test(cpu) {
                cpu += 1;
                continue;
            }
            let lo = cpu;
            while (cpu as usize) < NR_CPUS && self.test(cpu) {
                cpu += 1;
            }
            if !out.is_empty() {
                out.push(',');
            }
            if cpu - 1 == lo {
                let _ = write!(out, "{lo}");
            } else {
                let _ = write!(out, "{}-{}", lo, cpu - 1);
            }
        }
        out
    }

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

    #[test]
    fn words_and_format() {
        let mut s = CpuSet::from_words(&[0b1011, 1]);
        assert_eq!(s.count(), 4);
        assert!(s.test(64));
        assert_eq!(s.fmt_list(), "0-1,3,64");
        assert_eq!(s.fmt_hex(4), "b");
        assert_eq!(s.fmt_hex(36), "0,0000000b");
        assert_eq!(s.fmt_hex(72), "01,00000000,0000000b");
        s.clear(64);
        assert_eq!(CpuSet::one(3).words()[0], 8);
        assert_eq!(CpuSet::all().count(), NR_CPUS as u32);
    }
}

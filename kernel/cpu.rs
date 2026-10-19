//! This CPU's id and per-CPU variables (Linux include/linux/percpu.h,
//! smp_processor_id)
//!
//! [`PerCpu<T>`] holds one `T` per possible CPU, indexed by logical CPU
//! id (Linux DEFINE_PER_CPU). [`PerCpu::this`] is the calling CPU's
//! slot: the kernel is not preemptive, so a thread stays on its CPU
//! between scheduling points; IRQ-reachable slots still need their own
//! IRQ discipline, and cross-CPU reads their own barriers.

use crate::arch::{CurrentArch, PerCpuOps};
use crate::cpumask::NR_CPUS;

/// The calling CPU's logical id (Linux smp_processor_id); 0 before
/// per-CPU data exists, when only the boot CPU runs
#[inline]
pub fn this_id() -> u32 {
    CurrentArch::try_current_cpu_id().unwrap_or(0)
}

/// The calling CPU's id once its per-CPU data exists; None before (the
/// boot CPU early, or a CPU coming up): per-CPU caches (slab, page
/// lists) must not be used then
#[inline]
pub fn try_this_id() -> Option<u32> {
    CurrentArch::try_current_cpu_id()
}

/// One `T` per possible CPU
pub struct PerCpu<T>([T; NR_CPUS]);

impl<T> PerCpu<T> {
    /// From one value per CPU (see [`percpu!`](crate::percpu))
    pub const fn new(slots: [T; NR_CPUS]) -> Self {
        Self(slots)
    }

    /// The calling CPU's slot
    #[inline]
    pub fn this(&self) -> &T {
        &self.0[this_id() as usize]
    }

    /// CPU `cpu`'s slot (`cpu` < NR_CPUS)
    #[inline]
    pub fn get(&self, cpu: u32) -> &T {
        &self.0[cpu as usize]
    }

    /// CPU `cpu`'s slot, None past NR_CPUS
    #[inline]
    pub fn try_get(&self, cpu: u32) -> Option<&T> {
        self.0.get(cpu as usize)
    }

    /// Every possible CPU's slot, with its id (Linux for_each_possible_cpu)
    pub fn for_each_possible(&self) -> impl Iterator<Item = (u32, &T)> {
        self.0.iter().enumerate().map(|(c, t)| (c as u32, t))
    }
}

/// A [`PerCpu`] with every slot set to the const expression `$init`:
/// `static X: PerCpu<AtomicU32> = percpu![AtomicU32::new(0)];`
#[macro_export]
macro_rules! percpu {
    ($init:expr) => {
        $crate::cpu::PerCpu::new([const { $init }; $crate::cpumask::NR_CPUS])
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn slots() {
        static P: PerCpu<AtomicU32> = percpu![AtomicU32::new(0)];
        P.get(1 % NR_CPUS as u32).store(5, Ordering::Relaxed);
        assert_eq!(P.for_each_possible().count(), NR_CPUS);
        let sum: u32 = P
            .for_each_possible()
            .map(|(_, v)| v.load(Ordering::Relaxed))
            .sum();
        assert_eq!(sum, 5);
        assert!(P.try_get(NR_CPUS as u32).is_none());
    }
}

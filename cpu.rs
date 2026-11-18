//! This CPU's id and per-CPU variables (Linux include/linux/percpu.h,
//! smp_processor_id)
//!
//! [`PerCpu<T>`] holds one `T` per possible CPU, in that CPU's per-CPU
//! area (Linux DEFINE_PER_CPU, setup_per_cpu_areas). [`PerCpu::this`] is the calling CPU's
//! slot: the kernel is not preemptive, so a thread stays on its CPU
//! between scheduling points, but may resume on another after one (a
//! sleep, a yield, a return to user mode): a slot must not be used
//! across one. IRQ-reachable slots still need their own IRQ discipline,
//! and cross-CPU reads their own barriers.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::arch::{CurrentArch, PerCpuOps};
use crate::util::cpumask::NR_CPUS;

/// CPUs found at boot (Linux nr_cpu_ids): logical ids are below it
static NR_CPU_IDS: AtomicU32 = AtomicU32::new(1);

/// Number of possible CPUs: every CPU brought up at boot (hk has no
/// hotplug), 1 until SMP bring-up is done (early boot code, on the boot
/// CPU, sizes nothing per CPU before that). Acquire pairs with the one
/// store: the application CPUs are already running when it is made.
#[inline]
pub fn nr_cpu_ids() -> u32 {
    NR_CPU_IDS.load(Ordering::Acquire)
}

/// Record the CPUs found at boot (`smp::init`, once, on the boot CPU,
/// before any CPU takes call-function IPIs or schedules)
pub fn set_nr_cpu_ids(n: u32) {
    NR_CPU_IDS.store(n.clamp(1, NR_CPUS as u32), Ordering::Release);
}

/// The calling CPU's logical id (Linux smp_processor_id); 0 before
/// per-CPU data exists, when only the boot CPU runs
#[inline]
pub fn this_id() -> u32 {
    try_this_id().unwrap_or(0)
}

/// The calling CPU's id once its per-CPU data exists; None before (the
/// boot CPU early, or a CPU coming up): per-CPU caches (slab, page
/// lists) must not be used then
#[cfg(not(test))]
#[inline]
pub fn try_this_id() -> Option<u32> {
    CurrentArch::try_current_cpu_id()
}

/// Host unit tests run in user space, where the per-CPU base register
/// is out of reach (arm64 TPIDR_EL1 traps at EL0): no per-CPU data, so
/// everything uses slot 0
#[cfg(test)]
#[inline]
pub fn try_this_id() -> Option<u32> {
    None
}

/// One `T` per possible CPU (Linux DEFINE_PER_CPU): declared with
/// [`percpu!`](crate::percpu), its value is the template in the
/// `.data..percpu` section, and each CPU's copy lives in that CPU's
/// per-CPU area at `per_cpu_offset(cpu)` from it (Linux per_cpu_ptr).
/// A CPU's variables sit together in its own area, so two CPUs never
/// share a cache line through them. The template itself is never used
/// once the boot CPU's area exists (first thing at boot): it stays the
/// pristine image every area is copied from (Linux __per_cpu_load).
#[cfg(not(test))]
#[repr(transparent)]
pub struct PerCpu<T>(core::cell::UnsafeCell<T>);

// SAFETY: each CPU's copy is a separate `T`; sharing `&PerCpu<T>` hands
// out `&T`s to them, as sharing a `[T; N]` would (`T: Sync`)
#[cfg(not(test))]
unsafe impl<T: Sync> Sync for PerCpu<T> {}

#[cfg(not(test))]
impl<T> PerCpu<T> {
    /// The template (see [`percpu!`](crate::percpu))
    pub const fn new(init: T) -> Self {
        Self(core::cell::UnsafeCell::new(init))
    }

    /// CPU `cpu`'s copy, which must exist (`cpu` < the areas made)
    #[inline]
    fn slot(&self, cpu: u32) -> &T {
        let off = area_offset(cpu).expect("percpu: no area for this CPU");
        let p = (self.0.get() as usize).wrapping_add(off) as *const T;
        // SAFETY: the area of `cpu` holds a copy of the whole template
        // section at `off` from it, made from the pristine image before
        // the CPU or anyone else used it, and never freed; `T`'s copy
        // there is as valid as the template (const-initialized, bytes
        // copied)
        unsafe { &*p }
    }

    /// The calling CPU's copy (Linux this_cpu_ptr): a running CPU's
    /// area exists, so no bounds check (CPU 0's from the first
    /// instruction, the others' before they start)
    #[inline]
    pub fn this(&self) -> &T {
        let off = OFFSETS[this_id() as usize].load(Ordering::Relaxed);
        let p = (self.0.get() as usize).wrapping_add(off) as *const T;
        // SAFETY: as `slot`: the calling CPU runs, so its area was made
        // (and published to it) before it started
        unsafe { &*p }
    }

    /// CPU `cpu`'s copy (`cpu` a possible CPU)
    #[inline]
    pub fn get(&self, cpu: u32) -> &T {
        self.slot(cpu)
    }

    /// CPU `cpu`'s copy, None if it is not a possible CPU
    #[inline]
    pub fn try_get(&self, cpu: u32) -> Option<&T> {
        area_offset(cpu).map(|_| self.slot(cpu))
    }

    /// Every possible CPU's copy, with its id (Linux for_each_possible_cpu)
    pub fn for_each_possible(&self) -> impl Iterator<Item = (u32, &T)> {
        (0..nr_possible()).map(move |c| (c, self.slot(c)))
    }

    /// CPU `cpu`'s copy in an area made but not yet published, for a
    /// CPU prepare step
    ///
    /// # Safety
    /// `setup_areas` made `cpu`'s area (`cpu` > 0) and calls this before
    /// publishing it; nothing else runs on that CPU yet.
    pub unsafe fn get_unpublished(&self, cpu: u32) -> &T {
        let off = OFFSETS[cpu as usize].load(Ordering::Relaxed);
        debug_assert!(cpu > 0 && off != 0, "percpu: no unpublished area");
        let p = (self.0.get() as usize).wrapping_add(off) as *const T;
        // SAFETY: as `slot`: the area exists (the caller's contract)
        unsafe { &*p }
    }
}

/// Declare a per-CPU variable (Linux DEFINE_PER_CPU): its template, a
/// `PerCpu<T>`, goes in the `.data..percpu` section
/// (`percpu! { static X: AtomicU32 = AtomicU32::new(0); }`)
#[cfg(not(test))]
#[macro_export]
macro_rules! percpu {
    ($(#[$m:meta])* $vis:vis static $name:ident: $t:ty = $init:expr;) => {
        $(#[$m])*
        #[unsafe(link_section = ".data..percpu")]
        $vis static $name: $crate::cpu::PerCpu<$t> = $crate::cpu::PerCpu::new($init);
    };
}

/// Each possible CPU's area offset from the template (Linux
/// __per_cpu_offset), set once: CPU 0's first thing at boot, the others'
/// before any of them starts (`setup_areas`); read lock-free after
#[cfg(not(test))]
static OFFSETS: [core::sync::atomic::AtomicUsize; NR_CPUS] =
    [const { core::sync::atomic::AtomicUsize::new(0) }; NR_CPUS];

/// Possible CPUs (Linux nr_cpu_ids at setup_per_cpu_areas): those with
/// an area; 1 (the boot CPU) until `setup_areas`
#[cfg(not(test))]
static NR_POSSIBLE: AtomicU32 = AtomicU32::new(1);

#[cfg(not(test))]
unsafe extern "C" {
    /// The template section's bounds and the boot CPU's area (linker)
    static __per_cpu_start: u8;
    static __per_cpu_end: u8;
    static __per_cpu_area0: u8;
}

/// The template section's address and length
#[cfg(not(test))]
fn template() -> (usize, usize) {
    // Linker symbols: only their addresses are taken
    let (s, e) = (
        core::ptr::addr_of!(__per_cpu_start) as usize,
        core::ptr::addr_of!(__per_cpu_end) as usize,
    );
    (s, e - s)
}

/// Possible CPUs (Linux nr_cpu_ids at setup_per_cpu_areas): those
/// with a per-CPU area
#[cfg(not(test))]
pub fn nr_possible() -> u32 {
    NR_POSSIBLE.load(Ordering::Acquire)
}

/// Host unit tests: every slot
#[cfg(test)]
pub fn nr_possible() -> u32 {
    NR_CPUS as u32
}

/// CPU `cpu`'s area offset, None if it has no area
#[cfg(not(test))]
#[inline]
fn area_offset(cpu: u32) -> Option<usize> {
    (cpu < nr_possible()).then(|| OFFSETS[cpu as usize].load(Ordering::Relaxed))
}

/// Make the boot CPU's area from the template (Linux: the boot CPU's
/// copy, setup_per_cpu_areas). First thing at boot, before any per-CPU
/// variable is touched
///
/// # Safety
/// Once, on the boot CPU, before anything uses a per-CPU variable
#[cfg(not(test))]
pub unsafe fn setup_boot_area() {
    let (start, len) = template();
    // A linker symbol: only its address is taken
    let area0 = core::ptr::addr_of!(__per_cpu_area0) as usize;
    // SAFETY: the linker reserves `len` bytes at `__per_cpu_area0` in
    // .bss for this, apart from the template; nothing uses either yet
    unsafe { core::ptr::copy_nonoverlapping(start as *const u8, area0 as *mut u8, len) };
    OFFSETS[0].store(area0.wrapping_sub(start), Ordering::Relaxed);
}

/// Per-CPU state that names its CPU, set in a new area (Linux CPU
/// hotplug prepare states, run before the CPU starts)
///
/// # Safety
/// As [`PerCpu::get_unpublished`].
#[cfg(not(test))]
unsafe fn prepare_cpu(cpu: u32) {
    // SAFETY: the caller's contract
    unsafe { crate::time::hrtimer::prepare_cpu(cpu) };
}

/// Make the areas of CPUs 1..`n` from the template, `n` the possible
/// CPUs (Linux setup_per_cpu_areas, pcpu_embed_first_chunk), before any
/// of them starts; boot memory, never freed
#[cfg(not(test))]
pub fn setup_areas(n: u32) {
    let n = n.clamp(1, NR_CPUS as u32);
    let (start, len) = template();
    let layout =
        core::alloc::Layout::from_size_align(len.max(64), 4096).expect("percpu: area layout");
    for cpu in 1..n {
        // SAFETY: a nonzero size
        let p = unsafe { alloc::alloc::alloc(layout) };
        assert!(!p.is_null(), "percpu: no memory for CPU {cpu}'s area");
        // SAFETY: a fresh allocation of `len` bytes; the template is
        // pristine (the boot CPU uses its own area)
        unsafe { core::ptr::copy_nonoverlapping(start as *const u8, p, len) };
        OFFSETS[cpu as usize].store((p as usize).wrapping_sub(start), Ordering::Relaxed);
        // SAFETY: its area was just made, not yet published
        unsafe { prepare_cpu(cpu) };
    }
    // The offsets before the count (Release): a CPU that sees the count
    // sees its area
    NR_POSSIBLE.store(n, Ordering::Release);
}

/// One `T` per possible CPU (host unit tests: no per-CPU areas, an
/// array)
#[cfg(test)]
pub struct PerCpu<T>([T; NR_CPUS]);

#[cfg(test)]
impl<T> PerCpu<T> {
    pub const fn new(slots: [T; NR_CPUS]) -> Self {
        Self(slots)
    }

    pub fn this(&self) -> &T {
        &self.0[this_id() as usize]
    }

    pub fn get(&self, cpu: u32) -> &T {
        &self.0[cpu as usize]
    }

    pub fn try_get(&self, cpu: u32) -> Option<&T> {
        self.0.get(cpu as usize)
    }

    pub fn for_each_possible(&self) -> impl Iterator<Item = (u32, &T)> {
        self.0.iter().enumerate().map(|(c, t)| (c as u32, t))
    }

    /// # Safety
    /// None (host tests).
    pub unsafe fn get_unpublished(&self, cpu: u32) -> &T {
        &self.0[cpu as usize]
    }
}

/// Host unit tests: nothing to make
#[cfg(test)]
pub fn setup_areas(_n: u32) {}

/// Host unit tests: an array static, every slot `$init`
#[cfg(test)]
#[macro_export]
macro_rules! percpu {
    ($(#[$m:meta])* $vis:vis static $name:ident: $t:ty = $init:expr;) => {
        $(#[$m])*
        $vis static $name: $crate::cpu::PerCpu<$t> =
            $crate::cpu::PerCpu::new([const { $init }; $crate::util::cpumask::NR_CPUS]);
    };
}

/// The calling CPU's slot in an array of `len` per-CPU slots where CPUs
/// past it share slot 0 (one made before SMP bring-up), if the slot is
/// this CPU's alone: None for an unknown CPU (no per-CPU data yet) or
/// for slot 0 while other CPUs share it
pub fn own_slot(len: usize) -> Option<usize> {
    let cpu = try_this_id()? as usize;
    (cpu < len && (cpu != 0 || len >= nr_possible() as usize)).then_some(cpu)
}

/// A 64-bit per-CPU counter word (Linux this_cpu_add /
/// this_cpu_add_return): no lock prefix on x86, a barrier-free atomic on
/// arm64 (`arch::local_add_u64`)
pub trait LocalWord {
    /// Add `v` (two's complement for a negative one)
    ///
    /// # Safety
    /// Only the calling CPU writes the word (its interrupts included),
    /// and the caller stays on it (no scheduling point between choosing
    /// the word and this call): a static per-CPU variable's `this()`, or
    /// a slot [`own_slot`] gave.
    unsafe fn local_add(&self, v: i64);
    /// Add `v`, the new value
    ///
    /// # Safety
    /// As [`local_add`](Self::local_add).
    unsafe fn local_add_return(&self, v: i64) -> i64;
    /// Add `v` atomically, for a word CPUs share; the new value
    fn atomic_add_return(&self, v: i64) -> i64;
}

impl<T: LocalWord> PerCpu<T> {
    /// Add `v` to the calling CPU's word (Linux this_cpu_add); a CPU with
    /// no per-CPU data yet (the boot CPU early) adds atomically to CPU
    /// 0's
    #[inline]
    pub fn this_add(&self, v: i64) {
        self.this_add_return(v);
    }

    /// [`this_add`](Self::this_add), the word's new value (Linux
    /// this_cpu_add_return)
    #[inline]
    pub fn this_add_return(&self, v: i64) -> i64 {
        match try_this_id() {
            // SAFETY: a static per-CPU variable's word of the calling
            // CPU, which only it writes; nothing schedules before the add
            Some(c) => unsafe { self.get(c).local_add_return(v) },
            None => self.get(0).atomic_add_return(v),
        }
    }
}

macro_rules! local_word {
    ($t:ty, $v:ty) => {
        impl LocalWord for $t {
            #[inline]
            unsafe fn local_add(&self, v: i64) {
                // SAFETY: the word is this CPU's alone (the caller's
                // contract), 8 bytes, aligned
                unsafe { crate::arch::local_add_u64(self.as_ptr().cast::<u64>(), v as u64) };
            }

            #[inline]
            unsafe fn local_add_return(&self, v: i64) -> i64 {
                let p = self.as_ptr().cast::<u64>();
                // SAFETY: as local_add
                let old = unsafe { crate::arch::local_xadd_u64(p, v as u64) };
                (old as i64).wrapping_add(v)
            }

            #[inline]
            fn atomic_add_return(&self, v: i64) -> i64 {
                let old = self.fetch_add(v as $v, core::sync::atomic::Ordering::Relaxed);
                (old as i64).wrapping_add(v)
            }
        }
    };
}

local_word!(core::sync::atomic::AtomicU64, u64);
local_word!(core::sync::atomic::AtomicI64, i64);
local_word!(core::sync::atomic::AtomicIsize, isize);
local_word!(core::sync::atomic::AtomicUsize, usize);

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn slots() {
        crate::percpu! {
            static P: AtomicU32 = AtomicU32::new(0);
        }
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

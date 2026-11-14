//! Per-CPU counter slots (Linux mm/percpu.c's alloc_percpu, for
//! counters)
//!
//! A [`PcpSlot`] is one `isize` on every possible CPU. Each CPU's slots
//! sit together in page-sized chunks of its own, so a slot costs a word
//! per CPU and two CPUs never share a cache line through it (Linux's
//! percpu chunks, one unit per CPU). Slot numbers come from an `Ida`; a
//! chunk is made on every CPU the first time one of its slots is
//! handed out, published once and never freed. A slot is zeroed on
//! every CPU when it is handed out, so a freed one may be left with any
//! parts that sum to anything.
//!
//! Locking: none of its own beyond the `Ida` (an IrqSpinlock leaf) and
//! `GROW` (a sleeping Mutex, taken with nothing held, around making a
//! chunk); a part is an atomic, read and added to lock-free from any
//! context.

use alloc::boxed::Box;
use core::sync::atomic::{AtomicIsize, AtomicPtr, Ordering};

use crate::util::error::KernelError;
use crate::util::ida::Ida;

/// Slots per chunk: one page of words per CPU
const SLOTS: usize = 4096 / core::mem::size_of::<AtomicIsize>();
/// Chunks per CPU, so at most `SLOTS * CHUNKS` slots
const CHUNKS: usize = 1024;

/// One CPU's words for `SLOTS` slots
type Chunk = [AtomicIsize; SLOTS];

/// One CPU's chunk table
struct CpuArea {
    chunks: [AtomicPtr<Chunk>; CHUNKS],
}

impl CpuArea {
    const fn new() -> Self {
        Self {
            chunks: [const { AtomicPtr::new(core::ptr::null_mut()) }; CHUNKS],
        }
    }
}

/// Every possible CPU's chunk table, made on first use (after the CPU
/// count is known)
static AREAS: spin::Once<Box<[CpuArea]>> = spin::Once::new();

/// Slot numbers handed out
static IDS: Ida = Ida::new();

/// Serializes making a chunk (Linux pcpu_alloc_mutex)
static GROW: crate::sync::Mutex<()> = crate::sync::Mutex::new(());

fn areas() -> &'static [CpuArea] {
    AREAS.call_once(|| {
        let n = crate::cpu::nr_cpu_ids().max(1) as usize;
        (0..n).map(|_| CpuArea::new()).collect()
    })
}

/// One `isize` per possible CPU (Linux a `__percpu` counter)
///
/// # Invariants
/// Its chunk exists on every CPU of `AREAS` and is never freed.
pub struct PcpSlot(u32);

impl PcpSlot {
    /// A slot, zero on every CPU (Linux alloc_percpu); ENOMEM
    pub fn new() -> Result<Self, KernelError> {
        let id = IDS.try_alloc()?;
        let s = Self(id);
        s.populate(false)?;
        Ok(s)
    }

    /// [`PcpSlot::new`] that cannot fail (a mount tree copy)
    pub fn new_nofail() -> Self {
        let s = Self(IDS.alloc());
        let _ = s.populate(true);
        s
    }

    /// Make the slot's chunk on every CPU that lacks it, then zero the
    /// slot everywhere
    fn populate(&self, nofail: bool) -> Result<(), KernelError> {
        let (c, i) = (self.0 as usize / SLOTS, self.0 as usize % SLOTS);
        if c >= CHUNKS {
            return Err(KernelError::OutOfMemory);
        }
        let areas = areas();
        if areas
            .iter()
            .any(|a| a.chunks[c].load(Ordering::Acquire).is_null())
        {
            let _g = GROW.lock();
            for a in areas {
                if !a.chunks[c].load(Ordering::Acquire).is_null() {
                    continue;
                }
                let chunk: Box<Chunk> = if nofail {
                    crate::util::kalloc::box_nofail([const { AtomicIsize::new(0) }; SLOTS])
                } else {
                    crate::util::kalloc::try_box([const { AtomicIsize::new(0) }; SLOTS])?
                };
                // Published once, under GROW, never freed
                a.chunks[c].store(Box::into_raw(chunk), Ordering::Release);
            }
        }
        for a in areas {
            // SAFETY: made above or before, never freed
            unsafe { &(*a.chunks[c].load(Ordering::Acquire))[i] }.store(0, Ordering::Relaxed);
        }
        Ok(())
    }

    /// CPU `cpu`'s word (a CPU past the table uses the first's: still
    /// counted, only shared)
    fn part(&self, cpu: usize) -> &AtomicIsize {
        let areas = areas();
        let a = areas.get(cpu).unwrap_or(&areas[0]);
        let (c, i) = (self.0 as usize / SLOTS, self.0 as usize % SLOTS);
        // SAFETY: the type invariant: the chunk exists and lives forever
        unsafe { &(*a.chunks[c].load(Ordering::Acquire))[i] }
    }

    /// Add `n` to this CPU's word (Linux this_cpu_add); any CPU's would
    /// do, so preemption may move the caller meanwhile
    pub fn add(&self, n: isize) {
        let cpu = crate::cpu::try_this_id().unwrap_or(0) as usize;
        self.part(cpu).fetch_add(n, Ordering::Relaxed);
    }

    /// The words of every CPU, summed (Linux's per_cpu_ptr loop): exact
    /// only while no add runs
    pub fn sum(&self) -> isize {
        (0..areas().len())
            .map(|cpu| self.part(cpu).load(Ordering::Relaxed))
            .sum()
    }
}

impl Drop for PcpSlot {
    /// Linux free_percpu: the number goes back; the words stay, to be
    /// zeroed by the next owner
    fn drop(&mut self) {
        IDS.free(self.0);
    }
}

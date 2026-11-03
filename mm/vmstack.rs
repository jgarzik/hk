//! Kernel stacks with guard gaps (Linux CONFIG_VMAP_STACK,
//! kernel/fork.c alloc_thread_stack_node)
//!
//! Every task's kernel stack is `THREAD_SIZE` bytes of single pages
//! mapped at the start of its own 64KB slot of a dedicated kernel area
//! (`paging::VMSTACK_START`); the rest of the slot stays unmapped, so a
//! stack that overflows faults in the gap instead of overwriting the
//! memory below it. The fault cannot run on the overflowed stack: x86
//! takes it as a double fault on an IST stack, arm64's exception entry
//! sees SP leave the stack (bit 15 of SP set: slots are 64KB-aligned
//! and no EL1 stack is larger than 32KB) and switches to this CPU's
//! overflow stack. Both panic with "kernel stack overflow".
//!
//! Slot 0 is never used (the gap below slot 1's stack). A freed stack's
//! pages are unmapped and freed at once, but its slot is reused only
//! after a flush of the whole area on every CPU (Linux vmalloc's lazy
//! purge), done by `alloc` in thread context once `DIRTY_MAX` slots
//! wait for it (or no clean slot is left): `free` runs at the end of a
//! context switch, where interrupts may be off and IPIs must not be
//! waited for. Slots are taken lowest first, so the page tables of the
//! area stay those of the stacks in use (they are never freed).
//!
//! Locking: `SLOTS` is a spin leaf, thread context only (`free` may
//! run with interrupts off; no interrupt handler takes it); frames are
//! allocated, mapped and freed outside it.

use crate::arch::paging::VMSTACK_START;
use crate::sync::spin::Mutex;

/// Kernel stack size (Linux THREAD_SIZE on x86-64 and arm64)
pub const THREAD_SIZE: usize = 16 * 1024;

/// Slot size: the stack, then the unmapped gap the next stack's
/// overflow lands in (arm64's entry check needs 64KB alignment)
pub const SLOT_SIZE: u64 = 64 * 1024;

/// Slots in the area (512MB: at most this many kernel stacks)
const NR_SLOTS: usize = 8192;

/// Freed slots that wait for a flush before it is done (Linux
/// lazy_max_pages)
const DIRTY_MAX: usize = 64;

const PAGE_SIZE: u64 = 4096;
const WORDS: usize = NR_SLOTS / 64;

/// End of the stack area
const VMSTACK_END: u64 = VMSTACK_START + NR_SLOTS as u64 * SLOT_SIZE;

/// Slot bookkeeping: `used` slots hold a stack; `dirty` ones were freed
/// since the last flush and may still be cached in some TLB
struct Slots {
    used: [u64; WORDS],
    dirty: [u64; WORDS],
    nr_dirty: usize,
}

static SLOTS: Mutex<Slots> = Mutex::new(Slots::new());

/// One flusher at a time (sleeping, thread context): a second one must
/// not clean, from an older snapshot, a slot freed again after the first
/// flush (it would be reused with stale TLB entries)
static FLUSH: crate::sync::Mutex<()> = crate::sync::Mutex::new(());

impl Slots {
    const fn new() -> Self {
        let mut used = [0; WORDS];
        used[0] = 1; // slot 0: never used
        Self {
            used,
            dirty: [0; WORDS],
            nr_dirty: 0,
        }
    }

    /// Take the lowest clean free slot
    fn take(&mut self) -> Option<usize> {
        let w = (0..WORDS).find(|&w| self.used[w] | self.dirty[w] != u64::MAX)?;
        let bit = (!(self.used[w] | self.dirty[w])).trailing_zeros() as usize;
        self.used[w] |= 1 << bit;
        Some(w * 64 + bit)
    }

    /// Free `slot`: dirty until the next flush
    fn put(&mut self, slot: usize) {
        self.used[slot / 64] &= !(1 << (slot % 64));
        self.dirty[slot / 64] |= 1 << (slot % 64);
        self.nr_dirty += 1;
    }

    /// The slots in `flushed` are clean again
    fn clean(&mut self, flushed: &[u64; WORDS]) {
        for (w, f) in self.dirty.iter_mut().zip(flushed) {
            self.nr_dirty -= (*w & f).count_ones() as usize;
            *w &= !f;
        }
    }
}

fn slot_base(i: usize) -> u64 {
    VMSTACK_START + i as u64 * SLOT_SIZE
}

/// A clean slot, flushing the area first if `DIRTY_MAX` slots wait for
/// it or only dirty ones are left
fn take_slot() -> Option<usize> {
    if let Some(i) = try_clean_slot() {
        return Some(i);
    }
    let _flusher = FLUSH.lock();
    let dirty = {
        let mut s = SLOTS.lock();
        if s.nr_dirty < DIRTY_MAX
            && let Some(i) = s.take()
        {
            return Some(i);
        }
        if s.nr_dirty == 0 {
            return s.take();
        }
        // What is dirty now: what is freed during the flush stays
        // dirty until the next one
        s.dirty
    };
    crate::mm::tlb::flush_tlb_kernel_range(VMSTACK_START, VMSTACK_END);
    let mut s = SLOTS.lock();
    s.clean(&dirty);
    s.take()
}

/// A clean slot while fewer than `DIRTY_MAX` wait for a flush
fn try_clean_slot() -> Option<usize> {
    let mut s = SLOTS.lock();
    if s.nr_dirty < DIRTY_MAX {
        s.take()
    } else {
        None
    }
}

/// Allocate a zeroed kernel stack; its base (lowest address; the top
/// is `base + THREAD_SIZE`). Thread context (may flush every CPU's TLB).
pub fn alloc() -> Option<u64> {
    let slot = take_slot()?;
    let base = slot_base(slot);
    for off in (0..THREAD_SIZE as u64).step_by(PAGE_SIZE as usize) {
        let mapped = crate::FRAME_ALLOCATOR
            .alloc()
            .filter(|&pa| crate::arch::vmap_page(base + off, pa).is_ok());
        if mapped.is_none() {
            unmap(base, off);
            release(slot);
            return None;
        }
    }
    // SAFETY: the pages just mapped
    unsafe { core::ptr::write_bytes(base as *mut u8, 0, THREAD_SIZE) };
    Some(base)
}

/// Free the stack at `base` (from `alloc`): nothing runs on it any more
pub fn free(base: u64) {
    debug_assert!(contains(base) && (base - VMSTACK_START).is_multiple_of(SLOT_SIZE));
    unmap(base, THREAD_SIZE as u64);
    release(((base - VMSTACK_START) / SLOT_SIZE) as usize);
}

/// Unmap and free the first `len` bytes of the stack at `base`; this
/// CPU's stale entries go now, the other CPUs' before the slot is reused
fn unmap(base: u64, len: u64) {
    for off in (0..len).step_by(PAGE_SIZE as usize) {
        if let Some(pa) = crate::arch::vunmap_page(base + off) {
            crate::arch::tlb::local_flush_one(base + off);
            crate::FRAME_ALLOCATOR.free(pa);
        }
    }
}

/// The slot is free, but dirty until the next flush
fn release(slot: usize) {
    SLOTS.lock().put(slot);
}

/// `addr` lies in the kernel stack area (not in the linear map: no
/// virt_to_phys, no DMA)
pub fn contains(addr: u64) -> bool {
    (VMSTACK_START..VMSTACK_END).contains(&addr)
}

/// `addr` lies in a guard gap: a stack overflowed into it
pub fn in_guard(addr: u64) -> bool {
    contains(addr) && (addr - VMSTACK_START) % SLOT_SIZE >= THREAD_SIZE as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_lowest_clean_first() {
        let mut s = Slots::new();
        assert_eq!(s.take(), Some(1));
        assert_eq!(s.take(), Some(2));
        // Slot 1 freed: dirty, so not handed out again before a flush
        s.put(1);
        assert_eq!(s.take(), Some(3));
        assert_eq!(s.nr_dirty, 1);
        let flushed = s.dirty;
        s.clean(&flushed);
        assert_eq!(s.nr_dirty, 0);
        assert_eq!(s.take(), Some(1));
        // Every word full: the next word
        for i in 4..64 {
            assert_eq!(s.take(), Some(i));
        }
        assert_eq!(s.take(), Some(64));
    }

    #[test]
    fn guard_gaps() {
        let b = slot_base(5);
        assert!(!in_guard(b));
        assert!(!in_guard(b + THREAD_SIZE as u64 - 1));
        assert!(in_guard(b + THREAD_SIZE as u64));
        assert!(in_guard(b - 8));
        assert!(!contains(VMSTACK_END));
    }
}

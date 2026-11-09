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
//! overflow stack. Both panic with "kernel stack overflow". Each CPU's
//! IRQ stack (`crate::irq_stack`) is one of these stacks too.
//!
//! Slot 0 is never used (the gap below slot 1's stack). A freed stack's
//! pages are unmapped and freed at once, but its slot is reused only
//! after a flush of the whole area on every CPU (Linux vmalloc's lazy
//! purge), done by `alloc` in thread context once `DIRTY_MAX` slots
//! wait for it (or no clean slot is left): a stack is freed at the end of a
//! context switch, where interrupts may be off and IPIs must not be
//! waited for. Slots are taken lowest first, so the page tables of the
//! area stay those of the stacks in use (they are never freed).
//!
//! A stack is a [`VmStack`], its slot's ownership token: dropping it
//! frees the stack, so only its holder can (a task holds its own in a
//! [`StackSlot`] until its exit hands it to the next task to free).
//!
//! Locking: `SLOTS` is a spin leaf, thread context only (a stack may be
//! freed with interrupts off; no interrupt handler takes it); frames are
//! allocated, mapped and freed outside it.

use core::sync::atomic::{AtomicU64, Ordering};

use super::vmalloc::VmArea;
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

/// Pages of one stack
const STACK_PAGES: usize = THREAD_SIZE / PAGE_SIZE as usize;

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

/// A kernel stack from [`alloc`], owned: dropping it unmaps and frees
/// its pages (code that runs on it, through its address, is `unsafe`
/// and keeps the token meanwhile). A leaked one keeps its slot.
///
/// # Invariants
///
/// `0` is the stack pages of a slot `alloc` took for this holder alone,
/// all mapped.
#[must_use]
pub struct VmStack(VmArea);

impl VmStack {
    /// The lowest address
    #[inline]
    pub fn base(&self) -> u64 {
        self.0.base()
    }

    /// The top (`base + THREAD_SIZE`), where the stack starts
    #[inline]
    pub fn top(&self) -> u64 {
        self.base() + THREAD_SIZE as u64
    }

    /// Keep it for good (a CPU's own stacks); its base
    pub fn leak(self) -> u64 {
        let base = self.base();
        core::mem::forget(self);
        base
    }

    /// The stack at `base`, out of a leaked token
    ///
    /// # Safety
    ///
    /// `base` is from [`leak`](Self::leak) of a stack no token holds
    /// now (made again at most once).
    unsafe fn from_base(base: u64) -> Self {
        debug_assert!(contains(base) && (base - VMSTACK_START).is_multiple_of(SLOT_SIZE));
        // SAFETY: the stack pages of `base`'s slot, from `alloc`, whose
        // token is gone (the caller's guarantee)
        // INVARIANT: as the leaked token's
        Self(unsafe { VmArea::new(base, STACK_PAGES) })
    }
}

impl Drop for VmStack {
    /// Free it; this CPU's stale TLB entries go now, the other CPUs'
    /// before the slot is reused
    fn drop(&mut self) {
        let base = self.base();
        unmap(&mut self.0, STACK_PAGES);
        release(((base - VMSTACK_START) / SLOT_SIZE) as usize);
    }
}

/// The kernel stack a task owns (Linux task->stack), taken out once to
/// be freed after its last switch away; empty for a task on a stack it
/// does not own (the boot and idle stacks). A stack still in it when it
/// is dropped is freed.
///
/// # Invariants
///
/// `base` is 0 or the base of a leaked [`VmStack`] this slot owns.
pub struct StackSlot {
    base: AtomicU64,
}

impl StackSlot {
    /// No stack
    pub const fn empty() -> Self {
        // INVARIANT: 0
        Self {
            base: AtomicU64::new(0),
        }
    }

    /// Hold `s` (the slot is empty)
    pub fn set(&self, s: VmStack) {
        // INVARIANT: a leaked token, held here from now on
        let old = self.base.swap(s.leak(), Ordering::AcqRel);
        assert_eq!(old, 0, "task stack set twice");
    }

    /// The stack, if still held: the slot is empty after
    pub fn take(&self) -> Option<VmStack> {
        // INVARIANT: 0, the stack handed to the caller
        let base = self.base.swap(0, Ordering::AcqRel);
        // SAFETY: a leaked token this slot owned (type invariant), taken
        // out once by the swap
        (base != 0).then(|| unsafe { VmStack::from_base(base) })
    }
}

impl Drop for StackSlot {
    fn drop(&mut self) {
        drop(self.take());
    }
}

/// Allocate a zeroed kernel stack. Thread context (may flush every
/// CPU's TLB).
pub fn alloc() -> Option<VmStack> {
    let slot = take_slot()?;
    let base = slot_base(slot);
    // SAFETY: the stack pages of the slot just taken, ours alone until
    // released
    let mut area = unsafe { VmArea::new(base, STACK_PAGES) };
    for i in 0..STACK_PAGES {
        let mapped = crate::FRAME_ALLOCATOR.alloc().is_some_and(|pa| {
            // SAFETY: a fresh frame, ours, handed to the area
            let ok = unsafe { area.map(i, pa) };
            if !ok {
                crate::FRAME_ALLOCATOR.free(pa);
            }
            ok
        });
        if !mapped {
            unmap(&mut area, i);
            release(slot);
            return None;
        }
    }
    // SAFETY: the pages just mapped
    unsafe { core::ptr::write_bytes(base as *mut u8, 0, THREAD_SIZE) };
    // INVARIANT: the slot's stack pages, all mapped, ours alone
    Some(VmStack(area))
}

/// Unmap and free the first `pages` pages of the stack `area`; this
/// CPU's stale entries go now, the other CPUs' before the slot is reused
fn unmap(area: &mut VmArea, pages: usize) {
    for i in 0..pages {
        if let Some(pa) = area.unmap(i) {
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

/// The base of the stack a fault at `addr` in a guard gap overflowed:
/// the one in the slot above the gap
pub fn overflowed(addr: u64) -> Option<u64> {
    in_guard(addr)
        .then(|| (addr - VMSTACK_START) / SLOT_SIZE * SLOT_SIZE + VMSTACK_START + SLOT_SIZE)
}

/// The bounds of the stack `addr` lies on, if it is one of this area's
/// (mapped or not: a slot's stack part)
pub fn bounds(addr: u64) -> Option<core::ops::Range<u64>> {
    if !contains(addr) || in_guard(addr) {
        return None;
    }
    let base = addr - (addr - VMSTACK_START) % SLOT_SIZE;
    Some(base..base + THREAD_SIZE as u64)
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
        // An overflow below slot 5's stack is slot 5's
        assert_eq!(overflowed(b - 8), Some(b));
        assert_eq!(overflowed(b + THREAD_SIZE as u64), Some(slot_base(6)));
        assert_eq!(overflowed(b), None);
        assert_eq!(bounds(b + 100), Some(b..b + THREAD_SIZE as u64));
        assert_eq!(bounds(b - 8), None);
    }
}

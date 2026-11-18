//! Batched unmapping with one TLB flush (Linux include/asm-generic/tlb.h,
//! mm/mmu_gather.c)
//!
//! A [`Gather`] collects what an unmap releases while it clears entries
//! under the mm lock: the range to flush ([start, end), the smallest
//! stride met, whether page tables were freed) and the frames whose
//! references the cleared entries held. Nothing is released before the
//! flush: a CPU still caching a cleared translation can reach the frame
//! until then, so releasing it first (and the frame reused elsewhere)
//! would be a use after free. The batch is flushed when full and when
//! the gather ends (`Drop`): one munmap of many pages costs one flush
//! per batch instead of one per page. Each flush is one generation of
//! the address space (`mm::tlb`): a CPU already past it skips it, one
//! that missed several flushes everything once.

use super::tlb::{self, PAGE_SHIFT, PMD_SHIFT};
use super::{Mm, PAGE_SIZE};
use crate::arch::{Leaf, paging};
use crate::util::kmem::KVec;

/// Frames the gather itself holds (Linux MMU_GATHER_BUNDLE, the local
/// batch on the stack)
const MMU_GATHER_BUNDLE: usize = 8;

/// Frames a batch page holds (Linux MAX_GATHER_BATCH)
const MAX_GATHER_BATCH: usize = PAGE_SIZE as usize / core::mem::size_of::<Leaf>();

/// Batch pages one gather may chain (Linux MAX_GATHER_BATCH_COUNT:
/// about 10000 frames held back for one flush)
const MAX_GATHER_BATCH_COUNT: usize = 10000 / MAX_GATHER_BATCH;

/// The range a gather flushes: every entry cleared, at the smallest
/// stride met (Linux mmu_gather start/end + cleared_* levels)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FlushRange {
    /// Empty while `start >= end`
    start: u64,
    end: u64,
    /// 4KB or 2MB
    shift: u32,
}

impl FlushRange {
    const EMPTY: Self = Self {
        start: u64::MAX,
        end: 0,
        shift: PMD_SHIFT,
    };

    /// Cover the entry of `size` bytes mapping `va`
    fn add(&mut self, va: u64, size: u64, shift: u32) {
        let va = va & !(size - 1);
        self.start = self.start.min(va);
        self.end = self.end.max(va + size);
        self.shift = self.shift.min(shift);
    }

    fn is_empty(&self) -> bool {
        self.start >= self.end
    }
}

/// An unmap in progress on one address space (Linux struct mmu_gather)
pub struct Gather<'a> {
    mm: &'a Mm,
    range: FlushRange,
    /// Page tables were detached: paging-structure caches must go too
    freed_tables: bool,
    /// The whole address space goes (exit): flush it all
    full: bool,
    /// Frames to release after the flush: the local batch (Linux
    /// tlb->local) ...
    local: [Leaf; MMU_GATHER_BUNDLE],
    n: usize,
    /// ... then the batch pages chained after it, kept until the
    /// gather ends (Linux the list from tlb->local.next); each has a
    /// page of capacity it never grows past
    batches: alloc::vec::Vec<alloc::vec::Vec<Leaf>>,
    /// The batch being filled: 0 the local one, `i` `batches[i - 1]`
    /// (Linux tlb->active)
    active: usize,
    /// Detached page tables to free after the flush (exit)
    tables: Option<paging::UserTables>,
    /// Emptied page-table frames unlinked by munmap, freed after the
    /// flush (Linux tlb_remove_table)
    table_frames: alloc::vec::Vec<u64>,
}

impl<'a> Gather<'a> {
    /// Start unmapping part of `mm` (Linux tlb_gather_mmu)
    pub fn new(mm: &'a Mm) -> Self {
        Self {
            mm,
            range: FlushRange::EMPTY,
            freed_tables: false,
            full: false,
            local: [Leaf::Page(0); MMU_GATHER_BUNDLE],
            n: 0,
            batches: alloc::vec::Vec::new(),
            active: 0,
            tables: None,
            table_frames: alloc::vec::Vec::new(),
        }
    }

    /// Start tearing all of `mm` down (Linux tlb_gather_mmu_fullmm)
    pub fn new_full(mm: &'a Mm) -> Self {
        let mut g = Self::new(mm);
        g.full = true;
        g
    }

    /// The address space being unmapped
    pub fn mm(&self) -> &'a Mm {
        self.mm
    }

    /// The 4KB entry at `va` was cleared; it held a reference on `phys`
    /// (Linux tlb_remove_tlb_entry + __tlb_remove_page)
    pub fn remove_page(&mut self, va: u64, phys: u64) {
        self.range.add(va, PAGE_SIZE, PAGE_SHIFT);
        self.push(Leaf::Page(phys));
    }

    /// The 2MB entry at `va` was cleared; it held a reference on `phys`
    /// (Linux tlb_remove_pmd_tlb_entry)
    pub fn remove_huge(&mut self, va: u64, phys: u64) {
        self.range
            .add(va, super::huge_page::HUGE_PAGE_SIZE, PMD_SHIFT);
        self.push(Leaf::Huge(phys));
    }

    /// The user tables were detached: free them, and what they still
    /// map, after the flush (Linux free_pgtables + tlb_remove_table)
    pub fn free_tables(&mut self, t: paging::UserTables) {
        self.freed_tables = true;
        self.tables = Some(t);
    }

    /// The empty page table `phys` mapping [va, va + size) was unlinked
    /// from its parent: free it after the flush, which then covers the
    /// paging-structure caches (Linux pte_free_tlb / pmd_free_tlb)
    pub fn remove_table(&mut self, va: u64, size: u64, phys: u64) {
        self.freed_tables = true;
        self.range.add(va, size, PMD_SHIFT);
        self.table_frames.push(phys);
    }

    fn push(&mut self, leaf: Leaf) {
        if self.add(leaf) {
            self.flush();
        }
    }

    /// Gather `leaf` into the active batch; true when that filled it and
    /// no next batch can be had: the caller flushes (Linux
    /// __tlb_remove_page_size)
    fn add(&mut self, leaf: Leaf) -> bool {
        let full = match self.active {
            0 => {
                self.local[self.n] = leaf;
                self.n += 1;
                self.n == MMU_GATHER_BUNDLE
            }
            i => {
                let b = &mut self.batches[i - 1];
                // Within the page of capacity: no allocation
                b.push(leaf);
                b.len() == b.capacity()
            }
        };
        full && !self.next_batch()
    }

    /// Make the next batch page active: one kept from an earlier flush,
    /// else a new one, allocated GFP_NOWAIT under the page table lock;
    /// false at MAX_GATHER_BATCH_COUNT or without memory (Linux
    /// tlb_next_batch)
    fn next_batch(&mut self) -> bool {
        if self.active < self.batches.len() {
            self.active += 1;
            return true;
        }
        if self.batches.len() == MAX_GATHER_BATCH_COUNT {
            return false;
        }
        let gfp = crate::mm::page_alloc::Gfp::NOWAIT.with(crate::mm::page_alloc::Gfp::NOWARN);
        let b = crate::util::kalloc::with_gfp(gfp, || {
            if self.batches.capacity() == 0 {
                // The chain's slots, once: pushes below then never
                // allocate (Linux links the pages themselves)
                self.batches = KVec::try_with_capacity(MAX_GATHER_BATCH_COUNT)?.into_vec();
            }
            KVec::try_with_capacity(MAX_GATHER_BATCH)
        });
        let Ok(b) = b else {
            return false;
        };
        self.batches.push(b.into_vec());
        self.active += 1;
        true
    }

    /// Flush the TLB for what was gathered, then release it (Linux
    /// tlb_flush_mmu)
    pub fn flush(&mut self) {
        let r = core::mem::replace(&mut self.range, FlushRange::EMPTY);
        if self.full {
            tlb::flush_tlb_mm(self.mm);
        } else if !r.is_empty() {
            tlb::flush_tlb_mm_range(self.mm, r.start, r.end, r.shift, self.freed_tables);
        }
        // Linux tlb_batch_pages_flush: every batch from the local one,
        // then the first active again
        for &leaf in &self.local[..self.n] {
            super::memory::zap_leaf(leaf);
        }
        self.n = 0;
        for b in &mut self.batches {
            for leaf in b.drain(..) {
                super::memory::zap_leaf(leaf);
            }
        }
        self.active = 0;
        for t in self.table_frames.drain(..) {
            crate::FRAME_ALLOCATOR.free(t);
        }
        if let Some(t) = self.tables.take() {
            t.free(&mut super::memory::zap_leaf);
        }
    }
}

impl Drop for Gather<'_> {
    /// Linux tlb_finish_mmu
    fn drop(&mut self) {
        self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::super::huge_page::HUGE_PAGE_SIZE;
    use super::*;

    #[test]
    fn range_covers_every_entry() {
        let mut r = FlushRange::EMPTY;
        assert!(r.is_empty());
        r.add(0x5000, PAGE_SIZE, PAGE_SHIFT);
        r.add(0x2000, PAGE_SIZE, PAGE_SHIFT);
        r.add(0x9fff, PAGE_SIZE, PAGE_SHIFT);
        let want = FlushRange {
            start: 0x2000,
            end: 0xa000,
            shift: PAGE_SHIFT,
        };
        assert_eq!(r, want);
    }

    #[test]
    fn huge_entries_widen_to_their_page() {
        let mut r = FlushRange::EMPTY;
        r.add(0x40_1234, HUGE_PAGE_SIZE, PMD_SHIFT);
        assert_eq!((r.start, r.end, r.shift), (0x40_0000, 0x60_0000, PMD_SHIFT));
        // A 4KB entry: the stride drops to 4KB for the whole range
        r.add(0x70_0000, PAGE_SIZE, PAGE_SHIFT);
        assert_eq!(
            (r.start, r.end, r.shift),
            (0x40_0000, 0x70_1000, PAGE_SHIFT)
        );
    }
}

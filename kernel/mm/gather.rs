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

/// Frames held back for one flush (Linux MAX_GATHER_BATCH, smaller:
/// the gather lives on the kernel stack)
const BATCH: usize = 64;

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
    /// Frames to release after the flush
    batch: [Leaf; BATCH],
    n: usize,
    /// Detached page tables to free after the flush (exit)
    tables: Option<paging::UserTables>,
}

impl<'a> Gather<'a> {
    /// Start unmapping part of `mm` (Linux tlb_gather_mmu)
    pub fn new(mm: &'a Mm) -> Self {
        Self {
            mm,
            range: FlushRange::EMPTY,
            freed_tables: false,
            full: false,
            batch: [Leaf::Page(0); BATCH],
            n: 0,
            tables: None,
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

    fn push(&mut self, leaf: Leaf) {
        if self.n == BATCH {
            self.flush();
        }
        self.batch[self.n] = leaf;
        self.n += 1;
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
        for &leaf in &self.batch[..self.n] {
            super::memory::zap_leaf(leaf);
        }
        self.n = 0;
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

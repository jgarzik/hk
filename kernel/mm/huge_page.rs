//! Transparent Huge Page (THP) support
//!
//! Provides 2MB huge page allocation and mapping for anonymous mappings.
//! This module contains cross-platform utilities used by both x86-64 and aarch64
//! page fault handlers.

use super::vma::Vma;

/// 2MB huge page size
pub const HUGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;

/// 2MB alignment mask (for addr & HUGE_PAGE_MASK == offset within huge page)
pub const HUGE_PAGE_MASK: u64 = HUGE_PAGE_SIZE - 1;

/// Number of 4KB pages in a 2MB huge page
pub const PAGES_PER_HUGE_PAGE: usize = 512;

/// 4KB page size
pub const PAGE_SIZE: u64 = 4096;

/// Check if an address is 2MB-aligned
#[inline]
pub fn is_huge_aligned(addr: u64) -> bool {
    addr & HUGE_PAGE_MASK == 0
}

/// Round down to 2MB boundary
#[inline]
pub fn huge_page_align_down(addr: u64) -> u64 {
    addr & !HUGE_PAGE_MASK
}

/// Round up to 2MB boundary
#[inline]
pub fn huge_page_align_up(addr: u64) -> u64 {
    (addr + HUGE_PAGE_MASK) & !HUGE_PAGE_MASK
}

/// Determine if a page fault should try to allocate a huge page
///
/// Returns the 2MB-aligned base address if THP should be attempted, or None if:
/// - VMA is not THP-eligible (not anonymous private, or prohibited)
/// - VMA doesn't fully cover the 2MB region around the fault address
/// - The region is too small for a huge page
///
/// # Arguments
/// * `vma` - The VMA containing the fault address
/// * `fault_addr` - The address that caused the page fault
///
/// # Returns
/// * `Some(base_addr)` - The 2MB-aligned base address to map
/// * `None` - THP should not be attempted
pub fn should_try_huge_page(vma: &Vma, fault_addr: u64) -> Option<u64> {
    // Must be THP-eligible (anonymous private with VM_HUGEPAGE)
    if !vma.is_thp_eligible() {
        return None;
    }

    // Calculate the 2MB-aligned region containing this fault
    let huge_base = huge_page_align_down(fault_addr);
    let huge_end = huge_base + HUGE_PAGE_SIZE;

    // VMA must fully contain the 2MB region
    if vma.start > huge_base || vma.end < huge_end {
        return None;
    }

    Some(huge_base)
}

/// Check if a range can potentially use huge pages
///
/// Returns true if the range is large enough and properly aligned
/// for at least one huge page mapping.
#[inline]
pub fn can_use_huge_pages(start: u64, end: u64) -> bool {
    // Range must be at least 2MB
    if end - start < HUGE_PAGE_SIZE {
        return false;
    }

    // Check if there's at least one 2MB-aligned region within the range
    let aligned_start = huge_page_align_up(start);
    aligned_start + HUGE_PAGE_SIZE <= end
}

/// Calculate the number of complete huge pages that fit in a range
#[inline]
pub fn huge_pages_in_range(start: u64, end: u64) -> usize {
    if end <= start {
        return 0;
    }

    let aligned_start = huge_page_align_up(start);
    let aligned_end = huge_page_align_down(end);

    if aligned_end <= aligned_start {
        return 0;
    }

    ((aligned_end - aligned_start) / HUGE_PAGE_SIZE) as usize
}

/// Check if an address falls within a huge page mapping
///
/// Given a huge page base address and a target address, returns true
/// if the target is within the 2MB region.
#[inline]
pub fn is_within_huge_page(huge_base: u64, addr: u64) -> bool {
    addr >= huge_base && addr < huge_base + HUGE_PAGE_SIZE
}

/// Get the offset of an address within its containing huge page
#[inline]
pub fn offset_in_huge_page(addr: u64) -> u64 {
    addr & HUGE_PAGE_MASK
}

/// A 2MB entry in the middle of a split (Linux pmdp_invalidate's
/// invalid-but-not-none entry): invalid to the MMU on both arches (bit
/// 0 clear), neither a block nor a table to software. Lockless walkers
/// that meet it wait for the split, which holds the page_table_lock
/// from writing it until the PTE table replaces it, rather than taking
/// the slot for empty and missing the 4KB entries about to appear.
pub const PMD_SPLITTING: u64 = 0b10;

/// The value of the 2MB-level entry `pmd` once no split is under way
pub fn pmd_settled(pmd: &core::sync::atomic::AtomicU64) -> u64 {
    use core::sync::atomic::Ordering;
    loop {
        let v = pmd.load(Ordering::Acquire);
        if v != PMD_SPLITTING {
            return v;
        }
        core::hint::spin_loop();
    }
}

/// The 2MB-level entry at `p`, as an atomic
fn pmd_entry(p: *mut u64) -> &'static core::sync::atomic::AtomicU64 {
    // SAFETY: `p` points into a live page table of the locked mm
    unsafe { core::sync::atomic::AtomicU64::from_ptr(p) }
}

/// Split the 2MB page mapping `va` in `mm` into 512 4KB entries (Linux
/// __split_huge_pmd_locked), mm lock held; takes the page_table_lock
/// (a racing fault may split or map at the same time). The page table
/// is allocated first, so a failure (ENOMEM) changes nothing. Then break before
/// make (Linux pmdp_invalidate): the 2MB entry becomes `PMD_SPLITTING`
/// and is flushed on every CPU before the table replaces it, so no CPU
/// caches a 2MB and a 4KB translation of one address at once (ARM ARM
/// D8.16, Intel SDM 4.10.2.3); accessed/dirty bits set until then are
/// kept. Each 4KB frame gets the head's reference count.
///
/// Returns the physical base of the split page; None if `va` is not
/// mapped by a 2MB page or out of memory.
pub fn split_huge_pmd(mm: &super::Mm, va: u64) -> Option<u64> {
    use crate::arch::paging;
    use core::sync::atomic::Ordering;
    let pmdp = paging::pmd_ptr(mm.pgd(), va)?;
    if !paging::pmd_huge(pmd_entry(pmdp).load(Ordering::Acquire)) {
        return None;
    }
    let pt = crate::FRAME_ALLOCATOR.alloc()?;
    let _l = super::ptl::pt_lock(mm);
    let Some(old) = clear_huge(pmd_entry(pmdp), PMD_SPLITTING) else {
        crate::FRAME_ALLOCATOR.free(pt);
        return None;
    };
    // All levels (Linux flush_pmd_tlb_range): a table replaces the block
    flush_huge(mm, va);
    // The hardware may have set accessed/dirty until the clear: `old`
    // is the value cleared
    let base = paging::split_table(pt, old);
    paging::pmd_populate(pmdp, pt);
    crate::FRAME_ALLOCATOR.split_huge(base);
    split_rmap(base);
    Some(base)
}

/// The 512 pages of a split anonymous 2MB page each take the head's
/// mapping (an AnonVma reference each), their own index and one
/// mapping, and join the LRU (Linux __split_huge_page_tail,
/// lru_add_split_folio)
fn split_rmap(base: u64) {
    use crate::mm::page::phys_to_page;
    use core::sync::atomic::Ordering;
    let Some(head) = phys_to_page(base) else {
        return;
    };
    let Some(av) = head.get_anon_vma() else {
        return;
    };
    let index = head.index.load(Ordering::Relaxed);
    let maps = head.mapcount();
    for i in 0..PAGES_PER_HUGE_PAGE as u64 {
        let phys = base + i * PAGE_SIZE;
        if let Some(pg) = phys_to_page(phys)
            && i > 0
        {
            pg.set_anon_mapping(&av);
            pg.index.store(index + i, Ordering::Relaxed);
            pg.mapcount.store(maps, Ordering::Relaxed);
        }
        crate::mm::lru::lru_add(phys);
    }
}

/// Clear the 2MB page entry for `base` in `mm` (Linux zap_huge_pmd), mm
/// lock held, under the page_table_lock; the caller flushes it (`Gather`) before releasing the
/// returned frame, which still holds the mapping's reference.
pub fn take_huge_pmd(mm: &super::Mm, base: u64) -> Option<u64> {
    use crate::arch::paging;
    let pmd = pmd_entry(paging::pmd_ptr(mm.pgd(), base)?);
    let _l = super::ptl::pt_lock(mm);
    let old = clear_huge(pmd, 0)?;
    Some(paging::pte_addr(old) & !HUGE_PAGE_MASK)
}

/// Replace a 2MB page entry with `with` (0, or `PMD_SPLITTING`),
/// page_table_lock held (Linux pmdp_huge_get_and_clear,
/// pmdp_invalidate): the value replaced, None if it maps no 2MB page.
/// An exchange, not a compare-and-swap: the MMU may set the
/// accessed/dirty bits at any time, but only software turns a 2MB entry
/// into something else, and every software writer of one holds the
/// page_table_lock or the mmap_lock for writing (excluding the caller).
fn clear_huge(pmd: &core::sync::atomic::AtomicU64, with: u64) -> Option<u64> {
    use core::sync::atomic::Ordering;
    if !crate::arch::paging::pmd_huge(pmd.load(Ordering::Acquire)) {
        return None;
    }
    let old = pmd.swap(with, Ordering::AcqRel);
    debug_assert!(crate::arch::paging::pmd_huge(old));
    Some(old)
}

/// Flush the 2MB page translation at `va` of `mm`, paging-structure
/// caches too
fn flush_huge(mm: &super::Mm, va: u64) {
    use super::tlb::{PMD_SHIFT, flush_tlb_mm_range};
    let base = huge_page_align_down(va);
    flush_tlb_mm_range(mm, base, base + HUGE_PAGE_SIZE, PMD_SHIFT, true);
}

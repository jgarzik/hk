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

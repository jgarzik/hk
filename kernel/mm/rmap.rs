//! Reverse mapping - find all PTEs for a physical page
//!
//! Implements rmap_walk functionality for hk kernel, following Linux's design.
//!
//! For anonymous pages, we use the page's anon_vma to find all VMAs that might
//! contain mappings, then walk each VMA's page table to find the actual PTEs.
//!
//! ## Key Functions
//!
//! - `rmap_walk(frame_phys)` - Find all PTEs mapping a physical frame
//! - `try_to_unmap(frame_phys, swap_entry)` - Replace all PTEs with swap entry
//!
//! ## Locking Order
//!
//! 1. PAGE_DESCRIPTORS (read)
//! 2. AnonVma lock
//! 3. Page table access (no lock, but we flush TLB)
//!
//! Chains name the address space by its top-level table; exit_mmap and
//! munmap drop an address space's chains before freeing its tables.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::mm::anon_vma::AnonVma;
use crate::mm::page::{PG_ANON, page_descriptor};
use crate::mm::swap_entry::SwapEntry;

use core::sync::atomic::Ordering;

// ============================================================================
// PTE Mapping Result
// ============================================================================

/// Result of finding a PTE for a page
#[derive(Debug, Clone)]
pub struct PteMapping {
    /// Virtual address of the mapping
    pub vaddr: u64,
    /// Page table root physical address (CR3 on x86-64, TTBR0 on aarch64)
    pub pt_root: u64,
}

// ============================================================================
// rmap_walk
// ============================================================================

/// Walk all PTEs mapping the given physical frame
///
/// For anonymous pages, uses the page's anon_vma to find all VMAs,
/// then walks each VMA's page table to find PTEs.
///
/// For file-backed pages, we would use the address_space's i_mmap tree,
/// but currently we don't support swap for file pages.
///
/// # Arguments
/// * `frame_phys` - Physical address of the frame (page-aligned)
///
/// # Returns
/// Vector of PteMapping describing all mappings found
pub fn rmap_walk(frame_phys: u64) -> Vec<PteMapping> {
    let mut results = Vec::new();

    // Get page descriptor
    let page = match page_descriptor(frame_phys) {
        Some(p) => p,
        None => return results,
    };

    // Only handle anonymous pages (file pages use page cache eviction)
    if !page.is_anon() {
        return results;
    }

    // Get anon_vma from page descriptor
    let anon_vma = match page.get_anon_vma() {
        Some(av) => av,
        None => return results,
    };

    // Get all VMAs in this anon_vma
    let vmas = anon_vma.get_vmas();

    // Check each VMA for mappings to this frame
    for chain in vmas {
        if let Some(mapping) =
            check_vma_for_page(chain.root, chain.vma_start, chain.vma_end, frame_phys)
        {
            results.push(mapping);
        }
    }

    results
}

/// Check if a VMA contains a mapping to the given physical frame
///
/// Walks the page table for each page in the VMA range until we find
/// one that maps to our target frame.
fn check_vma_for_page(
    pt_root: u64,
    vma_start: u64,
    vma_end: u64,
    frame_phys: u64,
) -> Option<PteMapping> {
    // Walk pages in VMA to find one mapping our frame
    let mut addr = vma_start;
    while addr < vma_end {
        if let Some(phys) = translate_addr(pt_root, addr) {
            let phys_page = phys & !0xFFF;
            if phys_page == frame_phys {
                return Some(PteMapping {
                    vaddr: addr,
                    pt_root,
                });
            }
        }
        addr += 4096;
    }

    None
}

/// Find all mappings in a specific task for a given physical frame
///
/// Used when we need to unmap a page from a specific task.
#[allow(dead_code)]
pub fn rmap_walk_anon_vma(anon_vma: &Arc<AnonVma>, frame_phys: u64) -> Vec<PteMapping> {
    let mut results = Vec::new();

    let vmas = anon_vma.get_vmas();

    for chain in vmas {
        if let Some(mapping) =
            check_vma_for_page(chain.root, chain.vma_start, chain.vma_end, frame_phys)
        {
            results.push(mapping);
        }
    }

    results
}

// ============================================================================
// try_to_unmap
// ============================================================================

/// Unmap a page from all processes and replace PTEs with swap entry
///
/// This is the core swap-out operation:
/// 1. Find all PTEs via rmap_walk
/// 2. For each PTE, atomically replace with swap entry
/// 3. Flush TLB on each CPU
/// 4. Decrement page mapcount
///
/// # Arguments
/// * `frame_phys` - Physical address of the frame to unmap
/// * `swap_entry` - Swap entry to write into the PTEs
///
/// # Returns
/// Number of PTEs successfully unmapped
pub fn try_to_unmap(frame_phys: u64, swap_entry: SwapEntry) -> usize {
    let mappings = rmap_walk(frame_phys);
    let mut unmapped = 0;

    for mapping in mappings {
        if replace_pte_with_swap(mapping.pt_root, mapping.vaddr, frame_phys, swap_entry).is_ok() {
            unmapped += 1;
            // Decrement mapcount
            if let Some(page) = page_descriptor(frame_phys) {
                page.dec_mapcount();
            }
        }
    }

    unmapped
}

/// Unmap a page from all processes (without swap entry - just clear PTE)
///
/// Used for MADV_DONTNEED and similar operations where we just want
/// to free the page without swapping.
#[allow(dead_code)]
pub fn try_to_unmap_clear(frame_phys: u64) -> usize {
    let mappings = rmap_walk(frame_phys);
    let mut unmapped = 0;

    for mapping in mappings {
        if clear_pte(mapping.pt_root, mapping.vaddr, frame_phys).is_ok() {
            unmapped += 1;
            if let Some(page) = page_descriptor(frame_phys) {
                page.dec_mapcount();
            }
        }
    }

    unmapped
}

// ============================================================================
// Architecture-specific helpers
// ============================================================================

/// Translate a virtual address using a specific page table root
#[cfg(target_arch = "x86_64")]
fn translate_addr(pt_root: u64, vaddr: u64) -> Option<u64> {
    crate::arch::x86_64::paging::X86_64PageTable::translate_with_root(pt_root, vaddr)
}

#[cfg(target_arch = "aarch64")]
fn translate_addr(pt_root: u64, vaddr: u64) -> Option<u64> {
    crate::arch::aarch64::paging::Aarch64PageTable::translate_with_root(pt_root, vaddr)
}

/// The present leaf PTE for `vaddr` if it maps `expected_phys`
fn mapped_pte(pt_root: u64, vaddr: u64, expected_phys: u64) -> Result<*mut u64, ()> {
    use crate::arch::paging::{PTE_ADDR_MASK, pte_present, pte_ptr};
    let p = pte_ptr(pt_root, vaddr).ok_or(())?;
    let pte = unsafe { core::ptr::read_volatile(p) };
    if pte_present(pte) && pte & PTE_ADDR_MASK == expected_phys {
        Ok(p)
    } else {
        Err(())
    }
}

/// Replace the PTE mapping `expected_phys` at `vaddr` with a swap entry
fn replace_pte_with_swap(
    pt_root: u64,
    vaddr: u64,
    expected_phys: u64,
    swap_entry: SwapEntry,
) -> Result<(), ()> {
    let p = mapped_pte(pt_root, vaddr, expected_phys)?;
    unsafe { core::ptr::write_volatile(p, swap_entry.to_pte()) };
    crate::arch::paging::flush_tlb(vaddr);
    Ok(())
}

/// Clear the PTE mapping `expected_phys` at `vaddr`
fn clear_pte(pt_root: u64, vaddr: u64, expected_phys: u64) -> Result<(), ()> {
    let p = mapped_pte(pt_root, vaddr, expected_phys)?;
    unsafe { core::ptr::write_volatile(p, 0) };
    crate::arch::paging::flush_tlb(vaddr);
    Ok(())
}

// ============================================================================
// Page registration helpers
// ============================================================================

/// Register a page as anonymous with an anon_vma
///
/// Called from page fault handler when allocating a new anonymous page.
/// Sets up the page descriptor for reverse mapping lookups.
///
/// # Arguments
/// * `frame_phys` - Physical address of the allocated frame
/// * `anon_vma` - The VMA's anon_vma for reverse mapping
/// * `vaddr` - Virtual address (stored in page->index for debugging)
pub fn page_add_anon_rmap(frame_phys: u64, anon_vma: &Arc<AnonVma>, vaddr: u64) {
    if let Some(page) = page_descriptor(frame_phys) {
        page.set_flag(PG_ANON);
        page.set_anon_mapping(anon_vma);
        page.index.store(vaddr, Ordering::Relaxed);
        page.inc_mapcount();
    }
}

/// Remove page from reverse mapping (called when page is freed)
///
/// Clears the page descriptor's mapping and flags.
pub fn page_remove_rmap(frame_phys: u64) {
    if let Some(page) = page_descriptor(frame_phys) {
        let old_mapcount = page.dec_mapcount();
        if old_mapcount == 0 {
            // Last mapping removed
            page.clear_mapping();
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pte_mapping_struct() {
        let mapping = PteMapping {
            vaddr: 0x1000,
            pt_root: 0x2000,
        };

        assert_eq!(mapping.vaddr, 0x1000);
        assert_eq!(mapping.pt_root, 0x2000);
    }
}

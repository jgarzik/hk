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
//! 3. TASK_TABLE lock
//! 4. MmStruct lock (per-task)
//! 5. Page table access (no lock, but we flush TLB)

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::mm::anon_vma::AnonVma;
use crate::mm::page::{PG_ANON, page_descriptor};
use crate::mm::swap_entry::SwapEntry;
use crate::task::Tid;
use crate::task::percpu::TASK_TABLE;

use core::sync::atomic::Ordering;

// ============================================================================
// PTE Mapping Result
// ============================================================================

/// Result of finding a PTE for a page
#[derive(Debug, Clone)]
pub struct PteMapping {
    /// Task ID owning the mapping
    pub tid: Tid,
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
            check_vma_for_page(chain.tid, chain.vma_start, chain.vma_end, frame_phys)
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
    tid: Tid,
    vma_start: u64,
    vma_end: u64,
    frame_phys: u64,
) -> Option<PteMapping> {
    // Get the task's page table root
    let pt_root = {
        let table = TASK_TABLE.lock();
        let task = table.tasks.iter().find(|t| t.tid == tid)?;
        task.page_table.root_table_phys()
    };

    // Walk pages in VMA to find one mapping our frame
    let mut addr = vma_start;
    while addr < vma_end {
        if let Some(phys) = translate_addr(pt_root, addr) {
            let phys_page = phys & !0xFFF;
            if phys_page == frame_phys {
                return Some(PteMapping {
                    tid,
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
            check_vma_for_page(chain.tid, chain.vma_start, chain.vma_end, frame_phys)
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

/// Replace a present PTE with a swap entry
#[cfg(target_arch = "x86_64")]
fn replace_pte_with_swap(
    pt_root: u64,
    vaddr: u64,
    expected_phys: u64,
    swap_entry: SwapEntry,
) -> Result<(), ()> {
    use crate::arch::x86_64::paging::PAGE_PRESENT;

    // Get page table indices
    let pml4_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let pd_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let pt_idx = ((vaddr >> 12) & 0x1FF) as usize;

    const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

    unsafe {
        // Walk to PT level
        let pml4 = pt_root as *const u64;
        let pml4_entry = *pml4.add(pml4_idx);
        if pml4_entry & PAGE_PRESENT == 0 {
            return Err(());
        }

        let pdpt = (pml4_entry & ADDR_MASK) as *const u64;
        let pdpt_entry = *pdpt.add(pdpt_idx);
        if pdpt_entry & PAGE_PRESENT == 0 {
            return Err(());
        }

        let pd = (pdpt_entry & ADDR_MASK) as *const u64;
        let pd_entry = *pd.add(pd_idx);
        if pd_entry & PAGE_PRESENT == 0 {
            return Err(());
        }

        // Get PTE
        let pt = (pd_entry & ADDR_MASK) as *mut u64;
        let pte_ptr = pt.add(pt_idx);
        let pte_value = *pte_ptr;

        // Verify it's present and points to expected frame
        if pte_value & PAGE_PRESENT == 0 {
            return Err(());
        }
        if (pte_value & ADDR_MASK) != expected_phys {
            return Err(());
        }

        // Atomically replace PTE with swap entry
        core::ptr::write_volatile(pte_ptr, swap_entry.to_pte());

        // Flush TLB for this address
        core::arch::asm!(
            "invlpg [{}]",
            in(reg) vaddr,
            options(nostack, preserves_flags)
        );

        Ok(())
    }
}

#[cfg(target_arch = "aarch64")]
fn replace_pte_with_swap(
    pt_root: u64,
    vaddr: u64,
    expected_phys: u64,
    swap_entry: SwapEntry,
) -> Result<(), ()> {
    // Table descriptor: bits [1:0] = 0b11
    const TABLE_DESC: u64 = 0b11;
    // Page descriptor: bits [1:0] = 0b11, but we check valid bit
    const VALID_BIT: u64 = 0b01;
    const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

    let l0_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let l1_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let l2_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let l3_idx = ((vaddr >> 12) & 0x1FF) as usize;

    unsafe {
        // Walk to L3 level
        let l0 = pt_root as *const u64;
        let l0_entry = *l0.add(l0_idx);
        if (l0_entry & 0b11) != TABLE_DESC {
            return Err(());
        }

        let l1 = (l0_entry & ADDR_MASK) as *const u64;
        let l1_entry = *l1.add(l1_idx);
        if (l1_entry & 0b11) != TABLE_DESC {
            return Err(());
        }

        let l2 = (l1_entry & ADDR_MASK) as *const u64;
        let l2_entry = *l2.add(l2_idx);
        if (l2_entry & 0b11) != TABLE_DESC {
            return Err(());
        }

        // Get L3 PTE
        let l3 = (l2_entry & ADDR_MASK) as *mut u64;
        let pte_ptr = l3.add(l3_idx);
        let pte_value = *pte_ptr;

        // Verify it's valid and points to expected frame
        if pte_value & VALID_BIT == 0 {
            return Err(());
        }
        if (pte_value & ADDR_MASK) != expected_phys {
            return Err(());
        }

        // Atomically replace PTE with swap entry
        core::ptr::write_volatile(pte_ptr, swap_entry.to_pte());

        // TLB invalidation for this address
        core::arch::asm!(
            "dsb ishst",            // Ensure PTE write completes
            "tlbi vale1is, {0}",    // Invalidate TLB entry
            "dsb ish",              // Wait for invalidation
            "isb",                  // Synchronize
            in(reg) vaddr >> 12,    // VA in pages
            options(nostack)
        );

        Ok(())
    }
}

/// Clear a PTE (set to 0)
#[cfg(target_arch = "x86_64")]
fn clear_pte(pt_root: u64, vaddr: u64, expected_phys: u64) -> Result<(), ()> {
    use crate::arch::x86_64::paging::PAGE_PRESENT;

    let pml4_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let pd_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let pt_idx = ((vaddr >> 12) & 0x1FF) as usize;

    const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

    unsafe {
        let pml4 = pt_root as *const u64;
        let pml4_entry = *pml4.add(pml4_idx);
        if pml4_entry & PAGE_PRESENT == 0 {
            return Err(());
        }

        let pdpt = (pml4_entry & ADDR_MASK) as *const u64;
        let pdpt_entry = *pdpt.add(pdpt_idx);
        if pdpt_entry & PAGE_PRESENT == 0 {
            return Err(());
        }

        let pd = (pdpt_entry & ADDR_MASK) as *const u64;
        let pd_entry = *pd.add(pd_idx);
        if pd_entry & PAGE_PRESENT == 0 {
            return Err(());
        }

        let pt = (pd_entry & ADDR_MASK) as *mut u64;
        let pte_ptr = pt.add(pt_idx);
        let pte_value = *pte_ptr;

        if pte_value & PAGE_PRESENT == 0 {
            return Err(());
        }
        if (pte_value & ADDR_MASK) != expected_phys {
            return Err(());
        }

        core::ptr::write_volatile(pte_ptr, 0);

        core::arch::asm!(
            "invlpg [{}]",
            in(reg) vaddr,
            options(nostack, preserves_flags)
        );

        Ok(())
    }
}

#[cfg(target_arch = "aarch64")]
fn clear_pte(pt_root: u64, vaddr: u64, expected_phys: u64) -> Result<(), ()> {
    const TABLE_DESC: u64 = 0b11;
    const VALID_BIT: u64 = 0b01;
    const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

    let l0_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let l1_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let l2_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let l3_idx = ((vaddr >> 12) & 0x1FF) as usize;

    unsafe {
        let l0 = pt_root as *const u64;
        let l0_entry = *l0.add(l0_idx);
        if (l0_entry & 0b11) != TABLE_DESC {
            return Err(());
        }

        let l1 = (l0_entry & ADDR_MASK) as *const u64;
        let l1_entry = *l1.add(l1_idx);
        if (l1_entry & 0b11) != TABLE_DESC {
            return Err(());
        }

        let l2 = (l1_entry & ADDR_MASK) as *const u64;
        let l2_entry = *l2.add(l2_idx);
        if (l2_entry & 0b11) != TABLE_DESC {
            return Err(());
        }

        let l3 = (l2_entry & ADDR_MASK) as *mut u64;
        let pte_ptr = l3.add(l3_idx);
        let pte_value = *pte_ptr;

        if pte_value & VALID_BIT == 0 {
            return Err(());
        }
        if (pte_value & ADDR_MASK) != expected_phys {
            return Err(());
        }

        core::ptr::write_volatile(pte_ptr, 0);

        core::arch::asm!(
            "dsb ishst",
            "tlbi vale1is, {0}",
            "dsb ish",
            "isb",
            in(reg) vaddr >> 12,
            options(nostack)
        );

        Ok(())
    }
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
            tid: 1,
            vaddr: 0x1000,
            pt_root: 0x2000,
        };

        assert_eq!(mapping.tid, 1);
        assert_eq!(mapping.vaddr, 0x1000);
        assert_eq!(mapping.pt_root, 0x2000);
    }
}

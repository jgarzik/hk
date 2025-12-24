//! ioremap - MMIO virtual address space management for aarch64
//!
//! Provides Linux-like ioremap/iounmap functions for mapping physical
//! MMIO regions to kernel virtual addresses. Uses a dedicated virtual
//! address region separate from the identity-mapped boot region.
//!
//! Note: For addresses in the boot identity-mapped device region (0-1GB),
//! we simply return the physical address since it's already mapped with
//! device attributes. For other addresses, we allocate from the ioremap
//! region and create proper mappings.

use core::arch::asm;
use spin::Mutex;

use super::paging::{
    AF, AP_EL1_RW, ATTR_IDX_DEVICE, PAGE_SIZE, PXN, PageTableEntry, SH_INNER, UXN, flush_tlb,
    phys_to_virt, phys_to_virt_table, phys_to_virt_table_const,
};

/// ioremap region base (3GB - outside identity-mapped 0-2GB)
pub const IOREMAP_BASE: u64 = 0xC000_0000;

/// ioremap region end (3.25GB)
pub const IOREMAP_END: u64 = 0xD000_0000;

/// Total size of ioremap region (256MB)
pub const IOREMAP_SIZE: u64 = IOREMAP_END - IOREMAP_BASE;

/// Number of 4KB pages in ioremap region
const IOREMAP_PAGES: usize = (IOREMAP_SIZE / PAGE_SIZE) as usize;

/// Bitmap array size (64 bits per u64)
const BITMAP_SIZE: usize = IOREMAP_PAGES.div_ceil(64);

/// Device memory page attributes
const DEVICE_PAGE_ATTRS: u64 = AF | SH_INNER | ATTR_IDX_DEVICE | AP_EL1_RW | PXN | UXN;

/// Boot device region end (already identity-mapped with device attributes)
const BOOT_DEVICE_END: u64 = 0x4000_0000; // First 1GB

/// ioremap error types
#[derive(Debug, Clone, Copy)]
pub enum IoremapError {
    /// No contiguous virtual address space available
    OutOfVirtualSpace,
    /// Failed to allocate frame for page tables
    FrameAllocationFailed,
    /// Invalid size (zero or too large)
    InvalidSize,
}

/// Global ioremap allocator
static IOREMAP: Mutex<IoremapAllocator> = Mutex::new(IoremapAllocator::new());

/// Bitmap-based virtual address allocator for ioremap region
struct IoremapAllocator {
    /// Bitmap: 0 = free, 1 = used
    bitmap: [u64; BITMAP_SIZE],
    /// Whether initialized
    initialized: bool,
    /// Hint for next allocation search
    next_free: usize,
}

impl IoremapAllocator {
    /// Create a new uninitialized allocator
    const fn new() -> Self {
        Self {
            bitmap: [0; BITMAP_SIZE],
            initialized: false,
            next_free: 0,
        }
    }

    /// Initialize the allocator (mark all pages as free)
    fn init(&mut self) {
        self.bitmap = [0; BITMAP_SIZE];
        self.initialized = true;
        self.next_free = 0;
    }

    /// Allocate a contiguous range of virtual pages
    fn alloc(&mut self, num_pages: usize) -> Option<u64> {
        if !self.initialized || num_pages == 0 || num_pages > IOREMAP_PAGES {
            return None;
        }

        // First-fit search starting from hint
        let start_page = self.next_free;

        // Search from hint to end
        if let Some(page) = self.find_free_range(start_page, IOREMAP_PAGES, num_pages) {
            self.mark_range_used(page, num_pages);
            self.next_free = (page + num_pages) % IOREMAP_PAGES;
            return Some(IOREMAP_BASE + (page as u64) * PAGE_SIZE);
        }

        // Wrap around and search from beginning
        if start_page > 0
            && let Some(page) = self.find_free_range(0, start_page, num_pages)
        {
            self.mark_range_used(page, num_pages);
            self.next_free = (page + num_pages) % IOREMAP_PAGES;
            return Some(IOREMAP_BASE + (page as u64) * PAGE_SIZE);
        }

        None
    }

    /// Find a contiguous free range within [start, end)
    fn find_free_range(&self, start: usize, end: usize, count: usize) -> Option<usize> {
        let mut consecutive = 0;
        let mut range_start = start;

        for page in start..end {
            if self.is_free(page) {
                if consecutive == 0 {
                    range_start = page;
                }
                consecutive += 1;
                if consecutive >= count {
                    return Some(range_start);
                }
            } else {
                consecutive = 0;
            }
        }
        None
    }

    /// Mark a range of pages as used
    fn mark_range_used(&mut self, start: usize, count: usize) {
        for i in 0..count {
            self.set_used(start + i);
        }
    }

    /// Free a range of pages
    fn free(&mut self, virt_addr: u64, num_pages: usize) {
        if !(IOREMAP_BASE..IOREMAP_END).contains(&virt_addr) {
            return;
        }

        let start_page = ((virt_addr - IOREMAP_BASE) / PAGE_SIZE) as usize;
        for i in 0..num_pages {
            let page = start_page + i;
            if page < IOREMAP_PAGES {
                self.set_free(page);
            }
        }

        if start_page < self.next_free {
            self.next_free = start_page;
        }
    }

    fn is_free(&self, page: usize) -> bool {
        let word = page / 64;
        let bit = page % 64;
        (self.bitmap[word] & (1u64 << bit)) == 0
    }

    fn set_used(&mut self, page: usize) {
        let word = page / 64;
        let bit = page % 64;
        self.bitmap[word] |= 1u64 << bit;
    }

    fn set_free(&mut self, page: usize) {
        let word = page / 64;
        let bit = page % 64;
        self.bitmap[word] &= !(1u64 << bit);
    }
}

/// Initialize the ioremap subsystem
pub fn init() {
    IOREMAP.lock().init();
    crate::printkln!(
        "ioremap: initialized region {:#x}-{:#x} ({} pages)",
        IOREMAP_BASE,
        IOREMAP_END,
        IOREMAP_PAGES
    );
}

/// Map a physical MMIO region to kernel virtual address space
///
/// For addresses in the boot identity-mapped device region (0-1GB),
/// returns the physical address directly (already mapped with device attrs).
/// For other addresses, allocates from the ioremap region.
pub fn ioremap(phys_addr: u64, size: u64) -> Result<*mut u8, IoremapError> {
    if size == 0 {
        return Err(IoremapError::InvalidSize);
    }

    // For addresses in the boot device region, use identity mapping
    // The boot page tables already map 0-1GB with device memory attributes
    if (phys_addr + size) <= BOOT_DEVICE_END {
        return Ok(phys_addr as *mut u8);
    }

    // For other addresses, allocate from ioremap region and map
    let offset = phys_addr & (PAGE_SIZE - 1);
    let aligned_phys = phys_addr & !(PAGE_SIZE - 1);
    let aligned_size = (size + offset + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let num_pages = (aligned_size / PAGE_SIZE) as usize;

    // Allocate virtual address range
    let virt_base = IOREMAP
        .lock()
        .alloc(num_pages)
        .ok_or(IoremapError::OutOfVirtualSpace)?;

    // Get kernel page table (from TTBR0 since we use identity mapping)
    let ttbr0: u64;
    unsafe {
        asm!("mrs {}, ttbr0_el1", out(reg) ttbr0, options(nostack));
    }
    let l0_phys = ttbr0 & 0x0000_FFFF_FFFF_F000;

    // Map each page with device memory attributes
    for i in 0..num_pages {
        let va = virt_base + (i as u64) * PAGE_SIZE;
        let pa = aligned_phys + (i as u64) * PAGE_SIZE;

        if let Err(e) = map_device_page(l0_phys, va, pa) {
            // Rollback: unmap pages we've already mapped
            for j in 0..i {
                let rollback_va = virt_base + (j as u64) * PAGE_SIZE;
                unmap_page(l0_phys, rollback_va);
            }
            IOREMAP.lock().free(virt_base, num_pages);
            return Err(e);
        }
    }

    // Flush TLB for mapped range
    for i in 0..num_pages {
        flush_tlb(virt_base + (i as u64) * PAGE_SIZE);
    }

    Ok((virt_base + offset) as *mut u8)
}

/// Unmap a previously ioremap'd region
#[allow(dead_code)]
pub fn iounmap(virt_addr: *mut u8, size: u64) {
    let virt = virt_addr as u64;

    // If it's in the boot device region (identity-mapped), nothing to do
    if virt < BOOT_DEVICE_END {
        return;
    }

    // If it's not in our ioremap region, nothing to do
    if !(IOREMAP_BASE..IOREMAP_END).contains(&virt) {
        return;
    }

    let offset = virt & (PAGE_SIZE - 1);
    let aligned_virt = virt & !(PAGE_SIZE - 1);
    let aligned_size = (size + offset + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let num_pages = (aligned_size / PAGE_SIZE) as usize;

    // Get kernel page table
    let ttbr0: u64;
    unsafe {
        asm!("mrs {}, ttbr0_el1", out(reg) ttbr0, options(nostack));
    }
    let l0_phys = ttbr0 & 0x0000_FFFF_FFFF_F000;

    // Unmap pages and flush TLB
    for i in 0..num_pages {
        let va = aligned_virt + (i as u64) * PAGE_SIZE;
        unmap_page(l0_phys, va);
        flush_tlb(va);
    }

    // Free virtual address range
    IOREMAP.lock().free(aligned_virt, num_pages);
}

/// Map a single 4KB page with device memory attributes
fn map_device_page(l0_phys: u64, va: u64, pa: u64) -> Result<(), IoremapError> {
    let (l0_idx, l1_idx, l2_idx, l3_idx) = page_indices(va);

    unsafe {
        let l0 = phys_to_virt_table(l0_phys);

        // Get or create L1 table
        let l0_entry = (*l0).entry_mut(l0_idx);
        if !l0_entry.is_valid() {
            let l1_phys = alloc_page_table()?;
            l0_entry.set_table(l1_phys);
        }
        let l1 = phys_to_virt_table(l0_entry.addr());

        // Get or create L2 table
        let l1_entry = (*l1).entry_mut(l1_idx);
        if !l1_entry.is_valid() {
            let l2_phys = alloc_page_table()?;
            l1_entry.set_table(l2_phys);
        } else if l1_entry.is_block() {
            // 1GB block - would need to split, for now return error
            return Err(IoremapError::FrameAllocationFailed);
        }
        let l2 = phys_to_virt_table(l1_entry.addr());

        // Get or create L3 table
        let l2_entry = (*l2).entry_mut(l2_idx);
        if !l2_entry.is_valid() {
            let l3_phys = alloc_page_table()?;
            l2_entry.set_table(l3_phys);
        } else if l2_entry.is_block() {
            // 2MB block - would need to split
            return Err(IoremapError::FrameAllocationFailed);
        }
        let l3 = phys_to_virt_table(l2_entry.addr());

        // Set L3 page entry with device attributes
        let l3_entry = (*l3).entry_mut(l3_idx);
        l3_entry.set_page(pa, DEVICE_PAGE_ATTRS);

        // Data cache clean to ensure MMU sees the new entry
        let entry_addr = l3_entry as *mut PageTableEntry as u64;
        asm!(
            "dc cvau, {}",
            "dsb ish",
            in(reg) entry_addr,
            options(nostack)
        );
    }

    Ok(())
}

/// Unmap a single page (clear PTE)
fn unmap_page(l0_phys: u64, va: u64) {
    let (l0_idx, l1_idx, l2_idx, l3_idx) = page_indices(va);

    unsafe {
        let l0 = phys_to_virt_table_const(l0_phys);

        let l0_entry = (*l0).entry(l0_idx);
        if !l0_entry.is_valid() || !l0_entry.is_table() {
            return;
        }
        let l1 = phys_to_virt_table_const(l0_entry.addr());

        let l1_entry = (*l1).entry(l1_idx);
        if !l1_entry.is_valid() || !l1_entry.is_table() {
            return;
        }
        let l2 = phys_to_virt_table_const(l1_entry.addr());

        let l2_entry = (*l2).entry(l2_idx);
        if !l2_entry.is_valid() || !l2_entry.is_table() {
            return;
        }
        let l3 = phys_to_virt_table(l2_entry.addr());

        // Clear the L3 entry
        let l3_entry = (*l3).entry_mut(l3_idx);
        l3_entry.clear();

        // Data cache clean
        let entry_addr = l3_entry as *mut PageTableEntry as u64;
        asm!(
            "dc cvau, {}",
            "dsb ish",
            in(reg) entry_addr,
            options(nostack)
        );
    }
}

/// Allocate a zeroed page table frame
fn alloc_page_table() -> Result<u64, IoremapError> {
    // Use the global frame allocator
    let frame = crate::FRAME_ALLOCATOR
        .alloc()
        .ok_or(IoremapError::FrameAllocationFailed)?;

    // Zero the frame
    unsafe {
        core::ptr::write_bytes(phys_to_virt(frame), 0, PAGE_SIZE as usize);
    }

    Ok(frame)
}

/// Extract page table indices from virtual address
fn page_indices(vaddr: u64) -> (usize, usize, usize, usize) {
    let l0_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let l1_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let l2_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let l3_idx = ((vaddr >> 12) & 0x1FF) as usize;
    (l0_idx, l1_idx, l2_idx, l3_idx)
}

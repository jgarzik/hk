//! ioremap - MMIO virtual address space management
//!
//! Provides Linux-like ioremap/iounmap functions for mapping physical
//! MMIO regions to kernel virtual addresses. Uses a dedicated virtual
//! address region separate from the kernel heap and user space.

use spin::Mutex;

use super::paging::{
    PAGE_CACHE_DISABLE, PAGE_HUGE, PAGE_NO_EXECUTE, PAGE_PRESENT, PAGE_SIZE, PAGE_WRITABLE,
    PAGE_WRITE_THROUGH, X86_64PageTable, phys_to_virt, phys_to_virt_table,
};

/// ioremap region base (224MB)
pub const IOREMAP_BASE: u64 = 0x0E00_0000;

/// ioremap region end (512MB - 1)
pub const IOREMAP_END: u64 = 0x1FFF_FFFF;

/// Total size of ioremap region
pub const IOREMAP_SIZE: u64 = IOREMAP_END - IOREMAP_BASE + 1;

/// Number of 4KB pages in ioremap region
const IOREMAP_PAGES: usize = (IOREMAP_SIZE / PAGE_SIZE) as usize;

/// Bitmap array size (64 bits per u64)
const BITMAP_SIZE: usize = IOREMAP_PAGES.div_ceil(64);

/// MMIO page flags: present, writable, no-execute, cache-disable, write-through
const MMIO_FLAGS: u64 =
    PAGE_PRESENT | PAGE_WRITABLE | PAGE_NO_EXECUTE | PAGE_CACHE_DISABLE | PAGE_WRITE_THROUGH;

/// Intermediate page table flags
const INTERMEDIATE_FLAGS: u64 = PAGE_PRESENT | PAGE_WRITABLE;

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
        // All bits 0 = all pages free
        self.bitmap = [0; BITMAP_SIZE];
        self.initialized = true;
        self.next_free = 0;
    }

    /// Allocate a contiguous range of virtual pages
    /// Returns the base virtual address or None if no space
    fn alloc(&mut self, num_pages: usize) -> Option<u64> {
        if !self.initialized || num_pages == 0 || num_pages > IOREMAP_PAGES {
            return None;
        }

        // First-fit search starting from hint
        let start_page = self.next_free;
        let mut found_start = None;

        // Search from hint to end
        if let Some(page) = self.find_free_range(start_page, IOREMAP_PAGES, num_pages) {
            found_start = Some(page);
        } else if start_page > 0 {
            // Wrap around and search from beginning to hint
            if let Some(page) = self.find_free_range(0, start_page, num_pages) {
                found_start = Some(page);
            }
        }

        if let Some(page) = found_start {
            // Mark pages as used
            for i in 0..num_pages {
                self.set_used(page + i);
            }
            // Update hint
            self.next_free = page + num_pages;
            if self.next_free >= IOREMAP_PAGES {
                self.next_free = 0;
            }
            // Convert page number to virtual address
            Some(IOREMAP_BASE + (page as u64) * PAGE_SIZE)
        } else {
            None
        }
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

        // Update hint if we're freeing before current hint
        if start_page < self.next_free {
            self.next_free = start_page;
        }
    }

    /// Check if a page is free
    fn is_free(&self, page: usize) -> bool {
        let word = page / 64;
        let bit = page % 64;
        (self.bitmap[word] & (1u64 << bit)) == 0
    }

    /// Mark a page as used
    fn set_used(&mut self, page: usize) {
        let word = page / 64;
        let bit = page % 64;
        self.bitmap[word] |= 1u64 << bit;
    }

    /// Mark a page as free
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
        "ioremap: initialized region 0x{:x}-0x{:x} ({} pages)",
        IOREMAP_BASE,
        IOREMAP_END,
        IOREMAP_PAGES
    );
}

/// Map a physical MMIO region to kernel virtual address space
///
/// # Arguments
/// * `phys_addr` - Physical address of MMIO region (can be non-page-aligned)
/// * `size` - Size in bytes to map
///
/// # Returns
/// Virtual address pointer (with same offset as physical address had)
///
/// # Safety
/// The physical address must be a valid MMIO region, not regular RAM.
pub fn ioremap(phys_addr: u64, size: u64) -> Result<*mut u8, IoremapError> {
    if size == 0 {
        return Err(IoremapError::InvalidSize);
    }

    // Calculate page-aligned range
    let offset = phys_addr & (PAGE_SIZE - 1);
    let aligned_phys = phys_addr & !(PAGE_SIZE - 1);
    let aligned_size = (size + offset + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let num_pages = (aligned_size / PAGE_SIZE) as usize;

    // Allocate virtual address range
    let virt_base = IOREMAP
        .lock()
        .alloc(num_pages)
        .ok_or(IoremapError::OutOfVirtualSpace)?;

    // Get current CR3 (kernel page tables)
    let cr3 = X86_64PageTable::current_cr3();

    // Map each page
    for i in 0..num_pages {
        let va = virt_base + (i as u64) * PAGE_SIZE;
        let pa = aligned_phys + (i as u64) * PAGE_SIZE;

        if let Err(e) = map_mmio_page(cr3, va, pa) {
            // Rollback: unmap pages we've already mapped
            for j in 0..i {
                let rollback_va = virt_base + (j as u64) * PAGE_SIZE;
                unmap_page(cr3, rollback_va);
            }
            // Free the virtual address range
            IOREMAP.lock().free(virt_base, num_pages);
            return Err(e);
        }
    }

    // Flush TLB for mapped range
    for i in 0..num_pages {
        X86_64PageTable::flush_tlb(virt_base + (i as u64) * PAGE_SIZE);
    }

    // Return virtual address with offset
    Ok((virt_base + offset) as *mut u8)
}

/// Unmap a previously ioremap'd region
///
/// # Arguments
/// * `virt_addr` - Virtual address returned by ioremap
/// * `size` - Size that was passed to ioremap
#[allow(dead_code)]
pub fn iounmap(virt_addr: *mut u8, size: u64) {
    let virt = virt_addr as u64;

    // Validate address is in ioremap region
    if !(IOREMAP_BASE..IOREMAP_END).contains(&virt) {
        return;
    }

    // Calculate page-aligned range
    let offset = virt & (PAGE_SIZE - 1);
    let aligned_virt = virt & !(PAGE_SIZE - 1);
    let aligned_size = (size + offset + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let num_pages = (aligned_size / PAGE_SIZE) as usize;

    let cr3 = X86_64PageTable::current_cr3();

    // Unmap pages and flush TLB
    for i in 0..num_pages {
        let va = aligned_virt + (i as u64) * PAGE_SIZE;
        unmap_page(cr3, va);
        X86_64PageTable::flush_tlb(va);
    }

    // Free virtual address range
    IOREMAP.lock().free(aligned_virt, num_pages);
}

/// Map a single 4KB MMIO page
///
/// Handles the case where a 2MB huge page exists and needs to be split
/// into 4KB pages before remapping.
fn map_mmio_page(cr3: u64, va: u64, pa: u64) -> Result<(), IoremapError> {
    let (pml4_idx, pdpt_idx, pd_idx, pt_idx) = page_indices(va);

    unsafe {
        let pml4 = phys_to_virt_table(cr3);

        // Get or create PDPT
        let pml4_entry = (*pml4).entry_mut(pml4_idx);
        if !pml4_entry.is_present() {
            let pdpt_phys = alloc_zeroed_frame()?;
            pml4_entry.set(pdpt_phys, INTERMEDIATE_FLAGS);
        }
        let pdpt = phys_to_virt_table(pml4_entry.addr());

        // Get or create PD
        let pdpt_entry = (*pdpt).entry_mut(pdpt_idx);
        if !pdpt_entry.is_present() {
            let pd_phys = alloc_zeroed_frame()?;
            pdpt_entry.set(pd_phys, INTERMEDIATE_FLAGS);
        }
        let pd = phys_to_virt_table(pdpt_entry.addr());

        // Get or create PT - handle 2MB huge pages
        let pd_entry = (*pd).entry_mut(pd_idx);
        let pt = if !pd_entry.is_present() {
            // No entry - allocate a new page table
            let pt_phys = alloc_zeroed_frame()?;
            pd_entry.set(pt_phys, INTERMEDIATE_FLAGS);
            phys_to_virt_table(pt_phys)
        } else if pd_entry.is_huge() {
            // 2MB huge page - need to split into 4KB pages
            let huge_base = pd_entry.addr();
            let huge_flags = pd_entry.flags() & !PAGE_HUGE; // Remove huge flag for 4KB pages

            // Allocate a new page table
            let pt_phys = alloc_zeroed_frame()?;
            let pt = phys_to_virt_table(pt_phys);

            // Fill PT with 512 entries covering the same 2MB region
            for i in 0..512 {
                let entry_pa = huge_base + (i as u64) * PAGE_SIZE;
                (*pt).entry_mut(i).set(entry_pa, huge_flags);
            }

            // Replace the PD entry to point to our new PT
            pd_entry.set(pt_phys, INTERMEDIATE_FLAGS);

            pt
        } else {
            // Regular PT entry - just use its address
            phys_to_virt_table(pd_entry.addr())
        };

        // Map the page with MMIO flags
        let pt_entry = (*pt).entry_mut(pt_idx);
        pt_entry.set(pa, MMIO_FLAGS);
    }

    Ok(())
}

/// Unmap a single page (clear PTE, don't free intermediate tables)
fn unmap_page(cr3: u64, va: u64) {
    let (pml4_idx, pdpt_idx, pd_idx, pt_idx) = page_indices(va);

    unsafe {
        let pml4 = phys_to_virt_table(cr3);

        let pml4_entry = (*pml4).entry(pml4_idx);
        if !pml4_entry.is_present() {
            return;
        }
        let pdpt = phys_to_virt_table(pml4_entry.addr());

        let pdpt_entry = (*pdpt).entry(pdpt_idx);
        if !pdpt_entry.is_present() {
            return;
        }
        let pd = phys_to_virt_table(pdpt_entry.addr());

        let pd_entry = (*pd).entry(pd_idx);
        if !pd_entry.is_present() {
            return;
        }
        let pt = phys_to_virt_table(pd_entry.addr());

        // Clear the page table entry
        let pt_entry = (*pt).entry_mut(pt_idx);
        pt_entry.clear();
    }
}

/// Allocate a zeroed frame for page tables
fn alloc_zeroed_frame() -> Result<u64, IoremapError> {
    let frame = crate::FRAME_ALLOCATOR
        .alloc()
        .ok_or(IoremapError::FrameAllocationFailed)?;

    // Zero the frame
    unsafe {
        core::ptr::write_bytes(phys_to_virt(frame), 0, PAGE_SIZE as usize);
    }

    Ok(frame)
}

/// Calculate page table indices from virtual address
fn page_indices(vaddr: u64) -> (usize, usize, usize, usize) {
    let pml4_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let pd_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let pt_idx = ((vaddr >> 12) & 0x1FF) as usize;
    (pml4_idx, pdpt_idx, pd_idx, pt_idx)
}

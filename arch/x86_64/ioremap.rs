//! ioremap - MMIO virtual address space management
//!
//! Provides Linux-like ioremap/iounmap functions for mapping physical
//! MMIO regions to kernel virtual addresses. Uses a dedicated virtual
//! address region separate from the kernel heap and user space.
//!
//! The walkers here change the swapper's kernel half only, whose tables
//! are never freed; a page is mapped or unmapped only by the holder of
//! its range (an ioremap caller, `mm::vmalloc::VmArea`).

use crate::sync::spin::Mutex;
use crate::util::scope::ScopeGuard;

use super::kmap::swapper_phys;
use super::paging::{
    PAGE_CACHE_DISABLE, PAGE_NO_EXECUTE, PAGE_PRESENT, PAGE_SIZE, PAGE_WRITABLE,
    PAGE_WRITE_THROUGH, PageTableEntry, VMALLOC_START, phys_to_virt, phys_to_virt_table,
};
use crate::mm::tlb::flush_tlb_kernel_range;

/// ioremap window: the first 1GB of the vmalloc area in the kernel half
/// (its PDPT is preallocated by kmap, so every address space sees the
/// PDs and PTs added here)
pub const IOREMAP_BASE: u64 = VMALLOC_START;

/// Total size of ioremap region
pub const IOREMAP_SIZE: u64 = 1 << 30;

/// ioremap region end (inclusive)
pub const IOREMAP_END: u64 = IOREMAP_BASE + IOREMAP_SIZE - 1;

/// Number of 4KB pages in ioremap region
const IOREMAP_PAGES: usize = (IOREMAP_SIZE / PAGE_SIZE) as usize;

/// Bitmap array size (64 bits per u64)
const BITMAP_SIZE: usize = IOREMAP_PAGES.div_ceil(64);

/// MMIO page flags: present, writable, no-execute, cache-disable, write-through
const MMIO_FLAGS: u64 =
    PAGE_PRESENT | PAGE_WRITABLE | PAGE_NO_EXECUTE | PAGE_CACHE_DISABLE | PAGE_WRITE_THROUGH;

/// Intermediate page table flags
const INTERMEDIATE_FLAGS: u64 = PAGE_PRESENT | PAGE_WRITABLE;

/// Kernel RAM page flags (vmap): present, writable, no-execute
const RAM_FLAGS: u64 = PAGE_PRESENT | PAGE_WRITABLE | PAGE_NO_EXECUTE;

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

/// Serializes adding lower tables to the vmalloc area (ioremap window
/// and kernel stacks), shared by every address space (Linux
/// init_mm.page_table_lock): two mappings in one new table must not
/// both create it. Spin leaf, thread context; frames are allocated
/// under it.
static KTABLES: Mutex<()> = Mutex::new(());

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
/// The range is MMIO or firmware memory, not RAM the kernel uses (an
/// uncached alias of RAM conflicts with the direct map's attributes).
pub unsafe fn ioremap(phys_addr: u64, size: u64) -> Result<*mut u8, IoremapError> {
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

    // Map each page; on failure, unmap the ones mapped and free the range
    let mut mapped = ScopeGuard::new_with_data(0u64, |n| {
        for j in 0..n {
            // SAFETY: a page of the range just allocated to us, mapped
            // here and not yet handed out
            unsafe { unmap_page(virt_base + j * PAGE_SIZE) };
        }
        flush_tlb_kernel_range(virt_base, virt_base + aligned_size);
        IOREMAP.lock().free(virt_base, num_pages);
    });
    for i in 0..aligned_size / PAGE_SIZE {
        // SAFETY: an unmapped page of the range just allocated to us;
        // the target is MMIO (this fn's contract)
        unsafe {
            map_page(
                virt_base + i * PAGE_SIZE,
                aligned_phys + i * PAGE_SIZE,
                MMIO_FLAGS,
            )
        }?;
        *mapped += 1;
    }
    mapped.dismiss();

    // No flush: the entries were not present (x86 caches no
    // not-present entry) and iounmap flushed any earlier use of the range

    // Return virtual address with offset
    Ok((virt_base + offset) as *mut u8)
}

/// Point the ioremap page at `va` to `pa` instead (TLB self-test):
/// break (clear, flush every CPU), then make
///
/// # Safety
///
/// `va` is a page of the caller's ioremap mapping, and `pa` MMIO or a
/// frame the caller owns and touches through no other mapping.
#[cfg(feature = "lockdep")]
pub unsafe fn retarget(va: u64, pa: u64) -> Result<(), IoremapError> {
    // SAFETY: the caller's page (the caller's guarantee)
    unsafe { unmap_page(va) };
    flush_tlb_kernel_range(va, va + PAGE_SIZE);
    // SAFETY: the caller's page, unmapped and flushed; `pa` as the
    // caller guarantees
    unsafe { map_page(va, pa, MMIO_FLAGS) }?;
    flush_tlb_kernel_range(va, va + PAGE_SIZE);
    Ok(())
}

/// Unmap a previously ioremap'd region
///
/// # Safety
///
/// `virt_addr` and `size` are a mapping `ioremap` returned (with that
/// size) that the caller owns, and nothing uses it any more: no
/// reference into it or accessor of it (`IoMem`) is left.
pub unsafe fn iounmap(virt_addr: *mut u8, size: u64) {
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

    // Unmap pages, then flush every CPU before the range can be reused
    for i in 0..num_pages {
        // SAFETY: the caller's mapping from `ioremap`, no longer used
        // (the caller's guarantee); MMIO pages, nothing is freed
        unsafe { unmap_page(aligned_virt + (i as u64) * PAGE_SIZE) };
    }
    flush_tlb_kernel_range(aligned_virt, aligned_virt + aligned_size);

    // Free virtual address range
    IOREMAP.lock().free(aligned_virt, num_pages);
}

/// Map the RAM page `pa` at the kernel address `va` in the vmalloc
/// area (Linux vmap_pages_range): writable, never executable. No TLB
/// flush: `va` was not present (x86 caches no not-present entry), and
/// whoever unmapped it flushed it before handing it out again.
///
/// # Safety
///
/// `va` is an unmapped page of a vmalloc-area range the caller holds
/// alone (`mm::vmalloc::VmArea`), and `pa` a free frame the caller
/// owns and hands to that range.
pub(crate) unsafe fn vmap_page(va: u64, pa: u64) -> Result<(), IoremapError> {
    // SAFETY: the caller's guarantee
    unsafe { map_page(va, pa, RAM_FLAGS) }
}

/// Unmap the vmalloc-area page at `va`, returning the RAM page it
/// mapped. The caller flushes the TLBs before `va` is mapped again.
///
/// # Safety
///
/// `va` is a page of a vmalloc-area range the caller holds alone, which
/// nothing uses any more.
pub(crate) unsafe fn vunmap_page(va: u64) -> Option<u64> {
    // SAFETY: the caller's guarantee
    unsafe { unmap_page(va) }
}

/// The swapper's entry `idx` of the table frame `table`
///
/// # Safety
///
/// `table` is a live kernel table frame, and the caller holds KTABLES
/// or changes only an entry of a range it holds.
unsafe fn entry<'a>(table: u64, idx: usize) -> &'a mut PageTableEntry {
    // SAFETY: a live kernel table frame (the caller's guarantee),
    // reached through the direct map; `idx` < 512
    unsafe { (*phys_to_virt_table(table)).entry_mut(idx) }
}

/// Map a single 4KB page in the vmalloc window of the swapper's kernel
/// half (shared by every address space) with `flags`
///
/// # Safety
///
/// `va` is an unmapped page of a vmalloc-window range the caller holds
/// alone, and `pa` a page the caller may map there (MMIO, or a frame it
/// owns and hands over).
unsafe fn map_page(va: u64, pa: u64, flags: u64) -> Result<(), IoremapError> {
    let (pml4_idx, pdpt_idx, pd_idx, pt_idx) = page_indices(va);
    let _tables = KTABLES.lock();
    // SAFETY: the swapper root, live forever; KTABLES held
    let pml4e = unsafe { entry(swapper_phys(), pml4_idx) };
    // The window's PML4 entry is preallocated (kmap::init)
    assert!(pml4e.is_present(), "ioremap: no vmalloc PDPT");
    // SAFETY: the kernel tables under the swapper are never freed;
    // KTABLES held while missing ones are added
    let pd = unsafe { table(entry(pml4e.addr(), pdpt_idx)) }?;
    // SAFETY: as above
    let pt = unsafe { table(entry(pd, pd_idx)) }?;
    // SAFETY: the caller's page in a live kernel table; no one else
    // changes it (the caller's guarantee)
    unsafe { entry(pt, pt_idx) }.set(pa, flags);
    Ok(())
}

/// Table frame under a PDPT or PD entry, allocated if absent
///
/// # Safety
///
/// `e` is an entry of a live kernel page table, KTABLES held.
unsafe fn table(e: &mut PageTableEntry) -> Result<u64, IoremapError> {
    if !e.is_present() {
        e.set(alloc_zeroed_frame()?, INTERMEDIATE_FLAGS);
    }
    Ok(e.addr())
}

/// Unmap a single page (clear PTE, don't free intermediate tables);
/// the page it mapped, if any
///
/// # Safety
///
/// `va` is a page of a vmalloc-window range the caller holds alone,
/// which nothing uses any more.
unsafe fn unmap_page(va: u64) -> Option<u64> {
    let (pml4_idx, pdpt_idx, pd_idx, pt_idx) = page_indices(va);
    let mut table = swapper_phys();
    for idx in [pml4_idx, pdpt_idx, pd_idx] {
        // SAFETY: the swapper root or a kernel table under it, never
        // freed; only read here
        let e = unsafe { entry(table, idx) };
        if !e.is_present() {
            return None;
        }
        table = e.addr();
    }
    // SAFETY: the caller's page in a live kernel table; no one else
    // changes it (the caller's guarantee)
    let e = unsafe { entry(table, pt_idx) };
    let pa = e.is_present().then(|| e.addr());
    e.clear();
    pa
}

/// Allocate a zeroed frame for page tables
fn alloc_zeroed_frame() -> Result<u64, IoremapError> {
    let frame = crate::FRAME_ALLOCATOR
        .alloc()
        .ok_or(IoremapError::FrameAllocationFailed)?;
    // SAFETY: a fresh frame, reached through the direct map
    unsafe { core::ptr::write_bytes(phys_to_virt(frame), 0, PAGE_SIZE as usize) };
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

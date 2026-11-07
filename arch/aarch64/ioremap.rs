//! ioremap - MMIO virtual address space management for aarch64
//!
//! Provides Linux-like ioremap/iounmap functions for mapping physical
//! MMIO regions to kernel virtual addresses. Uses a dedicated virtual
//! address region separate from the identity-mapped boot region.
//!
//! Physical addresses in the device window (0-1GB on QEMU virt) are
//! already mapped with device attributes at IO_BASE + phys (kmap.rs);
//! other addresses get pages in the ioremap window. Both are in TTBR1,
//! shared by every address space.
//!
//! The walkers here change the swapper's TTBR1 tables only, which are
//! never freed; a page is mapped or unmapped only by the holder of its
//! range (an ioremap caller, `mm::vmalloc::VmArea`). Entries are only
//! accessed atomically: a missing table is added under `KTABLES` (a
//! release store), and read without it (an acquire load) by any walker,
//! which may race with that add in a neighbouring range.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::mm::tlb::flush_tlb_kernel_range;
use crate::sync::spin::Mutex;
use crate::util::scope::ScopeGuard;
use core::arch::asm;

use super::paging::{
    AF, AP_EL1_RW, ATTR_IDX_DEVICE, ATTR_IDX_NORMAL, IO_BASE, IO_SIZE, PAGE_SIZE, PXN,
    PageTableEntry, SH_INNER, UXN, VMALLOC_START, io_va, phys_to_virt,
};

/// ioremap window base (the vmalloc area, TTBR1)
pub const IOREMAP_BASE: u64 = VMALLOC_START;

/// Total size of ioremap region (1GB)
pub const IOREMAP_SIZE: u64 = 1 << 30;

/// ioremap region end (exclusive)
pub const IOREMAP_END: u64 = IOREMAP_BASE + IOREMAP_SIZE;

/// Number of 4KB pages in ioremap region
const IOREMAP_PAGES: usize = (IOREMAP_SIZE / PAGE_SIZE) as usize;

/// Bitmap array size (64 bits per u64)
const BITMAP_SIZE: usize = IOREMAP_PAGES.div_ceil(64);

/// Device memory page attributes
const DEVICE_PAGE_ATTRS: u64 = AF | SH_INNER | ATTR_IDX_DEVICE | AP_EL1_RW | PXN | UXN;

/// Kernel RAM page attributes (vmap): normal memory, writable, never
/// executable
const RAM_PAGE_ATTRS: u64 = AF | SH_INNER | ATTR_IDX_NORMAL | AP_EL1_RW | PXN | UXN;

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
/// # Safety
/// The range is device or firmware memory, not RAM the kernel uses.
pub unsafe fn ioremap(phys_addr: u64, size: u64) -> Result<*mut u8, IoremapError> {
    if size == 0 {
        return Err(IoremapError::InvalidSize);
    }

    // The device window already maps physical 0-1GB
    if phys_addr + size <= IO_SIZE {
        return Ok(io_va(phys_addr) as *mut u8);
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

    // Map each page with device memory attributes; on failure, unmap the ones mapped and free the range
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
        let (va, pa) = (virt_base + i * PAGE_SIZE, aligned_phys + i * PAGE_SIZE);
        // SAFETY: an unmapped page of the range just allocated to us;
        // the target is device memory (this fn's contract)
        unsafe { map_page(va, pa, DEVICE_PAGE_ATTRS) }?;
        *mapped += 1;
    }
    mapped.dismiss();

    // Make the entries visible on every CPU (a stale entry of a range
    // used before is already gone: iounmap flushed it)
    flush_tlb_kernel_range(virt_base, virt_base + aligned_size);

    Ok((virt_base + offset) as *mut u8)
}

/// Point the ioremap page at `va` to `pa` instead (TLB self-test):
/// break (clear, flush every CPU), then make
///
/// # Safety
///
/// `va` is a page of the caller's ioremap mapping (not the device
/// window), and `pa` MMIO or a frame the caller owns and touches
/// through no other mapping.
#[cfg(feature = "lockdep")]
pub unsafe fn retarget(va: u64, pa: u64) -> Result<(), IoremapError> {
    // SAFETY: the caller's page (the caller's guarantee)
    unsafe { unmap_page(va) };
    flush_tlb_kernel_range(va, va + PAGE_SIZE);
    // SAFETY: the caller's page, unmapped and flushed; `pa` as the
    // caller guarantees
    unsafe { map_page(va, pa, DEVICE_PAGE_ATTRS) }?;
    flush_tlb_kernel_range(va, va + PAGE_SIZE);
    Ok(())
}

/// Unmap a previously ioremap'd region (the device window is kept)
///
/// # Safety
///
/// `virt_addr` and `size` are a mapping `ioremap` returned (with that
/// size) that the caller owns, and nothing uses it any more: no
/// reference into it or accessor of it (`IoMem`) is left.
pub unsafe fn iounmap(virt_addr: *mut u8, size: u64) {
    let virt = virt_addr as u64;

    // The device window is permanent
    if (IO_BASE..IO_BASE + IO_SIZE).contains(&virt) {
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

    // Unmap pages, then flush every CPU before the range can be reused
    for i in 0..num_pages {
        // SAFETY: the caller's mapping from `ioremap`, no longer used
        // (the caller's guarantee); device pages, nothing is freed
        unsafe { unmap_page(aligned_virt + (i as u64) * PAGE_SIZE) };
    }
    flush_tlb_kernel_range(aligned_virt, aligned_virt + aligned_size);

    // Free virtual address range
    IOREMAP.lock().free(aligned_virt, num_pages);
}

/// Map the RAM page `pa` at the kernel address `va` (Linux
/// vmap_pages_range): writable, never executable. No TLB flush: `va`
/// was invalid, and whoever unmapped it flushed it before handing it
/// out again; the barrier in the mapping makes the entry visible.
///
/// # Safety
///
/// `va` is an unmapped page of a vmalloc-area range the caller holds
/// alone (`mm::vmalloc::VmArea`), and `pa` a free frame the caller
/// owns and hands to that range.
pub(crate) unsafe fn vmap_page(va: u64, pa: u64) -> Result<(), IoremapError> {
    // SAFETY: the caller's guarantee
    unsafe { map_page(va, pa, RAM_PAGE_ATTRS) }
}

/// Unmap the kernel page at `va`, returning the RAM page it mapped.
/// The caller flushes the TLBs before `va` is mapped again.
///
/// # Safety
///
/// `va` is a page of a vmalloc-area range the caller holds alone, which
/// nothing uses any more.
pub(crate) unsafe fn vunmap_page(va: u64) -> Option<u64> {
    // SAFETY: the caller's guarantee
    unsafe { unmap_page(va) }
}

/// The swapper's entry `idx` (mod 512) of the kernel table frame
/// `table`
///
/// # Safety
///
/// `table` is a TTBR1 table frame under the swapper (never freed).
unsafe fn entry(table: u64, idx: usize) -> &'static AtomicU64 {
    let p = phys_to_virt(table).cast::<u64>().wrapping_add(idx & 511);
    // SAFETY: an entry of a table frame that stays (the caller's
    // guarantee), through the linear map; page-table entries are only
    // accessed atomically
    unsafe { AtomicU64::from_ptr(p) }
}

/// Table frame under an L0-L2 entry, added if invalid; an error for a
/// block (never split here)
///
/// # Safety
///
/// `e` is an upper entry of a kernel table under the swapper, KTABLES
/// held.
unsafe fn table(e: &AtomicU64) -> Result<u64, IoremapError> {
    let v = PageTableEntry(e.load(Ordering::Acquire));
    if v.is_table() {
        return Ok(v.addr());
    }
    if v.is_valid() {
        return Err(IoremapError::FrameAllocationFailed);
    }
    let t = alloc_page_table()?;
    let mut n = PageTableEntry::empty();
    n.set_table(t);
    // Release: lock-free walkers that see the entry see the zeroed table
    e.store(n.0, Ordering::Release);
    Ok(t)
}

/// Make a changed L3 entry visible to the MMU (clean to the point of
/// unification, then a barrier)
fn sync_entry(e: &AtomicU64) {
    let addr = e.as_ptr().addr();
    // SAFETY: a cache clean by VA of a live table entry, and a
    // barrier: no Rust-visible memory changes (nostack: no stack use)
    unsafe { asm!("dc cvau, {}", "dsb ish", in(reg) addr, options(nostack)) };
}

/// Map a single 4KB page of the swapper's TTBR1 tables (shared by every
/// address space) with `attrs`
///
/// # Safety
///
/// `va` is an unmapped page of a vmalloc-window range the caller holds
/// alone, and `pa` a page the caller may map there (device memory, or a
/// frame it owns and hands over).
unsafe fn map_page(va: u64, pa: u64, attrs: u64) -> Result<(), IoremapError> {
    let (l0_idx, l1_idx, l2_idx, l3_idx) = page_indices(va);
    let _tables = KTABLES.lock();
    let mut table = super::kmap::swapper_phys();
    for idx in [l0_idx, l1_idx, l2_idx] {
        // SAFETY: the swapper root or a kernel table under it, never
        // freed; KTABLES held while missing ones are added
        table = unsafe { super::ioremap::table(entry(table, idx)) }?;
    }
    // SAFETY: a kernel table, never freed; the entry is the caller's
    // page, which no one else changes (the caller's guarantee)
    let e = unsafe { entry(table, l3_idx) };
    let mut n = PageTableEntry::empty();
    n.set_page(pa, attrs);
    e.store(n.0, Ordering::Release);
    sync_entry(e);
    Ok(())
}

/// Unmap a single page (clear PTE); the page it mapped, if any
///
/// # Safety
///
/// `va` is a page of a vmalloc-window range the caller holds alone,
/// which nothing uses any more.
unsafe fn unmap_page(va: u64) -> Option<u64> {
    let (l0_idx, l1_idx, l2_idx, l3_idx) = page_indices(va);
    let mut table = super::kmap::swapper_phys();
    for idx in [l0_idx, l1_idx, l2_idx] {
        // SAFETY: the swapper root or a kernel table under it, never
        // freed; read atomically (KTABLES not needed: an upper entry is
        // only ever added, under it)
        let e = PageTableEntry(unsafe { entry(table, idx) }.load(Ordering::Acquire));
        if !e.is_table() {
            return None;
        }
        table = e.addr();
    }
    // SAFETY: a kernel table, never freed; the entry is the caller's
    // page, which no one else changes (the caller's guarantee)
    let e = unsafe { entry(table, l3_idx) };
    let old = PageTableEntry(e.swap(0, Ordering::AcqRel));
    sync_entry(e);
    old.is_valid().then(|| old.addr())
}

/// Allocate a zeroed page table frame
fn alloc_page_table() -> Result<u64, IoremapError> {
    let frame = crate::FRAME_ALLOCATOR
        .alloc()
        .ok_or(IoremapError::FrameAllocationFailed)?;
    // SAFETY: a fresh frame, reached through the linear map
    unsafe { core::ptr::write_bytes(phys_to_virt(frame), 0, PAGE_SIZE as usize) };
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

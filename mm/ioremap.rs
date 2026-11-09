//! ioremap: device memory in the kernel's virtual address space (Linux
//! mm/ioremap.c, mm/vmalloc.c's vmap_pages_range)
//!
//! Device ranges get pages of a dedicated window, the first gigabyte of
//! the vmalloc area, handed out by a bitmap allocator; an arch may map
//! some physical ranges permanently instead (arm64's device window,
//! `IoremapOps::io_window`). The page tables and their encoding are the
//! arch's (`arch::IoremapOps`).
//!
//! The walkers here change the swapper's kernel half only, whose tables
//! are never freed; a page is mapped or unmapped only by the holder of
//! its range (an ioremap caller, `mm::vmalloc::VmArea`). Entries are
//! only accessed atomically: a missing table is added under `KTABLES`
//! (a release store), and read without it (an acquire load) by any
//! walker, which may race with that add in a neighbouring range.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::paging::{VMALLOC_START, phys_to_virt};
use crate::arch::{CurrentArch, IoremapOps};
use crate::mm::tlb::flush_tlb_kernel_range;
use crate::sync::spin::Mutex;
use crate::util::error::KernelError;
use crate::util::scope::ScopeGuard;

const PAGE_SIZE: u64 = 4096;

/// ioremap window: the first 1GB of the vmalloc area, whose top-level
/// entry exists from boot (so every address space sees the tables added
/// here)
const IOREMAP_BASE: u64 = VMALLOC_START;

/// Size of the ioremap window
const IOREMAP_SIZE: u64 = 1 << 30;

/// End of the ioremap window (exclusive)
const IOREMAP_END: u64 = IOREMAP_BASE + IOREMAP_SIZE;

/// Pages in the window
const IOREMAP_PAGES: usize = (IOREMAP_SIZE / PAGE_SIZE) as usize;

/// Bitmap words (64 pages each)
const WORDS: usize = IOREMAP_PAGES.div_ceil(64);

/// The window's pages
static IOREMAP: Mutex<Alloc<WORDS>> = Mutex::new(Alloc::new());

/// Serializes adding lower tables to the vmalloc area (ioremap window
/// and kernel stacks), shared by every address space (Linux
/// init_mm.page_table_lock): two mappings in one new table must not
/// both create it. Spin leaf, thread context; frames are allocated
/// under it.
static KTABLES: Mutex<()> = Mutex::new(());

/// First-fit page allocator over a `W`-word bitmap (1 = used),
/// searching from a hint and wrapping once
struct Alloc<const W: usize> {
    bitmap: [u64; W],
    /// Allocations fail until `init`
    initialized: bool,
    /// Where the next search starts
    next_free: usize,
}

impl<const W: usize> Alloc<W> {
    const PAGES: usize = W * 64;

    const fn new() -> Self {
        Self {
            bitmap: [0; W],
            initialized: false,
            next_free: 0,
        }
    }

    /// Every page free
    fn init(&mut self) {
        self.bitmap = [0; W];
        self.initialized = true;
        self.next_free = 0;
    }

    /// `n` contiguous free pages, marked used: the first page's index
    fn alloc(&mut self, n: usize) -> Option<usize> {
        if !self.initialized || n == 0 || n > Self::PAGES {
            return None;
        }
        let hint = self.next_free;
        let p = self
            .find_free_range(hint, Self::PAGES, n)
            .or_else(|| (hint > 0).then(|| self.find_free_range(0, hint, n))?)?;
        for q in p..p + n {
            self.set(q, true);
        }
        self.next_free = (p + n) % Self::PAGES;
        Some(p)
    }

    /// A run of `count` free pages within [start, end)
    fn find_free_range(&self, start: usize, end: usize, count: usize) -> Option<usize> {
        let mut run = 0;
        for page in start..end {
            if self.is_free(page) {
                run += 1;
                if run >= count {
                    return Some(page + 1 - count);
                }
            } else {
                run = 0;
            }
        }
        None
    }

    /// Free `n` pages at `p` (pages past the end are ignored)
    fn free(&mut self, p: usize, n: usize) {
        if p >= Self::PAGES {
            return;
        }
        for q in p..(p + n).min(Self::PAGES) {
            self.set(q, false);
        }
        self.next_free = self.next_free.min(p);
    }

    fn is_free(&self, page: usize) -> bool {
        self.bitmap[page / 64] & (1 << (page % 64)) == 0
    }

    fn set(&mut self, page: usize, used: bool) {
        let (w, b) = (page / 64, 1u64 << (page % 64));
        if used {
            self.bitmap[w] |= b;
        } else {
            self.bitmap[w] &= !b;
        }
    }
}

/// Initialize the ioremap window
pub fn init() {
    IOREMAP.lock().init();
    crate::printkln!(
        "ioremap: initialized region {:#x}-{:#x} ({} pages)",
        IOREMAP_BASE,
        IOREMAP_END,
        IOREMAP_PAGES
    );
}

/// The window's address of page `p`
fn page_va(p: usize) -> u64 {
    IOREMAP_BASE + p as u64 * PAGE_SIZE
}

/// The window's page at `va`
fn va_page(va: u64) -> usize {
    ((va - IOREMAP_BASE) / PAGE_SIZE) as usize
}

/// Map `size` bytes of device memory at physical `phys_addr` (any
/// alignment): a pointer with the same page offset. InvalidArgument for
/// a zero `size`, OutOfMemory when the window or a page-table frame runs
/// out, Busy when a huge or block entry already maps part of the window
/// (a kernel bug).
///
/// # Safety
/// [phys_addr, phys_addr + size) is device or firmware memory, not RAM
/// the kernel uses (an uncached alias of RAM conflicts with the direct
/// map's attributes).
pub unsafe fn ioremap(phys_addr: u64, size: u64) -> Result<*mut u8, KernelError> {
    if size == 0 {
        return Err(KernelError::InvalidArgument);
    }
    if let Some(va) = CurrentArch::io_window(phys_addr, size) {
        return Ok(core::ptr::with_exposed_provenance_mut(va as usize));
    }
    let offset = phys_addr & (PAGE_SIZE - 1);
    let aligned_phys = phys_addr & !(PAGE_SIZE - 1);
    let aligned_size = (size + offset).next_multiple_of(PAGE_SIZE);
    let num_pages = (aligned_size / PAGE_SIZE) as usize;
    let p = IOREMAP
        .lock()
        .alloc(num_pages)
        .ok_or(KernelError::OutOfMemory)?;
    let virt_base = page_va(p);
    // SAFETY: the range was just allocated to us; the target is device
    // memory (this fn's contract)
    unsafe { map_range(virt_base, aligned_phys, num_pages) }?;
    if CurrentArch::FLUSH_NEW {
        flush_tlb_kernel_range(virt_base, virt_base + aligned_size);
    }
    Ok(core::ptr::with_exposed_provenance_mut(
        (virt_base + offset) as usize,
    ))
}

/// Map `n` device pages at `pa` to the unmapped range at `va`; on
/// failure the pages mapped are unmapped and the range freed
///
/// # Safety
/// The range is the caller's, freshly allocated from `IOREMAP`; the
/// target is device memory.
unsafe fn map_range(va: u64, pa: u64, n: usize) -> Result<(), KernelError> {
    let mut mapped = ScopeGuard::new_with_data(0u64, |m| {
        for j in 0..m {
            // SAFETY: a page of the range just allocated to us, mapped
            // here and not yet handed out
            unsafe { unmap_page(va + j * PAGE_SIZE) };
        }
        flush_tlb_kernel_range(va, va + n as u64 * PAGE_SIZE);
        IOREMAP.lock().free(va_page(va), n);
    });
    for i in 0..n as u64 {
        // SAFETY: an unmapped page of the caller's range; the target is
        // device memory (this fn's contract)
        unsafe {
            map_page(
                va + i * PAGE_SIZE,
                pa + i * PAGE_SIZE,
                CurrentArch::PROT_DEVICE,
            )
        }?;
        *mapped += 1;
    }
    mapped.dismiss();
    // No flush: the entries were not present and iounmap flushed any
    // earlier use of the range
    Ok(())
}

/// Point the ioremap page at `va` to `pa` instead (TLB self-test):
/// break (clear, flush every CPU), then make
///
/// # Safety
///
/// `va` is a page of the caller's ioremap mapping (not an arch's
/// permanent window), and `pa` MMIO or a frame the caller owns and
/// touches through no other mapping.
#[cfg(feature = "lockdep")]
pub unsafe fn retarget(va: u64, pa: u64) -> Result<(), KernelError> {
    // SAFETY: the caller's page (the caller's guarantee)
    unsafe { unmap_page(va) };
    flush_tlb_kernel_range(va, va + PAGE_SIZE);
    // SAFETY: the caller's page, unmapped and flushed; `pa` as the
    // caller guarantees
    unsafe { map_page(va, pa, CurrentArch::PROT_DEVICE) }?;
    flush_tlb_kernel_range(va, va + PAGE_SIZE);
    Ok(())
}

/// Unmap a mapping `ioremap` returned (an arch's permanent window is
/// kept)
///
/// # Safety
///
/// `virt_addr` and `size` are a mapping `ioremap` returned (with that
/// size) that the caller owns, and nothing uses it any more: no
/// reference into it or accessor of it (`IoMem`) is left.
pub unsafe fn iounmap(virt_addr: *mut u8, size: u64) {
    let virt = virt_addr as u64;
    if CurrentArch::in_io_window(virt) || !(IOREMAP_BASE..IOREMAP_END).contains(&virt) {
        return;
    }
    let offset = virt & (PAGE_SIZE - 1);
    let aligned_virt = virt & !(PAGE_SIZE - 1);
    let aligned_size = (size + offset).next_multiple_of(PAGE_SIZE);
    let num_pages = (aligned_size / PAGE_SIZE) as usize;
    // Unmap, then flush every CPU before the range can be reused
    for i in 0..num_pages as u64 {
        // SAFETY: the caller's mapping from `ioremap`, no longer used
        // (the caller's guarantee); device pages, nothing is freed
        unsafe { unmap_page(aligned_virt + i * PAGE_SIZE) };
    }
    flush_tlb_kernel_range(aligned_virt, aligned_virt + aligned_size);
    IOREMAP.lock().free(va_page(aligned_virt), num_pages);
}

/// Map the RAM page `pa` at the kernel address `va` in the vmalloc
/// area (Linux vmap_pages_range): writable, never executable. No TLB
/// flush: `va` was not present (no CPU caches a not-present entry; the
/// arch makes the entry visible to the walker), and whoever unmapped
/// it flushed it before handing it out again.
///
/// # Safety
///
/// `va` is an unmapped page of a vmalloc-area range the caller holds
/// alone (`mm::vmalloc::VmArea`), and `pa` a free frame the caller
/// owns and hands to that range.
pub(crate) unsafe fn vmap_page(va: u64, pa: u64) -> Result<(), KernelError> {
    // SAFETY: the caller's guarantee
    unsafe { map_page(va, pa, CurrentArch::PROT_KERNEL) }
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

/// The swapper's entry `idx` (mod 512) of the kernel table frame
/// `table`
///
/// # Safety
///
/// `table` is a kernel table frame under the swapper (never freed).
unsafe fn entry(table: u64, idx: usize) -> &'static AtomicU64 {
    let p = phys_to_virt(table).cast::<u64>().wrapping_add(idx & 511);
    // SAFETY: an entry of a table frame that stays (the caller's
    // guarantee), through the direct map; page-table entries are only
    // accessed atomically
    unsafe { AtomicU64::from_ptr(p) }
}

/// Index of `va` in its table at the level of `shift`
fn idx(va: u64, shift: u32) -> usize {
    ((va >> shift) & 511) as usize
}

/// Map a single 4KB page in the vmalloc window of the swapper's kernel
/// half (shared by every address space) with `prot`
///
/// # Safety
///
/// `va` is an unmapped page of a vmalloc-window range the caller holds
/// alone, and `pa` a page the caller may map there (device memory, or a
/// frame it owns and hands over).
unsafe fn map_page(va: u64, pa: u64, prot: u64) -> Result<(), KernelError> {
    let _tables = KTABLES.lock();
    // SAFETY: the swapper root, live forever
    let top = unsafe { entry(CurrentArch::swapper_phys(), idx(va, 39)) }.load(Ordering::Acquire);
    // The window's top-level entry exists from boot (kmap::init)
    assert!(CurrentArch::pte_is_table(top), "ioremap: no vmalloc table");
    let mut t = CurrentArch::pte_addr(top);
    for shift in [30, 21] {
        // SAFETY: the kernel tables under the swapper are never freed;
        // KTABLES held while missing ones are added
        t = unsafe { table(entry(t, idx(va, shift))) }?;
    }
    // SAFETY: a kernel table, never freed; the entry is the caller's
    // page, which no one else changes (the caller's guarantee)
    let e = unsafe { entry(t, idx(va, 12)) };
    e.store(CurrentArch::mk_pte(pa, prot), Ordering::Release);
    CurrentArch::sync_pte(e);
    Ok(())
}

/// Table frame under an upper entry, added if absent; EBUSY for a huge
/// or block entry (never split here: a kernel bug to map inside one)
///
/// # Safety
///
/// `e` is an upper entry of a kernel page table under the swapper,
/// KTABLES held.
unsafe fn table(e: &AtomicU64) -> Result<u64, KernelError> {
    let v = e.load(Ordering::Acquire);
    if CurrentArch::pte_is_table(v) {
        return Ok(CurrentArch::pte_addr(v));
    }
    if CurrentArch::pte_present(v) {
        crate::printkln!("WARNING: ioremap: window already mapped by huge/block entry {v:#x}");
        return Err(KernelError::Busy);
    }
    let t = alloc_table()?;
    // Release: lock-free walkers that see the entry see the zeroed table
    e.store(CurrentArch::mk_table(t), Ordering::Release);
    Ok(t)
}

/// Unmap a single page (clear the entry, keep the tables); the page it
/// mapped, if any
///
/// # Safety
///
/// `va` is a page of a vmalloc-window range the caller holds alone,
/// which nothing uses any more.
unsafe fn unmap_page(va: u64) -> Option<u64> {
    let mut t = CurrentArch::swapper_phys();
    for shift in [39, 30, 21] {
        // SAFETY: the swapper root or a kernel table under it, never
        // freed; read atomically (KTABLES not needed: an upper entry is
        // only ever added, under it)
        let e = unsafe { entry(t, idx(va, shift)) }.load(Ordering::Acquire);
        if !CurrentArch::pte_is_table(e) {
            return None;
        }
        t = CurrentArch::pte_addr(e);
    }
    // SAFETY: a kernel table, never freed; the entry is the caller's
    // page, which no one else changes (the caller's guarantee)
    let e = unsafe { entry(t, idx(va, 12)) };
    let old = e.swap(0, Ordering::AcqRel);
    CurrentArch::sync_pte(e);
    CurrentArch::pte_present(old).then(|| CurrentArch::pte_addr(old))
}

/// A zeroed page-table frame
fn alloc_table() -> Result<u64, KernelError> {
    let frame = crate::FRAME_ALLOCATOR
        .alloc()
        .ok_or(KernelError::OutOfMemory)?;
    // SAFETY: a fresh frame, reached through the direct map
    unsafe { core::ptr::write_bytes(phys_to_virt(frame), 0, PAGE_SIZE as usize) };
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready<const W: usize>() -> Alloc<W> {
        let mut a = Alloc::new();
        a.init();
        a
    }

    #[test]
    fn alloc_before_init_fails() {
        let mut a: Alloc<1> = Alloc::new();
        assert_eq!(a.alloc(1), None);
    }

    #[test]
    fn alloc_free_reuse() {
        let mut a: Alloc<2> = ready();
        assert_eq!(a.alloc(0), None);
        assert_eq!(a.alloc(3), Some(0));
        assert_eq!(a.alloc(5), Some(3));
        a.free(0, 3);
        // The hint moves back to the lowest freed page
        assert_eq!(a.alloc(2), Some(0));
        assert_eq!(a.alloc(2), Some(8));
    }

    #[test]
    fn fragmented_run_skips_holes() {
        let mut a: Alloc<1> = ready();
        for i in 0..8 {
            assert_eq!(a.alloc(8), Some(i * 8));
        }
        a.free(8, 8);
        a.free(24, 8);
        // Two 8-page holes, no 16-page run
        assert_eq!(a.alloc(16), None);
        assert_eq!(a.alloc(8), Some(8));
        assert_eq!(a.alloc(8), Some(24));
    }

    #[test]
    fn search_wraps_to_start() {
        let mut a: Alloc<1> = ready();
        assert_eq!(a.alloc(60), Some(0));
        a.free(0, 10);
        a.next_free = 60;
        // Only 4 pages after the hint: the search wraps
        assert_eq!(a.alloc(6), Some(0));
    }

    /// The window runs out: ioremap's OutOfMemory
    #[test]
    fn exhaustion() {
        let mut a: Alloc<2> = ready();
        assert_eq!(a.alloc(129), None);
        assert_eq!(a.alloc(128), Some(0));
        assert_eq!(a.alloc(1), None);
        a.free(127, 1);
        assert_eq!(a.alloc(1), Some(127));
        // Out-of-range frees are ignored
        a.free(128, 4);
        assert_eq!(a.alloc(1), None);
    }
}

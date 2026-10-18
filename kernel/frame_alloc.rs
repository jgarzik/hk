//! Physical frame allocator API
//!
//! The kernel's interface to the page allocator (`mm::page_alloc`): frames
//! are physical addresses, reference counts live in each frame's struct
//! page. A frame is allocated with count 1, `incref`/`decref` share and
//! release it (the last reference frees it), `free` releases it whatever
//! the count. 2MB huge pages are compound pages counted on the head.
//! Everything here is IRQ-safe (per-CPU lists with interrupts off, the
//! zone lock an `IrqSpinlock` leaf).

use crate::arch::FrameAlloc;
use crate::mm::page_alloc::{Gfp, Wmark, Zone};

/// Page/frame size (4KB)
pub const FRAME_SIZE: usize = 4096;

/// Order of a 2MB huge page (512 frames)
const HUGE_ORDER: u32 = 9;

/// The frame allocator: one zone over all RAM
pub struct FrameAllocator {
    zone: Zone,
}

fn pfn(frame: u64) -> u64 {
    frame / FRAME_SIZE as u64
}

fn phys(pfn: u64) -> u64 {
    pfn * FRAME_SIZE as u64
}

impl FrameAllocator {
    pub const fn new() -> Self {
        Self { zone: Zone::new() }
    }

    /// Span the physical range [base, base + size) with struct pages at
    /// `map` + pfn * 64 (the vmemmap); every frame starts in use
    pub fn init_at(&self, map: usize, base: u64, size: u64) {
        self.zone.init(map, pfn(base), pfn(base + size), false);
    }

    /// Span [base, base + size) of the vmemmap (boot): only pfns of
    /// RAM sections have struct pages
    pub fn init(&self, base: u64, size: u64) {
        let map = crate::arch::paging::VMEMMAP_START as usize;
        self.zone.init(map, pfn(base), pfn(base + size), true);
    }

    /// Hand the free RAM [start, end) to the allocator (boot, from
    /// memblock); frames outside the span are ignored
    pub fn free_range(&self, start: u64, end: u64) {
        self.zone
            .free_range(start.div_ceil(FRAME_SIZE as u64), pfn(end));
    }

    /// Boot is done handing out free memory: set the watermarks and
    /// size the per-CPU lists
    pub fn init_done(&self) {
        self.zone.setup_wmarks(None);
        self.zone.setup_pcp();
    }

    /// A frame of the zone that the allocator handed out (not reserved)
    fn ours(&self, frame: u64) -> Option<u64> {
        let p = pfn(frame);
        let ok = frame.is_multiple_of(FRAME_SIZE as u64)
            && self.zone.valid(p)
            && !self.zone.page(p).is_reserved();
        ok.then_some(p)
    }

    /// Head pfn of an allocated 2MB huge page
    fn huge(&self, frame: u64) -> Option<u64> {
        use core::sync::atomic::Ordering::Relaxed;
        let p = self.ours(frame)?;
        let pg = self.zone.page(p);
        let head = pg.flags.load(Relaxed) & crate::mm::page::PG_HEAD != 0;
        (head && pg.order.load(Relaxed) == HUGE_ORDER).then_some(p)
    }

    /// Allocate a frame with `gfp`
    pub fn alloc_gfp(&self, gfp: Gfp) -> Option<u64> {
        self.zone.alloc_pages(0, gfp).map(phys)
    }

    /// Allocate 2^order contiguous frames (count 1 on the first)
    pub fn alloc_pages(&self, order: u32, gfp: Gfp) -> Option<u64> {
        self.zone.alloc_pages(order, gfp).map(phys)
    }

    /// Free what `alloc_pages(order)` returned
    pub fn free_pages(&self, frame: u64, order: u32) {
        if let Some(p) = self.ours(frame) {
            self.zone.free_pages(p, order);
        }
    }

    /// Allocate a kernel frame
    pub fn alloc(&self) -> Option<u64> {
        self.alloc_gfp(Gfp::KERNEL)
    }

    /// Free a frame whatever its count (its owner is done with it)
    pub fn free(&self, frame: u64) {
        if let Some(p) = self.ours(frame) {
            self.zone.free_pages(p, 0);
        }
    }

    /// Take a reference (sharing the frame) unless it is free (Linux
    /// get_page_unless_zero); true for frames the allocator does not
    /// manage (nothing to count)
    pub fn incref(&self, frame: u64) -> bool {
        self.ours(frame).is_none_or(|p| self.zone.get(p))
    }

    /// Drop a reference; true if that freed the frame
    pub fn decref(&self, frame: u64) -> bool {
        self.ours(frame).is_some_and(|p| self.zone.put(p))
    }

    /// References to the frame (0 for frames the allocator does not
    /// manage, such as MMIO)
    pub fn refcount(&self, frame: u64) -> u32 {
        self.ours(frame).map_or(0, |p| self.zone.count(p))
    }

    // =========================================================================
    // Huge Page Support (2MB = 512 frames)
    // =========================================================================

    /// Allocate a 2MB-aligned compound huge page with `gfp`
    pub fn alloc_huge_gfp(&self, gfp: Gfp) -> Option<u64> {
        self.zone
            .alloc_pages(HUGE_ORDER, gfp.with(Gfp::COMP))
            .map(phys)
    }

    /// Allocate a 2MB huge page for user data, if one is free at once
    /// (no drain: the fault falls back to 4KB pages)
    pub fn alloc_huge(&self) -> Option<u64> {
        self.alloc_huge_gfp(Gfp::TRANSHUGE_LIGHT)
    }

    /// Free a 2MB huge page whatever its count
    pub fn free_huge(&self, frame: u64) {
        if let Some(p) = self.huge(frame) {
            self.zone.free_pages(p, HUGE_ORDER);
        }
    }

    /// A huge page was split into 512 4KB mappings: every frame now
    /// carries the head's count, so each is released by its own PTE
    pub fn split_huge(&self, frame: u64) {
        if let Some(p) = self.huge(frame) {
            self.zone.split(p);
        }
    }

    /// Take a reference on a huge page unless it is free
    pub fn incref_huge(&self, frame: u64) -> bool {
        self.huge(frame).is_some_and(|p| self.zone.get(p))
    }

    /// Drop a reference on a huge page; true if that freed it
    pub fn decref_huge(&self, frame: u64) -> bool {
        self.huge(frame).is_some_and(|p| self.zone.put(p))
    }

    /// References to a huge page (0 if `frame` heads none)
    pub fn refcount_huge(&self, frame: u64) -> u32 {
        self.huge(frame).map_or(0, |p| self.zone.count(p))
    }

    /// `frame` heads an allocated 2MB huge page
    pub fn is_huge_page(&self, frame: u64) -> bool {
        self.refcount_huge(frame) > 0
    }

    // =========================================================================
    // Contiguous runs and statistics
    // =========================================================================

    /// Allocate `n` physically contiguous frames (aligned to n rounded
    /// up to a power of two), each with count 1 and freed one by one:
    /// kernel stacks and multi-frame DMA buffers (Linux
    /// alloc_pages_exact)
    pub fn alloc_contig(&self, n: usize) -> Option<u64> {
        if n == 0 {
            return None;
        }
        let order = n.next_power_of_two().trailing_zeros();
        let p = self.zone.alloc_pages(order, Gfp::KERNEL)?;
        self.zone.split_block(p, order);
        for i in n as u64..1 << order {
            self.zone.free_pages(p + i, 0);
        }
        Some(phys(p))
    }

    /// Free frames now (per-CPU lists included)
    pub fn free_frames(&self) -> usize {
        self.zone.free_pages_all()
    }

    /// Free memory is down to the low watermark, where user data
    /// (anonymous pages, unevictable page cache) stops
    pub fn low(&self) -> bool {
        self.zone.below(Wmark::Low)
    }

    /// A watermark, in frames
    pub fn wmark(&self, w: Wmark) -> usize {
        self.zone.wmark(w)
    }

    /// vm.min_free_kbytes
    pub fn min_free_kbytes(&self) -> usize {
        self.zone.min_free_kb()
    }

    /// Set vm.min_free_kbytes and the watermarks from it
    pub fn set_min_free_kbytes(&self, kb: usize) {
        self.zone.setup_wmarks(Some(kb));
    }

    /// Total (managed) and free memory
    pub fn stats(&self) -> MemoryStats {
        MemoryStats {
            total_bytes: (self.zone.managed() * FRAME_SIZE) as u64,
            free_bytes: (self.free_frames() * FRAME_SIZE) as u64,
        }
    }
}

impl Default for FrameAllocator {
    fn default() -> Self {
        Self::new()
    }
}

/// Memory statistics from frame allocator
#[derive(Debug, Clone, Copy)]
pub struct MemoryStats {
    /// Total memory in bytes
    pub total_bytes: u64,
    /// Free memory in bytes
    pub free_bytes: u64,
}

impl FrameAlloc for &FrameAllocator {
    type PhysAddr = u64;

    fn alloc_contig(&mut self, n: usize) -> Option<Self::PhysAddr> {
        FrameAllocator::alloc_contig(self, n)
    }

    fn alloc_frame(&mut self) -> Option<Self::PhysAddr> {
        self.alloc()
    }

    fn free_frame(&mut self, frame: Self::PhysAddr) {
        self.free(frame)
    }

    fn put_frame(&mut self, frame: Self::PhysAddr) {
        self.decref(frame);
    }
}

/// Wrapper for using the static FRAME_ALLOCATOR with traits requiring &mut self
pub struct FrameAllocRef<'a>(pub &'a FrameAllocator);

impl FrameAlloc for FrameAllocRef<'_> {
    type PhysAddr = u64;

    fn alloc_contig(&mut self, n: usize) -> Option<Self::PhysAddr> {
        self.0.alloc_contig(n)
    }

    fn reserve_low(&self) -> bool {
        self.0.low()
    }

    fn alloc_frame(&mut self) -> Option<Self::PhysAddr> {
        self.0.alloc()
    }

    fn free_frame(&mut self, frame: Self::PhysAddr) {
        self.0.free(frame)
    }

    fn put_frame(&mut self, frame: Self::PhysAddr) {
        self.0.decref(frame);
    }
}

/// /proc/sys/vm files of the page allocator
pub static VM_CTLS: &[crate::sysctl::Ctl] = &[crate::sysctl::Ctl {
    path: "vm/min_free_kbytes",
    mode: 0o644,
    show: || alloc::vec![crate::FRAME_ALLOCATOR.min_free_kbytes() as i64],
    store: |v| {
        crate::sysctl::range(v[0], 0, i32::MAX as i64)?;
        crate::FRAME_ALLOCATOR.set_min_free_kbytes(v[0] as usize);
        Ok(())
    },
    text: None,
}];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mm::page::Page;

    const BASE: u64 = 0x4020_0000; // 2MB aligned

    /// An allocator over `n` frames at BASE (frame 0 kept reserved),
    /// struct pages in a host array
    fn fa(n: usize) -> (FrameAllocator, Vec<Page>) {
        let map: Vec<Page> = (0..n).map(|_| Page::new()).collect();
        let a = FrameAllocator::new();
        let base = (map.as_ptr() as usize).wrapping_sub(pfn(BASE) as usize * 64);
        a.init_at(base, BASE, (n * FRAME_SIZE) as u64);
        a.free_range(pa(1), pa(n));
        a.init_done();
        a.zone.clear_wmarks();
        (a, map)
    }

    fn pa(i: usize) -> u64 {
        BASE + (i * FRAME_SIZE) as u64
    }

    #[test]
    fn unfreed_frames_are_never_handed_out() {
        let (a, _m) = fa(1000);
        assert_eq!(a.free_frames(), 999);
        let mut got = Vec::new();
        while let Some(f) = a.alloc() {
            assert!(f >= pa(1) && f < pa(1000), "{f:#x}");
            got.push(f);
        }
        assert_eq!(got.len(), 999);
        // A reserved frame is never freed into the allocator
        a.free(pa(0));
        assert_eq!(a.alloc(), None);
    }

    #[test]
    fn out_of_range_ops_are_noops() {
        let (a, _m) = fa(128);
        let free = a.free_frames();
        let bad = [
            0,
            BASE - FRAME_SIZE as u64,
            pa(0),
            pa(128),
            pa(1 << 30),
            u64::MAX & !4095,
            pa(5) + 8,
        ];
        for f in bad {
            a.free(f);
            a.incref(f);
            assert!(!a.decref(f));
            assert_eq!(a.refcount(f), 0);
            a.free_huge(f);
            a.incref_huge(f);
            assert!(!a.decref_huge(f));
            assert!(!a.is_huge_page(f));
        }
        assert_eq!(a.free_frames(), free);
    }

    #[test]
    fn refcounts_share_and_free() {
        let (a, _m) = fa(64);
        let f = a.alloc().unwrap();
        assert_eq!(a.refcount(f), 1);
        a.incref(f);
        assert!(!a.decref(f));
        assert!(a.decref(f));
        assert_eq!(a.refcount(f), 0);
        assert_eq!(a.free_frames(), 63);
    }

    #[test]
    fn contig_runs_free_one_by_one() {
        let (a, _m) = fa(64);
        let f = a.alloc_contig(3).unwrap();
        assert!(f.is_multiple_of(4 * FRAME_SIZE as u64));
        assert_eq!(a.free_frames(), 60);
        for i in 0..3 {
            assert_eq!(a.refcount(f + i * FRAME_SIZE as u64), 1);
            a.free(f + i * FRAME_SIZE as u64);
        }
        assert_eq!(a.free_frames(), 63);
        assert_eq!(a.alloc_contig(1000), None);
    }

    #[test]
    fn huge_pages_aligned_and_split() {
        // 1100 frames: one full 2MB run (frames 512..1023)
        let (a, _m) = fa(1100);
        let h = a.alloc_huge().expect("huge");
        assert_eq!(h, pa(512));
        assert!(a.is_huge_page(h));
        assert_eq!(a.alloc_huge(), None);
        assert!(a.decref_huge(h));
        let h = a.alloc_huge().unwrap();
        let free = a.free_frames();
        a.split_huge(h);
        assert!(!a.is_huge_page(h));
        assert_eq!(a.refcount(pa(1023)), 1);
        // A shared (forked) tail frame survives one put
        a.incref(pa(600));
        assert!(!a.decref(pa(600)));
        for i in 512..1024 {
            assert!(a.decref(pa(i)), "frame {i}");
        }
        assert_eq!(a.free_frames(), free + 512);
    }
}

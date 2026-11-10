//! struct page: the descriptor of every physical page frame
//!
//! Every pfn of a RAM section has a 64-byte [`Page`] at `VMEMMAP_START +
//! pfn * 64` (Linux SPARSEMEM_VMEMMAP): the array is virtually contiguous
//! and backed only for the 128MB sections that hold RAM, with frames
//! memblock gives at boot (never the heap). A page records its flags
//! (anonymous, buddy, compound head/tail, slab, ...), its reference and
//! map counts, its mapping (anon_vma or slab cache) and list links used
//! by whoever owns it (buddy free lists, per-CPU lists, slab lists).
//!
//! Pages not handed to the page allocator (reserved by memblock, holes
//! inside a section) carry `PG_RESERVED` and are never freed.

extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::mm::anon_vma::AnonVma;

// ============================================================================
// Page flags (stored in atomic for lock-free access)
// ============================================================================

/// Page is locked (I/O in progress)
pub const PG_LOCKED: u32 = 1 << 0;

/// Page has been modified
pub const PG_DIRTY: u32 = 1 << 1;

/// Page is on LRU list
pub const PG_LRU: u32 = 1 << 2;

/// Page is on active list (recently accessed)
pub const PG_ACTIVE: u32 = 1 << 3;

/// Page is anonymous (not file-backed)
pub const PG_ANON: u32 = 1 << 4;

/// Page is in swap cache
pub const PG_SWAPCACHE: u32 = 1 << 5;

/// Page cannot be evicted (mlocked)
pub const PG_UNEVICTABLE: u32 = 1 << 6;

/// Page is being written back
pub const PG_WRITEBACK: u32 = 1 << 7;

/// Never handed to the page allocator (boot memory, holes)
pub const PG_RESERVED: u32 = 1 << 8;

/// Head of a free block on a buddy free list (`order` is its order)
pub const PG_BUDDY: u32 = 1 << 9;

/// First page of a compound page (`order` is its order)
pub const PG_HEAD: u32 = 1 << 10;

/// Other page of a compound page (`private` is the head's pfn)
pub const PG_TAIL: u32 = 1 << 11;

/// Page (head) of a slab
pub const PG_SLAB: u32 = 1 << 12;

/// A page-cache page's data is valid (Linux PG_uptodate)
pub const PG_UPTODATE: u32 = 1 << 13;

/// A page of a private mapping that one PTE maps and no one shares
/// copy-on-write (Linux PG_anon_exclusive): a write fault or mprotect
/// may make it writable in place whatever its count (pins). Set when the
/// mapping gets the page as its own (a fresh fault page, a copy-on-write
/// copy or reuse, an exclusive swap-in, a pin of a writable entry);
/// cleared when fork shares it and when reclaim unmaps it; the free
/// resets it.
pub const PG_ANON_EXCL: u32 = 1 << 14;

/// Page frame size
pub const PAGE_SHIFT: u32 = 12;

// ============================================================================
// struct page
// ============================================================================

/// Descriptor of one physical page frame (Linux struct page, 64 bytes)
#[repr(C, align(64))]
pub struct Page {
    /// Page flags (atomic for lock-free flag checks)
    pub flags: AtomicU32,
    /// Buddy block or compound page order
    pub order: AtomicU32,
    /// References (Linux _refcount): 0 = free
    pub refcount: AtomicU32,
    /// Page table entries mapping an anonymous page (Linux _mapcount)
    pub mapcount: AtomicU32,
    /// Anonymous: AnonVma pointer with the low bit set, holding one
    /// reference; slab: its cache
    pub mapping: AtomicU64,
    /// Index within the mapping (virtual page for anonymous pages)
    pub index: AtomicU64,
    /// List links, pfn + 1 (0 = none), owned by the list holder's lock
    pub next: AtomicU64,
    pub prev: AtomicU64,
    /// Compound tail: the head's pfn; slab: first free object
    pub private: AtomicU64,
    /// Slab: objects in use
    pub inuse: AtomicU32,
    /// Page-table page: its split PTE lock (Linux ptdesc ptl; `mm::ptl`)
    pub ptl: AtomicU32,
}

const _: () = assert!(core::mem::size_of::<Page>() == 64);

impl Page {
    /// A reserved page with nothing else set
    pub const fn new() -> Self {
        Self {
            flags: AtomicU32::new(PG_RESERVED),
            order: AtomicU32::new(0),
            refcount: AtomicU32::new(0),
            mapcount: AtomicU32::new(0),
            mapping: AtomicU64::new(0),
            index: AtomicU64::new(0),
            next: AtomicU64::new(0),
            prev: AtomicU64::new(0),
            private: AtomicU64::new(0),
            inuse: AtomicU32::new(0),
            ptl: AtomicU32::new(0),
        }
    }

    // ========================================================================
    // Flag accessors
    // ========================================================================

    #[inline]
    fn has(&self, flag: u32) -> bool {
        self.flags.load(Ordering::Relaxed) & flag != 0
    }

    /// Check if page is anonymous
    #[inline]
    pub fn is_anon(&self) -> bool {
        self.has(PG_ANON)
    }

    /// Check if page is locked
    #[inline]
    pub fn is_locked(&self) -> bool {
        self.has(PG_LOCKED)
    }

    /// Check if page is unevictable (mlocked)
    #[inline]
    pub fn is_unevictable(&self) -> bool {
        self.has(PG_UNEVICTABLE)
    }

    /// Check if page is on LRU list
    #[inline]
    pub fn is_on_lru(&self) -> bool {
        self.has(PG_LRU)
    }

    /// Check if page is on active LRU list
    #[inline]
    pub fn is_active(&self) -> bool {
        self.has(PG_ACTIVE)
    }

    /// Check if page is dirty
    #[inline]
    pub fn is_dirty(&self) -> bool {
        self.has(PG_DIRTY)
    }

    /// Check if page is in swap cache
    #[inline]
    pub fn is_swapcache(&self) -> bool {
        self.has(PG_SWAPCACHE)
    }

    /// Never handed to the page allocator
    #[inline]
    pub fn is_reserved(&self) -> bool {
        self.has(PG_RESERVED)
    }

    /// The private mapping that maps it owns it alone (Linux
    /// PageAnonExclusive)
    #[inline]
    pub fn anon_exclusive(&self) -> bool {
        self.has(PG_ANON_EXCL)
    }

    /// Its private mapping owns it alone (Linux SetPageAnonExclusive)
    #[inline]
    pub fn set_anon_exclusive(&self) {
        self.set_flag(PG_ANON_EXCL);
    }

    /// Its private mapping may write it in place whatever its count:
    /// owned alone and not in the swap cache (a cached page is a clean
    /// copy of its slot, written back only if PG_DIRTY: it becomes
    /// writable only once out of the cache)
    #[inline]
    pub fn reusable(&self) -> bool {
        self.anon_exclusive() && !self.is_swapcache()
    }

    // ========================================================================
    // Flag modifiers
    // ========================================================================

    /// Set a flag
    #[inline]
    pub fn set_flag(&self, flag: u32) {
        self.flags.fetch_or(flag, Ordering::Relaxed);
    }

    /// Clear a flag
    #[inline]
    pub fn clear_flag(&self, flag: u32) {
        self.flags.fetch_and(!flag, Ordering::Relaxed);
    }

    /// Try to lock the page (set PG_LOCKED if not already set)
    /// Returns true if lock was acquired
    #[inline]
    pub fn try_lock(&self) -> bool {
        let old = self.flags.fetch_or(PG_LOCKED, Ordering::Acquire);
        old & PG_LOCKED == 0
    }

    /// Unlock the page
    #[inline]
    pub fn unlock(&self) {
        self.flags.fetch_and(!PG_LOCKED, Ordering::Release);
    }

    // ========================================================================
    // Mapcount operations
    // ========================================================================

    /// Get current mapcount
    #[inline]
    pub fn mapcount(&self) -> u32 {
        self.mapcount.load(Ordering::Relaxed)
    }

    /// Increment mapcount (when a new PTE maps this page)
    #[inline]
    pub fn inc_mapcount(&self) {
        self.mapcount.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement mapcount (never below 0) and return the new value
    #[inline]
    pub fn dec_mapcount(&self) -> u32 {
        let mut c = self.mapcount.load(Ordering::Relaxed);
        loop {
            let n = c.saturating_sub(1);
            match self
                .mapcount
                .compare_exchange_weak(c, n, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return n,
                Err(cur) => c = cur,
            }
        }
    }

    // ========================================================================
    // Anonymous page mapping
    // ========================================================================

    /// Set this page as anonymous with the given anon_vma; the page
    /// holds a reference on it until `clear_mapping` (a mapping set
    /// before is released)
    pub fn set_anon_mapping(&self, anon_vma: &Arc<AnonVma>) {
        let ptr = Arc::into_raw(anon_vma.clone()) as u64 | 1;
        self.set_flag(PG_ANON);
        let old = self.mapping.swap(ptr, Ordering::AcqRel);
        put_mapping(old);
    }

    /// Get the anon_vma for this anonymous page
    ///
    /// Returns None if this is not an anonymous page or has no mapping.
    /// The returned Arc is a new reference (increments refcount).
    pub fn get_anon_vma(&self) -> Option<Arc<AnonVma>> {
        if !self.is_anon() {
            return None;
        }
        let ptr = self.mapping.load(Ordering::Acquire);
        if ptr & 1 == 0 || ptr & !1 == 0 {
            return None;
        }
        let raw = (ptr & !1) as *const AnonVma;
        // SAFETY: the page holds a reference (`set_anon_mapping`); this
        // takes another for the caller
        unsafe {
            Arc::increment_strong_count(raw);
            Some(Arc::from_raw(raw))
        }
    }

    /// Clear the mapping, dropping the page's anon_vma reference
    pub fn clear_mapping(&self) {
        let old = self.mapping.swap(0, Ordering::AcqRel);
        self.clear_flag(PG_ANON);
        put_mapping(old);
    }

    /// Detach the mapping, flags and counts of a page about to be freed;
    /// the returned mapping word goes to `put_mapping` once no allocator
    /// lock is held (it may free an AnonVma)
    pub fn free_prepare(&self) -> u64 {
        let old = self.mapping.swap(0, Ordering::AcqRel);
        self.flags.store(0, Ordering::Relaxed);
        self.mapcount.store(0, Ordering::Relaxed);
        self.index.store(0, Ordering::Relaxed);
        old
    }
}

// ============================================================================
// Page lock (Linux folio_lock: PG_locked, hashed wait queues)
// ============================================================================

/// Lock the page at `phys` (Linux folio_lock), sleeping while another
/// task holds it. A sleeping lock: thread context, no spinlock held;
/// order: mmap_lock -> page lock -> AnonVma lock -> PTE lock. The
/// caller holds a reference on the page.
pub fn lock_page(phys: u64) {
    let Some(pg) = phys_to_page(phys) else {
        return;
    };
    while !pg.try_lock() {
        crate::sync::waitqueue::page_wait_queue(phys).wait_event(|| !pg.is_locked());
    }
}

/// The page at `phys` is a private mapping's own, writable in place
/// whatever its count ([`Page::reusable`]; Linux PageAnonExclusive)
pub fn reusable(phys: u64) -> bool {
    phys_to_page(phys).is_some_and(|p| p.reusable())
}

/// Unlock the page at `phys` and wake its waiters (Linux folio_unlock)
pub fn unlock_page(phys: u64) {
    if let Some(pg) = phys_to_page(phys) {
        pg.unlock();
        crate::sync::waitqueue::page_wait_queue(phys).wake_all();
    }
}

/// Lock the page at `phys` if no one holds it (Linux folio_trylock):
/// never sleeps, so it may be taken under a spinlock
pub fn trylock_page(phys: u64) -> bool {
    phys_to_page(phys).is_some_and(|pg| pg.try_lock())
}

// ============================================================================
// Page contents (Linux clear_page, copy_page, kmap_local_page)
// ============================================================================

/// The bytes of the 4KB page frame at `phys`, through the direct map
///
/// # Safety
/// `phys` is a RAM frame the caller may access for `'a`: it owns it,
/// holds its page lock, or keeps it referenced while no one else writes
/// it; and no other reference to its bytes is alive meanwhile.
#[inline]
pub unsafe fn frame_bytes<'a>(phys: u64) -> &'a mut [u8] {
    // SAFETY: a direct-mapped RAM frame; exclusivity is the caller's
    unsafe { core::slice::from_raw_parts_mut(crate::arch::phys_to_virt(phys), 1 << PAGE_SHIFT) }
}

/// Zero the page frame at `phys` (Linux clear_page)
///
/// # Safety
/// As [`frame_bytes`].
#[inline]
pub unsafe fn clear_page(phys: u64) {
    // SAFETY: the caller's contract
    unsafe { frame_bytes(phys) }.fill(0);
}

/// Copy the page frame `src` to `dst` (Linux copy_page)
///
/// # Safety
/// As [`frame_bytes`] for `dst`; `src` is a different RAM frame no
/// one writes meanwhile.
#[inline]
pub unsafe fn copy_page(dst: u64, src: u64) {
    debug_assert_ne!(dst, src);
    // SAFETY: the caller's contract; two different frames
    unsafe { frame_bytes(dst).copy_from_slice(frame_bytes(src)) };
}

/// Copy the page frame `src`, which another party (user space, a
/// device) may write meanwhile, to `dst` (Linux copy_user_highpage of a
/// shared kernel page): word by word with volatile reads, so a racing
/// write gives some mix of old and new bytes, never undefined behavior
///
/// # Safety
/// As [`frame_bytes`] for `dst`; `src` is a different RAM frame that
/// stays allocated meanwhile.
pub unsafe fn copy_page_racy(dst: u64, src: u64) {
    debug_assert_ne!(dst, src);
    let words = (1usize << PAGE_SHIFT) / 8;
    let s = crate::arch::phys_to_virt(src).cast::<u64>();
    let d = crate::arch::phys_to_virt(dst).cast::<u64>();
    for i in 0..words {
        // SAFETY: word `i` of two allocated RAM frames (the caller's
        // contract), page-aligned; `dst` is the caller's alone
        unsafe { d.add(i).write(s.add(i).read_volatile()) };
    }
}

/// Copy `src` to byte `off` of the frame `phys`, which user space may
/// access meanwhile (a pinned user page): volatile byte stores, so a
/// racing access sees some mix of old and new bytes, never undefined
/// behavior (Linux copy_to_page over a kmap)
///
/// # Safety
/// `phys` is a RAM frame kept allocated meanwhile (pinned) and meant to
/// be written (no kernel data); [off, off + src.len()) lies in it.
pub unsafe fn copy_to_frame_racy(phys: u64, off: usize, src: &[u8]) {
    debug_assert!(off + src.len() <= 1 << PAGE_SHIFT);
    let d = crate::arch::phys_to_virt(phys).wrapping_add(off);
    for (i, &b) in src.iter().enumerate() {
        // SAFETY: byte `off + i` of the frame, in it (the caller's
        // contract); volatile: another party may access it
        unsafe { d.add(i).write_volatile(b) };
    }
}

/// Fill `dst` from byte `off` of the frame `phys`, which user space may
/// write meanwhile: volatile byte loads (as `copy_to_frame_racy`)
///
/// # Safety
/// `phys` is a RAM frame kept allocated meanwhile (pinned);
/// [off, off + dst.len()) lies in it.
pub unsafe fn copy_from_frame_racy(dst: &mut [u8], phys: u64, off: usize) {
    debug_assert!(off + dst.len() <= 1 << PAGE_SHIFT);
    let s = crate::arch::phys_to_virt(phys).wrapping_add(off);
    for (i, b) in dst.iter_mut().enumerate() {
        // SAFETY: byte `off + i` of the frame, in it (the caller's
        // contract)
        *b = unsafe { s.add(i).read_volatile() };
    }
}

/// Release a mapping word taken off a page: an anon_vma reference
pub fn put_mapping(word: u64) {
    if word & 1 != 0 && word & !1 != 0 {
        // SAFETY: anonymous mappings hold one reference (`set_anon_mapping`)
        unsafe { Arc::decrement_strong_count((word & !1) as *const AnonVma) };
    }
}

// ============================================================================
// vmemmap
// ============================================================================

/// Pfns per memory section (128MB, Linux SECTION_SIZE_BITS 27)
pub const SECTION_PFNS: u64 = 1 << (27 - PAGE_SHIFT);

/// Physical address bits the memory map covers (Linux x86-64
/// MAX_PHYSMEM_BITS 46)
const MAX_PHYS_BITS: u32 = 46;

const NR_SECTIONS: usize = 1 << (MAX_PHYS_BITS - 27);

/// Sections whose struct pages are mapped (set at boot, read lock-free)
static SECTIONS: [AtomicU64; NR_SECTIONS / 64] = [const { AtomicU64::new(0) }; NR_SECTIONS / 64];

/// Last pfn + 1 the memory map covers
pub const MAX_PFN: u64 = 1 << (MAX_PHYS_BITS - PAGE_SHIFT);

/// The pfn has a struct page (Linux pfn_valid)
#[inline]
pub fn pfn_valid(pfn: u64) -> bool {
    let sec = (pfn / SECTION_PFNS) as usize;
    sec < NR_SECTIONS && SECTIONS[sec / 64].load(Ordering::Acquire) & (1 << (sec % 64)) != 0
}

/// The struct page of `pfn`, which must be valid (checked: one bitmap
/// test keeps this safe fn from reading unmapped memory)
#[inline]
pub fn pfn_to_page(pfn: u64) -> &'static Page {
    assert!(pfn_valid(pfn), "pfn_to_page: invalid pfn {pfn:#x}");
    // SAFETY: the memory map of a valid pfn's section is mapped for good
    unsafe { &*((crate::arch::paging::VMEMMAP_START + pfn * 64) as *const Page) }
}

/// The struct page of the frame at `phys`, if it has one
#[inline]
pub fn phys_to_page(phys: u64) -> Option<&'static Page> {
    let pfn = phys >> PAGE_SHIFT;
    pfn_valid(pfn).then(|| pfn_to_page(pfn))
}

/// Bytes of one section's struct pages: one 2MB block
const SECTION_MAP: u64 = SECTION_PFNS * 64;
const _: () = assert!(SECTION_MAP == 2 << 20 && core::mem::size_of::<Page>() == 64);

/// Fill the `len` bytes of fresh boot memory at `pa` with struct pages
fn init_pages(pa: u64, len: u64) {
    let p = crate::arch::phys_to_virt(pa).cast::<Page>();
    for i in 0..(len as usize / core::mem::size_of::<Page>()) {
        // SAFETY: fresh memory for that many struct pages
        unsafe { p.add(i).write(Page::new()) };
    }
}

/// A zeroed boot frame for the memory map's page tables
fn zeroed_frame() -> u64 {
    let pa = crate::mm::memblock::alloc(4096, 4096);
    // SAFETY: a fresh memblock frame, reached through the direct map
    unsafe { core::ptr::write_bytes(crate::arch::phys_to_virt(pa), 0, 4096) };
    pa
}

/// The first section after `after` (from 0 for None) that holds RAM of
/// the sorted `ranges` (Linux for_each_present_section_nr)
fn next_section(ranges: &[crate::mm::memblock::Range], after: Option<u64>) -> Option<u64> {
    let from = after.map_or(0, |s| s + 1);
    ranges.iter().find_map(|r| {
        let first = (r.base >> PAGE_SHIFT) / SECTION_PFNS;
        let last = (r.end >> PAGE_SHIFT).min(MAX_PFN).div_ceil(SECTION_PFNS);
        let sec = first.max(from);
        (sec < last).then_some(sec)
    })
}

/// The next RAM section of memblock after `after` (the lock is dropped
/// before the caller allocates from memblock)
fn next_ram_section(after: Option<u64>) -> Option<u64> {
    next_section(crate::mm::memblock::MEMBLOCK.lock().memory.ranges(), after)
}

/// Map and initialize the struct pages of every section holding RAM
/// (Linux sparse_init + memmap_init): every page starts reserved; the
/// page allocator frees what memblock left free. Boot CPU, before SMP
/// and before memblock's free ranges are handed out.
pub fn vmemmap_init() {
    let mut cur = None;
    while let Some(sec) = next_ram_section(cur) {
        cur = Some(sec);
        let va = crate::arch::paging::VMEMMAP_START + sec * SECTION_MAP;
        // One 2MB block per section if memblock has one, else 4KB pages
        // (Linux vmemmap_populate_hugepages, falling back to
        // vmemmap_populate_basepages)
        let block = crate::mm::memblock::MEMBLOCK
            .lock()
            .alloc(SECTION_MAP, SECTION_MAP);
        if let Some(pa) = block {
            init_pages(pa, SECTION_MAP);
            // SAFETY: boot CPU, before SMP; the vmemmap range is unused
            unsafe { crate::mm::swapper::map_pmd(va, pa, &mut zeroed_frame) };
        } else {
            for off in (0..SECTION_MAP).step_by(4096) {
                let pa = crate::mm::memblock::alloc(4096, 4096);
                init_pages(pa, 4096);
                // SAFETY: as above
                unsafe { crate::mm::swapper::map_page(va + off, pa, &mut zeroed_frame) };
            }
        }
        let s = sec as usize;
        SECTIONS[s / 64].fetch_or(1 << (s % 64), Ordering::Release);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Every RAM section is visited once, ascending, however many there
    /// are (40GB: 320 sections; a fixed 256-entry list panicked)
    #[test]
    fn sections_of_large_memory() {
        use crate::mm::memblock::Range;
        const GB: u64 = 1 << 30;
        let ranges = [
            Range {
                base: 0x1000,
                end: 0x9f000,
            },
            Range {
                base: 1 << 20,
                end: 3 * GB,
            },
            Range {
                base: 4 * GB,
                end: 41 * GB + 4096,
            },
        ];
        let mut secs = Vec::new();
        let mut cur = None;
        while let Some(s) = next_section(&ranges, cur) {
            secs.push(s);
            cur = Some(s);
        }
        // 0..24 (3GB), 32..328 (4GB..41GB) and the page past 41GB
        let want: Vec<u64> = (0..24).chain(32..329).collect();
        assert_eq!(secs, want);
    }

    #[test]
    fn test_page_descriptor_flags() {
        let page = Page::new();
        assert!(page.is_reserved());
        page.clear_flag(PG_RESERVED);

        assert!(!page.is_anon());
        assert!(!page.is_locked());
        assert!(!page.is_unevictable());

        page.set_flag(PG_ANON);
        assert!(page.is_anon());

        page.set_flag(PG_LOCKED);
        assert!(page.is_locked());

        page.clear_flag(PG_LOCKED);
        assert!(!page.is_locked());
        assert!(page.is_anon()); // Still set
    }

    #[test]
    fn test_page_descriptor_mapcount() {
        let page = Page::new();

        assert_eq!(page.mapcount(), 0);

        page.inc_mapcount();
        assert_eq!(page.mapcount(), 1);

        page.inc_mapcount();
        assert_eq!(page.mapcount(), 2);

        assert_eq!(page.dec_mapcount(), 1);
        assert_eq!(page.dec_mapcount(), 0);
        // Never below zero
        assert_eq!(page.dec_mapcount(), 0);
        assert_eq!(page.mapcount(), 0);
    }

    #[test]
    fn test_page_descriptor_try_lock() {
        let page = Page::new();

        // First lock should succeed
        assert!(page.try_lock());
        assert!(page.is_locked());

        // Second lock should fail
        assert!(!page.try_lock());

        // Unlock
        page.unlock();
        assert!(!page.is_locked());

        // Can lock again
        assert!(page.try_lock());
    }

    #[test]
    fn anon_mapping_holds_a_reference() {
        let av = AnonVma::new().unwrap();
        let page = Page::new();
        page.set_anon_mapping(&av);
        assert_eq!(Arc::strong_count(&av), 2);
        let got = page.get_anon_vma().unwrap();
        assert!(Arc::ptr_eq(&got, &av));
        drop(got);
        // Re-setting releases the old reference
        page.set_anon_mapping(&av);
        assert_eq!(Arc::strong_count(&av), 2);
        page.clear_mapping();
        assert_eq!(Arc::strong_count(&av), 1);
        assert!(!page.is_anon());
        page.clear_mapping();
        assert_eq!(Arc::strong_count(&av), 1);
    }

    #[test]
    fn anon_exclusive_until_freed() {
        let page = Page::new();
        assert!(!page.anon_exclusive());
        page.set_anon_exclusive();
        assert!(page.anon_exclusive());
        page.clear_flag(PG_ANON_EXCL);
        assert!(!page.anon_exclusive());
        page.set_anon_exclusive();
        put_mapping(page.free_prepare());
        assert!(!page.anon_exclusive());
    }

    #[test]
    fn free_prepare_resets() {
        let av = AnonVma::new().unwrap();
        let page = Page::new();
        page.set_anon_mapping(&av);
        page.inc_mapcount();
        page.index.store(42, Ordering::Relaxed);
        let m = page.free_prepare();
        assert_eq!(page.flags.load(Ordering::Relaxed), 0);
        assert_eq!(page.mapcount(), 0);
        assert_eq!(page.index.load(Ordering::Relaxed), 0);
        assert_eq!(Arc::strong_count(&av), 2);
        put_mapping(m);
        assert_eq!(Arc::strong_count(&av), 1);
    }

    #[test]
    fn no_struct_page_without_memory_map() {
        assert!(!pfn_valid(MAX_PFN));
        assert!(phys_to_page(0x1000).is_none());
    }
}

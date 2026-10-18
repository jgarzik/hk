//! Buddy page allocator with per-CPU page lists (Linux mm/page_alloc.c)
//!
//! One zone covers all RAM (single node; no DMA/DMA32 split yet). Free
//! memory sits in power-of-two blocks of 2^0..2^MAX_ORDER pages on
//! per-order free lists threaded through struct page (`next`/`prev`);
//! a freed block merges with its free buddy. Order-0 pages go through a
//! per-CPU list first (Linux per_cpu_pages): allocation and free touch
//! only this CPU's list, with interrupts off, and move `batch` pages to
//! or from the buddy lists when it runs empty or past `high`.
//!
//! Locking: each per-CPU list has its own lock (`IrqSpinlock`; Linux
//! pcp->lock), taken by its CPU for every use and by another CPU only to
//! drain the list when an allocation fails (Linux drain_all_pages);
//! `Zone.lock` (`IrqSpinlock`, leaf) guards the buddy lists and is taken
//! under it (Linux order: pcp -> zone->lock). No CPU holds two per-CPU
//! list locks at once. Both are IRQ-safe, so pages may be freed or
//! allocated in interrupt context. Nothing is freed back into another subsystem under either:
//! a page's struct page is reset (`free_prepare`) and its mapping
//! released before any allocator lock is taken.
//!
//! Reference counts live in struct page (`refcount`): an allocation
//! starts at 1, the page is freed when it drops to 0. Compound pages
//! (`__GFP_COMP`, 2MB huge pages) count on the head; tails point to it.
//!
//! Frees are checked (Linux bad_page): freeing a reserved page, a page
//! on a free list or an unreferenced one (a double free), are reported
//! and refused, so a page is never on a free list twice; a reference
//! is never taken on a free page (`get` fails: get_page_unless_zero); an allocated block found referenced is
//! leaked. Every pfn from outside is checked against the zone and the
//! memory map's sections before its struct page is touched.

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::arch::IrqSpinlock;
use crate::cpumask::NR_CPUS;
use crate::mm::page::{PG_BUDDY, PG_HEAD, PG_RESERVED, PG_TAIL, Page, put_mapping};

/// Largest block order (2^10 pages = 4MB, Linux MAX_PAGE_ORDER)
pub const MAX_ORDER: u32 = 10;

const ORDERS: usize = MAX_ORDER as usize + 1;

// The largest block never crosses a memory section (pfn_valid unit)
const _: () = assert!(crate::mm::page::SECTION_PFNS >= 1 << MAX_ORDER);

// ============================================================================
// GFP flags
// ============================================================================

/// Allocation flags (Linux gfp_t subset)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gfp(pub u32);

impl Gfp {
    /// May use part of the reserves (Linux __GFP_HIGH)
    pub const HIGH: Gfp = Gfp(1 << 0);
    /// Zero the pages
    pub const ZERO: Gfp = Gfp(1 << 1);
    /// A compound page (head counts for all)
    pub const COMP: Gfp = Gfp(1 << 2);
    /// The caller may sleep (Linux __GFP_DIRECT_RECLAIM)
    pub const RECLAIM: Gfp = Gfp(1 << 3);
    /// For user space (Linux __GFP_HARDWALL)
    pub const HARDWALL: Gfp = Gfp(1 << 4);
    /// Movable user data (Linux __GFP_MOVABLE)
    pub const MOVABLE: Gfp = Gfp(1 << 5);
    /// Failure is expected; do not report it
    pub const NOWARN: Gfp = Gfp(1 << 6);
    /// The caller holds no spinlock and may sleep in direct reclaim
    /// (Linux __GFP_DIRECT_RECLAIM in its own sense: hk's
    /// `Gfp::RECLAIM` only means thread context, since kernel heap
    /// allocations happen under spinlocks)
    pub const DIRECT: Gfp = Gfp(1 << 7);

    /// Kernel allocation from thread context
    pub const KERNEL: Gfp = Gfp::RECLAIM;
    /// Cannot sleep, may dip into reserves (interrupt context)
    pub const ATOMIC: Gfp = Gfp::HIGH;
    /// Cannot sleep, no reserves
    pub const NOWAIT: Gfp = Gfp(0);
    /// User memory the kernel needs to address
    pub const USER: Gfp = Gfp(Gfp::KERNEL.0 | Gfp::HARDWALL.0);
    /// User page data (anonymous memory, page cache)
    pub const HIGHUSER_MOVABLE: Gfp = Gfp(Gfp::USER.0 | Gfp::MOVABLE.0);
    /// User page data for a caller that may reclaim (a page fault with
    /// only the mmap_lock held)
    pub const HIGHUSER_RECLAIM: Gfp = Gfp(Gfp::HIGHUSER_MOVABLE.0 | Gfp::DIRECT.0);
    /// An opportunistic huge page for user data (Linux
    /// GFP_TRANSHUGE_LIGHT): never drains or reclaims, the fault falls
    /// back to 4KB pages
    pub const TRANSHUGE_LIGHT: Gfp = Gfp(Gfp::HARDWALL.0 | Gfp::MOVABLE.0 | Gfp::NOWARN.0);

    pub const fn has(self, f: Gfp) -> bool {
        self.0 & f.0 == f.0
    }

    pub const fn with(self, f: Gfp) -> Gfp {
        Gfp(self.0 | f.0)
    }

    /// User data: kept above the kernel's reserve
    pub const fn user(self) -> bool {
        self.has(Gfp::HARDWALL)
    }
}

// ============================================================================
// Watermarks
// ============================================================================

/// Zone watermarks (Linux enum zone_watermarks)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wmark {
    Min = 0,
    Low = 1,
    High = 2,
}

/// Linux min_free_kbytes for `managed` pages: sqrt(lowmem kB * 16),
/// clamped to [128, 262144] (init_per_zone_wmark_min)
pub fn min_free_kbytes(managed: usize) -> usize {
    let kb = managed * 4 * 16;
    kb.isqrt().clamp(128, 262_144)
}

/// The watermark an allocation must leave free, in pages (Linux
/// gfp_to_alloc_flags + __zone_watermark_ok): user data stops at the low
/// watermark, reclaim or not: until the OOM killer (P6) user data
/// stops at low (then Linux's min), leaving low - min to the kernel,
/// whose heap cannot fail gracefully. Kernel allocations stop at min,
/// __GFP_HIGH ones at half
/// of it, atomic (non-sleeping, __GFP_HIGH) ones a quarter lower still
fn alloc_mark(wmark: &[AtomicUsize; 3], gfp: Gfp) -> usize {
    if gfp.user() {
        return wmark[Wmark::Low as usize].load(Ordering::Relaxed);
    }
    let mut min = wmark[Wmark::Min as usize].load(Ordering::Relaxed);
    if gfp.has(Gfp::HIGH) {
        min -= min / 2;
        if !gfp.has(Gfp::RECLAIM) {
            min -= min / 4;
        }
    }
    min
}

// ============================================================================
// Per-CPU page lists
// ============================================================================

/// One CPU's order-0 page list (Linux per_cpu_pages)
struct Pcp {
    /// First page (pfn + 1, 0 = empty), linked through `Page.next`
    /// (under `lock`)
    lock: IrqSpinlock<u64>,
    /// Pages on the list (written under `lock`, read lock-free for
    /// statistics and to skip empty lists when draining)
    count: AtomicUsize,
}

impl Pcp {
    const fn new() -> Self {
        Self {
            lock: IrqSpinlock::new(0),
            count: AtomicUsize::new(0),
        }
    }
}

#[cfg(test)]
std::thread_local! {
    /// The CPU a host test thread plays
    pub static TEST_CPU: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// Rounds of direct reclaim before an allocation fails (Linux
/// MAX_RECLAIM_RETRIES)
const MAX_RECLAIM_RETRIES: usize = 16;

/// One pass of direct reclaim (none in host tests): pages freed
fn direct_reclaim() -> usize {
    #[cfg(not(test))]
    {
        crate::mm::vmscan::try_to_free_pages(crate::mm::vmscan::SWAP_CLUSTER_MAX)
    }
    #[cfg(test)]
    0
}

/// In an interrupt handler: allocations there never drain or reclaim,
/// whatever their flags (an IRQ-context caller must pass `Gfp::ATOMIC`;
/// one that passes `Gfp::RECLAIM` is a bug, caught in debug builds)
fn in_interrupt() -> bool {
    #[cfg(not(test))]
    {
        use crate::arch::{CurrentArch, PerCpuOps};
        let irq = CurrentArch::interrupt_depth() > 0;
        debug_assert!(!irq, "Gfp::RECLAIM allocation in interrupt context");
        irq
    }
    #[cfg(test)]
    false
}

/// This CPU; None before its per-CPU data exists (a CPU coming up, or
/// the boot CPU early), when per-CPU caches must not be used: the
/// caller takes the shared slow path instead. Host tests play CPU 0
/// unless they set `TEST_CPU`.
pub fn this_cpu() -> Option<usize> {
    #[cfg(not(test))]
    {
        use crate::arch::{CurrentArch, PerCpuOps};
        CurrentArch::try_current_cpu_id().map(|c| c as usize)
    }
    #[cfg(test)]
    Some(TEST_CPU.with(|c| c.get()))
}

// ============================================================================
// Zone
// ============================================================================

/// Buddy free lists (under `Zone.lock`)
struct FreeArea {
    /// First free block of each order (pfn + 1, 0 = none)
    head: [u64; ORDERS],
    /// Blocks on each list
    nr: [usize; ORDERS],
}

/// A range of physical memory managed as one pool (Linux struct zone)
pub struct Zone {
    /// Address of pfn 0's struct page: page(pfn) = map + pfn * 64 (the
    /// vmemmap; host tests point it at their own array)
    map: AtomicUsize,
    /// Pfns [start, end) the zone spans (holes are reserved pages)
    start: AtomicU64,
    end: AtomicU64,
    /// Buddy free lists (zone->lock)
    lock: IrqSpinlock<FreeArea>,
    /// Pages on the buddy lists (written under `lock`, read lock-free;
    /// Linux NR_FREE_PAGES)
    nr_free: AtomicUsize,
    /// Pages handed to the zone at boot (Linux managed_pages)
    managed: AtomicUsize,
    /// Bad page states seen (double frees, busy pages on a free list);
    /// such pages are leaked, never handed out twice
    bad: AtomicUsize,
    /// Check every pfn against the memory map's sections (the vmemmap
    /// backs only sections with RAM; host tests back the whole span)
    sections: core::sync::atomic::AtomicBool,
    /// Watermarks in pages (Wmark order)
    wmark: [AtomicUsize; 3],
    /// vm.min_free_kbytes the watermarks come from
    min_kb: AtomicUsize,
    /// Per-CPU list refill/drain size and limit
    batch: AtomicUsize,
    high: AtomicUsize,
    pcp: [Pcp; NR_CPUS],
    /// A drain of every CPU's list is running (Linux pcpu_drain_mutex)
    draining: AtomicBool,
}

impl Zone {
    pub const fn new() -> Self {
        Self {
            map: AtomicUsize::new(0),
            start: AtomicU64::new(0),
            end: AtomicU64::new(0),
            lock: IrqSpinlock::new(FreeArea {
                head: [0; ORDERS],
                nr: [0; ORDERS],
            }),
            nr_free: AtomicUsize::new(0),
            managed: AtomicUsize::new(0),
            bad: AtomicUsize::new(0),
            sections: core::sync::atomic::AtomicBool::new(false),
            wmark: [const { AtomicUsize::new(0) }; 3],
            min_kb: AtomicUsize::new(0),
            batch: AtomicUsize::new(1),
            high: AtomicUsize::new(0),
            pcp: [const { Pcp::new() }; NR_CPUS],
            draining: AtomicBool::new(false),
        }
    }

    /// Span pfns [start, end), struct pages at `map` + pfn * 64 (only
    /// for valid pfns when `sections`: the vmemmap); every page is
    /// reserved until `free_range` (boot, before any allocation)
    pub fn init(&self, map: usize, start: u64, end: u64, sections: bool) {
        self.sections.store(sections, Ordering::Relaxed);
        self.map.store(map, Ordering::Relaxed);
        self.start.store(start, Ordering::Relaxed);
        self.end.store(end, Ordering::Relaxed);
    }

    /// The struct page of `pfn` (inside the span)
    #[inline]
    pub fn page(&self, pfn: u64) -> &Page {
        let at = self
            .map
            .load(Ordering::Relaxed)
            .wrapping_add(pfn as usize * 64);
        // SAFETY: `init` mapped struct pages for the whole span's RAM
        // sections; callers pass pfns of pages they own or buddies of
        // them (same section)
        unsafe { &*(at as *const Page) }
    }

    /// The pfn is inside the zone
    #[inline]
    pub fn spans(&self, pfn: u64) -> bool {
        (self.start.load(Ordering::Relaxed)..self.end.load(Ordering::Relaxed)).contains(&pfn)
    }

    /// The pfn is inside the zone and has a struct page (a hole between
    /// RAM sections has none): check before `page` on any pfn not known
    /// to be ours
    #[inline]
    pub fn valid(&self, pfn: u64) -> bool {
        self.spans(pfn)
            && (!self.sections.load(Ordering::Relaxed) || crate::mm::page::pfn_valid(pfn))
    }

    /// A page in a state it must not be in (Linux bad_page): reported
    /// once per page and leaked
    fn bad_page(&self, pfn: u64, why: &str) {
        self.bad.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(test))]
        crate::printkln!("BUG: Bad page state: pfn {:#x}: {}", pfn, why);
        #[cfg(test)]
        let _ = (pfn, why);
    }

    /// Bad page states seen
    pub fn nr_bad(&self) -> usize {
        self.bad.load(Ordering::Relaxed)
    }

    // ------------------------------------------------------------------
    // Buddy lists (under `lock`)
    // ------------------------------------------------------------------

    fn list_add(&self, fa: &mut FreeArea, pfn: u64, order: u32) {
        let pg = self.page(pfn);
        let o = order as usize;
        let old = fa.head[o];
        pg.next.store(old, Ordering::Relaxed);
        pg.prev.store(0, Ordering::Relaxed);
        if old != 0 {
            self.page(old - 1).prev.store(pfn + 1, Ordering::Relaxed);
        }
        fa.head[o] = pfn + 1;
        fa.nr[o] += 1;
        pg.order.store(order, Ordering::Relaxed);
        pg.flags.store(PG_BUDDY, Ordering::Relaxed);
    }

    fn list_del(&self, fa: &mut FreeArea, pfn: u64, order: u32) {
        let pg = self.page(pfn);
        let (next, prev) = (
            pg.next.load(Ordering::Relaxed),
            pg.prev.load(Ordering::Relaxed),
        );
        if prev != 0 {
            self.page(prev - 1).next.store(next, Ordering::Relaxed);
        } else {
            fa.head[order as usize] = next;
        }
        if next != 0 {
            self.page(next - 1).prev.store(prev, Ordering::Relaxed);
        }
        fa.nr[order as usize] -= 1;
        pg.flags.store(0, Ordering::Relaxed);
    }

    /// Free block [pfn, pfn + 2^order): merge with free buddies (Linux
    /// __free_one_page)
    fn free_one(&self, fa: &mut FreeArea, mut pfn: u64, mut order: u32) {
        self.nr_free.fetch_add(1 << order, Ordering::Relaxed);
        while order < MAX_ORDER {
            // A buddy is in the same 2^MAX_ORDER block, so in the same
            // memory section; outside the zone it is never merged
            let buddy = pfn ^ (1 << order);
            if !self.valid(buddy) {
                break;
            }
            let b = self.page(buddy);
            if b.flags.load(Ordering::Relaxed) != PG_BUDDY
                || b.order.load(Ordering::Relaxed) != order
            {
                break;
            }
            self.list_del(fa, buddy, order);
            pfn &= !(1 << order);
            order += 1;
        }
        self.list_add(fa, pfn, order);
    }

    /// Take a block of `order`, splitting a larger one (Linux
    /// __rmqueue_smallest + expand)
    fn take(&self, fa: &mut FreeArea, order: u32) -> Option<u64> {
        let found = (order..=MAX_ORDER).find(|&o| fa.head[o as usize] != 0)?;
        let pfn = fa.head[found as usize] - 1;
        self.list_del(fa, pfn, found);
        let mut o = found;
        while o > order {
            o -= 1;
            self.list_add(fa, pfn + (1 << o), o);
        }
        self.nr_free.fetch_sub(1 << order, Ordering::Relaxed);
        Some(pfn)
    }

    // ------------------------------------------------------------------
    // Per-CPU lists (this CPU, interrupts off)
    // ------------------------------------------------------------------

    /// This CPU's list (None: no per-CPU data yet)
    fn pcp(&self) -> Option<&Pcp> {
        this_cpu().map(|c| &self.pcp[c])
    }

    fn pcp_push(&self, p: &Pcp, head: &mut u64, pfn: u64) {
        self.page(pfn).next.store(*head, Ordering::Relaxed);
        *head = pfn + 1;
        p.count.fetch_add(1, Ordering::Relaxed);
    }

    fn pcp_pop(&self, p: &Pcp, head: &mut u64) -> Option<u64> {
        let pfn = head.checked_sub(1)?;
        *head = self.page(pfn).next.load(Ordering::Relaxed);
        p.count.fetch_sub(1, Ordering::Relaxed);
        Some(pfn)
    }

    /// Order-0 page from this CPU's list, refilled with `batch` pages
    /// from the buddy lists when empty (Linux rmqueue_pcplist)
    fn pcp_alloc(&self) -> Option<u64> {
        let Some(p) = self.pcp() else {
            return self.take(&mut self.lock.lock(), 0);
        };
        let mut head = p.lock.lock();
        if *head == 0 {
            let mut fa = self.lock.lock();
            for _ in 0..self.batch.load(Ordering::Relaxed) {
                match self.take(&mut fa, 0) {
                    Some(pfn) => self.pcp_push(p, &mut head, pfn),
                    None => break,
                }
            }
        }
        self.pcp_pop(p, &mut head)
    }

    /// Order-0 page onto this CPU's list; past `high`, `batch` pages go
    /// back to the buddy lists (Linux free_unref_page)
    fn pcp_free(&self, pfn: u64) {
        let Some(p) = self.pcp() else {
            self.free_one(&mut self.lock.lock(), pfn, 0);
            return;
        };
        let mut head = p.lock.lock();
        self.pcp_push(p, &mut head, pfn);
        if p.count.load(Ordering::Relaxed) > self.high.load(Ordering::Relaxed) {
            let mut fa = self.lock.lock();
            for _ in 0..self.batch.load(Ordering::Relaxed) {
                match self.pcp_pop(p, &mut head) {
                    Some(pfn) => self.free_one(&mut fa, pfn, 0),
                    None => break,
                }
            }
        }
    }

    /// Give every CPU's list back to the buddy lists (Linux
    /// drain_all_pages, which drains each CPU's list under its pcp->lock
    /// from the calling CPU): pages there are invisible to watermarks
    /// and buddy merging. One list lock at a time.
    ///
    /// One drain at a time (Linux pcpu_drain_mutex, taken with trylock):
    /// a caller that finds one running returns at once, never waits
    /// (it may hold spinlocks, or have interrupted the drainer); false
    /// then.
    pub fn drain_all(&self) -> bool {
        if self.draining.swap(true, Ordering::Acquire) {
            return false;
        }
        self.drain_lists();
        self.draining.store(false, Ordering::Release);
        true
    }

    fn drain_lists(&self) {
        for p in &self.pcp {
            if p.count.load(Ordering::Relaxed) == 0 {
                continue;
            }
            let mut head = p.lock.lock();
            let mut fa = self.lock.lock();
            while let Some(pfn) = self.pcp_pop(p, &mut head) {
                self.free_one(&mut fa, pfn, 0);
            }
        }
    }

    // ------------------------------------------------------------------
    // Allocation
    // ------------------------------------------------------------------

    /// Allocate 2^order pages; refcount 1 on the first (every page with
    /// `__GFP_COMP`: tails point at the head). On failure an allocation
    /// from thread context (`Gfp::RECLAIM`) drains the per-CPU lists and
    /// tries once more (Linux __alloc_pages_slowpath); atomic and
    /// opportunistic ones (a huge page the fault can do without) fail
    /// at once.
    pub fn alloc_pages(&self, order: u32, gfp: Gfp) -> Option<u64> {
        if order > MAX_ORDER {
            return None;
        }
        self.try_alloc(order, gfp)
            .or_else(|| self.slowpath(order, gfp))
    }

    /// The allocation failed its first attempt (Linux
    /// __alloc_pages_slowpath)
    fn slowpath(&self, order: u32, gfp: Gfp) -> Option<u64> {
        if !gfp.has(Gfp::RECLAIM) || in_interrupt() {
            return None;
        }
        if !gfp.has(Gfp::DIRECT) {
            // A drain already running elsewhere is making progress:
            // retry once either way
            self.drain_all();
            return self.try_alloc(order, gfp);
        }
        // Linux order: reclaim, drain, retry; again only while a pass
        // frees at least the allocation's size (should_reclaim_retry),
        // at most MAX_RECLAIM_RETRIES times. User data stays above low
        // (`alloc_mark`): no OOM killer before P6
        for _ in 0..MAX_RECLAIM_RETRIES {
            let freed = direct_reclaim();
            self.drain_all();
            if let Some(p) = self.try_alloc(order, gfp) {
                return Some(p);
            }
            if freed < 1 << order {
                break;
            }
        }
        None
    }

    /// One allocation attempt from the per-CPU and buddy lists (Linux
    /// get_page_from_freelist)
    fn try_alloc(&self, order: u32, gfp: Gfp) -> Option<u64> {
        if !self.watermark_ok(order, gfp) {
            return None;
        }
        loop {
            let pfn = if order == 0 {
                self.pcp_alloc()?
            } else {
                let mut fa = self.lock.lock();
                self.take(&mut fa, order)?
            };
            // A free block must be unreferenced (Linux check_new_page);
            // one that is not stays out of circulation
            if self.page(pfn).refcount.load(Ordering::Relaxed) != 0 {
                self.bad_page(pfn, "allocating a referenced page");
                continue;
            }
            self.prep_new(pfn, order, gfp);
            return Some(pfn);
        }
    }

    /// Set up the struct pages of a fresh block (Linux prep_new_page)
    fn prep_new(&self, pfn: u64, order: u32, gfp: Gfp) {
        let head = self.page(pfn);
        head.refcount.store(1, Ordering::Relaxed);
        if gfp.has(Gfp::COMP) && order > 0 {
            head.order.store(order, Ordering::Relaxed);
            head.flags.store(PG_HEAD, Ordering::Relaxed);
            for i in 1..1u64 << order {
                let t = self.page(pfn + i);
                t.private.store(pfn, Ordering::Relaxed);
                t.flags.store(PG_TAIL, Ordering::Relaxed);
            }
        }
        if gfp.has(Gfp::ZERO) {
            let len = 4096usize << order;
            // SAFETY: the block is ours, reached through the direct map
            unsafe { core::ptr::write_bytes(crate::arch::phys_to_virt(pfn << 12), 0, len) };
        }
    }

    /// Free 2^order pages at `pfn` whatever their counts say (Linux
    /// __free_pages_ok). The block must be allocated: a reserved page,
    /// one on a free list or an unreferenced one (a double free) is
    /// refused and reported, never put on a free list twice.
    pub fn free_pages(&self, pfn: u64, order: u32) {
        if order > MAX_ORDER || !self.valid(pfn) || !self.valid(pfn + (1 << order) - 1) {
            return;
        }
        let pg = self.page(pfn);
        if pg.flags.load(Ordering::Relaxed) & (PG_RESERVED | PG_BUDDY) != 0 {
            self.bad_page(pfn, "freeing a free or reserved page");
            return;
        }
        if pg.refcount.swap(0, Ordering::AcqRel) == 0 {
            self.bad_page(pfn, "double free");
            return;
        }
        self.release(pfn, order);
    }

    /// Free an order-0 page whose count its owner froze to 0 (Linux
    /// free_unref_page after folio_ref_freeze: reclaim)
    pub fn free_frozen(&self, pfn: u64) {
        if !self.valid(pfn) || self.page(pfn).refcount.load(Ordering::Acquire) != 0 {
            self.bad_page(pfn, "freeing a referenced frozen page");
            return;
        }
        self.release(pfn, 0);
    }

    /// Reset an unreferenced block's struct pages and put it on a free
    /// list
    fn release(&self, pfn: u64, order: u32) {
        // No allocator lock is held yet: a page leaves the LRU (Linux
        // __page_cache_release), a released mapping may free an AnonVma
        // (slab)
        #[cfg(not(test))]
        if order == 0 && self.sections.load(Ordering::Relaxed) {
            crate::mm::lru::page_freed(pfn);
        }
        for i in 0..1u64 << order {
            let pg = self.page(pfn + i);
            pg.refcount.store(0, Ordering::Relaxed);
            pg.private.store(0, Ordering::Relaxed);
            put_mapping(pg.free_prepare());
        }
        if order == 0 {
            self.pcp_free(pfn);
        } else {
            let mut fa = self.lock.lock();
            self.free_one(&mut fa, pfn, order);
        }
    }

    /// Order of the block a page heads: its compound order, else 0
    fn order_of(&self, pfn: u64) -> u32 {
        let pg = self.page(pfn);
        if pg.flags.load(Ordering::Relaxed) & PG_HEAD != 0 {
            pg.order.load(Ordering::Relaxed)
        } else {
            0
        }
    }

    // ------------------------------------------------------------------
    // Reference counts
    // ------------------------------------------------------------------

    /// Take a reference unless the page is free (Linux
    /// get_page_unless_zero): false, and no reference, if its count is
    /// (or drops to) 0 meanwhile; a saturated count stays saturated
    pub fn get(&self, pfn: u64) -> bool {
        let rc = &self.page(pfn).refcount;
        let mut c = rc.load(Ordering::Relaxed);
        loop {
            match c {
                0 => return false,
                u32::MAX => return true,
                _ => {}
            }
            match rc.compare_exchange_weak(c, c + 1, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return true,
                Err(cur) => c = cur,
            }
        }
    }

    /// Drop a reference, freeing the page (its compound block) with the
    /// last one; true if freed. A saturated count is sticky: more
    /// references than it can count were taken, so the page is never
    /// freed (leaked instead of freed while still in use); a zero count
    /// (free page) is left alone.
    pub fn put(&self, pfn: u64) -> bool {
        let rc = &self.page(pfn).refcount;
        let mut c = rc.load(Ordering::Relaxed);
        loop {
            if c == 0 || c == u32::MAX {
                return false;
            }
            match rc.compare_exchange_weak(c, c - 1, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => break,
                Err(cur) => c = cur,
            }
        }
        if c != 1 {
            return false;
        }
        self.release(pfn, self.order_of(pfn));
        true
    }

    /// Current reference count
    pub fn count(&self, pfn: u64) -> u32 {
        self.page(pfn).refcount.load(Ordering::Relaxed)
    }

    /// Turn a compound page into independent pages, each with the head's
    /// count (a split 2MB mapping: every PTE releases its own page)
    pub fn split(&self, pfn: u64) {
        let head = self.page(pfn);
        if head.flags.load(Ordering::Relaxed) & PG_HEAD == 0 {
            return;
        }
        let order = head.order.load(Ordering::Relaxed);
        let count = head.refcount.load(Ordering::Relaxed);
        for i in 1..1u64 << order {
            let t = self.page(pfn + i);
            t.flags.store(0, Ordering::Relaxed);
            t.private.store(0, Ordering::Relaxed);
            t.refcount.store(count, Ordering::Relaxed);
        }
        head.clear_flag(PG_HEAD);
        head.order.store(0, Ordering::Relaxed);
    }

    /// Order-n block split into 2^order order-0 pages of count 1 (Linux
    /// split_page)
    pub fn split_block(&self, pfn: u64, order: u32) {
        for i in 1..1u64 << order {
            self.page(pfn + i).refcount.store(1, Ordering::Relaxed);
        }
    }

    // ------------------------------------------------------------------
    // Boot and statistics
    // ------------------------------------------------------------------

    /// Hand the free pfns [start, end) to the buddy lists (boot; Linux
    /// memblock_free_all), in the largest aligned blocks that fit
    pub fn free_range(&self, mut start: u64, end: u64) {
        let (lo, hi) = (
            self.start.load(Ordering::Relaxed),
            self.end.load(Ordering::Relaxed),
        );
        start = start.max(lo);
        let end = end.min(hi);
        let mut fa = self.lock.lock();
        while start < end {
            let fit = 63 - (end - start).leading_zeros();
            let order = start.trailing_zeros().min(fit).min(MAX_ORDER);
            if !self.valid(start) || !self.valid(start + (1 << order) - 1) {
                start += 1 << order;
                continue;
            }
            for i in 0..1u64 << order {
                let pg = self.page(start + i);
                pg.flags.fetch_and(!PG_RESERVED, Ordering::Relaxed);
                pg.refcount.store(0, Ordering::Relaxed);
            }
            self.managed.fetch_add(1 << order, Ordering::Relaxed);
            self.free_one(&mut fa, start, order);
            start += 1 << order;
        }
    }

    /// Size the per-CPU lists from the zone size (Linux zone_batchsize:
    /// managed / 1024 capped at 1MB, / 4, rounded to 2^n - 1; high = 4
    /// batches)
    pub fn setup_pcp(&self) {
        let b = (self.managed() / 1024).min(256) / 4;
        let x = (b + b / 2).max(2);
        let batch = (1usize << (usize::BITS - 1 - x.leading_zeros())) - 1;
        self.batch.store(batch, Ordering::Relaxed);
        self.high.store(4 * batch, Ordering::Relaxed);
    }

    /// Set the watermarks from min_free_kbytes (Linux
    /// __setup_per_zone_wmarks): min = min_free_kbytes in pages; low and
    /// high add max(min / 4, managed * watermark_scale_factor / 10000)
    /// once and twice (scale factor 10)
    ///
    /// Called once every boot memory range is in the zone (the base is
    /// the final managed count), and again when vm.min_free_kbytes is
    /// written (`kb`; None = the formula)
    pub fn setup_wmarks(&self, kb: Option<usize>) {
        let managed = self.managed();
        let kb = kb.unwrap_or_else(|| min_free_kbytes(managed));
        self.min_kb.store(kb, Ordering::Relaxed);
        let min = kb / 4;
        let step = (min / 4).max(managed * 10 / 10_000);
        for (w, v) in self.wmark.iter().zip([min, min + step, min + 2 * step]) {
            w.store(v, Ordering::Relaxed);
        }
    }

    /// Drop the watermarks (tests that exhaust a zone)
    #[cfg(test)]
    pub fn clear_wmarks(&self) {
        self.wmark
            .iter()
            .for_each(|w| w.store(0, Ordering::Relaxed));
    }

    /// vm.min_free_kbytes
    pub fn min_free_kb(&self) -> usize {
        self.min_kb.load(Ordering::Relaxed)
    }

    /// A watermark, in pages
    pub fn wmark(&self, w: Wmark) -> usize {
        self.wmark[w as usize].load(Ordering::Relaxed)
    }

    /// Taking 2^order pages leaves the zone above the allocation's
    /// watermark (Linux zone_watermark_ok; free pages on per-CPU lists
    /// are not counted, as in Linux)
    pub fn watermark_ok(&self, order: u32, gfp: Gfp) -> bool {
        let free = self.nr_free() as isize - (1isize << order) + 1;
        free > alloc_mark(&self.wmark, gfp) as isize
    }

    /// Free memory is at or below a watermark
    pub fn below(&self, w: Wmark) -> bool {
        self.nr_free() <= self.wmark(w)
    }

    /// Pages handed to the zone at boot
    pub fn managed(&self) -> usize {
        self.managed.load(Ordering::Relaxed)
    }

    /// Pages on the buddy lists (what watermarks are checked against)
    pub fn nr_free(&self) -> usize {
        self.nr_free.load(Ordering::Relaxed)
    }

    /// Free pages, per-CPU lists included
    pub fn free_pages_all(&self) -> usize {
        let pcp: usize = self
            .pcp
            .iter()
            .map(|p| p.count.load(Ordering::Relaxed))
            .sum();
        self.nr_free() + pcp
    }

    /// Blocks on each buddy list (tests, diagnostics)
    pub fn nr_blocks(&self) -> [usize; ORDERS] {
        self.lock.lock().nr
    }
}

impl Default for Zone {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A zone over pfns [start, start + n) backed by a host array
    struct TestZone {
        z: Zone,
        _map: Vec<Page>,
    }

    fn zone(start: u64, n: usize) -> TestZone {
        let map: Vec<Page> = (0..n).map(|_| Page::new()).collect();
        let z = Zone::new();
        let base = (map.as_ptr() as usize).wrapping_sub(start as usize * 64);
        z.init(base, start, start + n as u64, false);
        TestZone { z, _map: map }
    }

    #[test]
    fn free_range_builds_maximal_blocks() {
        let t = zone(0, 4096);
        t.z.free_range(3, 4096);
        // 3 | 4..8 | 8..16 | ... | 1024..2048 2048..3072 3072..4096
        let nr = t.z.nr_blocks();
        assert_eq!(nr[0], 1);
        assert_eq!(nr[2], 1);
        assert_eq!(nr[10], 3);
        assert_eq!(t.z.nr_free(), 4093);
        assert_eq!(t.z.managed(), 4093);
        assert!(t.z.page(0).is_reserved());
    }

    #[test]
    fn split_and_merge_back() {
        let t = zone(0, 1024);
        t.z.free_range(0, 1024);
        assert_eq!(t.z.nr_blocks()[10], 1);
        let a = t.z.alloc_pages(3, Gfp::KERNEL).unwrap();
        assert_eq!(a % 8, 0);
        assert_eq!(t.z.nr_free(), 1016);
        let b = t.z.alloc_pages(9, Gfp::KERNEL).unwrap();
        assert_eq!(b % 512, 0);
        t.z.free_pages(a, 3);
        t.z.free_pages(b, 9);
        assert_eq!(t.z.nr_blocks()[10], 1);
        assert_eq!(t.z.nr_free(), 1024);
    }

    #[test]
    fn exhaustion_and_reuse() {
        let t = zone(512, 512);
        t.z.free_range(512, 1024);
        t.z.setup_pcp();
        let mut got = Vec::new();
        while let Some(p) = t.z.alloc_pages(0, Gfp::KERNEL) {
            assert!((512..1024).contains(&p));
            assert_eq!(t.z.count(p), 1);
            got.push(p);
        }
        assert_eq!(got.len(), 512);
        got.sort();
        got.dedup();
        assert_eq!(got.len(), 512);
        assert_eq!(t.z.alloc_pages(1, Gfp::KERNEL), None);
        for p in got {
            assert!(t.z.put(p));
        }
        assert_eq!(t.z.free_pages_all(), 512);
        // Higher orders come back once the per-CPU pages are merged
        assert!(t.z.alloc_pages(8, Gfp::KERNEL).is_some());
    }

    #[test]
    fn pcp_stays_bounded() {
        let t = zone(0, 8192);
        t.z.free_range(0, 8192);
        t.z.setup_pcp();
        let high = t.z.high.load(Ordering::Relaxed);
        let v: Vec<u64> = (0..2000)
            .map(|_| t.z.alloc_pages(0, Gfp::KERNEL).unwrap())
            .collect();
        for p in v {
            t.z.put(p);
        }
        let pcp = t.z.free_pages_all() - t.z.nr_free();
        assert!(pcp <= high, "pcp {pcp} > high {high}");
        assert_eq!(t.z.free_pages_all(), 8192);
    }

    #[test]
    fn compound_counts_on_head() {
        let t = zone(0, 2048);
        t.z.free_range(0, 2048);
        let h = t.z.alloc_pages(9, Gfp::KERNEL.with(Gfp::COMP)).unwrap();
        assert!(t.z.page(h).flags.load(Ordering::Relaxed) & PG_HEAD != 0);
        assert_eq!(t.z.page(h + 7).private.load(Ordering::Relaxed), h);
        t.z.get(h);
        assert!(!t.z.put(h));
        assert!(t.z.put(h));
        assert_eq!(t.z.nr_free(), 2048);
        assert_eq!(t.z.page(h + 7).flags.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn split_compound_frees_page_by_page() {
        let t = zone(0, 1024);
        t.z.free_range(0, 1024);
        t.z.setup_pcp();
        let h = t.z.alloc_pages(9, Gfp::KERNEL.with(Gfp::COMP)).unwrap();
        t.z.get(h);
        t.z.split(h);
        for i in 0..512 {
            assert_eq!(t.z.count(h + i), 2);
            assert!(!t.z.put(h + i));
            assert!(t.z.put(h + i));
        }
        assert_eq!(t.z.free_pages_all(), 1024);
    }

    #[test]
    fn saturated_count_is_sticky() {
        let t = zone(0, 16);
        t.z.free_range(0, 16);
        let p = t.z.alloc_pages(0, Gfp::KERNEL).unwrap();
        t.z.page(p).refcount.store(u32::MAX - 1, Ordering::Relaxed);
        assert!(t.z.get(p) && t.z.get(p));
        assert_eq!(t.z.count(p), u32::MAX);
        assert!(!t.z.put(p));
        assert_eq!(t.z.count(p), u32::MAX);
        // A free page's count is never dropped below zero
        let q = t.z.alloc_pages(0, Gfp::KERNEL).unwrap();
        assert!(t.z.put(q));
        assert!(!t.z.put(q));
    }

    /// A reference taken while another CPU drops the last one either
    /// lands first (the page lives on) or is refused: a page freed to a
    /// free list never comes back with a count (Linux
    /// get_page_unless_zero)
    #[test]
    fn get_never_revives_a_freed_page() {
        use core::sync::atomic::AtomicBool;
        const ROUNDS: u64 = 200_000;
        let t = zone(0, 64);
        t.z.free_range(0, 64);
        let (go, done, page) = (AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0));
        let freed = AtomicBool::new(false);
        let mut revived = 0;
        std::thread::scope(|s| {
            s.spawn(|| {
                for r in 1..=ROUNDS {
                    while go.load(Ordering::Acquire) != r {
                        core::hint::spin_loop();
                    }
                    let p = page.load(Ordering::Relaxed);
                    freed.store(t.z.put(p), Ordering::Relaxed);
                    done.store(r, Ordering::Release);
                }
            });
            for r in 1..=ROUNDS {
                let p = t.z.alloc_pages(0, Gfp::KERNEL).unwrap();
                page.store(p, Ordering::Relaxed);
                go.store(r, Ordering::Release);
                let got = t.z.get(p);
                while done.load(Ordering::Acquire) != r {
                    core::hint::spin_loop();
                }
                if !freed.load(Ordering::Relaxed) {
                    assert!(got && t.z.put(p));
                } else if t.z.count(p) != 0 {
                    revived += 1;
                    t.z.page(p).refcount.store(0, Ordering::Relaxed);
                }
            }
        });
        assert_eq!(revived, 0);
    }

    /// Pages another CPU freed to its list are not lost to an
    /// allocation that finds the buddy lists empty: the lists are
    /// drained and it is tried again (Linux drain_all_pages)
    #[test]
    fn failed_alloc_drains_other_cpus() {
        let t = zone(0, 64);
        t.z.free_range(0, 64);
        t.z.batch.store(8, Ordering::Relaxed);
        t.z.high.store(32, Ordering::Relaxed);
        let mut got = Vec::new();
        std::thread::scope(|s| {
            s.spawn(|| {
                TEST_CPU.with(|c| c.set(1));
                let mut v = Vec::new();
                while let Some(p) = t.z.alloc_pages(0, Gfp::KERNEL) {
                    v.push(p);
                }
                assert_eq!(v.len(), 64);
                v.into_iter().for_each(|p| t.z.free_pages(p, 0));
            });
        });
        assert!(t.z.free_pages_all() - t.z.nr_free() > 0);
        while let Some(p) = t.z.alloc_pages(0, Gfp::KERNEL) {
            got.push(p);
        }
        assert_eq!(got.len(), 64);
        // A large block forms again once the pages come back
        got.into_iter().for_each(|p| t.z.free_pages(p, 0));
        t.z.drain_all();
        assert!(t.z.alloc_pages(5, Gfp::KERNEL).is_some());
    }

    /// User data stops at low, reclaiming or not; the kernel at min
    #[test]
    fn user_marks() {
        let w = [
            AtomicUsize::new(10),
            AtomicUsize::new(20),
            AtomicUsize::new(30),
        ];
        assert_eq!(alloc_mark(&w, Gfp::HIGHUSER_MOVABLE), 20);
        assert_eq!(alloc_mark(&w, Gfp::HIGHUSER_RECLAIM), 20);
        assert_eq!(alloc_mark(&w, Gfp::KERNEL), 10);
    }

    /// A drain that finds one running returns at once (never waits)
    #[test]
    fn nested_drain_returns_at_once() {
        let t = zone(0, 64);
        t.z.free_range(0, 64);
        t.z.draining.store(true, Ordering::Relaxed);
        assert!(!t.z.drain_all());
        t.z.draining.store(false, Ordering::Relaxed);
        assert!(t.z.drain_all());
        assert!(!t.z.draining.load(Ordering::Relaxed));
    }

    /// Atomic and opportunistic allocations (a huge-page try on every
    /// fault) fail without draining other CPUs' lists
    #[test]
    fn nowait_alloc_does_not_drain() {
        let t = zone(0, 64);
        t.z.free_range(0, 64);
        t.z.batch.store(8, Ordering::Relaxed);
        t.z.high.store(32, Ordering::Relaxed);
        std::thread::scope(|s| {
            s.spawn(|| {
                TEST_CPU.with(|c| c.set(1));
                let v: Vec<_> = (0..64)
                    .map_while(|_| t.z.alloc_pages(0, Gfp::KERNEL))
                    .collect();
                v.into_iter().for_each(|p| t.z.free_pages(p, 0));
            });
        });
        let parked = t.z.pcp[1].count.load(Ordering::Relaxed);
        assert!(parked > 0);
        while t.z.alloc_pages(0, Gfp::NOWAIT).is_some() {}
        assert!(t.z.alloc_pages(0, Gfp::TRANSHUGE_LIGHT).is_none());
        assert_eq!(t.z.pcp[1].count.load(Ordering::Relaxed), parked);
        // A thread-context allocation drains it
        assert!(t.z.alloc_pages(0, Gfp::KERNEL).is_some());
        assert_eq!(t.z.pcp[1].count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn double_free_is_refused() {
        let t = zone(0, 64);
        t.z.free_range(0, 64);
        t.z.setup_pcp();
        let p = t.z.alloc_pages(0, Gfp::KERNEL).unwrap();
        t.z.free_pages(p, 0);
        let free = t.z.free_pages_all();
        t.z.free_pages(p, 0);
        assert!(!t.z.put(p));
        assert!(!t.z.get(p));
        assert_eq!(t.z.nr_bad(), 1);
        assert_eq!(t.z.free_pages_all(), free);
        // A page inside a free buddy block too
        let q = t.z.alloc_pages(3, Gfp::KERNEL).unwrap();
        t.z.free_pages(q, 3);
        t.z.free_pages(q, 3);
        assert_eq!(t.z.nr_bad(), 2);
        assert_eq!(t.z.free_pages_all(), free);
        // Every page still comes out exactly once
        let mut got = Vec::new();
        while let Some(x) = t.z.alloc_pages(0, Gfp::KERNEL) {
            got.push(x);
        }
        let n = got.len();
        got.sort();
        got.dedup();
        assert_eq!((n, got.len()), (64, 64));
    }

    #[test]
    fn holes_are_refused_and_never_merged() {
        // RAM 0..512 and 520..1024: pages 512..520 stay reserved
        let t = zone(0, 1024);
        t.z.free_range(0, 512);
        t.z.free_range(520, 1024);
        t.z.setup_pcp();
        t.z.free_pages(515, 0);
        t.z.free_pages(512, 3);
        assert_eq!(t.z.nr_bad(), 2);
        assert_eq!(t.z.free_pages_all(), 1016);
        let mut got = Vec::new();
        while let Some(p) = t.z.alloc_pages(0, Gfp::KERNEL) {
            assert!(!(512..520).contains(&p));
            got.push(p);
        }
        for p in got {
            assert!(t.z.put(p));
        }
        // No block spans the hole
        assert_eq!(t.z.nr_blocks()[10], 0);
        assert!(t.z.alloc_pages(10, Gfp::KERNEL).is_none());
        // Outside the zone: ignored, nothing touched
        t.z.free_pages(5000, 0);
        t.z.free_pages(1023, 1);
        assert_eq!(t.z.free_pages_all(), 1016);
    }

    #[test]
    fn min_free_kbytes_formula() {
        // Linux values: 512MB -> 2896 kB (sqrt(524288 * 16)), clamps
        assert_eq!(min_free_kbytes(131072), 2896);
        assert_eq!(min_free_kbytes(16), 128);
        assert_eq!(min_free_kbytes(1 << 40), 262_144);
    }

    #[test]
    fn watermarks_order_user_kernel_atomic() {
        let t = zone(0, 16384);
        t.z.free_range(0, 16384);
        t.z.setup_wmarks(None);
        let (min, low, high) = (
            t.z.wmark(Wmark::Min),
            t.z.wmark(Wmark::Low),
            t.z.wmark(Wmark::High),
        );
        assert!(min > 0 && min < low && low < high);
        // Drain to just above low: user allocations stop first
        let mut held = Vec::new();
        while t.z.nr_free() > low + 1 {
            held.push(t.z.alloc_pages(0, Gfp::KERNEL).unwrap());
        }
        let mut user = 0;
        while t.z.alloc_pages(0, Gfp::HIGHUSER_MOVABLE).is_some() {
            user += 1;
        }
        assert!(user < 64, "{user}");
        let mut kernel = 0;
        while t.z.alloc_pages(0, Gfp::KERNEL).is_some() {
            kernel += 1;
        }
        assert!(t.z.nr_free() <= min + 1 && kernel > 0);
        assert!(t.z.alloc_pages(0, Gfp::KERNEL.with(Gfp::HIGH)).is_some());
        while t.z.alloc_pages(0, Gfp::KERNEL.with(Gfp::HIGH)).is_some() {}
        assert!(t.z.alloc_pages(0, Gfp::ATOMIC).is_some());
        while t.z.alloc_pages(0, Gfp::ATOMIC).is_some() {}
        assert!(t.z.nr_free() > 0);
        assert!(t.z.below(Wmark::Min));
    }

    #[test]
    fn unaligned_span_never_merges_outside() {
        // Buddies of pfns 100..103 lie below the span
        let t = zone(100, 28);
        t.z.free_range(100, 128);
        assert_eq!(t.z.nr_free(), 28);
        let mut n = 0;
        while let Some(p) = t.z.alloc_pages(0, Gfp::KERNEL) {
            assert!((100..128).contains(&p));
            n += 1;
        }
        assert_eq!(n, 28);
    }
}

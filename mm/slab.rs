//! Slab allocator: object caches over page-allocator slabs (Linux
//! mm/slab.c per-CPU array caches with SLUB-style partial lists)
//!
//! A `KmemCache` hands out objects of one size. A slab is a naturally
//! aligned block of 2^order pages cut into objects; its head struct page
//! keeps the slab's free-object list (`private`, linked through the free
//! objects' first word), its use count (`inuse`) and its list links. Each
//! CPU keeps an array of free objects (`ArrayCache`): allocation pops and
//! free pushes there with interrupts off and no lock; an empty array is
//! refilled, a full one drained, `batch` objects at a time under the
//! cache's `list_lock`. Slabs with free objects are on the partial list,
//! fully free ones on the empty list (a few kept, the rest returned to
//! the page allocator), full ones on no list.
//!
//! A SLAB_TYPESAFE_BY_RCU cache (`KmemCache::typesafe_by_rcu`) returns
//! each empty slab to the page allocator only a grace period after it
//! left the cache's lists (Linux free_slab's call_rcu, on an `RcuHead`
//! in the slab's head struct page over its list links, free list and
//! counts: `Page::slab_rcu_head`): a freed object is reused at
//! once, but its memory stays an object of the cache while an RCU
//! reader may still hold its address. Its constructor (Linux ctor) sets
//! the type-stable part of each object when its slab is made; the cache
//! writes nothing in an object but its free-list link, at an offset the
//! cache's user leaves out of that part (Linux freeptr_offset).
//!
//! Locking: per-CPU array (interrupts off) → `list_lock` (`IrqSpinlock`)
//! → page allocator (per-CPU list, `Zone.lock`); empty slabs are given
//! back after `list_lock` is dropped (queued to RCU, with no lock held,
//! for a type-stable cache). Everything is IRQ-safe. A CPU without
//! per-CPU data yet allocates and frees under `list_lock`.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::mm::page::{PG_SLAB, Page};
use crate::mm::page_alloc::{Gfp, this_cpu};
use crate::sync::{IrqSpinlock, local_irq_restore, local_irq_save};

/// Largest per-CPU array
const MAX_LIMIT: usize = 64;

/// Empty slabs a cache keeps for reuse
const KEEP_EMPTY: usize = 2;

/// Where slabs come from: the page allocator through the direct map
/// (host tests use their own)
pub trait SlabPages: Sync {
    /// A naturally aligned block of 2^order pages (its virtual address)
    fn alloc(&self, order: u32) -> Option<usize>;
    /// Give back a block from `alloc`
    fn free(&self, base: usize, order: u32);
    /// The struct page of the block at `base`
    fn page(&self, base: usize) -> &Page;
    /// The block whose first struct page is `pg` (Linux slab_address)
    fn base(&self, pg: &Page) -> usize;
}

/// One CPU's free objects (Linux array_cache)
struct ArrayCache {
    avail: usize,
    entry: [usize; MAX_LIMIT],
}

/// One CPU's object cache of a `KmemCache`: a per-CPU variable (Linux
/// kmem_cache->cpu_slab, alloc_percpu)
pub struct CpuCell(UnsafeCell<ArrayCache>);

impl CpuCell {
    pub const fn new() -> Self {
        CpuCell(UnsafeCell::new(ArrayCache {
            avail: 0,
            entry: [0; MAX_LIMIT],
        }))
    }
}

// SAFETY: each cell is used only by its CPU with interrupts off
unsafe impl Sync for CpuCell {}

/// Slab lists (under `list_lock`); heads are slab base addresses, 0 =
/// none, linked through the head pages' `next`/`prev`
struct Lists {
    partial: usize,
    empty: usize,
    nr_empty: usize,
    /// Objects out of their slabs (in use, or in a per-CPU array)
    active: usize,
}

/// Cache flag: memory stays type-stable for a grace period (Linux
/// SLAB_TYPESAFE_BY_RCU)
const SLAB_TYPESAFE_BY_RCU: u32 = 1;

/// A cache of equally sized objects (Linux struct kmem_cache)
pub struct KmemCache {
    pub name: &'static str,
    /// Object stride (size rounded up to the alignment)
    size: usize,
    /// SLAB_TYPESAFE_BY_RCU or 0
    flags: u32,
    /// Where a free object links the next (Linux kmem_cache->offset)
    freeptr: usize,
    /// Sets a fresh object up (Linux kmem_cache->ctor)
    ctor: Option<unsafe fn(*mut u8)>,
    /// The layout it was made for (named caches match it exactly)
    obj: (usize, usize),
    /// Slab order and objects per slab
    order: u32,
    objs: usize,
    /// Per-CPU array size and transfer batch
    limit: usize,
    batch: usize,
    src: &'static dyn SlabPages,
    /// Each CPU's object cache, in its per-CPU area
    cpu: &'static crate::cpu::PerCpu<CpuCell>,
    list_lock: IrqSpinlock<Lists>,
    /// Slabs allocated, until given back (meminfo Slab)
    nr_slabs: AtomicUsize,
}

/// Slab order for objects of `size`: at least 8 objects per slab, at
/// most 8 pages (Linux calculate_order, simplified)
const fn slab_order(size: usize) -> u32 {
    let mut order = 0;
    while order < 3 && (4096 << order) / size < 8 {
        order += 1;
    }
    order
}

/// Per-CPU array size for objects of `size` (Linux enable_cpucache)
const fn cpu_limit(size: usize) -> usize {
    if size > 4096 {
        8
    } else if size > 1024 {
        16
    } else if size > 256 {
        32
    } else {
        MAX_LIMIT
    }
}

impl KmemCache {
    /// A cache for objects of `size` bytes aligned to `align` (a power
    /// of two; objects never straddle their alignment)
    pub const fn new(
        name: &'static str,
        size: usize,
        align: usize,
        src: &'static dyn SlabPages,
        cpu: &'static crate::cpu::PerCpu<CpuCell>,
    ) -> Self {
        let obj = (size, align);
        let a = if align < 8 { 8 } else { align };
        let size = (if size < 8 { 8 } else { size }).next_multiple_of(a);
        let order = slab_order(size);
        let limit = cpu_limit(size);
        Self {
            name,
            size,
            flags: 0,
            freeptr: 0,
            ctor: None,
            obj,
            order,
            objs: (4096 << order) / size,
            limit,
            batch: limit.div_ceil(2),
            src,
            cpu,
            list_lock: IrqSpinlock::new(Lists {
                partial: 0,
                empty: 0,
                nr_empty: 0,
                active: 0,
            }),
            nr_slabs: AtomicUsize::new(0),
        }
    }

    /// A SLAB_TYPESAFE_BY_RCU cache (Linux kmem_cache_create with that
    /// flag, `freeptr_offset` and `ctor`): an object freed may be handed
    /// out again at once, but its memory stays an object of this cache
    /// until a grace period after it was freed, its slab given back to
    /// the page allocator only then. `ctor` sets up each object of a new
    /// slab; the cache writes nothing in an object afterwards but its
    /// free-list link, at `freeptr` (8-aligned, inside the object), which
    /// its user keeps out of the part readers rely on.
    ///
    /// # Safety
    /// The cache is never dropped (a `static`): its slabs' grace-period
    /// callbacks reach it. `ctor` may be called on any fresh object of it.
    pub const unsafe fn typesafe_by_rcu(
        name: &'static str,
        size: usize,
        align: usize,
        freeptr: usize,
        ctor: unsafe fn(*mut u8),
        src: &'static dyn SlabPages,
        cpu: &'static crate::cpu::PerCpu<CpuCell>,
    ) -> Self {
        assert!(freeptr.is_multiple_of(8) && freeptr + 8 <= size);
        let mut c = Self::new(name, size, align, src, cpu);
        c.flags = SLAB_TYPESAFE_BY_RCU;
        c.freeptr = freeptr;
        c.ctor = Some(ctor);
        c
    }

    /// Object stride
    pub fn size(&self) -> usize {
        self.size
    }

    /// Bytes of slab pages this cache holds
    pub fn bytes(&self) -> usize {
        self.nr_slabs.load(Ordering::Relaxed) * (4096 << self.order)
    }

    fn slab_bytes(&self) -> usize {
        4096 << self.order
    }

    /// Base of the slab holding `obj` (slabs are naturally aligned)
    fn base_of(&self, obj: usize) -> usize {
        obj & !(self.slab_bytes() - 1)
    }

    fn head(&self, base: usize) -> &Page {
        self.src.page(base)
    }

    /// The free-list link of `obj`
    fn link(&self, obj: usize) -> *mut usize {
        (obj + self.freeptr) as *mut usize
    }

    // ------------------------------------------------------------------
    // Slab lists (under list_lock)
    // ------------------------------------------------------------------

    fn push(&self, list: &mut usize, base: usize) {
        let pg = self.head(base);
        pg.next.store(*list as u64, Ordering::Relaxed);
        pg.prev.store(0, Ordering::Relaxed);
        if *list != 0 {
            self.head(*list).prev.store(base as u64, Ordering::Relaxed);
        }
        *list = base;
    }

    fn unlink(&self, list: &mut usize, base: usize) {
        let pg = self.head(base);
        let (next, prev) = (
            pg.next.load(Ordering::Relaxed) as usize,
            pg.prev.load(Ordering::Relaxed) as usize,
        );
        if prev != 0 {
            self.head(prev).next.store(next as u64, Ordering::Relaxed);
        } else {
            *list = next;
        }
        if next != 0 {
            self.head(next).prev.store(prev as u64, Ordering::Relaxed);
        }
    }

    /// Take one free object of the slab at `base`, moving the slab
    /// between lists as its use count changes
    fn take_obj(&self, l: &mut Lists, base: usize) -> usize {
        let pg = self.head(base);
        let obj = pg.private.load(Ordering::Relaxed) as usize;
        // SAFETY: a free object of a slab we own, whose link word (no
        // reader's) names the next free object
        let next = unsafe { *self.link(obj) };
        pg.private.store(next as u64, Ordering::Relaxed);
        l.active += 1;
        // Under list_lock (`l`): Linux slab->inuse++
        let inuse = pg.inuse.load(Ordering::Relaxed) as usize + 1;
        pg.inuse.store(inuse as u32, Ordering::Relaxed);
        if inuse == 1 {
            self.unlink(&mut l.empty, base);
            l.nr_empty -= 1;
            if inuse < self.objs {
                self.push(&mut l.partial, base);
            }
        } else if inuse == self.objs {
            self.unlink(&mut l.partial, base);
        }
        obj
    }

    /// Return an object to its slab
    fn put_obj(&self, l: &mut Lists, obj: usize) {
        let base = self.base_of(obj);
        let pg = self.head(base);
        // SAFETY: the object is free again; its link word (no reader's)
        // links the list
        unsafe { *self.link(obj) = pg.private.load(Ordering::Relaxed) as usize };
        pg.private.store(obj as u64, Ordering::Relaxed);
        l.active -= 1;
        // Under list_lock (`l`): Linux slab->inuse--
        let inuse = pg.inuse.load(Ordering::Relaxed) as usize - 1;
        pg.inuse.store(inuse as u32, Ordering::Relaxed);
        if inuse + 1 < self.objs {
            if inuse == 0 {
                self.unlink(&mut l.partial, base);
            }
        } else if inuse > 0 {
            // Was full (on no list)
            self.push(&mut l.partial, base);
        }
        if inuse == 0 {
            self.push(&mut l.empty, base);
            l.nr_empty += 1;
        }
    }

    /// An object from the lists (partial slabs first)
    fn list_alloc(&self, l: &mut Lists) -> Option<usize> {
        let base = if l.partial != 0 { l.partial } else { l.empty };
        (base != 0).then(|| self.take_obj(l, base))
    }

    /// Unlink an empty slab beyond the ones kept (to give back)
    fn shrink_one(&self, l: &mut Lists) -> Option<usize> {
        if l.nr_empty <= KEEP_EMPTY {
            return None;
        }
        let base = l.empty;
        self.unlink(&mut l.empty, base);
        l.nr_empty -= 1;
        Some(base)
    }

    // ------------------------------------------------------------------
    // Slabs from the page allocator
    // ------------------------------------------------------------------

    /// A new slab, all objects free, on the empty list
    fn grow(&self) -> bool {
        let Some(base) = self.src.alloc(self.order) else {
            return false;
        };
        let pg = self.head(base);
        let mut free = 0;
        for i in (0..self.objs).rev() {
            let obj = base + i * self.size;
            if let Some(ctor) = self.ctor {
                // SAFETY: a fresh object of this cache (the constructor's
                // contract), which no one else reaches yet
                unsafe { ctor(obj as *mut u8) };
            }
            // SAFETY: the fresh slab's objects are ours
            unsafe { *self.link(obj) = free };
            free = obj;
        }
        pg.private.store(free as u64, Ordering::Relaxed);
        pg.inuse.store(0, Ordering::Relaxed);
        pg.mapping
            .store(core::ptr::from_ref::<Self>(self) as u64, Ordering::Relaxed);
        pg.set_flag(PG_SLAB);
        self.nr_slabs.fetch_add(1, Ordering::Relaxed);
        let mut l = self.list_lock.lock();
        self.push(&mut l.empty, base);
        l.nr_empty += 1;
        true
    }

    /// Give an empty slab, off every list, back (Linux discard_slab ->
    /// free_slab): to the page allocator, a grace period later for a
    /// type-stable cache (no list_lock held)
    fn discard(&self, base: usize) {
        if self.flags & SLAB_TYPESAFE_BY_RCU == 0 {
            self.release(base);
            return;
        }
        self.free_rcu(base);
    }

    /// Queue the slab's `rcu_free_slab` (Linux call_rcu(&slab->rcu_head))
    #[cfg(not(test))]
    fn free_rcu(&self, base: usize) {
        if !crate::sync::rcu::can_queue() {
            // Early boot: no other CPU runs a reader yet
            self.release(base);
            return;
        }
        let pg = self.head(base);
        // SAFETY: an empty slab off every list (`shrink_one`), the
        // caller's alone; its links, free list and counts stay untouched
        // until `rcu_free_slab`
        let h = unsafe { pg.slab_rcu_head() };
        // SAFETY: the head is in the slab's struct page, which stays (the
        // memory map is never freed), and `rcu_free_slab` gets that page
        // of a slab of this cache, never dropped (`typesafe_by_rcu`'s
        // contract); it neither sleeps nor cares which CPU runs it
        unsafe {
            crate::sync::rcu::call_rcu(h, rcu_free_slab, core::ptr::from_ref(pg).cast());
        }
    }

    /// Host tests queue the slab for their own grace period
    /// (`tests::grace_period`)
    #[cfg(test)]
    fn free_rcu(&self, base: usize) {
        let pg = self.head(base);
        // SAFETY: an empty slab off every list (`shrink_one`), the
        // caller's alone, untouched until `grace_period` runs
        // `rcu_free_slab` on it
        let _ = unsafe { pg.slab_rcu_head() };
        tests::GP
            .lock()
            .unwrap()
            .push(core::ptr::from_ref(pg) as usize);
    }

    /// Give an empty slab to the page allocator (Linux __free_slab)
    fn release(&self, base: usize) {
        let pg = self.head(base);
        pg.clear_flag(PG_SLAB);
        pg.mapping.store(0, Ordering::Relaxed);
        pg.private.store(0, Ordering::Relaxed);
        self.nr_slabs.fetch_sub(1, Ordering::Relaxed);
        self.src.free(base, self.order);
    }

    // ------------------------------------------------------------------
    // Allocation and free
    // ------------------------------------------------------------------

    /// This CPU's array (None: no per-CPU data yet)
    ///
    /// # Safety
    /// Interrupts are off until the returned borrow ends.
    #[expect(clippy::mut_from_ref)]
    unsafe fn array(&self) -> Option<&mut ArrayCache> {
        // SAFETY: only this CPU uses its cell, and interrupts are off
        this_cpu().map(|c| unsafe { &mut *self.cpu.get(c as u32).0.get() })
    }

    /// Fill `ac` with up to `batch` objects from the slabs (Linux
    /// cache_alloc_refill); false if none has any
    fn refill(&self, ac: &mut ArrayCache) -> bool {
        let mut l = self.list_lock.lock();
        while ac.avail < self.batch {
            match self.list_alloc(&mut l) {
                Some(obj) => {
                    ac.entry[ac.avail] = obj;
                    ac.avail += 1;
                }
                None => break,
            }
        }
        ac.avail > 0
    }

    /// Give the oldest `batch` objects of `ac` back to their slabs, and
    /// excess empty slabs to the page allocator (Linux cache_flusharray)
    fn flush(&self, ac: &mut ArrayCache) {
        let n = self.batch.min(ac.avail);
        let mut gone = [0usize; MAX_LIMIT];
        let mut ng = 0;
        {
            let mut l = self.list_lock.lock();
            for &obj in &ac.entry[..n] {
                self.put_obj(&mut l, obj);
            }
            while let Some(base) = self.shrink_one(&mut l) {
                gone[ng] = base;
                ng += 1;
                if ng == gone.len() {
                    break;
                }
            }
        }
        ac.entry.copy_within(n..ac.avail, 0);
        ac.avail -= n;
        for &base in &gone[..ng] {
            self.discard(base);
        }
    }

    /// Allocate an object (null if memory is exhausted). A new slab is
    /// made with interrupts as the caller had them, so its pages come
    /// GFP_KERNEL (reclaiming) where the caller may sleep (Linux
    /// cache_grow_begin enables interrupts for a blocking allocation).
    pub fn alloc(&self) -> *mut u8 {
        loop {
            let flags = local_irq_save();
            // SAFETY: interrupts are off
            let obj = match unsafe { self.array() } {
                Some(ac) => {
                    if ac.avail > 0 || self.refill(ac) {
                        ac.avail -= 1;
                        ac.entry[ac.avail]
                    } else {
                        0
                    }
                }
                None => self.list_alloc(&mut self.list_lock.lock()).unwrap_or(0),
            };
            local_irq_restore(flags);
            if obj != 0 {
                return obj as *mut u8;
            }
            if !self.grow() {
                return core::ptr::null_mut();
            }
        }
    }

    /// Free an object of this cache
    pub fn free(&self, obj: *mut u8) {
        let flags = local_irq_save();
        // SAFETY: interrupts are off
        match unsafe { self.array() } {
            Some(ac) => {
                if ac.avail == self.limit {
                    self.flush(ac);
                }
                ac.entry[ac.avail] = obj as usize;
                ac.avail += 1;
            }
            None => self.slow_free(obj as usize),
        }
        local_irq_restore(flags);
    }

    /// Free without a per-CPU array
    fn slow_free(&self, obj: usize) {
        let gone = {
            let mut l = self.list_lock.lock();
            self.put_obj(&mut l, obj);
            self.shrink_one(&mut l)
        };
        if let Some(base) = gone {
            self.discard(base);
        }
    }
}

// SAFETY: per-CPU arrays are used only by their CPU with interrupts
// off; everything else is atomics or under list_lock
unsafe impl Sync for KmemCache {}

/// A slab's grace period is over (Linux rcu_free_slab): give it to the
/// page allocator
///
/// # Safety
/// `p` is the head struct page of a slab whose `free_rcu` queued it, and
/// its head's callback runs now.
unsafe fn rcu_free_slab(p: *const ()) {
    // SAFETY: a struct page (the caller's contract), never freed
    let pg = unsafe { &*p.cast::<Page>() };
    // SAFETY: a slab page's `mapping` is its cache (`grow`), never
    // dropped (`typesafe_by_rcu`'s contract)
    let c = unsafe { &*(pg.mapping.load(Ordering::Relaxed) as *const KmemCache) };
    // SAFETY: its head's callback runs: on no list, never used again
    unsafe { pg.slab_rcu_end() };
    c.release(c.src.base(pg));
}

// ============================================================================
// Slabs from the page allocator
// ============================================================================

/// Slab pages from `FRAME_ALLOCATOR`, used through the direct map
pub struct KernelPages;

/// Heap pages, GFP from the context (the heap API has no flags): the
/// one the call named (`util::kalloc::with_gfp`), else GFP_KERNEL, down
/// to the min watermark; the page allocator reclaims for it only where
/// the caller may sleep, else it drains the per-CPU lists and fails (an
/// unnamed allocation in atomic context, which `might_alloc` reports as
/// `MIGHT_ALLOC:FAIL`). GFP_ATOMIC (Linux's partial allowance below min) in an
/// interrupt handler unless it named one, and within reclaim
/// (PF_MEMALLOC, which overrides a named one as in Linux
/// __gfp_pfmemalloc_flags). User data, kernel buffers of it included
/// (pipe pages), stops at low, so heap objects get low - min to
/// themselves.
fn heap_gfp() -> Gfp {
    #[cfg(not(test))]
    {
        use crate::arch::{CurrentArch, PerCpuOps};
        let irq = CurrentArch::interrupt_depth() > 0;
        if !irq && crate::task::percpu::current().has_flag(crate::task::pf::MEMALLOC) {
            return Gfp::ATOMIC;
        }
        if let Some(g) = crate::util::kalloc::named_gfp() {
            return g;
        }
        if irq {
            return Gfp::ATOMIC;
        }
    }
    Gfp::KERNEL
}

impl SlabPages for KernelPages {
    fn alloc(&self, order: u32) -> Option<usize> {
        let pa = crate::FRAME_ALLOCATOR.alloc_pages(order, heap_gfp())?;
        Some(crate::arch::phys_to_virt(pa) as usize)
    }

    fn free(&self, base: usize, order: u32) {
        crate::FRAME_ALLOCATOR.free_pages(crate::arch::virt_to_phys(base as u64), order);
    }

    fn page(&self, base: usize) -> &Page {
        let pa = crate::arch::virt_to_phys(base as u64);
        crate::mm::page::phys_to_page(pa).expect("slab: no struct page")
    }

    fn base(&self, pg: &Page) -> usize {
        let pfn = crate::mm::page::page_to_pfn(pg);
        crate::arch::phys_to_virt(pfn << crate::mm::page::PAGE_SHIFT) as usize
    }
}

pub static KERNEL_PAGES: KernelPages = KernelPages;

// ============================================================================
// kmalloc
// ============================================================================

/// kmalloc size classes (Linux kmalloc caches: powers of two plus 96
/// and 192, up to 8KB; larger allocations take pages directly)
const SIZES: [usize; 13] = [
    8, 16, 32, 64, 96, 128, 192, 256, 512, 1024, 2048, 4096, 8192,
];

macro_rules! kmalloc_caches {
    ($($n:literal),*) => {
        [$({
            crate::percpu! {
                static CPU: CpuCell = CpuCell::new();
            }
            KmemCache::new(concat!("kmalloc-", stringify!($n)), $n, 8, &KERNEL_PAGES, &CPU)
        }),*]
    };
}

static KMALLOC: [KmemCache; 13] = kmalloc_caches!(
    8, 16, 32, 64, 96, 128, 192, 256, 512, 1024, 2048, 4096, 8192
);

/// Largest kmalloc cache size
const KMALLOC_MAX: usize = 8192;

/// The kmalloc class for a layout: the smallest size that holds it and
/// is a multiple of its alignment (objects sit at multiples of their
/// size in page-aligned slabs, so that aligns them); None: pages
fn kmalloc_index(size: usize, align: usize) -> Option<usize> {
    SIZES
        .iter()
        .position(|&c| c >= size && c.is_multiple_of(align))
}

/// Page order for an allocation too big for kmalloc caches
fn large_order(size: usize, align: usize) -> u32 {
    let pages = size.max(align).div_ceil(4096);
    pages.next_power_of_two().trailing_zeros()
}

// ============================================================================
// Named caches
// ============================================================================

const fn box_of<T>() -> (usize, usize) {
    (core::mem::size_of::<T>(), core::mem::align_of::<T>())
}

/// The block an `Arc<T>` allocates: its two counts, then `T`
/// (`kalloc::arc_layout`, as a const)
const fn arc_of<T>() -> (usize, usize) {
    let (size, align) = box_of::<T>();
    let word = core::mem::align_of::<usize>();
    let align = if align > word { align } else { word };
    let off = (2 * core::mem::size_of::<usize>()).next_multiple_of(align);
    ((off + size).next_multiple_of(align), align)
}

macro_rules! named_cache {
    ($name:literal, $layout:expr) => {{
        crate::percpu! {
            static CPU: CpuCell = CpuCell::new();
        }
        KmemCache::new($name, $layout.0, $layout.1, &KERNEL_PAGES, &CPU)
    }};
}

/// VMAs (`Box<Vma>`; Linux vm_area_cachep)
pub static VMA_CACHE: KmemCache = named_cache!("vm_area_struct", box_of::<crate::mm::Vma>());
/// Dentries (`DentryRef`; Linux dentry_cache)
pub static DENTRY_CACHE: KmemCache = named_cache!("dentry", box_of::<crate::fs::dentry::Dentry>());
/// Inodes (`InodeRef`; Linux inode_cache)
pub static INODE_CACHE: KmemCache =
    named_cache!("inode_cache", box_of::<crate::fs::inode::Inode>());
/// Buffer heads (`Box<BufferHead>`; Linux bh_cachep, buffer_init)
pub static BH_CACHE: KmemCache = named_cache!(
    "buffer_head",
    box_of::<crate::fs::pageio::buffer::BufferHead>()
);
/// TCP TIME_WAIT entries (`Arc<TimeWait>`; Linux tcp_prot's twsk_slab,
/// "tw_sock_TCP")
pub static TW_CACHE: KmemCache = named_cache!(
    "tw_sock_TCP",
    arc_of::<crate::net::tcp::timewait::TimeWait>()
);

/// Pages for the caches made here (host tests: their own)
#[cfg(not(test))]
use KERNEL_PAGES as CACHE_PAGES;
#[cfg(test)]
use tests::HOST_PAGES as CACHE_PAGES;

/// Open files (`fs::file::FileObj`; Linux filp_cache, files_init):
/// SLAB_TYPESAFE_BY_RCU, so a descriptor table's RCU reader that loaded
/// a file's address may try for a count on it however soon it is freed
/// and reused. Used only by `File::alloc` and a file's release, never
/// through the global allocator.
pub static FILP_CACHE: KmemCache = {
    use crate::fs::file::FileObj;
    crate::percpu! {
        static CPU: CpuCell = CpuCell::new();
    }
    // SAFETY: a static; `FileObj::ctor` takes any fresh object
    unsafe {
        KmemCache::typesafe_by_rcu(
            "filp",
            core::mem::size_of::<FileObj>(),
            core::mem::align_of::<FileObj>(),
            FileObj::FREEPTR,
            FileObj::ctor,
            &CACHE_PAGES,
            &CPU,
        )
    }
};

/// Caches used by name only (Linux kmem_cache_create's callers)
static OWN: [&KmemCache; 1] = [&FILP_CACHE];

/// Object types with a cache of their own. Rust allocates through the
/// global allocator with only a layout, so these caches serve every
/// allocation of exactly their type's layout (another type of the same
/// size and alignment shares it, like Linux slab merging); keeps them
/// out of the kmalloc caches and counted per type.
static NAMED: [&KmemCache; 5] = [
    &VMA_CACHE,
    &DENTRY_CACHE,
    &INODE_CACHE,
    &BH_CACHE,
    &TW_CACHE,
];

/// The cache that serves a layout: a named cache of exactly that
/// layout, else the kmalloc class
fn cache_for(size: usize, align: usize) -> Option<&'static KmemCache> {
    if let Some(c) = NAMED.iter().find(|c| c.obj == (size, align)) {
        return Some(c);
    }
    kmalloc_index(size, align).map(|i| &KMALLOC[i])
}

/// Allocate for `layout` (null if out of memory)
pub fn kmalloc(size: usize, align: usize) -> *mut u8 {
    match cache_for(size, align) {
        Some(c) => c.alloc(),
        None => {
            let order = large_order(size, align);
            crate::FRAME_ALLOCATOR
                .alloc_pages(order, heap_gfp())
                .map_or(core::ptr::null_mut(), crate::arch::phys_to_virt)
        }
    }
}

/// Free what `kmalloc(size, align)` returned
pub fn kfree(ptr: *mut u8, size: usize, align: usize) {
    match cache_for(size, align) {
        Some(c) => c.free(ptr),
        None => {
            let pa = crate::arch::virt_to_phys(ptr as u64);
            crate::FRAME_ALLOCATOR.free_pages(pa, large_order(size, align));
        }
    }
}

/// `ptr` from `kmalloc(old, align)` can hold `new` bytes in place
pub fn fits(old: usize, new: usize, align: usize) -> bool {
    match (cache_for(old, align), cache_for(new, align)) {
        (Some(a), Some(b)) => core::ptr::eq(a, b),
        (None, None) => large_order(old, align) == large_order(new, align),
        _ => false,
    }
}

/// Bytes of slab pages (meminfo Slab; large kmallocs are page
/// allocations, as in Linux)
/// /proc/slabinfo (Linux slabinfo 2.1 format; active objects include
/// those cached in per-CPU arrays, as Linux SLAB counted them)
pub fn slabinfo() -> alloc::vec::Vec<u8> {
    use core::fmt::Write;
    const HEAD: &str = "slabinfo - version: 2.1\n# name            <active_objs> <num_objs> <objsize> \
         <objperslab> <pagesperslab> : tunables <limit> <batchcount> <sharedfactor> \
         : slabdata <active_slabs> <num_slabs> <sharedavail>\n";
    // Each cache line below is about 110 bytes
    const LINE: usize = 112;
    let n = OWN.len() + NAMED.len() + KMALLOC.len();
    let mut out = alloc::string::String::with_capacity(HEAD.len() + n * LINE);
    out.push_str(HEAD);
    for c in OWN
        .iter()
        .chain(NAMED.iter())
        .copied()
        .chain(KMALLOC.iter())
    {
        let active = c.list_lock.lock().active;
        let slabs = c.nr_slabs.load(Ordering::Relaxed);
        let _ = writeln!(
            out,
            "{:<17} {:>6} {:>6} {:>6} {:>4} {:>4} : tunables {:>4} {:>4} {:>4} : slabdata {:>6} {:>6} {:>6}",
            c.name,
            active,
            slabs * c.objs,
            c.size,
            c.objs,
            1 << c.order,
            c.limit,
            c.batch,
            0,
            slabs,
            slabs,
            0
        );
    }
    out.into_bytes()
}

pub fn slab_bytes() -> usize {
    KMALLOC.iter().map(KmemCache::bytes).sum::<usize>()
        + OWN
            .iter()
            .chain(NAMED.iter())
            .map(|c| c.bytes())
            .sum::<usize>()
}

const _: () = assert!(SIZES[SIZES.len() - 1] == KMALLOC_MAX);

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::alloc::Layout;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// Slabs from the host allocator, struct pages in a side table
    pub struct HostPages {
        pages: Mutex<BTreeMap<usize, &'static Page>>,
        pub live: AtomicUsize,
    }

    impl HostPages {
        pub const fn empty() -> Self {
            Self {
                pages: Mutex::new(BTreeMap::new()),
                live: AtomicUsize::new(0),
            }
        }

        pub fn new() -> &'static Self {
            Box::leak(Box::new(Self::empty()))
        }
    }

    /// The host tests' pages for `FILP_CACHE` and the like
    pub static HOST_PAGES: HostPages = HostPages::empty();

    impl SlabPages for HostPages {
        fn alloc(&self, order: u32) -> Option<usize> {
            let l = Layout::from_size_align(4096 << order, 4096 << order).unwrap();
            let p = unsafe { std::alloc::alloc(l) } as usize;
            let pg: &'static Page = Box::leak(Box::new(Page::new()));
            self.pages.lock().unwrap().insert(p, pg);
            self.live.fetch_add(1, Ordering::Relaxed);
            Some(p)
        }
        fn free(&self, base: usize, order: u32) {
            let l = Layout::from_size_align(4096 << order, 4096 << order).unwrap();
            self.pages.lock().unwrap().remove(&base).unwrap();
            self.live.fetch_sub(1, Ordering::Relaxed);
            unsafe { std::alloc::dealloc(base as *mut u8, l) };
        }
        fn page(&self, base: usize) -> &Page {
            self.pages.lock().unwrap()[&base]
        }
        fn base(&self, pg: &Page) -> usize {
            let m = self.pages.lock().unwrap();
            *m.iter().find(|(_, p)| core::ptr::eq(**p, pg)).unwrap().0
        }
    }

    /// Slab frees queued (head struct pages), waiting for `grace_period`
    pub static GP: Mutex<Vec<usize>> = Mutex::new(Vec::new());

    /// End a grace period for `c`: run its slab frees queued so far
    fn grace_period(c: &KmemCache) {
        let mine: Vec<usize> = {
            let mut q = GP.lock().unwrap();
            let (mine, rest) = q.drain(..).partition(|&p| {
                // SAFETY: a struct page queued by `free_rcu` (leaked,
                // never freed)
                let pg = unsafe { &*(p as *const Page) };
                pg.mapping.load(Ordering::Relaxed) == core::ptr::from_ref(c) as u64
            });
            *q = rest;
            mine
        };
        for p in mine {
            // SAFETY: queued by `free_rcu`, taken off the queue once
            unsafe { rcu_free_slab(p as *const ()) };
        }
    }

    fn cpus() -> &'static crate::cpu::PerCpu<CpuCell> {
        Box::leak(Box::new(crate::cpu::PerCpu::new(
            [const { CpuCell::new() }; crate::util::cpumask::NR_CPUS],
        )))
    }

    fn cache(size: usize, align: usize) -> (&'static KmemCache, &'static HostPages) {
        let src = HostPages::new();
        let c = Box::leak(Box::new(KmemCache::new("test", size, align, src, cpus())));
        (c, src)
    }

    /// A type-stable object: `state` is its constructed part, the rest
    /// (where the cache links it when free) its user's
    #[repr(C)]
    struct Stable {
        body: [u64; 7],
        state: core::sync::atomic::AtomicU64,
    }

    const CTOR: u64 = 0xc0;

    /// # Safety
    /// `p` is a fresh object of a `Stable` cache.
    unsafe fn stable_ctor(p: *mut u8) {
        let s = p.cast::<Stable>();
        // SAFETY: the caller's contract
        unsafe { (&raw mut (*s).state).write(core::sync::atomic::AtomicU64::new(CTOR)) };
    }

    fn typesafe() -> (&'static KmemCache, &'static HostPages) {
        let src = HostPages::new();
        let (s, a) = box_of::<Stable>();
        // SAFETY: leaked, never dropped; `stable_ctor` takes a fresh one
        let c = unsafe { KmemCache::typesafe_by_rcu("ts", s, a, 0, stable_ctor, src, cpus()) };
        (Box::leak(Box::new(c)), src)
    }

    fn state(o: usize) -> &'static core::sync::atomic::AtomicU64 {
        // SAFETY: an object of a `Stable` cache whose slab is still the
        // cache's: its state stays constructed
        unsafe { &(*(o as *const Stable)).state }
    }

    /// An object freed and handed out again keeps its constructed part:
    /// the cache writes only its link word, which is not in it
    #[test]
    fn typesafe_keeps_layout() {
        let (c, _) = typesafe();
        let v: Vec<usize> = (0..100).map(|_| c.alloc() as usize).collect();
        for &o in &v {
            assert_eq!(state(o).load(Ordering::Relaxed), CTOR);
            state(o).store(o as u64, Ordering::Relaxed);
            // SAFETY: allocated, ours: its body is its user's
            unsafe { (*(o as *mut Stable)).body = [!0; 7] };
        }
        for &o in &v {
            c.free(o as *mut u8);
            // Freed: still what its user left
            assert_eq!(state(o).load(Ordering::Relaxed), o as u64);
        }
        let w: Vec<usize> = (0..100).map(|_| c.alloc() as usize).collect();
        let again = w.iter().filter(|o| v.contains(o)).count();
        assert!(again >= 64, "freed objects are handed out at once");
        for &o in &w {
            let want = if v.contains(&o) { o as u64 } else { CTOR };
            assert_eq!(state(o).load(Ordering::Relaxed), want);
        }
    }

    /// Empty slabs go back to the pages only once a grace period ends,
    /// each on its own: a slab emptied after another's free was queued
    /// goes back after the same one grace period (Linux: an rcu_head per
    /// slab)
    #[test]
    fn typesafe_slabs_wait_for_gp() {
        let (c, src) = typesafe();
        let v: Vec<usize> = (0..400).map(|_| c.alloc() as usize).collect();
        let slabs = src.live.load(Ordering::Relaxed);
        let bytes = c.bytes();
        let (a, b) = v.split_at(v.len() / 2);
        for &o in a {
            c.free(o as *mut u8);
        }
        // Slabs emptied after the first ones were queued
        for &o in b {
            c.free(o as *mut u8);
        }
        assert_eq!(src.live.load(Ordering::Relaxed), slabs, "none back yet");
        assert_eq!(c.bytes(), bytes, "counted until given back");
        grace_period(c);
        let left = src.live.load(Ordering::Relaxed);
        assert!(
            left <= KEEP_EMPTY + 2,
            "{left} of {slabs} after one grace period"
        );
        assert_eq!(c.bytes(), left * c.slab_bytes());
    }

    #[test]
    fn objects_are_distinct_aligned_and_reused() {
        let (c, src) = cache(96, 32);
        let mut v: Vec<usize> = (0..1000).map(|_| c.alloc() as usize).collect();
        for &o in &v {
            assert!(o != 0 && o % 32 == 0);
            unsafe { core::ptr::write_bytes(o as *mut u8, 0xab, 96) };
        }
        let mut s = v.clone();
        s.sort();
        s.dedup();
        assert_eq!(s.len(), 1000);
        // Objects never straddle slabs
        for &o in &v {
            assert_eq!(c.base_of(o), c.base_of(o + 95));
        }
        let slabs = src.live.load(Ordering::Relaxed);
        for o in v.drain(..) {
            c.free(o as *mut u8);
        }
        // Empty slabs went back (but a few kept and the CPU's array)
        let left = src.live.load(Ordering::Relaxed);
        assert!(left < slabs && left <= KEEP_EMPTY + 2, "{left} of {slabs}");
        // Cycling one object allocates no slab
        let before = src.live.load(Ordering::Relaxed);
        for _ in 0..10_000 {
            let o = c.alloc();
            c.free(o);
        }
        assert_eq!(src.live.load(Ordering::Relaxed), before);
    }

    #[test]
    fn large_objects_use_higher_orders() {
        let (c, src) = cache(4096, 4096);
        assert_eq!(c.order, 3);
        assert_eq!(c.objs, 8);
        let v: Vec<usize> = (0..20).map(|_| c.alloc() as usize).collect();
        assert!(v.iter().all(|&o| o % 4096 == 0));
        assert_eq!(src.live.load(Ordering::Relaxed), 3);
        assert_eq!(c.bytes(), 3 * 32768);
        for o in v {
            c.free(o as *mut u8);
        }
    }

    #[test]
    fn partial_slabs_fill_before_new_ones() {
        let (c, src) = cache(512, 8);
        let v: Vec<usize> = (0..64).map(|_| c.alloc() as usize).collect();
        let slabs = src.live.load(Ordering::Relaxed);
        // Free every other object: slabs become partial, none empty
        for &o in v.iter().step_by(2) {
            c.free(o as *mut u8);
        }
        for _ in 0..32 {
            assert!(!c.alloc().is_null());
        }
        assert_eq!(src.live.load(Ordering::Relaxed), slabs);
    }

    #[test]
    fn kmalloc_classes() {
        assert_eq!(kmalloc_index(1, 1), Some(0));
        assert_eq!(SIZES[kmalloc_index(65, 8).unwrap()], 96);
        assert_eq!(SIZES[kmalloc_index(65, 64).unwrap()], 128);
        assert_eq!(SIZES[kmalloc_index(100, 32).unwrap()], 128);
        assert_eq!(SIZES[kmalloc_index(16, 4096).unwrap()], 4096);
        assert_eq!(kmalloc_index(8193, 8), None);
        assert_eq!(kmalloc_index(64, 16384), None);
        assert_eq!(large_order(8193, 8), 2);
        assert_eq!(large_order(100, 16384), 2);
        assert_eq!(large_order(2 << 20, 4096), 9);
        assert!(fits(100, 110, 8));
        assert!(!fits(100, 200, 8));
        assert!(fits(9000, 16000, 8));
        assert!(!fits(8000, 9000, 8));
    }

    #[test]
    fn named_caches_take_their_exact_layout() {
        let (s, a) = box_of::<crate::mm::Vma>();
        assert!(core::ptr::eq(cache_for(s, a).unwrap(), &VMA_CACHE));
        let (s, a) = box_of::<crate::fs::dentry::Dentry>();
        assert!(core::ptr::eq(cache_for(s, a).unwrap(), &DENTRY_CACHE));
        let (s, a) = box_of::<crate::fs::inode::Inode>();
        assert!(core::ptr::eq(cache_for(s, a).unwrap(), &INODE_CACHE));
        use crate::net::tcp::timewait::TimeWait;
        let l = crate::util::kalloc::arc_layout::<TimeWait>();
        assert_eq!(arc_of::<TimeWait>(), (l.size(), l.align()));
        let tw = cache_for(l.size(), l.align()).unwrap();
        assert!(core::ptr::eq(tw, &TW_CACHE));
    }

    #[test]
    fn slow_paths_agree() {
        let (c, src) = cache(64, 8);
        // The list path alone (no per-CPU array), growing as needed
        let take = || loop {
            if let Some(o) = c.list_alloc(&mut c.list_lock.lock()) {
                break o;
            }
            assert!(c.grow());
        };
        let v: Vec<usize> = (0..500).map(|_| take()).collect();
        for o in v {
            c.slow_free(o);
        }
        assert!(src.live.load(Ordering::Relaxed) <= KEEP_EMPTY);
        let l = c.list_lock.lock();
        assert_eq!(l.partial, 0);
    }
}

//! Large kernel allocations: virtually contiguous, backed by single
//! pages (Linux mm/vmalloc.c vmalloc/vfree, and kvmalloc's fallback)
//!
//! The heap (`mm::heap`) comes here for an allocation the slab cannot
//! serve: one larger than its biggest page order, or a multi-page one
//! whose pages it could not find contiguous. Each allocation gets a
//! page-aligned range of `VMALLOC_AREA` (`arch::paging`), its pages
//! mapped one by one, and an unmapped guard page after it, so an
//! overrun faults instead of corrupting the next area. The memory is
//! not physically contiguous: no `virt_to_phys`, no DMA (both assert).
//!
//! A freed range's pages are unmapped (this CPU's TLB flushed) and freed
//! at once, but the range is reused only after one flush of the whole
//! area on every CPU (Linux's lazy purge), done by an allocation once
//! `LAZY_MAX_PAGES` wait for it or no clean range fits. The bitmaps are
//! static (1.5 MiB): never copy one onto a kernel stack.
//!
//! Context: allocating may flush every CPU's TLB, so it needs a context
//! that may sleep (`sync::in_atomic` false; otherwise it fails, and the
//! heap's caller sees an ordinary allocation failure). Freeing works
//! anywhere: from an interrupt handler the area goes on a lock-free
//! list kept in its own first bytes and is freed by the next allocation
//! (Linux vfree_atomic).
//!
//! Locking: `AREA` is a spin leaf, thread context (bitmap updates only:
//! no mapping, flush or allocation under it); `FLUSH` (sleeping) keeps
//! one purge at a time; mapping takes the arch's KTABLES and the frame
//! allocator outside both.

use core::sync::atomic::{AtomicPtr, Ordering};

use crate::arch::paging::{VMALLOC_AREA, VMALLOC_AREA_SIZE};
use crate::sync::spin::Mutex;

const PAGE_SIZE: u64 = 4096;
/// Pages in the area
const PAGES: usize = (VMALLOC_AREA_SIZE / PAGE_SIZE) as usize;
const WORDS: usize = PAGES / 64;
/// Freed pages that may wait for a purge (Linux lazy_max_pages: 32 MiB)
const LAZY_MAX_PAGES: usize = (32 << 20) / PAGE_SIZE as usize;

/// End of the area
const AREA_END: u64 = VMALLOC_AREA + VMALLOC_AREA_SIZE;

/// Page bookkeeping over `W`-word bitmaps: `used` pages belong to an
/// allocation (or its guard page); dirty pages were freed since the last
/// purge and may still be cached in some CPU's TLB. Frees go to
/// `dirty[cur]`; a purge flips `cur`, flushes, then cleans the other
/// bitmap, so pages freed during the flush wait for the next purge and
/// no bitmap is ever copied (they are far too big for a kernel stack).
pub(crate) struct Map<const W: usize> {
    used: [u64; W],
    dirty: [[u64; W]; 2],
    cur: usize,
    nr_dirty: [usize; 2],
    /// Where the next search starts (next fit)
    hint: usize,
}

impl<const W: usize> Map<W> {
    pub(crate) const fn new() -> Self {
        Self {
            used: [0; W],
            dirty: [[0; W]; 2],
            cur: 0,
            nr_dirty: [0; 2],
            hint: 0,
        }
    }

    fn busy_word(&self, w: usize) -> u64 {
        self.used[w] | self.dirty[0][w] | self.dirty[1][w]
    }

    fn busy(&self, p: usize) -> bool {
        self.busy_word(p / 64) & (1 << (p % 64)) != 0
    }

    /// Pages waiting for a purge
    pub(crate) fn nr_dirty(&self) -> usize {
        self.nr_dirty[0] + self.nr_dirty[1]
    }

    /// `n` contiguous clean free pages, searching from `hint` and
    /// wrapping once; marked used
    pub(crate) fn take(&mut self, n: usize) -> Option<usize> {
        let total = W * 64;
        if n == 0 || n > total {
            return None;
        }
        let mut start = if self.hint + n <= total { self.hint } else { 0 };
        let mut wrapped = start == 0;
        loop {
            match self.run_from(start, n, total) {
                Ok(p) => {
                    self.set_used(p, n, true);
                    self.hint = p + n;
                    return Some(p);
                }
                Err(next) if next + n <= total => start = next,
                Err(_) if !wrapped => {
                    wrapped = true;
                    start = 0;
                }
                Err(_) => return None,
            }
        }
    }

    /// A free run of `n` at `start`, or where to look next
    fn run_from(&self, start: usize, n: usize, total: usize) -> Result<usize, usize> {
        let mut p = start;
        // Skip whole busy words
        while p < total && p.is_multiple_of(64) && self.busy_word(p / 64) == u64::MAX {
            p += 64;
        }
        while p < total && self.busy(p) {
            p += 1;
        }
        if p + n > total {
            return Err(total);
        }
        match (p..p + n).find(|&q| self.busy(q)) {
            None => Ok(p),
            Some(q) => Err(q + 1),
        }
    }

    fn set_used(&mut self, p: usize, n: usize, used: bool) {
        for q in p..p + n {
            let (w, b) = (q / 64, 1u64 << (q % 64));
            if used {
                self.used[w] |= b;
            } else {
                self.used[w] &= !b;
            }
        }
    }

    /// Free `n` pages at `p`: dirty until a purge
    pub(crate) fn put(&mut self, p: usize, n: usize) {
        self.set_used(p, n, false);
        let c = self.cur;
        for q in p..p + n {
            self.dirty[c][q / 64] |= 1 << (q % 64);
        }
        self.nr_dirty[c] += n;
    }

    /// Start a purge: later frees go to the other bitmap; the pages
    /// dirty now are the ones the flush will cover
    pub(crate) fn begin_purge(&mut self) -> usize {
        let old = self.cur;
        self.cur ^= 1;
        old
    }

    /// The flush is done: the pages dirty at `begin_purge` are clean
    pub(crate) fn end_purge(&mut self, old: usize) {
        self.dirty[old].fill(0);
        self.nr_dirty[old] = 0;
    }
}

static AREA: Mutex<Map<WORDS>> = Mutex::new(Map::new());

/// One purge at a time: a second one must not clean, from an older
/// snapshot, pages freed again after the first flush
static FLUSH: crate::sync::Mutex<()> = crate::sync::Mutex::new(());

/// Areas freed from interrupt handlers, waiting for thread context
/// (a Treiber stack threaded through the areas' own first bytes)
static DEFERRED: AtomicPtr<Deferred> = AtomicPtr::new(core::ptr::null_mut());

/// The head of a deferred area: its page count and the next one
struct Deferred {
    next: *mut Deferred,
    pages: usize,
}

fn page_of(va: u64) -> usize {
    ((va - VMALLOC_AREA) / PAGE_SIZE) as usize
}

fn va_of(page: usize) -> u64 {
    VMALLOC_AREA + page as u64 * PAGE_SIZE
}

/// `va` lies in the vmalloc area
pub fn contains(va: u64) -> bool {
    (VMALLOC_AREA..AREA_END).contains(&va)
}

/// Purge: flush the area on every CPU, then the dirty pages are clean
fn purge() {
    let _one = FLUSH.lock();
    let old = AREA.lock().begin_purge();
    crate::mm::tlb::flush_tlb_kernel_range(VMALLOC_AREA, AREA_END);
    AREA.lock().end_purge(old);
}

/// `n` clean pages, purging first when too many wait or none fit
fn take_range(n: usize) -> Option<usize> {
    {
        let mut a = AREA.lock();
        if a.nr_dirty() < LAZY_MAX_PAGES
            && let Some(p) = a.take(n)
        {
            return Some(p);
        }
        if a.nr_dirty() == 0 {
            return None;
        }
    }
    purge();
    AREA.lock().take(n)
}

/// Free the areas interrupt handlers left
fn drain_deferred() {
    let mut d = DEFERRED.swap(core::ptr::null_mut(), Ordering::Acquire);
    while !d.is_null() {
        // SAFETY: `d` heads an area pushed by `free` that nothing else
        // uses; read before the area is unmapped
        let Deferred { next, pages } = unsafe { d.read() };
        release(d as u64, pages);
        d = next;
    }
}

/// `size` bytes, page-aligned, from a context that may sleep; null if
/// the area or memory is exhausted or the context is atomic
pub fn alloc(size: usize) -> *mut u8 {
    if crate::sync::in_atomic() || size == 0 {
        return core::ptr::null_mut();
    }
    drain_deferred();
    let pages = size.div_ceil(PAGE_SIZE as usize);
    // One more for the guard page
    let Some(p) = take_range(pages + 1) else {
        return core::ptr::null_mut();
    };
    let base = va_of(p);
    for i in 0..pages {
        let va = base + i as u64 * PAGE_SIZE;
        let ok =
            crate::FRAME_ALLOCATOR
                .alloc()
                .is_some_and(|pa| match crate::arch::vmap_page(va, pa) {
                    Ok(()) => true,
                    Err(_) => {
                        crate::FRAME_ALLOCATOR.free(pa);
                        false
                    }
                });
        if !ok {
            unmap(base, i);
            AREA.lock().put(p, pages + 1);
            return core::ptr::null_mut();
        }
    }
    base as *mut u8
}

/// Unmap and free the first `pages` pages at `base`
fn unmap(base: u64, pages: usize) {
    for i in 0..pages {
        let va = base + i as u64 * PAGE_SIZE;
        if let Some(pa) = crate::arch::vunmap_page(va) {
            crate::arch::tlb::local_flush_one(va);
            crate::FRAME_ALLOCATOR.free(pa);
        }
    }
}

fn release(base: u64, pages: usize) {
    unmap(base, pages);
    AREA.lock().put(page_of(base), pages + 1);
}

/// Free `size` bytes at `ptr` (from `alloc(size)`), from any context
pub fn free(ptr: *mut u8, size: usize) {
    use crate::arch::{CurrentArch, PerCpuOps};
    debug_assert!(contains(ptr as u64) && (ptr as u64).is_multiple_of(PAGE_SIZE));
    let pages = size.div_ceil(PAGE_SIZE as usize);
    if CurrentArch::interrupt_depth() == 0 {
        release(ptr as u64, pages);
        return;
    }
    // Interrupt handler: KTABLES is thread-context only
    let d = ptr as *mut Deferred;
    let mut head = DEFERRED.load(Ordering::Relaxed);
    loop {
        // SAFETY: the area is still mapped and ours (freed by the caller)
        unsafe { d.write(Deferred { next: head, pages }) };
        match DEFERRED.compare_exchange_weak(head, d, Ordering::Release, Ordering::Relaxed) {
            Ok(_) => return,
            Err(h) => head = h,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_and_wrap() {
        let mut m: Map<2> = Map::new();
        let a = m.take(10).unwrap();
        let b = m.take(60).unwrap();
        assert_eq!((a, b), (0, 10));
        assert!(m.take(60).is_none()); // 58 left
        m.put(a, 10);
        // The clean pages above are used first; the freed ones are dirty
        assert_eq!(m.take(58), Some(70));
        assert!(m.take(10).is_none());
        let old = m.begin_purge();
        // Freed during the flush: still dirty after it
        m.put(70, 1);
        m.end_purge(old);
        assert_eq!(m.nr_dirty(), 1);
        // After the purge the search wraps to them
        assert_eq!(m.take(10), Some(0));
        assert!(m.take(1).is_none());
        let old = m.begin_purge();
        m.end_purge(old);
        assert_eq!(m.take(1), Some(70));
    }

    #[test]
    fn runs_skip_busy_words() {
        let mut m: Map<4> = Map::new();
        assert_eq!(m.take(130), Some(0));
        assert_eq!(m.take(3), Some(130));
        m.put(0, 130);
        let old = m.begin_purge();
        m.end_purge(old);
        // From the hint (133) the rest fits 123; 200 does not fit
        assert!(m.take(200).is_none());
        assert_eq!(m.take(123), Some(133));
        assert_eq!(m.take(130), Some(0));
    }
}

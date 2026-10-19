//! LRU lists of reclaimable pages (Linux mm/swap.c, the lruvec)
//!
//! One lruvec (one node, no memory cgroups) with Linux's lists:
//! inactive and active anonymous pages (file pages join with the page
//! cache, P5). A page on a list has `PG_LRU` (and `PG_ACTIVE` on an
//! active list) and is linked through its struct page (`next`/`prev`,
//! pfn + 1), owned by the list while `PG_LRU` is set. New pages go to
//! the head; reclaim takes from the tail (the oldest).
//!
//! A page reaches the lists through a per-CPU batch (Linux
//! cpu_fbatches.lru_add): the batch holds a reference on each page, and
//! a full batch moves to the lists under one lock hold. The lists hold
//! no reference: a page freed while on a list leaves it on its way to
//! the allocator (`page_freed`). Reclaim isolates pages it takes a
//! reference on (get_page_unless_zero), so it never takes a page being
//! freed.
//!
//! Locking: `Lruvec.lock` (Linux lruvec->lru_lock) is an `IrqSpinlock`
//! (pages are freed in any context); a batch's lock (`IrqSpinlock`, one
//! per CPU) is never held with it. Neither is held while a page
//! reference is dropped. Order: PTE lock -> batch lock | lru_lock;
//! nothing is taken under lru_lock.

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::FRAME_ALLOCATOR;
use crate::arch::IrqSpinlock;
use crate::cpu::PerCpu;
use crate::mm::page::{PG_ACTIVE, PG_LRU, Page, pfn_to_page, phys_to_page};

/// The lists (Linux enum lru_list)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lru {
    InactiveAnon = 0,
    ActiveAnon = 1,
}

const NR_LRU: usize = 2;

/// List heads and tails, pfn + 1 (0: empty)
struct Lists {
    head: [u64; NR_LRU],
    tail: [u64; NR_LRU],
}

/// The pages of the machine, by recency (Linux struct lruvec)
pub struct Lruvec {
    lock: IrqSpinlock<Lists>,
    /// Pages on each list (written under `lock`)
    nr: [AtomicUsize; NR_LRU],
}

/// The one lruvec
pub static LRUVEC: Lruvec = Lruvec {
    lock: IrqSpinlock::new(Lists {
        head: [0; NR_LRU],
        tail: [0; NR_LRU],
    }),
    nr: [const { AtomicUsize::new(0) }; NR_LRU],
};

fn page(pfn: u64) -> &'static Page {
    pfn_to_page(pfn)
}

fn list_of(pg: &Page) -> Lru {
    if pg.is_active() {
        Lru::ActiveAnon
    } else {
        Lru::InactiveAnon
    }
}

impl Lruvec {
    /// Link `pfn` at the head (or tail) of list `l` (Linux
    /// lruvec_add_folio), lock held
    fn add(&self, ls: &mut Lists, pfn: u64, l: Lru, tail: bool) {
        let pg = page(pfn);
        let i = l as usize;
        if tail {
            pg.next.store(0, Ordering::Relaxed);
            pg.prev.store(ls.tail[i], Ordering::Relaxed);
            match ls.tail[i] {
                0 => ls.head[i] = pfn + 1,
                t => page(t - 1).next.store(pfn + 1, Ordering::Relaxed),
            }
            ls.tail[i] = pfn + 1;
        } else {
            pg.prev.store(0, Ordering::Relaxed);
            pg.next.store(ls.head[i], Ordering::Relaxed);
            match ls.head[i] {
                0 => ls.tail[i] = pfn + 1,
                h => page(h - 1).prev.store(pfn + 1, Ordering::Relaxed),
            }
            ls.head[i] = pfn + 1;
        }
        pg.set_flag(PG_LRU);
        if l == Lru::ActiveAnon {
            pg.set_flag(PG_ACTIVE);
        } else {
            pg.clear_flag(PG_ACTIVE);
        }
        self.nr[i].fetch_add(1, Ordering::Relaxed);
    }

    /// Unlink `pfn` from its list (Linux lruvec_del_folio), lock held
    fn del(&self, ls: &mut Lists, pfn: u64) {
        let pg = page(pfn);
        let i = list_of(pg) as usize;
        let (next, prev) = (
            pg.next.load(Ordering::Relaxed),
            pg.prev.load(Ordering::Relaxed),
        );
        match prev {
            0 => ls.head[i] = next,
            p => page(p - 1).next.store(next, Ordering::Relaxed),
        }
        match next {
            0 => ls.tail[i] = prev,
            n => page(n - 1).prev.store(prev, Ordering::Relaxed),
        }
        pg.next.store(0, Ordering::Relaxed);
        pg.prev.store(0, Ordering::Relaxed);
        pg.clear_flag(PG_LRU | PG_ACTIVE);
        self.nr[i].fetch_sub(1, Ordering::Relaxed);
    }

    /// Pages on list `l`
    pub fn len(&self, l: Lru) -> usize {
        self.nr[l as usize].load(Ordering::Relaxed)
    }
}

// ============================================================================
// Per-CPU add batches (Linux folio_batch, cpu_fbatches)
// ============================================================================

/// Pages a batch holds (Linux PAGEVEC_SIZE)
const BATCH: usize = 15;

struct Batch {
    n: usize,
    pfn: [u64; BATCH],
}

static BATCHES: PerCpu<IrqSpinlock<Batch>> = crate::percpu![IrqSpinlock::new(Batch {
    n: 0,
    pfn: [0; BATCH],
})];

/// Move pages to the head of the inactive list, then drop the batch's
/// references (after the lock)
fn add_all(pfns: &[u64]) {
    {
        let mut ls = LRUVEC.lock.lock();
        for &pfn in pfns {
            // Never freed meanwhile (the batch holds a reference); one
            // already on a list (added twice) stays where it is
            if !page(pfn).is_on_lru() {
                LRUVEC.add(&mut ls, pfn, Lru::InactiveAnon, false);
            }
        }
    }
    for &pfn in pfns {
        FRAME_ALLOCATOR.decref(pfn << 12);
    }
}

/// A new anonymous page goes on the LRU (Linux folio_add_lru), through
/// this CPU's batch; huge pages stay off (not reclaimed whole)
pub fn lru_add(phys: u64) {
    let Some(pg) = phys_to_page(phys) else {
        return;
    };
    if pg.is_on_lru() || pg.flags.load(Ordering::Relaxed) & crate::mm::page::PG_HEAD != 0 {
        return;
    }
    if !FRAME_ALLOCATOR.incref(phys) {
        return;
    }
    let pfn = phys >> 12;
    let Some(cpu) = crate::mm::page_alloc::this_cpu() else {
        add_all(&[pfn]);
        return;
    };
    let full = {
        let mut b = BATCHES.get(cpu as u32).lock();
        let n = b.n;
        b.pfn[n] = pfn;
        b.n += 1;
        (b.n == BATCH).then(|| take(&mut b))
    };
    if let Some((pfns, n)) = full {
        add_all(&pfns[..n]);
    }
}

fn take(b: &mut Batch) -> ([u64; BATCH], usize) {
    let n = core::mem::take(&mut b.n);
    (b.pfn, n)
}

/// Move one CPU's batch to the lists (Linux lru_add_drain_cpu)
fn drain_cpu(b: &IrqSpinlock<Batch>) {
    let (pfns, n) = take(&mut b.lock());
    add_all(&pfns[..n]);
}

/// Move every CPU's batch to the lists (Linux lru_add_drain_all, which
/// asks each CPU; hk drains them from here under their locks): reclaim
/// and MADV_PAGEOUT see every page
pub fn lru_add_drain_all() {
    for (_, b) in BATCHES.for_each_possible() {
        drain_cpu(b);
    }
}

// ============================================================================
// Isolation and putback (reclaim)
// ============================================================================

/// The page at `pfn` is being freed (its count reached 0): off its
/// list (Linux __page_cache_release), before the allocator reuses its
/// links
pub fn page_freed(pfn: u64) {
    if page(pfn).is_on_lru() {
        let mut ls = LRUVEC.lock.lock();
        // Isolation clears PG_LRU under the lock: test it again
        if page(pfn).is_on_lru() {
            LRUVEC.del(&mut ls, pfn);
        }
    }
}

/// Take the page at `phys` off the LRU for reclaim, with a reference
/// (Linux folio_isolate_lru); false if not on a list (or being freed)
pub fn isolate(phys: u64) -> bool {
    let pfn = phys >> 12;
    if !phys_to_page(phys).is_some_and(|p| p.is_on_lru()) {
        return false;
    }
    let mut ls = LRUVEC.lock.lock();
    if !page(pfn).is_on_lru() || !FRAME_ALLOCATOR.incref(phys) {
        return false;
    }
    LRUVEC.del(&mut ls, pfn);
    true
}

/// Up to `nr` pages from the tail of list `l`, each with a reference
/// (Linux isolate_lru_folios): pages being freed are skipped
pub fn isolate_tail(l: Lru, nr: usize, out: &mut alloc::vec::Vec<u64>) {
    let mut ls = LRUVEC.lock.lock();
    let mut cur = ls.tail[l as usize];
    let mut scanned = 0;
    while cur != 0 && out.len() < nr && scanned < 4 * nr {
        let pfn = cur - 1;
        cur = page(pfn).prev.load(Ordering::Relaxed);
        scanned += 1;
        if FRAME_ALLOCATOR.incref(pfn << 12) {
            LRUVEC.del(&mut ls, pfn);
            out.push(pfn << 12);
        }
    }
}

/// Return an isolated page to list `l` (head; the tail with `tail`) and
/// drop the isolation reference (Linux folio_putback_lru)
pub fn putback(phys: u64, l: Lru, tail: bool) {
    {
        let mut ls = LRUVEC.lock.lock();
        LRUVEC.add(&mut ls, phys >> 12, l, tail);
    }
    FRAME_ALLOCATOR.decref(phys);
}

/// Move an LRU page to the tail of the inactive list, next for reclaim
/// (Linux folio_deactivate, MADV_COLD)
pub fn deactivate(phys: u64) {
    if isolate(phys) {
        putback(phys, Lru::InactiveAnon, true);
    }
}

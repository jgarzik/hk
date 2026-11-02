//! Copying and releasing user page tables (Linux mm/memory.c
//! copy_page_range, zap_*, mm/mmap.c exit_mmap)
//!
//! Every present user PTE holds one reference on its frame (fork increfs
//! the frames it shares): unmapping drops it, and the frame is freed with
//! the last one. Frames outside the allocator (MMIO) have no count and
//! are never freed.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use super::gather::Gather;
use super::huge_page::{HUGE_PAGE_SIZE, split_huge_pmd, take_huge_pmd};
use super::pagewalk::{PteRange, PteWalk, entry, table_slot, walk_pte_range};
use super::{Mm, PAGE_SIZE, SwapEntry, Vma};
use crate::FRAME_ALLOCATOR;
use crate::arch::{Leaf, paging};
use crate::mm::page::phys_to_page;

const ENOMEM: i32 = 12;

/// Drop one mapping's reference to the 4KB user page `phys` (Linux
/// zap_present_pte: rmap removal + put). The last reference frees it
/// (the allocator resets its struct page, the mapping released).
pub fn put_page(phys: u64) {
    super::rmap::page_remove_rmap(phys);
    crate::FRAME_ALLOCATOR.decref(phys);
}

/// Release the 4KB page a zapped PTE mapped, after the TLB flush (Linux
/// free_pages_and_swap_cache): a swap-cache page no one maps any more
/// leaves the cache when no swap PTE needs its slot either
fn zap_page(phys: u64) {
    super::rmap::page_remove_rmap(phys);
    super::swap_state::free_swap_cache(phys);
    crate::FRAME_ALLOCATOR.decref(phys);
}

/// Drop one mapping's reference to the 2MB user page at `phys`
pub fn put_huge(phys: u64) {
    super::rmap::page_remove_rmap(phys);
    crate::FRAME_ALLOCATOR.decref_huge(phys);
}

/// Release one user mapping (after its TLB flush: `Gather`)
pub(super) fn zap_leaf(leaf: Leaf) {
    use super::SwapEntry;
    match leaf {
        Leaf::Page(p) => zap_page(p),
        Leaf::Huge(p) => put_huge(p),
        Leaf::Swap(pte) if SwapEntry::is_swap_pte(pte) => {
            super::swap::free_swap_and_cache(SwapEntry::from_pte(pte))
        }
        Leaf::Swap(_) => {}
    }
}

/// Tear down an address space whose last user is gone (Linux
/// exit_mmap): drop its VMAs and their rmap chains, release every user
/// page and swap slot, and free the user page tables. The top-level
/// table stays until the last mm_count reference (`Mm::drop`).
///
/// No task runs in it any more, but a CPU that ran its last task may
/// still have it loaded: the user half is detached and every such CPU
/// flushed (paging-structure caches included) before anything is
/// freed (Linux tlb_gather_mmu_fullmm).
pub(super) fn exit_mmap(mm: &Mm) {
    // Out of their reverse-map chains first (Linux free_pgtables
    // unlinks each VMA): a walk holding a chain never meets the tables
    // freed below
    let vmas: Vec<_> = mm.mmap_write().take_vmas();
    let mut tlb = Gather::new_full(mm);
    tlb.free_tables(paging::detach_user(mm.pgd()));
    drop(tlb);
    // VMAs go last, outside any lock: they may hold the last reference
    // to a mapped file
    drop(vmas);
}

/// Clear the entries of [start, end) of the gather's address space
/// (Linux zap_page_range / unmap_page_range), mm lock held (for reading
/// is enough: 2MB entries change under the page_table_lock, 4KB ones
/// under their table's PTE lock): each 4KB
/// entry (a page, protnone included, or a swap slot) is cleared, a 2MB
/// page wholly inside goes whole, one partly inside is split first. The
/// pages go to `tlb`, released only after its TLB flush (a swap slot
/// at once: no CPU caches a swap entry). Tables stay (munmap frees
/// them, `free_pgtables`). Only
/// user addresses: callers pass ranges inside VMAs, a range past
/// TASK_SIZE is a bug (clamped).
pub fn zap_range(tlb: &mut Gather, start: u64, end: u64) {
    let pgd = tlb.mm().pgd();
    let _ = walk_pte_range(pgd, start, end, &mut Zap { tlb });
}

/// `zap_range`'s walk
struct Zap<'g, 'a> {
    tlb: &'g mut Gather<'a>,
}

impl PteWalk for Zap<'_, '_> {
    type Err = core::convert::Infallible;

    fn huge(&mut self, _: &AtomicU64, addr: u64, end: u64) -> Result<bool, Self::Err> {
        let base = addr & !(HUGE_PAGE_SIZE - 1);
        let mm = self.tlb.mm();
        if addr == base && end == base + HUGE_PAGE_SIZE {
            if let Some(phys) = take_huge_pmd(mm, base) {
                self.tlb.remove_huge(base, phys);
                return Ok(true);
            }
            // Split (or zapped) under us: clear the 4KB entries
            // (Linux zap_pmd_range falls back to zap_pte_range)
        } else {
            // Out of memory: the 2MB page stays mapped (BUGS.md)
            let _ = split_huge_pmd(mm, base);
        }
        Ok(false)
    }

    /// Clear the 4KB entry; what it held goes to the gather
    fn pte(&mut self, e: &AtomicU64, addr: u64) -> Result<(), Self::Err> {
        let pte = e.swap(0, Ordering::AcqRel);
        if paging::pte_present(pte) {
            self.tlb.remove_page(addr, paging::pte_addr(pte));
        } else if SwapEntry::is_swap_pte(pte) {
            super::swap::free_swap_and_cache(SwapEntry::from_pte(pte));
        }
        Ok(())
    }
}

/// Free the page tables of [start, end) that no VMA needs any more
/// (Linux free_pgtables / free_pgd_range), mm lock held for writing,
/// after the range was zapped and its VMAs left their reverse-map
/// chains: a table is freed when the whole span it maps lies in
/// [floor, ceiling) (the gap between the neighbouring VMAs) and it is
/// empty. Its parent entry is cleared at once; the frame goes to `tlb`,
/// freed after the flush that drops the paging-structure caches. The
/// top-level table stays.
pub fn free_pgtables(tlb: &mut Gather, start: u64, end: u64, floor: u64, ceiling: u64) {
    if start < end {
        let r = PtRange {
            start,
            end,
            floor,
            ceiling,
        };
        free_level(tlb, tlb.mm().pgd(), 3, 0, &r);
    }
}

/// The range `free_pgtables` works on
struct PtRange {
    start: u64,
    end: u64,
    floor: u64,
    ceiling: u64,
}

/// The entries of the table `table` at `level` (3: top level, 1: the
/// 2MB level) whose spans meet [r.start, r.end), `base` being the
/// table's first address: each child table is freed bottom-up
fn free_level(tlb: &mut Gather, table: u64, level: u32, base: u64, r: &PtRange) {
    let span = 1u64 << (12 + 9 * level);
    let first = (r.start.max(base) - base) / span;
    let last = ((r.end - 1).min(base + 512 * span - 1) - base) / span;
    for i in first..=last {
        let lo = base + i * span;
        let e = entry(table_slot(table, i));
        let Some(child) = paging::table_of(e.load(Ordering::Acquire)) else {
            continue;
        };
        if level > 1 {
            free_level(tlb, child, level - 1, lo, r);
        }
        if lo >= r.floor && lo + span <= r.ceiling && table_empty(child) {
            e.store(0, Ordering::Release);
            tlb.remove_table(lo, span, child);
        }
    }
}

/// Every entry of the table frame `table` is empty
fn table_empty(table: u64) -> bool {
    (0..512).all(|i| entry(table_slot(table, i)).load(Ordering::Acquire) == 0)
}

/// One past the last user address a top-level entry can map: the
/// ceiling of the page tables above the last VMA (Linux
/// USER_PGTABLES_CEILING)
pub fn pgtables_ceiling() -> u64 {
    super::TASK_SIZE.next_multiple_of(1 << 39)
}

/// A page is mapped at `addr` (protnone included), mm lock held
pub fn resident(pgd: u64, addr: u64) -> bool {
    match paging::pte_ptr(pgd, addr) {
        Some(p) => paging::pte_present(entry(p).load(Ordering::Acquire)),
        None => paging::pmd_ptr(pgd, addr)
            .is_some_and(|p| paging::pmd_huge(entry(p).load(Ordering::Acquire))),
    }
}

/// (resident, swapped) 4KB pages of [start, end), mm lock held (Linux
/// MM_*PAGES and MM_SWAPENTS, counted from the tables): a 2MB page
/// counts its part inside; a 1GB range without tables is skipped whole
pub fn count_ptes(pgd: u64, start: u64, end: u64) -> (u64, u64) {
    struct Count(u64, u64);
    impl PteWalk for Count {
        type Err = core::convert::Infallible;
        fn huge(&mut self, _: &AtomicU64, addr: u64, end: u64) -> Result<bool, Self::Err> {
            self.0 += (end - addr) / PAGE_SIZE;
            Ok(true)
        }
        fn pte(&mut self, e: &AtomicU64, _: u64) -> Result<(), Self::Err> {
            let pte = e.load(Ordering::Acquire);
            if paging::pte_present(pte) {
                self.0 += 1;
            } else if SwapEntry::is_swap_pte(pte) {
                self.1 += 1;
            }
            Ok(())
        }
    }
    let mut c = Count(0, 0);
    let _ = walk_pte_range(pgd, start, end, &mut c);
    (c.0, c.1)
}

/// The first address in [addr, end) whose 4KB entry is a swap entry of
/// device `ty`, mm lock held (swapoff); 1GB ranges without tables and
/// 2MB pages are skipped
pub fn next_swap_pte(pgd: u64, addr: u64, end: u64, ty: u8) -> Option<u64> {
    struct Find(u8);
    impl PteWalk for Find {
        type Err = u64;
        fn pte(&mut self, e: &AtomicU64, addr: u64) -> Result<(), u64> {
            let pte = e.load(Ordering::Acquire);
            if SwapEntry::is_swap_pte(pte) && SwapEntry::from_pte(pte).swap_type() == self.0 {
                return Err(addr);
            }
            Ok(())
        }
    }
    walk_pte_range(pgd, addr, end, &mut Find(ty)).err()
}

/// Copy the page tables of the parent's `vma` from the address space
/// `src` into the child's tables at `dst` (Linux copy_page_range), under
/// the parent's mm lock. A shared mapping keeps sharing its pages; a private
/// one shares them copy-on-write, read-only in both; a swap PTE is
/// copied with another slot reference (`swap::swap_duplicate`). A 2MB
/// page is split first so that its 4KB pages are copied one by one.
/// Returns whether a parent PTE lost write permission (its TLB needs a
/// flush).
pub fn copy_page_range(dst: u64, src_mm: &Mm, vma: &Vma) -> Result<bool, i32> {
    let mut c = CopyRange {
        dst,
        src_mm,
        cow: !vma.is_shared(),
        wp: false,
    };
    walk_pte_range(src_mm.pgd(), vma.start, vma.end, &mut c)?;
    Ok(c.wp)
}

/// `copy_page_range`'s walk
struct CopyRange<'a> {
    dst: u64,
    src_mm: &'a Mm,
    cow: bool,
    wp: bool,
}

impl PteWalk for CopyRange<'_> {
    type Err = i32;

    fn huge(&mut self, _: &AtomicU64, addr: u64, _: u64) -> Result<bool, i32> {
        split_huge_pmd(self.src_mm, addr).ok_or(ENOMEM)?;
        Ok(false)
    }

    /// One parent table, its PTE lock held by the walk (the reverse map,
    /// reclaim, changes its entries without the mmap_lock: Linux
    /// copy_pte_range), into the child's table under that table's PTE
    /// lock (dup_mm already put the child's VMA on the reverse-map
    /// chains). Parent, then child: only fork nests these two.
    /// The child's table, allocated before the parent's PTE lock is
    /// taken (Linux copy_pte_range: pte_alloc_map_lock of the child
    /// first): the allocation may reclaim
    fn prepare(&mut self, addr: u64, _end: u64) -> Result<(), i32> {
        paging::pte_alloc(self.dst, addr).map(|_| ()).ok_or(ENOMEM)
    }

    fn ptes(&mut self, r: &PteRange) -> Result<(), i32> {
        if r.iter().all(|(_, e)| e.load(Ordering::Acquire) == 0) {
            return Ok(());
        }
        let dp = paging::pte_ptr(self.dst, r.start).ok_or(ENOMEM)?;
        let _l = super::ptl::pte_lock(dp);
        let d = PteRange::at(dp, r.start, r.end);
        for (a, se) in r.iter() {
            self.wp |= copy_pte(d.entry(a), se, self.cow)?;
        }
        Ok(())
    }
}

/// Copy the parent PTE `sp` into the child's `dp` (Linux
/// copy_present_pte / copy_nonpresent_pte), both PTE locks held; true
/// if the parent's entry was write-protected
fn copy_pte(dp: &AtomicU64, sp: &AtomicU64, cow: bool) -> Result<bool, i32> {
    let mut pte = sp.load(Ordering::Acquire);
    if pte == 0 {
        return Ok(false);
    }
    if !paging::pte_present(pte) {
        if SwapEntry::is_swap_pte(pte) {
            // The child's PTE references the slot too (Linux
            // copy_nonpresent_pte: swap_duplicate); a full count is
            // ENOMEM (Linux would chain a count continuation)
            if !super::swap::swap_duplicate(SwapEntry::from_pte(pte)) {
                return Err(ENOMEM);
            }
            dp.store(pte, Ordering::Release);
        }
        return Ok(false);
    }
    let mut child = pte;
    if cow && !paging::pte_cow(pte) {
        // Under the PTE lock only the MMU changes the entry (accessed /
        // dirty bits, each set once): retry with them
        loop {
            child = paging::pte_mkcow(pte);
            match sp.compare_exchange(pte, child, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break,
                Err(now) => pte = now,
            }
        }
    }
    // The entry holds a reference, kept while its PTE lock is held
    let held = FRAME_ALLOCATOR.incref(paging::pte_addr(pte));
    debug_assert!(held, "copy_pte: mapped frame without a reference");
    // One more mapping of an anonymous page (Linux page_dup_rmap);
    // both mm's anon_vma chains hold the VMA (dup_mm)
    if let Some(pg) = phys_to_page(paging::pte_addr(pte))
        && pg.is_anon()
    {
        pg.inc_mapcount();
    }
    dp.store(child, Ordering::Release);
    Ok(child != pte && paging::pte_write(pte))
}

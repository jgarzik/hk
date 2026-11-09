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
use super::pagewalk::{PteRange, PteWalk, walk_pte_range};
use super::pgtable::{PgPrune, PgTables, Pmd, PruneDir};
use super::{Mm, MmStruct, PAGE_SIZE, SwapEntry, Vma};
use crate::FRAME_ALLOCATOR;
use crate::arch::{Leaf, paging};
use crate::mm::page::phys_to_page;
use crate::util::error::{KernelError, KernelResult};

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
    // freed below. The tables go with the mmap_lock held for writing
    // (Linux exit_mmap), so no `PgTables` of this mm lives meanwhile.
    let mut map = mm.mmap_write();
    let vmas: Vec<_> = map.take_vmas();
    // The executable's path too (Linux mmput: set_mm_exe_file(mm, NULL))
    let exe = map.take_exe();
    let mut tlb = Gather::new_full(mm);
    tlb.free_tables(super::pgtable::detach_user(mm, &mut map));
    drop(tlb);
    drop(map);
    // VMAs go last, outside any lock: they may hold the last reference
    // to a mapped file
    drop(vmas);
    drop(exe);
}

/// Clear the entries of [start, end) of `t`, the tables of the gather's
/// address space (Linux zap_page_range / unmap_page_range), under the
/// mm lock (for reading is enough: 2MB entries change under the page_table_lock, 4KB ones
/// under their table's PTE lock): each 4KB
/// entry (a page, protnone included, or a swap slot) is cleared, a 2MB
/// page wholly inside goes whole, one partly inside is split first. The
/// pages go to `tlb`, released only after its TLB flush (a swap slot
/// at once: no CPU caches a swap entry). Tables stay (munmap frees
/// them, `free_pgtables`). Only
/// user addresses: callers pass ranges inside VMAs, a range past
/// TASK_SIZE is a bug (clamped).
pub fn zap_range(tlb: &mut Gather<'_>, t: PgTables<'_>, start: u64, end: u64) {
    assert_eq!(tlb.mm().pgd(), t.pgd(), "zap: tables of another mm");
    let _ = walk_pte_range(t, start, end, &mut Zap { tlb });
}

/// `zap_range`'s walk
struct Zap<'g, 'a> {
    tlb: &'g mut Gather<'a>,
}

impl PteWalk for Zap<'_, '_> {
    type Err = core::convert::Infallible;

    fn huge(&mut self, pmd: Pmd<'_>, addr: u64, end: u64) -> Result<bool, Self::Err> {
        let base = addr & !(HUGE_PAGE_SIZE - 1);
        let mm = self.tlb.mm();
        if addr == base && end == base + HUGE_PAGE_SIZE {
            if let Some(phys) = take_huge_pmd(mm, pmd) {
                self.tlb.remove_huge(base, phys);
                return Ok(true);
            }
            // Split (or zapped) under us: clear the 4KB entries
            // (Linux zap_pmd_range falls back to zap_pte_range)
        } else {
            // Never fails for memory: the table was deposited with it
            let _ = split_huge_pmd(mm, pmd);
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
/// (Linux free_pgtables / free_pgd_range), after the range was zapped
/// and its VMAs removed from `map` (which unlinks them from their
/// reverse-map chains). `map` is the gather's address space's VMA tree,
/// borrowed mutably: the mmap_lock held for writing, and no
/// `PgTables` of the address space alive. A table is freed when the
/// whole span it maps lies in the gap between the VMAs around the range
/// (so outside every VMA left, and every chain entry) and it is empty
/// (`PruneDir::take_child`). Its parent entry is cleared at once; the
/// frame goes to `tlb`, freed after the flush that drops the
/// paging-structure caches. The top-level table stays.
pub fn free_pgtables(map: &mut MmStruct, tlb: &mut Gather<'_>, start: u64, end: u64) {
    if start >= end {
        return;
    }
    let mm = tlb.mm();
    let mut p = PgPrune::new(mm, map, start, end);
    free_level(tlb, &mut p.top(), start, end);
}

/// The entries of the table `d` whose spans meet [start, end): each
/// child table is freed bottom-up
fn free_level(tlb: &mut Gather<'_>, d: &mut PruneDir<'_>, start: u64, end: u64) {
    let (base, span) = (d.base(), d.span());
    let first = (start.max(base) - base) / span;
    let last = ((end - 1).min(base + 512 * span - 1) - base) / span;
    for i in first..=last {
        if let Some(mut c) = d.child(i) {
            free_level(tlb, &mut c, start, end);
        }
        if let Some(table) = d.take_child(i) {
            tlb.remove_table(base + i * span, span, table);
        }
    }
}

/// One past the last user address a top-level entry can map: the
/// ceiling of the page tables above the last VMA (Linux
/// USER_PGTABLES_CEILING)
pub fn pgtables_ceiling() -> u64 {
    super::TASK_SIZE.next_multiple_of(1 << 39)
}

/// A page is mapped at `addr` in `t` (protnone included)
pub fn resident(t: PgTables<'_>, addr: u64) -> bool {
    match t.pte(addr) {
        Some(p) => paging::pte_present(p.get()),
        None => t.pmd(addr).is_some_and(|p| p.huge()),
    }
}

/// (resident, swapped) 4KB pages of [start, end) in `t` (Linux
/// MM_*PAGES and MM_SWAPENTS, counted from the tables): a 2MB page
/// counts its part inside; a 1GB range without tables is skipped whole
pub fn count_ptes(t: PgTables<'_>, start: u64, end: u64) -> (u64, u64) {
    struct Count(u64, u64);
    impl PteWalk for Count {
        type Err = core::convert::Infallible;
        fn huge(&mut self, _: Pmd<'_>, addr: u64, end: u64) -> Result<bool, Self::Err> {
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
    let _ = walk_pte_range(t, start, end, &mut c);
    (c.0, c.1)
}

/// The first address in [addr, end) whose 4KB entry is a swap entry of
/// device `ty` in `t` (swapoff); 1GB ranges without tables and
/// 2MB pages are skipped
pub fn next_swap_pte(t: PgTables<'_>, addr: u64, end: u64, ty: u8) -> Option<u64> {
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
    walk_pte_range(t, addr, end, &mut Find(ty)).err()
}

/// Copy the page tables of the parent's `vma` from `src`, the tables of
/// `src_mm`, into the child's tables `dst`, those of `dst_mm` (Linux
/// copy_page_range), under both mm locks (dup_mm). A shared mapping
/// keeps sharing its pages; a private one shares them copy-on-write,
/// read-only in both, except a page the parent owns alone that may be
/// pinned for DMA: the child gets a copy and the parent keeps the page,
/// writable (Linux copy_present_page, page_needs_cow_for_dma), so a
/// device's write still lands in the page the parent sees. A swap PTE is
/// copied with another slot reference (`swap::swap_duplicate`). A 2MB
/// page is split first so that its 4KB pages are copied one by one.
/// Returns whether a parent PTE lost write permission (its TLB needs a
/// flush).
pub fn copy_page_range(
    dst: PgTables<'_>,
    dst_mm: &Mm,
    src: PgTables<'_>,
    src_mm: &Mm,
    vma: &Vma,
) -> KernelResult<bool> {
    assert_eq!(src_mm.pgd(), src.pgd(), "tables of another mm");
    let mut c = CopyRange {
        dst,
        dst_mm,
        src_mm,
        vma,
        cow: !vma.is_shared(),
        wp: false,
        spare: None,
    };
    let mut from = vma.start;
    let r = loop {
        match walk_pte_range(src, from, vma.end, &mut c) {
            Ok(()) => break Ok(c.wp),
            // A pinned page needs a copy: allocate it with no lock but
            // the mm locks held (it may reclaim), and go on from there
            // (Linux copy_pte_range's -EAGAIN and folio_prealloc)
            Err(CopyErr::Page(at)) => match super::fault::alloc_user() {
                Some(p) => {
                    c.spare = Some(p);
                    from = at;
                }
                None => break Err(KernelError::OutOfMemory),
            },
            Err(CopyErr::Oom) => break Err(KernelError::OutOfMemory),
        }
    };
    if let Some(p) = c.spare {
        FRAME_ALLOCATOR.free(p);
    }
    r
}

/// Why `copy_page_range`'s walk stopped
enum CopyErr {
    Oom,
    /// The entry at this address needs a page for the child's copy
    Page(u64),
}

/// `copy_page_range`'s walk
struct CopyRange<'a> {
    dst: PgTables<'a>,
    dst_mm: &'a Mm,
    src_mm: &'a Mm,
    vma: &'a Vma,
    cow: bool,
    wp: bool,
    /// A page for the next pinned page's copy
    spare: Option<u64>,
}

impl PteWalk for CopyRange<'_> {
    type Err = CopyErr;

    fn huge(&mut self, pmd: Pmd<'_>, _: u64, _: u64) -> Result<bool, CopyErr> {
        split_huge_pmd(self.src_mm, pmd).ok_or(CopyErr::Oom)?;
        Ok(false)
    }

    /// One parent table, its PTE lock held by the walk (the reverse map,
    /// reclaim, changes its entries without the mmap_lock: Linux
    /// copy_pte_range), into the child's table under that table's PTE
    /// lock (dup_mm already put the child's VMA on the reverse-map
    /// chains). Parent, then child: only fork nests these two.
    /// The child's table, allocated before the parent's PTE lock is
    /// taken (Linux copy_pte_range: pte_alloc_map_lock of the child
    /// first)
    fn prepare(&mut self, addr: u64, _end: u64) -> Result<(), CopyErr> {
        self.dst
            .pte_alloc(self.dst_mm, addr)
            .map(|_| ())
            .ok_or(CopyErr::Oom)
    }

    fn ptes(&mut self, r: &PteRange<'_>) -> Result<(), CopyErr> {
        if r.iter().all(|(_, e)| e.load(Ordering::Acquire) == 0) {
            return Ok(());
        }
        let d = self.dst.pte(r.start).ok_or(CopyErr::Oom)?.lock();
        for (a, se) in r.iter() {
            if self.cow && needs_cow_for_dma(se.load(Ordering::Acquire)) {
                let new = self.spare.take().ok_or(CopyErr::Page(a))?;
                copy_pinned(d.entry(a), se, new, a, self.vma);
                continue;
            }
            self.wp |= copy_pte(d.entry(a), se, self.cow).map_err(|_| CopyErr::Oom)?;
        }
        Ok(())
    }
}

/// The present private entry `pte` maps a page its mapping owns alone
/// and that may be pinned (Linux folio_needs_cow_for_dma, after
/// folio_try_dup_anon_rmap failed): fork must not share it. Stable under
/// the parent's PTE lock, which a pin takes.
fn needs_cow_for_dma(pte: u64) -> bool {
    if !paging::pte_present(pte) {
        return false;
    }
    let phys = paging::pte_addr(pte);
    phys_to_page(phys).is_some_and(|p| p.anon_exclusive()) && super::gup::maybe_dma_pinned(phys)
}

/// Give the child at `addr` a copy, in the fresh page `new`, of the
/// pinned page the parent entry `sp` maps (Linux copy_present_page):
/// the child's own page, with the mapping's protection; the parent's
/// entry and page stay as they are. Both PTE locks held.
fn copy_pinned(dp: &AtomicU64, sp: &AtomicU64, new: u64, addr: u64, vma: &Vma) {
    let pte = sp.load(Ordering::Acquire);
    let old = paging::pte_addr(pte);
    // SAFETY: `new` is ours; `old` stays mapped and referenced (parent
    // PTE lock held). A device writing it meanwhile gives the child a
    // copy from some moment of the I/O, as Linux's copy does.
    unsafe { super::page::copy_page(new, old) };
    paging::sync_page(new, paging::pte_exec(pte));
    if let Some(av) = vma
        .anon_vma
        .as_ref()
        .filter(|_| phys_to_page(old).is_some_and(|p| p.is_anon()))
    {
        super::rmap::page_add_anon_rmap(new, av, vma.index_of(addr));
        super::lru::lru_add(new);
    }
    if let Some(pg) = phys_to_page(new) {
        pg.set_anon_exclusive();
    }
    // The parent's entry with the child's page: its protection (a
    // protnone entry stays protnone), dirty and accessed bits
    dp.store((pte & !paging::PTE_ADDR_MASK) | new, Ordering::Release);
}

/// Copy the parent PTE `sp` into the child's `dp` (Linux
/// copy_present_pte / copy_nonpresent_pte), both PTE locks held; true
/// if the parent's entry was write-protected
fn copy_pte(dp: &AtomicU64, sp: &AtomicU64, cow: bool) -> KernelResult<bool> {
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
                return Err(KernelError::OutOfMemory);
            }
            dp.store(pte, Ordering::Release);
        }
        return Ok(false);
    }
    let mut child = pte;
    if cow {
        // Shared copy-on-write from now on: no longer the parent's alone
        if let Some(pg) = phys_to_page(paging::pte_addr(pte)) {
            pg.clear_flag(super::page::PG_ANON_EXCL);
        }
    }
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

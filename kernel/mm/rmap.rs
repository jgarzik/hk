//! Reverse mapping of anonymous pages (Linux mm/rmap.c)
//!
//! An anonymous page records its AnonVma (`Page.mapping`, a reference
//! held until the page is freed, so a walker holding a page reference
//! can always reach it) and its linear index (`Page.index`); its map
//! count counts the PTEs mapping it. See `anon_vma` for the chains.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::mm::anon_vma::{AnonVma, Avc};
use crate::mm::page::phys_to_page;

/// A PTE now maps the new anonymous page `phys` of `anon_vma` at the
/// linear index `index` (Linux folio_add_new_anon_rmap)
pub fn page_add_anon_rmap(phys: u64, anon_vma: &Arc<AnonVma>, index: u64) {
    if let Some(page) = phys_to_page(phys) {
        page.set_anon_mapping(anon_vma);
        page.index.store(index, Ordering::Relaxed);
        page.inc_mapcount();
    }
}

/// A PTE stopped mapping the anonymous page `phys` (Linux
/// folio_remove_rmap_pte): its mapping stays until the page is freed
pub fn page_remove_rmap(phys: u64) {
    if let Some(page) = phys_to_page(phys)
        && page.is_anon()
    {
        page.dec_mapcount();
    }
}

/// Each PTE mapping the anonymous page `phys` (Linux rmap_walk_anon):
/// `f(mm, chain entry, address, PTE pointer, PTE value)` under that
/// table's PTE lock, the AnonVma chain held for reading (so no table
/// of a VMA in the chain is freed meanwhile); `f` returns false to
/// stop the walk, and so does `rmap_walk`. The caller holds a reference
/// on the page (its mapping stays until it is freed). Sleeps (the
/// chain lock): thread context, no spinlock held.
pub fn rmap_walk(
    phys: u64,
    f: &mut dyn FnMut(&crate::mm::Mm, &Avc, u64, *mut u64, u64) -> bool,
) -> bool {
    use crate::arch::paging;
    let Some(pg) = phys_to_page(phys).filter(|p| p.is_anon()) else {
        return true;
    };
    let Some(av) = pg.get_anon_vma() else {
        return true;
    };
    let index = pg.index.load(Ordering::Relaxed);
    let chain = av.read();
    for avc in chain.iter() {
        let Some(addr) = avc.address(index) else {
            continue;
        };
        let Some(mm) = avc.mm.upgrade() else {
            continue;
        };
        let Some(ptep) = paging::pte_ptr(avc.pgd, addr) else {
            continue;
        };
        let _l = crate::mm::ptl::pte_lock(ptep);
        // SAFETY: a live table of a VMA in the chain, under its PTE lock
        let pte = unsafe { core::sync::atomic::AtomicU64::from_ptr(ptep) }.load(Ordering::Acquire);
        if paging::pte_present(pte)
            && paging::pte_addr(pte) == phys
            && !f(&mm, avc, addr, ptep, pte)
        {
            return false;
        }
    }
    true
}

/// Replace every PTE mapping the locked swap-cache page `phys` by the
/// swap entry `e` (Linux try_to_unmap_one): each swap PTE takes a slot
/// reference, each PTE's page reference goes (the caller holds its own).
/// Stops at a memory-locked VMA. True if no PTE maps the page any more:
/// a mapping the walk did not find keeps the map count up, and the
/// page is then never freed.
pub fn try_to_unmap(phys: u64, e: crate::mm::SwapEntry) -> bool {
    use core::sync::atomic::AtomicU64;
    rmap_walk(phys, &mut |mm, avc, addr, ptep, pte| {
        if avc.locked || !crate::mm::swap::swap_duplicate(e) {
            return false;
        }
        // SAFETY: as in `rmap_walk`
        let p = unsafe { AtomicU64::from_ptr(ptep) };
        if !unmap_one(p, pte, phys, e) {
            crate::mm::swap::swap_free(e);
            return true;
        }
        crate::mm::tlb::flush_tlb_page(mm, addr);
        page_remove_rmap(phys);
        crate::FRAME_ALLOCATOR.decref(phys);
        true
    });
    phys_to_page(phys).is_some_and(|p| p.mapcount() == 0)
}

/// Swap the entry `p` (last seen as `pte`) from mapping `phys` to the
/// swap entry `e`, its PTE lock held. Only the MMU changes it meanwhile
/// (accessed/dirty bits): retry with those; false if it no longer maps
/// `phys` (never overwrite what some other writer stored)
fn unmap_one(
    p: &core::sync::atomic::AtomicU64,
    pte: u64,
    phys: u64,
    e: crate::mm::SwapEntry,
) -> bool {
    use crate::arch::paging;
    let mut cur = pte;
    loop {
        if !paging::pte_present(cur) || paging::pte_addr(cur) != phys {
            return false;
        }
        match p.compare_exchange(cur, e.to_pte(), Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(now) => cur = now,
        }
    }
}

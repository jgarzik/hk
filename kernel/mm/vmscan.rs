//! Page reclaim (Linux mm/vmscan.c, anonymous pages only)
//!
//! `shrink_folio_list` frees isolated LRU pages by swapping them out:
//! each page is locked (trylock: reclaim never waits for a page lock),
//! given a swap slot and put in the swap cache (dirty), unmapped from
//! every PTE through the reverse map (each PTE becomes the swap entry),
//! written to its slot if dirty, then taken out of the swap cache with
//! its count frozen (no lookup can take a reference meanwhile) and
//! freed. A page still mapped (a locked VMA, a mapping the walk did not
//! reach), still referenced elsewhere, or that cannot be written goes
//! back to the LRU, active. The write sleeps (block I/O) with the page
//! locked and no spinlock held.
//!
//! Callers: MADV_PAGEOUT (`reclaim_pages`) and the allocator's slow
//! path (`try_to_free_pages`, direct reclaim). Reclaim takes no mmap_lock
//! (the caller may hold one for reading).
//!
//! Deviation from Linux: no accessed-bit aging (a page's PTE young bit
//! is not consulted: pages go inactive at fault and are reclaimed
//! oldest first), no file pages (P5), no kswapd (P6), writes are
//! synchronous.

use alloc::vec::Vec;

use super::lru::{self, Lru};
use super::page::{PG_DIRTY, phys_to_page, trylock_page, unlock_page};
use super::swap::get_swap_page;
use super::swap_state;
use crate::FRAME_ALLOCATOR;

/// Pages direct reclaim takes per pass (Linux SWAP_CLUSTER_MAX)
pub const SWAP_CLUSTER_MAX: usize = 32;

/// What became of a page `shrink_page` looked at
enum Fate {
    /// Freed
    Freed,
    /// Back to the LRU (active: not worth trying again soon)
    Keep { active: bool },
}

/// Reclaim the isolated pages `pages` (each holding an isolation
/// reference, Linux shrink_folio_list): the number freed; the others
/// go back to the LRU
pub fn shrink_folio_list(pages: Vec<u64>) -> usize {
    let mut freed = 0;
    for phys in pages {
        match shrink_page(phys) {
            Fate::Freed => freed += 1,
            Fate::Keep { active } => {
                let l = if active {
                    Lru::ActiveAnon
                } else {
                    Lru::InactiveAnon
                };
                lru::putback(phys, l, false);
            }
        }
    }
    freed
}

/// Reclaim one isolated page
fn shrink_page(phys: u64) -> Fate {
    let Some(pg) = phys_to_page(phys) else {
        return Fate::Keep { active: true };
    };
    if !pg.is_anon() || !trylock_page(phys) {
        return Fate::Keep { active: false };
    }
    let fate = pageout(phys);
    if !matches!(fate, Fate::Freed) {
        unlock_page(phys);
    }
    fate
}

/// Swap out the locked page `phys` (isolation reference held)
fn pageout(phys: u64) -> Fate {
    let Some(pg) = phys_to_page(phys) else {
        return Fate::Keep { active: true };
    };
    // A slot and a swap-cache place (Linux add_to_swap)
    if !pg.is_swapcache() {
        let Some(e) = get_swap_page() else {
            return Fate::Keep { active: true };
        };
        if !swap_state::add(e, phys) {
            super::swap::swapcache_clear(e);
            return Fate::Keep { active: true };
        }
        pg.set_flag(PG_DIRTY);
    }
    let Some(e) = swap_state::entry_of(phys) else {
        return Fate::Keep { active: true };
    };
    if pg.mapcount() > 0 && !super::rmap::try_to_unmap(phys, e) {
        return Fate::Keep { active: true };
    }
    // Written only if changed since the slot last held it (a page read
    // back from swap is mapped read-only while it stays in the cache)
    if pg.is_dirty() {
        pg.clear_flag(PG_DIRTY);
        if super::swap::swap_write_page(e, phys).is_err() {
            pg.set_flag(PG_DIRTY);
            return Fate::Keep { active: true };
        }
    }
    // Ours and the cache's references only (Linux __remove_mapping):
    // freeze them and free the page; the slot stays for its swap PTEs
    if !swap_state::delete_frozen(e, phys, 2) {
        return Fate::Keep { active: false };
    }
    pg.unlock();
    FRAME_ALLOCATOR.free_frozen(phys);
    Fate::Freed
}

/// Reclaim the isolated pages of MADV_PAGEOUT (Linux reclaim_pages)
pub fn reclaim_pages(pages: Vec<u64>) -> usize {
    shrink_folio_list(pages)
}

/// Direct reclaim (Linux try_to_free_pages, one pass of
/// shrink_inactive_list): up to `nr` pages from the inactive tail, the
/// active list aged into it first when it runs short. Only with swap.
/// The number freed.
pub fn try_to_free_pages(nr: usize) -> usize {
    let (total, free) = super::swap::swap_totals();
    if total == 0 || free == 0 || super::swap::file_swap_active() {
        return 0;
    }
    lru::lru_add_drain_all();
    if lru::LRUVEC.len(Lru::InactiveAnon) < nr {
        age_active(nr);
    }
    let mut pages = Vec::with_capacity(nr);
    lru::isolate_tail(Lru::InactiveAnon, nr, &mut pages);
    shrink_folio_list(pages)
}

/// Move up to `nr` pages from the active tail to the inactive head
/// (Linux shrink_active_list, without the referenced check)
fn age_active(nr: usize) {
    let mut pages = Vec::with_capacity(nr);
    lru::isolate_tail(Lru::ActiveAnon, nr, &mut pages);
    for phys in pages {
        lru::putback(phys, Lru::InactiveAnon, false);
    }
}

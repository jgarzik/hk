//! Reverse mapping of anonymous pages (Linux mm/rmap.c)
//!
//! An anonymous page records its AnonVma (`Page.mapping`, a reference
//! held until the page is freed, so a walker holding a page reference
//! can always reach it) and its linear index (`Page.index`); its map
//! count counts the PTEs mapping it. See `anon_vma` for the chains.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::mm::anon_vma::AnonVma;
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

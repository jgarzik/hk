//! Releasing user memory (Linux mm/memory.c zap_*, mm/mmap.c exit_mmap)
//!
//! Every present user PTE holds one reference on its frame (fork increfs
//! the shared copy-on-write frame, SysV shm attachments take one per
//! page): unmapping drops it, and the frame is freed with the last one.
//! Frames outside the allocator (MMIO) have no count and are never freed.

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::Mm;
use crate::arch::Leaf;
use crate::mm::page::page_descriptor;

/// Drop one mapping's reference to the 4KB user page `phys` (Linux
/// zap_present_pte: rmap removal + put). The last reference frees it;
/// its descriptor state goes first so a reallocated frame starts clean.
pub fn put_page(phys: u64) {
    let fa = &crate::FRAME_ALLOCATOR;
    if fa.refcount(phys) <= 1 {
        release_desc(phys);
    } else if let Some(pg) = page_descriptor(phys)
        && pg.is_anon()
        && pg.mapcount() > 0
    {
        pg.dec_mapcount();
    }
    fa.decref(phys);
}

/// Drop one mapping's reference to the 2MB user page at `phys`
pub fn put_huge(phys: u64) {
    let fa = &crate::FRAME_ALLOCATOR;
    if fa.refcount_huge(phys) <= 1 {
        release_desc(phys);
    }
    fa.decref_huge(phys);
}

/// Forget a page's rmap and LRU state: it is about to be freed
fn release_desc(phys: u64) {
    super::lru::lru_remove(phys);
    if let Some(pg) = page_descriptor(phys) {
        pg.clear_mapping();
        pg.mapcount.store(0, Ordering::Relaxed);
    }
}

/// Release one user mapping met by `paging::free_user`
fn zap_leaf(leaf: Leaf) {
    use super::SwapEntry;
    match leaf {
        Leaf::Page(p) => put_page(p),
        Leaf::Huge(p) => put_huge(p),
        Leaf::Swap(pte) if SwapEntry::is_swap_pte(pte) => {
            super::free_swap_entry(SwapEntry::from_pte(pte))
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
/// still have it loaded: `free_user` detaches the user half and flushes
/// the TLB before freeing anything.
pub(super) fn exit_mmap(mm: &Mm) {
    let vmas: Vec<_> = mm.lock().take_vmas();
    for vma in &vmas {
        if let Some(av) = &vma.anon_vma {
            av.remove_root(mm.pgd());
        }
    }
    crate::arch::paging::free_user(mm.pgd(), &mut zap_leaf);
    // VMAs go last, outside any lock: they may hold the last reference
    // to a mapped file
    drop(vmas);
}

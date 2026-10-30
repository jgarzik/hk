//! The swap cache (Linux mm/swap_state.c)
//!
//! A page being written to a swap slot, or read back from one, sits in
//! its device's swap cache (`SwapInfo.cache`, an xarray by slot) with
//! `PG_SWAPCACHE` set and the entry in `Page.private`; the cache holds
//! a page reference and the slot's SWAP_HAS_CACHE count. Every swap PTE
//! of the slot then finds that one page: tasks sharing a slot after
//! fork share the page again, and a page reclaimed while still clean
//! needs no second write.
//!
//! Locking: the cache's `IrqSpinlock` (Linux i_pages xa_lock_irq) is a
//! leaf over the xarray; under it only the allocator is taken (index
//! nodes). A lookup takes its page reference under it with
//! get_page_unless_zero, so it never revives a page reclaim froze
//! (refcount 0) to delete it. Adding and deleting a page happen with the
//! page locked (`page::lock_page`); the slot count (`SwapInfo.map`) is
//! updated after the cache lock is dropped, never under it.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::fault::VmFault;
use super::page::{PG_SWAPCACHE, lock_page, phys_to_page, trylock_page, unlock_page};
use super::swap::{
    SwapInfo, get_swap_info, swap_count, swap_read_page, swapcache_clear, swapcache_prepare,
};
use super::swap_entry::SwapEntry;
use crate::FRAME_ALLOCATOR;
use crate::error::KernelError;

/// The swap-cache page of `e`, with a reference (Linux
/// swap_cache_get_folio)
pub fn lookup(e: SwapEntry) -> Option<u64> {
    let si = get_swap_info(e.swap_type())?;
    let cache = si.cache.lock();
    let page = cache.load(e.offset());
    (page != 0 && FRAME_ALLOCATOR.incref(page)).then_some(page)
}

/// The page holds `e` in the swap cache
fn holds(phys: u64, e: SwapEntry) -> bool {
    phys_to_page(phys)
        .is_some_and(|pg| pg.is_swapcache() && pg.private.load(Ordering::Relaxed) == e.raw())
}

/// Put the locked page `phys` in the swap cache for `e`, whose slot
/// already counts SWAP_HAS_CACHE (Linux add_to_swap_cache); the cache
/// takes a page reference. False if out of memory for index nodes.
pub fn add(e: SwapEntry, phys: u64) -> bool {
    let (Some(si), Some(pg)) = (get_swap_info(e.swap_type()), phys_to_page(phys)) else {
        return false;
    };
    if !FRAME_ALLOCATOR.incref(phys) {
        return false;
    }
    pg.private.store(e.raw(), Ordering::Relaxed);
    pg.set_flag(PG_SWAPCACHE);
    let stored = si
        .cache
        .lock()
        .store(e.offset(), phys, &mut || FRAME_ALLOCATOR.alloc());
    debug_assert!(stored.is_none_or(|old| old == 0));
    if stored.is_none() {
        unhash(pg);
        FRAME_ALLOCATOR.decref(phys);
        return false;
    }
    si.cached.fetch_add(1, Ordering::Relaxed);
    true
}

fn unhash(pg: &super::page::Page) {
    pg.clear_flag(PG_SWAPCACHE);
    pg.private.store(0, Ordering::Relaxed);
}

/// Take the locked page `phys` out of the swap cache of `e` (Linux
/// delete_from_swap_cache): its SWAP_HAS_CACHE count and the cache's
/// page reference go
pub fn delete(e: SwapEntry, phys: u64) {
    if let Some(si) = get_swap_info(e.swap_type()) {
        let old = si.cache.lock().erase(e.offset());
        debug_assert_eq!(old, phys);
        si.cached.fetch_sub(1, Ordering::Relaxed);
    }
    if let Some(pg) = phys_to_page(phys) {
        unhash(pg);
    }
    swapcache_clear(e);
    FRAME_ALLOCATOR.decref(phys);
}

/// Delete the locked page `phys`, with `expected` references (the
/// cache's included) and no other, from the swap cache, leaving it
/// unreferenced (Linux __remove_mapping: folio_ref_freeze under the
/// cache lock, so no lookup can take a reference meanwhile). The caller
/// frees the frozen page. False if someone else holds a reference.
pub fn delete_frozen(e: SwapEntry, phys: u64, expected: u32) -> bool {
    let (Some(si), Some(pg)) = (get_swap_info(e.swap_type()), phys_to_page(phys)) else {
        return false;
    };
    {
        let mut cache = si.cache.lock();
        if pg
            .refcount
            .compare_exchange(expected, 0, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return false;
        }
        cache.erase(e.offset());
    }
    si.cached.fetch_sub(1, Ordering::Relaxed);
    unhash(pg);
    swapcache_clear(e);
    true
}

/// The swap entry of a swap-cache page
pub fn entry_of(phys: u64) -> Option<SwapEntry> {
    let pg = phys_to_page(phys)?;
    pg.is_swapcache()
        .then(|| SwapEntry::from_raw(pg.private.load(Ordering::Relaxed)))
}

/// Drop the locked page `phys` from the swap cache if no swap PTE needs
/// its slot any more (Linux folio_free_swap): true if it was
pub fn try_free_swap(phys: u64) -> bool {
    match entry_of(phys) {
        Some(e) if swap_count(e) == 0 => {
            delete(e, phys);
            true
        }
        _ => false,
    }
}

/// A page whose last mapping went (zap after the TLB flush, Linux
/// free_swap_cache): drop it from the swap cache if nothing else needs
/// it there. Never sleeps (trylock).
pub fn free_swap_cache(phys: u64) {
    let unmapped = phys_to_page(phys).is_some_and(|pg| pg.is_swapcache() && pg.mapcount() == 0);
    if unmapped && trylock_page(phys) {
        try_free_swap(phys);
        unlock_page(phys);
    }
}

/// The last swap PTE of `e` went and its slot still has a cache page:
/// drop the page if it is unmapped (Linux __try_to_reclaim_swap with
/// TTRS_UNMAPPED). Never sleeps.
pub fn try_reclaim_swap(e: SwapEntry) {
    let Some(phys) = lookup(e) else {
        return;
    };
    if trylock_page(phys) {
        let unmapped = phys_to_page(phys).is_some_and(|pg| pg.mapcount() == 0);
        if unmapped && holds(phys, e) {
            try_free_swap(phys);
        }
        unlock_page(phys);
    }
    FRAME_ALLOCATOR.decref(phys);
}

/// The page of swap entry `e` for a fault (Linux do_swap_page +
/// swapin), locked and with a reference: the swap-cache page if there
/// is one, else a new page read from the slot into the cache. Sleeps
/// (page lock, I/O): mmap_lock held for reading, no spinlock. `Retry`
/// if the slot was freed meanwhile (the PTE changed).
pub fn read_swap_page(e: SwapEntry) -> Result<u64, VmFault> {
    loop {
        if let Some(phys) = lookup(e) {
            lock_page(phys);
            if holds(phys, e) {
                return Ok(phys);
            }
            unlock_page(phys);
            FRAME_ALLOCATOR.decref(phys);
            continue;
        }
        match swapcache_prepare(e) {
            Ok(()) => return read_new(e),
            // Another task is reading it in: sleep until its page
            // shows up or its claim goes (Linux: the racer sleeps on
            // the locked folio)
            Err(true) => super::swap::swap_wait(e).wait_event(|| settled(e)),
            Err(false) => return Err(VmFault::Retry),
        }
    }
}

/// A claim on `e` settled: its page is in the swap cache, or nobody
/// holds SWAP_HAS_CACHE any more
fn settled(e: SwapEntry) -> bool {
    if let Some(phys) = lookup(e) {
        FRAME_ALLOCATOR.decref(phys);
        return true;
    }
    !super::swap::swapcache_busy(e)
}

/// Read `e`, whose slot this task claimed (SWAP_HAS_CACHE), into a new
/// locked swap-cache page
fn read_new(e: SwapEntry) -> Result<u64, VmFault> {
    let Some(phys) = super::fault::alloc_user() else {
        swapcache_clear(e);
        return Err(VmFault::Oom);
    };
    let locked = trylock_page(phys);
    debug_assert!(locked);
    if !add(e, phys) {
        unlock_page(phys);
        FRAME_ALLOCATOR.decref(phys);
        swapcache_clear(e);
        return Err(VmFault::Oom);
    }
    // Racers waiting on the claim find the (locked) page now
    super::swap::swap_wait(e).wake_all();
    if swap_read_page(e, phys).is_err() {
        delete(e, phys);
        unlock_page(phys);
        FRAME_ALLOCATOR.decref(phys);
        return Err(VmFault::Bus);
    }
    super::lru::lru_add(phys);
    Ok(phys)
}

/// swapoff: bring every page of `si` back into memory (Linux
/// try_to_unuse): every swap PTE of the device in every address space
/// is faulted in, then the cache pages left are dropped. ENOMEM if a
/// page cannot be read, EINTR on SIGKILL.
pub fn try_to_unuse(si: &Arc<SwapInfo>) -> Result<(), KernelError> {
    for _ in 0..16 {
        for mm in all_mms() {
            if let Some(mm) = super::mmget_not_zero(&mm) {
                unuse_mm(&mm, si.swap_type)?;
            }
        }
        drop_cache(si);
        if si.inuse.load(Ordering::Acquire) == 0 {
            return Ok(());
        }
        if crate::signal::fatal_signal_pending() {
            return Err(KernelError::Interrupted);
        }
    }
    Err(KernelError::OutOfMemory)
}

/// Every live address space (mm_count references)
fn all_mms() -> Vec<Arc<super::Mm>> {
    let mut v: Vec<Arc<super::Mm>> = Vec::new();
    {
        let table = crate::task::percpu::TASKLIST.read();
        for t in table.iter() {
            let a = t.task.task_lock();
            if let Some(mm) = a.mm()
                && !v.iter().any(|m| Arc::ptr_eq(m, mm.arc()))
            {
                v.push(mm.arc().clone());
            }
        }
    }
    v
}

/// Fault in the swap PTEs of type `ty` in `mm`
fn unuse_mm(mm: &super::Mm, ty: u8) -> Result<(), KernelError> {
    let map = mm.mmap_read_killable()?;
    for vma in map.iter().filter(|v| v.anon_vma.is_some()) {
        let mut addr = vma.start;
        while addr < vma.end {
            match super::memory::next_swap_pte(mm.pgd(), addr, vma.end, ty) {
                Some(a) => {
                    super::fault::unuse_pte(mm, vma, a).map_err(|_| KernelError::OutOfMemory)?;
                    addr = a + super::PAGE_SIZE;
                }
                None => break,
            }
        }
    }
    Ok(())
}

/// Drop the cache pages of `si` no swap PTE needs (swapoff)
fn drop_cache(si: &SwapInfo) {
    let mut pages = Vec::new();
    si.cache
        .lock()
        .for_each(0, si.max, &mut |off, _| pages.push(off));
    for off in pages {
        let e = SwapEntry::new(si.swap_type, off);
        if let Some(phys) = lookup(e) {
            lock_page(phys);
            if holds(phys, e) {
                try_free_swap(phys);
            }
            unlock_page(phys);
            FRAME_ALLOCATOR.decref(phys);
        }
    }
}

/// Free the cache's index of a device swapoff emptied
pub fn destroy_cache(si: &SwapInfo) {
    // Empty by now (every slot free): only index nodes are left
    si.cache.lock().destroy(&mut |_| {});
}

/// Pages in every swap cache (meminfo SwapCached)
pub fn total_cached() -> u64 {
    super::swap::SWAP_INFO
        .read()
        .iter()
        .flatten()
        .map(|si| si.cached.load(Ordering::Relaxed))
        .sum()
}

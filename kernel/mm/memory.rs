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
use super::{Mm, PAGE_SIZE, SwapEntry, Vma};
use crate::FRAME_ALLOCATOR;
use crate::arch::{Leaf, paging};
use crate::mm::page::phys_to_page;

const ENOMEM: i32 = 12;

/// Attempts at copying one PTE that keeps changing under fork
const COPY_RETRIES: usize = 16;

/// Drop one mapping's reference to the 4KB user page `phys` (Linux
/// zap_present_pte: rmap removal + put). The last reference frees it;
/// its descriptor state goes first so a reallocated frame starts clean.
pub fn put_page(phys: u64) {
    let fa = &crate::FRAME_ALLOCATOR;
    if fa.refcount(phys) <= 1 {
        release_desc(phys);
    } else if let Some(pg) = phys_to_page(phys)
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
    if let Some(pg) = phys_to_page(phys) {
        pg.clear_mapping();
        pg.mapcount.store(0, Ordering::Relaxed);
    }
}

/// Release one user mapping (after its TLB flush: `Gather`)
pub(super) fn zap_leaf(leaf: Leaf) {
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
/// still have it loaded: the user half is detached and every such CPU
/// flushed (paging-structure caches included) before anything is
/// freed (Linux tlb_gather_mmu_fullmm).
pub(super) fn exit_mmap(mm: &Mm) {
    let vmas: Vec<_> = mm.mmap_write().take_vmas();
    for vma in &vmas {
        if let Some(av) = &vma.anon_vma {
            av.remove_root(mm.pgd());
        }
    }
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
/// at once: no CPU caches a swap entry). Empty tables are kept. Only
/// user addresses: callers pass ranges inside VMAs, a range past
/// TASK_SIZE is a bug (clamped).
pub fn zap_range(tlb: &mut Gather, start: u64, end: u64) {
    let mm = tlb.mm();
    let pgd = mm.pgd();
    const GB: u64 = 1 << 30;
    debug_assert!(
        start <= end && end <= super::TASK_SIZE,
        "zap_range {start:#x}..{end:#x}"
    );
    let end = end.min(super::TASK_SIZE);
    let mut addr = start;
    while addr < end {
        let Some(pmd) = paging::pmd_ptr(pgd, addr) else {
            addr = ((addr | (GB - 1)) + 1).min(end);
            continue;
        };
        let base = addr & !(HUGE_PAGE_SIZE - 1);
        let next = (base + HUGE_PAGE_SIZE).min(end);
        if paging::pmd_huge(entry(pmd).load(Ordering::Acquire)) {
            if addr == base && next == base + HUGE_PAGE_SIZE {
                if let Some(phys) = take_huge_pmd(mm, base) {
                    tlb.remove_huge(base, phys);
                }
                addr = next;
                continue;
            }
            // Out of memory: the 2MB page stays mapped (BUGS.md)
            let _ = split_huge_pmd(mm, base);
        }
        // A table stays once installed: lock it for its entries
        if let Some(p) = paging::pte_ptr(pgd, addr) {
            let _l = super::ptl::pte_lock(p);
            for a in (addr..next).step_by(PAGE_SIZE as usize) {
                zap_pte(tlb, a);
            }
        }
        addr = next;
    }
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
    const GB: u64 = 1 << 30;
    let (mut rss, mut swap) = (0, 0);
    let mut addr = start;
    while addr < end {
        let Some(pmd) = paging::pmd_ptr(pgd, addr) else {
            addr = ((addr | (GB - 1)) + 1).min(end);
            continue;
        };
        let next = ((addr | (HUGE_PAGE_SIZE - 1)) + 1).min(end);
        let e = entry(pmd).load(Ordering::Acquire);
        if paging::pmd_huge(e) {
            rss += (next - addr) / PAGE_SIZE;
        } else if e != 0 {
            for a in (addr..next).step_by(PAGE_SIZE as usize) {
                let Some(p) = paging::pte_ptr(pgd, a) else {
                    continue;
                };
                let pte = entry(p).load(Ordering::Acquire);
                if paging::pte_present(pte) {
                    rss += 1;
                } else if SwapEntry::is_swap_pte(pte) {
                    swap += 1;
                }
            }
        }
        addr = next;
    }
    (rss, swap)
}

/// Clear the 4KB entry for `addr`; what it held goes to `tlb`
fn zap_pte(tlb: &mut Gather, addr: u64) {
    let Some(p) = paging::pte_ptr(tlb.mm().pgd(), addr) else {
        return;
    };
    let pte = entry(p).swap(0, Ordering::AcqRel);
    if paging::pte_present(pte) {
        tlb.remove_page(addr, paging::pte_addr(pte));
    } else if SwapEntry::is_swap_pte(pte) {
        super::free_swap_entry(SwapEntry::from_pte(pte));
    }
}

/// The page table entry at `p`, as an atomic
fn entry(p: *mut u64) -> &'static AtomicU64 {
    // SAFETY: `p` points into a live page table
    unsafe { AtomicU64::from_ptr(p) }
}

/// Copy the page tables of the parent's `vma` from the address space
/// `src` into the child's tables at `dst` (Linux copy_page_range), under
/// the parent's mm lock. A shared mapping keeps sharing its pages; a private
/// one shares them copy-on-write, read-only in both; a swap PTE fails
/// the copy (ENOMEM, see `swap_pte_unsupported`). A 2MB page is split first so that its 4KB
/// pages are copied one by one. Returns whether a parent PTE lost write
/// permission (its TLB needs a flush).
pub fn copy_page_range(dst: u64, src_mm: &Mm, vma: &Vma) -> Result<bool, i32> {
    const GB: u64 = 1 << 30;
    let src = src_mm.pgd();
    let cow = !vma.is_shared();
    let mut wp = false;
    let mut addr = vma.start;
    while addr < vma.end {
        let Some(pmd) = paging::pmd_ptr(src, addr) else {
            // No table for this 1GB: skipped whole, so a sparse VMA is not
            // walked 2MB by 2MB under the lock
            addr = ((addr | (GB - 1)) + 1).min(vma.end);
            continue;
        };
        let next = ((addr | (HUGE_PAGE_SIZE - 1)) + 1).min(vma.end);
        if paging::pmd_huge(entry(pmd).load(Ordering::Acquire)) {
            split_huge_pmd(src_mm, addr).ok_or(ENOMEM)?;
        }
        if entry(pmd).load(Ordering::Acquire) != 0 {
            for a in (addr..next).step_by(PAGE_SIZE as usize) {
                wp |= copy_pte(dst, src, a, cow)?;
            }
        }
        addr = next;
    }
    Ok(wp)
}

/// fork met a swap PTE. Unreachable while swap-out is inert (page
/// descriptors are never initialized, BUGS.md): copying one needs swap
/// slot reference counting that is safe against a racing swap-in, left
/// for when reclaim is enabled. Until then fork fails with ENOMEM.
fn swap_pte_unsupported() -> i32 {
    use core::sync::atomic::AtomicBool;
    static WARNED: AtomicBool = AtomicBool::new(false);
    if !WARNED.swap(true, Ordering::Relaxed) {
        crate::printkln!("fork: swap PTE not copied, fork fails (ENOMEM)");
    }
    ENOMEM
}

/// Copy the PTE for `addr` (Linux copy_present_pte); true if the
/// parent's entry was write-protected
fn copy_pte(dst: u64, src: u64, addr: u64, cow: bool) -> Result<bool, i32> {
    let Some(sp) = paging::pte_ptr(src, addr) else {
        return Ok(false);
    };
    if entry(sp).load(Ordering::Acquire) == 0 {
        return Ok(false);
    }
    let dp = paging::pte_alloc(dst, addr).ok_or(ENOMEM)?;
    // Faults and the other PTE writers hold the mm lock, as fork does: the
    // entry should not change under us. It is still updated with a
    // compare-and-swap (a hardware dirty/accessed bit update, or a writer
    // that does not take the lock, changes it): a bounded number of
    // retries, then fork fails (ENOMEM) instead of spinning.
    for _ in 0..COPY_RETRIES {
        let pte = entry(sp).load(Ordering::Acquire);
        if !paging::pte_present(pte) {
            if SwapEntry::is_swap_pte(pte) {
                return Err(swap_pte_unsupported());
            }
            return Ok(false);
        }
        let mut child = pte;
        if cow && !paging::pte_cow(pte) {
            child = paging::pte_mkcow(pte);
            if entry(sp)
                .compare_exchange(pte, child, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }
        }
        FRAME_ALLOCATOR.incref(paging::pte_addr(pte));
        // One more mapping of an anonymous page (Linux page_dup_rmap);
        // both mm's anon_vma chains hold the VMA (dup_mm)
        if let Some(pg) = phys_to_page(paging::pte_addr(pte))
            && pg.is_anon()
        {
            pg.inc_mapcount();
        }
        entry(dp).store(child, Ordering::Release);
        return Ok(child != pte && paging::pte_write(pte));
    }
    Err(ENOMEM)
}

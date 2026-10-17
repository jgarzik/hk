//! Changing the protection of mapped pages (Linux mm/mprotect.c)
//!
//! mprotect rewrites the entries already mapped in its range under the
//! mm lock (Linux change_protection), then flushes the TLB of the range
//! before the lock is dropped. A page left with no access (PROT_NONE)
//! keeps its frame in a protnone entry (`paging::pte_modify`): every
//! access faults (SIGSEGV, SEGV_ACCERR, from the VMA), the page stays
//! referenced, fork shares it, munmap and exit free it, and a later
//! mprotect restores access with the data intact.

use core::sync::atomic::{AtomicU64, Ordering};

use super::huge_page::{HUGE_PAGE_SIZE, split_huge_pmd};
use super::{Mm, PAGE_SIZE, PROT_EXEC, PROT_READ, PROT_WRITE};
use crate::FRAME_ALLOCATOR;
use crate::arch::{CurrentArch, SchedArch, paging};
use crate::error::KernelError;

type ArchPageTable = <CurrentArch as SchedArch>::SchedPageTable;

const GB: u64 = 1 << 30;

/// The page table entry at `p`, as an atomic
fn entry(p: *mut u64) -> &'static AtomicU64 {
    // SAFETY: `p` points into a live page table of the locked mm
    unsafe { AtomicU64::from_ptr(p) }
}

/// The first address of the next 1GB (no 2MB-level table for `addr`)
fn next_gb(addr: u64) -> u64 {
    (addr | (GB - 1)) + 1
}

/// `prot` grants no access at all
fn prot_none(prot: u32) -> bool {
    prot & (PROT_READ | PROT_WRITE | PROT_EXEC) == 0
}

/// Split the 2MB pages of [start, end) that cannot keep a single entry
/// with protection `prot`: partly inside the range, or made
/// inaccessible (hk has no protnone 2MB entries). Called before any VMA
/// changes, mm lock held: ENOMEM leaves the mapping as it was (a split
/// page maps the same memory).
pub fn split_huge(mm: &Mm, start: u64, end: u64, prot: u32) -> Result<(), KernelError> {
    let mut addr = start & !(HUGE_PAGE_SIZE - 1);
    while addr < end {
        let Some(pmd) = paging::pmd_ptr(mm.pgd(), addr) else {
            addr = next_gb(addr);
            continue;
        };
        let whole = addr >= start && addr + HUGE_PAGE_SIZE <= end;
        if paging::pmd_huge(entry(pmd).load(Ordering::Acquire)) && (!whole || prot_none(prot)) {
            split_huge_pmd(mm, addr).ok_or(KernelError::OutOfMemory)?;
        }
        addr += HUGE_PAGE_SIZE;
    }
    Ok(())
}

/// Give the mapped pages of [start, end), part of one VMA, the
/// protection `prot` (Linux change_protection), mm lock held, after
/// `split_huge`: a 2MB page left whole is changed in place, every
/// mapped 4KB entry rewritten. The caller flushes the TLB of the range.
pub fn change_protection(pgd: u64, start: u64, end: u64, prot: u32, shared: bool) {
    let mut addr = start;
    while addr < end {
        let Some(pmd) = paging::pmd_ptr(pgd, addr) else {
            addr = next_gb(addr).min(end);
            continue;
        };
        let next = ((addr | (HUGE_PAGE_SIZE - 1)) + 1).min(end);
        let pmdval = entry(pmd).load(Ordering::Acquire);
        if paging::pmd_huge(pmdval) {
            // Wholly inside and accessible (`split_huge`); never shared
            let base = addr & !(HUGE_PAGE_SIZE - 1);
            let (w, x) = (prot & PROT_WRITE != 0, prot & PROT_EXEC != 0);
            if x && !paging::pte_exec(pmdval) {
                sync_huge(paging::pte_addr(pmdval) & !(HUGE_PAGE_SIZE - 1));
            }
            ArchPageTable::update_huge_page_protection(pgd, base, w, x);
        } else if pmdval != 0 {
            for a in (addr..next).step_by(PAGE_SIZE as usize) {
                change_pte(pgd, a, prot, shared);
            }
        }
        addr = next;
    }
}

/// A 2MB page at `phys` becomes executable: instruction caches see its
/// data (each 4KB cleaned, the instruction caches invalidated once)
fn sync_huge(phys: u64) {
    let pages = HUGE_PAGE_SIZE / PAGE_SIZE;
    for i in 0..pages {
        paging::sync_page(phys + i * PAGE_SIZE, i == pages - 1);
    }
}

/// Rewrite the entry of the page at `addr` for `prot` if it maps one. A
/// private page becomes writable only if no one else maps it (Linux
/// can_change_pte_writable); one still shared is copied at its write
/// fault.
fn change_pte(pgd: u64, addr: u64, prot: u32, shared: bool) {
    let Some(p) = paging::pte_ptr(pgd, addr) else {
        return;
    };
    let pte = entry(p);
    let old = pte.load(Ordering::Acquire);
    if !paging::pte_present(old) {
        return; // none, or a swap entry: the fault uses the VMA's prot
    }
    if prot & PROT_EXEC != 0 && !paging::pte_exec(old) {
        // Becomes executable: instruction caches see its data
        paging::sync_page(paging::pte_addr(old), true);
    }
    // Every other writer holds the mm lock: only a hardware
    // accessed/dirty update races, and each sets its bit once, so the
    // update ends after a few attempts
    let write = shared || FRAME_ALLOCATOR.refcount(paging::pte_addr(old)) <= 1;
    // Write implies read (x86, arm64): a page left read-only keeps it
    let prot = if write || prot & PROT_WRITE == 0 {
        prot
    } else {
        (prot & !PROT_WRITE) | PROT_READ
    };
    let mut cur = old;
    loop {
        if !paging::pte_present(cur) {
            return;
        }
        let new = paging::pte_modify(cur, prot);
        match pte.compare_exchange(cur, new, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return,
            Err(now) => cur = now,
        }
    }
}

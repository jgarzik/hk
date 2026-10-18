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
use super::pagewalk::{PteWalk, walk_pte_range};
use super::{Mm, PROT_EXEC, PROT_READ, PROT_WRITE};
use crate::FRAME_ALLOCATOR;
use crate::arch::{CurrentArch, SchedArch, paging};
use crate::error::KernelError;

type ArchPageTable = <CurrentArch as SchedArch>::SchedPageTable;

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
    struct Split<'a>(&'a Mm, u32);
    impl PteWalk for Split<'_> {
        type Err = KernelError;
        const PTES: bool = false;
        fn huge(&mut self, _: &AtomicU64, addr: u64, end: u64) -> Result<bool, KernelError> {
            let base = addr & !(HUGE_PAGE_SIZE - 1);
            if addr != base || end != base + HUGE_PAGE_SIZE || prot_none(self.1) {
                split_huge_pmd(self.0, addr).ok_or(KernelError::OutOfMemory)?;
            }
            Ok(true)
        }
    }
    walk_pte_range(mm.pgd(), start, end, &mut Split(mm, prot))
}

/// Give the mapped pages of [start, end), part of one VMA, the
/// protection `prot` (Linux change_protection), mm lock held, after
/// `split_huge`: a 2MB page left whole is changed in place, every
/// mapped 4KB entry rewritten under its table's PTE lock. The caller
/// flushes the TLB of the range.
pub fn change_protection(pgd: u64, start: u64, end: u64, prot: u32, shared: bool) {
    struct Change {
        pgd: u64,
        prot: u32,
        shared: bool,
    }
    impl PteWalk for Change {
        type Err = core::convert::Infallible;
        fn huge(&mut self, pmd: &AtomicU64, addr: u64, _: u64) -> Result<bool, Self::Err> {
            // Wholly inside and accessible (`split_huge`); never shared
            let pmdval = pmd.load(Ordering::Acquire);
            let base = addr & !(HUGE_PAGE_SIZE - 1);
            let (w, x) = (self.prot & PROT_WRITE != 0, self.prot & PROT_EXEC != 0);
            if x && !paging::pte_exec(pmdval) {
                sync_huge(paging::pte_addr(pmdval) & !(HUGE_PAGE_SIZE - 1));
            }
            ArchPageTable::update_huge_page_protection(self.pgd, base, w, x);
            Ok(true)
        }
        fn pte(&mut self, e: &AtomicU64, _: u64) -> Result<(), Self::Err> {
            change_pte(e, self.prot, self.shared);
            Ok(())
        }
    }
    let _ = walk_pte_range(pgd, start, end, &mut Change { pgd, prot, shared });
}

/// A 2MB page at `phys` becomes executable: instruction caches see its
/// data (all 2MB cleaned to the point of unification, the instruction
/// caches invalidated once)
pub(super) fn sync_huge(phys: u64) {
    paging::sync_icache(phys, HUGE_PAGE_SIZE as usize);
}

/// Rewrite the entry `pte` for `prot` if it maps a page, its PTE lock
/// held. A
/// private page becomes writable only if no one else maps it (Linux
/// can_change_pte_writable); one still shared is copied at its write
/// fault.
fn change_pte(pte: &AtomicU64, prot: u32, shared: bool) {
    let old = pte.load(Ordering::Acquire);
    if !paging::pte_present(old) {
        return; // none, or a swap entry: the fault uses the VMA's prot
    }
    if prot & PROT_EXEC != 0 && !paging::pte_exec(old) {
        // Becomes executable: instruction caches see its data
        paging::sync_page(paging::pte_addr(old), true);
    }
    let write = shared || FRAME_ALLOCATOR.refcount(paging::pte_addr(old)) <= 1;
    // Write implies read (x86, arm64): a page left read-only keeps it
    let prot = if write || prot & PROT_WRITE == 0 {
        prot
    } else {
        (prot & !PROT_WRITE) | PROT_READ
    };
    // Under the PTE lock only the MMU changes the entry (accessed /
    // dirty bits, each set once): the update ends after a few attempts
    let mut cur = old;
    while let Err(now) = pte.compare_exchange(
        cur,
        paging::pte_modify(cur, prot),
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        cur = now;
    }
}

//! Moving page table entries for mremap (Linux mm/mremap.c
//! move_page_tables)
//!
//! A move never loses a page: what it needs is allocated first
//! (`move_prep`: the old range's 2MB pages split, the new range's page
//! tables allocated) before any entry or VMA changes, so running out of
//! memory fails the mremap with ENOMEM and leaves the old mapping as it
//! was. `move_ptes` then cannot fail: each entry (a page or a swap
//! entry) is taken from its old address and stored at the new one with
//! its frame reference, under both tables' PTE locks, and the old
//! range's TLB flushed. All under the mm lock.

use core::sync::atomic::{AtomicU64, Ordering};

use super::huge_page::split_huge_pmd;
use super::pagewalk::{PteRange, PteWalk, entry, walk_pte_range};
use super::ptl::{self, PteLock};
use super::{Mm, PAGE_SIZE, tlb};
use crate::FRAME_ALLOCATOR;
use crate::arch::paging;
use crate::error::KernelError;

/// The 4KB entry for `addr` holds something (a page or a swap entry)
fn mapped(pgd: u64, addr: u64) -> bool {
    paging::pte_ptr(pgd, addr).is_some_and(|p| entry(p).load(Ordering::Acquire) != 0)
}

/// Allocate what moving [old, old + len) to `new` needs (Linux
/// move_page_tables allocates each table before moving into it): the
/// old range's 2MB pages are split, and each new address whose old one
/// maps something gets its page table through `alloc` (normally
/// `paging::pte_alloc`). Nothing moves: an error (ENOMEM) leaves both
/// ranges as they were.
pub fn move_prep(
    mm: &Mm,
    old: u64,
    new: u64,
    len: u64,
    alloc: &mut dyn FnMut(u64) -> Option<*mut u64>,
) -> Result<(), KernelError> {
    struct Prep<'a> {
        mm: &'a Mm,
        delta: u64,
        alloc: &'a mut dyn FnMut(u64) -> Option<*mut u64>,
    }
    impl PteWalk for Prep<'_> {
        type Err = KernelError;
        fn huge(&mut self, _: &AtomicU64, addr: u64, _: u64) -> Result<bool, KernelError> {
            split_huge_pmd(self.mm, addr).ok_or(KernelError::OutOfMemory)?;
            Ok(false)
        }
        /// Tables are allocated under the old table's PTE lock (the
        /// allocator nests inside it); nothing is written there
        fn pte(&mut self, e: &AtomicU64, addr: u64) -> Result<(), KernelError> {
            if e.load(Ordering::Acquire) != 0
                && (self.alloc)(addr.wrapping_add(self.delta)).is_none()
            {
                return Err(KernelError::OutOfMemory);
            }
            Ok(())
        }
    }
    let delta = new.wrapping_sub(old);
    walk_pte_range(mm.pgd(), old, old + len, &mut Prep { mm, delta, alloc })
}

/// Move the entries of [old, old + len) to `new` after `move_prep`
/// (same mm lock hold): the new range is unmapped, its tables exist,
/// the old range has no 2MB page. Each entry moves under both tables'
/// PTE locks (Linux move_ptes: old, then new nested; only mremap, under
/// the mmap_lock held for writing, nests two PTE locks of one mm). The
/// old range's TLB is flushed.
pub fn move_ptes(mm: &Mm, old: u64, new: u64, len: u64) {
    let pgd = mm.pgd();
    let mut m = Move {
        pgd,
        delta: new.wrapping_sub(old),
    };
    let _ = walk_pte_range(pgd, old, old + len, &mut m);
    tlb::flush_tlb_mm_range(mm, old, old + len, tlb::PAGE_SHIFT, false);
}

/// `move_ptes`'s walk
struct Move {
    pgd: u64,
    delta: u64,
}

impl PteWalk for Move {
    type Err = core::convert::Infallible;

    /// The old table is locked by the walk; the destination entries of
    /// one old table lie in at most two new tables, each locked while
    /// its entries move (not again if it is the old table itself)
    fn ptes(&mut self, r: &PteRange) -> Result<(), Self::Err> {
        let mut held: Option<(u64, Option<PteLock>)> = None;
        for (a, src) in r.iter() {
            if src.load(Ordering::Acquire) == 0 {
                continue;
            }
            // Allocated by `move_prep`: nothing frees tables meanwhile
            let Some(dp) = paging::pte_ptr(self.pgd, a.wrapping_add(self.delta)) else {
                continue;
            };
            let d = crate::arch::virt_to_phys(dp as u64 & !0xfff);
            if held.as_ref().map(|h| h.0) != Some(d) {
                drop(held.take());
                held = Some((d, (d != r.table()).then(|| ptl::table_lock(d))));
            }
            let dst = entry(dp);
            debug_assert_eq!(dst.load(Ordering::Acquire), 0);
            dst.store(src.swap(0, Ordering::AcqRel), Ordering::Release);
        }
        Ok(())
    }
}

/// Boot self-test (kselftest) of the allocation-first move, on a
/// scratch address space never loaded on a CPU: moving four pages fails
/// with ENOMEM when the Nth page-table allocation fails (each N), and
/// every old entry, frame reference and byte is then as it was; with
/// memory, the entries move whole. None if right, else what failed.
pub fn selftest() -> Option<&'static str> {
    use crate::arch::phys_to_virt;
    const OLD: u64 = 0x4000_0000;
    // Another top-level entry: three table levels to allocate
    const NEW: u64 = 0x80_0000_1000;
    const N: u64 = 4;
    let root = FRAME_ALLOCATOR.alloc()?;
    // SAFETY: a fresh frame, reached through the direct map
    unsafe { core::ptr::write_bytes(phys_to_virt(root), 0, PAGE_SIZE as usize) };
    // Owns `root`: dropping it frees the tables and pages left
    let mm = super::mm_alloc(root);
    let mut ptes = [0u64; N as usize];
    let mut r = None;
    for (i, pte) in ptes.iter_mut().enumerate() {
        let Some(frame) = FRAME_ALLOCATOR.alloc() else {
            r = Some("mremap_selftest_alloc");
            break;
        };
        let Some(p) = paging::pte_alloc(root, OLD + i as u64 * PAGE_SIZE) else {
            FRAME_ALLOCATOR.free(frame);
            r = Some("mremap_selftest_alloc");
            break;
        };
        // SAFETY: a fresh frame, reached through the direct map
        unsafe { *(phys_to_virt(frame) as *mut u64) = 0xa5a5_0000 + i as u64 };
        *pte = paging::mk_pte(frame, super::PROT_READ | super::PROT_WRITE);
        entry(p).store(*pte, Ordering::Release);
    }
    let len = N * PAGE_SIZE;
    for fail in 0..N {
        if r.is_some() {
            break;
        }
        let mut n = 0;
        let mut alloc = |va| {
            n += 1;
            if n > fail {
                None
            } else {
                paging::pte_alloc(root, va)
            }
        };
        if move_prep(&mm, OLD, NEW, len, &mut alloc).is_ok() || !holds(root, OLD, NEW, &ptes) {
            r = Some("mremap_enomem_intact");
        }
    }
    if r.is_none() {
        let mut alloc = |va| paging::pte_alloc(root, va);
        if move_prep(&mm, OLD, NEW, len, &mut alloc).is_err() {
            r = Some("mremap_prep");
        } else {
            move_ptes(&mm, OLD, NEW, len);
            if !holds(root, NEW, OLD, &ptes) {
                r = Some("mremap_moved");
            }
        }
    }
    drop(mm);
    r
}

/// The selftest's pages are mapped at `at` (entries `ptes`, one frame
/// reference each, data intact) and nothing at `empty`
fn holds(root: u64, at: u64, empty: u64, ptes: &[u64]) -> bool {
    use crate::arch::phys_to_virt;
    ptes.iter().enumerate().all(|(i, &pte)| {
        let off = i as u64 * PAGE_SIZE;
        let frame = paging::pte_addr(pte);
        // SAFETY: the selftest's own frame, reached through the direct map
        let data = unsafe { *(phys_to_virt(frame) as *const u64) };
        paging::pte_ptr(root, at + off).is_some_and(|p| entry(p).load(Ordering::Acquire) == pte)
            && !mapped(root, empty + off)
            && FRAME_ALLOCATOR.refcount(frame) == 1
            && data == 0xa5a5_0000 + i as u64
    })
}

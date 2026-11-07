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
use super::pagewalk::{PteRange, PteWalk, walk_pte_range};
use super::pgtable::{PgTables, Pmd, PteTable};
use super::{Mm, PAGE_SIZE, tlb};
use crate::FRAME_ALLOCATOR;
use crate::arch::paging;
use crate::util::error::KernelError;

/// The 4KB entry for `addr` holds something (a page or a swap entry)
fn mapped(t: PgTables<'_>, addr: u64) -> bool {
    t.pte(addr).is_some_and(|p| p.get() != 0)
}

/// Allocate what moving [old, old + len) of `mm` (tables `t`, borrowing
/// its mmap_lock) to `new` needs (Linux move_page_tables allocates each
/// table before moving into it): the old range's 2MB pages are split,
/// and each new address whose old one maps something gets its page
/// table through `alloc` (normally `PgTables::pte_alloc`), false if out
/// of memory. Nothing moves: an error (ENOMEM) leaves both ranges as
/// they were.
pub fn move_prep(
    mm: &Mm,
    t: PgTables<'_>,
    old: u64,
    new: u64,
    len: u64,
    alloc: &mut dyn FnMut(u64) -> bool,
) -> Result<(), KernelError> {
    struct Prep<'a> {
        mm: &'a Mm,
        delta: u64,
        alloc: &'a mut dyn FnMut(u64) -> bool,
    }
    impl PteWalk for Prep<'_> {
        type Err = KernelError;
        fn huge(&mut self, pmd: Pmd<'_>, _: u64, _: u64) -> Result<bool, KernelError> {
            split_huge_pmd(self.mm, pmd).ok_or(KernelError::OutOfMemory)?;
            Ok(false)
        }
        /// Entries are read without the old table's PTE lock, so the
        /// allocation may reclaim: with the mmap_lock held for writing
        /// no entry goes from empty to set meanwhile (reclaim only turns
        /// a present one into a swap entry); nothing is written there
        const LOCKED: bool = false;

        fn pte(&mut self, e: &AtomicU64, addr: u64) -> Result<(), KernelError> {
            if e.load(Ordering::Acquire) != 0 && !(self.alloc)(addr.wrapping_add(self.delta)) {
                return Err(KernelError::OutOfMemory);
            }
            Ok(())
        }
    }
    assert_eq!(mm.pgd(), t.pgd(), "tables of another mm");
    let delta = new.wrapping_sub(old);
    walk_pte_range(t.pgd(), old, old + len, &mut Prep { mm, delta, alloc })
}

/// Move the entries of [old, old + len) to `new` after `move_prep`
/// (same mm lock hold): the new range is unmapped, its tables exist,
/// the old range has no 2MB page. Each entry moves under both tables'
/// PTE locks (Linux move_ptes: old, then new nested; only mremap, under
/// the mmap_lock held for writing, nests two PTE locks of one mm). The
/// old range's TLB is flushed.
pub fn move_ptes(mm: &Mm, t: PgTables<'_>, old: u64, new: u64, len: u64) {
    assert_eq!(mm.pgd(), t.pgd(), "tables of another mm");
    let mut m = Move {
        t,
        delta: new.wrapping_sub(old),
    };
    let _ = walk_pte_range(t.pgd(), old, old + len, &mut m);
    tlb::flush_tlb_mm_range(mm, old, old + len, tlb::PAGE_SHIFT, false);
}

/// `move_ptes`'s walk
struct Move<'a> {
    t: PgTables<'a>,
    delta: u64,
}

impl PteWalk for Move<'_> {
    type Err = core::convert::Infallible;

    /// The old table is locked by the walk; the destination entries of
    /// one old table lie in at most two new tables, each locked while
    /// its entries move (not again if it is the old table itself)
    fn ptes(&mut self, r: &PteRange) -> Result<(), Self::Err> {
        let mut held: Option<PteTable<'_>> = None;
        for (a, src) in r.iter() {
            if src.load(Ordering::Acquire) == 0 {
                continue;
            }
            // Allocated by `move_prep`: nothing frees tables meanwhile
            let to = a.wrapping_add(self.delta);
            let Some(dp) = self.t.pte(to) else {
                continue;
            };
            let dst = if dp.table() == r.table() {
                drop(held.take());
                r.entry(to)
            } else {
                if held.as_ref().is_none_or(|h| h.table() != dp.table()) {
                    drop(held.take());
                    held = Some(dp.lock());
                }
                let Some(h) = held.as_ref() else {
                    continue;
                };
                h.entry(to)
            };
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
    let root = FRAME_ALLOCATOR.alloc()?;
    // SAFETY: a fresh frame, reached through the direct map
    unsafe { core::ptr::write_bytes(phys_to_virt(root), 0, PAGE_SIZE as usize) };
    // Owns `root`: dropping it frees the tables and pages left
    let mm = super::mm_alloc(root);
    let r = {
        let map = mm.mmap_write();
        selftest_in(&mm, PgTables::new(&mm, &map))
    };
    drop(mm);
    r
}

/// `selftest` on the tables `t` of `mm`
fn selftest_in(mm: &Mm, t: PgTables<'_>) -> Option<&'static str> {
    use crate::arch::phys_to_virt;
    const OLD: u64 = 0x4000_0000;
    // Another top-level entry: three table levels to allocate
    const NEW: u64 = 0x80_0000_1000;
    const N: u64 = 4;
    let mut ptes = [0u64; N as usize];
    let mut r = None;
    for (i, pte) in ptes.iter_mut().enumerate() {
        let Some(frame) = FRAME_ALLOCATOR.alloc() else {
            r = Some("mremap_selftest_alloc");
            break;
        };
        let va = OLD + i as u64 * PAGE_SIZE;
        let Some(p) = t.pte_alloc(mm, va) else {
            FRAME_ALLOCATOR.free(frame);
            r = Some("mremap_selftest_alloc");
            break;
        };
        // SAFETY: a fresh frame, reached through the direct map
        unsafe { *phys_to_virt(frame).cast::<u64>() = 0xa5a5_0000 + i as u64 };
        *pte = paging::mk_pte(frame, super::PROT_READ | super::PROT_WRITE);
        p.lock().store(va, *pte);
    }
    let len = N * PAGE_SIZE;
    for fail in 0..N {
        if r.is_some() {
            break;
        }
        let mut n = 0;
        let mut alloc = |va| {
            n += 1;
            n <= fail && t.pte_alloc(mm, va).is_some()
        };
        if move_prep(mm, t, OLD, NEW, len, &mut alloc).is_ok() || !holds(t, OLD, NEW, &ptes) {
            r = Some("mremap_enomem_intact");
        }
    }
    if r.is_none() {
        let mut alloc = |va| t.pte_alloc(mm, va).is_some();
        if move_prep(mm, t, OLD, NEW, len, &mut alloc).is_err() {
            r = Some("mremap_prep");
        } else {
            move_ptes(mm, t, OLD, NEW, len);
            if !holds(t, NEW, OLD, &ptes) {
                r = Some("mremap_moved");
            }
        }
    }
    r
}

/// The selftest's pages are mapped at `at` (entries `ptes`, one frame
/// reference each, data intact) and nothing at `empty`
fn holds(t: PgTables<'_>, at: u64, empty: u64, ptes: &[u64]) -> bool {
    use crate::arch::phys_to_virt;
    ptes.iter().enumerate().all(|(i, &pte)| {
        let off = i as u64 * PAGE_SIZE;
        let frame = paging::pte_addr(pte);
        // SAFETY: the selftest's own frame, reached through the direct map
        let data = unsafe { *(phys_to_virt(frame) as *const u64) };
        t.pte(at + off).is_some_and(|p| p.get() == pte)
            && !mapped(t, empty + off)
            && FRAME_ALLOCATOR.refcount(frame) == 1
            && data == 0xa5a5_0000 + i as u64
    })
}

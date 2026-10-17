//! Moving page table entries for mremap (Linux mm/mremap.c
//! move_page_tables)
//!
//! A move never loses a page: what it needs is allocated first
//! (`move_prep`: the old range's 2MB pages split, the new range's page
//! tables allocated) before any entry or VMA changes, so running out of
//! memory fails the mremap with ENOMEM and leaves the old mapping as it
//! was. `move_ptes` then cannot fail: each entry (a page or a swap
//! entry) is taken from its old address and stored at the new one with
//! its frame reference, and the old range's TLB flushed. All under the
//! mm lock.

use core::sync::atomic::{AtomicU64, Ordering};

use super::PAGE_SIZE;
use super::huge_page::HUGE_PAGE_SIZE;
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

/// The 4KB entry for `addr` holds something (a page or a swap entry)
fn mapped(pgd: u64, addr: u64) -> bool {
    paging::pte_ptr(pgd, addr).is_some_and(|p| entry(p).load(Ordering::Acquire) != 0)
}

/// The 4KB-page addresses of [start, end) that may be mapped, in order,
/// 2MB by 2MB: `f(chunk start, chunk end, 2MB entry)` for each 2MB
/// region with a table or page; regions with no 2MB-level table are
/// skipped 1GB at a time. Stops at the first error.
fn walk(
    pgd: u64,
    start: u64,
    end: u64,
    f: &mut dyn FnMut(u64, u64, &AtomicU64) -> Result<(), KernelError>,
) -> Result<(), KernelError> {
    let mut addr = start;
    while addr < end {
        let Some(pmd) = paging::pmd_ptr(pgd, addr) else {
            addr = ((addr | (GB - 1)) + 1).min(end);
            continue;
        };
        let next = ((addr | (HUGE_PAGE_SIZE - 1)) + 1).min(end);
        if entry(pmd).load(Ordering::Acquire) != 0 {
            f(addr, next, entry(pmd))?;
        }
        addr = next;
    }
    Ok(())
}

/// Allocate what moving [old, old + len) to `new` needs (Linux
/// move_page_tables allocates each table before moving into it): the
/// old range's 2MB pages are split, and each new address whose old one
/// maps something gets its page table through `alloc` (normally
/// `paging::pte_alloc`). Nothing moves: an error (ENOMEM) leaves both
/// ranges as they were.
pub fn move_prep(
    pgd: u64,
    old: u64,
    new: u64,
    len: u64,
    alloc: &mut dyn FnMut(u64) -> Option<*mut u64>,
) -> Result<(), KernelError> {
    walk(pgd, old, old + len, &mut |start, end, pmd| {
        if paging::pmd_huge(pmd.load(Ordering::Acquire)) {
            let base = start & !(HUGE_PAGE_SIZE - 1);
            ArchPageTable::split_huge_page(pgd, base, &mut &FRAME_ALLOCATOR)
                .map_err(|_| KernelError::OutOfMemory)?;
        }
        for a in (start..end).step_by(PAGE_SIZE as usize) {
            if mapped(pgd, a) && alloc(new + (a - old)).is_none() {
                return Err(KernelError::OutOfMemory);
            }
        }
        Ok(())
    })
}

/// Move the entries of [old, old + len) to `new` after `move_prep`
/// (same mm lock hold): the new range is unmapped, its tables exist,
/// the old range has no 2MB page. The old range's TLB is flushed.
pub fn move_ptes(pgd: u64, old: u64, new: u64, len: u64) {
    let _ = walk(pgd, old, old + len, &mut |start, end, _| {
        for a in (start..end).step_by(PAGE_SIZE as usize) {
            let Some(src) = paging::pte_ptr(pgd, a) else {
                continue;
            };
            if entry(src).load(Ordering::Acquire) == 0 {
                continue;
            }
            // Allocated by `move_prep`: nothing frees tables meanwhile
            let Some(dst) = paging::pte_ptr(pgd, new + (a - old)) else {
                continue;
            };
            debug_assert_eq!(entry(dst).load(Ordering::Acquire), 0);
            entry(dst).store(entry(src).swap(0, Ordering::AcqRel), Ordering::Release);
        }
        Ok(())
    });
    paging::flush_tlb_range(old, old + len);
}

/// Boot self-test (kselftest) of the allocation-first move, on a
/// scratch page table never loaded on a CPU: moving four pages fails
/// with ENOMEM when the Nth page-table allocation fails (each N), and
/// every old entry, frame reference and byte is then as it was; with
/// memory, the entries move whole. None if right, else what failed.
pub fn selftest() -> Option<&'static str> {
    use crate::arch::{Leaf, phys_to_virt};
    const OLD: u64 = 0x4000_0000;
    // Another top-level entry: three table levels to allocate
    const NEW: u64 = 0x80_0000_1000;
    const N: u64 = 4;
    let root = FRAME_ALLOCATOR.alloc()?;
    // SAFETY: a fresh frame, reached through the direct map
    unsafe { core::ptr::write_bytes(phys_to_virt(root), 0, PAGE_SIZE as usize) };
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
        if move_prep(root, OLD, NEW, len, &mut alloc).is_ok() || !holds(root, OLD, NEW, &ptes) {
            r = Some("mremap_enomem_intact");
        }
    }
    if r.is_none() {
        let mut alloc = |va| paging::pte_alloc(root, va);
        if move_prep(root, OLD, NEW, len, &mut alloc).is_err() {
            r = Some("mremap_prep");
        } else {
            move_ptes(root, OLD, NEW, len);
            if !holds(root, NEW, OLD, &ptes) {
                r = Some("mremap_moved");
            }
        }
    }
    paging::free_user(root, &mut |leaf| {
        if let Leaf::Page(p) = leaf {
            FRAME_ALLOCATOR.free(p);
        }
    });
    FRAME_ALLOCATOR.free(root);
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

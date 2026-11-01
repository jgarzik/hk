//! Page-table locks (Linux mm->page_table_lock and split PTE locks,
//! include/linux/mm.h pte_lockptr)
//!
//! With the mmap_lock held for reading, several tasks may change one
//! address space's page tables at once (faults, MADV_DONTNEED, a
//! remote write). Two spin locks order them:
//!
//! - `Mm.page_table_lock` ([`pt_lock`]): the table structure -- a missing
//!   table installed ([`pte_alloc`]), a 2MB entry mapped, split or
//!   cleared (Linux pmd_lock without split PMD locks).
//! - the PTE lock ([`pte_lock`], [`table_lock`]) of each PTE table
//!   page, a lock word in its struct page (`Page.ptl`, Linux ptdesc
//!   ptl): every software change of a 4KB entry, whatever the mmap_lock
//!   mode, from reading the entry to the last change that depends on it
//!   (break-before-make included). Range operations take it once per
//!   table (`pagewalk::walk_pte_range`).
//!
//! Under the PTE lock the MMU still sets accessed/dirty bits, so
//! entries change by compare-and-swap, retried only for those bits.
//! Only fork (parent, then child) and mremap (old table, then new)
//! nest two PTE locks, under the mmap_lock held for writing. Tables are freed only with the mmap_lock held for
//! writing (munmap, mremap: `memory::free_pgtables`), after their
//! VMAs left the reverse-map chains, so a pointer to an entry stays
//! valid under any mmap_lock hold, or the AnonVma lock of a VMA there.
//!
//! Order: mmap_lock -> page_table_lock -> PTE lock -> allocator, never
//! the reverse. Both are spin locks with preemption off: an allocation
//! under them never reclaims (reclaim walks the reverse map, which
//! takes PTE locks), so it may fail where one without them would
//! not -- allocate first where that matters (fork and mremap allocate
//! the destination tables before taking the source's PTE lock, a
//! copy-on-write break its page: `PteWalk::prepare`, `do_wp_page`); no
//! lock is taken in interrupt context. A holder may flush the TLB
//! (x86: IPIs): waiters spin with interrupts on (syscalls and faults
//! run with them on) and answer the IPI, as in Linux.

use core::sync::atomic::{AtomicU32, Ordering};

use super::Mm;
use super::page::{Page, phys_to_page};
use crate::arch::{paging, virt_to_phys};

/// The PTE lock of a page-table page, held until dropped
pub struct PteLock {
    word: &'static AtomicU32,
}

/// Lockdep class shared by every PTE lock (one source location, like
/// Linux's single ptlock class)
#[cfg(feature = "lockdep")]
fn class() -> &'static core::panic::Location<'static> {
    core::panic::Location::caller()
}

/// Lock the PTE table holding the entry at `ptep` (Linux
/// pte_offset_map_lock); the entry must lie in a live user table
#[track_caller]
pub fn pte_lock(ptep: *mut u64) -> PteLock {
    table_lock(virt_to_phys(ptep as u64 & !0xfff))
}

/// Lock the PTE table frame `table` (a live user table)
#[track_caller]
pub fn table_lock(table: u64) -> PteLock {
    let page: &'static Page = phys_to_page(table).expect("page table outside RAM");
    let word = &page.ptl;
    // A spin lock like Linux spin_lock: no preemption, and in_atomic()
    // for what runs under it, so an allocation there never enters
    // direct reclaim (whose reverse-map walk takes PTE locks: this one
    // too, a self-deadlock) and a sleep there is reported
    preempt_disable();
    #[cfg(feature = "lockdep")]
    crate::sync::lockdep::acquire(
        word as *const _ as usize,
        class(),
        core::panic::Location::caller(),
        true,
    );
    while word
        .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        while word.load(Ordering::Relaxed) != 0 {
            core::hint::spin_loop();
        }
    }
    PteLock { word }
}

impl Drop for PteLock {
    fn drop(&mut self) {
        self.word.store(0, Ordering::Release);
        #[cfg(feature = "lockdep")]
        crate::sync::lockdep::release(self.word as *const _ as usize);
        preempt_enable();
    }
}

#[cfg(not(test))]
use crate::arch::{preempt_disable, preempt_enable};
#[cfg(test)]
fn preempt_disable() {}
#[cfg(test)]
fn preempt_enable() {}

/// `mm`'s page_table_lock (Linux mm->page_table_lock)
#[track_caller]
pub fn pt_lock(mm: &Mm) -> crate::sync::spin::MutexGuard<'_, ()> {
    mm.page_table_lock().lock()
}

/// The 4KB entry for `addr` in `mm`, installing missing tables under
/// the page_table_lock (Linux pte_alloc). None if out of memory or a
/// 2MB page maps `addr`.
pub fn pte_alloc(mm: &Mm, addr: u64) -> Option<*mut u64> {
    if let Some(p) = paging::pte_ptr(mm.pgd(), addr) {
        return Some(p);
    }
    let _l = pt_lock(mm);
    paging::pte_alloc(mm.pgd(), addr)
}

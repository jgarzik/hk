//! Walking a range of user page tables (Linux mm/pagewalk.c
//! walk_page_range)
//!
//! [`walk_pte_range`] descends the tables of [start, end) one level at a
//! time: a missing upper-level entry skips its whole span (512GB, 1GB),
//! a 2MB entry goes to [`PteWalk::huge`], and each PTE table is handed
//! to [`PteWalk::ptes`] once, its PTE lock held across all its entries
//! (Linux pte_offset_map_lock in walk_pte_range), never once per 4KB.
//!
//! Locking (`ptl`): the caller holds the mmap_lock (read or write) or
//! the AnonVma chain of a VMA in the range, so no table is freed
//! meanwhile. Every software write of a 4KB entry happens under its
//! table's PTE lock; a 2MB entry changes under the page_table_lock
//! (`huge_page`), so `huge` runs with no PTE lock held and may split;
//! a 2MB entry in the middle of a split (`PMD_SPLITTING`) is waited
//! out, never taken for an empty slot.
//! Under the PTE lock only the MMU still changes an entry (accessed and
//! dirty bits): a compare-and-swap that fails sees such an update, the
//! same page with more bits, and nothing else.

use core::sync::atomic::{AtomicU64, Ordering};

use super::PAGE_SIZE;
use crate::arch::paging;

/// The page table entry at `p`, as an atomic
pub(super) fn entry(p: *mut u64) -> &'static AtomicU64 {
    // SAFETY: `p` points into a live page table (see the module doc)
    unsafe { AtomicU64::from_ptr(p) }
}

/// Slot `i` of the table frame `table`
pub(super) fn table_slot(table: u64, i: u64) -> *mut u64 {
    // SAFETY: a live table frame, through the direct map
    unsafe { (crate::arch::phys_to_virt(table) as *mut u64).add(i as usize) }
}

/// The part of one PTE table a walk visits: the 4KB entries of
/// [start, end), all in the table frame `table`, its PTE lock held
pub struct PteRange {
    table: u64,
    /// First address
    pub start: u64,
    /// One past the last address (inside the same 2MB region)
    pub end: u64,
}

impl PteRange {
    /// The entries of [start, end) of the table holding the entry `ptep`
    /// (the caller holds its PTE lock)
    pub fn at(ptep: *mut u64, start: u64, end: u64) -> Self {
        Self {
            table: crate::arch::virt_to_phys(ptep as u64 & !0xfff),
            start,
            end,
        }
    }

    /// The table frame
    pub fn table(&self) -> u64 {
        self.table
    }

    /// The entry for `addr` (inside the range)
    pub fn entry(&self, addr: u64) -> &'static AtomicU64 {
        debug_assert!(self.start <= addr && addr < self.end);
        entry(table_slot(self.table, (addr >> 12) & 511))
    }

    /// (address, entry) for each 4KB page of the range
    pub fn iter(&self) -> impl Iterator<Item = (u64, &'static AtomicU64)> + '_ {
        (self.start..self.end)
            .step_by(PAGE_SIZE as usize)
            .map(|a| (a, self.entry(a)))
    }
}

/// What a walk does with the entries it finds
pub trait PteWalk {
    /// Error that stops the walk
    type Err;

    /// Whether to visit PTE tables (false: 2MB entries only)
    const PTES: bool = true;

    /// Whether `ptes` runs under the table's PTE lock (false: only for
    /// a walker that reads entries as hints, with the mmap_lock held
    /// for writing)
    const LOCKED: bool = true;

    /// Before a PTE table's lock is taken (no spin lock held): work
    /// that may sleep or reclaim, such as allocating the tables an
    /// update of [addr, end) will need
    fn prepare(&mut self, _addr: u64, _end: u64) -> Result<(), Self::Err> {
        Ok(())
    }

    /// A 2MB page maps [addr, end) (inside its 2MB region; no PTE lock
    /// held): true if done with the region, false to walk its PTE table
    /// if it has one now (it was split)
    fn huge(&mut self, _pmd: &AtomicU64, _addr: u64, _end: u64) -> Result<bool, Self::Err> {
        Ok(true)
    }

    /// The entries of one PTE table, its PTE lock held: `pte` for each
    fn ptes(&mut self, r: &PteRange) -> Result<(), Self::Err> {
        for (addr, e) in r.iter() {
            self.pte(e, addr)?;
        }
        Ok(())
    }

    /// One 4KB entry (empty ones too), its table's PTE lock held
    fn pte(&mut self, _pte: &AtomicU64, _addr: u64) -> Result<(), Self::Err> {
        Ok(())
    }
}

/// Walk the user page tables rooted at `pgd` over [start, end) with `w`
/// (Linux walk_page_range); the first error stops it. Only user
/// addresses: a range past TASK_SIZE is a bug (clamped).
pub fn walk_pte_range<W: PteWalk>(pgd: u64, start: u64, end: u64, w: &mut W) -> Result<(), W::Err> {
    debug_assert!(
        start <= end && end <= super::TASK_SIZE,
        "walk {start:#x}..{end:#x}"
    );
    let end = end.min(super::TASK_SIZE);
    if start < end {
        walk_level(pgd, 3, start, end, w)?;
    }
    Ok(())
}

/// The entries of the table `table` at `level` (3: top, 1: the 2MB
/// level) for [start, end)
fn walk_level<W: PteWalk>(
    table: u64,
    level: u32,
    start: u64,
    end: u64,
    w: &mut W,
) -> Result<(), W::Err> {
    let shift = 12 + 9 * level;
    let mut addr = start;
    while addr < end {
        let next = ((addr | ((1u64 << shift) - 1)) + 1).min(end);
        let slot = entry(table_slot(table, (addr >> shift) & 511));
        if level == 1 {
            walk_pmd(slot, addr, next, w)?;
        } else if let Some(child) = paging::table_of(slot.load(Ordering::Acquire)) {
            walk_level(child, level - 1, addr, next, w)?;
        }
        addr = next;
    }
    Ok(())
}

/// One 2MB-level entry for [addr, end): its 2MB page, then its PTE
/// table under the table's PTE lock
fn walk_pmd<W: PteWalk>(pmd: &AtomicU64, addr: u64, end: u64, w: &mut W) -> Result<(), W::Err> {
    // A split under way is waited out: its slot is about to hold a PTE
    // table (huge_page::PMD_SPLITTING)
    if paging::pmd_huge(super::huge_page::pmd_settled(pmd)) && w.huge(pmd, addr, end)? {
        return Ok(());
    }
    if !W::PTES {
        return Ok(());
    }
    let Some(table) = paging::table_of(super::huge_page::pmd_settled(pmd)) else {
        return Ok(());
    };
    w.prepare(addr, end)?;
    let _l = W::LOCKED.then(|| super::ptl::table_lock(table));
    w.ptes(&PteRange {
        table,
        start: addr,
        end,
    })
}

/// Boot self-test (kselftest) on a scratch address space never loaded
/// on a CPU: entries in two PTE tables 1GB apart are visited in order,
/// each table once, empty spans skipped. None if right, else what
/// failed.
pub fn selftest() -> Option<&'static str> {
    use crate::FRAME_ALLOCATOR;
    use crate::arch::phys_to_virt;
    const A: u64 = 0x4000_0000 - 2 * PAGE_SIZE; // last two pages of a 1GB
    const B: u64 = 0x8000_0000 + 0x20_0000; // 1GB later, second 2MB
    let root = FRAME_ALLOCATOR.alloc()?;
    // SAFETY: a fresh frame, reached through the direct map
    unsafe { core::ptr::write_bytes(phys_to_virt(root), 0, PAGE_SIZE as usize) };
    // Owns `root`: dropping it frees the tables
    let mm = super::mm_alloc(root);
    let addrs = [A, A + PAGE_SIZE, B, B + 5 * PAGE_SIZE];
    for (i, &a) in addrs.iter().enumerate() {
        let Some(p) = paging::pte_alloc(root, a) else {
            return Some("pagewalk_alloc");
        };
        // Swap-like values: no frame behind them, nothing to free
        entry(p).store((i as u64 + 1) << 12, Ordering::Release);
    }
    struct Seen {
        tables: u32,
        found: [u64; 4],
        n: usize,
    }
    impl PteWalk for Seen {
        type Err = ();
        fn ptes(&mut self, r: &PteRange) -> Result<(), ()> {
            self.tables += 1;
            for (a, e) in r.iter() {
                if e.load(Ordering::Acquire) != 0 {
                    *self.found.get_mut(self.n).ok_or(())? = a;
                    self.n += 1;
                }
            }
            Ok(())
        }
    }
    let mut s = Seen {
        tables: 0,
        found: [0; 4],
        n: 0,
    };
    let ok = walk_pte_range(root, PAGE_SIZE, 0x1_0000_0000, &mut s).is_ok()
        && s.tables == 2
        && s.n == 4
        && s.found == addrs;
    // A walk inside one table, starting mid-table, sees only its part
    let mut t = Seen {
        tables: 0,
        found: [0; 4],
        n: 0,
    };
    let part = walk_pte_range(root, B + PAGE_SIZE, B + 6 * PAGE_SIZE, &mut t).is_ok()
        && t.tables == 1
        && t.n == 1
        && t.found[0] == B + 5 * PAGE_SIZE;
    for &a in &addrs {
        if let Some(p) = paging::pte_ptr(root, a) {
            entry(p).store(0, Ordering::Release);
        }
    }
    drop(mm);
    match (ok, part) {
        (true, true) => None,
        (false, _) => Some("pagewalk_tables"),
        (_, false) => Some("pagewalk_part"),
    }
}

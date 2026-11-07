//! Typed access to user page tables (Linux pte_offset_map,
//! pte_offset_map_lock)
//!
//! A page table can be freed while its address space lives (munmap,
//! mremap: `memory::free_pgtables`), so a reference to one of its
//! entries is valid only while something keeps the table: the
//! mmap_lock in either mode, or the reverse-map chain lock
//! (`AnonVma.chain`, a file's `i_mmap`) of a VMA the entry lies in
//! (doc/LOCKING.md, Page-table locks). The types here turn that rule
//! into borrows, as Rust-for-Linux ties a `VmaRef` to its
//! `MmapReadGuard`: a handle cannot outlive the lock it came from.
//!
//! - [`PgTables`]: the tables of one address space, pinned for `'a`.
//!   Made from a borrow of the address space's `MmStruct`, which only
//!   an mmap_lock guard hands out ([`PgTables::new`]), or from a held
//!   reverse-map chain (`anon_vma::ChainRead::entries`, limited to its
//!   VMA's range). Freeing tables takes `&mut MmStruct`
//!   (`memory::free_pgtables`), which the borrow checker refuses while
//!   a `PgTables` of the address space lives.
//! - [`Pte`]: one 4KB entry of pinned tables, read-only: a value read
//!   without the PTE lock is a hint.
//! - [`PteTable`]: a PTE table with its PTE lock held, the only handle
//!   that writes 4KB entries (outside the range walker, `pagewalk`).
//!
//! Each is a pointer-sized copy of what the open-coded `*mut u64` was;
//! the walk itself stays in `arch::paging`.

use core::marker::PhantomData;
use core::sync::atomic::{AtomicU64, Ordering};

use super::ptl::{PteLock, table_lock};
use super::{Mm, MmStruct};
use crate::arch::{paging, phys_to_virt, virt_to_phys};

/// The page tables of one address space, pinned for `'a`
///
/// # Invariants
///
/// During `'a`, `pgd` is a live top-level table and no table under it
/// that maps an address of [lo, hi) is freed.
#[derive(Clone, Copy)]
pub struct PgTables<'a> {
    pgd: u64,
    lo: u64,
    hi: u64,
    _pin: PhantomData<&'a ()>,
}

impl<'a> PgTables<'a> {
    /// The tables of `mm`, pinned by `map`, a borrow of its VMA tree:
    /// only an mmap_lock guard (or exclusive ownership of the `Mm`)
    /// hands one out
    #[inline]
    pub fn new(mm: &'a Mm, map: &'a MmStruct) -> Self {
        assert!(mm.holds(map), "page tables pinned by another mm's VMAs");
        // INVARIANT: tables are freed only through `&mut MmStruct` of
        // `mm` (`free_pgtables`, `exit_mmap`), impossible while `map`
        // is borrowed for 'a; `pgd` goes with `mm`, borrowed for 'a
        Self {
            pgd: mm.pgd(),
            lo: 0,
            hi: super::TASK_SIZE,
            _pin: PhantomData,
        }
    }

    /// The tables under `pgd` that map [lo, hi), pinned by the caller
    ///
    /// # Safety
    ///
    /// For `'a`, `pgd` stays a live top-level table and no table under
    /// it that maps an address of [lo, hi) is freed.
    #[inline]
    pub(super) unsafe fn from_raw(pgd: u64, lo: u64, hi: u64) -> Self {
        // INVARIANT: the caller's guarantee
        Self {
            pgd,
            lo,
            hi: hi.min(super::TASK_SIZE),
            _pin: PhantomData,
        }
    }

    /// The top-level table
    #[inline]
    pub fn pgd(&self) -> u64 {
        self.pgd
    }

    /// `addr` lies in the pinned range
    #[inline]
    fn covers(&self, addr: u64) -> bool {
        self.lo <= addr && addr < self.hi
    }

    /// The 4KB entry for `addr` (Linux pte_offset_map), present or not;
    /// None outside the pinned range, if a table is missing, or if a
    /// 2MB page maps `addr`
    #[inline]
    pub fn pte(&self, addr: u64) -> Option<Pte<'a>> {
        if !self.covers(addr) {
            return None;
        }
        let p = paging::pte_ptr(self.pgd, addr)?;
        // SAFETY: `p` is the entry of `addr` in a table under `pgd`,
        // through the direct map, which stays for 'a (type invariant);
        // page-table entries are only accessed atomically
        let slot = unsafe { AtomicU64::from_ptr(p) };
        // INVARIANT: that entry, in a table kept for 'a
        Some(Pte { slot, addr })
    }

    /// `pte`, installing missing tables under `mm`'s page_table_lock
    /// (Linux pte_alloc); `mm` is the owner of the tables. None outside
    /// the pinned range, out of memory, or if a 2MB page maps `addr`.
    #[track_caller]
    pub fn pte_alloc(&self, mm: &Mm, addr: u64) -> Option<Pte<'a>> {
        assert_eq!(mm.pgd(), self.pgd, "page_table_lock of another mm");
        if let Some(p) = self.pte(addr) {
            return Some(p);
        }
        if !self.covers(addr) {
            return None;
        }
        let _l = super::ptl::pt_lock(mm);
        let p = paging::pte_alloc(self.pgd, addr)?;
        // SAFETY: as in `pte`: the entry of `addr`, under `pgd`
        let slot = unsafe { AtomicU64::from_ptr(p) };
        // INVARIANT: as in `pte`
        Some(Pte { slot, addr })
    }
}

/// One 4KB entry of pinned page tables (Linux the `pte_t *` of
/// pte_offset_map): read without a lock, changed only through its
/// table's [`PteTable`]
///
/// # Invariants
///
/// `slot` is the entry for `addr` in a PTE table that stays for `'a`.
#[derive(Clone, Copy)]
pub struct Pte<'a> {
    slot: &'a AtomicU64,
    addr: u64,
}

impl<'a> Pte<'a> {
    /// The entry's value (Linux ptep_get): without the PTE lock, a hint
    /// the lock holder checks again
    #[inline]
    pub fn get(&self) -> u64 {
        self.slot.load(Ordering::Acquire)
    }

    /// The address it maps
    #[inline]
    pub fn addr(&self) -> u64 {
        self.addr
    }

    /// The frame of its PTE table
    #[inline]
    pub fn table(&self) -> u64 {
        virt_to_phys(core::ptr::from_ref(self.slot).addr() as u64 & !0xfff)
    }

    /// Its PTE table, locked (Linux pte_offset_map_lock)
    #[track_caller]
    #[inline]
    pub fn lock(&self) -> PteTable<'a> {
        let table = self.table();
        // INVARIANT: the table holding `slot`, kept for 'a (type
        // invariant), and its PTE lock
        PteTable {
            table,
            _lock: table_lock(table),
            _pin: PhantomData,
        }
    }
}

/// A PTE table of pinned page tables with its PTE lock held (Linux
/// pte_offset_map_lock's table and ptl): its 4KB entries may be
/// changed, by compare-and-swap where the MMU may set accessed/dirty
/// bits meanwhile. The entries it lends end with it, and so does the
/// lock. Forgetting it leaves the lock held (a deadlock, never a freed
/// table: the table is kept by `'a`, not by this guard).
///
/// # Invariants
///
/// `table` is a PTE table frame that stays for `'a`, and `_lock` holds
/// its PTE lock.
#[must_use]
pub struct PteTable<'a> {
    table: u64,
    _lock: PteLock,
    _pin: PhantomData<&'a ()>,
}

impl PteTable<'_> {
    /// The table frame
    #[inline]
    pub fn table(&self) -> u64 {
        self.table
    }

    /// The entry for `addr`, whose 2MB region this table maps
    #[inline]
    pub fn entry(&self, addr: u64) -> &AtomicU64 {
        let i = ((addr >> 12) & 511) as usize;
        // SAFETY: a live table frame (type invariant) through the direct
        // map, `i` < 512 entries; borrowed no longer than `self`
        unsafe { AtomicU64::from_ptr(phys_to_virt(self.table).cast::<u64>().add(i)) }
    }

    /// The entry for `addr`'s value
    #[inline]
    pub fn get(&self, addr: u64) -> u64 {
        self.entry(addr).load(Ordering::Acquire)
    }

    /// Install `new` in the entry for `addr` if it still holds `old`
    /// (Linux pte_same + set_pte_at)
    #[inline]
    pub fn set(&self, addr: u64, old: u64, new: u64) -> bool {
        self.entry(addr)
            .compare_exchange(old, new, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Store `new` in the entry for `addr`, which nothing but this lock
    /// holder changes (an empty or invalid entry)
    #[inline]
    pub fn store(&self, addr: u64, new: u64) {
        self.entry(addr).store(new, Ordering::Release);
    }
}

/// Boot self-test (kselftest) on a scratch address space never loaded
/// on a CPU: a 4KB entry reached under the mmap_lock is allocated,
/// changed under its PTE lock and read back, and tables pinned for a
/// range (a chain entry's) reach nothing outside it. None if right,
/// else what failed.
pub fn selftest() -> Option<&'static str> {
    use crate::FRAME_ALLOCATOR;
    let root = FRAME_ALLOCATOR.alloc()?;
    // SAFETY: a fresh frame, reached through the direct map
    unsafe { core::ptr::write_bytes(phys_to_virt(root), 0, super::PAGE_SIZE as usize) };
    // Owns `root`: dropping it frees the tables
    let mm = super::mm_alloc(root);
    let r = {
        let map = mm.mmap_read();
        selftest_in(&mm, PgTables::new(&mm, &map))
    };
    drop(mm);
    r
}

/// `selftest` on the tables `t` of `mm`
fn selftest_in(mm: &Mm, t: PgTables<'_>) -> Option<&'static str> {
    const A: u64 = 0x4000_0000;
    const B: u64 = A + super::PAGE_SIZE;
    // A swap-like value: no frame behind it, nothing to free
    const V: u64 = 7 << 12;
    if t.pte(A).is_some() {
        return Some("pgtable_absent");
    }
    let Some(p) = t.pte_alloc(mm, A) else {
        return Some("pgtable_alloc");
    };
    let set = {
        let l = p.lock();
        l.set(A, 0, V) && !l.set(A, 0, V + (1 << 12)) && l.get(A) == V
    };
    let read = p.get() == V
        && t.pte(B)
            .is_some_and(|q| q.get() == 0 && q.table() == p.table());
    // SAFETY: `t`'s tables, pinned for this call
    let part = unsafe { PgTables::from_raw(t.pgd(), B, B + super::PAGE_SIZE) };
    let range = part.pte(A).is_none() && part.pte(B).is_some();
    p.lock().store(A, 0);
    match (set, read, range) {
        (true, true, true) => None,
        (false, _, _) => Some("pgtable_set"),
        (_, false, _) => Some("pgtable_read"),
        (_, _, false) => Some("pgtable_range"),
    }
}

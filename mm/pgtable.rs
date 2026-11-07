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
//! - [`Pmd`]: one 2MB-level entry of pinned tables; a 2MB page in it
//!   changes only with the page_table_lock held (`ptl::PtLock`), which
//!   its writes take as an argument.
//! - [`Dir`]: one upper-level table of pinned tables, for the range
//!   walker (`pagewalk`), which descends them level by level.
//! - [`PgPrune`] / [`PruneDir`]: the tables of a gap between VMAs, made
//!   from `&mut MmStruct`, the only handles that take a table out of
//!   the tree (`memory::free_pgtables`).
//!
//! Each is a pointer-sized copy of what the open-coded `*mut u64` was;
//! the walk itself stays in `arch::paging`, whose walkers are `unsafe
//! fn`s on a raw root reached only from here.

use core::marker::PhantomData;
use core::sync::atomic::{AtomicU64, Ordering};

use super::huge_page::{HUGE_PAGE_MASK, pmd_settled};
use super::page::{Page, phys_to_page};
use super::ptl::{PtLock, PteLock, table_lock};
use super::{Mm, MmStruct, PAGE_SIZE};
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
        // SAFETY: `pgd` is live and no table under it mapping `addr`, an
        // address of the pinned range, is freed for 'a (type invariant)
        let p = unsafe { paging::pte_ptr(self.pgd, addr) }?;
        // SAFETY: `p` is the entry of `addr` in a table under `pgd`,
        // through the direct map, which stays for 'a (type invariant);
        // page-table entries are only accessed atomically
        let slot = unsafe { AtomicU64::from_ptr(p) };
        // INVARIANT: that entry, in a table kept for 'a
        Some(Pte { slot, addr })
    }

    /// The 2MB-level entry of `addr`'s 2MB region (Linux pmd_offset);
    /// None outside the pinned range or if an upper table is missing
    #[inline]
    pub fn pmd(&self, addr: u64) -> Option<Pmd<'a>> {
        if !self.covers(addr) {
            return None;
        }
        // SAFETY: as in `pte`
        let p = unsafe { paging::pmd_ptr(self.pgd, addr) }?;
        // SAFETY: as in `pte`: the 2MB-level entry of `addr`, in a
        // table under `pgd` kept for 'a
        let slot = unsafe { AtomicU64::from_ptr(p) };
        // INVARIANT: that entry, in a table kept for 'a
        Some(Pmd {
            slot,
            pgd: self.pgd,
            addr: addr & !HUGE_PAGE_MASK,
        })
    }

    /// `pmd`, installing missing upper tables under the page_table_lock
    /// `l` of the tables' address space (Linux pmd_alloc); None outside
    /// the pinned range or out of memory
    pub fn pmd_alloc(&self, l: &PtLock<'_>, addr: u64) -> Option<Pmd<'a>> {
        assert_eq!(l.pgd(), self.pgd, "page_table_lock of another mm");
        if !self.covers(addr) {
            return None;
        }
        // SAFETY: as in `pte`
        let p = unsafe { paging::pmd_alloc(self.pgd, addr) }?;
        // SAFETY: as in `pmd`
        let slot = unsafe { AtomicU64::from_ptr(p) };
        // INVARIANT: as in `pmd`
        Some(Pmd {
            slot,
            pgd: self.pgd,
            addr: addr & !HUGE_PAGE_MASK,
        })
    }

    /// The physical address `addr` maps to (a 4KB or 2MB page); None
    /// outside the pinned range or if not mapped. Without the lock of
    /// its entry, a hint: the frame may go at once.
    pub fn translate(&self, addr: u64) -> Option<u64> {
        if !self.covers(addr) {
            return None;
        }
        // SAFETY: as in `pte`
        unsafe { paging::translate(self.pgd, addr) }
    }

    /// The top-level table, where a range walk starts
    #[inline]
    pub fn top(&self) -> Dir<'a> {
        // INVARIANT: the top-level table, live for 'a (type invariant)
        Dir {
            t: *self,
            table: self.pgd,
            level: 3,
        }
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
        // SAFETY: as in `pte`
        let p = unsafe { paging::pte_alloc(self.pgd, addr) }?;
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

    /// Its PTE table, locked (Linux pte_offset_map_lock). Bind the
    /// result for a critical section of more than one step: a
    /// temporary (`p.lock().set(..)`) unlocks at the end of its
    /// statement, before what follows.
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

/// One 2MB-level entry of pinned page tables (Linux the `pmd_t *` of
/// pmd_offset): a 2MB page, a PTE table or nothing. Read without a
/// lock; a 2MB page in it is replaced only with the page_table_lock
/// held (`PtLock`), which a split keeps from writing `PMD_SPLITTING`
/// until the PTE table is in.
///
/// # Invariants
///
/// `slot` is the 2MB-level entry for the 2MB region at `addr` in the
/// tables under `pgd`, in a table that stays for `'a`.
#[derive(Clone, Copy)]
pub struct Pmd<'a> {
    slot: &'a AtomicU64,
    pgd: u64,
    addr: u64,
}

impl Pmd<'_> {
    /// The entry's value
    #[inline]
    pub fn get(&self) -> u64 {
        self.slot.load(Ordering::Acquire)
    }

    /// The value once no split is under way (`huge_page::pmd_settled`)
    #[inline]
    pub fn settled(&self) -> u64 {
        pmd_settled(self.slot)
    }

    /// It maps a 2MB page
    #[inline]
    pub fn huge(&self) -> bool {
        paging::pmd_huge(self.get())
    }

    /// The first address of its 2MB region
    #[inline]
    pub fn addr(&self) -> u64 {
        self.addr
    }

    /// The top-level table it lies under
    #[inline]
    pub fn pgd(&self) -> u64 {
        self.pgd
    }

    /// The PTE table it points to once no split is under way, if any:
    /// kept for `'a` like the entry (it maps the same addresses)
    #[inline]
    pub fn pte_table(&self) -> Option<u64> {
        paging::table_of(self.settled())
    }

    /// The page of the table holding it (deposits: `huge_page`)
    pub(super) fn table_page(&self) -> &'static Page {
        let table = virt_to_phys(core::ptr::from_ref(self.slot).addr() as u64 & !0xfff);
        phys_to_page(table).expect("page table outside RAM")
    }

    /// Replace the value by `v`, the page_table_lock of its address
    /// space held (Linux pmdp_huge_get_and_clear): the value replaced
    #[inline]
    pub(super) fn swap(&self, l: &PtLock<'_>, v: u64) -> u64 {
        assert_eq!(l.pgd(), self.pgd, "page_table_lock of another mm");
        // A table is installed only by `populate`, which owns it
        assert!(paging::table_of(v).is_none(), "table through Pmd::swap");
        self.slot.swap(v, Ordering::AcqRel)
    }

    /// Install the 2MB page entry `v` in the empty entry, under the
    /// page_table_lock `l` (Linux set_pmd_at); false if not empty
    #[inline]
    pub(super) fn set_huge(&self, l: &PtLock<'_>, v: u64) -> bool {
        assert_eq!(l.pgd(), self.pgd, "page_table_lock of another mm");
        assert!(paging::pmd_huge(v), "not a 2MB entry");
        paging::pmd_set_huge(self.slot, v)
    }

    /// Make its 2MB page writable or not and executable or not, under
    /// the page_table_lock `l` (Linux change_huge_pmd); false if it maps
    /// no 2MB page. A compare-and-swap: the MMU may set accessed/dirty
    /// bits meanwhile. The caller flushes the TLB.
    pub(super) fn set_prot(&self, l: &PtLock<'_>, writable: bool, executable: bool) -> bool {
        assert_eq!(l.pgd(), self.pgd, "page_table_lock of another mm");
        self.slot
            .try_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                paging::pmd_huge(v).then(|| paging::pmd_mkprot(v, writable, executable))
            })
            .is_ok()
    }

    /// Install the filled PTE table `pt` in the entry, emptied (and
    /// flushed) under the page_table_lock `l` (Linux pmd_populate)
    ///
    /// # Safety
    ///
    /// `pt` is a PTE table frame the caller owns, which the tables take
    /// over.
    #[inline]
    pub(super) unsafe fn populate(&self, l: &PtLock<'_>, pt: u64) {
        assert_eq!(l.pgd(), self.pgd, "page_table_lock of another mm");
        // SAFETY: `pt` is the caller's table, handed over (the
        // caller's guarantee)
        unsafe { paging::pmd_populate(self.slot, pt) };
    }
}

/// Detach the user tables of `mm` for exit (Linux exit_mmap): `map`,
/// its VMA tree borrowed mutably, holds no VMA any more, so no chain
/// entry of it is left and no `PgTables` of it can be made. The caller
/// frees them only after flushing every CPU (`Gather::free_tables`).
pub(super) fn detach_user(mm: &Mm, map: &mut MmStruct) -> paging::UserTables {
    assert!(mm.holds(map), "tables detached under another mm's VMAs");
    assert!(
        map.iter().next().is_none(),
        "tables detached under live VMAs"
    );
    // SAFETY: `mm`'s live top-level table; no VMA left means no chain
    // entry and no table user, and `map` is borrowed mutably; the
    // gather frees the tables after its full flush
    unsafe { paging::detach_user(mm.pgd()) }
}

/// Slot `i` (mod 512) of the table frame `table`, through the direct map
#[inline]
fn slot_ptr(table: u64, i: u64) -> *mut u64 {
    phys_to_virt(table)
        .cast::<u64>()
        .wrapping_add((i & 511) as usize)
}

/// Bytes mapped by one entry of a table at `level` (1: 2MB ... 3: 512GB)
#[inline]
fn span(level: u32) -> u64 {
    1 << (12 + 9 * level)
}

/// One upper-level table of pinned page tables: the top level (3), the
/// 1GB level (2) or the table of 2MB entries (1) (Linux the pgd, pud and
/// pmd pages walk_page_range descends)
///
/// # Invariants
///
/// `table` is a table frame at `level` under `t`'s tables that maps an
/// address of `t`'s pinned range, so it stays for `'a`.
#[derive(Clone, Copy)]
pub struct Dir<'a> {
    t: PgTables<'a>,
    table: u64,
    level: u32,
}

impl<'a> Dir<'a> {
    /// Its level: 3 (top) to 1 (2MB entries)
    #[inline]
    pub fn level(&self) -> u32 {
        self.level
    }

    /// The entry mapping `addr`
    #[inline]
    fn slot(&self, addr: u64) -> &'a AtomicU64 {
        let p = slot_ptr(self.table, addr >> (12 + 9 * self.level));
        // SAFETY: an entry of a table frame kept for 'a (type
        // invariant); page-table entries are only accessed atomically
        unsafe { AtomicU64::from_ptr(p) }
    }

    /// The table one level down that maps `addr` (Linux pud_offset,
    /// pmd_offset); None at level 1, outside the pinned range, or if the
    /// entry holds no table
    #[inline]
    pub fn child(&self, addr: u64) -> Option<Dir<'a>> {
        if self.level < 2 || !self.t.covers(addr) {
            return None;
        }
        let table = paging::table_of(self.slot(addr).load(Ordering::Acquire))?;
        // INVARIANT: the table under this one that maps `addr`, an
        // address of the pinned range
        Some(Dir {
            t: self.t,
            table,
            level: self.level - 1,
        })
    }

    /// At level 1, the 2MB-level entry of `addr` (Linux pmd_offset);
    /// None at another level or outside the pinned range
    #[inline]
    pub fn pmd(&self, addr: u64) -> Option<Pmd<'a>> {
        if self.level != 1 || !self.t.covers(addr) {
            return None;
        }
        // INVARIANT: the 2MB-level entry of `addr`, in a table kept for
        // 'a (type invariant)
        Some(Pmd {
            slot: self.slot(addr),
            pgd: self.t.pgd,
            addr: addr & !HUGE_PAGE_MASK,
        })
    }
}

/// The page tables of one address space being pruned (Linux
/// free_pgtables): made from `&mut MmStruct` (its mmap_lock held for
/// writing, so no `PgTables::new` of it lives) for the gap [floor,
/// ceiling) between the VMAs around a removed range. No VMA lies in the
/// gap, and every reverse-map chain entry of the address space is a VMA
/// of the tree (a removed VMA is unlinked first), so no `PgTables` of a
/// chain pins it either. Only a table whose whole span lies in the gap
/// is taken out.
///
/// # Invariants
///
/// For `'a`, `pgd` is a live top-level table, no `PgTables` of it pins
/// an address of [floor, ceiling), and its tables are freed only
/// through this handle.
pub struct PgPrune<'a> {
    pgd: u64,
    floor: u64,
    ceiling: u64,
    _excl: PhantomData<&'a mut MmStruct>,
}

impl<'a> PgPrune<'a> {
    /// The tables of `mm` around [start, end), whose VMAs are gone from
    /// `map`, its VMA tree (Linux free_pgtables' floor and ceiling)
    pub fn new(mm: &'a Mm, map: &'a mut MmStruct, start: u64, end: u64) -> Self {
        assert!(mm.holds(map), "tables pruned under another mm's VMAs");
        let (floor, ceiling) = map.gap_around(start, end);
        // INVARIANT: `map` is borrowed mutably for 'a, so no `PgTables`
        // of `mm` is made from it meanwhile; chain entries are VMAs of
        // `map`, outside the gap; `pgd` goes with `mm`, borrowed for 'a
        Self {
            pgd: mm.pgd(),
            floor,
            ceiling,
            _excl: PhantomData,
        }
    }

    /// The top-level table
    pub fn top(&mut self) -> PruneDir<'_> {
        // INVARIANT: the live top-level table, mapping from 0
        PruneDir {
            table: self.pgd,
            level: 3,
            base: 0,
            floor: self.floor,
            ceiling: self.ceiling,
            _p: PhantomData,
        }
    }
}

/// One upper-level table of a [`PgPrune`], borrowing it (or its parent
/// `PruneDir`) mutably: a child table is taken out only while no handle
/// to it lives
///
/// # Invariants
///
/// `table` is a live table frame at `level` (3: top, 1: 2MB entries)
/// whose first entry maps `base`; for `'p`, no `PgTables` pins an
/// address of [floor, ceiling) under it, and tables are freed only
/// through this handle.
pub struct PruneDir<'p> {
    table: u64,
    level: u32,
    base: u64,
    floor: u64,
    ceiling: u64,
    _p: PhantomData<&'p mut ()>,
}

impl PruneDir<'_> {
    /// Its level: 3 (top) to 1 (2MB entries)
    pub fn level(&self) -> u32 {
        self.level
    }

    /// The first address it maps
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Bytes one of its entries maps
    pub fn span(&self) -> u64 {
        span(self.level)
    }

    /// Entry `i` (mod 512)
    fn slot(&self, i: u64) -> &AtomicU64 {
        // SAFETY: an entry of a live table frame (type invariant),
        // borrowed no longer than `self`; entries are only accessed
        // atomically
        unsafe { AtomicU64::from_ptr(slot_ptr(self.table, i)) }
    }

    /// The table under entry `i`, a level down; None at level 1 (its
    /// children are PTE tables) or if the entry holds no table
    pub fn child(&mut self, i: u64) -> Option<PruneDir<'_>> {
        if self.level < 2 {
            return None;
        }
        let table = paging::table_of(self.slot(i).load(Ordering::Acquire))?;
        // INVARIANT: a live table under this one, mapping from its
        // entry's first address; it borrows `self` mutably
        Some(PruneDir {
            table,
            level: self.level - 1,
            base: self.base + (i & 511) * self.span(),
            floor: self.floor,
            ceiling: self.ceiling,
            _p: PhantomData,
        })
    }

    /// Take out the table under entry `i` if the entry's whole span lies
    /// in the gap and the table is empty: the entry is cleared and the
    /// frame returned, for the caller to free once no CPU caches it (a
    /// TLB flush with the paging-structure caches)
    #[must_use]
    pub fn take_child(&mut self, i: u64) -> Option<u64> {
        let lo = self.base + (i & 511) * self.span();
        if lo < self.floor || lo + self.span() > self.ceiling {
            return None;
        }
        let e = self.slot(i);
        let child = paging::table_of(e.load(Ordering::Acquire))?;
        let empty = (0..512).all(|j| {
            // SAFETY: an entry of a live table frame under this one,
            // which nothing else pins (type invariant: its span lies in
            // the gap); borrowed for this load only
            unsafe { AtomicU64::from_ptr(slot_ptr(child, j)) }.load(Ordering::Acquire) == 0
        });
        if !empty {
            return None;
        }
        e.store(0, Ordering::Release);
        Some(child)
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
    let r = r.or_else(|| prune_selftest(&mm));
    drop(mm);
    r
}

/// The PTE table of `addr` in `p`'s tables, taken out if possible
fn prune_pte_table(p: &mut PgPrune<'_>, addr: u64) -> Option<u64> {
    let mut top = p.top();
    let mut l2 = top.child(addr >> 39)?;
    let mut l1 = l2.child(addr >> 30)?;
    l1.take_child(addr >> 21)
}

/// A PTE table of `mm` (VMA-free, never loaded on a CPU) is taken out
/// by a `PgPrune` only once empty, and is gone from the tree after
fn prune_selftest(mm: &Mm) -> Option<&'static str> {
    const A: u64 = 0x8000_0000;
    const V: u64 = 7 << 12;
    {
        let map = mm.mmap_read();
        let t = PgTables::new(mm, &map);
        let Some(p) = t.pte_alloc(mm, A) else {
            return Some("pgtable_prune_alloc");
        };
        p.lock().store(A, V);
    }
    let mut map = mm.mmap_write();
    let busy = prune_pte_table(&mut PgPrune::new(mm, &mut map, A, A + PAGE_SIZE), A).is_none();
    if let Some(p) = PgTables::new(mm, &map).pte(A) {
        p.lock().store(A, 0);
    }
    let taken = prune_pte_table(&mut PgPrune::new(mm, &mut map, A, A + PAGE_SIZE), A);
    if let Some(pt) = taken {
        // Never loaded on a CPU: nothing to flush
        crate::FRAME_ALLOCATOR.free(pt);
    }
    let gone = PgTables::new(mm, &map).pte(A).is_none();
    match (busy, taken.is_some() && gone) {
        (true, true) => None,
        (false, _) => Some("pgtable_prune_busy"),
        (_, false) => Some("pgtable_prune_empty"),
    }
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

//! The kernel's top-level page table (Linux swapper_pg_dir) and the
//! boot helpers that fill it
//!
//! Each arch's `kmap::init` (Linux paging_init) lays out the kernel half
//! with these: tables from a static pool (the frame allocator does not
//! exist yet), entries through the arch encoding (`arch::IoremapOps`,
//! `arch::KmapOps`). Later boot code adds kernel pages below top-level
//! entries `init` created (`map_page`, `map_pmd`: vmemmap). All of it
//! runs on the BSP before SMP.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::arch::paging::{RawPageTable, phys_to_virt_table};
use crate::arch::{CurrentArch, IoremapOps, KmapOps};
use crate::sync::RacyCell;

const POOL_PAGES: usize = <CurrentArch as KmapOps>::POOL_PAGES;

const _: () = assert!(size_of::<RawPageTable>() == 4096);

#[repr(C, align(4096))]
struct Pool([RawPageTable; POOL_PAGES]);

static POOL: RacyCell<Pool> = RacyCell::new(Pool([const { RawPageTable::new() }; POOL_PAGES]));
/// Pool pages handed out
static POOL_USED: AtomicUsize = AtomicUsize::new(0);

/// The kernel's top-level table (x86 init_top_pgt, arm64 TTBR1 root)
static SWAPPER: RacyCell<RawPageTable> = RacyCell::new(RawPageTable::new());

/// Physical end of the direct map: RAM above it is not mapped
static DIRECT_END: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" {
    static __kernel_start: u8;
    static __kernel_end: u8;
}

/// Physical address of a kernel image symbol (Linux: __pa_symbol)
pub fn pa_symbol(va: u64) -> u64 {
    va - CurrentArch::KIMAGE_OFFSET
}

/// The kernel image in physical memory, as [start, end)
pub fn image_range() -> (u64, u64) {
    let start = pa_symbol(&raw const __kernel_start as u64);
    (start, pa_symbol(&raw const __kernel_end as u64))
}

/// The top-level table, for the arch's boot builders
pub fn swapper() -> *mut RawPageTable {
    SWAPPER.get()
}

/// Physical address of the top-level table
pub fn swapper_phys() -> u64 {
    pa_symbol(SWAPPER.get() as u64)
}

/// Physical end of the direct map (0 before `kmap::init`)
pub fn direct_end() -> u64 {
    DIRECT_END.load(Ordering::Relaxed)
}

/// Record the direct map's physical end (`kmap::init`)
pub fn set_direct_end(end: u64) {
    DIRECT_END.store(end, Ordering::Relaxed);
}

/// A zeroed page-table page from the pool, as its physical address
fn pool_page() -> u64 {
    let n = POOL_USED.fetch_add(1, Ordering::Relaxed);
    assert!(n < POOL_PAGES, "kmap: page-table pool exhausted");
    // SAFETY: page `n` of the pool, in bounds, handed out once (the
    // counter); only its address is taken
    let t = unsafe { &raw mut (*POOL.get()).0[n] };
    pa_symbol(t as u64)
}

/// Entry `idx` of `table`
///
/// # Safety
/// `table` is a live page table and `idx < 512`.
unsafe fn ent(table: *mut RawPageTable, idx: usize) -> *mut u64 {
    // SAFETY: a page table is 512 u64 entries (the size assert; both
    // arches' entries are transparent u64s); in bounds (the caller's
    // guarantee)
    unsafe { table.cast::<u64>().add(idx) }
}

/// The table under the upper entry `e`, a new one from `table` if absent
///
/// # Safety
/// `e` is an entry of a boot or kernel table this CPU alone changes
/// (before SMP); `table` gives zeroed frames.
unsafe fn descend(e: *mut u64, table: &mut dyn FnMut() -> u64) -> *mut RawPageTable {
    // SAFETY: the caller's guarantee
    unsafe {
        if !CurrentArch::pte_present(*e) {
            *e = CurrentArch::mk_table(table());
        }
        phys_to_virt_table(CurrentArch::pte_addr(*e))
    }
}

/// Next-level table under `table[idx]`, created from the pool if absent
///
/// # Safety
/// `table` is a boot page table (swapper or pool page), during
/// single-CPU early boot; `idx < 512`.
pub unsafe fn next(table: *mut RawPageTable, idx: usize) -> *mut RawPageTable {
    // SAFETY: `table` is a boot table no other CPU or reference reaches
    // (the caller's guarantee); a missing entry gets a zeroed pool
    // page, itself a boot table, reached through the direct map
    unsafe { descend(ent(table, idx), &mut pool_page) }
}

/// Index of `va` in its table at the level of `shift`
pub fn idx(va: u64, shift: u32) -> usize {
    ((va >> shift) & 511) as usize
}

/// Map the kernel page `va` to `pa` (writable, never executable) below
/// a top-level entry `kmap::init` created; missing lower tables come
/// from `table` (the physical address of a zeroed frame)
///
/// # Safety
/// Boot CPU, before SMP; `va` is unmapped and not in use.
pub unsafe fn map_page(va: u64, pa: u64, table: &mut dyn FnMut() -> u64) {
    // SAFETY: `walk`'s contract is this fn's; `va`'s entry, unmapped
    // and unused, in a live swapper table
    unsafe {
        let t = walk(va, &[39, 30, 21], table);
        *ent(t, idx(va, 12)) = CurrentArch::mk_pte(pa, CurrentArch::PROT_KERNEL);
    }
    CurrentArch::kmap_sync();
}

/// `map_page` for a 2MB page: `va` and `pa` 2MB aligned, no page table
/// below that entry yet
///
/// # Safety
/// As for `map_page`.
pub unsafe fn map_pmd(va: u64, pa: u64, table: &mut dyn FnMut() -> u64) {
    // SAFETY: as in `map_page`
    unsafe {
        let t = walk(va, &[39, 30], table);
        *ent(t, idx(va, 21)) = CurrentArch::mk_pmd(pa, CurrentArch::PROT_KERNEL);
    }
    CurrentArch::kmap_sync();
}

/// The table `shifts` lead to from the top level for `va`, missing ones
/// from `table`
///
/// # Safety
/// As for `map_page`.
unsafe fn walk(va: u64, shifts: &[u32], table: &mut dyn FnMut() -> u64) -> *mut RawPageTable {
    // SAFETY: the swapper and the kernel tables under it are live and,
    // before SMP (the caller's guarantee), changed by this CPU only;
    // `table` gives zeroed frames, reached through the direct map
    unsafe {
        let mut t = SWAPPER.get();
        assert!(
            CurrentArch::pte_present(*ent(t, idx(va, 39))),
            "kmap: no top-level entry"
        );
        for &shift in shifts {
            t = descend(ent(t, idx(va, shift)), table);
        }
        t
    }
}

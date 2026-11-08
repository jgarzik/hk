//! Kernel page table (TTBR1, swapper_pg_dir): linear map, image, devices
//!
//! Linux arm64 48-bit layout (Documentation/arch/arm64/memory.rst):
//!
//! ```text
//! 0000000000000000 - 0000ffffffffffff  user space (TTBR0, per process)
//! ffff000000000000 - ...               linear map of RAM (PAGE_OFFSET)
//! ffff800040100000 - ...               kernel image (KIMAGE_OFFSET + phys)
//! ffff800100000000 - ffff80013fffffff  vmalloc/ioremap window
//! ffff800140000000 - ffff80015fffffff  kernel stacks (mm::vmstack)
//! ffff800200000000 - ffff80023fffffff  device window (physical 0-1GB)
//! ffff800400000000 - ffff8007ffffffff  vmalloc allocations (mm::vmalloc)
//! ```
//!
//! boot.S enables the MMU on coarse boot tables (1GB blocks: an identity
//! map of the kernel's RAM gigabyte in TTBR0, the first RAM gigabyte,
//! the image and the device window in TTBR1). `init` builds the final
//! TTBR1 tables once the heap exists (the DTB parser needs it) and
//! leaves TTBR0 with an empty table; user page tables only ever hold
//! user mappings. Boot-time tables come from a static pool.

use core::arch::asm;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::sync::RacyCell;

use super::paging::{
    AF, AP_EL1_RO, AP_EL1_RW, ATTR_IDX_DEVICE, ATTR_IDX_NORMAL, IO_BASE, IO_SIZE, KIMAGE_OFFSET,
    PAGE_OFFSET, PAGE_SIZE, PXN, RawPageTable, SH_INNER, UXN, VMEMMAP_START, phys_to_virt_table,
};

/// Page-table pages for the boot-built kernel tables
const POOL_PAGES: usize = 48;

const SZ_2M: u64 = 2 << 20;
const SZ_1G: u64 = 1 << 30;

/// RAM assumed when the DTB has no memory node (QEMU virt, -m 512M)
const DEFAULT_RAM: (u64, u64) = (0x4000_0000, 512 << 20);

#[repr(C, align(4096))]
struct Pool([RawPageTable; POOL_PAGES]);

static POOL: RacyCell<Pool> = RacyCell::new(Pool([const { RawPageTable::new() }; POOL_PAGES]));
/// Pool pages handed out
static POOL_USED: AtomicUsize = AtomicUsize::new(0);

/// TTBR1 root (Linux: swapper_pg_dir)
static SWAPPER: RacyCell<RawPageTable> = RacyCell::new(RawPageTable::new());

/// Empty TTBR0 root for kernel threads (Linux: reserved_pg_dir)
static RESERVED: RawPageTable = RawPageTable::new();

/// Physical end of the linear map
static DIRECT_END: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" {
    static _text: u8;
    static _etext: u8;
    static _sdata: u8;
    static __kernel_start: u8;
    static __kernel_end: u8;
    fn __replace_ttbr1(ttbr1: u64, ttbr0: u64);
}

/// Physical address of a kernel image symbol (Linux: __pa_symbol)
pub fn pa_symbol(va: u64) -> u64 {
    va - KIMAGE_OFFSET
}

/// Image virtual address of a physical address inside the image
pub fn kimage_va(pa: u64) -> u64 {
    pa + KIMAGE_OFFSET
}

/// The kernel image in physical memory, as [start, end)
pub fn image_range() -> (u64, u64) {
    let start = pa_symbol(&raw const __kernel_start as u64);
    (start, pa_symbol(&raw const __kernel_end as u64))
}

/// Physical address of the TTBR1 root
pub fn swapper_phys() -> u64 {
    pa_symbol(SWAPPER.get() as u64)
}

/// Physical address of the empty TTBR0 root
pub fn reserved_phys() -> u64 {
    pa_symbol(&raw const RESERVED as u64)
}

/// Physical end of the linear map (0 before `init`)
pub fn direct_end() -> u64 {
    DIRECT_END.load(Ordering::Relaxed)
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

/// Next-level table under `table[idx]`, created if absent
///
/// # Safety
/// `table` is a boot page table (swapper or pool page), during
///  single-CPU early boot.
unsafe fn next(table: *mut RawPageTable, idx: usize) -> *mut RawPageTable {
    // SAFETY: `table` is a boot table no other CPU or reference reaches
    // (the caller's guarantee); a missing entry gets a zeroed pool
    // page, itself a boot table, reached through the linear map
    unsafe {
        let e = (*table).entry_mut(idx);
        if !e.is_valid() {
            e.set_table(pool_page());
        }
        phys_to_virt_table(e.addr())
    }
}

fn idx(va: u64, shift: u32) -> usize {
    ((va >> shift) & 511) as usize
}

/// Linear-map RAM [base, base + size): 1GB blocks where a whole
/// gigabyte is RAM, else 2MB blocks (normal memory, never executable);
/// returns the end of the mapping
///
/// # Safety
/// As [`next`] for `root`; [base, base + size) is RAM.
unsafe fn map_linear(root: *mut RawPageTable, base: u64, size: u64) -> u64 {
    let attrs = AF | SH_INNER | ATTR_IDX_NORMAL | AP_EL1_RW | PXN | UXN;
    let (start, end) = (base & !(SZ_2M - 1), (base + size).next_multiple_of(SZ_2M));
    let mut p = start;
    while p < end {
        let va = PAGE_OFFSET + p;
        // SAFETY: `root` and the tables `next` returns are boot tables
        // (this fn's contract, `next`'s), single CPU
        unsafe {
            let l1 = next(root, idx(va, 39));
            if p.is_multiple_of(SZ_1G) && p + SZ_1G <= end {
                (*l1).entry_mut(idx(va, 30)).set_block(p, attrs);
                p += SZ_1G;
            } else {
                let l2 = next(l1, idx(va, 30));
                (*l2).entry_mut(idx(va, 21)).set_block(p, attrs);
                p += SZ_2M;
            }
        }
    }
    end
}

/// Map the kernel image with 4KB pages: text read-only executable,
/// rodata read-only, data and bss writable, neither executable (W^X)
///
/// # Safety
/// As [`next`] for `root`.
unsafe fn map_image(root: *mut RawPageTable) {
    let normal = AF | SH_INNER | ATTR_IDX_NORMAL | UXN;
    let text = &raw const _text as u64;
    let etext = &raw const _etext as u64;
    let sdata = &raw const _sdata as u64;
    let mut va = &raw const __kernel_start as u64;
    let end = &raw const __kernel_end as u64;
    while va < end {
        let attrs = if (text..etext).contains(&va) {
            normal | AP_EL1_RO
        } else if va >= sdata {
            normal | AP_EL1_RW | PXN
        } else {
            normal | AP_EL1_RO | PXN
        };
        // SAFETY: as in `map_linear`
        unsafe {
            let l1 = next(root, idx(va, 39));
            let l2 = next(l1, idx(va, 30));
            let l3 = next(l2, idx(va, 21));
            (*l3).entry_mut(idx(va, 12)).set_page(pa_symbol(va), attrs);
        }
        va += PAGE_SIZE;
    }
}

/// Device window: one 1GB Device-nGnRnE block over physical 0-1GB
///
/// # Safety
/// As [`next`] for `root`.
unsafe fn map_io(root: *mut RawPageTable) {
    let attrs = AF | ATTR_IDX_DEVICE | AP_EL1_RW | PXN | UXN;
    // SAFETY: as in `map_linear`
    unsafe {
        let l1 = next(root, idx(IO_BASE, 39));
        (*l1).entry_mut(idx(IO_BASE, 30)).set_block(0, attrs);
    }
    const { assert!(IO_SIZE == SZ_1G) };
}

/// Build the final TTBR1 tables and switch to them (TTBR0 gets the
/// empty table): every RAM range of the DTB goes to memblock and into
/// the linear map. Runs on the BSP, on the boot tables.
///
/// # Safety
/// Once, on the BSP, before SMP and before any user address space.
pub unsafe fn init() {
    use crate::mm::memblock;
    if !super::dtb::for_each_memory(memblock::add) {
        memblock::add(DEFAULT_RAM.0, DEFAULT_RAM.1);
    }
    // SAFETY: once on the BSP before SMP (this fn's contract): the
    // swapper is a boot table nothing else reaches yet, and the
    // map_* calls get it. The barrier only orders the table writes
    // (nostack). `__replace_ttbr1` is the asm routine at that linker
    // symbol with this C signature, run through its physical
    // (identity-mapped) address; the tables it installs map the
    // running image and the linear map
    unsafe {
        let root = SWAPPER.get();
        let mut end = 0;
        for r in memblock::MEMBLOCK.lock().memory.ranges() {
            end = end.max(map_linear(root, r.base, r.size()));
        }
        DIRECT_END.store(end, Ordering::Relaxed);
        map_image(root);
        map_io(root);
        // vmemmap's top-level entry (filled by `map_page`)
        next(root, idx(VMEMMAP_START, 39));
        // Table writes must reach memory before the walker uses them
        asm!("dsb ishst", options(nostack));
        // The switch runs from the identity map (TTBR0), so no TTBR1
        // translation is live while TTBR1 changes (Linux:
        // cpu_replace_ttbr1)
        let f: unsafe extern "C" fn(u64, u64) =
            core::mem::transmute(pa_symbol(__replace_ttbr1 as *const () as u64));
        f(swapper_phys(), reserved_phys());
    }
    drop_idmap();
}

/// Map the kernel page `va` to `pa` (normal memory, writable, never
/// executable) in TTBR1; missing tables come from `table` (the
/// physical address of a zeroed frame)
///
/// # Safety
/// Boot CPU, before SMP; `va` is unmapped and not in use.
pub unsafe fn map_page(va: u64, pa: u64, table: &mut dyn FnMut() -> u64) {
    // SAFETY: `walk`'s contract is this fn's; `va`'s entry, unmapped
    // and unused, in a live swapper table; barriers only (nostack)
    unsafe {
        let t = walk(va, &[39, 30, 21], table);
        (*t).entry_mut(idx(va, 12)).set_page(pa, KERNEL_RW);
        // The walker sees the entry before the first access
        asm!("dsb ishst", "isb", options(nostack));
    }
}

/// `map_page` for a 2MB block: `va` and `pa` 2MB aligned, no table
/// below that entry yet
///
/// # Safety
/// As for `map_page`.
pub unsafe fn map_pmd(va: u64, pa: u64, table: &mut dyn FnMut() -> u64) {
    // SAFETY: as in `map_page`
    unsafe {
        let t = walk(va, &[39, 30], table);
        (*t).entry_mut(idx(va, 21)).set_block(pa, KERNEL_RW);
        asm!("dsb ishst", "isb", options(nostack));
    }
}

/// Kernel data: read-write, never executable
const KERNEL_RW: u64 = AF | SH_INNER | ATTR_IDX_NORMAL | AP_EL1_RW | PXN | UXN;

/// The table `shifts` lead to from TTBR1's root for `va`, missing ones
/// from `table`
///
/// # Safety
/// As for `map_page`.
unsafe fn walk(va: u64, shifts: &[u32], table: &mut dyn FnMut() -> u64) -> *mut RawPageTable {
    // SAFETY: the swapper and the kernel tables under it are live and,
    // before SMP (the caller's guarantee), changed by this CPU only;
    // `table` gives zeroed frames, reached through the linear map
    unsafe {
        let mut t = SWAPPER.get();
        for &shift in shifts {
            let e = (*t).entry_mut(idx(va, shift));
            if !e.is_valid() {
                e.set_table(table());
            }
            t = phys_to_virt_table(e.addr());
        }
        t
    }
}

/// Leave the boot identity map on this CPU (APs, after reaching the
/// high half): TTBR0 gets the empty table
pub fn drop_idmap() {
    // SAFETY: TTBR0 gets the empty reserved table (the kernel runs from
    // TTBR1), then this CPU's TLB is flushed; it changes how memory is
    // reached, so no nomem (nostack: no stack use)
    unsafe {
        asm!(
            "msr ttbr0_el1, {}",
            "isb",
            "tlbi vmalle1",
            "dsb nsh",
            "isb",
            in(reg) reserved_phys(),
            options(nostack)
        );
    }
}

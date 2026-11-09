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

use crate::arch::KmapOps;
use crate::mm::swapper::{idx, next, pa_symbol, set_direct_end, swapper, swapper_phys};

use super::Aarch64Arch;
use super::paging::{
    AF, AP_EL1_RO, AP_EL1_RW, ATTR_IDX_DEVICE, ATTR_IDX_NORMAL, IO_BASE, IO_SIZE, KIMAGE_OFFSET,
    PAGE_OFFSET, PAGE_SIZE, PXN, PageTableEntry, RawPageTable, SH_INNER, UXN, VMEMMAP_START,
};

/// Page-table pages for the boot-built kernel tables
const POOL_PAGES: usize = 48;

const SZ_2M: u64 = 2 << 20;
const SZ_1G: u64 = 1 << 30;

/// RAM assumed when the DTB has no memory node (QEMU virt, -m 512M)
const DEFAULT_RAM: (u64, u64) = (0x4000_0000, 512 << 20);

impl KmapOps for Aarch64Arch {
    const KIMAGE_OFFSET: u64 = KIMAGE_OFFSET;
    const POOL_PAGES: usize = POOL_PAGES;

    fn mk_pmd(pa: u64, prot: u64) -> u64 {
        let mut n = PageTableEntry::empty();
        n.set_block(pa, prot);
        n.0
    }

    fn kmap_sync() {
        // SAFETY: barriers only (nostack): the walker sees the entry
        // before the first access
        unsafe { asm!("dsb ishst", "isb", options(nostack)) };
    }
}

/// Empty TTBR0 root for kernel threads (Linux: reserved_pg_dir)
static RESERVED: RawPageTable = RawPageTable::new();

unsafe extern "C" {
    static _text: u8;
    static _etext: u8;
    static _sdata: u8;
    static __kernel_start: u8;
    static __kernel_end: u8;
    fn __replace_ttbr1(ttbr1: u64, ttbr0: u64);
}

/// Image virtual address of a physical address inside the image
pub fn kimage_va(pa: u64) -> u64 {
    pa + KIMAGE_OFFSET
}

/// Physical address of the empty TTBR0 root
pub fn reserved_phys() -> u64 {
    pa_symbol(&raw const RESERVED as u64)
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
        let root = swapper();
        let mut end = 0;
        for r in memblock::MEMBLOCK.lock().memory.ranges() {
            end = end.max(map_linear(root, r.base, r.size()));
        }
        set_direct_end(end);
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

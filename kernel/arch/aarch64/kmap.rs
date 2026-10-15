//! Kernel page table (TTBR1, swapper_pg_dir): linear map, image, devices
//!
//! Linux arm64 48-bit layout (Documentation/arch/arm64/memory.rst):
//!
//! ```text
//! 0000000000000000 - 0000ffffffffffff  user space (TTBR0, per process)
//! ffff000000000000 - ...               linear map of RAM (PAGE_OFFSET)
//! ffff800040100000 - ...               kernel image (KIMAGE_OFFSET + phys)
//! ffff800100000000 - ffff80013fffffff  vmalloc/ioremap window
//! ffff800200000000 - ffff80023fffffff  device window (physical 0-1GB)
//! ```
//!
//! boot.S enables the MMU on coarse boot tables (1GB blocks: an identity
//! map of the kernel's RAM gigabyte in TTBR0, the first RAM gigabyte,
//! the image and the device window in TTBR1). `init` builds the final
//! TTBR1 tables once the heap exists (the DTB parser needs it) and
//! leaves TTBR0 with an empty table; user page tables only ever hold
//! user mappings. Boot-time tables come from a static pool.

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

use super::paging::{
    AF, AP_EL1_RO, AP_EL1_RW, ATTR_IDX_DEVICE, ATTR_IDX_NORMAL, IO_BASE, IO_SIZE, KIMAGE_OFFSET,
    PAGE_OFFSET, PAGE_SIZE, PXN, RawPageTable, SH_INNER, UXN, phys_to_virt_table,
};

/// Page-table pages for the boot-built kernel tables
const POOL_PAGES: usize = 48;

const SZ_2M: u64 = 2 << 20;
const SZ_1G: u64 = 1 << 30;

/// RAM assumed when the DTB has no memory node (QEMU virt, -m 512M)
const DEFAULT_RAM: (u64, u64) = (0x4000_0000, 512 << 20);

#[repr(C, align(4096))]
struct Pool([RawPageTable; POOL_PAGES]);

static mut POOL: Pool = Pool([const { RawPageTable::new() }; POOL_PAGES]);
static mut POOL_USED: usize = 0;

/// TTBR1 root (Linux: swapper_pg_dir)
static mut SWAPPER: RawPageTable = RawPageTable::new();

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

/// Physical address of the TTBR1 root
pub fn swapper_phys() -> u64 {
    pa_symbol(&raw const SWAPPER as u64)
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
    unsafe {
        assert!(POOL_USED < POOL_PAGES, "kmap: page-table pool exhausted");
        let t = &raw mut POOL.0[POOL_USED];
        POOL_USED += 1;
        pa_symbol(t as u64)
    }
}

/// Next-level table under `table[idx]`, created if absent
unsafe fn next(table: *mut RawPageTable, idx: usize) -> *mut RawPageTable {
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
/// gigabyte is RAM, else 2MB blocks (normal memory, never executable)
unsafe fn map_linear(root: *mut RawPageTable, base: u64, size: u64) {
    let attrs = AF | SH_INNER | ATTR_IDX_NORMAL | AP_EL1_RW | PXN | UXN;
    let (start, end) = (base & !(SZ_2M - 1), (base + size).next_multiple_of(SZ_2M));
    let mut p = start;
    while p < end {
        let va = PAGE_OFFSET + p;
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
    DIRECT_END.store(end, Ordering::Relaxed);
}

/// Map the kernel image with 4KB pages: text read-only executable,
/// rodata read-only, data and bss writable, neither executable (W^X)
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
unsafe fn map_io(root: *mut RawPageTable) {
    let attrs = AF | ATTR_IDX_DEVICE | AP_EL1_RW | PXN | UXN;
    unsafe {
        let l1 = next(root, idx(IO_BASE, 39));
        (*l1).entry_mut(idx(IO_BASE, 30)).set_block(0, attrs);
    }
    const { assert!(IO_SIZE == SZ_1G) };
}

/// Build the final TTBR1 tables and switch to them (TTBR0 gets the
/// empty table). Runs on the BSP after the heap is up, on the boot
/// tables.
///
/// # Safety
/// Once, on the BSP, before SMP and before any user address space.
pub unsafe fn init(dtb: u64) {
    let (base, size) = super::dtb::memory(dtb).unwrap_or(DEFAULT_RAM);
    unsafe {
        let root = &raw mut SWAPPER;
        map_linear(root, base, size);
        map_image(root);
        map_io(root);
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

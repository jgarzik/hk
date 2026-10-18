//! Kernel page table (swapper_pg_dir): direct map, kernel image, vmalloc
//!
//! Linux x86-64 4-level layout (Documentation/arch/x86/x86_64/mm.rst):
//!
//! ```text
//! 0000000000000000 - 00007fffffffefff  user space (TASK_SIZE)
//! ffff888000000000 - ...               direct map of RAM (PAGE_OFFSET)
//! ffffc90000000000 - ffffc9003fffffff  vmalloc/ioremap window
//! ffffffff80000000 - ...               kernel image (__START_KERNEL_map)
//! ```
//!
//! The kernel half (PML4 entries 256-511) is built once here and every
//! address space links the same lower-level tables (`copy_kernel_mappings`
//! copies the PML4 entries). No kernel PML4 entry is added after boot:
//! the vmalloc PDPT is preallocated, so ioremap's PD/PT changes are seen by
//! every address space (Linux: preallocate_vmalloc_pages). Boot-time
//! tables come from a static pool (the frame allocator does not exist yet).

use core::sync::atomic::{AtomicU64, Ordering};

use super::paging::{
    KERNEL_MAP, PAGE_HUGE, PAGE_NO_EXECUTE, PAGE_OFFSET, PAGE_PRESENT, PAGE_SIZE, PAGE_WRITABLE,
    RawPageTable, VMALLOC_START, phys_to_virt_table,
};
use crate::multiboot2;

/// Page-table pages for the boot-built kernel half
const POOL_PAGES: usize = 64;

const SZ_2M: u64 = 2 << 20;
const SZ_1G: u64 = 1 << 30;

#[repr(C, align(4096))]
struct Pool([RawPageTable; POOL_PAGES]);

static mut POOL: Pool = Pool([const { RawPageTable::new() }; POOL_PAGES]);
static mut POOL_USED: usize = 0;

/// The kernel's top-level table (Linux: swapper_pg_dir / init_top_pgt)
static mut SWAPPER: RawPageTable = RawPageTable::new();

/// End of the direct map (physical): RAM above it is not mapped
static DIRECT_END: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" {
    static _text: u8;
    static _etext: u8;
    static __end_rodata: u8;
    static _sdata: u8;
    static __kernel_start: u8;
    static __kernel_end: u8;
    static boot_pml4: u8;
}

/// Physical address of a kernel image symbol (Linux: __pa_symbol)
pub fn pa_symbol(va: u64) -> u64 {
    va - KERNEL_MAP
}

/// The kernel image in physical memory, as [start, end)
pub fn image_range() -> (u64, u64) {
    let start = pa_symbol(&raw const __kernel_start as u64);
    (start, pa_symbol(&raw const __kernel_end as u64))
}

/// Physical address of the kernel top-level table
pub fn swapper_phys() -> u64 {
    pa_symbol(&raw const SWAPPER as u64)
}

/// Physical end of the direct map
pub fn direct_end() -> u64 {
    DIRECT_END.load(Ordering::Relaxed)
}

/// A zeroed page-table page from the pool, as (virt, phys)
fn pool_page() -> (*mut RawPageTable, u64) {
    unsafe {
        assert!(POOL_USED < POOL_PAGES, "kmap: page-table pool exhausted");
        let t = &raw mut POOL.0[POOL_USED];
        POOL_USED += 1;
        (t, pa_symbol(t as u64))
    }
}

/// Next-level table under `table[idx]`, created if absent
unsafe fn next(table: *mut RawPageTable, idx: usize) -> *mut RawPageTable {
    unsafe {
        let e = (*table).entry_mut(idx);
        if !e.is_present() {
            let (_, phys) = pool_page();
            e.set(phys, PAGE_PRESENT | PAGE_WRITABLE);
        }
        phys_to_virt_table(e.addr())
    }
}

fn idx(va: u64, shift: u32) -> usize {
    ((va >> shift) & 511) as usize
}

/// CPU supports 1GB pages (CPUID 0x80000001 EDX.Page1GB)
fn gbpages() -> bool {
    let r = core::arch::x86_64::__cpuid(0x8000_0001);
    r.edx & (1 << 26) != 0
}

/// RAM ranges for the direct map: available, ACPI and NVS memory plus
/// the first 1MB (BIOS data, VGA text buffer, AP trampoline)
fn ram_ranges(mbi: u64, out: &mut [(u64, u64); 32]) -> usize {
    out[0] = (0, 1 << 20);
    let mut n = 1;
    unsafe {
        multiboot2::for_each_region(mbi, |base, len, kind| {
            if matches!(kind, 1 | 3 | 4) && n < out.len() {
                out[n] = (
                    base,
                    base.saturating_add(len)
                        .min(crate::mm::memblock::PHYS_LIMIT),
                );
                n += 1;
            }
        });
    }
    n
}

fn hits(r: &[(u64, u64)], start: u64, end: u64) -> bool {
    r.iter().any(|&(s, e)| s < end && start < e)
}

/// Direct map every 2MB chunk that holds RAM, with 1GB pages where a
/// whole gigabyte is RAM and the CPU allows it
unsafe fn map_direct(pml4: *mut RawPageTable, ram: &[(u64, u64)]) {
    let top = ram.iter().map(|r| r.1).max().unwrap_or(0);
    // Each gigabyte may need a PD; keep a reserve for image and vmalloc
    let cap = ((POOL_PAGES as u64 - 16) * SZ_1G).min(top.next_multiple_of(SZ_2M));
    let flags = PAGE_PRESENT | PAGE_WRITABLE | PAGE_NO_EXECUTE;
    let gb = gbpages();
    let mut end = 0;
    let mut base = 0;
    while base < cap {
        let va = PAGE_OFFSET + base;
        unsafe {
            let pdpt = next(pml4, idx(va, 39));
            let whole = (0..512).all(|i| hits(ram, base + i * SZ_2M, base + (i + 1) * SZ_2M));
            if gb && whole && base + SZ_1G <= cap {
                (*pdpt).entry_mut(idx(va, 30)).set(base, flags | PAGE_HUGE);
                end = base + SZ_1G;
            } else {
                let pd = next(pdpt, idx(va, 30));
                for i in 0..512u64 {
                    let p = base + i * SZ_2M;
                    if p < cap && hits(ram, p, p + SZ_2M) {
                        (*pd).entry_mut(i as usize).set(p, flags | PAGE_HUGE);
                        end = p + SZ_2M;
                    }
                }
            }
        }
        base += SZ_1G;
    }
    DIRECT_END.store(end, Ordering::Relaxed);
}

/// Map the kernel image with 4KB pages: text read-only executable,
/// rodata read-only, data and bss writable, neither executable (W^X)
unsafe fn map_image(pml4: *mut RawPageTable) {
    let text = &raw const _text as u64;
    let etext = &raw const _etext as u64;
    let erodata = &raw const __end_rodata as u64;
    let sdata = &raw const _sdata as u64;
    let mut va = &raw const __kernel_start as u64;
    let end = &raw const __kernel_end as u64;
    while va < end {
        let flags = if (text..etext).contains(&va) {
            PAGE_PRESENT
        } else if va >= sdata {
            PAGE_PRESENT | PAGE_WRITABLE | PAGE_NO_EXECUTE
        } else {
            debug_assert!(va < erodata || va >= sdata);
            PAGE_PRESENT | PAGE_NO_EXECUTE
        };
        unsafe {
            let pdpt = next(pml4, idx(va, 39));
            let pd = next(pdpt, idx(va, 30));
            let pt = next(pd, idx(va, 21));
            (*pt).entry_mut(idx(va, 12)).set(pa_symbol(va), flags);
        }
        va += PAGE_SIZE;
    }
}

/// Build the kernel page table and switch to it, dropping the boot
/// identity map. Runs first thing on the BSP, on the boot tables.
///
/// # Safety
/// Once, on the BSP, before anything uses the direct map past 4GB.
pub unsafe fn init(mbi: u64) {
    let mut ram = [(0u64, 0u64); 32];
    let n = ram_ranges(mbi, &mut ram);
    unsafe {
        let pml4 = &raw mut SWAPPER;
        map_direct(pml4, &ram[..n]);
        map_image(pml4);
        // vmalloc/ioremap PDPT: present before any address space copies
        next(pml4, idx(VMALLOC_START, 39));
        core::arch::asm!("mov cr3, {}", in(reg) swapper_phys(), options(nostack));
    }
}

/// Page table for the AP trampoline: the boot table's identity map of
/// low memory plus the kernel half (the trampoline enables paging at
/// its low physical address, then jumps to the high-half entry)
pub fn trampoline_pgd() -> u64 {
    let phys = &raw const boot_pml4 as u64;
    unsafe {
        let boot = phys_to_virt_table(phys);
        let swapper = &raw const SWAPPER;
        for i in 256..512 {
            *(*boot).entry_mut(i) = *(*swapper).entry(i);
        }
    }
    phys
}

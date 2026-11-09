//! Kernel page table (swapper_pg_dir): direct map, kernel image, vmalloc
//!
//! Linux x86-64 4-level layout (Documentation/arch/x86/x86_64/mm.rst):
//!
//! ```text
//! 0000000000000000 - 00007fffffffefff  user space (TASK_SIZE)
//! ffff888000000000 - ...               direct map of RAM (PAGE_OFFSET)
//! ffffc90000000000 - ffffc9003fffffff  vmalloc/ioremap window
//! ffffc90040000000 - ffffc9005fffffff  kernel stacks (mm::vmstack)
//! ffffc90100000000 - ffffc904ffffffff  vmalloc allocations (mm::vmalloc)
//! ffffffff80000000 - ...               kernel image (__START_KERNEL_map)
//! ```
//!
//! The kernel half (PML4 entries 256-511) is built once here and every
//! address space links the same lower-level tables (`copy_kernel_mappings`
//! copies the PML4 entries). No kernel PML4 entry is added after boot:
//! the vmalloc PDPT is preallocated, so ioremap's PD/PT changes are seen by
//! every address space (Linux: preallocate_vmalloc_pages). Boot-time
//! tables come from a static pool (the frame allocator does not exist yet).

use crate::arch::{IoremapOps, KmapOps};
use crate::mm::swapper::{idx, next, pa_symbol, set_direct_end, swapper, swapper_phys};

use super::X86_64Arch;
use super::paging::{
    KERNEL_MAP, PAGE_HUGE, PAGE_NO_EXECUTE, PAGE_OFFSET, PAGE_PRESENT, PAGE_SIZE, PAGE_WRITABLE,
    RawPageTable, VMALLOC_START, VMEMMAP_START, phys_to_virt_table,
};
use crate::arch::x86_64::multiboot2;

/// Page-table pages for the boot-built kernel half
const POOL_PAGES: usize = 64;

const SZ_2M: u64 = 2 << 20;
const SZ_1G: u64 = 1 << 30;

impl KmapOps for X86_64Arch {
    const KIMAGE_OFFSET: u64 = KERNEL_MAP;
    const POOL_PAGES: usize = POOL_PAGES;

    fn mk_pmd(pa: u64, prot: u64) -> u64 {
        Self::mk_pte(pa, prot) | PAGE_HUGE
    }
}

unsafe extern "C" {
    static _text: u8;
    static _etext: u8;
    static __end_rodata: u8;
    static _sdata: u8;
    static __kernel_start: u8;
    static __kernel_end: u8;
    static boot_pml4: u8;
}

/// CPU supports 1GB pages (CPUID 0x80000001 EDX.Page1GB)
fn gbpages() -> bool {
    let r = core::arch::x86_64::__cpuid(0x8000_0001);
    r.edx & (1 << 26) != 0
}

/// Physical RAM for the direct map: [start, end) ranges, any order
trait RamMap {
    fn each(&self, f: &mut dyn FnMut(u64, u64));

    /// The 2MB chunks of the gigabyte at `base` some range overlaps,
    /// as a 512-bit set (bit i: [base + i * 2MB, base + (i + 1) * 2MB));
    /// one pass over the ranges per gigabyte
    fn chunks(&self, base: u64) -> [u64; 8] {
        let mut set = [0u64; 8];
        self.each(&mut |s, e| {
            let (s, e) = (s.max(base), e.min(base + SZ_1G));
            if s < e {
                for i in (s - base) / SZ_2M..(e - base).div_ceil(SZ_2M) {
                    set[i as usize / 64] |= 1 << (i % 64);
                }
            }
        });
        set
    }

    /// End of the highest range
    fn top(&self) -> u64 {
        let mut top = 0;
        self.each(&mut |_, e| top = top.max(e));
        top
    }
}

/// The boot memory map: available, ACPI and NVS memory plus the first
/// 1MB (BIOS data, VGA text buffer, AP trampoline). Read in place, as
/// many regions as firmware reports (no copy to a fixed array).
struct BootRam;

impl RamMap for BootRam {
    fn each(&self, f: &mut dyn FnMut(u64, u64)) {
        f(0, 1 << 20);
        multiboot2::for_each_region(|base, len, kind| {
            if matches!(kind, 1 | 3 | 4) {
                let end = base.saturating_add(len);
                f(base, end.min(crate::mm::memblock::PHYS_LIMIT));
            }
        });
    }
}

/// The large pages of the direct map below `cap`, ascending, as
/// (phys, 1GB page?): every 2MB chunk that holds RAM, a whole gigabyte
/// of RAM as one 1GB page where `gb`
fn direct_pages(ram: &dyn RamMap, gb: bool, cap: u64, mut page: impl FnMut(u64, bool)) {
    let mut base = 0;
    while base < cap {
        let set = ram.chunks(base);
        if gb && set.iter().all(|&w| w == u64::MAX) && base + SZ_1G <= cap {
            page(base, true);
        } else {
            for i in 0..512u64 {
                let p = base + i * SZ_2M;
                if p < cap && set[i as usize / 64] & (1 << (i % 64)) != 0 {
                    page(p, false);
                }
            }
        }
        base += SZ_1G;
    }
}

/// Direct map every 2MB chunk that holds RAM, with 1GB pages where a
/// whole gigabyte is RAM and the CPU allows it. Past the page-table
/// pool's reach nothing is mapped, and memblock drops that RAM
/// (`direct_end`).
///
/// # Safety
/// As [`next`] for `pml4`.
unsafe fn map_direct(pml4: *mut RawPageTable, ram: &dyn RamMap) {
    // Each gigabyte may need a PD; keep a reserve for image and vmalloc
    let cap = ((POOL_PAGES as u64 - 16) * SZ_1G).min(ram.top().next_multiple_of(SZ_2M));
    let flags = PAGE_PRESENT | PAGE_WRITABLE | PAGE_NO_EXECUTE;
    let mut end = 0;
    direct_pages(ram, gbpages(), cap, |p, huge_gb| {
        let va = PAGE_OFFSET + p;
        // SAFETY: `pml4` and the tables `next` returns are boot tables
        // (this fn's contract, `next`'s), single CPU
        unsafe {
            let pdpt = next(pml4, idx(va, 39));
            if huge_gb {
                (*pdpt).entry_mut(idx(va, 30)).set(p, flags | PAGE_HUGE);
                end = p + SZ_1G;
            } else {
                let pd = next(pdpt, idx(va, 30));
                (*pd).entry_mut(idx(va, 21)).set(p, flags | PAGE_HUGE);
                end = p + SZ_2M;
            }
        }
    });
    set_direct_end(end);
}

/// Map the kernel image with 4KB pages: text read-only executable,
/// rodata read-only, data and bss writable, neither executable (W^X)
///
/// # Safety
/// As [`next`] for `pml4`.
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
        // SAFETY: as in `map_direct`
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
pub unsafe fn init() {
    // SAFETY: once on the BSP (this fn's contract): the swapper is a
    // boot table nothing else reaches yet. The CR3 write switches to
    // it: it maps the running image and the direct map the boot code
    // uses (nostack: no stack use; memory ordering kept, no nomem)
    unsafe {
        let pml4 = swapper();
        map_direct(pml4, &BootRam);
        map_image(pml4);
        // vmalloc/ioremap and vmemmap PDPTs: present before any address
        // space copies the kernel half
        next(pml4, idx(VMALLOC_START, 39));
        next(pml4, idx(VMEMMAP_START, 39));
        core::arch::asm!("mov cr3, {}", in(reg) swapper_phys(), options(nostack));
    }
}

/// Page table for the AP trampoline: the boot table's identity map of
/// low memory plus the kernel half (the trampoline enables paging at
/// its low physical address, then jumps to the high-half entry)
pub fn trampoline_pgd() -> u64 {
    let phys = &raw const boot_pml4 as u64;
    // SAFETY: the boot PML4 (a linker symbol, reached through the
    // direct map) is used only by AP startup, which this precedes; the
    // swapper's kernel half is read only
    unsafe {
        let boot = phys_to_virt_table(phys);
        let top = swapper().cast_const();
        for i in 256..512 {
            *(*boot).entry_mut(i) = *(*top).entry(i);
        }
    }
    phys
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RAM in a slice of ranges
    struct Ranges<'a>(&'a [(u64, u64)]);

    impl RamMap for Ranges<'_> {
        fn each(&self, f: &mut dyn FnMut(u64, u64)) {
            self.0.iter().for_each(|&(s, e)| f(s, e));
        }
    }

    /// Every region is mapped however many the firmware reports (UEFI
    /// maps have hundreds; the direct map once kept only 31): each
    /// 2MB chunk with RAM, nothing else
    #[test]
    fn direct_map_covers_every_region() {
        let ram: Vec<(u64, u64)> = (0..100u64)
            .map(|i| (i * 8 * SZ_2M + 4096, i * 8 * SZ_2M + 3 * SZ_2M))
            .collect();
        let r = Ranges(&ram);
        let cap = r.top().next_multiple_of(SZ_2M);
        let mut pages = Vec::new();
        direct_pages(&r, true, cap, |p, gb| pages.push((p, gb)));
        let want: Vec<(u64, bool)> = (0..100u64)
            .flat_map(|i| (0..3).map(move |k| ((i * 8 + k) * SZ_2M, false)))
            .collect();
        assert_eq!(pages, want);
    }

    /// A whole gigabyte of RAM is one 1GB page when the CPU has them
    #[test]
    fn direct_map_gb_pages() {
        let ram = [(0, 2 * SZ_1G + SZ_2M)];
        let r = Ranges(&ram);
        let cap = r.top().next_multiple_of(SZ_2M);
        let mut pages = Vec::new();
        direct_pages(&r, true, cap, |p, gb| pages.push((p, gb)));
        assert_eq!(pages, [(0, true), (SZ_1G, true), (2 * SZ_1G, false)]);
        pages.clear();
        direct_pages(&r, false, cap, |p, gb| pages.push((p, gb)));
        assert_eq!(pages.len(), 1025);
    }
}

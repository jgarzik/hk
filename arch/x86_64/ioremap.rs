//! Kernel page-table primitives behind `mm::ioremap` (Linux
//! arch/x86/include/asm/pgtable_types.h): 4-level entries, MMIO
//! uncached (PCD|PWT)

use crate::arch::IoremapOps;

use super::X86_64Arch;
use super::paging::{
    PAGE_CACHE_DISABLE, PAGE_HUGE, PAGE_NO_EXECUTE, PAGE_PRESENT, PAGE_WRITABLE,
    PAGE_WRITE_THROUGH, PTE_ADDR_MASK,
};

impl IoremapOps for X86_64Arch {
    const PROT_KERNEL: u64 = PAGE_PRESENT | PAGE_WRITABLE | PAGE_NO_EXECUTE;
    const PROT_DEVICE: u64 =
        PAGE_PRESENT | PAGE_WRITABLE | PAGE_NO_EXECUTE | PAGE_CACHE_DISABLE | PAGE_WRITE_THROUGH;
    /// x86 caches no not-present entry
    const FLUSH_NEW: bool = false;

    fn swapper_phys() -> u64 {
        super::kmap::swapper_phys()
    }

    fn pte_present(e: u64) -> bool {
        e & PAGE_PRESENT != 0
    }

    fn pte_is_table(e: u64) -> bool {
        e & (PAGE_PRESENT | PAGE_HUGE) == PAGE_PRESENT
    }

    fn pte_addr(e: u64) -> u64 {
        e & PTE_ADDR_MASK
    }

    fn mk_table(t: u64) -> u64 {
        t | PAGE_PRESENT | PAGE_WRITABLE
    }

    fn mk_pte(pa: u64, prot: u64) -> u64 {
        (pa & PTE_ADDR_MASK) | prot
    }
}

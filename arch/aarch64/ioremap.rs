//! Kernel page-table primitives behind `mm::ioremap` (Linux
//! arch/arm64/include/asm/pgtable.h): TTBR1 descriptors, and the
//! permanent device window over physical 0-1GB (`kmap::map_io`)

use core::arch::asm;
use core::sync::atomic::AtomicU64;

use crate::arch::IoremapOps;

use super::Aarch64Arch;
use super::paging::{
    AF, AP_EL1_RW, ATTR_IDX_DEVICE, ATTR_IDX_NORMAL, IO_BASE, IO_SIZE, PXN, PageTableEntry,
    SH_INNER, UXN, io_va,
};

impl IoremapOps for Aarch64Arch {
    const PROT_KERNEL: u64 = AF | SH_INNER | ATTR_IDX_NORMAL | AP_EL1_RW | PXN | UXN;
    const PROT_DEVICE: u64 = AF | SH_INNER | ATTR_IDX_DEVICE | AP_EL1_RW | PXN | UXN;
    const FLUSH_NEW: bool = true;

    fn swapper_phys() -> u64 {
        super::kmap::swapper_phys()
    }

    fn pte_present(e: u64) -> bool {
        PageTableEntry(e).is_valid()
    }

    fn pte_is_table(e: u64) -> bool {
        PageTableEntry(e).is_table()
    }

    fn pte_addr(e: u64) -> u64 {
        PageTableEntry(e).addr()
    }

    fn mk_table(t: u64) -> u64 {
        let mut n = PageTableEntry::empty();
        n.set_table(t);
        n.0
    }

    fn mk_pte(pa: u64, prot: u64) -> u64 {
        let mut n = PageTableEntry::empty();
        n.set_page(pa, prot);
        n.0
    }

    /// Clean the entry to the point of unification, then a barrier
    fn sync_pte(e: &AtomicU64) {
        let addr = e.as_ptr().addr();
        // SAFETY: a cache clean by VA of a live table entry, and a
        // barrier: no Rust-visible memory changes (nostack: no stack use)
        unsafe { asm!("dc cvau, {}", "dsb ish", in(reg) addr, options(nostack)) };
    }

    /// The device window maps physical 0-1GB
    fn io_window(phys: u64, size: u64) -> Option<u64> {
        (phys + size <= IO_SIZE).then(|| io_va(phys))
    }

    fn in_io_window(va: u64) -> bool {
        (IO_BASE..IO_BASE + IO_SIZE).contains(&va)
    }
}

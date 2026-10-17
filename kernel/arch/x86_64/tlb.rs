//! x86-64 TLB primitives for `mm::tlb` (Linux arch/x86/include/asm/tlbflush.h)
//!
//! No PCID and no global pages (CR4.PGE clear): a CR3 write drops every
//! translation of this CPU, user and kernel, and paging-structure
//! caches with them. Other CPUs are only reached by IPI (`mm::tlb`
//! shootdown): the hardware broadcasts nothing.

/// Per-address-space arch state: none without PCID
pub struct ArchCtx;

impl ArchCtx {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for ArchCtx {
    fn default() -> Self {
        Self::new()
    }
}

/// A range flush of more pages than this flushes everything (Linux
/// tlb_single_page_flush_ceiling)
pub const FLUSH_CEILING: u64 = 33;

/// Invalidate this CPU's translation of `va` (all levels: INVLPG also
/// drops the paging-structure caches of the current address space)
#[inline]
pub fn local_flush_one(va: u64) {
    // SAFETY: TLB maintenance only
    unsafe { core::arch::asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags)) };
}

/// Invalidate every translation of this CPU (CR3 reload; no global
/// pages)
#[inline]
pub fn local_flush_all() {
    // SAFETY: reloads the current table
    unsafe {
        core::arch::asm!(
            "mov {t}, cr3",
            "mov cr3, {t}",
            t = out(reg) _,
            options(nostack, preserves_flags)
        )
    };
}

/// Hardware-broadcast flush of a user range: x86 has none, the caller
/// shoots the CPUs of the mm's cpumask down
#[inline]
pub fn flush_mm_range(_ctx: &ArchCtx, _start: u64, _end: u64, _shift: u32, _tables: bool) -> bool {
    false
}

/// Hardware-broadcast flush of a kernel range: none on x86 (IPIs)
#[inline]
pub fn flush_kernel_range(_start: u64, _end: u64) -> bool {
    false
}

/// Load the table `root` on this CPU (interrupts disabled): the CR3
/// write flushes everything, so the new address space starts with no
/// stale entry
#[inline]
pub fn load_mm(root: u64, _ctx: Option<&ArchCtx>) {
    // SAFETY: `root` is a live top-level table with the kernel half
    unsafe { core::arch::asm!("mov cr3, {}", in(reg) root, options(nostack, preserves_flags)) };
}

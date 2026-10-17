//! AArch64 TLB primitives for `mm::tlb` (Linux
//! arch/arm64/include/asm/tlbflush.h)
//!
//! TLB maintenance is broadcast by hardware: a `TLBI ...IS` reaches every
//! CPU of the inner-shareable domain and the DSB ISH after it waits until
//! all of them have completed it, so no IPI and no wait on another CPU's
//! software is ever needed (nor possible to deadlock).

use core::arch::asm;

/// Per-address-space arch state
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

/// A range flush of more pages than this flushes the whole address
/// space (Linux MAX_DVM_OPS = PTRS_PER_PTE)
pub const FLUSH_CEILING: u64 = 512;

/// TLBI operand for `va`: VA[55:12]
#[inline]
fn tlbi_va(va: u64) -> u64 {
    (va >> 12) & ((1 << 44) - 1)
}

/// Invalidate this CPU's translation of `va` (local only)
#[inline]
pub fn local_flush_one(va: u64) {
    // SAFETY: TLB maintenance only
    unsafe {
        asm!("dsb nshst", "tlbi vae1, {}", "dsb nsh", "isb", in(reg) tlbi_va(va), options(nostack))
    };
}

/// Invalidate every translation of this CPU (local only)
#[inline]
pub fn local_flush_all() {
    // SAFETY: TLB maintenance only
    unsafe {
        asm!(
            "dsb nshst",
            "tlbi vmalle1",
            "dsb nsh",
            "isb",
            options(nostack)
        )
    };
}

/// Broadcast-invalidate the user translations of [start, end), one per
/// `1 << shift` bytes, on every CPU (Linux __flush_tlb_range): the
/// last-level form unless page tables were freed, the whole address
/// space past `FLUSH_CEILING` entries. Always handled here (true).
pub fn flush_mm_range(ctx: &ArchCtx, start: u64, end: u64, shift: u32, tables: bool) -> bool {
    let n = end.saturating_sub(start) >> shift;
    if end == u64::MAX || n > FLUSH_CEILING {
        flush_mm(ctx);
        return true;
    }
    // SAFETY: TLB maintenance only; PTE stores complete first
    unsafe { asm!("dsb ishst", options(nostack)) };
    let mut va = start & !((1 << shift) - 1);
    while va < end {
        // SAFETY: as above
        unsafe {
            if tables {
                asm!("tlbi vae1is, {}", in(reg) tlbi_va(va), options(nostack));
            } else {
                asm!("tlbi vale1is, {}", in(reg) tlbi_va(va), options(nostack));
            }
        }
        va += 1 << shift;
    }
    // SAFETY: barriers only
    unsafe { asm!("dsb ish", "isb", options(nostack)) };
    true
}

/// Broadcast-invalidate every user translation of an address space
fn flush_mm(_ctx: &ArchCtx) {
    // SAFETY: TLB maintenance only
    unsafe {
        asm!(
            "dsb ishst",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            options(nostack)
        )
    };
}

/// Broadcast-invalidate the kernel translations of [start, end) on every
/// CPU (Linux flush_tlb_kernel_range: all ASIDs). Always handled (true).
pub fn flush_kernel_range(start: u64, end: u64) -> bool {
    if end.saturating_sub(start) >> 12 > FLUSH_CEILING {
        // SAFETY: TLB maintenance only
        unsafe {
            asm!(
                "dsb ishst",
                "tlbi vmalle1is",
                "dsb ish",
                "isb",
                options(nostack)
            )
        };
        return true;
    }
    // SAFETY: TLB maintenance only
    unsafe { asm!("dsb ishst", options(nostack)) };
    let mut va = start & !0xfff;
    while va < end {
        // SAFETY: as above
        unsafe { asm!("tlbi vaae1is, {}", in(reg) tlbi_va(va), options(nostack)) };
        va += 0x1000;
    }
    // SAFETY: barriers only
    unsafe { asm!("dsb ish", "isb", options(nostack)) };
    true
}

/// Load the user table `root` into TTBR0 on this CPU (interrupts
/// disabled). Without ASIDs every user translation is global and
/// shared by all address spaces, so they all go (broadcast) and the
/// instruction caches with them.
pub fn load_mm(root: u64, _ctx: Option<&ArchCtx>) {
    // SAFETY: `root` is a live user table (or the empty one)
    unsafe {
        asm!(
            "msr ttbr0_el1, {}",
            "isb",
            "tlbi vmalle1is",
            "ic iallu",
            "dsb sy",
            "isb",
            in(reg) root,
            options(nostack)
        )
    };
}

//! AArch64 TLB primitives for `mm::tlb` (Linux
//! arch/arm64/include/asm/tlbflush.h)
//!
//! TLB maintenance is broadcast by hardware: a `TLBI ...IS` reaches every
//! CPU of the inner-shareable domain and the DSB ISH after it waits until
//! all of them have completed it, so no IPI and no wait on another CPU's
//! software is ever needed (nor possible to deadlock).
//!
//! Address spaces are tagged with ASIDs (`mm::asid`, Linux
//! arch/arm64/mm/context.c): TTBR0 carries the ASID (TCR_EL1.A1 = 0;
//! Linux puts it in TTBR1 for KPTI/SW PAN, which hk has neither of), user
//! entries are non-global (nG), so a switch flushes nothing; flushes of
//! one address space name its ASID. ASID 0 is never handed out: kernel
//! threads run on the empty table with it, and only global (kernel)
//! entries exist there.

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::mm::asid::AsidAlloc;

/// The machine's ASIDs (8-bit until `init_cpu` finds 16)
static ASIDS: AsidAlloc = AsidAlloc::new(8);

/// Per-address-space arch state: `generation | asid`, 0 until it first
/// runs (Linux mm->context.id)
pub struct ArchCtx {
    id: AtomicU64,
}

impl ArchCtx {
    pub const fn new() -> Self {
        Self {
            id: AtomicU64::new(0),
        }
    }

    /// TLBI operand bits of the ASID (bits 63:48); ASID 0 before the
    /// first run, which tags no user entry
    fn asid(&self) -> u64 {
        ASIDS.asid(self.id.load(Ordering::Relaxed)) << 48
    }
}

/// TCR_EL1.AS: 16-bit ASIDs
const TCR_AS: u64 = 1 << 36;

/// Per-CPU ASID setup (each CPU, before any user address space runs
/// there): 16-bit ASIDs when ID_AA64MMFR0_EL1.ASIDBits says so (the
/// boot CPU decides for all), then a local flush of the old tagging
pub fn init_cpu() {
    let mmfr0: u64;
    // SAFETY: reads an ID register
    unsafe { asm!("mrs {}, id_aa64mmfr0_el1", out(reg) mmfr0, options(nomem, nostack)) };
    let wide = (mmfr0 >> 4) & 0xf == 0b0010;
    static SIZED: AtomicBool = AtomicBool::new(false);
    if !SIZED.swap(true, Ordering::Relaxed) {
        // LOCKDEP builds use 31 ASIDs only (more than CPUs, as a
        // rollover keeps one per CPU), so the boot tests roll the
        // generation over again and again on real switches
        let bits = if cfg!(feature = "lockdep") {
            5
        } else if wide {
            16
        } else {
            8
        };
        ASIDS.set_bits(bits);
    }
    if wide {
        // SAFETY: only the ASID width changes; flushed below
        unsafe {
            asm!(
                "mrs {t}, tcr_el1",
                "orr {t}, {t}, {as_}",
                "msr tcr_el1, {t}",
                "isb",
                t = out(reg) _,
                as_ = in(reg) TCR_AS,
                options(nostack)
            )
        };
    }
    local_flush_all();
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
    let asid = ctx.asid();
    // SAFETY: TLB maintenance only; PTE stores complete first
    unsafe { asm!("dsb ishst", options(nostack)) };
    let mut va = start & !((1 << shift) - 1);
    while va < end {
        let op = asid | tlbi_va(va);
        // SAFETY: as above
        unsafe {
            if tables {
                asm!("tlbi vae1is, {}", in(reg) op, options(nostack));
            } else {
                asm!("tlbi vale1is, {}", in(reg) op, options(nostack));
            }
        }
        va += 1 << shift;
    }
    // SAFETY: barriers only
    unsafe { asm!("dsb ish", "isb", options(nostack)) };
    true
}

/// Broadcast-invalidate every user translation of an address space (its
/// ASID; Linux flush_tlb_mm)
fn flush_mm(ctx: &ArchCtx) {
    // SAFETY: TLB maintenance only
    unsafe {
        asm!(
            "dsb ishst",
            "tlbi aside1is, {}",
            "dsb ish",
            "isb",
            in(reg) ctx.asid(),
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

/// This CPU's first switch since an ASID rollover: drop every
/// translation, and the instruction cache too: on an ASID-tagged VIVT
/// I-cache (CTR_EL0.L1Ip AIVIVT) lines carry the ASID, so an address
/// space given a reused ASID could hit the previous owner's code at the
/// same address (old Linux flush_context: icache_is_aivivt). Rollovers
/// are rare: done on every I-cache kind.
fn rollover_flush() {
    local_flush_all();
    // SAFETY: cache maintenance only
    unsafe { asm!("ic iallu", "dsb nsh", "isb", options(nostack)) };
}

/// Load the user table `root` into TTBR0 on this CPU (interrupts
/// disabled) with the address space's ASID (Linux
/// check_and_switch_context + cpu_switch_mm): no flush, unless an ASID
/// rollover asks this CPU for one; no instruction-cache maintenance
/// either (done where a page becomes executable: `paging::sync_page`). Kernel threads (`ctx` None) run on
/// the empty table with ASID 0.
pub fn load_mm(root: u64, ctx: Option<&ArchCtx>) {
    let asid = match ctx {
        Some(c) => {
            let cpu = crate::cpu::this_id();
            let (asid, flush) = ASIDS.switch(cpu, &c.id);
            if flush {
                rollover_flush();
            }
            asid
        }
        None => 0,
    };
    // SAFETY: `root` is a live user table (or the empty one); table and
    // ASID change together in one TTBR0 write
    unsafe {
        asm!(
            "msr ttbr0_el1, {}",
            "isb",
            in(reg) root | (asid << 48),
            options(nostack)
        )
    };
}

//! AArch64 user memory access
//!
//! Provides safe user-space memory access with PAN (Privileged Access Never)
//! protection. On ARMv8.1+, PAN prevents kernel from accidentally accessing
//! user memory without explicit permission.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::uaccess::UaccessArch;

/// PAN is implemented and enabled (set once by the boot CPU; every CPU of
/// a system has the same feature set)
static PAN_ENABLED: AtomicBool = AtomicBool::new(false);

// `msr pan, #imm` (ARMv8.1 FEAT_PAN) as raw encodings, so the kernel
// assembles for a v8.0 baseline: MSR (immediate), op1=0, op2=4, CRm=imm
macro_rules! msr_pan_0 {
    () => {
        ".inst 0xd500409f"
    };
}
macro_rules! msr_pan_1 {
    () => {
        ".inst 0xd500419f"
    };
}

/// Enable PAN (Privileged Access Never) on this CPU if implemented
/// (Linux: cpu_enable_pan)
///
/// With PSTATE.PAN set, EL1 loads/stores to EL0-accessible pages fault,
/// so only the uaccess helpers (which clear PAN around the copy) can touch
/// user memory. SCTLR_EL1.SPAN=0 makes every exception entry to EL1 set
/// PAN, and ERET restores the interrupted context's PAN from SPSR.
/// Call on each CPU before it runs user tasks.
pub fn pan_init_cpu() {
    let mmfr1: u64;
    // SAFETY: reading an ID register has no side effects
    unsafe {
        core::arch::asm!("mrs {}, id_aa64mmfr1_el1", out(reg) mmfr1, options(nomem, nostack));
    }
    // ID_AA64MMFR1_EL1.PAN, bits [23:20]: 0 = not implemented
    if (mmfr1 >> 20) & 0xf == 0 {
        return;
    }
    // SAFETY: clearing SCTLR_EL1.SPAN (bit 23) and setting PSTATE.PAN only
    // restrict EL1 access to EL0-accessible pages; kernel mappings are
    // EL1-only and user accesses go through hk_copy_user with PAN cleared.
    unsafe {
        core::arch::asm!(
            "mrs {t}, sctlr_el1",
            "bic {t}, {t}, #(1 << 23)",
            "msr sctlr_el1, {t}",
            "isb",
            msr_pan_1!(),
            t = out(reg) _,
            options(nostack),
        );
    }
    PAN_ENABLED.store(true, Ordering::Relaxed);
}

/// Whether PAN is enabled (for diagnostics)
pub fn pan_enabled() -> bool {
    PAN_ENABLED.load(Ordering::Relaxed)
}

/// AArch64 user access implementation
pub struct Aarch64Uaccess;

impl UaccessArch for Aarch64Uaccess {
    const TASK_SIZE: u64 = super::paging::TASK_SIZE;

    /// Begin user access (disable PAN if available)
    ///
    /// This temporarily allows kernel access to user memory.
    /// Also ensures any prior TLB/cache maintenance is complete.
    #[inline(always)]
    unsafe fn user_access_begin() {
        // Ensure any prior TLB invalidations or page table updates are complete
        // before we access user memory. This is particularly important on ARM
        // where memory ordering is weaker than x86.
        //
        // SAFETY: dsb ish is a data synchronization barrier that ensures all
        // prior memory accesses are complete before proceeding.
        unsafe {
            core::arch::asm!("dsb ish", options(nostack, preserves_flags));
        }

        // Clear PSTATE.PAN so EL1 may access user pages (ARMv8.1+; no-op
        // on CPUs without PAN, e.g. cortex-a72)
        if PAN_ENABLED.load(Ordering::Relaxed) {
            // SAFETY: re-set by user_access_end()
            unsafe {
                core::arch::asm!(msr_pan_0!(), options(nostack, preserves_flags));
            }
        }
    }

    /// Fault-tolerant copy; returns the number of bytes NOT copied
    #[inline(always)]
    unsafe fn copy_user_raw(dst: *mut u8, src: *const u8, len: usize) -> usize {
        unsafe { hk_copy_user(dst, src, len) }
    }

    /// End user access (re-enable PAN if available)
    ///
    /// This restores protection against accidental user memory access.
    /// Also ensures all user memory accesses are complete before proceeding.
    #[inline(always)]
    unsafe fn user_access_end() {
        // Ensure all user memory accesses complete before continuing
        //
        // SAFETY: dsb ish is a data synchronization barrier that ensures all
        // prior memory accesses are complete before proceeding.
        unsafe {
            core::arch::asm!("dsb ish", options(nostack, preserves_flags));
        }

        // Set PSTATE.PAN again: user pages are off limits to EL1
        if PAN_ENABLED.load(Ordering::Relaxed) {
            // SAFETY: setting PAN only restricts EL1 accesses
            unsafe {
                core::arch::asm!(msr_pan_1!(), options(nostack, preserves_flags));
            }
        }
    }
}

// Fault-tolerant user copy (Linux: __arch_copy_to_user + USER() extable).
// x0=dst, x1=src, x2=len. Loads/stores have no effect when they fault, so
// on an unresolvable fault x2 is the (conservative) remaining byte count and
// the fixup returns it.
core::arch::global_asm!(
    ".pushsection .text.hk_copy_user, \"ax\"",
    ".global hk_copy_user",
    "hk_copy_user:",
    ".global hk_copy_user_start",
    "hk_copy_user_start:",
    "1:  cmp x2, #8",
    "    b.lo 2f",
    "    ldr x3, [x1]",
    "    str x3, [x0]",
    "    add x0, x0, #8",
    "    add x1, x1, #8",
    "    sub x2, x2, #8",
    "    b 1b",
    "2:  cbz x2, 3f",
    "    ldrb w3, [x1]",
    "    strb w3, [x0]",
    "    add x0, x0, #1",
    "    add x1, x1, #1",
    "    sub x2, x2, #1",
    "    b 2b",
    "3:  mov x0, #0",
    "    ret",
    ".global hk_copy_user_end",
    "hk_copy_user_end:",
    ".global hk_copy_user_fixup",
    "hk_copy_user_fixup:",
    "    mov x0, x2",
    "    ret",
    ".popsection",
);

unsafe extern "C" {
    fn hk_copy_user(dst: *mut u8, src: *const u8, len: usize) -> usize;
    static hk_copy_user_start: u8;
    static hk_copy_user_end: u8;
    static hk_copy_user_fixup: u8;
}

/// Exception-table lookup: if a kernel-mode fault at `pc` is inside the
/// user-copy routine, return the address to resume at (Linux: fixup_exception)
pub fn uaccess_fixup(pc: u64) -> Option<u64> {
    let start = &raw const hk_copy_user_start as u64;
    let end = &raw const hk_copy_user_end as u64;
    if (start..end).contains(&pc) {
        Some(&raw const hk_copy_user_fixup as u64)
    } else {
        None
    }
}

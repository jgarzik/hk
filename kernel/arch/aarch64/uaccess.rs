//! AArch64 user memory access
//!
//! Provides safe user-space memory access with PAN (Privileged Access Never)
//! protection. On ARMv8.1+, PAN prevents kernel from accidentally accessing
//! user memory without explicit permission.

use crate::uaccess::UaccessArch;

/// AArch64 user access implementation
pub struct Aarch64Uaccess;

impl UaccessArch for Aarch64Uaccess {
    /// Start of valid user address space
    const USER_START: u64 = 0x0000_0000_0000_0000;
    /// End of valid user address space (48-bit VA with lower half for user)
    const USER_END: u64 = 0x0001_0000_0000_0000;

    /// Check if a user address range is valid
    ///
    /// On aarch64, user space is typically 0x0000_0000_0000_0000 to
    /// 0x0000_FFFF_FFFF_FFFF (with 48-bit virtual addressing).
    fn access_ok(addr: u64, size: usize) -> bool {
        // Check for overflow
        let end = match addr.checked_add(size as u64) {
            Some(e) => e,
            None => return false,
        };

        // Must be entirely within user space
        end <= Self::USER_END
    }

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

        // PAN (Privileged Access Never) is an ARMv8.1+ feature.
        // For ARMv8.0 CPUs like cortex-a57, this is a no-op.
        // A full implementation would check ID_AA64MMFR1_EL1.PAN and use
        // "msr pan, #0" via .inst directive if supported.
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

        // PAN (Privileged Access Never) is an ARMv8.1+ feature.
        // For ARMv8.0 CPUs like cortex-a57, this is a no-op.
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

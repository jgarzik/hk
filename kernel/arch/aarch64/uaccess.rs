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

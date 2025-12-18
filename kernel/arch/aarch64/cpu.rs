//! AArch64 CPU initialization and feature detection
//!
//! Handles early CPU setup including exception level detection,
//! feature verification, and basic CPU configuration.

use core::arch::asm;

/// Current Exception Level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionLevel {
    EL0, // User mode
    EL1, // Kernel mode
    EL2, // Hypervisor mode
    EL3, // Secure monitor mode
}

/// Read the current exception level
pub fn current_el() -> ExceptionLevel {
    let el: u64;
    unsafe {
        asm!("mrs {}, CurrentEL", out(reg) el);
    }
    match (el >> 2) & 0x3 {
        0 => ExceptionLevel::EL0,
        1 => ExceptionLevel::EL1,
        2 => ExceptionLevel::EL2,
        3 => ExceptionLevel::EL3,
        _ => unreachable!(),
    }
}

/// Read MPIDR_EL1 (Multiprocessor Affinity Register)
///
/// Returns the CPU's affinity values used to identify it in SMP systems.
pub fn read_mpidr() -> u64 {
    let mpidr: u64;
    unsafe {
        asm!("mrs {}, mpidr_el1", out(reg) mpidr);
    }
    mpidr
}

/// Get the CPU ID from MPIDR (Aff0 field, bits [7:0])
///
/// This is typically the CPU number within a cluster.
pub fn cpu_id() -> u32 {
    (read_mpidr() & 0xFF) as u32
}

/// Initialize CPU features and configuration
///
/// Called early in boot before the MMU is enabled.
pub fn init() {
    // Verify we're running at EL1 (kernel mode)
    let el = current_el();
    if el != ExceptionLevel::EL1 {
        // We should be at EL1 after the bootloader hands off to us
        // If not, we'd need to drop from EL2 to EL1
        // For now, just continue - QEMU with -kernel starts us at EL1
    }

    // Enable floating point and SIMD (NEON)
    // CPACR_EL1.FPEN = 0b11 (bits [21:20])
    unsafe {
        let mut cpacr: u64;
        asm!("mrs {}, cpacr_el1", out(reg) cpacr);
        cpacr |= 0x3 << 20; // FPEN = full access
        asm!("msr cpacr_el1, {}", in(reg) cpacr);
        asm!("isb");
    }
}

/// Halt the CPU until an interrupt arrives
#[inline]
pub fn halt() {
    unsafe {
        asm!("wfi", options(nomem, nostack));
    }
}

/// Enable interrupts (clear DAIF.I bit)
#[inline]
pub fn enable_interrupts() {
    unsafe {
        asm!("msr daifclr, #2", options(nomem, nostack));
    }
}

/// Disable interrupts (set DAIF.I bit)
#[inline]
pub fn disable_interrupts() {
    unsafe {
        asm!("msr daifset, #2", options(nomem, nostack));
    }
}

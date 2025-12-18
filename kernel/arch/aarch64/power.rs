//! AArch64 power management
//!
//! Provides shutdown, reboot, and halt functionality for aarch64.
//! Uses PSCI (Power State Coordination Interface) for power control.

/// PSCI function IDs (SMCCC compliant)
#[allow(dead_code)]
pub mod psci {
    /// PSCI version
    pub const PSCI_VERSION: u32 = 0x84000000;
    /// CPU_ON (64-bit)
    pub const CPU_ON_64: u32 = 0xC4000003;
    /// CPU_OFF
    pub const CPU_OFF: u32 = 0x84000002;
    /// System off
    pub const SYSTEM_OFF: u32 = 0x84000008;
    /// System reset
    pub const SYSTEM_RESET: u32 = 0x84000009;

    /// PSCI return codes
    pub const SUCCESS: i64 = 0;
    pub const NOT_SUPPORTED: i64 = -1;
    pub const INVALID_PARAMS: i64 = -2;
    pub const DENIED: i64 = -3;
    pub const ALREADY_ON: i64 = -4;
    pub const ON_PENDING: i64 = -5;
    pub const INTERNAL_FAILURE: i64 = -6;
}

/// Query PSCI version to test if PSCI is working
pub fn psci_version() -> u32 {
    let result: u32;
    unsafe {
        core::arch::asm!(
            "mov x0, {func}",
            "hvc #0",
            func = in(reg) psci::PSCI_VERSION as u64,
            lateout("x0") result,
            out("x1") _,
            out("x2") _,
            out("x3") _,
        );
    }
    result
}

/// Call PSCI CPU_ON to start a secondary CPU
///
/// # Arguments
/// * `target_mpidr` - MPIDR of the target CPU (Aff0 = CPU ID for QEMU virt)
/// * `entry_point` - Physical address where the CPU should start execution
/// * `context_id` - Value passed to the CPU in x0 register
///
/// # Returns
/// PSCI return code (0 = success)
pub fn psci_cpu_on(target_mpidr: u64, entry_point: u64, context_id: u64) -> i64 {
    let result: i64;
    unsafe {
        core::arch::asm!(
            "mov x0, {func}",
            "mov x1, {mpidr}",
            "mov x2, {entry}",
            "mov x3, {ctx}",
            "hvc #0",
            func = in(reg) psci::CPU_ON_64 as u64,
            mpidr = in(reg) target_mpidr,
            entry = in(reg) entry_point,
            ctx = in(reg) context_id,
            lateout("x0") result,
            out("x1") _,
            out("x2") _,
            out("x3") _,
        );
    }
    result
}

/// Shutdown the system using PSCI
pub fn shutdown() -> ! {
    crate::printkln!("System shutdown via PSCI");
    unsafe {
        core::arch::asm!(
            "mov x0, {func}",
            "hvc #0",
            func = in(reg) psci::SYSTEM_OFF as u64,
            options(nostack, nomem)
        );
    }
    // If PSCI fails, loop forever
    loop {
        unsafe {
            core::arch::asm!("wfi");
        }
    }
}

/// Reboot the system using PSCI
pub fn reboot() -> ! {
    crate::printkln!("System reboot via PSCI");
    unsafe {
        core::arch::asm!(
            "mov x0, {func}",
            "hvc #0",
            func = in(reg) psci::SYSTEM_RESET as u64,
            options(nostack, nomem)
        );
    }
    // If PSCI fails, loop forever
    loop {
        unsafe {
            core::arch::asm!("wfi");
        }
    }
}

/// Halt the CPU
pub fn halt() -> ! {
    crate::printkln!("System halt");
    loop {
        unsafe {
            core::arch::asm!("wfi");
        }
    }
}

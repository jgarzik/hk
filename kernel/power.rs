//! Power management - architecture-independent interface
//!
//! This module provides the generic power management interface and sys_reboot
//! implementation. Architecture-specific power operations are implemented in
//! arch/<arch>/power.rs modules.

use crate::error::KernelError;

/// Linux reboot syscall command constants
pub mod cmd {
    /// Magic number 1 for reboot syscall
    pub const LINUX_REBOOT_MAGIC1: u32 = 0xfee1dead;
    /// Magic number 2 variants (any of these is valid)
    pub const LINUX_REBOOT_MAGIC2: u32 = 0x28121969;
    pub const LINUX_REBOOT_MAGIC2A: u32 = 0x05121996;
    pub const LINUX_REBOOT_MAGIC2B: u32 = 0x16041998;
    pub const LINUX_REBOOT_MAGIC2C: u32 = 0x20112000;

    /// Power off the system
    pub const POWER_OFF: u32 = 0x4321fedc;
    /// Restart the system
    pub const RESTART: u32 = 0x01234567;
    /// Halt the system (stop CPUs but don't power off)
    pub const HALT: u32 = 0xcdef0123;
}

/// sys_reboot implementation
///
/// Implements the Linux reboot(2) syscall. The caller must provide valid
/// magic numbers to prevent accidental shutdown.
///
/// # Arguments
/// * `magic1` - Must be LINUX_REBOOT_MAGIC1 (0xfee1dead)
/// * `magic2` - Must be one of the LINUX_REBOOT_MAGIC2 variants
/// * `cmd` - Reboot command (POWER_OFF, RESTART, HALT)
/// * `_arg` - Unused for power off/restart/halt
///
/// # Returns
/// Does not return on success (system shuts down/reboots/halts).
/// Returns -EINVAL on invalid magic numbers or unknown command.
pub fn sys_reboot(magic1: u32, magic2: u32, cmd: u32, _arg: u64) -> i64 {
    // Validate magic number 1
    if magic1 != cmd::LINUX_REBOOT_MAGIC1 {
        return KernelError::InvalidArgument.sysret();
    }

    // Validate magic number 2 (any of the valid variants)
    if magic2 != cmd::LINUX_REBOOT_MAGIC2
        && magic2 != cmd::LINUX_REBOOT_MAGIC2A
        && magic2 != cmd::LINUX_REBOOT_MAGIC2B
        && magic2 != cmd::LINUX_REBOOT_MAGIC2C
    {
        return KernelError::InvalidArgument.sysret();
    }

    // Dispatch to architecture-specific implementation
    match cmd {
        cmd::POWER_OFF => crate::arch::power::shutdown(),
        cmd::RESTART => crate::arch::power::reboot(),
        cmd::HALT => crate::arch::power::halt(),
        _ => KernelError::InvalidArgument.sysret(),
    }
}

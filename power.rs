//! Power management - architecture-independent interface
//!
//! This module provides the generic power management interface and sys_reboot
//! implementation. Architecture-specific power operations are implemented in
//! arch/<arch>/power.rs modules.

use crate::util::error::{KernelError, KernelResult};

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
    /// Restart with a command string (only inside a child pid
    /// namespace here, where it is RESTART)
    pub const RESTART2: u32 = 0xa1b2c3d4;
}

/// Serializes power-off, restart and halt (Linux system_transition_mutex)
static SYSTEM_TRANSITION: crate::sync::Mutex<()> = crate::sync::Mutex::new(());

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
pub fn sys_reboot(magic1: u32, magic2: u32, cmd: u32, _arg: u64) -> KernelResult<()> {
    // The capability first, then the magic numbers (Linux)
    if !crate::task::capable(crate::task::CAP_SYS_BOOT) {
        return Err(KernelError::NotPermitted);
    }

    // Validate magic number 1
    if magic1 != cmd::LINUX_REBOOT_MAGIC1 {
        return Err(KernelError::InvalidArgument);
    }

    // Validate magic number 2 (any of the valid variants)
    if magic2 != cmd::LINUX_REBOOT_MAGIC2
        && magic2 != cmd::LINUX_REBOOT_MAGIC2A
        && magic2 != cmd::LINUX_REBOOT_MAGIC2B
        && magic2 != cmd::LINUX_REBOOT_MAGIC2C
    {
        return Err(KernelError::InvalidArgument);
    }

    // Inside a child pid namespace the command ends the namespace, never
    // the machine (Linux reboot_pid_ns, before system_transition_mutex)
    if let Some(e) = crate::task::pidns::reboot_pid_ns(cmd) {
        return Err(e);
    }

    // One transition at a time (Linux system_transition_mutex): a second
    // caller waits here, and the machine is gone before it gets the lock,
    // rather than powering off while the first still quiesces devices
    let _transition = SYSTEM_TRANSITION.lock();

    // Devices quiesce first (Linux kernel_shutdown_prepare and
    // kernel_restart_prepare: device_shutdown), then the other CPUs stop
    // (Linux machine_shutdown -> stop_other_cpus), so nothing goes on
    // running against quiesced hardware
    if matches!(cmd, cmd::POWER_OFF | cmd::RESTART | cmd::HALT) {
        // Linux kernel_shutdown_prepare / kernel_restart_prepare
        use crate::system_state::{SystemState, set_system_state};
        set_system_state(match cmd {
            cmd::POWER_OFF => SystemState::PowerOff,
            cmd::RESTART => SystemState::Restart,
            _ => SystemState::Halt,
        });
        crate::base::device_shutdown();
        crate::smp::stop_other_cpus();
    }

    // Dispatch to architecture-specific implementation
    match cmd {
        cmd::POWER_OFF => {
            #[cfg(feature = "lockdep")]
            crate::sync::lockdep::summary();
            crate::arch::power::shutdown()
        }
        cmd::RESTART => crate::arch::power::reboot(),
        cmd::HALT => crate::arch::power::halt(),
        _ => Err(KernelError::InvalidArgument),
    }
}

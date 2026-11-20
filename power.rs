//! Power management - architecture-independent interface
//!
//! This module provides the generic power management interface and sys_reboot
//! implementation. Architecture-specific power operations are implemented in
//! arch/<arch>/power.rs modules.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicI32, Ordering};

use crate::task::pid::Pid;
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
    /// Ctrl-Alt-Del restarts at once
    pub const CAD_ON: u32 = 0x89abcdef;
    /// Ctrl-Alt-Del sends SIGINT to the CAD process (init)
    pub const CAD_OFF: u32 = 0x0000_0000;
}

/// Serializes power-off, restart and halt (Linux system_transition_mutex)
static SYSTEM_TRANSITION: crate::sync::Mutex<()> = crate::sync::Mutex::new(());

/// Ctrl-Alt-Del restarts at once when non-zero (Linux int C_A_D: 1 at
/// boot, written under SYSTEM_TRANSITION by reboot(2) CAD_ON (1) /
/// CAD_OFF (0) or with any value by kernel.ctrl-alt-del, read
/// lock-free)
static C_A_D: AtomicI32 = AtomicI32::new(1);

/// The process Ctrl-Alt-Del signals when C_A_D is off (Linux cad_pid:
/// init's, set as it starts, changed through kernel.cad_pid); a spin
/// leaf, its reference dropped after it
static CAD_PID: crate::sync::spin::Mutex<Option<Arc<Pid>>> = crate::sync::spin::Mutex::new(None);

/// Init starts (Linux kernel_init: cad_pid = get_pid(task_pid(current)))
pub fn set_cad_pid(pid: Arc<Pid>) {
    let old = CAD_PID.lock().replace(pid);
    drop(old);
}

/// /proc/sys/kernel/ctrl-alt-del and cad_pid (Linux kern_table)
pub static CAD_CTLS: &[crate::sysctl::Ctl] = &[
    crate::sysctl::Ctl {
        path: "kernel/ctrl-alt-del",
        mode: 0o644,
        show: || alloc::vec![i64::from(C_A_D.load(Ordering::Relaxed))],
        // An int, kept as written (Linux proc_dointvec: EINVAL past
        // its range)
        store: |v| {
            let c = i32::try_from(v[0]).map_err(|_| KernelError::InvalidArgument)?;
            C_A_D.store(c, Ordering::Relaxed);
            Ok(())
        },
        text: None,
    },
    crate::sysctl::Ctl {
        path: "kernel/cad_pid",
        mode: 0o600,
        show: || {
            let p = CAD_PID.lock().clone();
            alloc::vec![p.map_or(0, |p| i64::from(p.vnr()))]
        },
        store: cad_pid_store,
        text: None,
    },
];

/// kernel.cad_pid written: the process numbered so in the writer's
/// namespace (Linux proc_do_cad_pid: ESRCH if there is none)
fn cad_pid_store(v: &[i64]) -> Result<(), KernelError> {
    let nr = u32::try_from(v[0]).map_err(|_| KernelError::NoProcess)?;
    let pid = crate::task::pid::find_vpid(nr).ok_or(KernelError::NoProcess)?;
    set_cad_pid(pid);
    Ok(())
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
pub fn sys_reboot(magic1: u32, magic2: u32, cmd: u32, arg: u64) -> KernelResult<()> {
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

    // Ctrl-Alt-Del's mode (Linux: under system_transition_mutex)
    let cmd = match cmd {
        cmd::CAD_ON | cmd::CAD_OFF => {
            C_A_D.store(i32::from(cmd == cmd::CAD_ON), Ordering::Relaxed);
            return Ok(());
        }
        // A restart with a command for the firmware, which hk passes to
        // none (Linux: strncpy_from_user of 256 bytes, EFAULT, the
        // command logged, kernel_restart)
        cmd::RESTART2 => {
            // An unterminated one is cut to 255 bytes and logged so, as
            // Linux's (char buffer[256], strncpy_from_user of 255)
            let mut buf = [0u8; 255];
            let n = match crate::uaccess::strncpy_from_user(arg, 255) {
                Ok(c) => {
                    buf[..c.len()].copy_from_slice(&c);
                    c.len()
                }
                Err(crate::uaccess::UaccessError::TooLong) => {
                    crate::uaccess::copy_from_user(&mut buf, arg, 255)
                        .map_err(|_| KernelError::BadAddress)?;
                    255
                }
                Err(_) => return Err(KernelError::BadAddress),
            };
            crate::printkln!(
                "reboot: Restarting system with command '{}'",
                core::str::from_utf8(&buf[..n]).unwrap_or("?")
            );
            cmd::RESTART
        }
        c => c,
    };

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

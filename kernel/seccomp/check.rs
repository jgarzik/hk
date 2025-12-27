//! Seccomp syscall checking
//!
//! This module provides the check_syscall() function that is called
//! at the beginning of every syscall to enforce seccomp policy.

use alloc::sync::Arc;

use super::filter::SeccompFilter;
use super::{
    MAX_ERRNO, SECCOMP_MODE_DISABLED, SECCOMP_MODE_FILTER, SECCOMP_MODE_STRICT, SECCOMP_RET_ACTION,
    SECCOMP_RET_ALLOW, SECCOMP_RET_DATA, SECCOMP_RET_ERRNO, SECCOMP_RET_KILL_PROCESS,
    SECCOMP_RET_KILL_THREAD, SECCOMP_RET_LOG, SECCOMP_RET_TRACE, SECCOMP_RET_TRAP,
    SECCOMP_RET_USER_NOTIF, SeccompData, current_audit_arch,
};

// Syscall numbers for STRICT mode whitelist
#[cfg(target_arch = "x86_64")]
mod strict_syscalls {
    pub const SYS_READ: i32 = 0;
    pub const SYS_WRITE: i32 = 1;
    pub const SYS_EXIT: i32 = 60;
    pub const SYS_EXIT_GROUP: i32 = 231;
    pub const SYS_RT_SIGRETURN: i32 = 15;
}

#[cfg(target_arch = "aarch64")]
mod strict_syscalls {
    pub const SYS_READ: i32 = 63;
    pub const SYS_WRITE: i32 = 64;
    pub const SYS_EXIT: i32 = 93;
    pub const SYS_EXIT_GROUP: i32 = 94;
    pub const SYS_RT_SIGRETURN: i32 = 139;
}

/// Check if a syscall is allowed by seccomp policy
///
/// This function should be called at the start of syscall dispatch,
/// before the actual syscall handler runs.
///
/// # Arguments
/// * `mode` - Current seccomp mode (DISABLED, STRICT, FILTER)
/// * `filter` - The seccomp filter (for FILTER mode)
/// * `nr` - Syscall number
/// * `ip` - Instruction pointer at syscall entry
/// * `args` - Syscall arguments
///
/// # Returns
/// * `None` - Allow the syscall to proceed normally
/// * `Some(errno)` - Block the syscall and return this negative errno
pub fn check_syscall(
    mode: u8,
    filter: Option<&Arc<SeccompFilter>>,
    nr: u64,
    ip: u64,
    args: [u64; 6],
) -> Option<i64> {
    match mode {
        SECCOMP_MODE_DISABLED => None,

        SECCOMP_MODE_STRICT => {
            use strict_syscalls::*;

            // In STRICT mode, only allow read, write, exit, exit_group, sigreturn
            let nr_i32 = nr as i32;
            match nr_i32 {
                SYS_READ | SYS_WRITE | SYS_EXIT | SYS_EXIT_GROUP | SYS_RT_SIGRETURN => None,
                _ => {
                    // Kill the process
                    // In a full implementation, we'd send SIGKILL here
                    // For now, return -ENOSYS to indicate blocked syscall
                    Some(-38) // ENOSYS
                }
            }
        }

        SECCOMP_MODE_FILTER => {
            let filter = filter?;

            // Build seccomp_data
            let data = SeccompData {
                nr: nr as i32,
                arch: current_audit_arch(),
                instruction_pointer: ip,
                args,
            };

            // Run the filter chain
            let result = filter.run(&data);
            let action = result & SECCOMP_RET_ACTION;

            // Handle special case: KILL has high bit set
            if result >= 0x8000_0000 {
                // KILL_PROCESS or other high-bit action
                // Return -ENOSYS (should actually send SIGKILL)
                return Some(-38);
            }

            match action {
                _ if result == SECCOMP_RET_ALLOW => None,

                _ if action == (SECCOMP_RET_ERRNO & SECCOMP_RET_ACTION) => {
                    // Return the errno from the data field
                    let errno = (result & SECCOMP_RET_DATA).min(MAX_ERRNO);
                    Some(-(errno as i64))
                }

                _ if result == SECCOMP_RET_KILL_THREAD || result == SECCOMP_RET_KILL_PROCESS => {
                    // Kill the thread/process
                    Some(-38) // Should send SIGKILL
                }

                _ if action == (SECCOMP_RET_TRAP & SECCOMP_RET_ACTION) => {
                    // Send SIGSYS
                    // For now, just block with ENOSYS
                    Some(-38)
                }

                _ if action == (SECCOMP_RET_TRACE & SECCOMP_RET_ACTION) => {
                    // ptrace notification - not implemented
                    // Fall through to allow if no tracer
                    None
                }

                _ if action == (SECCOMP_RET_LOG & SECCOMP_RET_ACTION) => {
                    // Log and allow
                    // TODO: Actually log the syscall
                    None
                }

                _ if action == (SECCOMP_RET_USER_NOTIF & SECCOMP_RET_ACTION) => {
                    // User notification - not implemented
                    Some(-38)
                }

                _ => {
                    // Unknown action or ALLOW
                    None
                }
            }
        }

        _ => None, // Unknown mode - allow
    }
}

/// Simplified check for use from syscall dispatcher
///
/// This wraps check_syscall() with per-CPU task lookup.
/// Returns None to allow, Some(result) to return that value instead.
///
/// Uses a two-level check for performance:
/// 1. Fast path: Check per-CPU cached seccomp_mode (no lock required)
/// 2. Slow path: Only if seccomp is enabled, lock TASK_TABLE to get filter
#[allow(clippy::too_many_arguments)]
fn check_syscall_impl(
    nr: u64,
    ip: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> Option<u64> {
    use crate::arch::PerCpuOps;

    // Fast path: check per-CPU cached seccomp_mode (no lock needed!)
    // This follows Linux's approach of checking TIF_SECCOMP flag.
    #[cfg(target_arch = "x86_64")]
    type CurrentArch = crate::arch::x86_64::X86_64Arch;
    #[cfg(target_arch = "aarch64")]
    type CurrentArch = crate::arch::aarch64::Aarch64Arch;

    let current_task = CurrentArch::get_current_task();

    // Most tasks have seccomp disabled - fast return
    if current_task.seccomp_mode == SECCOMP_MODE_DISABLED {
        return None;
    }

    // Slow path: seccomp is enabled, need to get filter from TASK_TABLE
    use crate::task::percpu::TASK_TABLE;

    let filter = {
        let table = TASK_TABLE.lock();
        match table.tasks.iter().find(|t| t.tid == current_task.tid) {
            Some(task) => task.seccomp_filter.clone(),
            None => return None, // No task found, allow (shouldn't happen)
        }
    };

    // Run the check
    let args = [arg0, arg1, arg2, arg3, arg4, arg5];
    check_syscall(current_task.seccomp_mode, filter.as_ref(), nr, ip, args)
        .map(|errno| errno as u64)
}

#[cfg(target_arch = "x86_64")]
#[allow(clippy::too_many_arguments)]
pub fn check_syscall_x86_64(
    nr: u64,
    ip: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> Option<u64> {
    check_syscall_impl(nr, ip, arg0, arg1, arg2, arg3, arg4, arg5)
}

#[cfg(target_arch = "aarch64")]
#[allow(clippy::too_many_arguments)]
pub fn check_syscall_aarch64(
    nr: u64,
    ip: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> Option<u64> {
    check_syscall_impl(nr, ip, arg0, arg1, arg2, arg3, arg4, arg5)
}

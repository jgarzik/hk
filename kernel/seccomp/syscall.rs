//! Seccomp syscall handlers
//!
//! This module implements the seccomp(2) syscall and prctl(2) integration.

use crate::error::KernelError;
use crate::task::percpu::{TASK_TABLE, update_current_seccomp_mode};

use super::filter::create_filter_from_user;
use super::{
    SECCOMP_FILTER_FLAG_LOG, SECCOMP_FILTER_FLAG_TSYNC, SECCOMP_GET_ACTION_AVAIL,
    SECCOMP_GET_NOTIF_SIZES, SECCOMP_MODE_DISABLED, SECCOMP_MODE_FILTER, SECCOMP_MODE_STRICT,
    SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO, SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_KILL_THREAD,
    SECCOMP_RET_LOG, SECCOMP_RET_TRACE, SECCOMP_RET_TRAP, SECCOMP_SET_MODE_FILTER,
    SECCOMP_SET_MODE_STRICT,
};

/// seccomp(2) syscall handler
///
/// # Arguments
/// * `op` - Operation (SECCOMP_SET_MODE_STRICT, SECCOMP_SET_MODE_FILTER, etc.)
/// * `flags` - Flags for the operation
/// * `args` - Arguments (depends on operation)
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_seccomp(op: u64, flags: u64, args: u64) -> i64 {
    match op as u32 {
        SECCOMP_SET_MODE_STRICT => {
            if flags != 0 {
                return KernelError::InvalidArgument.sysret();
            }
            set_seccomp_strict()
        }

        SECCOMP_SET_MODE_FILTER => {
            let log = (flags as u32 & SECCOMP_FILTER_FLAG_LOG) != 0;
            let tsync = (flags as u32 & SECCOMP_FILTER_FLAG_TSYNC) != 0;

            // Check for unsupported flags
            let known_flags = SECCOMP_FILTER_FLAG_LOG | SECCOMP_FILTER_FLAG_TSYNC;
            if (flags as u32 & !known_flags) != 0 {
                return KernelError::InvalidArgument.sysret();
            }

            set_seccomp_filter(args, log, tsync)
        }

        SECCOMP_GET_ACTION_AVAIL => {
            // Check if an action is available
            if flags != 0 {
                return KernelError::InvalidArgument.sysret();
            }
            get_action_avail(args)
        }

        SECCOMP_GET_NOTIF_SIZES => {
            // Return notification structure sizes (not implemented)
            KernelError::OperationNotSupported.sysret()
        }

        _ => KernelError::InvalidArgument.sysret(),
    }
}

/// Enable STRICT seccomp mode
fn set_seccomp_strict() -> i64 {
    let tid = crate::task::percpu::current_tid();

    {
        let mut table = TASK_TABLE.lock();
        let task = match table.tasks.iter_mut().find(|t| t.tid == tid) {
            Some(t) => t,
            None => return KernelError::NoProcess.sysret(),
        };

        // Can only enable seccomp, not change modes once enabled
        if task.seccomp_mode != SECCOMP_MODE_DISABLED {
            return KernelError::InvalidArgument.sysret();
        }

        task.seccomp_mode = SECCOMP_MODE_STRICT;
    }

    // Update per-CPU cached seccomp_mode for fast syscall-entry check
    update_current_seccomp_mode(SECCOMP_MODE_STRICT);

    0
}

/// Enable FILTER seccomp mode with a BPF program
fn set_seccomp_filter(fprog_ptr: u64, log: bool, _tsync: bool) -> i64 {
    use crate::arch::Uaccess;

    if fprog_ptr == 0 {
        return KernelError::InvalidArgument.sysret();
    }

    let tid = crate::task::percpu::current_tid();

    // Get current task's existing filter and check no_new_privs
    let (existing_filter, has_no_new_privs, is_privileged) = {
        let table = TASK_TABLE.lock();
        let task = match table.tasks.iter().find(|t| t.tid == tid) {
            Some(t) => t,
            None => return KernelError::NoProcess.sysret(),
        };

        (
            task.seccomp_filter.clone(),
            task.prctl.no_new_privs,
            task.cred.euid == 0, // Root is privileged
        )
    };

    // Must have no_new_privs set or be privileged (CAP_SYS_ADMIN)
    if !has_no_new_privs && !is_privileged {
        return KernelError::PermissionDenied.sysret();
    }

    // Create new filter from userspace program
    let new_filter = match create_filter_from_user::<Uaccess>(fprog_ptr, existing_filter, log) {
        Ok(f) => f,
        Err(e) => return -(e as i64),
    };

    // Update task's seccomp state
    {
        let mut table = TASK_TABLE.lock();
        let task = match table.tasks.iter_mut().find(|t| t.tid == tid) {
            Some(t) => t,
            None => return KernelError::NoProcess.sysret(),
        };

        task.seccomp_mode = SECCOMP_MODE_FILTER;
        task.seccomp_filter = Some(new_filter);
    }

    // Update per-CPU cached seccomp_mode for fast syscall-entry check
    update_current_seccomp_mode(SECCOMP_MODE_FILTER);

    // TODO: If tsync, sync across all threads in thread group

    0
}

/// Check if an action is available
fn get_action_avail(action: u64) -> i64 {
    // Check if we support this action
    match action as u32 {
        SECCOMP_RET_KILL_PROCESS
        | SECCOMP_RET_KILL_THREAD
        | SECCOMP_RET_TRAP
        | SECCOMP_RET_ERRNO
        | SECCOMP_RET_TRACE
        | SECCOMP_RET_LOG
        | SECCOMP_RET_ALLOW => 0, // Supported

        // USER_NOTIF not supported yet
        _ => KernelError::OperationNotSupported.sysret(),
    }
}

/// prctl(PR_GET_SECCOMP) handler
///
/// Returns the current seccomp mode.
pub fn prctl_get_seccomp() -> i64 {
    let tid = crate::task::percpu::current_tid();

    let table = TASK_TABLE.lock();
    match table.tasks.iter().find(|t| t.tid == tid) {
        Some(task) => task.seccomp_mode as i64,
        None => SECCOMP_MODE_DISABLED as i64,
    }
}

/// prctl(PR_SET_SECCOMP) handler
///
/// # Arguments
/// * `mode` - Mode to set (SECCOMP_MODE_STRICT or SECCOMP_MODE_FILTER)
/// * `filter` - Filter program pointer (for FILTER mode)
///
/// # Returns
/// 0 on success, negative errno on error
pub fn prctl_set_seccomp(mode: u64, filter: u64) -> i64 {
    match mode as u8 {
        SECCOMP_MODE_STRICT => set_seccomp_strict(),

        SECCOMP_MODE_FILTER => {
            if filter == 0 {
                return KernelError::InvalidArgument.sysret();
            }
            set_seccomp_filter(filter, false, false)
        }

        _ => KernelError::InvalidArgument.sysret(),
    }
}

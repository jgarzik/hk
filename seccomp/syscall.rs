//! Seccomp syscall handlers
//!
//! This module implements the seccomp(2) syscall and prctl(2) integration.

use crate::task::percpu::TASKLIST;
use crate::util::error::KernelError;

use super::filter::{SeccompFilter, create_filter_from_user};
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
        let mut table = TASKLIST.write();
        let Some(task) = table.get_mut(tid) else {
            return KernelError::NoProcess.sysret();
        };

        // Can only enable seccomp, not change modes once enabled
        if task.task.seccomp_mode() != SECCOMP_MODE_DISABLED {
            return KernelError::InvalidArgument.sysret();
        }

        task.task
            .seccomp_mode
            .store(SECCOMP_MODE_STRICT, core::sync::atomic::Ordering::Relaxed);
    }

    0
}

/// Enable FILTER seccomp mode with a BPF program; `tsync` puts it on
/// every thread of the group (Linux SECCOMP_FILTER_FLAG_TSYNC)
fn set_seccomp_filter(fprog_ptr: u64, log: bool, tsync: bool) -> i64 {
    use crate::arch::Uaccess;

    if fprog_ptr == 0 {
        return KernelError::InvalidArgument.sysret();
    }

    let tid = crate::task::percpu::current_tid();

    // TSYNC holds the group's cred_guard (Linux: killable) so no exec
    // changes the threads meanwhile
    let _guard = if tsync {
        match crate::signal::CredGuard::lock(tid) {
            Ok(g) => Some(g),
            Err(e) => return e.sysret(),
        }
    } else {
        None
    };

    // The filter stacks on the thread's current one. It is built from
    // user memory without TASKLIST, so another thread's TSYNC may
    // replace the current one meanwhile: then build again on that one,
    // never dropping it (Linux builds and installs under siglock)
    let (new_filter, mut table) = loop {
        // Get current task's existing filter and check no_new_privs
        let (existing_filter, has_no_new_privs, is_privileged) = {
            let table = TASKLIST.read();
            let Some(task) = table.get(tid) else {
                return KernelError::NoProcess.sysret();
            };
            (
                task.seccomp_filter.clone(),
                task.prctl.no_new_privs,
                crate::task::capable(crate::task::CAP_SYS_ADMIN),
            )
        };

        // Must have no_new_privs set or be privileged (CAP_SYS_ADMIN)
        if !has_no_new_privs && !is_privileged {
            return KernelError::PermissionDenied.sysret();
        }

        // Create new filter from userspace program
        let new_filter =
            match create_filter_from_user::<Uaccess>(fprog_ptr, existing_filter.clone(), log) {
                Ok(f) => f,
                Err(e) => return -(e as i64),
            };
        let table = TASKLIST.write();
        let Some(me) = table.get(tid) else {
            return KernelError::NoProcess.sysret();
        };
        let same = match (&me.seccomp_filter, &existing_filter) {
            (Some(a), Some(b)) => alloc::sync::Arc::ptr_eq(a, b),
            (None, None) => true,
            _ => false,
        };
        if same {
            break (new_filter, table);
        }
    };
    let Some(me) = table.get(tid) else {
        return KernelError::NoProcess.sysret();
    };
    let (pid, mine, nnp) = (
        me.task.pid,
        me.seccomp_filter.clone(),
        me.prctl.no_new_privs,
    );
    let mut targets = alloc::vec![tid];
    if tsync {
        // Linux seccomp_can_sync_threads: every other thread's filter is
        // ours or one ours stacks on; else that thread's tid
        // Exiting and zombie threads are skipped (Linux: PF_EXITING)
        for t in table
            .threads(pid)
            .filter(|t| t.task.tid() != tid && crate::signal::task_live(t))
        {
            let mode = t.task.seccomp_mode();
            let ok = (mode == SECCOMP_MODE_DISABLED || mode == SECCOMP_MODE_FILTER)
                && SeccompFilter::is_ancestor_of(t.seccomp_filter.as_ref(), mine.as_ref());
            if !ok {
                return t.task.tid() as i64;
            }
            targets.push(t.task.tid());
        }
    }
    for t in targets {
        let Some(mut task) = table.get_mut(t) else {
            continue;
        };
        // Filter first: syscall entry reads the mode lock-free, then
        // the filter under TASKLIST
        task.seccomp_filter = Some(new_filter.clone());
        if nnp {
            task.prctl.no_new_privs = true;
        }
        task.task
            .seccomp_mode
            .store(SECCOMP_MODE_FILTER, core::sync::atomic::Ordering::Release);
    }
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

    let table = TASKLIST.read();
    match table.get(tid) {
        Some(task) => i64::from(task.task.seccomp_mode()),
        None => i64::from(SECCOMP_MODE_DISABLED),
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

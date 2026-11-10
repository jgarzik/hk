//! Seccomp syscall handlers
//!
//! This module implements the seccomp(2) syscall and prctl(2) integration.

use crate::task::percpu::TASKLIST;
use crate::uaccess::UserPtr;
use crate::util::error::{KernelError, KernelResult};

use super::filter::{SeccompFilter, SockFprog, create_filter_from_user};
use super::{
    SECCOMP_FILTER_FLAG_LOG, SECCOMP_FILTER_FLAG_TSYNC, SECCOMP_GET_ACTION_AVAIL,
    SECCOMP_GET_NOTIF_SIZES, SECCOMP_MODE_DISABLED, SECCOMP_MODE_FILTER, SECCOMP_MODE_STRICT,
    SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO, SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_KILL_THREAD,
    SECCOMP_RET_LOG, SECCOMP_RET_TRACE, SECCOMP_RET_TRAP, SECCOMP_RET_USER_NOTIF,
    SECCOMP_SET_MODE_FILTER, SECCOMP_SET_MODE_STRICT,
};

/// seccomp(op, flags, args)
pub fn sys_seccomp(op: u64, flags: u64, args: u64) -> KernelResult<i64> {
    match op as u32 {
        SECCOMP_SET_MODE_STRICT => {
            if flags != 0 || args != 0 {
                return Err(KernelError::InvalidArgument);
            }
            set_seccomp_strict().map(|()| 0)
        }
        SECCOMP_SET_MODE_FILTER => {
            let known_flags = SECCOMP_FILTER_FLAG_LOG | SECCOMP_FILTER_FLAG_TSYNC;
            if flags as u32 & !known_flags != 0 {
                return Err(KernelError::InvalidArgument);
            }
            let log = flags as u32 & SECCOMP_FILTER_FLAG_LOG != 0;
            let tsync = flags as u32 & SECCOMP_FILTER_FLAG_TSYNC != 0;
            set_seccomp_filter(UserPtr::new(args), log, tsync)
        }
        SECCOMP_GET_ACTION_AVAIL => {
            if flags != 0 {
                return Err(KernelError::InvalidArgument);
            }
            get_action_avail(UserPtr::new(args)).map(|()| 0)
        }
        // No user notification
        SECCOMP_GET_NOTIF_SIZES => Err(KernelError::OperationNotSupported),
        _ => Err(KernelError::InvalidArgument),
    }
}

/// Enable STRICT seccomp mode
fn set_seccomp_strict() -> KernelResult<()> {
    let me = crate::task::percpu::current();

    {
        let mut table = TASKLIST.write();
        let task = table.view_mut(&me).ok_or(KernelError::NoProcess)?;
        // Can only enable seccomp, not change modes once enabled
        if task.task.seccomp_mode() != SECCOMP_MODE_DISABLED {
            return Err(KernelError::InvalidArgument);
        }

        task.task
            .seccomp_mode
            .store(SECCOMP_MODE_STRICT, core::sync::atomic::Ordering::Relaxed);
    }
    Ok(())
}

/// Enable FILTER seccomp mode with a BPF program; `tsync` puts it on
/// every thread of the group (Linux SECCOMP_FILTER_FLAG_TSYNC): 0, or
/// with TSYNC the tid of a thread that cannot take it
fn set_seccomp_filter(fprog: UserPtr<SockFprog>, log: bool, tsync: bool) -> KernelResult<i64> {
    if fprog.is_null() {
        return Err(KernelError::InvalidArgument);
    }

    let cur = crate::task::percpu::current();
    let tid = cur.tid();

    // TSYNC holds the group's cred_guard (Linux: killable) so no exec
    // changes the threads meanwhile
    let _guard = if tsync {
        Some(crate::signal::CredGuard::lock(&cur)?)
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
            let task = table.view(&cur).ok_or(KernelError::NoProcess)?;
            (
                task.seccomp_filter().cloned(),
                task.no_new_privs(),
                crate::task::capable(crate::task::CAP_SYS_ADMIN),
            )
        };

        // Must have no_new_privs set or be privileged (CAP_SYS_ADMIN)
        if !has_no_new_privs && !is_privileged {
            return Err(KernelError::PermissionDenied);
        }

        let new_filter = create_filter_from_user(fprog.addr(), existing_filter.clone(), log)?;
        let table = TASKLIST.write();
        let me = table.view(&cur).ok_or(KernelError::NoProcess)?;
        let same = match (me.seccomp_filter(), &existing_filter) {
            (Some(a), Some(b)) => alloc::sync::Arc::ptr_eq(a, b),
            (None, None) => true,
            _ => false,
        };
        if same {
            break (new_filter, table);
        }
    };
    let me = table.view(&cur).ok_or(KernelError::NoProcess)?;
    let (pid, mine, nnp) = (me.task.pid, me.seccomp_filter().cloned(), me.no_new_privs());
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
                && SeccompFilter::is_ancestor_of(t.seccomp_filter(), mine.as_ref());
            if !ok {
                return Ok(t.task.tid() as i64);
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
        task.set_seccomp_filter(new_filter.clone());
        if nnp {
            task.set_no_new_privs();
        }
        task.task
            .seccomp_mode
            .store(SECCOMP_MODE_FILTER, core::sync::atomic::Ordering::Release);
    }
    Ok(0)
}

/// Whether the u32 action at `uaction` is one a filter may return
/// (Linux seccomp_get_action_avail): EFAULT, EOPNOTSUPP if unknown.
/// USER_NOTIF is known: with no listener it is ENOSYS, as in Linux.
fn get_action_avail(uaction: UserPtr<u32>) -> KernelResult<()> {
    match uaction.read()? {
        SECCOMP_RET_KILL_PROCESS
        | SECCOMP_RET_KILL_THREAD
        | SECCOMP_RET_TRAP
        | SECCOMP_RET_ERRNO
        | SECCOMP_RET_USER_NOTIF
        | SECCOMP_RET_TRACE
        | SECCOMP_RET_LOG
        | SECCOMP_RET_ALLOW => Ok(()),
        _ => Err(KernelError::OperationNotSupported),
    }
}

/// prctl(PR_GET_SECCOMP) handler
///
/// Returns the current seccomp mode.
pub fn prctl_get_seccomp() -> i64 {
    let table = TASKLIST.read();
    match table.view(&crate::task::percpu::current()) {
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
/// 0 on success
pub fn prctl_set_seccomp(mode: u64, filter: UserPtr<SockFprog>) -> KernelResult<i64> {
    match mode as u8 {
        SECCOMP_MODE_STRICT => set_seccomp_strict().map(|()| 0),
        SECCOMP_MODE_FILTER => set_seccomp_filter(filter, false, false),
        _ => Err(KernelError::InvalidArgument),
    }
}

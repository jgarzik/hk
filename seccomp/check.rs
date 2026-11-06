//! Seccomp syscall checking
//!
//! `secure_computing` runs at syscall entry (`entry::syscall_enter_from_user_mode`,
//! after a ptrace entry stop, like Linux syscall_trace_enter); its
//! decision comes from `check_syscall`.

use alloc::sync::Arc;

use super::filter::SeccompFilter;
use super::{
    MAX_ERRNO, SECCOMP_MODE_DISABLED, SECCOMP_MODE_FILTER, SECCOMP_MODE_STRICT,
    SECCOMP_RET_ACTION_FULL, SECCOMP_RET_ALLOW, SECCOMP_RET_DATA, SECCOMP_RET_ERRNO,
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

/// What seccomp decides for one syscall (Linux __seccomp_filter,
/// __secure_computing_strict)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Run it
    Allow,
    /// Skip it, returning this (negative errno)
    Ret(i64),
    /// SECCOMP_RET_TRAP: a forced SIGSYS, the syscall skipped (ENOSYS)
    Trap,
    /// SECCOMP_RET_KILL_THREAD: the thread exits by SIGSYS (the process,
    /// if it is the last thread)
    KillThread,
    /// SECCOMP_RET_KILL_PROCESS, and any action Linux does not know: the
    /// process dies by SIGSYS
    KillProcess,
    /// A strict-mode violation: the thread exits by SIGKILL
    Strict,
}

/// Seccomp's decision on syscall `nr` (Linux seccomp_run_filters and
/// the action switch of __seccomp_filter)
pub fn check_syscall(
    mode: u8,
    filter: Option<&Arc<SeccompFilter>>,
    nr: u64,
    ip: u64,
    args: [u64; 6],
) -> Verdict {
    match mode {
        SECCOMP_MODE_DISABLED => Verdict::Allow,
        SECCOMP_MODE_STRICT => {
            use strict_syscalls::*;
            match nr as i32 {
                SYS_READ | SYS_WRITE | SYS_EXIT | SYS_EXIT_GROUP | SYS_RT_SIGRETURN => {
                    Verdict::Allow
                }
                _ => Verdict::Strict,
            }
        }
        SECCOMP_MODE_FILTER => {
            let Some(filter) = filter else {
                return Verdict::Allow;
            };
            if filter.cache_allows(nr) {
                return Verdict::Allow;
            }
            let data = SeccompData {
                nr: nr as i32,
                arch: current_audit_arch(),
                instruction_pointer: ip,
                args,
            };
            verdict(filter.run(&data))
        }
        _ => Verdict::Allow,
    }
}

/// The verdict of filter result `result` (Linux __seccomp_filter: an
/// action it does not know kills the process)
fn verdict(result: u32) -> Verdict {
    match result & SECCOMP_RET_ACTION_FULL {
        SECCOMP_RET_ALLOW | SECCOMP_RET_LOG => Verdict::Allow,
        SECCOMP_RET_ERRNO => Verdict::Ret(-i64::from((result & SECCOMP_RET_DATA).min(MAX_ERRNO))),
        SECCOMP_RET_TRAP => Verdict::Trap,
        // No tracer (hk has no PTRACE_EVENT_SECCOMP) and no listener:
        // ENOSYS, the syscall skipped
        SECCOMP_RET_TRACE | SECCOMP_RET_USER_NOTIF => Verdict::Ret(-38),
        SECCOMP_RET_KILL_THREAD => Verdict::KillThread,
        _ => Verdict::KillProcess,
    }
}

/// Seccomp at syscall entry (Linux __secure_computing): None to run the
/// syscall, Some(return value) to skip it. A kill verdict does not
/// return. The mode is read lock-free (Linux TIF_SECCOMP), the filter
/// only when it is on.
pub fn secure_computing(regs: &crate::arch::UserFrame, nr: u64) -> Option<u64> {
    let me = crate::task::percpu::current();
    let mode = me.seccomp_mode();
    if mode == SECCOMP_MODE_DISABLED {
        return None;
    }
    let filter = {
        let table = crate::task::percpu::TASKLIST.read();
        table.get(me.tid())?.seccomp_filter.clone()
    };
    match check_syscall(mode, filter.as_ref(), nr, regs.ip(), regs.syscall_args()) {
        Verdict::Allow => None,
        Verdict::Ret(e) => Some(e as u64),
        Verdict::Trap => {
            crate::signal::force_sig(me.tid(), crate::signal::SIGSYS);
            Some(-38i64 as u64)
        }
        Verdict::KillThread => kill(crate::signal::SIGSYS, true),
        Verdict::KillProcess => kill(crate::signal::SIGSYS, false),
        Verdict::Strict => kill(crate::signal::SIGKILL, true),
    }
}

/// End the thread by `sig` (`thread`, while others live) or the whole
/// process (Linux: do_exit(SIGSYS / SIGKILL), or force_sig_seccomp
/// with the handler reset so the process dies)
fn kill(sig: u32, thread: bool) -> ! {
    use crate::task::percpu;
    if thread && percpu::group_others(percpu::current_pid(), percpu::current_tid()) {
        crate::task::proc::do_exit(sig as i32)
    }
    crate::signal::do_group_exit(sig as i32)
}

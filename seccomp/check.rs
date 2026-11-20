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

/// What seccomp decides for one syscall (Linux __seccomp_filter,
/// __secure_computing_strict)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Run it
    Allow,
    /// Skip it, returning this (negative errno)
    Ret(i64),
    /// SECCOMP_RET_TRAP: a forced SIGSYS carrying the filter's 16 bits
    /// of data, the syscall skipped
    Trap(u32),
    /// SECCOMP_RET_TRACE: a tracer's PTRACE_EVENT_SECCOMP with the
    /// filter's 16 bits of data, else ENOSYS
    Trace(u32),
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
            // Linux compares the number as an int
            if crate::arch::uapi::SECCOMP_STRICT.contains(&(nr as i32)) {
                Verdict::Allow
            } else {
                Verdict::Strict
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
        SECCOMP_RET_TRAP => Verdict::Trap(result & SECCOMP_RET_DATA),
        SECCOMP_RET_TRACE => Verdict::Trace(result & SECCOMP_RET_DATA),
        // No listener (hk has no seccomp user notification): ENOSYS,
        // the syscall skipped
        SECCOMP_RET_USER_NOTIF => Verdict::Ret(-38),
        SECCOMP_RET_KILL_THREAD => Verdict::KillThread,
        _ => Verdict::KillProcess,
    }
}

/// Seccomp at syscall entry (Linux __secure_computing): None to run the
/// syscall, Some(return value) to skip it. A kill verdict does not
/// return. The mode is read lock-free (Linux TIF_SECCOMP), the filter
/// only when it is on.
pub fn secure_computing(regs: &crate::arch::UserFrame, nr: u64) -> Option<u64> {
    secure_computing_in(regs, nr, false)
}

/// [`secure_computing`]; `recheck`: the check after a tracer's
/// PTRACE_EVENT_SECCOMP stop, where a second RET_TRACE allows the
/// syscall (Linux __seccomp_filter's recheck_after_trace)
fn secure_computing_in(regs: &crate::arch::UserFrame, nr: u64, recheck: bool) -> Option<u64> {
    let me = crate::task::percpu::current();
    let mode = me.seccomp_mode();
    if mode == SECCOMP_MODE_DISABLED {
        return None;
    }
    let filter = {
        let table = crate::task::tasklist::TASKLIST.read();
        table.view(&me)?.seccomp_filter().cloned()
    };
    match check_syscall(mode, filter.as_ref(), nr, regs.ip(), regs.syscall_args()) {
        Verdict::Allow => None,
        Verdict::Trace(_) if recheck => None,
        Verdict::Trace(data) => trace(regs, data),
        Verdict::Ret(e) => Some(e as u64),
        Verdict::Trap(data) => {
            // The handler sees the registers as at entry (Linux
            // syscall_rollback), and the syscall returns what they hold
            regs.syscall_rollback();
            force_sigsys(&me, regs, nr, data);
            Some(regs.ret())
        }
        Verdict::KillThread => kill(crate::signal::SIGSYS, true),
        Verdict::KillProcess => kill(crate::signal::SIGSYS, false),
        // Linux __secure_computing_strict: do_exit(SIGKILL), the thread
        // alone even if it is the last
        Verdict::Strict => crate::task::proc::do_exit(i32::from(crate::signal::SIGKILL)),
    }
}

/// SECCOMP_RET_TRACE (Linux __seccomp_filter): ENOSYS unless a tracer
/// asked for PTRACE_EVENT_SECCOMP; then that stop, the data its
/// message, and the syscall as the tracer left it: skipped if killed
/// meanwhile or its number is now negative (returning what the tracer put in
/// the return register), else checked again with every register read
/// afresh
fn trace(regs: &crate::arch::UserFrame, data: u32) -> Option<u64> {
    use crate::task::ptrace::{PTRACE_EVENT_SECCOMP, ptrace_event, ptrace_event_enabled};
    if !ptrace_event_enabled(PTRACE_EVENT_SECCOMP) {
        return Some(-38i64 as u64);
    }
    ptrace_event(PTRACE_EVENT_SECCOMP, u64::from(data));
    regs.sync_syscall_args();
    let nr = regs.syscall_nr();
    // Any negative number skips it (Linux: the int this_syscall < 0)
    if crate::signal::fatal_signal_pending() || (nr as i32) < 0 {
        return Some(regs.ret());
    }
    secure_computing_in(regs, nr, true)
}

/// SIGSYS for syscall `nr` a filter trapped with `data` (Linux
/// force_sig_seccomp): SYS_SECCOMP, the data in si_errno, the calling
/// instruction, the syscall and its AUDIT_ARCH
fn force_sigsys(me: &crate::task::Task, regs: &crate::arch::UserFrame, nr: u64, data: u32) {
    use crate::signal::{SIGSYS, SigFields, SigInfo, si_code};
    let fields = SigFields::Sys {
        call_addr: regs.ip(),
        syscall: nr as i32,
        arch: super::current_audit_arch(),
    };
    let mut info = SigInfo::new(SIGSYS, si_code::SYS_SECCOMP, fields);
    info.errno = data as i32;
    crate::signal::force_sig_info(me, SIGSYS, info);
}

/// End the thread by `sig` (`thread`, while another has not started
/// exiting) or the whole process (Linux __seccomp_filter: do_exit(SIGSYS)
/// unless signal->live is 1, else force_sig_seccomp with the handler
/// reset so the process dies)
fn kill(sig: crate::signal::Signal, thread: bool) -> ! {
    let me = crate::task::percpu::current();
    let others = crate::signal::get_task_signal_struct(&me).is_some_and(|s| s.live() > 1);
    if thread && others {
        crate::task::proc::do_exit(sig.into())
    }
    crate::signal::do_group_exit(sig.into())
}

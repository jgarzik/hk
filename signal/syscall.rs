//! Signal-related system calls
//!
//! Implements:
//! - rt_sigaction (13) - examine and change signal action
//! - rt_sigprocmask (14) - examine and change blocked signals
//! - rt_sigpending (127) - examine pending signals
//! - rt_sigsuspend (130) - wait for signal
//! - kill (62) - send signal to process
//! - tgkill (234) - send signal to specific thread
//! - tkill (200) - send signal to thread (deprecated)
//!
//! Note: rt_sigreturn (15) is implemented in arch-specific signal.rs files

use crate::arch::Uaccess;
use crate::signal::{
    SIGKILL, SIGSTOP, SendInfo, SigAction, SigInfo, SigSet, dequeue_signal, get_task_sighand,
    kill_pgrp, kill_proc_info, send_sig_info, si_code, with_task_signal_state,
};
use crate::task::percpu::{current_pgid, current_tid, get_all_pids};
use crate::uaccess::{UserPtr, get_user, put_user};
use crate::util::error::KernelError;

/// SIG_BLOCK - Add signals to blocked mask
pub const SIG_BLOCK: i32 = 0;
/// SIG_UNBLOCK - Remove signals from blocked mask
pub const SIG_UNBLOCK: i32 = 1;
/// SIG_SETMASK - Set blocked mask
pub const SIG_SETMASK: i32 = 2;

/// User-space sigaction structure (x86_64 Linux ABI)
///
/// This matches the user-space `struct sigaction` layout.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UserSigAction {
    /// Signal handler address (or SIG_DFL/SIG_IGN)
    pub sa_handler: u64,
    /// Flags (SA_*)
    pub sa_flags: u64,
    /// Signal trampoline (restorer)
    pub sa_restorer: u64,
    /// Signals to block during handler
    pub sa_mask: u64, // sigset_t is 64-bit
}

crate::pod!(UserSigAction {
    sa_handler,
    sa_flags,
    sa_restorer,
    sa_mask,
});

impl From<&SigAction> for UserSigAction {
    fn from(action: &SigAction) -> Self {
        Self {
            sa_handler: action.handler.into(),
            sa_flags: action.flags,
            sa_restorer: action.restorer,
            sa_mask: action.mask.bits(),
        }
    }
}

impl From<UserSigAction> for SigAction {
    fn from(user: UserSigAction) -> Self {
        Self {
            handler: user.sa_handler.into(),
            flags: user.sa_flags,
            restorer: user.sa_restorer,
            mask: SigSet::from_bits(user.sa_mask).blockable(),
        }
    }
}

/// rt_sigaction(sig, act, oact, sigsetsize) - examine and change signal action
///
/// # Arguments
/// * `sig` - Signal number
/// * `act_ptr` - Pointer to new sigaction, or 0 to query
/// * `oact_ptr` - Pointer to store old sigaction, or 0
/// * `sigsetsize` - Size of sigset_t (must be 8)
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_rt_sigaction(sig: u32, act_ptr: u64, oact_ptr: u64, sigsetsize: u64) -> i64 {
    // Validate sigsetsize - must be 8 bytes (64-bit sigset_t)
    if sigsetsize != 8 {
        return -22; // EINVAL
    }

    // Validate signal number
    if sig == 0 || sig > 64 {
        return -22; // EINVAL
    }

    // SIGKILL and SIGSTOP can be queried, not changed (Linux
    // do_sigaction: `act && sig_kernel_only(sig)`)
    if act_ptr != 0 && (sig == SIGKILL || sig == SIGSTOP) {
        return -22; // EINVAL
    }

    // The new action is read before the old one is written (Linux
    // copy_from_user, do_sigaction, copy_to_user): act and oact may be
    // one buffer
    let new = if act_ptr != 0 {
        match UserPtr::<UserSigAction>::new(act_ptr).read() {
            Ok(a) => Some(SigAction::from(a)),
            Err(_) => return -14, // EFAULT
        }
    } else {
        None
    };

    let tid = current_tid();
    let Some(sighand) = get_task_sighand(tid) else {
        return -3; // ESRCH
    };
    // The old action and the swap in one hold of the action lock
    let changed = new.is_some();
    let old = match new {
        Some(a) => match sighand.set_action(sig, a) {
            Ok(old) => old,
            Err(e) => return i64::from(e),
        },
        None => match sighand.get_action(sig) {
            Some(a) => a,
            None => return -22, // EINVAL
        },
    };
    if changed && handler_ignored(&sighand, sig) {
        crate::signal::flush_group_signal(sig);
    }
    if oact_ptr != 0
        && UserPtr::<UserSigAction>::new(oact_ptr)
            .write(&UserSigAction::from(&old))
            .is_err()
    {
        return -14; // EFAULT
    }
    0
}

/// `sig`'s action now discards it: SIG_IGN, or SIG_DFL for a signal
/// whose default is to ignore it (Linux sig_handler_ignored)
fn handler_ignored(sighand: &crate::signal::SigHand, sig: u32) -> bool {
    use crate::signal::{DefaultAction, SigHandler, default_action};
    match sighand.get_action(sig).map(|a| a.handler) {
        Some(SigHandler::Ignore) => true,
        Some(SigHandler::Default) => matches!(
            default_action(sig),
            DefaultAction::Ignore | DefaultAction::Continue
        ),
        _ => false,
    }
}

/// rt_sigprocmask(how, set, oset, sigsetsize) - examine and change blocked signals
///
/// # Arguments
/// * `how` - SIG_BLOCK, SIG_UNBLOCK, or SIG_SETMASK
/// * `set_ptr` - Pointer to new mask, or 0 to query
/// * `oset_ptr` - Pointer to store old mask, or 0
/// * `sigsetsize` - Size of sigset_t (must be 8)
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_rt_sigprocmask(how: i32, set_ptr: u64, oset_ptr: u64, sigsetsize: u64) -> i64 {
    if sigsetsize != 8 {
        return -22; // EINVAL
    }

    let tid = current_tid();

    // User memory is read before and written after the signal state is
    // locked (TASKLIST: no user access under a spinlock), like Linux
    let new_set = if set_ptr != 0 {
        match get_user::<Uaccess, u64>(set_ptr) {
            Ok(v) => Some(SigSet::from_bits(v)),
            Err(_) => return -14, // EFAULT
        }
    } else {
        None
    };

    let r = with_task_signal_state(tid, |state| {
        let old = state.blocked.bits();
        if let Some(new_set) = new_set {
            match how {
                SIG_BLOCK => {
                    state.blocked = state.blocked.union(&new_set);
                }
                SIG_UNBLOCK => {
                    state.blocked = state.blocked.subtract(&new_set);
                }
                SIG_SETMASK => {
                    state.blocked = new_set;
                }
                _ => return Err(-22i64), // EINVAL
            }

            // Never allow blocking SIGKILL/SIGSTOP
            state.blocked = state.blocked.blockable();
        }
        Ok(old)
    });
    let old = match r {
        Some(Ok(old)) => old,
        Some(Err(e)) => return e,
        None => return -3, // ESRCH
    };

    // Return old mask if requested
    if oset_ptr != 0 && put_user::<Uaccess, u64>(oset_ptr, old).is_err() {
        return -14; // EFAULT
    }
    0
}

/// rt_sigpending(set, sigsetsize) - examine pending signals
///
/// # Arguments
/// * `set_ptr` - Pointer to store pending mask
/// * `sigsetsize` - Size of sigset_t (must be 8)
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_rt_sigpending(set_ptr: u64, sigsetsize: u64) -> i64 {
    if sigsetsize != 8 {
        return -22; // EINVAL
    }

    if set_ptr == 0 {
        return -22; // EINVAL
    }

    let tid = current_tid();

    let pending = with_task_signal_state(tid, |state| {
        // Combine private and shared pending
        let shared = state.shared_pending.lock();
        state.pending.signal.union(&shared.signal).bits()
    });
    let Some(pending) = pending else {
        return -3; // ESRCH
    };

    // Written after the signal state is unlocked
    if put_user::<Uaccess, u64>(set_ptr, pending).is_err() {
        return -14; // EFAULT
    }
    0
}

// =============================================================================
// Kill Permission Check
// =============================================================================

/// Check if current task has permission to send a signal to target task
///
/// Based on Linux kernel/signal.c:check_kill_permission()
///
/// # Arguments
/// * `target_pid` - Target process ID
/// * `sig` - Signal number (SIGCONT has special handling)
///
/// # Returns
/// 0 if permitted, -1 (EPERM) if denied, -3 (ESRCH) if target not found
fn check_kill_permission(target_pid: u64, sig: u32) -> i32 {
    use crate::signal::SIGCONT;
    use crate::task::percpu::{TASKLIST, current_sid, current_tid};
    use crate::task::{CAP_KILL, capable, current_cred};

    let caller_tid = current_tid();
    let caller_cred = current_cred();

    // Get target task info
    let target_info = {
        let table = TASKLIST.read();
        // Find the thread group leader for this pid
        table
            .get(target_pid)
            .map(|t| (t.task.pid, t.task.sid(), t.cred_arc()))
    };

    let (target_tgid, target_sid, target_cred) = match target_info {
        Some(info) => info,
        None => return -3, // ESRCH - no such process
    };

    // Get caller's tgid
    let caller_tgid = {
        let table = TASKLIST.read();
        table.get(caller_tid).map(|t| t.task.pid).unwrap_or(0)
    };

    // Same thread group - always allowed
    if caller_tgid == target_tgid {
        return 0;
    }

    // CAP_KILL capability - always allowed
    if capable(CAP_KILL) {
        return 0;
    }

    // UID match check (like Linux kill_ok_by_cred)
    // Caller's real or effective UID must match target's real or saved UID
    let uid_ok = caller_cred.euid == target_cred.suid
        || caller_cred.euid == target_cred.uid
        || caller_cred.uid == target_cred.suid
        || caller_cred.uid == target_cred.uid;

    if uid_ok {
        return 0;
    }

    // SIGCONT special case: same session allows SIGCONT
    if sig == SIGCONT && current_sid() == target_sid {
        return 0;
    }

    -1 // EPERM - permission denied
}

/// A user signal to the process `pid` names: the permission check, then
/// the send (Linux group_send_sig_info). Every user-facing path goes
/// through this or [`user_thread_send`], so none can forget the check.
pub(crate) fn user_group_send(pid: u64, sig: u32, info: SendInfo) -> i32 {
    let perm = check_kill_permission(pid, sig);
    if perm != 0 {
        return perm;
    }
    kill_proc_info(pid, sig, info)
}

/// A user signal to one thread `tid`, which must be in group `tgid`
/// if one is given (Linux do_send_specific; tkill gives none): ESRCH
/// if it is not, then the same
/// permission check as a process-wide signal, then the send.
fn user_thread_send(tgid: Option<u64>, tid: u64, sig: u32, info: SendInfo) -> i32 {
    use crate::task::percpu::TASKLIST;
    if let Some(tgid) = tgid {
        let in_group = TASKLIST
            .read()
            .get(tid)
            .map(|t| t.task.pid == tgid)
            .unwrap_or(false);
        if !in_group {
            return -3; // ESRCH
        }
    }
    let perm = check_kill_permission(tid, sig);
    if perm != 0 {
        return perm;
    }
    send_sig_info(tid, sig, info)
}

/// What tkill and tgkill send: SI_TKILL from the caller's process and
/// real uid (Linux prepare_kill_siginfo, PIDTYPE_PID)
fn tkill_info(sig: u32) -> SendInfo {
    let pid = crate::task::percpu::current_pid() as i32;
    let uid = crate::task::current_cred().uid;
    SendInfo::Info(SigInfo::kill(sig, si_code::SI_TKILL, pid, uid))
}

/// kill(pid, sig) - send signal to process
///
/// # Arguments
/// * `pid` - Target process:
///   - > 0: specific process
///   - 0: all processes in caller's process group
///   - -1: all processes except init
///   - < -1: all processes in process group -pid
/// * `sig` - Signal number (0 to check if process exists)
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_kill(pid: i64, sig: u32) -> i64 {
    if sig > 64 {
        return -22; // EINVAL
    }

    if pid > 0 {
        i64::from(user_group_send(pid as u64, sig, SendInfo::User))
    } else if pid == 0 {
        // Every process in the caller's process group, once each
        i64::from(kill_pgrp(current_pgid(), sig, SendInfo::User, |p| {
            check_kill_permission(p, sig)
        }))
    } else if pid == -1 {
        // Send to all processes (except init)
        // Signal 0 is a validity check, don't actually send
        // Every process the caller may signal, except init and its own
        // thread group (Linux kill_something_info): a per-target EPERM
        // does not fail the call, and ESRCH only if nothing matched
        let self_tgid = {
            let table = crate::task::percpu::TASKLIST.read();
            table.get(current_tid()).map(|t| t.task.pid).unwrap_or(0)
        };
        let mut matched = false;
        for target_pid in get_all_pids() {
            if target_pid <= 1 || target_pid == self_tgid {
                continue;
            }
            match check_kill_permission(target_pid, sig) {
                0 => {
                    matched = true;
                    if sig != 0 {
                        kill_proc_info(target_pid, sig, SendInfo::User);
                    }
                }
                -1 => matched = true, // permission denied, but it exists
                _ => {}               // ESRCH: gone between listing and now
            }
        }
        if matched { 0 } else { -3 }
    } else {
        // pid < -1: every process in group -pid, once each (signal 0:
        // does the group exist, may we signal it)
        let pgid = pid.unsigned_abs();
        i64::from(kill_pgrp(pgid, sig, SendInfo::User, |p| {
            check_kill_permission(p, sig)
        }))
    }
}

/// tgkill(tgid, tid, sig) - send signal to specific thread
///
/// # Arguments
/// * `tgid` - Thread group ID (process ID)
/// * `tid` - Thread ID
/// * `sig` - Signal number
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_tgkill(tgid: i64, tid: i64, sig: u32) -> i64 {
    if sig > 64 || tid <= 0 || tgid <= 0 {
        return -22; // EINVAL
    }

    i64::from(user_thread_send(
        Some(tgid as u64),
        tid as u64,
        sig,
        tkill_info(sig),
    ))
}

/// tkill(tid, sig) - send signal to thread (deprecated)
///
/// This is the older, deprecated version of tgkill.
/// Use tgkill instead for new code.
pub fn sys_tkill(tid: i64, sig: u32) -> i64 {
    if sig > 64 || tid <= 0 {
        return -22; // EINVAL
    }
    i64::from(user_thread_send(None, tid as u64, sig, tkill_info(sig)))
}

/// rt_sigqueueinfo(pid, sig, uinfo) - send signal with info to a process
///
/// # Arguments
/// * `pid` - Target process ID
/// * `sig` - Signal number to send
/// * `uinfo` - Pointer to user-space siginfo_t
///
/// # Returns
/// 0 on success, negative errno on error:
/// * -EINVAL: Invalid signal number
/// * -EPERM: Permission denied (cannot impersonate kernel/other process)
/// * -ESRCH: No such process
/// * -EFAULT: Bad uinfo pointer
pub fn sys_rt_sigqueueinfo(pid: i64, sig: u32, uinfo: u64) -> i64 {
    // Validate signal number
    if sig == 0 || sig > 64 {
        return -22; // EINVAL
    }

    let info = match read_info(uinfo, sig) {
        Ok(i) => i,
        Err(e) => return e.sysret(),
    };

    // Security check (Linux kernel/signal.c do_rt_sigqueueinfo): si_code
    // values reserved to the kernel (>= 0, or SI_TKILL) may only be queued
    // by a thread to its own number, never used to forge signals to
    // other processes
    if reserved_to_kernel(info.code) && pid != current_tid() as i64 {
        return -1; // EPERM
    }

    i64::from(user_group_send(pid as u64, sig, SendInfo::Info(info)))
}

/// rt_tgsigqueueinfo(tgid, tid, sig, uinfo) - send signal with info to a thread
///
/// # Arguments
/// * `tgid` - Target thread group ID (process ID)
/// * `tid` - Target thread ID
/// * `sig` - Signal number to send
/// * `uinfo` - Pointer to user-space siginfo_t
///
/// # Returns
/// 0 on success, negative errno on error:
/// * -EINVAL: Invalid signal number, pid <= 0, or tgid <= 0
/// * -EPERM: Permission denied
/// * -ESRCH: No such process/thread
/// * -EFAULT: Bad uinfo pointer
pub fn sys_rt_tgsigqueueinfo(tgid: i64, tid: i64, sig: u32, uinfo: u64) -> i64 {
    // Validate arguments
    if tid <= 0 || tgid <= 0 {
        return -22; // EINVAL
    }

    if sig == 0 || sig > 64 {
        return -22; // EINVAL
    }

    let info = match read_info(uinfo, sig) {
        Ok(i) => i,
        Err(e) => return e.sysret(),
    };

    // Security check (Linux do_rt_tgsigqueueinfo): kernel-reserved si_code
    // only when targeting the calling thread itself
    let caller_tid = crate::task::percpu::current_tid() as i64;
    if reserved_to_kernel(info.code) && tid != caller_tid {
        return -1; // EPERM
    }

    i64::from(user_thread_send(
        Some(tgid as u64),
        tid as u64,
        sig,
        SendInfo::Info(info),
    ))
}

/// rt_sigsuspend(mask, sigsetsize) - wait for signal with temporary mask
///
/// Atomically replaces the signal mask with `mask` and sleeps until a signal
/// becomes deliverable. The original mask is kept in `saved_sigmask`
/// (TIF_RESTORE_SIGMASK); the syscall-return path (`do_signal`) delivers the signal under the temporary
/// mask, stores the original mask in the signal frame (restored by
/// rt_sigreturn), or restores it directly if no handler runs.
///
/// # Arguments
/// * `mask_ptr` - Pointer to temporary signal mask
/// * `sigsetsize` - Size of sigset_t (must be 8)
///
/// # Returns
/// Always returns -EINTR (interrupted by signal) on success
/// * -EINVAL: Invalid sigsetsize
/// * -EFAULT: Bad mask_ptr pointer
pub fn sys_rt_sigsuspend(mask_ptr: u64, sigsetsize: u64) -> i64 {
    if sigsetsize != 8 {
        return -22; // EINVAL
    }

    // Read the new mask from user space
    let new_mask = match get_user::<Uaccess, u64>(mask_ptr) {
        Ok(v) => SigSet::from_bits(v),
        Err(_) => return -14, // EFAULT
    };

    // Save old mask (restored on return to user) and install the new one
    if crate::signal::set_temp_sigmask(new_mask).is_none() {
        return -3; // ESRCH
    }

    // Sleep until a signal is deliverable under the temporary mask
    // (send_signal wakes interruptible sleepers)
    wait_for_signal();

    // -EINTR once the handler runs (the saved mask goes into its frame)
    KernelError::RestartNoHand.sysret()
}

/// Sleep interruptibly until a signal is deliverable
fn wait_for_signal() {
    use crate::task::percpu::{SleepState, schedule, set_current_state};
    loop {
        set_current_state(SleepState::Interruptible);
        if crate::sync::waitqueue::signal_pending() {
            break;
        }
        schedule();
    }
    set_current_state(SleepState::Running);
}

/// pause() - sleep until a signal handler runs (x86-64 only; arm64 libc
/// uses ppoll). Returns -EINTR after the handler, like Linux.
pub fn sys_pause() -> i64 {
    wait_for_signal();
    KernelError::RestartNoHand.sysret()
}

/// The siginfo rt_sigqueueinfo and rt_tgsigqueueinfo queue, made for
/// `sig` whatever its si_signo (Linux __copy_siginfo_from_user): EFAULT,
/// E2BIG (`SigInfo::copy_from_user`)
fn read_info(uinfo: u64, sig: u32) -> Result<SigInfo, KernelError> {
    let mut info = SigInfo::copy_from_user(uinfo)?;
    info.signo = sig as i32;
    Ok(info)
}

/// Codes no user may queue to another task: the kernel's (> 0), and
/// those kill and tkill fill in (Linux si_code_reserved_to_kernel)
pub(crate) fn reserved_to_kernel(code: i32) -> bool {
    code >= 0 || code == si_code::SI_TKILL
}

/// rt_sigtimedwait(uthese, uinfo, uts, sigsetsize) - wait for signal
///
/// Synchronously wait for a signal from the specified set. The calling
/// thread is suspended until a signal from the set becomes pending, or
/// the timeout expires.
///
/// # Arguments
/// * `set_ptr` - Pointer to set of signals to wait for
/// * `info_ptr` - Pointer to receive siginfo_t (can be null)
/// * `ts_ptr` - Pointer to timeout (can be null for infinite wait)
/// * `sigsetsize` - Size of sigset_t (must be 8)
///
/// # Returns
/// Signal number on success, negative errno on error:
/// * -EINTR: Interrupted by signal not in set
/// * -EAGAIN: Timeout expired without signal
/// * -EINVAL: Invalid sigsetsize or timeout
/// * -EFAULT: Bad pointer
pub fn sys_rt_sigtimedwait(set_ptr: u64, info_ptr: u64, ts_ptr: u64, sigsetsize: u64) -> i64 {
    use crate::signal::{SIGKILL, SIGSTOP};

    // Validate sigsetsize
    if sigsetsize != 8 {
        return -22; // EINVAL
    }

    // Read the signal set to wait for
    let wait_set = match get_user::<Uaccess, u64>(set_ptr) {
        Ok(v) => SigSet::from_bits(v),
        Err(_) => return -14, // EFAULT
    };

    // Read timeout if provided
    let timeout_ns = if ts_ptr != 0 {
        let tv_sec = match get_user::<Uaccess, i64>(ts_ptr) {
            Ok(v) => v,
            Err(_) => return -14, // EFAULT
        };
        let tv_nsec = match get_user::<Uaccess, i64>(ts_ptr + 8) {
            Ok(v) => v,
            Err(_) => return -14, // EFAULT
        };

        // Validate timeout
        if tv_sec < 0 || !(0..1_000_000_000).contains(&tv_nsec) {
            return -22; // EINVAL
        }

        Some(crate::time::timespec_to_ns(tv_sec, tv_nsec))
    } else {
        None // Infinite wait
    };

    let tid = current_tid();

    // Cannot wait for SIGKILL or SIGSTOP (they're always delivered)
    let mut mask = wait_set;
    mask.remove(SIGKILL);
    mask.remove(SIGSTOP);

    let mut info = dequeue_signal(&mask);
    if info.is_none() && timeout_ns != Some(0) {
        // Linux do_sigtimedwait: unblock the awaited signals while
        // sleeping so their arrival wakes us, then restore the mask
        let saved = with_task_signal_state(tid, |st| {
            let old = st.blocked;
            st.real_blocked = old;
            st.blocked = old.subtract(&mask);
            old
        });
        let deadline = timeout_ns.map(|ns| crate::time::monotonic_ns().saturating_add(ns));
        sleep_until_signal(deadline);
        if let Some(old) = saved {
            with_task_signal_state(tid, |st| {
                st.blocked = old;
                st.real_blocked = SigSet::EMPTY;
            });
        }
        info = dequeue_signal(&mask);
        if info.is_none() {
            // Another signal (EINTR) or the timeout (EAGAIN)
            let timed_out = deadline.is_some_and(|d| crate::time::monotonic_ns() >= d);
            return if timed_out {
                KernelError::WouldBlock.sysret()
            } else {
                KernelError::Interrupted.sysret()
            };
        }
    }
    let Some(info) = info else {
        return KernelError::WouldBlock.sysret();
    };
    // The signal is taken even if its info cannot be written (Linux)
    if info_ptr != 0
        && let Err(e) = info.copy_to_user(info_ptr)
    {
        return e.sysret();
    }
    i64::from(info.sig())
}

/// Sleep interruptibly until a signal is deliverable or the
/// CLOCK_MONOTONIC `deadline` (ns) passes
fn sleep_until_signal(deadline: Option<u64>) {
    use crate::task::percpu::{SleepState, set_current_state};
    use crate::time::hrtimer::{HrClock, schedule_hrtimeout};
    loop {
        set_current_state(SleepState::Interruptible);
        if crate::sync::waitqueue::signal_pending() {
            break;
        }
        if deadline.is_some_and(|d| crate::time::monotonic_ns() >= d) {
            break;
        }
        schedule_hrtimeout(deadline, HrClock::Monotonic);
    }
    set_current_state(SleepState::Running);
}

/// sigaltstack(ss, oss) - set/get alternate signal stack
///
/// Sets up or queries an alternate signal stack for signal handling.
/// This allows signal handlers to execute on a separate stack, which is
/// useful when the normal stack might be corrupted (e.g., stack overflow).
///
/// # Arguments
/// * `ss_ptr` - Pointer to new stack_t to set (can be null to just query)
/// * `oss_ptr` - Pointer to receive old stack_t (can be null)
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_sigaltstack(ss_ptr: u64, oss_ptr: u64) -> i64 {
    use crate::signal::{AltStack, MINSIGSTKSZ, ss_flags};

    let tid = current_tid();

    // Get current user stack pointer to check if on signal stack
    let user_sp = crate::task::percpu::current_pt_regs().sp();

    // Read the new stack before locking the signal state (Linux
    // copy_from_user, then do_sigaltstack, then copy_to_user)
    let new = if ss_ptr != 0 {
        let rd = || -> Option<(u64, i32, usize)> {
            Some((
                get_user::<Uaccess, u64>(ss_ptr).ok()?,
                get_user::<Uaccess, i32>(ss_ptr.wrapping_add(8)).ok()?,
                get_user::<Uaccess, u64>(ss_ptr.wrapping_add(16)).ok()? as usize,
            ))
        };
        match rd() {
            Some(v) => Some(v),
            None => return -14, // EFAULT
        }
    } else {
        None
    };

    let r = with_task_signal_state(tid, |state| {
        // Check if currently executing on the altstack
        let on_stack = state.altstack.is_enabled() && {
            let sp_start = state.altstack.ss_sp;
            let sp_end = sp_start.saturating_add(state.altstack.ss_size as u64);
            user_sp >= sp_start && user_sp < sp_end
        };
        let old = (state.altstack.ss_sp, state.altstack.ss_size);
        let old_flags = if on_stack {
            state.altstack.ss_flags | ss_flags::SS_ONSTACK
        } else {
            state.altstack.ss_flags
        };

        // Set new stack if provided
        if let Some((ss_sp, ss_flags_val, ss_size)) = new {
            // Cannot change while on signal stack
            if on_stack {
                return Err(-1i64); // EPERM
            }

            // Validate flags - only SS_DISABLE and SS_FLAG_BITS are valid
            let mode = ss_flags_val & !ss_flags::SS_FLAG_BITS;
            if mode != 0 && mode != ss_flags::SS_DISABLE {
                return Err(-22); // EINVAL
            }

            if mode == ss_flags::SS_DISABLE {
                // Disable the alternate stack
                state.altstack = AltStack {
                    ss_sp: 0,
                    ss_size: 0,
                    ss_flags: ss_flags::SS_DISABLE,
                };
            } else {
                // Enable/update the alternate stack
                if ss_size < MINSIGSTKSZ {
                    return Err(-12); // ENOMEM
                }

                state.altstack = AltStack {
                    ss_sp,
                    ss_size,
                    ss_flags: ss_flags_val,
                };
            }
        }
        Ok((old, old_flags))
    });
    let (old, old_flags) = match r {
        Some(Ok(v)) => v,
        Some(Err(e)) => return e,
        None => return -3, // ESRCH
    };

    // Return old stack if requested: ss_sp @0, ss_flags @8, ss_size @16
    if oss_ptr != 0
        && (put_user::<Uaccess, u64>(oss_ptr, old.0).is_err()
            || put_user::<Uaccess, i32>(oss_ptr.wrapping_add(8), old_flags).is_err()
            || put_user::<Uaccess, u64>(oss_ptr.wrapping_add(16), old.1 as u64).is_err())
    {
        return -14; // EFAULT
    }
    0
}

/// signalfd4(fd, mask, sizemask, flags) - create/update signalfd
///
/// # Arguments
/// * `fd` - -1 for new fd, or existing signalfd to update mask
/// * `mask_ptr` - Pointer to signal mask (sigset_t)
/// * `sizemask` - Size of signal mask (must be 8)
/// * `flags` - SFD_CLOEXEC | SFD_NONBLOCK
///
/// # Returns
/// fd on success, negative errno on error
pub fn sys_signalfd4(fd: i32, mask_ptr: u64, sizemask: u64, flags: i32) -> i64 {
    use crate::io::pipe::FD_CLOEXEC;
    use crate::io::signalfd::{create_signalfd, get_signalfd, sfd_flags};
    use crate::task::fdtable::get_task_fd;

    // Validate sizemask
    if sizemask != 8 {
        return -22; // EINVAL
    }

    // Validate flags
    let valid_flags = sfd_flags::SFD_CLOEXEC | sfd_flags::SFD_NONBLOCK;
    if flags & !valid_flags != 0 {
        return -22; // EINVAL
    }

    // Read mask from user space
    let mask_bits = match get_user::<Uaccess, u64>(mask_ptr) {
        Ok(v) => v,
        Err(_) => return -14, // EFAULT
    };
    let mask = SigSet::from_bits(mask_bits);

    if fd == -1 {
        // Create new signalfd
        let file = match create_signalfd(mask, flags) {
            Ok(f) => f,
            Err(_) => return -12, // ENOMEM
        };

        // Allocate fd and install file
        let fd_table = match get_task_fd(current_tid()) {
            Some(t) => t,
            None => return -24, // EMFILE
        };
        let mut table = fd_table.lock();
        let fd_flags = if flags & sfd_flags::SFD_CLOEXEC != 0 {
            FD_CLOEXEC
        } else {
            0
        };

        // Get RLIMIT_NOFILE
        let nofile_limit = {
            let limit = crate::task::rlimit::rlimit(crate::task::rlimit::RLIMIT_NOFILE);
            if limit == crate::task::rlimit::RLIM_INFINITY {
                u64::MAX
            } else {
                limit
            }
        };

        match table.alloc_with_flags(file, fd_flags, nofile_limit) {
            Ok(new_fd) => i64::from(new_fd),
            Err(e) => -i64::from(e),
        }
    } else {
        // Update existing signalfd mask
        let fd_table = match get_task_fd(current_tid()) {
            Some(t) => t,
            None => return -9, // EBADF
        };

        let file = match fd_table.lock().get(fd) {
            Some(f) => f,
            None => return -9, // EBADF
        };

        // Verify it's a signalfd
        match get_signalfd(&file) {
            Some(signalfd) => {
                signalfd.update_mask(mask);
                i64::from(fd)
            }
            None => -22, // EINVAL - not a signalfd
        }
    }
}

/// signalfd(fd, mask, flags) - legacy signalfd (x86_64 only)
///
/// This is the legacy version without sizemask parameter.
/// The mask size is assumed to be 8 bytes.
pub fn sys_signalfd(fd: i32, mask_ptr: u64, flags: i32) -> i64 {
    sys_signalfd4(fd, mask_ptr, 8, flags)
}

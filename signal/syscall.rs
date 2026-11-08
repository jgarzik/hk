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

use crate::signal::{
    SIGKILL, SIGSTOP, SendInfo, SigAction, SigInfo, SigSet, UserSigInfo, dequeue_signal,
    get_task_sighand, kill_pgrp, kill_proc_info, send_sig_info, si_code, with_task_signal_state,
};
use crate::task::percpu::{current_pgid, current_tid, get_all_pids};
use crate::time::time_syscall::LinuxTimespec;
use crate::uaccess::UserPtr;
use crate::util::error::{KernelError, KernelResult};

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

/// rt_sigaction(sig, act, oact, sigsetsize): either pointer may be NULL
pub fn sys_rt_sigaction(
    sig: u32,
    act: UserPtr<UserSigAction>,
    oact: UserPtr<UserSigAction>,
    sigsetsize: u64,
) -> KernelResult<()> {
    if sigsetsize != 8 || sig == 0 || sig > 64 {
        return Err(KernelError::InvalidArgument);
    }
    // SIGKILL and SIGSTOP can be queried, not changed (Linux
    // do_sigaction: `act && sig_kernel_only(sig)`)
    if !act.is_null() && (sig == SIGKILL || sig == SIGSTOP) {
        return Err(KernelError::InvalidArgument);
    }

    // The new action is read before the old one is written (Linux
    // copy_from_user, do_sigaction, copy_to_user): act and oact may be
    // one buffer
    let new = if act.is_null() {
        None
    } else {
        Some(SigAction::from(act.read()?))
    };

    let sighand = get_task_sighand(current_tid()).ok_or(KernelError::NoProcess)?;
    // The old action and the swap in one hold of the action lock
    let changed = new.is_some();
    let old = match new {
        Some(a) => sighand.set_action(sig, a)?,
        None => sighand
            .get_action(sig)
            .ok_or(KernelError::InvalidArgument)?,
    };
    // Ignored now: discarded pending; no longer ignored: interval timers
    // whose signal it ignored queue it (Linux do_sigaction)
    if changed && handler_ignored(&sighand, sig) {
        crate::signal::flush_group_signal(sig);
    } else if changed && old.handler == crate::signal::SigHandler::Ignore {
        crate::time::posix_timer::sig_unignore(sig);
    }
    if !oact.is_null() {
        oact.write(&UserSigAction::from(&old))?;
    }
    Ok(())
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

/// rt_sigprocmask(how, set, oset, sigsetsize): either pointer may be
/// NULL
pub fn sys_rt_sigprocmask(
    how: i32,
    set: UserPtr<u64>,
    oset: UserPtr<u64>,
    sigsetsize: u64,
) -> KernelResult<()> {
    if sigsetsize != 8 {
        return Err(KernelError::InvalidArgument);
    }

    // User memory is read before and written after the signal state is
    // locked (TASKLIST: no user access under a spinlock), like Linux
    let new_set = if set.is_null() {
        None
    } else {
        Some(SigSet::from_bits(set.read()?))
    };

    let old = with_task_signal_state(current_tid(), |state| {
        let old = state.blocked.bits();
        if let Some(new_set) = new_set {
            state.blocked = match how {
                SIG_BLOCK => state.blocked.union(&new_set),
                SIG_UNBLOCK => state.blocked.subtract(&new_set),
                SIG_SETMASK => new_set,
                _ => return Err(KernelError::InvalidArgument),
            };
            // Never allow blocking SIGKILL/SIGSTOP
            state.blocked = state.blocked.blockable();
        }
        Ok(old)
    })
    .ok_or(KernelError::NoProcess)??;

    if !oset.is_null() {
        oset.write(&old)?;
    }
    Ok(())
}

/// rt_sigpending(set, sigsetsize)
pub fn sys_rt_sigpending(set: UserPtr<u64>, sigsetsize: u64) -> KernelResult<()> {
    if sigsetsize != 8 || set.is_null() {
        return Err(KernelError::InvalidArgument);
    }
    let pending = with_task_signal_state(current_tid(), |state| {
        // Combine private and shared pending
        let shared = state.shared_pending.lock();
        state.pending.signal.union(&shared.signal).bits()
    })
    .ok_or(KernelError::NoProcess)?;
    // Written after the signal state is unlocked
    Ok(set.write(&pending)?)
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
/// EPERM if denied, ESRCH if target not found
fn check_kill_permission(target_pid: u64, sig: u32) -> KernelResult<()> {
    let me = Sender::current();
    let table = crate::task::percpu::TASKLIST.read();
    let t = table.get(target_pid).ok_or(KernelError::NoProcess)?;
    me.may_kill(&t, sig)
}

/// What the kill permission check needs of the caller, read before
/// TASKLIST is taken
pub(crate) struct Sender {
    tgid: u64,
    sid: u64,
    cred: crate::task::Cred,
}

impl Sender {
    pub(crate) fn current() -> Self {
        Self {
            tgid: crate::task::percpu::current_pid(),
            sid: crate::task::percpu::current_sid(),
            cred: crate::task::current_cred(),
        }
    }

    /// May it send `sig` to `t` (Linux check_kill_permission): same
    /// thread group, CAP_KILL, a real or effective uid matching the
    /// target's real or saved one, or SIGCONT within the session; else
    /// EPERM
    pub(crate) fn may_kill(
        &self,
        t: &crate::task::percpu::TaskView<'_>,
        sig: u32,
    ) -> KernelResult<()> {
        use crate::signal::SIGCONT;
        use crate::task::{CAP_KILL, capable};
        if self.tgid == t.task.pid || capable(CAP_KILL) {
            return Ok(());
        }
        let c = &self.cred;
        let tc = t.cred_arc();
        if c.euid == tc.suid || c.euid == tc.uid || c.uid == tc.suid || c.uid == tc.uid {
            return Ok(());
        }
        if sig == SIGCONT && self.sid == t.task.sid() {
            return Ok(());
        }
        Err(KernelError::NotPermitted)
    }
}

/// A user signal to the process `pid` names: the permission check, then
/// the send (Linux group_send_sig_info). Every user-facing path goes
/// through this or [`user_thread_send`], so none can forget the check.
fn user_group_send(pid: u64, sig: u32, info: SendInfo) -> KernelResult<()> {
    check_kill_permission(pid, sig)?;
    kill_proc_info(pid, sig, info)
}

/// A user signal to one thread `tid`, which must be in group `tgid`
/// if one is given (Linux do_send_specific; tkill gives none): ESRCH
/// if it is not, then the same
/// permission check as a process-wide signal, then the send.
fn user_thread_send(tgid: Option<u64>, tid: u64, sig: u32, info: SendInfo) -> KernelResult<()> {
    use crate::task::percpu::TASKLIST;
    // The caller's numbers (Linux find_task_by_vpid, task_tgid_vnr)
    let (Some(tid), Some(tgid)) = (
        crate::task::pid::from_vnr(tid),
        tgid.map_or(Some(None), |g| crate::task::pid::from_vnr(g).map(Some)),
    ) else {
        return Err(KernelError::NoProcess);
    };
    if let Some(tgid) = tgid {
        let in_group = TASKLIST
            .read()
            .get(tid)
            .map(|t| t.task.pid == tgid)
            .unwrap_or(false);
        if !in_group {
            return Err(KernelError::NoProcess);
        }
    }
    check_kill_permission(tid, sig)?;
    send_sig_info(tid, sig, info)
}

/// What tkill and tgkill send: SI_TKILL from the caller's process and
/// real uid (Linux prepare_kill_siginfo, PIDTYPE_PID)
fn tkill_info(sig: u32) -> SendInfo {
    let pid = crate::task::pid::vnr(crate::task::percpu::current_pid()) as i32;
    let uid = crate::task::current_cred().uid;
    SendInfo::Info(SigInfo::kill(sig, si_code::SI_TKILL, pid, uid))
}

/// kill(pid, sig): `pid` > 0 a process, 0 the caller's process group,
/// -1 every process it may signal but init, < -1 the group -pid; signal
/// 0 only checks
pub fn sys_kill(pid: i64, sig: u32) -> KernelResult<()> {
    if sig > 64 {
        return Err(KernelError::InvalidArgument);
    }
    // Numbers are the caller's (Linux find_vpid): none it sees is ESRCH
    let vpid = |nr: u64| crate::task::pid::from_vnr(nr).ok_or(KernelError::NoProcess);
    let check = |p| check_kill_permission(p, sig);
    match pid {
        1.. => user_group_send(vpid(pid as u64)?, sig, SendInfo::User),
        // Every process in the caller's process group, once each
        0 => kill_pgrp(current_pgid(), sig, SendInfo::User, check),
        -1 => kill_all(sig),
        // Every process in group -pid, once each (signal 0: does the
        // group exist, may we signal it)
        _ => kill_pgrp(vpid(pid.unsigned_abs())?, sig, SendInfo::User, check),
    }
}

/// kill(-1, sig): every process the caller may signal, except init and
/// its own thread group (Linux kill_something_info): a per-target EPERM
/// does not fail the call, and ESRCH only if nothing matched
fn kill_all(sig: u32) -> KernelResult<()> {
    let self_tgid = {
        let table = crate::task::percpu::TASKLIST.read();
        table.get(current_tid()).map(|t| t.task.pid).unwrap_or(0)
    };
    // Only processes the caller's namespace numbers, but its init
    // (Linux kill_something_info: task_pid_vnr(p) > 1)
    let ns = crate::task::pid::current_pid_ns();
    let mut matched = false;
    for target_pid in get_all_pids() {
        if crate::task::pid::nr_ns(target_pid, ns) <= 1 || target_pid == self_tgid {
            continue;
        }
        match check_kill_permission(target_pid, sig) {
            Ok(()) => {
                matched = true;
                // Signal 0 is a validity check, don't actually send
                if sig != 0 {
                    let _ = kill_proc_info(target_pid, sig, SendInfo::User);
                }
            }
            // Permission denied, but it exists
            Err(KernelError::NotPermitted) => matched = true,
            _ => {} // ESRCH: gone between listing and now
        }
    }
    if matched {
        Ok(())
    } else {
        Err(KernelError::NoProcess)
    }
}

/// tgkill(tgid, tid, sig): a signal to thread `tid` of process `tgid`
pub fn sys_tgkill(tgid: i64, tid: i64, sig: u32) -> KernelResult<()> {
    if sig > 64 || tid <= 0 || tgid <= 0 {
        return Err(KernelError::InvalidArgument);
    }
    user_thread_send(Some(tgid as u64), tid as u64, sig, tkill_info(sig))
}

/// tkill(tid, sig): tgkill without the process check (deprecated)
pub fn sys_tkill(tid: i64, sig: u32) -> KernelResult<()> {
    if sig > 64 || tid <= 0 {
        return Err(KernelError::InvalidArgument);
    }
    user_thread_send(None, tid as u64, sig, tkill_info(sig))
}

/// rt_sigqueueinfo(pid, sig, uinfo): a signal with caller-made info to
/// a process
pub fn sys_rt_sigqueueinfo(pid: i64, sig: u32, uinfo: UserPtr<UserSigInfo>) -> KernelResult<()> {
    if sig == 0 || sig > 64 {
        return Err(KernelError::InvalidArgument);
    }
    let info = read_info(uinfo, sig)?;

    // Security check (Linux kernel/signal.c do_rt_sigqueueinfo): si_code
    // values reserved to the kernel (>= 0, or SI_TKILL) may only be queued
    // by a thread to its own number, never used to forge signals to
    // other processes
    if reserved_to_kernel(info.code) && pid != i64::from(crate::task::pid::vnr(current_tid())) {
        return Err(KernelError::NotPermitted);
    }
    let pid = crate::task::pid::from_vnr(pid as u64).ok_or(KernelError::NoProcess)?;
    user_group_send(pid, sig, SendInfo::Info(info))
}

/// rt_tgsigqueueinfo(tgid, tid, sig, uinfo): the same to one thread
pub fn sys_rt_tgsigqueueinfo(
    tgid: i64,
    tid: i64,
    sig: u32,
    uinfo: UserPtr<UserSigInfo>,
) -> KernelResult<()> {
    if tid <= 0 || tgid <= 0 || sig == 0 || sig > 64 {
        return Err(KernelError::InvalidArgument);
    }
    let info = read_info(uinfo, sig)?;

    // Security check (Linux do_rt_tgsigqueueinfo): kernel-reserved si_code
    // only when targeting the calling thread itself
    let caller_tid = i64::from(crate::task::pid::vnr(current_tid()));
    if reserved_to_kernel(info.code) && tid != caller_tid {
        return Err(KernelError::NotPermitted);
    }
    user_thread_send(Some(tgid as u64), tid as u64, sig, SendInfo::Info(info))
}

/// rt_sigsuspend(mask, sigsetsize) - wait for signal with temporary mask
///
/// Atomically replaces the signal mask with `mask` and sleeps until a signal
/// becomes deliverable. The original mask is kept in `saved_sigmask`
/// (TIF_RESTORE_SIGMASK); the syscall-return path (`do_signal`) delivers the signal under the temporary
/// mask, stores the original mask in the signal frame (restored by
/// rt_sigreturn), or restores it directly if no handler runs.
/// Returns -ERESTARTNOHAND: -EINTR once the handler runs.
pub fn sys_rt_sigsuspend(mask: UserPtr<u64>, sigsetsize: u64) -> KernelResult<()> {
    if sigsetsize != 8 {
        return Err(KernelError::InvalidArgument);
    }
    let new_mask = SigSet::from_bits(mask.read()?);
    // Save old mask (restored on return to user) and install the new one
    crate::signal::set_temp_sigmask(new_mask).ok_or(KernelError::NoProcess)?;
    // Sleep until a signal is deliverable under the temporary mask
    // (send_signal wakes interruptible sleepers)
    wait_for_signal();
    // -EINTR once the handler runs (the saved mask goes into its frame)
    Err(KernelError::RestartNoHand)
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
pub fn sys_pause() -> KernelResult<()> {
    wait_for_signal();
    Err(KernelError::RestartNoHand)
}

/// The siginfo rt_sigqueueinfo and rt_tgsigqueueinfo queue, made for
/// `sig` whatever its si_signo, its layout judged by `sig` (Linux
/// __copy_siginfo_from_user): EFAULT, E2BIG
fn read_info(uinfo: UserPtr<UserSigInfo>, sig: u32) -> KernelResult<SigInfo> {
    SigInfo::copy_from_user_sig(uinfo.addr(), sig as i32)
}

/// Codes no user may queue to another task: the kernel's (> 0), and
/// those kill and tkill fill in (Linux si_code_reserved_to_kernel)
pub(crate) fn reserved_to_kernel(code: i32) -> bool {
    code >= 0 || code == si_code::SI_TKILL
}

/// rt_sigtimedwait(uthese, uinfo, uts, sigsetsize): wait for a signal
/// of the set and take it; `uinfo` and `uts` (no timeout) may be NULL.
/// The signal number; EAGAIN at the timeout, EINTR for another signal.
pub fn sys_rt_sigtimedwait(
    set: UserPtr<u64>,
    uinfo: UserPtr<UserSigInfo>,
    uts: UserPtr<LinuxTimespec>,
    sigsetsize: u64,
) -> KernelResult<i32> {
    use crate::signal::{SIGKILL, SIGSTOP};
    if sigsetsize != 8 {
        return Err(KernelError::InvalidArgument);
    }
    let wait_set = SigSet::from_bits(set.read()?);
    let timeout_ns = if uts.is_null() {
        None // Infinite wait
    } else {
        Some(uts.read()?.to_ns()?)
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
            return Err(if timed_out {
                KernelError::WouldBlock
            } else {
                KernelError::Interrupted
            });
        }
    }
    let info = info.ok_or(KernelError::WouldBlock)?;
    // The signal is taken even if its info cannot be written (Linux)
    if !uinfo.is_null() {
        info.copy_to_user(uinfo.addr())?;
    }
    Ok(info.sig() as i32)
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

/// User `stack_t` (sigaltstack)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UserStack {
    ss_sp: u64,
    ss_flags: i32,
    _pad: i32,
    ss_size: u64,
}
crate::pod!(UserStack {
    ss_sp,
    ss_flags,
    _pad,
    ss_size
});

/// sigaltstack(ss, oss): set and/or read the alternate signal stack;
/// either pointer may be NULL
pub fn sys_sigaltstack(ss: UserPtr<UserStack>, oss: UserPtr<UserStack>) -> KernelResult<()> {
    // Get current user stack pointer to check if on signal stack
    let user_sp = crate::task::percpu::current_pt_regs().sp();
    // Read the new stack before locking the signal state (Linux
    // copy_from_user, then do_sigaltstack, then copy_to_user)
    let new = if ss.is_null() { None } else { Some(ss.read()?) };
    let old = with_task_signal_state(current_tid(), |state| do_sigaltstack(state, new, user_sp))
        .ok_or(KernelError::NoProcess)??;
    if !oss.is_null() {
        oss.write(&old)?;
    }
    Ok(())
}

/// Install `new` (if any) as the alternate stack of a thread at
/// `user_sp` (Linux do_sigaltstack); the stack it had
fn do_sigaltstack(
    state: &mut crate::signal::TaskSignalState,
    new: Option<UserStack>,
    user_sp: u64,
) -> KernelResult<UserStack> {
    use crate::signal::{AltStack, MINSIGSTKSZ, ss_flags};
    let alt = &state.altstack;
    let on_stack = alt.is_enabled() && {
        let end = alt.ss_sp.saturating_add(alt.ss_size as u64);
        (alt.ss_sp..end).contains(&user_sp)
    };
    let old = UserStack {
        ss_sp: alt.ss_sp,
        ss_flags: alt.ss_flags | if on_stack { ss_flags::SS_ONSTACK } else { 0 },
        _pad: 0,
        ss_size: alt.ss_size as u64,
    };
    let Some(new) = new else {
        return Ok(old);
    };
    // Cannot change while on signal stack
    if on_stack {
        return Err(KernelError::NotPermitted);
    }
    // Only SS_DISABLE and SS_FLAG_BITS are valid
    let mode = new.ss_flags & !ss_flags::SS_FLAG_BITS;
    if mode != 0 && mode != ss_flags::SS_DISABLE {
        return Err(KernelError::InvalidArgument);
    }
    state.altstack = if mode == ss_flags::SS_DISABLE {
        AltStack {
            ss_sp: 0,
            ss_size: 0,
            ss_flags: ss_flags::SS_DISABLE,
        }
    } else {
        if (new.ss_size as usize) < MINSIGSTKSZ {
            return Err(KernelError::OutOfMemory);
        }
        AltStack {
            ss_sp: new.ss_sp,
            ss_size: new.ss_size as usize,
            ss_flags: new.ss_flags,
        }
    };
    Ok(old)
}

/// signalfd4(fd, mask, sizemask, flags): a new signalfd (`fd` -1) or a
/// new mask for the signalfd `fd`; the descriptor
pub fn sys_signalfd4(fd: i32, mask: UserPtr<u64>, sizemask: u64, flags: i32) -> KernelResult<i32> {
    use crate::io::signalfd::{create_signalfd, get_signalfd, sfd_flags};
    if sizemask != 8 {
        return Err(KernelError::InvalidArgument);
    }
    if flags & !(sfd_flags::SFD_CLOEXEC | sfd_flags::SFD_NONBLOCK) != 0 {
        return Err(KernelError::InvalidArgument);
    }
    let mask = SigSet::from_bits(mask.read()?);
    if fd == -1 {
        let file = create_signalfd(mask, flags)?;
        return crate::fs::io::fd_install(
            file,
            crate::time::time_syscall::cloexec(flags & sfd_flags::SFD_CLOEXEC != 0),
        );
    }
    let file = crate::fs::io::fget(fd)?;
    let signalfd = get_signalfd(&file).ok_or(KernelError::InvalidArgument)?; // not a signalfd
    signalfd.update_mask(mask);
    Ok(fd)
}

/// signalfd(fd, mask, flags): signalfd4 with an 8-byte mask (x86-64
/// only)
pub fn sys_signalfd(fd: i32, mask: UserPtr<u64>, flags: i32) -> KernelResult<i32> {
    sys_signalfd4(fd, mask, 8, flags)
}

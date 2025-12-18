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
//! - rt_sigreturn (15) - return from signal handler

use crate::arch::Uaccess;
use crate::signal::{
    SIGKILL, SIGSTOP, SigAction, SigSet, UNMASKABLE_SIGNALS, get_task_sighand, send_signal,
    send_signal_to_process, with_task_signal_state,
};
use crate::task::percpu::current_tid;
use crate::uaccess::{get_user, put_user};

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
            mask: SigSet::from_bits(user.sa_mask),
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

    // Cannot change SIGKILL or SIGSTOP
    if sig == SIGKILL || sig == SIGSTOP {
        return -22; // EINVAL
    }

    let tid = current_tid();
    let sighand = match get_task_sighand(tid) {
        Some(sh) => sh,
        None => return -3, // ESRCH
    };

    // Get old action if requested
    if oact_ptr != 0 && sighand.get_action(sig).is_some() {
        let old_action = sighand.get_action(sig).unwrap();
        let user_action: UserSigAction = (&old_action).into();

        // Write to user space as raw bytes
        if put_user::<Uaccess, u64>(oact_ptr, user_action.sa_handler).is_err() {
            return -14; // EFAULT
        }
        if put_user::<Uaccess, u64>(oact_ptr + 8, user_action.sa_flags).is_err() {
            return -14; // EFAULT
        }
        if put_user::<Uaccess, u64>(oact_ptr + 16, user_action.sa_restorer).is_err() {
            return -14; // EFAULT
        }
        if put_user::<Uaccess, u64>(oact_ptr + 24, user_action.sa_mask).is_err() {
            return -14; // EFAULT
        }
    }

    // Set new action if provided
    if act_ptr != 0 {
        // Read from user space
        let sa_handler = match get_user::<Uaccess, u64>(act_ptr) {
            Ok(v) => v,
            Err(_) => return -14, // EFAULT
        };
        let sa_flags = match get_user::<Uaccess, u64>(act_ptr + 8) {
            Ok(v) => v,
            Err(_) => return -14, // EFAULT
        };
        let sa_restorer = match get_user::<Uaccess, u64>(act_ptr + 16) {
            Ok(v) => v,
            Err(_) => return -14, // EFAULT
        };
        let sa_mask = match get_user::<Uaccess, u64>(act_ptr + 24) {
            Ok(v) => v,
            Err(_) => return -14, // EFAULT
        };

        let user_action = UserSigAction {
            sa_handler,
            sa_flags,
            sa_restorer,
            sa_mask,
        };

        let new_action: SigAction = user_action.into();

        if let Err(e) = sighand.set_action(sig, new_action) {
            return e as i64;
        }
    }

    0
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

    with_task_signal_state(tid, |state| {
        // Return old mask if requested
        if oset_ptr != 0 && put_user::<Uaccess, u64>(oset_ptr, state.blocked.bits()).is_err() {
            return -14i64; // EFAULT
        }

        // Modify mask if requested
        if set_ptr != 0 {
            let new_set = match get_user::<Uaccess, u64>(set_ptr) {
                Ok(v) => SigSet::from_bits(v),
                Err(_) => return -14, // EFAULT
            };

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
                _ => return -22i64, // EINVAL
            }

            // Never allow blocking SIGKILL/SIGSTOP
            state.blocked = state.blocked.subtract(&UNMASKABLE_SIGNALS);

            // Recalculate pending flag
            state.recalc_sigpending();
        }

        0i64
    })
    .unwrap_or(-3) // ESRCH
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

    with_task_signal_state(tid, |state| {
        // Combine private and shared pending
        let shared = state.shared_pending.lock();
        let pending = state.pending.signal.union(&shared.signal);

        if put_user::<Uaccess, u64>(set_ptr, pending.bits()).is_err() {
            return -14i64; // EFAULT
        }

        0i64
    })
    .unwrap_or(-3) // ESRCH
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

    // TODO: Permission checks (CAP_KILL, same user, etc.)

    if pid > 0 {
        // Send to specific process
        send_signal_to_process(pid as u64, sig) as i64
    } else if pid == 0 {
        // Send to all processes in caller's process group
        // TODO: Implement process group signaling
        -1 // ESRCH for now
    } else if pid == -1 {
        // Send to all processes (except init)
        // TODO: Implement broadcast signaling
        -1 // ESRCH for now
    } else {
        // pid < -1: Send to all processes in process group -pid
        // TODO: Implement process group signaling
        -1 // ESRCH for now
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

    // TODO: Verify tid belongs to tgid (thread group)
    // For now, just send to the specified tid

    send_signal(tid as u64, sig) as i64
}

/// tkill(tid, sig) - send signal to thread (deprecated)
///
/// This is the older, deprecated version of tgkill.
/// Use tgkill instead for new code.
pub fn sys_tkill(tid: i64, sig: u32) -> i64 {
    if sig > 64 || tid <= 0 {
        return -22; // EINVAL
    }

    send_signal(tid as u64, sig) as i64
}

/// rt_sigsuspend(mask, sigsetsize) - wait for signal with temporary mask
///
/// Temporarily replaces the signal mask and waits for a signal.
/// Returns when a signal handler is invoked.
///
/// # Arguments
/// * `mask_ptr` - Pointer to temporary signal mask
/// * `sigsetsize` - Size of sigset_t (must be 8)
///
/// # Returns
/// Always returns -EINTR (interrupted by signal)
#[allow(dead_code)]
pub fn sys_rt_sigsuspend(mask_ptr: u64, sigsetsize: u64) -> i64 {
    if sigsetsize != 8 {
        return -22; // EINVAL
    }

    let _new_mask = match get_user::<Uaccess, u64>(mask_ptr) {
        Ok(v) => SigSet::from_bits(v),
        Err(_) => return -14, // EFAULT
    };

    // TODO: Implement actual signal waiting
    // For now, just return -EINTR as if a signal was delivered
    -4 // EINTR
}

/// rt_sigreturn() - return from signal handler
///
/// This is called by the user-space signal trampoline after the signal
/// handler returns. It restores the saved context from the signal frame.
///
/// # Safety
/// This function never returns normally - it restores context and jumps
/// back to the interrupted code.
#[allow(dead_code)]
pub fn sys_rt_sigreturn() -> ! {
    // TODO: Implement signal return
    // 1. Read signal frame from user stack
    // 2. Restore blocked mask from frame
    // 3. Restore registers from ucontext
    // 4. Check for more pending signals
    // 5. Return to original code

    panic!("rt_sigreturn not yet implemented");
}

/// sigaltstack(ss, oss) - set/get alternate signal stack
///
/// Not yet implemented - returns ENOSYS.
#[allow(dead_code)]
pub fn sys_sigaltstack(_ss_ptr: u64, _oss_ptr: u64) -> i64 {
    -38 // ENOSYS
}

/// signalfd/signalfd4 - create file descriptor for signals
///
/// Not yet implemented - returns ENOSYS.
#[allow(dead_code)]
pub fn sys_signalfd(_fd: i32, _mask_ptr: u64, _flags: i32) -> i64 {
    -38 // ENOSYS
}

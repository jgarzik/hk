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
    use crate::task::percpu::current_pid;

    // Validate signal number
    if sig == 0 || sig > 64 {
        return -22; // EINVAL
    }

    // Read siginfo from user space
    let info = match SigInfo::read_from_user(uinfo, sig) {
        Ok(i) => i,
        Err(e) => return -(e as i64),
    };

    // Security check: si_code validation per Linux kernel
    // - si_code >= 0 means kernel-generated (SI_USER=0, SI_KERNEL=128, etc.)
    // - si_code < 0 means user-generated (SI_QUEUE=-1, SI_TKILL=-6, etc.)
    //
    // User cannot:
    // 1. Pretend to be the kernel (si_code >= 0)
    // 2. Use SI_TKILL code (reserved for tgkill/tkill)
    // 3. Pretend to be a different process (si_pid != current_pid)
    let caller_pid = current_pid() as i32;
    if (info.code() >= 0 || info.code() == si_code::SI_TKILL) && info.pid() != caller_pid {
        return -1; // EPERM
    }

    // Send signal to process
    send_signal_to_process(pid as u64, sig) as i64
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
    use crate::task::percpu::current_pid;

    // Validate arguments
    if tid <= 0 || tgid <= 0 {
        return -22; // EINVAL
    }

    if sig == 0 || sig > 64 {
        return -22; // EINVAL
    }

    // Read siginfo from user space
    let info = match SigInfo::read_from_user(uinfo, sig) {
        Ok(i) => i,
        Err(e) => return -(e as i64),
    };

    // Security check: same as rt_sigqueueinfo
    // Cannot pretend to be kernel or use SI_TKILL code unless actually this process
    let caller_pid = current_pid() as i32;
    if (info.code() >= 0 || info.code() == si_code::SI_TKILL) && info.pid() != caller_pid {
        return -1; // EPERM
    }

    // TODO: Verify tid belongs to tgid (thread group check)
    // For now, just send to the specified tid

    // Send signal to specific thread
    send_signal(tid as u64, sig) as i64
}

/// rt_sigsuspend(mask, sigsetsize) - wait for signal with temporary mask
///
/// Temporarily replaces the signal mask and waits for a signal.
/// Returns when a signal handler is invoked or a signal terminates the process.
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
    use crate::signal::has_pending_signals;

    if sigsetsize != 8 {
        return -22; // EINVAL
    }

    // Read the new mask from user space
    let new_mask = match get_user::<Uaccess, u64>(mask_ptr) {
        Ok(v) => SigSet::from_bits(v),
        Err(_) => return -14, // EFAULT
    };

    let tid = current_tid();

    // Save old mask and set new mask
    let old_mask = with_task_signal_state(tid, |state| {
        let old = state.blocked;
        // Set new blocked mask, but never block SIGKILL/SIGSTOP
        state.blocked = new_mask.subtract(&UNMASKABLE_SIGNALS);
        state.recalc_sigpending();
        old
    });

    let old_mask = match old_mask {
        Some(m) => m,
        None => return -3, // ESRCH
    };

    // Check for immediately deliverable signals
    // In a full implementation, we would loop here and block
    // until a signal becomes deliverable
    if has_pending_signals(tid) {
        // Restore old mask before returning
        with_task_signal_state(tid, |state| {
            state.blocked = old_mask;
            state.recalc_sigpending();
        });
        return -4; // EINTR
    }

    // TODO: In a complete implementation, we would:
    // 1. Mark the task as sleeping/waiting
    // 2. Schedule another task
    // 3. When woken by a signal, restore the old mask
    // 4. Return -EINTR
    //
    // For now, restore mask and return -EINTR
    // This is sufficient for testing but not for real signal waiting
    with_task_signal_state(tid, |state| {
        state.blocked = old_mask;
        state.recalc_sigpending();
    });

    -4 // EINTR
}

/// siginfo_t structure for user space (Linux ABI)
///
/// This is the 128-byte structure passed to user space signal handlers
/// and returned by rt_sigtimedwait.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SigInfo {
    /// Signal number
    pub si_signo: i32,
    /// Error number (not used for most signals)
    pub si_errno: i32,
    /// Signal code (SI_USER, SI_KERNEL, etc.)
    pub si_code: i32,
    /// Padding for alignment
    _pad0: i32,
    /// Union of signal-specific data
    _sifields: SigInfoFields,
}

/// Signal-specific fields union (128 bytes total for siginfo_t)
#[repr(C)]
#[derive(Clone, Copy)]
union SigInfoFields {
    /// Common: sender PID and UID
    kill: SigInfoKill,
    /// Padding to ensure 128-byte total size for siginfo_t
    /// (128 - 16 bytes for header = 112 bytes)
    _pad: [u8; 112],
}

impl Default for SigInfoFields {
    fn default() -> Self {
        Self { _pad: [0; 112] }
    }
}

impl core::fmt::Debug for SigInfoFields {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Safety: accessing _pad is always safe
        f.debug_struct("SigInfoFields").finish()
    }
}

/// Kill signal info (SI_USER, SI_TKILL)
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SigInfoKill {
    /// Sender's PID
    si_pid: i32,
    /// Sender's UID
    si_uid: u32,
}

/// Signal codes
pub mod si_code {
    /// Sent by kill, sigsend, raise
    pub const SI_USER: i32 = 0;
    /// Sent by kernel
    pub const SI_KERNEL: i32 = 128;
    /// Sent by sigqueue
    pub const SI_QUEUE: i32 = -1;
    /// Sent by timer expiration
    pub const SI_TIMER: i32 = -2;
    /// Sent by real-time mesq state change
    pub const SI_MESGQ: i32 = -3;
    /// Sent by AIO completion
    pub const SI_ASYNCIO: i32 = -4;
    /// Sent by queued SIGIO
    pub const SI_SIGIO: i32 = -5;
    /// Sent by tkill/tgkill
    pub const SI_TKILL: i32 = -6;
}

impl SigInfo {
    /// Create siginfo for a user-sent signal
    pub fn from_kill(sig: u32, pid: i32, uid: u32) -> Self {
        Self {
            si_signo: sig as i32,
            si_errno: 0,
            si_code: si_code::SI_USER,
            _pad0: 0,
            _sifields: SigInfoFields {
                kill: SigInfoKill {
                    si_pid: pid,
                    si_uid: uid,
                },
            },
        }
    }

    /// Write siginfo to user space
    pub fn write_to_user(&self, ptr: u64) -> Result<(), i32> {
        // Write si_signo (offset 0)
        if put_user::<Uaccess, i32>(ptr, self.si_signo).is_err() {
            return Err(14); // EFAULT
        }
        // Write si_errno (offset 4)
        if put_user::<Uaccess, i32>(ptr + 4, self.si_errno).is_err() {
            return Err(14);
        }
        // Write si_code (offset 8)
        if put_user::<Uaccess, i32>(ptr + 8, self.si_code).is_err() {
            return Err(14);
        }
        // Write _pad0 (offset 12)
        if put_user::<Uaccess, i32>(ptr + 12, self._pad0).is_err() {
            return Err(14);
        }
        // Write kill fields (offset 16)
        // Safety: We always initialize _sifields
        let kill = unsafe { self._sifields.kill };
        if put_user::<Uaccess, i32>(ptr + 16, kill.si_pid).is_err() {
            return Err(14);
        }
        if put_user::<Uaccess, u32>(ptr + 20, kill.si_uid).is_err() {
            return Err(14);
        }
        Ok(())
    }

    /// Read siginfo from user space
    ///
    /// # Arguments
    /// * `ptr` - User-space pointer to siginfo_t (128 bytes)
    /// * `sig` - Expected signal number for validation
    ///
    /// # Returns
    /// Ok(SigInfo) on success, Err(errno) on error
    pub fn read_from_user(ptr: u64, sig: u32) -> Result<Self, i32> {
        // Read si_signo (offset 0)
        let si_signo = match get_user::<Uaccess, i32>(ptr) {
            Ok(v) => v,
            Err(_) => return Err(14), // EFAULT
        };
        // Read si_errno (offset 4)
        let si_errno = match get_user::<Uaccess, i32>(ptr + 4) {
            Ok(v) => v,
            Err(_) => return Err(14),
        };
        // Read si_code (offset 8)
        let si_code = match get_user::<Uaccess, i32>(ptr + 8) {
            Ok(v) => v,
            Err(_) => return Err(14),
        };
        // Read si_pid (offset 16)
        let si_pid = match get_user::<Uaccess, i32>(ptr + 16) {
            Ok(v) => v,
            Err(_) => return Err(14),
        };
        // Read si_uid (offset 20)
        let si_uid = match get_user::<Uaccess, u32>(ptr + 20) {
            Ok(v) => v,
            Err(_) => return Err(14),
        };

        // Validate si_signo matches expected signal
        if si_signo != sig as i32 {
            return Err(22); // EINVAL
        }

        Ok(Self {
            si_signo,
            si_errno,
            si_code,
            _pad0: 0,
            _sifields: SigInfoFields {
                kill: SigInfoKill { si_pid, si_uid },
            },
        })
    }

    /// Get si_code value
    pub fn code(&self) -> i32 {
        self.si_code
    }

    /// Get sender's PID from siginfo
    pub fn pid(&self) -> i32 {
        // Safety: We always initialize _sifields with kill variant
        unsafe { self._sifields.kill.si_pid }
    }
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

        Some(tv_sec as u64 * 1_000_000_000 + tv_nsec as u64)
    } else {
        None // Infinite wait
    };

    let tid = current_tid();

    // Cannot wait for SIGKILL or SIGSTOP (they're always delivered)
    let mut mask = wait_set;
    mask.remove(SIGKILL);
    mask.remove(SIGSTOP);

    // Check if any signals in the set are already pending
    let dequeued_sig = with_task_signal_state(tid, |state| {
        // Check private pending
        let deliverable = state.pending.signal.intersect(&mask);
        if let Some(sig) = deliverable.first() {
            state.pending.remove(sig);
            state.recalc_sigpending();
            return Some(sig);
        }

        // Check shared pending
        let mut shared = state.shared_pending.lock();
        let deliverable = shared.signal.intersect(&mask);
        if let Some(sig) = deliverable.first() {
            shared.remove(sig);
            drop(shared);
            state.recalc_sigpending();
            return Some(sig);
        }

        None
    });

    if let Some(Some(sig)) = dequeued_sig {
        // Signal was pending - return it
        if info_ptr != 0 {
            // Create basic siginfo (SI_USER with pid/uid 0 since we don't track sender)
            let siginfo = SigInfo::from_kill(sig, 0, 0);
            if siginfo.write_to_user(info_ptr).is_err() {
                return -14; // EFAULT
            }
        }
        return sig as i64;
    }

    // No signal pending - check if we should wait
    match timeout_ns {
        Some(0) => {
            // Zero timeout - return immediately
            -11 // EAGAIN
        }
        Some(_ns) => {
            // Non-zero timeout - for now, just return EAGAIN
            // TODO: Implement actual sleeping with timeout
            -11 // EAGAIN
        }
        None => {
            // Infinite wait - for now, just return EAGAIN
            // TODO: Implement actual sleeping
            -11 // EAGAIN
        }
    }
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

    with_task_signal_state(tid, |state| {
        // Return old stack if requested
        if oss_ptr != 0 {
            let old = &state.altstack;
            // Write ss_sp (offset 0)
            if put_user::<Uaccess, u64>(oss_ptr, old.ss_sp).is_err() {
                return -14i64; // EFAULT
            }
            // Write ss_flags (offset 8)
            if put_user::<Uaccess, i32>(oss_ptr + 8, old.ss_flags).is_err() {
                return -14; // EFAULT
            }
            // Write ss_size (offset 16, with padding after flags)
            if put_user::<Uaccess, u64>(oss_ptr + 16, old.ss_size as u64).is_err() {
                return -14; // EFAULT
            }
        }

        // Set new stack if provided
        if ss_ptr != 0 {
            // Read ss_sp (offset 0)
            let ss_sp = match get_user::<Uaccess, u64>(ss_ptr) {
                Ok(v) => v,
                Err(_) => return -14, // EFAULT
            };
            // Read ss_flags (offset 8)
            let ss_flags_val = match get_user::<Uaccess, i32>(ss_ptr + 8) {
                Ok(v) => v,
                Err(_) => return -14, // EFAULT
            };
            // Read ss_size (offset 16)
            let ss_size = match get_user::<Uaccess, u64>(ss_ptr + 16) {
                Ok(v) => v as usize,
                Err(_) => return -14, // EFAULT
            };

            // Cannot change while on signal stack
            // TODO: Check if currently on signal stack using SP
            // For now, we skip this check

            // Validate flags - only SS_DISABLE and SS_FLAG_BITS are valid
            let mode = ss_flags_val & !ss_flags::SS_FLAG_BITS;
            if mode != 0 && mode != ss_flags::SS_DISABLE {
                return -22; // EINVAL
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
                    return -12; // ENOMEM
                }

                state.altstack = AltStack {
                    ss_sp,
                    ss_size,
                    ss_flags: ss_flags_val,
                };
            }
        }

        0i64
    })
    .unwrap_or(-3) // ESRCH
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
    use crate::pipe::FD_CLOEXEC;
    use crate::signalfd::{create_signalfd, get_signalfd, sfd_flags};
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
            let limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_NOFILE);
            if limit == crate::rlimit::RLIM_INFINITY {
                u64::MAX
            } else {
                limit
            }
        };

        match table.alloc_with_flags(file, fd_flags, nofile_limit) {
            Ok(new_fd) => new_fd as i64,
            Err(e) => -(e as i64),
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
                fd as i64
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

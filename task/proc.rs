//! Process lifecycle syscalls
//!
//! This module contains syscalls for process/thread creation and termination:
//! - fork, vfork (process creation)
//! - clone, clone3 (process/thread creation with flags)
//! - exit (process termination)
//! - wait4, waitid (child process waiting)
//! - set_tid_address (thread exit notification)

use super::misc::Rusage;
use crate::signal::SigInfo;
use crate::uaccess::UserPtr;
use crate::util::error::{KernelError, KernelResult};

/// sys_sched_yield - yield the processor
///
/// Causes the calling thread to relinquish the CPU. The thread is moved
/// to the end of the queue for its priority and a new thread gets to run.
pub fn sys_sched_yield() {
    super::percpu::yield_now();
}

/// Wait queue for parents in wait4/waitid: woken whenever a task exits
/// (Linux signal->wait_chldexit, simplified to one global queue; waiters
/// re-check for their own zombies)
pub static CHILD_EXIT_WQ: crate::sync::waitqueue::WaitQueue =
    crate::sync::waitqueue::WaitQueue::new();

/// sys_exit - terminate the calling process
///
/// # Arguments
/// * `status` - Exit code; the low 8 bits are reported to the parent
///
/// This function never returns. The task is marked as zombie and the
/// scheduler switches to the next runnable task.
pub fn sys_exit(status: i32) -> u64 {
    do_exit((status & 0xff) << 8)
}

/// sys_exit_group - terminate every thread of the process (Linux
/// do_group_exit)
pub fn sys_exit_group(status: i32) -> u64 {
    crate::signal::do_group_exit((status & 0xff) << 8)
}

/// Terminate the current task with a Linux wait status word
///
/// `(code << 8)` for a normal exit, the signal number (| 0x80 if a core was
/// dumped) for a signal death, exactly what wait4 reports.
pub fn do_exit(wait_status: i32) -> ! {
    // Release everything, become a zombie carrying the status for
    // wait4/waitid, switch away (never returns)
    super::percpu::exit_current(Some(wait_status));
}

/// sys_clone - create a new thread or process
///
/// # Arguments
/// * `flags` - Clone flags (CLONE_VM, CLONE_THREAD, etc.)
/// * `child_stack` - Stack pointer for child (required for CLONE_VM)
/// * `parent_tidptr` - Where to store parent TID (if CLONE_PARENT_SETTID),
///   or the child's pidfd (if CLONE_PIDFD)
/// * `_child_tidptr` - Where to store child TID (if CLONE_CHILD_SETTID)
/// * `_tls` - TLS pointer for child (if CLONE_SETTLS)
///
/// The child gets a copy of the caller's user registers (its pt_regs).
///
/// # Returns
/// * > 0: Child TID (to parent)
/// * 0: Child returns 0 (handled via TrapFrame)
/// * < 0: Error code
pub fn sys_clone(
    flags: u64,
    child_stack: u64,
    parent_tidptr: UserPtr<i32>,
    child_tidptr: UserPtr<i32>,
    tls: u64,
) -> KernelResult<i64> {
    // Legacy clone() only takes the low 32 flag bits (kernel/fork.c:
    // lower_32_bits(clone_flags)); higher flags such as CLONE_CLEAR_SIGHAND
    // are only reachable through clone3().
    let flags = flags & 0xffff_ffff;

    // exit_signal: the low 8 bits of flags (CSIGNAL), as given (Linux
    // kernel_clone checks no legacy clone's)
    let exit_signal = crate::signal::ExitSignal::csignal(flags as u8);

    // CLONE_PIDFD stores the pidfd at parent_tid (Linux sys_clone: one
    // pointer for both), so CLONE_PARENT_SETTID with it is EINVAL
    // (kernel_clone)
    use super::clone_flags::{CLONE_PARENT_SETTID, CLONE_PIDFD};
    let pidfd_ptr = if flags & CLONE_PIDFD != 0 {
        if flags & CLONE_PARENT_SETTID != 0 {
            return Err(KernelError::InvalidArgument);
        }
        parent_tidptr.addr()
    } else {
        0
    };

    clone(super::percpu::CloneConfig {
        flags: flags & !0xff, // Remove signal bits from flags
        child_stack,
        parent_tidptr: parent_tidptr.addr(),
        child_tidptr: child_tidptr.addr(),
        tls,
        pidfd_ptr,
        exit_signal,
        cgroup_fd: -1, // CLONE_INTO_CGROUP only supported via clone3
        set_tid: super::percpu::CloneConfig::NO_SET_TID,
        set_tid_size: 0,
    })
}

/// Create the task described by `config` (do_clone with the global
/// frame allocator): the child's tid
fn clone(config: super::percpu::CloneConfig) -> KernelResult<i64> {
    let mut frame_alloc = crate::mm::frame_alloc::FrameAllocRef(&crate::FRAME_ALLOCATOR);
    Ok(super::percpu::do_clone(config, &mut frame_alloc)? as i64)
}

/// sys_fork - create a new process (classic fork)
///
/// Creates a new process by duplicating the calling process.
/// The child process has a copy of the parent's address space.
///
/// # Returns
/// * > 0: Child PID (to parent)
/// * 0: Child returns 0
/// * < 0: Error code
pub fn sys_fork() -> KernelResult<i64> {
    // fork() is clone() with no CLONE_* flags and child_stack = 0 (inherit parent stack)
    clone(super::percpu::CloneConfig {
        flags: 0,       // No sharing flags = fork semantics
        child_stack: 0, // 0 = inherit parent's stack pointer
        parent_tidptr: 0,
        child_tidptr: 0,
        tls: 0,
        pidfd_ptr: 0,
        exit_signal: crate::signal::ExitSignal::SIGCHLD, // fork sends SIGCHLD on exit
        cgroup_fd: -1,
        set_tid: super::percpu::CloneConfig::NO_SET_TID,
        set_tid_size: 0,
    })
}

/// sys_vfork - create a child process and block until it exec()s or _exit()s
///
/// vfork() is similar to fork() but:
/// 1. The child shares the parent's address space (CLONE_VM)
/// 2. The parent is suspended until the child calls exec() or _exit()
///
/// This is an optimization for the common fork+exec pattern.
///
/// The user-space contract (not a Rust one):
/// The child MUST NOT:
/// - Return from the function containing vfork()
/// - Modify any data except the vfork() return value
/// - Call exit() (only _exit() is safe)
///
/// # Returns
/// * > 0: Child PID (to parent, after child exits/execs)
/// * 0: Child returns 0
/// * < 0: Error code
pub fn sys_vfork() -> KernelResult<i64> {
    use crate::task::clone_flags::{CLONE_VFORK, CLONE_VM};

    // vfork() = clone(CLONE_VM | CLONE_VFORK, parent_stack)
    // Child shares address space and parent blocks until child exec()s or _exit()s
    clone(super::percpu::CloneConfig {
        flags: CLONE_VM | CLONE_VFORK,
        child_stack: super::percpu::current_pt_regs().sp(), // the parent's (CLONE_VM needs one)
        parent_tidptr: 0,
        child_tidptr: 0,
        tls: 0,
        pidfd_ptr: 0,
        exit_signal: crate::signal::ExitSignal::SIGCHLD, // vfork sends SIGCHLD on exit
        cgroup_fd: -1,
        set_tid: super::percpu::CloneConfig::NO_SET_TID,
        set_tid_size: 0,
    })
}

/// sys_wait4 - wait for child process state change
///
/// # Arguments
/// * `pid` - Which children to wait for:
///   - pid > 0: wait for specific child
///   - pid == -1: wait for any child
///   - pid == 0: wait for any child in same process group
/// * `wstatus` - Pointer to store status (can be null)
/// * `options` - WNOHANG, etc.
/// * `_rusage` - Resource usage (ignored)
///
/// # Returns
/// * > 0: PID of terminated child
/// * 0: WNOHANG and no child ready
/// * -ECHILD: No matching children
pub fn sys_wait4(
    pid: i64,
    wstatus: UserPtr<i32>,
    options: i32,
    rusage: UserPtr<Rusage>,
) -> KernelResult<i64> {
    use super::wait_options::WNOHANG;

    // Linux kernel_wait4: WEXITED/WNOWAIT and the like are waitid-only
    const WUNTRACED: i32 = 2;
    const WCONTINUED: i32 = 8;
    const WNOTHREAD: i32 = 0x2000_0000;
    let valid = WNOHANG
        | WUNTRACED
        | WCONTINUED
        | WNOTHREAD
        | super::wait_options::__WCLONE
        | super::wait_options::__WALL;
    if options & !valid != 0 {
        return Err(KernelError::InvalidArgument);
    }

    let current_pid = super::percpu::current_pid();
    let pid = wait_target(pid).ok_or(KernelError::NoChild)?;

    use super::percpu::{SleepState, schedule};
    use crate::sync::waitqueue::{WaitEntry, signal_pending};

    // Sleep on CHILD_EXIT_WQ until a matching child is a zombie
    let w = core::pin::pin!(WaitEntry::new());
    let result = loop {
        CHILD_EXIT_WQ.prepare_to_wait(w.as_ref(), SleepState::Interruptible);

        // A tracee's ptrace stop: (code << 8) | 0x7f (Linux
        // wait_task_stopped)
        if let Some((tid, code)) = super::percpu::wait_traced(current_pid, pid, false) {
            let st = ((code as i32) << 8) | 0x7f;
            break put_status(wstatus, st).map(|()| tid as i64);
        }
        if let Some((child_pid, wait_status, utime, stime)) =
            super::percpu::reap_zombie_child_times(current_pid, pid, options)
        {
            // The zombie holds the Linux wait status word; the child's
            // and its children's CPU time (Linux getrusage(RUSAGE_BOTH))
            let r = put_status(wstatus, wait_status).and_then(|()| put_times(rusage, utime, stime));
            break r.map(|()| child_pid as i64);
        }

        // No zombie child found - check if we have any children at all
        if !super::percpu::has_children(current_pid, pid, options)
            && !super::percpu::has_tracees(current_pid, pid)
        {
            break Err(KernelError::NoChild);
        }

        // If WNOHANG, return 0 (no child ready)
        if options & WNOHANG != 0 {
            break Ok(0);
        }

        if signal_pending() {
            break Err(KernelError::RestartSys);
        }
        schedule();
    };
    CHILD_EXIT_WQ.finish_wait(w.as_ref());
    result
}

/// Store wait4's status word, if asked for
fn put_status(wstatus: UserPtr<i32>, st: i32) -> KernelResult<()> {
    if !wstatus.is_null() {
        wstatus.write(&st)?;
    }
    Ok(())
}

/// Store a reaped child's CPU times, if asked for
fn put_times(rusage: UserPtr<Rusage>, utime: u64, stime: u64) -> KernelResult<()> {
    if !rusage.is_null() {
        super::misc::put_rusage_times(rusage, utime, stime)?;
    }
    Ok(())
}

/// wait4's `pid` (> 0 a child, < -1 a group, 0 the caller's group, -1
/// any) with the caller's numbers made root ones: None if it names a
/// pid the caller does not see, which no child matches (Linux
/// find_get_pid: NULL, so ECHILD)
fn wait_target(pid: i64) -> Option<i64> {
    use crate::task::pid::from_vnr;
    let root = |nr: u64| from_vnr(nr).and_then(|r| i64::try_from(r).ok());
    match pid {
        -1 | 0 => Some(pid),
        p if p > 0 => root(p as u64),
        p => root(p.unsigned_abs()).map(|r| -r),
    }
}

/// The siginfo bytes waitid writes: si_signo through si_status
const WAITID_INFO: usize = 28;

/// Write the siginfo fields waitid fills (Linux kernel_waitid's
/// unsafe_put_user: si_signo through si_status, the rest untouched)
fn put_waitid_info(infop: UserPtr<SigInfo>, info: &SigInfo) -> KernelResult<()> {
    use crate::util::pod::IntoBytes;
    if infop.is_null() {
        return Ok(());
    }
    let head = &info.as_bytes()[..WAITID_INFO];
    crate::uaccess::copy_to_user::<crate::arch::Uaccess>(infop.addr(), head)?;
    Ok(())
}

/// SIGCHLD info for waitid: `code` (CLD_*), the child and its status
fn chld_info(code: i32, pid: i32, status: i32) -> crate::signal::SigInfo {
    let fields = crate::signal::SigFields::Chld {
        pid,
        uid: 0,
        status,
        utime: 0,
        stime: 0,
    };
    crate::signal::SigInfo::new(crate::signal::SIGCHLD, code, fields)
}

/// sys_waitid - wait for child process state change (extended interface)
///
/// # Arguments
/// * `idtype` - Type of ID:
///   - P_PID (1): wait for specific child
///   - P_PGID (2): wait for any child in process group
///   - P_ALL (0): wait for any child
/// * `id` - The ID value (PID or PGID depending on idtype)
/// * `infop` - Pointer to siginfo_t structure to fill
/// * `options` - WEXITED, WSTOPPED, WCONTINUED, WNOHANG, WNOWAIT
/// * `rusage` - Optional `struct rusage *` filled with the child's usage
///   (Linux kernel/exit.c: waitid takes 5 args)
///
/// # Returns
/// * 0: Success (or WNOHANG with no child ready)
/// * -ECHILD: No matching children
/// * -EINVAL: Invalid arguments
pub fn sys_waitid(
    idtype: i32,
    id: u64,
    infop: UserPtr<SigInfo>,
    options: i32,
    rusage: UserPtr<Rusage>,
) -> KernelResult<i64> {
    use super::wait_options::{P_ALL, P_PGID, P_PID, P_PIDFD, WEXITED, WNOHANG};

    use crate::signal::si_code;
    use crate::uaccess::access_ok;

    let current_pid = super::percpu::current_pid();

    // Validate infop pointer if non-null
    if !infop.is_null() && !access_ok(infop.addr(), WAITID_INFO) {
        return Err(KernelError::BadAddress);
    }

    // Validate idtype
    if idtype != P_ALL && idtype != P_PID && idtype != P_PGID && idtype != P_PIDFD {
        return Err(KernelError::InvalidArgument);
    }

    // Must specify at least one wait condition
    // For now we only support WEXITED (terminated children)
    if options & WEXITED == 0 {
        // We don't support WSTOPPED or WCONTINUED yet
        return Err(KernelError::InvalidArgument);
    }

    // An O_NONBLOCK pidfd waits as with WNOHANG, EAGAIN where WNOHANG
    // itself would return 0 (Linux kernel_waitid_prepare, kernel_waitid)
    let mut nohang = options & WNOHANG != 0;

    // Convert idtype/id to the pid format used by wait4/reap_zombie_child:
    // pid > 0: specific child
    // pid == -1: any child (P_ALL)
    // pid == 0: same process group
    // pid < -1: process group -pid
    let wait_pid: i64 = match idtype {
        P_ALL => -1,
        P_PID => id as i64,
        P_PGID => {
            if id == 0 {
                0 // Same process group as caller
            } else {
                -(id as i64) // Specific process group
            }
        }
        P_PIDFD => {
            // id is a file descriptor - get the PID from the pidfd
            let file = crate::fs::io::fget(id as i32)?;
            // not a pidfd: EBADF
            let pid = crate::task::pidfd::get_pidfd_pid(&file).ok_or(KernelError::BadFd)?;
            nohang |= file.get_flags() & crate::fs::file::flags::O_NONBLOCK != 0;
            pid as i64
        }
        _ => return Err(KernelError::InvalidArgument),
    };
    // A pidfd names its pid by root number already
    let wait_pid = if idtype == P_PIDFD {
        wait_pid
    } else {
        wait_target(wait_pid).ok_or(KernelError::NoChild)?
    };

    use super::percpu::{SleepState, schedule};
    use crate::sync::waitqueue::{WaitEntry, signal_pending};

    // Sleep on CHILD_EXIT_WQ until a matching child is a zombie
    let w = core::pin::pin!(WaitEntry::new());
    let result = loop {
        CHILD_EXIT_WQ.prepare_to_wait(w.as_ref(), SleepState::Interruptible);

        // A tracee's ptrace stop (CLD_TRAPPED)
        let wnowait = options & super::wait_options::WNOWAIT != 0;
        if let Some((tid, code)) = super::percpu::wait_traced(current_pid, wait_pid, wnowait) {
            let info = chld_info(si_code::CLD_TRAPPED, tid as i32, code as i32);
            break put_waitid_info(infop, &info).map(|()| 0);
        }

        // Reap a zombie child (with WNOWAIT, only report it)
        if let Some((child_pid, wait_status, utime, stime)) =
            super::percpu::reap_zombie_child_times(current_pid, wait_pid, options)
        {
            // Decode the wait status word (exit code vs. killing signal)
            let termsig = wait_status & 0x7f;
            let (code, status) = if termsig == 0 {
                (si_code::CLD_EXITED, (wait_status >> 8) & 0xff)
            } else if wait_status & 0x80 != 0 {
                (si_code::CLD_DUMPED, termsig)
            } else {
                (si_code::CLD_KILLED, termsig)
            };
            let info = chld_info(code, child_pid as i32, status);
            let r = put_times(rusage, utime, stime).and_then(|()| put_waitid_info(infop, &info));
            break r.map(|()| 0);
        }

        // No zombie child found - check if we have any children at all
        if !super::percpu::has_children(current_pid, wait_pid, options)
            && !super::percpu::has_tracees(current_pid, wait_pid)
        {
            break Err(KernelError::NoChild);
        }

        // If WNOHANG, return 0 with a zeroed siginfo (si_pid 0: no
        // child); EAGAIN for a non-blocking pidfd without WNOHANG
        if nohang {
            if let Err(e) = put_waitid_info(infop, &SigInfo::default()) {
                break Err(e);
            }
            if options & WNOHANG == 0 {
                break Err(KernelError::WouldBlock);
            }
            break Ok(0);
        }

        if signal_pending() {
            break Err(KernelError::RestartSys);
        }
        schedule();
    };
    CHILD_EXIT_WQ.finish_wait(w.as_ref());
    result
}

/// sys_set_tid_address - Set pointer for thread ID clearing on exit
///
/// Sets the `clear_child_tid` address for the calling thread. When the thread
/// exits:
/// 1. The kernel writes 0 to this address
/// 2. The kernel performs futex(FUTEX_WAKE, 1) on this address
///
/// This mechanism is used by pthread libraries to implement thread joining.
/// The thread library stores a futex here and the parent waits on it.
///
/// Returns the caller's thread ID.
pub fn sys_set_tid_address(tidptr: UserPtr<i32>) -> i64 {
    let me = super::percpu::current();
    crate::task::set_clear_child_tid(&me, tidptr.addr());
    me.tid() as i64
}

// =============================================================================
// clone3 syscall - Modern extensible process/thread creation
// =============================================================================

/// clone_args structure for clone3 syscall (matches Linux struct clone_args)
///
/// The structure is versioned by size, allowing future extensions.
/// Fields are 64-bit aligned as required by Linux ABI.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct CloneArgs {
    /// Clone flags (CLONE_* constants, except CSIGNAL bits)
    pub flags: u64,
    /// File descriptor for pidfd (CLONE_PIDFD)
    pub pidfd: u64,
    /// Address to store child TID in child's memory (CLONE_CHILD_SETTID)
    pub child_tid: u64,
    /// Address to store child TID in parent's memory (CLONE_PARENT_SETTID)
    pub parent_tid: u64,
    /// Exit signal for child (replaces low bits of clone() flags)
    pub exit_signal: u64,
    /// Lowest address of the stack (stack grows down on x86/arm)
    pub stack: u64,
    /// Size of the stack in bytes
    pub stack_size: u64,
    /// TLS pointer for child (CLONE_SETTLS)
    pub tls: u64,
    /// The child's pid in each innermost level (an array of pid_t)
    pub set_tid: u64,
    /// Size of set_tid array
    pub set_tid_size: u64,
    /// Cgroup file descriptor (CLONE_INTO_CGROUP, not implemented)
    pub cgroup: u64,
}

crate::pod!(CloneArgs {
    flags,
    pidfd,
    child_tid,
    parent_tid,
    exit_signal,
    stack,
    stack_size,
    tls,
    set_tid,
    set_tid_size,
    cgroup,
});

/// Size of clone_args version 0 (flags through tls)
pub const CLONE_ARGS_SIZE_VER0: usize = 64;
/// Size of clone_args version 1 (adds set_tid, set_tid_size)
pub const CLONE_ARGS_SIZE_VER1: usize = 80;
/// Size of clone_args version 2 (adds cgroup)
pub const CLONE_ARGS_SIZE_VER2: usize = 88;

/// CLONE_INTO_CGROUP flag (clone3 only)
const CLONE_INTO_CGROUP: u64 = 0x200000000;

/// Signal mask for exit signal
const CSIGNAL: u64 = 0x000000ff;

/// sys_clone3 - create a new process with extended arguments
///
/// This is the modern, extensible syscall for process/thread creation.
/// It takes a struct clone_args that is versioned by size.
///
/// # Arguments
/// * `uargs` - User pointer to struct clone_args
/// * `size` - Size of the clone_args structure
///
/// # Returns
/// * > 0: Child PID/TID (to parent)
/// * 0: Child returns 0
/// * < 0: Error code
pub fn sys_clone3(uargs: UserPtr<CloneArgs>, size: u64) -> KernelResult<i64> {
    use super::percpu::CloneConfig;
    use crate::arch::Uaccess;
    use crate::uaccess::copy_struct_from_user;

    // Linux clone3: more than a page is E2BIG, less than VER0 EINVAL
    if size > 4096 {
        return Err(KernelError::ArgListTooLong);
    }
    if size < CLONE_ARGS_SIZE_VER0 as u64 {
        return Err(KernelError::InvalidArgument);
    }
    // A larger struct than this kernel's must be zero past it (E2BIG)
    let args = match copy_struct_from_user::<Uaccess, CloneArgs>(uargs.addr(), size as usize) {
        Ok(a) => a,
        Err(None) => return Err(KernelError::ArgListTooLong),
        Err(Some(_)) => return Err(KernelError::BadAddress),
    };

    // Validate clone3-specific constraints

    // exit_signal: CSIGNAL bits only, then a signal or 0 (Linux
    // copy_clone_args_from_user, clone3_args_valid: valid_signal)
    if (args.exit_signal & !CSIGNAL) != 0 || args.exit_signal > u64::from(crate::signal::NSIG) {
        return Err(KernelError::InvalidArgument);
    }
    // 0..=NSIG: fits the CSIGNAL byte
    let exit_signal = crate::signal::ExitSignal::csignal(args.exit_signal as u8);

    // CLONE_INTO_CGROUP requires cgroup fd and VER2 size
    let cgroup_fd = if (args.flags & CLONE_INTO_CGROUP) != 0 {
        if size < CLONE_ARGS_SIZE_VER2 as u64 {
            return Err(KernelError::InvalidArgument);
        }
        args.cgroup as i32
    } else {
        -1
    };

    // set_tid: at most MAX_PID_NS_LEVEL numbers, a pointer exactly
    // when a size (EINVAL), copied in now (EFAULT); checked against the
    // child's namespace at clone (Linux copy_clone_args_from_user)
    let size_ok = args.set_tid_size <= u64::from(crate::ns::pid::MAX_PID_NS_LEVEL);
    if !size_ok || (args.set_tid == 0) != (args.set_tid_size == 0) {
        return Err(KernelError::InvalidArgument);
    }
    let n = args.set_tid_size as usize;
    let mut set_tid = CloneConfig::NO_SET_TID;
    if n > 0 {
        let mut b = [0u8; 4 * crate::ns::pid::MAX_PID_NS_LEVEL as usize];
        crate::uaccess::copy_from_user::<Uaccess>(&mut b[..n * 4], args.set_tid, n * 4)?;
        for (t, c) in set_tid.iter_mut().zip(b[..n * 4].as_chunks::<4>().0) {
            *t = u32::from_ne_bytes(*c);
        }
    }

    // Validate stack - if stack is provided, stack_size must also be provided
    if args.stack != 0 && args.stack_size == 0 {
        return Err(KernelError::InvalidArgument);
    }
    if args.stack == 0 && args.stack_size != 0 {
        return Err(KernelError::InvalidArgument);
    }

    // The pidfd and the parent's tid cannot share one place (Linux
    // kernel_clone)
    let both = super::clone_flags::CLONE_PIDFD | super::clone_flags::CLONE_PARENT_SETTID;
    if args.flags & both == both && args.pidfd == args.parent_tid {
        return Err(KernelError::InvalidArgument);
    }

    // CLONE_THREAD or CLONE_PARENT cannot have exit_signal
    let clone_thread = super::clone_flags::CLONE_THREAD;
    let clone_parent = super::clone_flags::CLONE_PARENT;
    if (args.flags & (clone_thread | clone_parent)) != 0 && args.exit_signal != 0 {
        return Err(KernelError::InvalidArgument);
    }

    // Calculate actual child stack pointer
    // clone3 provides stack base and size; we need to compute the stack top
    let child_stack = if args.stack != 0 {
        // Stack grows down, so stack top = stack + stack_size
        args.stack.wrapping_add(args.stack_size)
    } else {
        0 // Inherit parent stack (for fork-like behavior)
    };

    clone(CloneConfig {
        flags: args.flags,
        child_stack,
        parent_tidptr: args.parent_tid,
        child_tidptr: args.child_tid,
        tls: args.tls,
        pidfd_ptr: args.pidfd,
        exit_signal,
        cgroup_fd,
        set_tid,
        set_tid_size: n,
    })
}

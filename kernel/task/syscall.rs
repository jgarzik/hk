//! Task-related syscalls (getpid, gettid, sched_yield, exit, clone, etc.)
//!
//! Generic handlers for scheduler and task syscalls.
//! These are called by arch-specific syscall dispatchers.

use super::{Pid, Tid};

// Linux error codes
const EPERM: i64 = -1; // Operation not permitted
const ESRCH: i64 = -3; // No such process
const ECHILD: i64 = -10; // No child processes
const EINVAL: i64 = -22; // Invalid argument

/// sys_getpid - get current process ID
pub fn sys_getpid(pid: Pid) -> i64 {
    pid as i64
}

/// sys_gettid - get current thread ID
pub fn sys_gettid(tid: Tid) -> i64 {
    tid as i64
}

/// sys_getppid - get parent process ID
///
/// Returns the process ID of the parent of the calling process.
/// For init (PID 1), returns 0.
pub fn sys_getppid(ppid: Pid) -> i64 {
    ppid as i64
}

/// sys_getuid - get real user ID
///
/// Returns the real user ID of the calling process.
/// No locking needed - credentials are immutable during syscall execution.
pub fn sys_getuid(uid: u32) -> i64 {
    uid as i64
}

/// sys_geteuid - get effective user ID
///
/// Returns the effective user ID of the calling process.
/// No locking needed - credentials are immutable during syscall execution.
pub fn sys_geteuid(euid: u32) -> i64 {
    euid as i64
}

/// sys_getgid - get real group ID
///
/// Returns the real group ID of the calling process.
/// No locking needed - credentials are immutable during syscall execution.
pub fn sys_getgid(gid: u32) -> i64 {
    gid as i64
}

/// sys_getegid - get effective group ID
///
/// Returns the effective group ID of the calling process.
/// No locking needed - credentials are immutable during syscall execution.
pub fn sys_getegid(egid: u32) -> i64 {
    egid as i64
}

/// sys_setuid - set user identity (Linux-compatible)
///
/// If the caller is privileged (euid=0), sets real, saved, effective, and
/// filesystem UID to the specified value. After this, root privileges are
/// permanently dropped.
///
/// If not privileged, can only set effective UID (and fsuid) to the current
/// real UID or saved set-user-ID. This allows setuid programs to switch
/// between privileged and unprivileged states.
///
/// # Arguments
/// * `uid` - New user ID to set
/// * `current_cred` - Current credentials (passed from dispatcher)
///
/// # Returns
/// * 0 on success
/// * -EPERM if not permitted
///
/// # Linux semantics
/// This matches setuid(2) with _POSIX_SAVED_IDS:
/// - Privileged: sets uid, suid, euid, fsuid (permanently drops privileges)
/// - Unprivileged: sets only euid, fsuid (can switch between uid and suid)
pub fn sys_setuid(uid: u32, current_cred: super::Cred) -> i64 {
    // Privileged: euid==0 (or CAP_SETUID, which we don't have yet)
    if current_cred.euid == 0 {
        // Set all UIDs: uid, suid, euid, fsuid - permanently drops root
        super::percpu::set_current_uid_all(uid);
        return 0;
    }

    // Unprivileged: can only set euid to uid or suid
    if uid == current_cred.uid || uid == current_cred.suid {
        super::percpu::set_current_euid(uid);
        return 0;
    }

    // Not permitted
    EPERM
}

/// sys_setgid - set group identity (Linux-compatible)
///
/// If the caller is privileged (euid=0), sets real, saved, effective, and
/// filesystem GID to the specified value.
///
/// If not privileged, can only set effective GID (and fsgid) to the current
/// real GID or saved set-group-ID. This allows setgid programs to switch
/// between privileged and unprivileged states.
///
/// # Arguments
/// * `gid` - New group ID to set
/// * `current_cred` - Current credentials (passed from dispatcher)
///
/// # Returns
/// * 0 on success
/// * -EPERM if not permitted
///
/// # Linux semantics
/// This matches setgid(2) with _POSIX_SAVED_IDS:
/// - Privileged: sets gid, sgid, egid, fsgid
/// - Unprivileged: sets only egid, fsgid (can switch between gid and sgid)
///
/// Note: Linux checks euid==0 (not egid==0) for privilege.
pub fn sys_setgid(gid: u32, current_cred: super::Cred) -> i64 {
    // Privileged: euid==0 (or CAP_SETGID, which we don't have yet)
    // Note: Linux checks euid, not egid, for setgid privilege
    if current_cred.euid == 0 {
        // Set all GIDs: gid, sgid, egid, fsgid
        super::percpu::set_current_gid_all(gid);
        return 0;
    }

    // Unprivileged: can only set egid to gid or sgid
    if gid == current_cred.gid || gid == current_cred.sgid {
        super::percpu::set_current_egid(gid);
        return 0;
    }

    // Not permitted
    EPERM
}

/// sys_getpgid - get process group ID
///
/// Returns the process group ID of the process specified by pid.
/// If pid is 0, returns the PGID of the calling process.
///
/// # Arguments
/// * `pid` - Process ID to query (0 = calling process)
/// * `caller_pid` - PID of calling process
/// * `caller_pgid` - PGID of calling process
pub fn sys_getpgid(pid: Pid, caller_pid: Pid, caller_pgid: Pid) -> i64 {
    if pid == 0 || pid == caller_pid {
        caller_pgid as i64
    } else {
        match super::percpu::lookup_task_pgid(pid) {
            Some(pgid) => pgid as i64,
            None => ESRCH,
        }
    }
}

/// sys_getsid - get session ID
///
/// Returns the session ID of the process specified by pid.
/// If pid is 0, returns the SID of the calling process.
///
/// Note: Linux does NOT return EPERM for cross-session queries.
///
/// # Arguments
/// * `pid` - Process ID to query (0 = calling process)
/// * `caller_pid` - PID of calling process
/// * `caller_sid` - SID of calling process
pub fn sys_getsid(pid: Pid, caller_pid: Pid, caller_sid: Pid) -> i64 {
    if pid == 0 || pid == caller_pid {
        caller_sid as i64
    } else {
        match super::percpu::lookup_task_sid(pid) {
            Some(sid) => sid as i64,
            None => ESRCH,
        }
    }
}

/// sys_setpgid - set process group ID
///
/// Sets the process group ID of the process specified by pid to pgid.
/// If pid is 0, the calling process's PID is used.
/// If pgid is 0, the PID is used as the new PGID (creating a new process group).
///
/// # Restrictions
/// - Can only set PGID of self or child (we only support self for now)
/// - Cannot change PGID of session leader
/// - Target PGID must exist in same session, or pgid==pid (new group)
///
/// # Arguments
/// * `pid` - Process to modify (0 = calling process)
/// * `pgid` - New process group ID (0 = use pid)
/// * `caller_pid` - PID of calling process
/// * `caller_pgid` - Current PGID of calling process
/// * `caller_sid` - SID of calling process
pub fn sys_setpgid(
    pid: Pid,
    pgid: Pid,
    caller_pid: Pid,
    _caller_pgid: Pid,
    caller_sid: Pid,
) -> i64 {
    // Normalize pid and pgid
    let target_pid = if pid == 0 { caller_pid } else { pid };
    let new_pgid = if pgid == 0 { target_pid } else { pgid };

    // Validate pgid (cannot be negative in Linux, we use u64 so this is fine)
    if new_pgid == 0 {
        return EINVAL;
    }

    // For now, we only support setting own PGID (no child process support yet)
    if target_pid != caller_pid {
        // TODO: When we have fork(), allow setting child's PGID
        return ESRCH;
    }

    // Call the scheduler function to update the task
    match super::percpu::set_task_pgid(target_pid, new_pgid, caller_sid) {
        Ok(()) => {
            // Update per-CPU cached value if we changed our own PGID
            if target_pid == caller_pid {
                super::percpu::update_current_pgid_sid(new_pgid, caller_sid);
            }
            0
        }
        Err(errno) => -(errno as i64),
    }
}

/// sys_setsid - create session and set process group ID
///
/// Creates a new session if the calling process is not a process group leader.
/// Upon return, the calling process will be:
/// - The session leader of the new session
/// - The process group leader of a new process group
/// - Have no controlling terminal
///
/// # Returns
/// - Session ID (== PID) on success
/// - -EPERM if already a process group leader
pub fn sys_setsid(caller_pid: Pid, caller_pgid: Pid) -> i64 {
    match super::percpu::create_session(caller_pid, caller_pgid) {
        Ok(new_sid) => {
            // Update per-CPU cached values (pgid = sid = pid for new session leader)
            super::percpu::update_current_pgid_sid(new_sid, new_sid);
            new_sid as i64
        }
        Err(errno) => -(errno as i64),
    }
}

/// sys_sched_yield - yield the processor
///
/// Causes the calling thread to relinquish the CPU. The thread is moved
/// to the end of the queue for its priority and a new thread gets to run.
pub fn sys_sched_yield() {
    super::percpu::yield_now();
}

/// sys_exit - terminate the calling process
///
/// # Arguments
/// * `status` - Exit status (stored in zombie state for waitpid)
///
/// This function never returns. The task is marked as zombie and the
/// scheduler switches to the next runnable task.
pub fn sys_exit(status: i32) -> u64 {
    let tid = super::percpu::current_tid();

    // Mark task as Zombie (stores exit status for waitpid)
    super::percpu::mark_zombie(tid, status);

    // Remove from run queue and switch to another task (never returns)
    super::percpu::exit_current();
}

/// sys_clone - create a new thread or process
///
/// # Arguments
/// * `flags` - Clone flags (CLONE_VM, CLONE_THREAD, etc.)
/// * `child_stack` - Stack pointer for child (required for CLONE_VM)
/// * `_parent_tidptr` - Where to store parent TID (if CLONE_PARENT_SETTID)
/// * `_child_tidptr` - Where to store child TID (if CLONE_CHILD_SETTID)
/// * `_tls` - TLS pointer for child (if CLONE_SETTLS)
///
/// Note: Parent's RIP, RFLAGS, and RSP are retrieved from per-CPU data,
/// which is set at syscall entry.
///
/// # Returns
/// * > 0: Child TID (to parent)
/// * 0: Child returns 0 (handled via TrapFrame)
/// * < 0: Error code
#[cfg(target_arch = "x86_64")]
pub fn sys_clone(
    flags: u64,
    child_stack: u64,
    parent_tidptr: u64,
    child_tidptr: u64,
    tls: u64,
) -> i64 {
    use super::percpu::CloneConfig;
    use crate::FRAME_ALLOCATOR;
    use crate::arch::x86_64::percpu::{
        get_syscall_user_rflags, get_syscall_user_rip, get_syscall_user_rsp,
    };
    use crate::frame_alloc::FrameAllocRef;

    // Get parent's return address, flags, and stack from per-CPU data
    let parent_rip = get_syscall_user_rip();
    let parent_rflags = get_syscall_user_rflags();
    let parent_rsp = get_syscall_user_rsp();

    let config = CloneConfig {
        flags,
        child_stack,
        parent_rip,
        parent_rflags,
        parent_rsp,
        parent_tidptr,
        child_tidptr,
        tls,
    };

    // Get frame allocator
    let mut frame_alloc = FrameAllocRef(&FRAME_ALLOCATOR);

    match super::percpu::do_clone(config, &mut frame_alloc) {
        Ok(child_tid) => child_tid as i64,
        Err(errno) => -(errno as i64),
    }
}

/// sys_clone for aarch64 - create a new thread/process
#[cfg(target_arch = "aarch64")]
pub fn sys_clone(
    flags: u64,
    child_stack: u64,
    parent_tidptr: u64,
    child_tidptr: u64,
    tls: u64,
) -> i64 {
    use super::percpu::CloneConfig;
    use crate::FRAME_ALLOCATOR;
    use crate::arch::PerCpuOps;
    use crate::arch::aarch64::Aarch64Arch;
    use crate::frame_alloc::FrameAllocRef;

    // Get parent's return address, flags, and stack from per-CPU data
    let parent_rip = Aarch64Arch::get_syscall_user_rip();
    let parent_rflags = Aarch64Arch::get_syscall_user_rflags();
    let parent_rsp = Aarch64Arch::get_syscall_user_rsp();

    let config = CloneConfig {
        flags,
        child_stack,
        parent_rip,
        parent_rflags,
        parent_rsp,
        parent_tidptr,
        child_tidptr,
        tls,
    };

    // Get frame allocator
    let mut frame_alloc = FrameAllocRef(&FRAME_ALLOCATOR);

    match super::percpu::do_clone(config, &mut frame_alloc) {
        Ok(child_tid) => child_tid as i64,
        Err(errno) => -(errno as i64),
    }
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
#[cfg(target_arch = "x86_64")]
pub fn sys_fork() -> i64 {
    use super::percpu::CloneConfig;
    use crate::FRAME_ALLOCATOR;
    use crate::arch::x86_64::percpu::{
        get_syscall_user_rflags, get_syscall_user_rip, get_syscall_user_rsp,
    };
    use crate::frame_alloc::FrameAllocRef;

    // Get parent's return address, flags, and stack from per-CPU data
    let parent_rip = get_syscall_user_rip();
    let parent_rflags = get_syscall_user_rflags();
    let parent_rsp = get_syscall_user_rsp();

    // fork() is clone() with no CLONE_* flags and child_stack = 0 (inherit parent stack)
    let config = CloneConfig {
        flags: 0,       // No sharing flags = fork semantics
        child_stack: 0, // 0 = inherit parent's stack pointer
        parent_rip,
        parent_rflags,
        parent_rsp,
        parent_tidptr: 0,
        child_tidptr: 0,
        tls: 0,
    };

    // Get frame allocator
    let mut frame_alloc = FrameAllocRef(&FRAME_ALLOCATOR);

    match super::percpu::do_clone(config, &mut frame_alloc) {
        Ok(child_pid) => child_pid as i64,
        Err(errno) => -(errno as i64),
    }
}

/// sys_fork for aarch64 - create a new process (classic fork)
#[cfg(target_arch = "aarch64")]
pub fn sys_fork() -> i64 {
    use super::percpu::CloneConfig;
    use crate::FRAME_ALLOCATOR;
    use crate::arch::PerCpuOps;
    use crate::arch::aarch64::Aarch64Arch;
    use crate::frame_alloc::FrameAllocRef;

    // Get parent's return address, flags, and stack from per-CPU data
    let parent_rip = Aarch64Arch::get_syscall_user_rip();
    let parent_rflags = Aarch64Arch::get_syscall_user_rflags();
    let parent_rsp = Aarch64Arch::get_syscall_user_rsp();

    // fork() is clone() with no CLONE_* flags and child_stack = 0 (inherit parent stack)
    let config = CloneConfig {
        flags: 0,       // No sharing flags = fork semantics
        child_stack: 0, // 0 = inherit parent's stack pointer
        parent_rip,
        parent_rflags,
        parent_rsp,
        parent_tidptr: 0,
        child_tidptr: 0,
        tls: 0,
    };

    // Get frame allocator
    let mut frame_alloc = FrameAllocRef(&FRAME_ALLOCATOR);

    match super::percpu::do_clone(config, &mut frame_alloc) {
        Ok(child_pid) => child_pid as i64,
        Err(errno) => -(errno as i64),
    }
}

/// sys_vfork - create a child process and block until it exec()s or _exit()s
///
/// vfork() is similar to fork() but:
/// 1. The child shares the parent's address space (CLONE_VM)
/// 2. The parent is suspended until the child calls exec() or _exit()
///
/// This is an optimization for the common fork+exec pattern.
///
/// # Safety
/// The child MUST NOT:
/// - Return from the function containing vfork()
/// - Modify any data except the vfork() return value
/// - Call exit() (only _exit() is safe)
///
/// # Returns
/// * > 0: Child PID (to parent, after child exits/execs)
/// * 0: Child returns 0
/// * < 0: Error code
#[cfg(target_arch = "x86_64")]
pub fn sys_vfork() -> i64 {
    use super::percpu::CloneConfig;
    use crate::FRAME_ALLOCATOR;
    use crate::arch::x86_64::percpu::{
        get_syscall_user_rflags, get_syscall_user_rip, get_syscall_user_rsp,
    };
    use crate::frame_alloc::FrameAllocRef;
    use crate::task::clone_flags::{CLONE_VFORK, CLONE_VM};

    // Get parent's return address, flags, and stack from per-CPU data
    let parent_rip = get_syscall_user_rip();
    let parent_rflags = get_syscall_user_rflags();
    let parent_rsp = get_syscall_user_rsp();

    // vfork() = clone(CLONE_VM | CLONE_VFORK, parent_stack)
    // Child shares address space and parent blocks until child exec()s or _exit()s
    let config = CloneConfig {
        flags: CLONE_VM | CLONE_VFORK,
        child_stack: parent_rsp, // Use parent's stack (required for CLONE_VM)
        parent_rip,
        parent_rflags,
        parent_rsp,
        parent_tidptr: 0,
        child_tidptr: 0,
        tls: 0,
    };

    // Get frame allocator
    let mut frame_alloc = FrameAllocRef(&FRAME_ALLOCATOR);

    match super::percpu::do_clone(config, &mut frame_alloc) {
        Ok(child_pid) => child_pid as i64,
        Err(errno) => -(errno as i64),
    }
}

/// sys_vfork for aarch64 - create a child process and block until it exec()s or _exit()s
#[cfg(target_arch = "aarch64")]
pub fn sys_vfork() -> i64 {
    use super::percpu::CloneConfig;
    use crate::FRAME_ALLOCATOR;
    use crate::arch::PerCpuOps;
    use crate::arch::aarch64::Aarch64Arch;
    use crate::frame_alloc::FrameAllocRef;
    use crate::task::clone_flags::{CLONE_VFORK, CLONE_VM};

    // Get parent's return address, flags, and stack from per-CPU data
    let parent_rip = Aarch64Arch::get_syscall_user_rip();
    let parent_rflags = Aarch64Arch::get_syscall_user_rflags();
    let parent_rsp = Aarch64Arch::get_syscall_user_rsp();

    // vfork() = clone(CLONE_VM | CLONE_VFORK, parent_stack)
    // Child shares address space and parent blocks until child exec()s or _exit()s
    let config = CloneConfig {
        flags: CLONE_VM | CLONE_VFORK,
        child_stack: parent_rsp, // Use parent's stack (required for CLONE_VM)
        parent_rip,
        parent_rflags,
        parent_rsp,
        parent_tidptr: 0,
        child_tidptr: 0,
        tls: 0,
    };

    // Get frame allocator
    let mut frame_alloc = FrameAllocRef(&FRAME_ALLOCATOR);

    match super::percpu::do_clone(config, &mut frame_alloc) {
        Ok(child_pid) => child_pid as i64,
        Err(errno) => -(errno as i64),
    }
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
pub fn sys_wait4(pid: i64, wstatus: u64, options: i32, _rusage: u64) -> i64 {
    use super::wait_options::WNOHANG;

    let current_pid = super::percpu::current_pid();

    // Loop until we find a zombie child or determine there are no children
    loop {
        // Try to reap a zombie child
        if let Some((child_pid, exit_status)) = super::percpu::reap_zombie_child(current_pid, pid) {
            // Write status to user space if pointer is non-null
            if wstatus != 0 {
                // Linux encodes exit status as (exit_code << 8)
                let status_word = exit_status << 8;
                unsafe {
                    let ptr = wstatus as *mut i32;
                    *ptr = status_word;
                }
            }
            return child_pid as i64;
        }

        // No zombie child found - check if we have any children at all
        if !super::percpu::has_children(current_pid, pid) {
            return ECHILD;
        }

        // If WNOHANG, return 0 (no child ready)
        if options & WNOHANG != 0 {
            return 0;
        }

        // Children exist but none are zombies yet - yield and retry
        // This is a simple busy-wait implementation; a proper implementation
        // would put the parent to sleep and wake it when a child exits.
        super::percpu::yield_now();
    }
}

/// Simplified siginfo_t structure for waitid
///
/// Linux siginfo_t is much larger and more complex, but for waitid we only
/// need a subset of fields. This matches the layout at the start of siginfo_t.
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SigInfo {
    /// Signal number (SIGCHLD for waitid)
    pub si_signo: i32,
    /// Error number (usually 0)
    pub si_errno: i32,
    /// Signal code (CLD_EXITED, CLD_KILLED, etc.)
    pub si_code: i32,
    /// Padding to align union
    pub _pad0: i32,
    /// Process ID of child
    pub si_pid: i32,
    /// User ID of child
    pub si_uid: u32,
    /// Exit status or signal number
    pub si_status: i32,
}

// Signal codes for SIGCHLD
const CLD_EXITED: i32 = 1; // Child has exited
#[allow(dead_code)]
const CLD_KILLED: i32 = 2; // Child was killed
#[allow(dead_code)]
const CLD_DUMPED: i32 = 3; // Child terminated abnormally
#[allow(dead_code)]
const CLD_TRAPPED: i32 = 4; // Traced child has trapped
#[allow(dead_code)]
const CLD_STOPPED: i32 = 5; // Child has stopped
#[allow(dead_code)]
const CLD_CONTINUED: i32 = 6; // Stopped child has continued

// Error code
const EFAULT: i64 = -14;

// Signal number for SIGCHLD
const SIGCHLD: i32 = 17;

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
///
/// # Returns
/// * 0: Success (or WNOHANG with no child ready)
/// * -ECHILD: No matching children
/// * -EINVAL: Invalid arguments
pub fn sys_waitid(idtype: i32, id: u64, infop: u64, options: i32) -> i64 {
    use super::wait_options::{P_ALL, P_PGID, P_PID, WEXITED, WNOHANG};
    use crate::arch::Uaccess;
    use crate::uaccess::{UaccessArch, put_user};

    let current_pid = super::percpu::current_pid();

    // Validate infop pointer if non-null
    if infop != 0 && !Uaccess::access_ok(infop, core::mem::size_of::<SigInfo>()) {
        return EFAULT;
    }

    // Validate idtype
    if idtype != P_ALL && idtype != P_PID && idtype != P_PGID {
        return EINVAL;
    }

    // Must specify at least one wait condition
    // For now we only support WEXITED (terminated children)
    if options & WEXITED == 0 {
        // We don't support WSTOPPED or WCONTINUED yet
        return EINVAL;
    }

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
        _ => return EINVAL,
    };

    // Loop until we find a zombie child or determine there are no children
    loop {
        // Try to reap a zombie child (or peek if WNOWAIT)
        // Note: WNOWAIT leaves child in waitable state - we don't fully support this yet
        if let Some((child_pid, exit_status)) =
            super::percpu::reap_zombie_child(current_pid, wait_pid)
        {
            // Fill siginfo_t structure if pointer is non-null
            if infop != 0 {
                let info = SigInfo {
                    si_signo: SIGCHLD,
                    si_errno: 0,
                    si_code: CLD_EXITED,
                    _pad0: 0,
                    si_pid: child_pid as i32,
                    si_uid: 0,
                    si_status: exit_status,
                };
                if put_user::<Uaccess, SigInfo>(infop, info).is_err() {
                    return EFAULT;
                }
            }
            return 0; // Success
        }

        // No zombie child found - check if we have any children at all
        if !super::percpu::has_children(current_pid, wait_pid) {
            return ECHILD;
        }

        // If WNOHANG, return 0 but leave infop->si_pid as 0 to indicate no child
        if options & WNOHANG != 0 {
            if infop != 0 {
                // Zero out siginfo to indicate no child was available
                let info = SigInfo {
                    si_signo: 0,
                    si_errno: 0,
                    si_code: 0,
                    _pad0: 0,
                    si_pid: 0,
                    si_uid: 0,
                    si_status: 0,
                };
                if put_user::<Uaccess, SigInfo>(infop, info).is_err() {
                    return EFAULT;
                }
            }
            return 0;
        }

        // Children exist but none are zombies yet - yield and retry
        super::percpu::yield_now();
    }
}

/// sys_getcpu - get CPU and NUMA node for calling thread
///
/// Returns the CPU number and NUMA node that the calling thread is running on.
///
/// # Arguments
/// * `cpu` - Current CPU number (from per-CPU data)
/// * `cpup` - Optional user pointer to store CPU number (can be 0/NULL)
/// * `nodep` - Optional user pointer to store NUMA node (can be 0/NULL)
///
/// Returns 0 on success, -EFAULT if copy to user space fails.
///
/// # Locking
/// None required - reads per-CPU data which is stable during syscall execution.
/// This matches Linux's implementation which uses raw_smp_processor_id().
pub fn sys_getcpu<A: crate::uaccess::UaccessArch>(cpu: u32, cpup: u64, nodep: u64) -> i64 {
    use crate::uaccess::put_user;

    // Write CPU number if pointer provided
    if cpup != 0 {
        if !A::access_ok(cpup, core::mem::size_of::<u32>()) {
            return EFAULT;
        }
        if put_user::<A, u32>(cpup, cpu).is_err() {
            return EFAULT;
        }
    }

    // Write NUMA node if pointer provided (always 0 - no NUMA support)
    if nodep != 0 {
        if !A::access_ok(nodep, core::mem::size_of::<u32>()) {
            return EFAULT;
        }
        if put_user::<A, u32>(nodep, 0).is_err() {
            return EFAULT;
        }
    }

    0
}

// Error code for permission denied (priority raise without permission)
const EACCES: i64 = -13;

/// sys_getpriority - get program scheduling priority
///
/// # Arguments
/// * `which` - PRIO_PROCESS, PRIO_PGRP, or PRIO_USER
/// * `who` - PID, PGID, or UID depending on `which` (0 = calling process)
/// * `caller_pid` - PID of calling process
///
/// # Returns
/// * 20 - nice (range 1-40) on success, to avoid negative return values
/// * Negative errno on error (-ESRCH, -EINVAL)
///
/// # Locking
/// Acquires TASK_TABLE lock briefly to read priority.
pub fn sys_getpriority(which: i32, who: u64, caller_pid: Pid) -> i64 {
    use super::{PRIO_PGRP, PRIO_PROCESS, PRIO_USER, priority_to_nice};

    match which {
        PRIO_PROCESS => {
            let target_pid = if who == 0 { caller_pid } else { who };
            match super::percpu::lookup_task_priority(target_pid) {
                Some(priority) => {
                    let nice = priority_to_nice(priority);
                    // Return 20 - nice (range 1-40) to avoid negative return values
                    (20 - nice) as i64
                }
                None => ESRCH,
            }
        }
        PRIO_PGRP | PRIO_USER => {
            // Not implemented yet - would require task iteration
            ESRCH // Return ESRCH for now (no matching processes)
        }
        _ => EINVAL,
    }
}

/// sys_setpriority - set program scheduling priority
///
/// # Arguments
/// * `which` - PRIO_PROCESS, PRIO_PGRP, or PRIO_USER
/// * `who` - PID, PGID, or UID depending on `which` (0 = calling process)
/// * `niceval` - New nice value (-20 to 19)
/// * `caller_pid` - PID of calling process
/// * `caller_euid` - Effective UID of calling process
///
/// # Returns
/// * 0 on success
/// * Negative errno on error (-ESRCH, -EINVAL, -EACCES, -EPERM)
///
/// # Locking
/// Acquires TASK_TABLE lock briefly to modify priority.
///
/// # Permission Model
/// - Root (euid=0): Can set any priority for any process
/// - Non-root: Can only lower priority (increase nice value), not raise it
pub fn sys_setpriority(
    which: i32,
    who: u64,
    niceval: i32,
    caller_pid: Pid,
    caller_euid: super::Uid,
) -> i64 {
    use super::{
        PRIO_MAX, PRIO_MIN, PRIO_PGRP, PRIO_PROCESS, PRIO_USER, nice_to_priority, priority_to_nice,
    };

    // Clamp nice value to valid range (Linux does this)
    let niceval = niceval.clamp(PRIO_MIN, PRIO_MAX);

    match which {
        PRIO_PROCESS => {
            let target_pid = if who == 0 { caller_pid } else { who };

            // Get current priority to check permissions
            let current_nice = match super::percpu::lookup_task_priority(target_pid) {
                Some(priority) => priority_to_nice(priority),
                None => return ESRCH,
            };

            // Permission check: non-root cannot raise priority (lower nice value)
            if caller_euid != 0 && niceval < current_nice {
                return EACCES;
            }

            // Set the new priority
            let new_priority = nice_to_priority(niceval);
            match super::percpu::set_task_priority(target_pid, new_priority) {
                Ok(()) => 0,
                Err(errno) => -(errno as i64),
            }
        }
        PRIO_PGRP | PRIO_USER => {
            // Not implemented yet
            ESRCH
        }
        _ => EINVAL,
    }
}

/// sys_getresuid - get real, effective, and saved user IDs
///
/// Returns the real UID, effective UID, and saved set-user-ID of the calling process.
/// All three pointers must be valid.
///
/// # Arguments
/// * `ruid_ptr` - User pointer to store real UID
/// * `euid_ptr` - User pointer to store effective UID
/// * `suid_ptr` - User pointer to store saved UID
/// * `current_cred` - Current credentials (passed from dispatcher)
///
/// # Returns
/// * 0 on success
/// * -EFAULT if any pointer is invalid
///
/// # Locking
/// None required - credentials are stable during syscall execution.
/// Linux uses RCU for credential access; we use per-CPU cached credentials.
pub fn sys_getresuid<A: crate::uaccess::UaccessArch>(
    ruid_ptr: u64,
    euid_ptr: u64,
    suid_ptr: u64,
    current_cred: super::Cred,
) -> i64 {
    use crate::uaccess::put_user;

    // Validate all pointers
    if !A::access_ok(ruid_ptr, core::mem::size_of::<u32>()) {
        return EFAULT;
    }
    if !A::access_ok(euid_ptr, core::mem::size_of::<u32>()) {
        return EFAULT;
    }
    if !A::access_ok(suid_ptr, core::mem::size_of::<u32>()) {
        return EFAULT;
    }

    // Write the three UIDs to user space
    if put_user::<A, u32>(ruid_ptr, current_cred.uid).is_err() {
        return EFAULT;
    }
    if put_user::<A, u32>(euid_ptr, current_cred.euid).is_err() {
        return EFAULT;
    }
    if put_user::<A, u32>(suid_ptr, current_cred.suid).is_err() {
        return EFAULT;
    }

    0
}

/// sys_getresgid - get real, effective, and saved group IDs
///
/// Returns the real GID, effective GID, and saved set-group-ID of the calling process.
/// All three pointers must be valid.
///
/// # Arguments
/// * `rgid_ptr` - User pointer to store real GID
/// * `egid_ptr` - User pointer to store effective GID
/// * `sgid_ptr` - User pointer to store saved GID
/// * `current_cred` - Current credentials (passed from dispatcher)
///
/// # Returns
/// * 0 on success
/// * -EFAULT if any pointer is invalid
///
/// # Locking
/// None required - credentials are stable during syscall execution.
pub fn sys_getresgid<A: crate::uaccess::UaccessArch>(
    rgid_ptr: u64,
    egid_ptr: u64,
    sgid_ptr: u64,
    current_cred: super::Cred,
) -> i64 {
    use crate::uaccess::put_user;

    // Validate all pointers
    if !A::access_ok(rgid_ptr, core::mem::size_of::<u32>()) {
        return EFAULT;
    }
    if !A::access_ok(egid_ptr, core::mem::size_of::<u32>()) {
        return EFAULT;
    }
    if !A::access_ok(sgid_ptr, core::mem::size_of::<u32>()) {
        return EFAULT;
    }

    // Write the three GIDs to user space
    if put_user::<A, u32>(rgid_ptr, current_cred.gid).is_err() {
        return EFAULT;
    }
    if put_user::<A, u32>(egid_ptr, current_cred.egid).is_err() {
        return EFAULT;
    }
    if put_user::<A, u32>(sgid_ptr, current_cred.sgid).is_err() {
        return EFAULT;
    }

    0
}

/// sys_setresuid - set real, effective, and saved user IDs
///
/// Sets the real UID, effective UID, and saved UID of the calling process.
/// A value of -1 (0xFFFFFFFF) means "don't change this field".
///
/// # Arguments
/// * `ruid` - New real UID (-1 to leave unchanged)
/// * `euid` - New effective UID (-1 to leave unchanged)
/// * `suid` - New saved UID (-1 to leave unchanged)
/// * `current_cred` - Current credentials (passed from dispatcher)
///
/// # Returns
/// * 0 on success
/// * -EPERM if not permitted
///
/// # Permission Model (Linux-compatible)
/// - If unprivileged: can only set each field to one of {current uid, euid, suid}
/// - If privileged (euid=0 or CAP_SETUID): can set any field to any value
/// - When euid changes, fsuid follows (set to new euid)
///
/// # Locking
/// Per-CPU credential update is atomic. Linux uses prepare_creds/commit_creds
/// for RCU-based credential replacement; we update per-CPU data directly.
pub fn sys_setresuid(ruid: u32, euid: u32, suid: u32, current_cred: super::Cred) -> i64 {
    const NO_CHANGE: u32 = 0xFFFFFFFF; // -1 as unsigned

    // Check permissions for each field that will be changed
    // Unprivileged: can only set to current uid, euid, or suid
    // Privileged (euid=0): can set to any value
    let is_privileged = current_cred.euid == 0;

    // Helper to check if a value is in the current credential set
    let is_permitted = |val: u32| -> bool {
        val == current_cred.uid || val == current_cred.euid || val == current_cred.suid
    };

    // Check each field
    if ruid != NO_CHANGE && !is_privileged && !is_permitted(ruid) {
        return EPERM;
    }
    if euid != NO_CHANGE && !is_privileged && !is_permitted(euid) {
        return EPERM;
    }
    if suid != NO_CHANGE && !is_privileged && !is_permitted(suid) {
        return EPERM;
    }

    // Convert -1 to None (don't change)
    let ruid_opt = if ruid == NO_CHANGE { None } else { Some(ruid) };
    let euid_opt = if euid == NO_CHANGE { None } else { Some(euid) };
    let suid_opt = if suid == NO_CHANGE { None } else { Some(suid) };

    // Apply the changes
    super::percpu::set_current_resuid(ruid_opt, euid_opt, suid_opt);

    0
}

/// sys_setresgid - set real, effective, and saved group IDs
///
/// Sets the real GID, effective GID, and saved GID of the calling process.
/// A value of -1 (0xFFFFFFFF) means "don't change this field".
///
/// # Arguments
/// * `rgid` - New real GID (-1 to leave unchanged)
/// * `egid` - New effective GID (-1 to leave unchanged)
/// * `sgid` - New saved GID (-1 to leave unchanged)
/// * `current_cred` - Current credentials (passed from dispatcher)
///
/// # Returns
/// * 0 on success
/// * -EPERM if not permitted
///
/// # Permission Model (Linux-compatible)
/// - If unprivileged: can only set each field to one of {current gid, egid, sgid}
/// - If privileged (euid=0 or CAP_SETGID): can set any field to any value
/// - When egid changes, fsgid follows (set to new egid)
/// - Note: Linux checks euid (not egid) for privilege
///
/// # Locking
/// Per-CPU credential update is atomic.
pub fn sys_setresgid(rgid: u32, egid: u32, sgid: u32, current_cred: super::Cred) -> i64 {
    const NO_CHANGE: u32 = 0xFFFFFFFF; // -1 as unsigned

    // Check permissions - note: Linux checks euid, not egid, for setgid privilege
    let is_privileged = current_cred.euid == 0;

    // Helper to check if a value is in the current credential set
    let is_permitted = |val: u32| -> bool {
        val == current_cred.gid || val == current_cred.egid || val == current_cred.sgid
    };

    // Check each field
    if rgid != NO_CHANGE && !is_privileged && !is_permitted(rgid) {
        return EPERM;
    }
    if egid != NO_CHANGE && !is_privileged && !is_permitted(egid) {
        return EPERM;
    }
    if sgid != NO_CHANGE && !is_privileged && !is_permitted(sgid) {
        return EPERM;
    }

    // Convert -1 to None (don't change)
    let rgid_opt = if rgid == NO_CHANGE { None } else { Some(rgid) };
    let egid_opt = if egid == NO_CHANGE { None } else { Some(egid) };
    let sgid_opt = if sgid == NO_CHANGE { None } else { Some(sgid) };

    // Apply the changes
    super::percpu::set_current_resgid(rgid_opt, egid_opt, sgid_opt);

    0
}

/// sys_setreuid - set real and effective user IDs
///
/// Sets the real UID and effective UID of the calling process.
/// A value of -1 (0xFFFFFFFF) means "don't change this field".
///
/// # Arguments
/// * `ruid` - New real UID (-1 to leave unchanged)
/// * `euid` - New effective UID (-1 to leave unchanged)
/// * `current_cred` - Current credentials (passed from dispatcher)
///
/// # Returns
/// * 0 on success
/// * -EPERM if not permitted
///
/// # Permission Model (Linux-compatible)
/// - ruid: can set to current {uid, euid} OR requires CAP_SETUID
/// - euid: can set to current {uid, euid, suid} OR requires CAP_SETUID
/// - suid is updated to new euid if: (ruid != -1) OR (euid != -1 AND new_euid != old_uid)
/// - fsuid always follows euid
///
/// # Locking
/// Per-CPU credential update is atomic.
pub fn sys_setreuid(ruid: u32, euid: u32, current_cred: super::Cred) -> i64 {
    const NO_CHANGE: u32 = 0xFFFFFFFF; // -1 as unsigned

    let is_privileged = current_cred.euid == 0;

    // Permission check for ruid: must be in {uid, euid} or privileged
    if ruid != NO_CHANGE && !is_privileged && ruid != current_cred.uid && ruid != current_cred.euid
    {
        return EPERM;
    }

    // Permission check for euid: must be in {uid, euid, suid} or privileged
    if euid != NO_CHANGE
        && !is_privileged
        && euid != current_cred.uid
        && euid != current_cred.euid
        && euid != current_cred.suid
    {
        return EPERM;
    }

    // Determine what to set
    let ruid_opt = if ruid == NO_CHANGE { None } else { Some(ruid) };
    let euid_opt = if euid == NO_CHANGE { None } else { Some(euid) };

    // Determine if suid should be updated (Linux semantics):
    // suid = new_euid if: (ruid != -1) OR (euid != -1 AND new_euid != old_uid)
    let new_suid = if ruid != NO_CHANGE {
        // ruid is changing, so suid = new euid (or current euid if euid not changing)
        Some(euid_opt.unwrap_or(current_cred.euid))
    } else if euid != NO_CHANGE && euid != current_cred.uid {
        // euid is changing to something other than current uid
        Some(euid)
    } else {
        None
    };

    // Apply the changes (fsuid follows euid in set_current_reuid)
    super::percpu::set_current_reuid(ruid_opt, euid_opt, new_suid);

    0
}

/// sys_setregid - set real and effective group IDs
///
/// Sets the real GID and effective GID of the calling process.
/// A value of -1 (0xFFFFFFFF) means "don't change this field".
///
/// # Arguments
/// * `rgid` - New real GID (-1 to leave unchanged)
/// * `egid` - New effective GID (-1 to leave unchanged)
/// * `current_cred` - Current credentials (passed from dispatcher)
///
/// # Returns
/// * 0 on success
/// * -EPERM if not permitted
///
/// # Permission Model (Linux-compatible)
/// - rgid: can set to current {gid, egid} OR requires CAP_SETGID
/// - egid: can set to current {gid, egid, sgid} OR requires CAP_SETGID
/// - sgid is updated to new egid if: (rgid != -1) OR (egid != -1 AND new_egid != old_gid)
/// - fsgid always follows egid
/// - Note: Linux checks euid (not egid) for privilege
///
/// # Locking
/// Per-CPU credential update is atomic.
pub fn sys_setregid(rgid: u32, egid: u32, current_cred: super::Cred) -> i64 {
    const NO_CHANGE: u32 = 0xFFFFFFFF; // -1 as unsigned

    // Note: Linux checks euid, not egid, for setgid privilege
    let is_privileged = current_cred.euid == 0;

    // Permission check for rgid: must be in {gid, egid} or privileged
    if rgid != NO_CHANGE && !is_privileged && rgid != current_cred.gid && rgid != current_cred.egid
    {
        return EPERM;
    }

    // Permission check for egid: must be in {gid, egid, sgid} or privileged
    if egid != NO_CHANGE
        && !is_privileged
        && egid != current_cred.gid
        && egid != current_cred.egid
        && egid != current_cred.sgid
    {
        return EPERM;
    }

    // Determine what to set
    let rgid_opt = if rgid == NO_CHANGE { None } else { Some(rgid) };
    let egid_opt = if egid == NO_CHANGE { None } else { Some(egid) };

    // Determine if sgid should be updated (Linux semantics):
    // sgid = new_egid if: (rgid != -1) OR (egid != -1 AND new_egid != old_gid)
    let new_sgid = if rgid != NO_CHANGE {
        // rgid is changing, so sgid = new egid (or current egid if egid not changing)
        Some(egid_opt.unwrap_or(current_cred.egid))
    } else if egid != NO_CHANGE && egid != current_cred.gid {
        // egid is changing to something other than current gid
        Some(egid)
    } else {
        None
    };

    // Apply the changes (fsgid follows egid in set_current_regid)
    super::percpu::set_current_regid(rgid_opt, egid_opt, new_sgid);

    0
}

/// sys_setfsuid - set filesystem UID
///
/// Sets the filesystem UID of the calling process.
/// Unlike most syscalls, this one returns the OLD fsuid value, not an error code.
///
/// # Arguments
/// * `uid` - New filesystem UID
/// * `current_cred` - Current credentials (passed from dispatcher)
///
/// # Returns
/// * Old fsuid value (always succeeds in returning this)
/// * If permission denied or invalid, returns old fsuid without changing
///
/// # Permission Model (Linux-compatible)
/// - Can set fsuid to current {uid, euid, suid, fsuid} OR requires CAP_SETUID
/// - Invalid UID (-1 treated as invalid) returns old fsuid without change
///
/// # Note
/// This syscall does NOT auto-update when euid changes elsewhere.
/// fsuid must be explicitly set via this syscall.
pub fn sys_setfsuid(uid: u32, current_cred: super::Cred) -> i64 {
    let old_fsuid = current_cred.fsuid;

    // Check if uid is valid (treat -1 as "query only")
    if uid == 0xFFFFFFFF {
        return old_fsuid as i64;
    }

    // Permission check: must be in {uid, euid, suid, fsuid} or privileged
    let is_privileged = current_cred.euid == 0;

    let is_permitted = uid == current_cred.uid
        || uid == current_cred.euid
        || uid == current_cred.suid
        || uid == current_cred.fsuid;

    if !is_privileged && !is_permitted {
        // Permission denied - return old fsuid without changing
        return old_fsuid as i64;
    }

    // Apply the change
    super::percpu::set_current_fsuid(uid);

    old_fsuid as i64
}

/// sys_setfsgid - set filesystem GID
///
/// Sets the filesystem GID of the calling process.
/// Unlike most syscalls, this one returns the OLD fsgid value, not an error code.
///
/// # Arguments
/// * `gid` - New filesystem GID
/// * `current_cred` - Current credentials (passed from dispatcher)
///
/// # Returns
/// * Old fsgid value (always succeeds in returning this)
/// * If permission denied or invalid, returns old fsgid without changing
///
/// # Permission Model (Linux-compatible)
/// - Can set fsgid to current {gid, egid, sgid, fsgid} OR requires CAP_SETGID
/// - Invalid GID (-1 treated as invalid) returns old fsgid without change
/// - Note: Linux checks euid (not egid) for privilege
///
/// # Note
/// This syscall does NOT auto-update when egid changes elsewhere.
/// fsgid must be explicitly set via this syscall.
pub fn sys_setfsgid(gid: u32, current_cred: super::Cred) -> i64 {
    let old_fsgid = current_cred.fsgid;

    // Check if gid is valid (treat -1 as "query only")
    if gid == 0xFFFFFFFF {
        return old_fsgid as i64;
    }

    // Permission check: must be in {gid, egid, sgid, fsgid} or privileged
    // Note: Linux checks euid, not egid, for setgid privilege
    let is_privileged = current_cred.euid == 0;

    let is_permitted = gid == current_cred.gid
        || gid == current_cred.egid
        || gid == current_cred.sgid
        || gid == current_cred.fsgid;

    if !is_privileged && !is_permitted {
        // Permission denied - return old fsgid without changing
        return old_fsgid as i64;
    }

    // Apply the change
    super::percpu::set_current_fsgid(gid);

    old_fsgid as i64
}

// =============================================================================
// sysinfo and getrusage syscalls
// =============================================================================

/// Linux sysinfo structure (matches Linux kernel struct sysinfo layout)
///
/// Used by the sysinfo(2) syscall to return system-wide statistics.
/// The compiler automatically adds padding for alignment with #[repr(C)].
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SysInfo {
    /// Seconds since boot
    pub uptime: i64,
    /// 1, 5, and 15 minute load averages (fixed-point)
    pub loads: [u64; 3],
    /// Total usable main memory size
    pub totalram: u64,
    /// Available memory size
    pub freeram: u64,
    /// Amount of shared memory (0 for us)
    pub sharedram: u64,
    /// Memory used by buffers (0 for us)
    pub bufferram: u64,
    /// Total swap space size (0 for us)
    pub totalswap: u64,
    /// Swap space still available (0 for us)
    pub freeswap: u64,
    /// Number of current processes
    pub procs: u16,
    /// Padding for alignment
    pub pad: u16,
    // Compiler adds 4 bytes of implicit padding here for u64 alignment
    /// Total high memory size (0 for 64-bit)
    pub totalhigh: u64,
    /// Available high memory size (0 for 64-bit)
    pub freehigh: u64,
    /// Memory unit size in bytes (1 = bytes)
    pub mem_unit: u32,
    // Compiler adds 4 bytes of implicit padding here for struct alignment
}

// Compile-time assertion that SysInfo is 112 bytes (matches Linux and userspace)
const _: () = assert!(core::mem::size_of::<SysInfo>() == 112);

impl Default for SysInfo {
    fn default() -> Self {
        Self {
            uptime: 0,
            loads: [0; 3],
            totalram: 0,
            freeram: 0,
            sharedram: 0,
            bufferram: 0,
            totalswap: 0,
            freeswap: 0,
            procs: 0,
            pad: 0,
            totalhigh: 0,
            freehigh: 0,
            mem_unit: 1,
        }
    }
}

/// Timeval structure for rusage (matches Linux)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Timeval {
    /// Seconds
    pub tv_sec: i64,
    /// Microseconds
    pub tv_usec: i64,
}

/// Linux rusage structure (144 bytes)
///
/// This matches the Linux kernel's struct rusage layout exactly.
/// Used by getrusage(2) to return resource usage statistics.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Rusage {
    /// User CPU time used
    pub ru_utime: Timeval,
    /// System CPU time used
    pub ru_stime: Timeval,
    /// Maximum resident set size (in kilobytes)
    pub ru_maxrss: i64,
    /// Integral shared memory size (unused)
    pub ru_ixrss: i64,
    /// Integral unshared data size (unused)
    pub ru_idrss: i64,
    /// Integral unshared stack size (unused)
    pub ru_isrss: i64,
    /// Page reclaims (soft page faults)
    pub ru_minflt: i64,
    /// Page faults (hard page faults)
    pub ru_majflt: i64,
    /// Swaps (unused)
    pub ru_nswap: i64,
    /// Block input operations (unused for now)
    pub ru_inblock: i64,
    /// Block output operations (unused for now)
    pub ru_oublock: i64,
    /// IPC messages sent (unused)
    pub ru_msgsnd: i64,
    /// IPC messages received (unused)
    pub ru_msgrcv: i64,
    /// Signals received (unused)
    pub ru_nsignals: i64,
    /// Voluntary context switches
    pub ru_nvcsw: i64,
    /// Involuntary context switches
    pub ru_nivcsw: i64,
}

// Compile-time assertion that Rusage is 144 bytes (matches Linux)
const _: () = assert!(core::mem::size_of::<Rusage>() == 144);

/// RUSAGE_SELF - get resource usage of calling process
pub const RUSAGE_SELF: i32 = 0;
/// RUSAGE_CHILDREN - get resource usage of terminated children
pub const RUSAGE_CHILDREN: i32 = -1;
/// RUSAGE_THREAD - get resource usage of calling thread
pub const RUSAGE_THREAD: i32 = 1;

/// sys_sysinfo - return system information
///
/// Returns system-wide statistics in a SysInfo structure.
///
/// # Arguments
/// * `info_ptr` - User pointer to struct sysinfo
///
/// # Returns
/// * 0 on success
/// * -EFAULT if copy to user fails
///
/// # Locking
/// Reads memory stats and process count with brief lock holds.
/// Reads time without locking (seqlock-protected).
pub fn sys_sysinfo<A: crate::uaccess::UaccessArch>(info_ptr: u64) -> i64 {
    use crate::FRAME_ALLOCATOR;
    use crate::time::{ClockId, TIMEKEEPER};
    use crate::uaccess::put_user;

    // Validate user pointer
    if !A::access_ok(info_ptr, core::mem::size_of::<SysInfo>()) {
        return EFAULT;
    }

    // Get uptime (monotonic time since boot, in seconds)
    let mono = TIMEKEEPER.read(ClockId::Monotonic, TIMEKEEPER.get_read_cycles());
    let uptime_secs = mono.sec;

    // Get memory statistics from frame allocator
    let mem_stats = FRAME_ALLOCATOR.stats();

    // Get process count from scheduler
    let procs = super::percpu::task_count() as u16;

    // Build the sysinfo structure
    let info = SysInfo {
        uptime: uptime_secs,
        loads: [0; 3], // Load averages not implemented yet
        totalram: mem_stats.total_bytes,
        freeram: mem_stats.free_bytes,
        sharedram: 0,
        bufferram: 0,
        totalswap: 0,
        freeswap: 0,
        procs,
        pad: 0,
        totalhigh: 0,
        freehigh: 0,
        mem_unit: 1, // All sizes in bytes
    };

    // Copy to user space
    if put_user::<A, SysInfo>(info_ptr, info).is_err() {
        return EFAULT;
    }

    0
}

/// sys_getrusage - get resource usage
///
/// Returns resource usage statistics for the specified target.
///
/// # Arguments
/// * `who` - RUSAGE_SELF, RUSAGE_CHILDREN, or RUSAGE_THREAD
/// * `usage_ptr` - User pointer to struct rusage
///
/// # Returns
/// * 0 on success
/// * -EINVAL for invalid `who` value
/// * -EFAULT if copy to user fails
///
/// # Locking
/// None required for current minimal implementation.
/// When per-task stats are added, will need to read task struct with lock.
///
/// # Implementation Notes
/// Currently returns minimal/zero values for most fields since we don't
/// track detailed per-task resource usage yet. This is Linux-compatible
/// behavior for a minimal implementation.
pub fn sys_getrusage<A: crate::uaccess::UaccessArch>(who: i32, usage_ptr: u64) -> i64 {
    use crate::uaccess::put_user;

    // Validate who parameter
    if who != RUSAGE_SELF && who != RUSAGE_CHILDREN && who != RUSAGE_THREAD {
        return EINVAL;
    }

    // Validate user pointer
    if !A::access_ok(usage_ptr, core::mem::size_of::<Rusage>()) {
        return EFAULT;
    }

    // Build rusage structure
    // For now, we return zeros for most fields since we don't track
    // detailed per-task resource usage. This matches Linux behavior
    // for fields that aren't implemented.
    let usage = match who {
        RUSAGE_SELF | RUSAGE_THREAD => {
            // For RUSAGE_SELF and RUSAGE_THREAD, return current task stats
            // Currently we don't track these per-task, so return zeros
            Rusage::default()
        }
        RUSAGE_CHILDREN => {
            // For RUSAGE_CHILDREN, return stats of terminated and waited-for children
            // We don't track child resource usage yet, so return zeros
            Rusage::default()
        }
        _ => return EINVAL,
    };

    // Copy to user space
    if put_user::<A, Rusage>(usage_ptr, usage).is_err() {
        return EFAULT;
    }

    0
}

/// sys_getrandom - get random bytes
///
/// Fills a buffer with random bytes from the kernel CRNG.
///
/// # Arguments
/// * `buf` - User pointer to buffer to fill
/// * `buflen` - Number of bytes to generate
/// * `flags` - GRND_NONBLOCK, GRND_RANDOM, GRND_INSECURE
///
/// # Returns
/// Number of bytes written on success, negative errno on error.
///
/// # Errors
/// * EFAULT - Invalid buffer pointer
/// * EINVAL - Invalid flags
pub fn sys_getrandom<A: crate::uaccess::UaccessArch>(buf: u64, buflen: usize, flags: u32) -> i64 {
    use crate::random;
    use crate::uaccess::copy_to_user;

    // Limit buffer size per call to prevent stack overflow
    const MAX_GETRANDOM: usize = 256;

    if buflen == 0 {
        return 0;
    }

    // Validate flags first
    const VALID_FLAGS: u32 = random::GRND_NONBLOCK | random::GRND_RANDOM | random::GRND_INSECURE;
    if flags & !VALID_FLAGS != 0 {
        return EINVAL;
    }

    // Limit single read to stack buffer size
    let len = buflen.min(MAX_GETRANDOM);

    // Validate user buffer
    if !A::access_ok(buf, len) {
        return EFAULT;
    }

    // Generate random bytes
    let mut tmp = [0u8; MAX_GETRANDOM];
    match random::get_random_bytes(&mut tmp[..len], flags) {
        Ok(n) => {
            // Copy to user space
            if copy_to_user::<A>(buf, &tmp[..n]).is_err() {
                return EFAULT;
            }
            n as i64
        }
        Err(e) => e as i64,
    }
}

// =============================================================================
// Scheduling syscalls (sched_* family)
// =============================================================================

/// sys_sched_getscheduler - get scheduling policy
///
/// Returns the scheduling policy of the process specified by pid.
/// If pid is 0, returns the policy of the calling process.
///
/// # Arguments
/// * `pid` - Process ID (0 = calling process)
/// * `caller_pid` - PID of calling process
///
/// # Returns
/// * Scheduling policy (SCHED_NORMAL, SCHED_FIFO, SCHED_RR, etc.) on success
/// * Negative errno on error
///
/// # Locking
/// Acquires TASK_TABLE lock briefly to read policy.
pub fn sys_sched_getscheduler(pid: i64, caller_pid: Pid) -> i64 {
    // pid < 0 is invalid
    if pid < 0 {
        return EINVAL;
    }

    let target_pid = if pid == 0 { caller_pid } else { pid as u64 };

    match super::percpu::lookup_task_policy(target_pid) {
        Some(policy) => policy as i64,
        None => ESRCH,
    }
}

/// sys_sched_setscheduler - set scheduling policy and parameters
///
/// Sets the scheduling policy and parameters for the process specified by pid.
/// If pid is 0, sets for the calling process.
///
/// # Arguments
/// * `pid` - Process ID (0 = calling process)
/// * `policy` - Scheduling policy (SCHED_NORMAL, SCHED_FIFO, etc.)
/// * `param_ptr` - Pointer to sched_param struct
/// * `caller_pid` - PID of calling process
/// * `caller_euid` - Effective UID of calling process
///
/// # Returns
/// * 0 on success
/// * Negative errno on error
///
/// # Permission Model
/// - Root (euid=0): Can set any policy
/// - Non-root: Can only set SCHED_NORMAL/BATCH/IDLE (not RT policies)
///
/// # Locking
/// Acquires TASK_TABLE lock to modify policy.
pub fn sys_sched_setscheduler<A: crate::uaccess::UaccessArch>(
    pid: i64,
    policy: i32,
    param_ptr: u64,
    caller_pid: Pid,
    caller_euid: super::Uid,
) -> i64 {
    use super::SchedParam;
    use crate::uaccess::get_user;

    // pid < 0 is invalid
    if pid < 0 {
        return EINVAL;
    }

    // Validate param_ptr
    if param_ptr == 0 {
        return EINVAL;
    }
    if !A::access_ok(param_ptr, core::mem::size_of::<SchedParam>()) {
        return EFAULT;
    }

    // Read sched_param from user space
    let param: SchedParam = match get_user::<A, SchedParam>(param_ptr) {
        Ok(p) => p,
        Err(_) => return EFAULT,
    };

    // Validate policy
    if !super::is_valid_policy(policy) {
        return EINVAL;
    }

    // Permission check: non-root cannot set RT policies
    let base_policy = policy & !super::SCHED_RESET_ON_FORK;
    if super::is_rt_policy(base_policy) && caller_euid != 0 {
        return EPERM;
    }

    let target_pid = if pid == 0 { caller_pid } else { pid as u64 };

    // Set the scheduler
    match super::percpu::set_task_scheduler(target_pid, policy, param.sched_priority) {
        Ok(()) => 0,
        Err(errno) => -(errno as i64),
    }
}

/// sys_sched_getparam - get scheduling parameters
///
/// Returns the scheduling parameters of the process specified by pid.
/// If pid is 0, returns the parameters of the calling process.
///
/// # Arguments
/// * `pid` - Process ID (0 = calling process)
/// * `param_ptr` - Pointer to sched_param struct to fill
/// * `caller_pid` - PID of calling process
///
/// # Returns
/// * 0 on success
/// * Negative errno on error
///
/// # Locking
/// Acquires TASK_TABLE lock briefly to read parameters.
pub fn sys_sched_getparam<A: crate::uaccess::UaccessArch>(
    pid: i64,
    param_ptr: u64,
    caller_pid: Pid,
) -> i64 {
    use super::SchedParam;
    use crate::uaccess::put_user;

    // pid < 0 is invalid
    if pid < 0 {
        return EINVAL;
    }

    // Validate param_ptr
    if param_ptr == 0 {
        return EINVAL;
    }
    if !A::access_ok(param_ptr, core::mem::size_of::<SchedParam>()) {
        return EFAULT;
    }

    let target_pid = if pid == 0 { caller_pid } else { pid as u64 };

    // Get the RT priority (0 for non-RT tasks)
    let rt_prio = match super::percpu::lookup_task_rt_priority(target_pid) {
        Some(p) => p,
        None => return ESRCH,
    };

    let param = SchedParam {
        sched_priority: rt_prio,
    };

    // Copy to user space
    if put_user::<A, SchedParam>(param_ptr, param).is_err() {
        return EFAULT;
    }

    0
}

/// sys_sched_setparam - set scheduling parameters
///
/// Sets the scheduling parameters for the process specified by pid,
/// keeping the current scheduling policy.
/// If pid is 0, sets for the calling process.
///
/// # Arguments
/// * `pid` - Process ID (0 = calling process)
/// * `param_ptr` - Pointer to sched_param struct
/// * `caller_pid` - PID of calling process
/// * `caller_euid` - Effective UID of calling process
///
/// # Returns
/// * 0 on success
/// * Negative errno on error
///
/// # Permission Model
/// - Root (euid=0): Can set any parameters
/// - Non-root: Can only set parameters for non-RT policies
///
/// # Locking
/// Acquires TASK_TABLE lock to modify parameters.
pub fn sys_sched_setparam<A: crate::uaccess::UaccessArch>(
    pid: i64,
    param_ptr: u64,
    caller_pid: Pid,
    caller_euid: super::Uid,
) -> i64 {
    use super::SchedParam;
    use crate::uaccess::get_user;

    // pid < 0 is invalid
    if pid < 0 {
        return EINVAL;
    }

    // Validate param_ptr
    if param_ptr == 0 {
        return EINVAL;
    }
    if !A::access_ok(param_ptr, core::mem::size_of::<SchedParam>()) {
        return EFAULT;
    }

    // Read sched_param from user space
    let param: SchedParam = match get_user::<A, SchedParam>(param_ptr) {
        Ok(p) => p,
        Err(_) => return EFAULT,
    };

    let target_pid = if pid == 0 { caller_pid } else { pid as u64 };

    // Get current policy to preserve it
    let current_policy = match super::percpu::lookup_task_policy(target_pid) {
        Some(p) => p,
        None => return ESRCH,
    };

    // Permission check: non-root cannot set RT parameters
    let base_policy = current_policy & !super::SCHED_RESET_ON_FORK;
    if super::is_rt_policy(base_policy) && caller_euid != 0 {
        return EPERM;
    }

    // Set the scheduler with current policy
    match super::percpu::set_task_scheduler(target_pid, current_policy, param.sched_priority) {
        Ok(()) => 0,
        Err(errno) => -(errno as i64),
    }
}

/// sys_sched_getaffinity - get CPU affinity mask
///
/// Returns the CPU affinity mask of the process specified by pid.
/// If pid is 0, returns the mask of the calling process.
///
/// # Arguments
/// * `pid` - Process ID (0 = calling process)
/// * `cpusetsize` - Size of the user buffer in bytes
/// * `mask_ptr` - Pointer to user buffer for the CPU mask
/// * `caller_pid` - PID of calling process
///
/// # Returns
/// * Number of bytes written on success (minimum of cpusetsize and sizeof(cpu_set_t))
/// * Negative errno on error
///
/// # Locking
/// Acquires TASK_TABLE lock briefly to read affinity mask.
pub fn sys_sched_getaffinity<A: crate::uaccess::UaccessArch>(
    pid: i64,
    cpusetsize: u64,
    mask_ptr: u64,
    caller_pid: Pid,
) -> i64 {
    use crate::uaccess::copy_to_user;

    // pid < 0 is invalid
    if pid < 0 {
        return EINVAL;
    }

    // cpusetsize must be at least 8 bytes (sizeof u64)
    if cpusetsize < 8 {
        return EINVAL;
    }

    // Validate mask_ptr
    if mask_ptr == 0 {
        return EFAULT;
    }

    let target_pid = if pid == 0 { caller_pid } else { pid as u64 };

    // Get the CPU affinity mask
    let mask = match super::percpu::lookup_task_cpus_allowed(target_pid) {
        Some(m) => m,
        None => return ESRCH,
    };

    // We only support 64 CPUs (single u64), but Linux allows larger buffers
    // Return up to cpusetsize bytes, zero-padded
    let write_size = cpusetsize.min(8) as usize;

    if !A::access_ok(mask_ptr, write_size) {
        return EFAULT;
    }

    // Convert mask to bytes and copy
    let mask_bytes = mask.to_ne_bytes();
    if copy_to_user::<A>(mask_ptr, &mask_bytes[..write_size]).is_err() {
        return EFAULT;
    }

    // Return the size of the kernel cpu_set_t (8 bytes for u64)
    8
}

/// sys_sched_setaffinity - set CPU affinity mask
///
/// Sets the CPU affinity mask for the process specified by pid.
/// If pid is 0, sets for the calling process.
///
/// # Arguments
/// * `pid` - Process ID (0 = calling process)
/// * `cpusetsize` - Size of the user buffer in bytes
/// * `mask_ptr` - Pointer to user buffer containing the CPU mask
/// * `caller_pid` - PID of calling process
/// * `caller_euid` - Effective UID of calling process
///
/// # Returns
/// * 0 on success
/// * Negative errno on error
///
/// # Permission Model
/// - Can always set own affinity
/// - Setting another process's affinity requires CAP_SYS_NICE (or root)
///
/// # Locking
/// Acquires TASK_TABLE lock to modify affinity mask.
pub fn sys_sched_setaffinity<A: crate::uaccess::UaccessArch>(
    pid: i64,
    cpusetsize: u64,
    mask_ptr: u64,
    caller_pid: Pid,
    caller_euid: super::Uid,
) -> i64 {
    use crate::uaccess::copy_from_user;

    // pid < 0 is invalid
    if pid < 0 {
        return EINVAL;
    }

    // cpusetsize must be at least 8 bytes (sizeof u64)
    if cpusetsize < 8 {
        return EINVAL;
    }

    // Validate mask_ptr
    if mask_ptr == 0 {
        return EFAULT;
    }
    if !A::access_ok(mask_ptr, 8) {
        return EFAULT;
    }

    // Read the mask from user space
    let mut mask_bytes = [0u8; 8];
    if copy_from_user::<A>(&mut mask_bytes, mask_ptr, 8).is_err() {
        return EFAULT;
    }
    let mask = u64::from_ne_bytes(mask_bytes);

    // Empty mask is invalid
    if mask == 0 {
        return EINVAL;
    }

    let target_pid = if pid == 0 { caller_pid } else { pid as u64 };

    // Permission check: non-root can only set own affinity
    if target_pid != caller_pid && caller_euid != 0 {
        return EPERM;
    }

    // Set the CPU affinity mask
    match super::percpu::set_task_cpus_allowed(target_pid, mask) {
        Ok(()) => 0,
        Err(errno) => -(errno as i64),
    }
}

/// sys_sched_rr_get_interval - get round-robin time quantum
///
/// Returns the round-robin time quantum for the process specified by pid.
/// If pid is 0, returns for the calling process.
///
/// For non-SCHED_RR tasks, returns 0.
///
/// # Arguments
/// * `pid` - Process ID (0 = calling process)
/// * `tp_ptr` - Pointer to timespec structure to fill
/// * `caller_pid` - PID of calling process
///
/// # Returns
/// * 0 on success
/// * Negative errno on error
///
/// # Locking
/// Acquires TASK_TABLE lock briefly to read policy.
pub fn sys_sched_rr_get_interval<A: crate::uaccess::UaccessArch>(
    pid: i64,
    tp_ptr: u64,
    caller_pid: Pid,
) -> i64 {
    use crate::uaccess::put_user;

    // Timespec structure for return value
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Timespec {
        tv_sec: i64,
        tv_nsec: i64,
    }

    // pid < 0 is invalid
    if pid < 0 {
        return EINVAL;
    }

    // Validate tp_ptr
    if tp_ptr == 0 {
        return EINVAL;
    }
    if !A::access_ok(tp_ptr, core::mem::size_of::<Timespec>()) {
        return EFAULT;
    }

    let target_pid = if pid == 0 { caller_pid } else { pid as u64 };

    // Get the scheduling policy
    let policy = match super::percpu::lookup_task_policy(target_pid) {
        Some(p) => p,
        None => return ESRCH,
    };

    // Only SCHED_RR has a meaningful time quantum
    let base_policy = policy & !super::SCHED_RESET_ON_FORK;
    let time_slice_ns = if base_policy == super::SCHED_RR {
        super::RR_TIMESLICE_NS
    } else {
        0
    };

    // Convert nanoseconds to timespec
    let ts = Timespec {
        tv_sec: (time_slice_ns / 1_000_000_000) as i64,
        tv_nsec: (time_slice_ns % 1_000_000_000) as i64,
    };

    // Copy to user space
    if put_user::<A, Timespec>(tp_ptr, ts).is_err() {
        return EFAULT;
    }

    0
}

/// sys_nice - adjust process priority (nice value)
///
/// Adds `inc` to the nice value for the calling process.
/// Positive values decrease priority, negative values increase it.
///
/// # Arguments
/// * `inc` - Nice value increment
/// * `caller_pid` - PID of calling process
/// * `caller_euid` - Effective UID of calling process
///
/// # Returns
/// * New nice value on success (can be negative!)
/// * Note: Unlike POSIX, Linux nice() returns the new nice value
///
/// # Permission Model
/// - Any process can lower its priority (increase nice)
/// - Only root can raise its priority (decrease nice)
///
/// # Locking
/// Acquires TASK_TABLE lock to modify priority.
pub fn sys_nice(inc: i32, caller_pid: Pid, caller_euid: super::Uid) -> i64 {
    // Get current nice value
    let current_nice = match super::percpu::lookup_task_priority(caller_pid) {
        Some(priority) => super::priority_to_nice(priority),
        None => return ESRCH,
    };

    // Calculate new nice value (clamped to valid range)
    let new_nice = (current_nice + inc).clamp(super::PRIO_MIN, super::PRIO_MAX);

    // Permission check: non-root cannot increase priority (decrease nice)
    if new_nice < current_nice && caller_euid != 0 {
        return EPERM;
    }

    // Set the new priority
    let new_priority = super::nice_to_priority(new_nice);
    match super::percpu::set_task_priority(caller_pid, new_priority) {
        Ok(()) => new_nice as i64,
        Err(errno) => -(errno as i64),
    }
}

// =============================================================================
// I/O Priority Syscalls
// =============================================================================

/// sys_ioprio_set - set I/O scheduling class and priority
///
/// # Arguments
/// * `which` - IOPRIO_WHO_PROCESS, IOPRIO_WHO_PGRP, or IOPRIO_WHO_USER
/// * `who` - ID (pid, pgid, or uid) or 0 for current
/// * `ioprio` - I/O priority value (class << 13 | level)
///
/// # Returns
/// * 0 on success
/// * -EINVAL for invalid arguments
/// * -ESRCH if target not found
/// * -EPERM if not permitted
pub fn sys_ioprio_set(which: i32, who: i32, ioprio: i32) -> i64 {
    use super::{
        IOPRIO_CLASS_IDLE, IOPRIO_CLASS_RT, IOPRIO_WHO_PGRP, IOPRIO_WHO_PROCESS, IOPRIO_WHO_USER,
        get_task_io_context, ioprio_prio_class, ioprio_valid,
    };

    let ioprio = ioprio as u16;

    // Validate ioprio
    if !ioprio_valid(ioprio) {
        return EINVAL;
    }

    let class = ioprio_prio_class(ioprio);
    let caller_euid = super::percpu::current_cred().euid;

    // Permission check: RT and IDLE classes require CAP_SYS_NICE (or root)
    if (class == IOPRIO_CLASS_RT || class == IOPRIO_CLASS_IDLE) && caller_euid != 0 {
        return EPERM;
    }

    match which {
        IOPRIO_WHO_PROCESS => {
            let tid = if who == 0 {
                super::percpu::current_tid()
            } else {
                who as u64
            };

            // Get or create IoContext for the target
            let ctx = match get_task_io_context(tid) {
                Some(ctx) => ctx,
                None => {
                    // Create a new context if target exists
                    if !super::percpu::task_exists(tid) {
                        return ESRCH;
                    }
                    let ctx = alloc::sync::Arc::new(super::IoContext::new());
                    super::set_task_io_context(tid, ctx.clone());
                    ctx
                }
            };

            ctx.set_ioprio(ioprio);
            0
        }
        IOPRIO_WHO_PGRP => {
            // Set ioprio for all processes in a process group
            let pgid = if who == 0 {
                super::percpu::current_pgid()
            } else {
                who as u64
            };

            let tids = super::percpu::get_tids_by_pgid(pgid);
            if tids.is_empty() {
                return ESRCH;
            }

            for tid in tids {
                let ctx = match get_task_io_context(tid) {
                    Some(ctx) => ctx,
                    None => {
                        let ctx = alloc::sync::Arc::new(super::IoContext::new());
                        super::set_task_io_context(tid, ctx.clone());
                        ctx
                    }
                };
                ctx.set_ioprio(ioprio);
            }
            0
        }
        IOPRIO_WHO_USER => {
            // Set ioprio for all processes of a user - not fully implemented
            // Just return success for simplicity
            0
        }
        _ => EINVAL,
    }
}

/// sys_ioprio_get - get I/O scheduling class and priority
///
/// # Arguments
/// * `which` - IOPRIO_WHO_PROCESS, IOPRIO_WHO_PGRP, or IOPRIO_WHO_USER
/// * `who` - ID (pid, pgid, or uid) or 0 for current
///
/// # Returns
/// * I/O priority value on success (class << 13 | level)
/// * -EINVAL for invalid arguments
/// * -ESRCH if target not found
pub fn sys_ioprio_get(which: i32, who: i32) -> i64 {
    use super::{
        IOPRIO_DEFAULT, IOPRIO_WHO_PGRP, IOPRIO_WHO_PROCESS, IOPRIO_WHO_USER, get_task_io_context,
    };

    match which {
        IOPRIO_WHO_PROCESS => {
            let tid = if who == 0 {
                super::percpu::current_tid()
            } else {
                who as u64
            };

            // Check if task exists
            if !super::percpu::task_exists(tid) {
                return ESRCH;
            }

            match get_task_io_context(tid) {
                Some(ctx) => ctx.get_ioprio() as i64,
                None => IOPRIO_DEFAULT as i64,
            }
        }
        IOPRIO_WHO_PGRP => {
            let pgid = if who == 0 {
                super::percpu::current_pgid()
            } else {
                who as u64
            };

            let tids = super::percpu::get_tids_by_pgid(pgid);
            if tids.is_empty() {
                return ESRCH;
            }

            // Return the highest priority (lowest class value, then highest level)
            let mut best_ioprio = IOPRIO_DEFAULT;
            for tid in tids {
                if let Some(ctx) = get_task_io_context(tid) {
                    let ioprio = ctx.get_ioprio();
                    // Compare: lower class is higher priority
                    if ioprio < best_ioprio {
                        best_ioprio = ioprio;
                    }
                }
            }
            best_ioprio as i64
        }
        IOPRIO_WHO_USER => {
            // Get highest ioprio for all processes of a user - not fully implemented
            // Return default for simplicity
            IOPRIO_DEFAULT as i64
        }
        _ => EINVAL,
    }
}

// =============================================================================
// Thread-Local Storage syscalls
// =============================================================================

#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::percpu::{
    ARCH_GET_FS, ARCH_GET_GS, ARCH_SET_FS, ARCH_SET_GS, read_fs_base, write_fs_base,
};

/// sys_arch_prctl - Architecture-specific thread state (x86_64 only)
///
/// Controls architecture-specific thread state. On x86_64, this is used
/// primarily for setting the FS and GS base registers for thread-local storage.
///
/// Supported operations:
/// - ARCH_SET_FS (0x1002): Set FS base address (user TLS pointer)
/// - ARCH_GET_FS (0x1003): Get FS base address
/// - ARCH_SET_GS (0x1001): Not supported (GS is kernel per-CPU)
/// - ARCH_GET_GS (0x1004): Not supported
///
/// Returns 0 on success, negative errno on error.
#[cfg(target_arch = "x86_64")]
pub fn sys_arch_prctl(code: i32, addr: u64) -> i64 {
    use crate::CurrentArch;
    use crate::arch::PerCpuOps;
    use crate::arch::Uaccess;
    use crate::task::{get_task_tls, set_task_tls};
    use crate::uaccess::put_user;

    let tid = CurrentArch::current_tid();

    match code {
        ARCH_SET_FS => {
            // Set FS base - user TLS pointer
            set_task_tls(tid, addr);
            write_fs_base(addr);
            0
        }
        ARCH_GET_FS => {
            // Get FS base - return via user pointer
            // First try our stored value, fall back to reading the register
            let tls = get_task_tls(tid).unwrap_or_else(read_fs_base);

            // Write to user address
            if put_user::<Uaccess, u64>(addr, tls).is_err() {
                return EFAULT;
            }
            0
        }
        ARCH_SET_GS | ARCH_GET_GS => {
            // GS base is used by kernel for per-CPU data, not available to user
            EINVAL
        }
        _ => EINVAL,
    }
}

/// sys_arch_prctl stub for non-x86_64 architectures
#[cfg(not(target_arch = "x86_64"))]
pub fn sys_arch_prctl(_code: i32, _addr: u64) -> i64 {
    // arch_prctl is x86_64-specific
    const ENOSYS: i64 = -38;
    ENOSYS
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
pub fn sys_set_tid_address(tidptr: u64) -> i64 {
    use crate::CurrentArch;
    use crate::arch::PerCpuOps;
    use crate::task::set_clear_child_tid;

    let tid = CurrentArch::current_tid();
    set_clear_child_tid(tid, tidptr);
    tid as i64
}

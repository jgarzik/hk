//! Process lifecycle syscalls
//!
//! This module contains syscalls for process/thread creation and termination:
//! - fork, vfork (process creation)
//! - clone, clone3 (process/thread creation with flags)
//! - exit (process termination)
//! - wait4, waitid (child process waiting)
//! - set_tid_address (thread exit notification)

use crate::error::KernelError;

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

    // Extract exit_signal from low 8 bits of flags (CSIGNAL mask = 0xff)
    let exit_signal = (flags & 0xff) as i32;

    let config = CloneConfig {
        flags: flags & !0xff, // Remove signal bits from flags
        child_stack,
        parent_rip,
        parent_rflags,
        parent_rsp,
        parent_tidptr,
        child_tidptr,
        tls,
        pidfd_ptr: 0,  // CLONE_PIDFD only supported via clone3
        exit_signal,
        cgroup_fd: -1, // CLONE_INTO_CGROUP only supported via clone3
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

    // Extract exit_signal from low 8 bits of flags (CSIGNAL mask = 0xff)
    let exit_signal = (flags & 0xff) as i32;

    let config = CloneConfig {
        flags: flags & !0xff, // Remove signal bits from flags
        child_stack,
        parent_rip,
        parent_rflags,
        parent_rsp,
        parent_tidptr,
        child_tidptr,
        tls,
        pidfd_ptr: 0,  // CLONE_PIDFD only supported via clone3
        exit_signal,
        cgroup_fd: -1, // CLONE_INTO_CGROUP only supported via clone3
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
        pidfd_ptr: 0,
        exit_signal: crate::signal::SIGCHLD as i32, // fork sends SIGCHLD on exit
        cgroup_fd: -1,
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
        pidfd_ptr: 0,
        exit_signal: crate::signal::SIGCHLD as i32, // fork sends SIGCHLD on exit
        cgroup_fd: -1,
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
        pidfd_ptr: 0,
        exit_signal: crate::signal::SIGCHLD as i32, // vfork sends SIGCHLD on exit
        cgroup_fd: -1,
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
        pidfd_ptr: 0,
        exit_signal: crate::signal::SIGCHLD as i32, // vfork sends SIGCHLD on exit
        cgroup_fd: -1,
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
            return KernelError::NoChild.sysret();
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
    use super::wait_options::{P_ALL, P_PGID, P_PID, P_PIDFD, WEXITED, WNOHANG};
    use crate::arch::Uaccess;
    use crate::uaccess::{UaccessArch, put_user};

    let current_pid = super::percpu::current_pid();
    let current_tid = super::percpu::current_tid();

    // Validate infop pointer if non-null
    if infop != 0 && !Uaccess::access_ok(infop, core::mem::size_of::<SigInfo>()) {
        return KernelError::BadAddress.sysret();
    }

    // Validate idtype
    if idtype != P_ALL && idtype != P_PID && idtype != P_PGID && idtype != P_PIDFD {
        return KernelError::InvalidArgument.sysret();
    }

    // Must specify at least one wait condition
    // For now we only support WEXITED (terminated children)
    if options & WEXITED == 0 {
        // We don't support WSTOPPED or WCONTINUED yet
        return KernelError::InvalidArgument.sysret();
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
        P_PIDFD => {
            // id is a file descriptor - get the PID from the pidfd
            let fd_table = match super::fdtable::get_task_fd(current_tid) {
                Some(table) => table,
                None => return KernelError::NoProcess.sysret(),
            };
            let file = {
                let table = fd_table.lock();
                match table.get(id as i32) {
                    Some(file) => file,
                    None => return KernelError::BadFd.sysret(),
                }
            };
            match crate::pidfd::get_pidfd_pid(&file) {
                Some(pid) => pid as i64,
                None => return KernelError::BadFd.sysret(), // not a pidfd
            }
        }
        _ => return KernelError::InvalidArgument.sysret(),
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
                    return KernelError::BadAddress.sysret();
                }
            }
            return 0; // Success
        }

        // No zombie child found - check if we have any children at all
        if !super::percpu::has_children(current_pid, wait_pid) {
            return KernelError::NoChild.sysret();
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
                    return KernelError::BadAddress.sysret();
                }
            }
            return 0;
        }

        // Children exist but none are zombies yet - yield and retry
        super::percpu::yield_now();
    }
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
    /// Array of PIDs for set_tid feature (CLONE_SET_TID, not implemented)
    pub set_tid: u64,
    /// Size of set_tid array
    pub set_tid_size: u64,
    /// Cgroup file descriptor (CLONE_INTO_CGROUP, not implemented)
    pub cgroup: u64,
}

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
#[cfg(target_arch = "x86_64")]
pub fn sys_clone3(uargs: u64, size: u64) -> i64 {
    use super::percpu::CloneConfig;
    use crate::FRAME_ALLOCATOR;
    use crate::arch::Uaccess;
    use crate::arch::x86_64::percpu::{
        get_syscall_user_rflags, get_syscall_user_rip, get_syscall_user_rsp,
    };
    use crate::frame_alloc::FrameAllocRef;
    use crate::uaccess::{UaccessArch, copy_from_user};

    // Validate size - must be at least VER0 and not too large
    if size < CLONE_ARGS_SIZE_VER0 as u64 || size > 4096 {
        return KernelError::InvalidArgument.sysret();
    }

    // Validate user pointer
    if !Uaccess::access_ok(uargs, size as usize) {
        return KernelError::BadAddress.sysret();
    }

    // Copy clone_args from userspace (zero-fill any missing fields)
    let mut args = CloneArgs::default();
    let copy_size = core::cmp::min(size as usize, core::mem::size_of::<CloneArgs>());
    let args_bytes = unsafe {
        core::slice::from_raw_parts_mut(&mut args as *mut CloneArgs as *mut u8, copy_size)
    };
    if copy_from_user::<Uaccess>(args_bytes, uargs, copy_size).is_err() {
        return KernelError::BadAddress.sysret();
    }

    // Validate clone3-specific constraints

    // exit_signal must be valid (only low 8 bits used, must be valid signal or 0)
    if (args.exit_signal & !CSIGNAL) != 0 || args.exit_signal > 64 {
        return KernelError::InvalidArgument.sysret();
    }

    // CLONE_INTO_CGROUP requires cgroup fd and VER2 size
    let cgroup_fd = if (args.flags & CLONE_INTO_CGROUP) != 0 {
        if size < CLONE_ARGS_SIZE_VER2 as u64 {
            return KernelError::InvalidArgument.sysret();
        }
        args.cgroup as i32
    } else {
        -1
    };

    // set_tid feature not supported
    if args.set_tid != 0 || args.set_tid_size != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Validate stack - if stack is provided, stack_size must also be provided
    if args.stack != 0 && args.stack_size == 0 {
        return KernelError::InvalidArgument.sysret();
    }
    if args.stack == 0 && args.stack_size != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // CLONE_THREAD or CLONE_PARENT cannot have exit_signal
    let clone_thread = super::clone_flags::CLONE_THREAD;
    let clone_parent = super::clone_flags::CLONE_PARENT;
    if (args.flags & (clone_thread | clone_parent)) != 0 && args.exit_signal != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Get parent's return address, flags, and stack from per-CPU data
    let parent_rip = get_syscall_user_rip();
    let parent_rflags = get_syscall_user_rflags();
    let parent_rsp = get_syscall_user_rsp();

    // Calculate actual child stack pointer
    // clone3 provides stack base and size; we need to compute the stack top
    let child_stack = if args.stack != 0 {
        // Stack grows down, so stack top = stack + stack_size
        args.stack.wrapping_add(args.stack_size)
    } else {
        0 // Inherit parent stack (for fork-like behavior)
    };

    let config = CloneConfig {
        flags: args.flags,
        child_stack,
        parent_rip,
        parent_rflags,
        parent_rsp,
        parent_tidptr: args.parent_tid,
        child_tidptr: args.child_tid,
        tls: args.tls,
        pidfd_ptr: args.pidfd,
        exit_signal: args.exit_signal as i32,
        cgroup_fd,
    };

    // Get frame allocator
    let mut frame_alloc = FrameAllocRef(&FRAME_ALLOCATOR);

    match super::percpu::do_clone(config, &mut frame_alloc) {
        Ok(child_tid) => child_tid as i64,
        Err(errno) => -(errno as i64),
    }
}

/// sys_clone3 for aarch64 - create a new process with extended arguments
#[cfg(target_arch = "aarch64")]
pub fn sys_clone3(uargs: u64, size: u64) -> i64 {
    use super::percpu::CloneConfig;
    use crate::FRAME_ALLOCATOR;
    use crate::arch::PerCpuOps;
    use crate::arch::Uaccess;
    use crate::arch::aarch64::Aarch64Arch;
    use crate::frame_alloc::FrameAllocRef;
    use crate::uaccess::{UaccessArch, copy_from_user};

    // Validate size - must be at least VER0 and not too large
    if size < CLONE_ARGS_SIZE_VER0 as u64 || size > 4096 {
        return KernelError::InvalidArgument.sysret();
    }

    // Validate user pointer
    if !Uaccess::access_ok(uargs, size as usize) {
        return KernelError::BadAddress.sysret();
    }

    // Copy clone_args from userspace (zero-fill any missing fields)
    let mut args = CloneArgs::default();
    let copy_size = core::cmp::min(size as usize, core::mem::size_of::<CloneArgs>());
    let args_bytes = unsafe {
        core::slice::from_raw_parts_mut(&mut args as *mut CloneArgs as *mut u8, copy_size)
    };
    if copy_from_user::<Uaccess>(args_bytes, uargs, copy_size).is_err() {
        return KernelError::BadAddress.sysret();
    }

    // Validate clone3-specific constraints

    // exit_signal must be valid (only low 8 bits used, must be valid signal or 0)
    if (args.exit_signal & !CSIGNAL) != 0 || args.exit_signal > 64 {
        return KernelError::InvalidArgument.sysret();
    }

    // CLONE_INTO_CGROUP requires cgroup fd and VER2 size
    let cgroup_fd = if (args.flags & CLONE_INTO_CGROUP) != 0 {
        if size < CLONE_ARGS_SIZE_VER2 as u64 {
            return KernelError::InvalidArgument.sysret();
        }
        args.cgroup as i32
    } else {
        -1
    };

    // set_tid feature not supported
    if args.set_tid != 0 || args.set_tid_size != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Validate stack - if stack is provided, stack_size must also be provided
    if args.stack != 0 && args.stack_size == 0 {
        return KernelError::InvalidArgument.sysret();
    }
    if args.stack == 0 && args.stack_size != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // CLONE_THREAD or CLONE_PARENT cannot have exit_signal
    let clone_thread = super::clone_flags::CLONE_THREAD;
    let clone_parent = super::clone_flags::CLONE_PARENT;
    if (args.flags & (clone_thread | clone_parent)) != 0 && args.exit_signal != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Get parent's return address, flags, and stack from per-CPU data
    let parent_rip = Aarch64Arch::get_syscall_user_rip();
    let parent_rflags = Aarch64Arch::get_syscall_user_rflags();
    let parent_rsp = Aarch64Arch::get_syscall_user_rsp();

    // Calculate actual child stack pointer
    // clone3 provides stack base and size; we need to compute the stack top
    let child_stack = if args.stack != 0 {
        // Stack grows down, so stack top = stack + stack_size
        args.stack.wrapping_add(args.stack_size)
    } else {
        0 // Inherit parent stack (for fork-like behavior)
    };

    let config = CloneConfig {
        flags: args.flags,
        child_stack,
        parent_rip,
        parent_rflags,
        parent_rsp,
        parent_tidptr: args.parent_tid,
        child_tidptr: args.child_tid,
        tls: args.tls,
        pidfd_ptr: args.pidfd,
        exit_signal: args.exit_signal as i32,
        cgroup_fd,
    };

    // Get frame allocator
    let mut frame_alloc = FrameAllocRef(&FRAME_ALLOCATOR);

    match super::percpu::do_clone(config, &mut frame_alloc) {
        Ok(child_tid) => child_tid as i64,
        Err(errno) => -(errno as i64),
    }
}

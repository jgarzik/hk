//! Miscellaneous task syscalls
//!
//! This module contains various task-related syscalls:
//! - sysinfo, getrusage, getrandom (system info)
//! - prctl, arch_prctl, personality (process control)
//! - syslog (kernel logging)
//! - capget, capset (capabilities)
//! - pidfd_open, pidfd_send_signal, pidfd_getfd (pidfd operations)

use crate::error::KernelError;

use super::Pid;

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
        return KernelError::BadAddress.sysret();
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
        return KernelError::BadAddress.sysret();
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
        return KernelError::InvalidArgument.sysret();
    }

    // Validate user pointer
    if !A::access_ok(usage_ptr, core::mem::size_of::<Rusage>()) {
        return KernelError::BadAddress.sysret();
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
        _ => return KernelError::InvalidArgument.sysret(),
    };

    // Copy to user space
    if put_user::<A, Rusage>(usage_ptr, usage).is_err() {
        return KernelError::BadAddress.sysret();
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
        return KernelError::InvalidArgument.sysret();
    }

    // Limit single read to stack buffer size
    let len = buflen.min(MAX_GETRANDOM);

    // Validate user buffer
    if !A::access_ok(buf, len) {
        return KernelError::BadAddress.sysret();
    }

    // Generate random bytes
    let mut tmp = [0u8; MAX_GETRANDOM];
    match random::get_random_bytes(&mut tmp[..len], flags) {
        Ok(n) => {
            // Copy to user space
            if copy_to_user::<A>(buf, &tmp[..n]).is_err() {
                return KernelError::BadAddress.sysret();
            }
            n as i64
        }
        Err(e) => e as i64,
    }
}

// =============================================================================
// prctl syscall
// =============================================================================

use crate::task::prctl_ops::{
    PR_GET_DUMPABLE, PR_GET_NAME, PR_GET_NO_NEW_PRIVS, PR_GET_PDEATHSIG, PR_GET_SECCOMP,
    PR_GET_TIMERSLACK, PR_SET_DUMPABLE, PR_SET_NAME, PR_SET_NO_NEW_PRIVS, PR_SET_PDEATHSIG,
    PR_SET_SECCOMP, PR_SET_TIMERSLACK,
};

/// sys_prctl - Process/thread control operations
///
/// Provides various process/thread control operations. Unlike arch_prctl,
/// this syscall is portable across architectures.
///
/// Supported operations:
/// - PR_SET_PDEATHSIG (1): Set parent death signal (arg2 = signal, 0 to disable)
/// - PR_GET_PDEATHSIG (2): Get parent death signal (arg2 = int* for result)
/// - PR_SET_DUMPABLE (4): Set core dump flag (arg2 = 0, 1, or 2)
/// - PR_GET_DUMPABLE (3): Get core dump flag (returns value)
/// - PR_SET_NAME (15): Set thread name (16-byte max, arg2 = char*)
/// - PR_GET_NAME (16): Get thread name (arg2 = char* buffer)
/// - PR_SET_TIMERSLACK (29): Set timer slack (arg2 = nanoseconds)
/// - PR_GET_TIMERSLACK (30): Get timer slack (returns nanoseconds)
/// - PR_SET_NO_NEW_PRIVS (38): Disable privilege escalation (arg2 = 1, irreversible)
/// - PR_GET_NO_NEW_PRIVS (39): Get no_new_privs flag (returns 0 or 1)
///
/// Returns 0 on success (or value for GET operations), negative errno on error.
pub fn sys_prctl(option: i32, arg2: u64, _arg3: u64, _arg4: u64, _arg5: u64) -> i64 {
    use crate::arch::Uaccess;
    use crate::task::dumpable::{SUID_DUMP_DISABLE, SUID_DUMP_ROOT, SUID_DUMP_USER};
    use crate::task::percpu::{TASK_TABLE, current_tid};
    use crate::uaccess::{get_user, put_user};

    let tid = current_tid();

    match option {
        PR_SET_PDEATHSIG => {
            // Set signal to send when parent dies
            // arg2 is the signal number (0 = disable)
            let sig = arg2 as i32;

            // Validate signal number (0 is valid - means disable)
            if !(0..=64).contains(&sig) {
                return KernelError::InvalidArgument.sysret();
            }

            let mut table = TASK_TABLE.lock();
            if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
                task.pdeath_signal = sig;
                0
            } else {
                KernelError::NoProcess.sysret()
            }
        }

        PR_GET_PDEATHSIG => {
            // Get current parent death signal
            // arg2 is pointer to int where result is stored
            let sig = {
                let table = TASK_TABLE.lock();
                match table.tasks.iter().find(|t| t.tid == tid) {
                    Some(task) => task.pdeath_signal,
                    None => return KernelError::NoProcess.sysret(),
                }
            };

            // Write signal to user-space pointer
            if put_user::<Uaccess, i32>(arg2, sig).is_err() {
                return KernelError::BadAddress.sysret();
            }
            0
        }

        PR_SET_NAME => {
            // Set thread name from user-space string (max 16 bytes including null)
            let mut name = [0u8; 16];

            // Read up to 16 bytes from user space
            for (i, slot) in name.iter_mut().enumerate() {
                match get_user::<Uaccess, u8>(arg2 + i as u64) {
                    Ok(byte) => {
                        *slot = byte;
                        if byte == 0 {
                            break; // Null terminator found
                        }
                    }
                    Err(_) => return KernelError::BadAddress.sysret(),
                }
            }
            // Ensure null termination
            name[15] = 0;

            // Update task's prctl state
            let mut table = TASK_TABLE.lock();
            if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
                task.prctl.name = name;
                0
            } else {
                KernelError::NoProcess.sysret()
            }
        }

        PR_GET_NAME => {
            // Get thread name and write to user buffer
            let name = {
                let table = TASK_TABLE.lock();
                match table.tasks.iter().find(|t| t.tid == tid) {
                    Some(task) => task.prctl.name,
                    None => return KernelError::NoProcess.sysret(),
                }
            };

            // Write name to user space (16 bytes)
            for (i, &byte) in name.iter().enumerate() {
                if put_user::<Uaccess, u8>(arg2 + i as u64, byte).is_err() {
                    return KernelError::BadAddress.sysret();
                }
            }
            0
        }

        PR_SET_DUMPABLE => {
            // Set dumpable flag (0, 1, or 2)
            let value = arg2 as u8;
            if value != SUID_DUMP_DISABLE && value != SUID_DUMP_USER && value != SUID_DUMP_ROOT {
                return KernelError::InvalidArgument.sysret();
            }

            let mut table = TASK_TABLE.lock();
            if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
                task.prctl.dumpable = value;
                0
            } else {
                KernelError::NoProcess.sysret()
            }
        }

        PR_GET_DUMPABLE => {
            // Return dumpable flag value
            let table = TASK_TABLE.lock();
            match table.tasks.iter().find(|t| t.tid == tid) {
                Some(task) => task.prctl.dumpable as i64,
                None => KernelError::NoProcess.sysret(),
            }
        }

        PR_SET_NO_NEW_PRIVS => {
            // Set no_new_privs flag (irreversible once set)
            // arg2 must be 1 to enable, any other value is EINVAL
            if arg2 != 1 {
                return KernelError::InvalidArgument.sysret();
            }

            let mut table = TASK_TABLE.lock();
            if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
                task.prctl.no_new_privs = true;
                0
            } else {
                KernelError::NoProcess.sysret()
            }
        }

        PR_GET_NO_NEW_PRIVS => {
            // Return no_new_privs flag (0 or 1)
            let table = TASK_TABLE.lock();
            match table.tasks.iter().find(|t| t.tid == tid) {
                Some(task) => {
                    if task.prctl.no_new_privs {
                        1
                    } else {
                        0
                    }
                }
                None => KernelError::NoProcess.sysret(),
            }
        }

        PR_SET_TIMERSLACK => {
            // Set timer slack in nanoseconds
            // arg2 of 0 resets to default (50,000 ns)
            let slack = if arg2 == 0 { 50_000 } else { arg2 };

            let mut table = TASK_TABLE.lock();
            if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
                task.prctl.timer_slack_ns = slack;
                0
            } else {
                KernelError::NoProcess.sysret()
            }
        }

        PR_GET_TIMERSLACK => {
            // Return timer slack in nanoseconds
            let table = TASK_TABLE.lock();
            match table.tasks.iter().find(|t| t.tid == tid) {
                Some(task) => task.prctl.timer_slack_ns as i64,
                None => KernelError::NoProcess.sysret(),
            }
        }

        PR_GET_SECCOMP => {
            // Delegate to seccomp module
            crate::seccomp::prctl_get_seccomp()
        }

        PR_SET_SECCOMP => {
            // Delegate to seccomp module
            // arg2 = mode, _arg3 = filter (for FILTER mode)
            crate::seccomp::prctl_set_seccomp(arg2, _arg3)
        }

        _ => KernelError::InvalidArgument.sysret(), // unsupported operation
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
                return KernelError::BadAddress.sysret();
            }
            0
        }
        ARCH_SET_GS | ARCH_GET_GS => {
            // GS base is used by kernel for per-CPU data, not available to user
            KernelError::InvalidArgument.sysret()
        }
        _ => KernelError::InvalidArgument.sysret(),
    }
}

/// sys_arch_prctl stub for non-x86_64 architectures
#[cfg(not(target_arch = "x86_64"))]
pub fn sys_arch_prctl(_code: i32, _addr: u64) -> i64 {
    // arch_prctl is x86_64-specific
    KernelError::NotImplemented.sysret()
}

// =============================================================================
// personality syscall - Process execution domain
// =============================================================================

/// sys_personality - set process execution domain
///
/// The personality syscall controls various execution behaviors like
/// how the kernel reports certain system information. Used primarily
/// for running programs compiled for different ABIs.
///
/// # Arguments
/// * `personality` - New personality value, or 0xFFFFFFFF to query current
///
/// # Returns
/// * Previous personality value on success
///
/// # Linux ABI
/// If personality is 0xFFFFFFFF, returns current personality without changing it.
/// Otherwise, sets new personality and returns old value.
pub fn sys_personality(personality: u32) -> i64 {
    // Get current personality
    let old = super::percpu::get_current_personality();

    // If querying only, return current value
    if personality == 0xFFFFFFFF {
        return old as i64;
    }

    // Set new personality
    super::percpu::set_current_personality(personality);

    old as i64
}

// =============================================================================
// syslog syscall - Kernel logging operations
// =============================================================================

/// Syslog action codes (from Linux include/linux/syslog.h)
pub mod syslog_action {
    /// Close the log (nop for us)
    pub const SYSLOG_ACTION_CLOSE: i32 = 0;
    /// Open the log (nop for us)
    pub const SYSLOG_ACTION_OPEN: i32 = 1;
    /// Read from the log
    pub const SYSLOG_ACTION_READ: i32 = 2;
    /// Read all messages (and mark as read)
    pub const SYSLOG_ACTION_READ_ALL: i32 = 3;
    /// Read all messages and clear ring buffer
    pub const SYSLOG_ACTION_READ_CLEAR: i32 = 4;
    /// Clear ring buffer
    pub const SYSLOG_ACTION_CLEAR: i32 = 5;
    /// Disable printk to console
    pub const SYSLOG_ACTION_CONSOLE_OFF: i32 = 6;
    /// Enable printk to console
    pub const SYSLOG_ACTION_CONSOLE_ON: i32 = 7;
    /// Set console log level
    pub const SYSLOG_ACTION_CONSOLE_LEVEL: i32 = 8;
    /// Return number of unread characters
    pub const SYSLOG_ACTION_SIZE_UNREAD: i32 = 9;
    /// Return size of the log buffer
    pub const SYSLOG_ACTION_SIZE_BUFFER: i32 = 10;
}

/// sys_syslog - read and/or clear kernel message ring buffer
///
/// Provides access to the kernel's message buffer (dmesg).
///
/// # Arguments
/// * `type_` - Operation to perform (SYSLOG_ACTION_*)
/// * `buf` - User buffer for read operations
/// * `len` - Length of buffer
///
/// # Returns
/// * >= 0 on success (depends on operation)
/// * < 0 on error
///
/// # Permissions
/// Most operations require CAP_SYSLOG or CAP_SYS_ADMIN.
pub fn sys_syslog<A: crate::uaccess::UaccessArch>(type_: i32, buf: u64, len: i32) -> i64 {
    use syslog_action::*;

    // Basic validation
    if len < 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Check permissions for privileged operations
    // SYSLOG_ACTION_READ_ALL, READ_CLEAR, CLEAR, CONSOLE_* require CAP_SYSLOG
    let needs_cap = matches!(
        type_,
        SYSLOG_ACTION_READ
            | SYSLOG_ACTION_READ_ALL
            | SYSLOG_ACTION_READ_CLEAR
            | SYSLOG_ACTION_CLEAR
            | SYSLOG_ACTION_CONSOLE_OFF
            | SYSLOG_ACTION_CONSOLE_ON
            | SYSLOG_ACTION_CONSOLE_LEVEL
    );

    if needs_cap && !super::capable(super::CAP_SYSLOG) && !super::capable(super::CAP_SYS_ADMIN) {
        return KernelError::NotPermitted.sysret();
    }

    match type_ {
        SYSLOG_ACTION_CLOSE | SYSLOG_ACTION_OPEN => {
            // No-op, just return success
            0
        }

        SYSLOG_ACTION_READ | SYSLOG_ACTION_READ_ALL | SYSLOG_ACTION_READ_CLEAR => {
            // Read from kernel log buffer
            if buf == 0 || len == 0 {
                return KernelError::InvalidArgument.sysret();
            }
            if !A::access_ok(buf, len as usize) {
                return KernelError::BadAddress.sysret();
            }

            // For now, we don't have a kernel log buffer implementation
            // Just return 0 bytes read (empty buffer)
            0
        }

        SYSLOG_ACTION_CLEAR => {
            // Clear the ring buffer - no-op for now
            0
        }

        SYSLOG_ACTION_CONSOLE_OFF => {
            // Disable console logging - no-op for now
            0
        }

        SYSLOG_ACTION_CONSOLE_ON => {
            // Enable console logging - no-op for now
            0
        }

        SYSLOG_ACTION_CONSOLE_LEVEL => {
            // Set console log level
            // len parameter is the log level (1-8 typically)
            if !(1..=8).contains(&len) {
                return KernelError::InvalidArgument.sysret();
            }
            // No-op for now
            0
        }

        SYSLOG_ACTION_SIZE_UNREAD => {
            // Return number of unread bytes
            // We don't track this, so return 0
            0
        }

        SYSLOG_ACTION_SIZE_BUFFER => {
            // Return size of log buffer
            // We don't have one, so return a reasonable default
            0
        }

        _ => KernelError::InvalidArgument.sysret(),
    }
}

// =============================================================================
// Capability syscalls (capget, capset)
// =============================================================================

use super::{
    _LINUX_CAPABILITY_U32S_3, _LINUX_CAPABILITY_VERSION_1, _LINUX_CAPABILITY_VERSION_2,
    _LINUX_CAPABILITY_VERSION_3, CapUserData, CapUserHeader, KernelCap,
};

/// Validate capability header version and return number of u32s to copy
///
/// If the version is invalid, writes the current version back to the header
/// and returns -EINVAL.
fn cap_validate_magic<A: crate::uaccess::UaccessArch>(
    header_addr: u64,
) -> Result<(usize, i32), i64> {
    use crate::uaccess::{get_user, put_user};

    if header_addr == 0 {
        return Err(KernelError::BadAddress.sysret());
    }

    // Read header from user space
    let hdr: CapUserHeader = match get_user::<A, CapUserHeader>(header_addr) {
        Ok(h) => h,
        Err(_) => return Err(KernelError::BadAddress.sysret()),
    };

    let version = hdr.version;
    let pid = hdr.pid;

    match version {
        _LINUX_CAPABILITY_VERSION_1 => {
            // Legacy 32-bit version - only 1 u32 per set
            Ok((1, pid))
        }
        _LINUX_CAPABILITY_VERSION_2 | _LINUX_CAPABILITY_VERSION_3 => {
            // 64-bit versions - 2 u32s per set
            Ok((_LINUX_CAPABILITY_U32S_3, pid))
        }
        _ => {
            // Invalid version - write current version back and return EINVAL
            let current_version = CapUserHeader {
                version: _LINUX_CAPABILITY_VERSION_3,
                pid: 0,
            };
            let _ = put_user::<A, CapUserHeader>(header_addr, current_version);
            Err(KernelError::InvalidArgument.sysret())
        }
    }
}

/// sys_capget - get capabilities of a process
///
/// Gets the capabilities of the target process. The target can be:
/// - 0: current process
/// - current pid: current process
/// - other pid: that process (requires appropriate permissions)
///
/// If dataptr is NULL and the version is valid, returns 0 (version query).
/// Otherwise, copies capability data to userspace.
pub fn sys_capget<A: crate::uaccess::UaccessArch>(header_addr: u64, data_addr: u64) -> i64 {
    use crate::uaccess::put_user;

    // Validate version and get number of u32s to copy
    let (tocopy, pid) = match cap_validate_magic::<A>(header_addr) {
        Ok((n, p)) => (n, p),
        Err(e) => {
            // If dataptr is NULL and we got EINVAL, this is a version query
            if data_addr == 0 && e == KernelError::InvalidArgument.sysret() {
                return 0;
            }
            return e;
        }
    };

    // If dataptr is NULL, this is just a version query (already validated)
    if data_addr == 0 {
        return 0;
    }

    // Get current pid
    let current_pid = super::percpu::current_pid() as i32;

    // Determine which credentials to read
    let cred = if pid == 0 || pid == current_pid {
        // Query our own capabilities
        super::current_cred()
    } else if pid < 0 {
        return KernelError::InvalidArgument.sysret();
    } else {
        // Query another process's capabilities
        // For now, only support querying current process
        // Full implementation would use find_task_by_vpid and RCU
        return KernelError::NoProcess.sysret();
    };

    // Build capability data arrays
    // Linux uses 2 CapUserData structs for 64-bit capability representation
    let mut kdata = [CapUserData::default(); 2];
    kdata[0].effective = cred.cap_effective.low();
    kdata[1].effective = cred.cap_effective.high();
    kdata[0].permitted = cred.cap_permitted.low();
    kdata[1].permitted = cred.cap_permitted.high();
    kdata[0].inheritable = cred.cap_inheritable.low();
    kdata[1].inheritable = cred.cap_inheritable.high();

    // Copy to user space
    for (i, item) in kdata.iter().enumerate().take(tocopy) {
        let dst = data_addr + (i * core::mem::size_of::<CapUserData>()) as u64;
        if put_user::<A, CapUserData>(dst, *item).is_err() {
            return KernelError::BadAddress.sysret();
        }
    }

    0
}

/// sys_capset - set capabilities of current process
///
/// Sets the capabilities of the current process. The pid in the header
/// must be 0 or the current process's pid.
///
/// Restrictions:
/// - I (inheritable): raised bits must be subset of old permitted
/// - P (permitted): raised bits must be subset of old permitted
/// - E (effective): must be subset of new permitted
pub fn sys_capset<A: crate::uaccess::UaccessArch>(header_addr: u64, data_addr: u64) -> i64 {
    use crate::uaccess::get_user;

    // Validate version and get number of u32s to copy
    let (tocopy, pid) = match cap_validate_magic::<A>(header_addr) {
        Ok((n, p)) => (n, p),
        Err(e) => return e,
    };

    // Get current pid
    let current_pid = super::percpu::current_pid() as i32;

    // May only affect current process (Linux restriction since kernel 2.6.27)
    if pid != 0 && pid != current_pid {
        return KernelError::NotPermitted.sysret();
    }

    // Read capability data from user space
    let mut kdata = [CapUserData::default(); 2];
    for (i, item) in kdata.iter_mut().enumerate().take(tocopy) {
        let src = data_addr + (i * core::mem::size_of::<CapUserData>()) as u64;
        match get_user::<A, CapUserData>(src) {
            Ok(d) => *item = d,
            Err(_) => return KernelError::BadAddress.sysret(),
        }
    }

    // Combine 32-bit values into 64-bit capabilities
    let effective = KernelCap::from_u32s(kdata[0].effective, kdata[1].effective);
    let permitted = KernelCap::from_u32s(kdata[0].permitted, kdata[1].permitted);
    let inheritable = KernelCap::from_u32s(kdata[0].inheritable, kdata[1].inheritable);

    // Get current credentials
    let old_cred = super::current_cred();

    // Validate capability changes (Linux security rules from kernel/capability.c):
    //
    // 1. New inheritable must not add any capabilities not in old permitted
    //    (can only inherit what we're permitted to use)
    if !inheritable.is_subset(&old_cred.cap_permitted) {
        return KernelError::NotPermitted.sysret();
    }

    // 2. New permitted must not add any capabilities not in old permitted
    //    (can't gain capabilities we don't already have)
    if !permitted.is_subset(&old_cred.cap_permitted) {
        return KernelError::NotPermitted.sysret();
    }

    // 3. New effective must be subset of new permitted
    //    (can't use capabilities we're not permitted to use)
    if !effective.is_subset(&permitted) {
        return KernelError::NotPermitted.sysret();
    }

    // Create new credentials with updated capabilities
    let mut new_cred = old_cred;
    new_cred.cap_effective = effective;
    new_cred.cap_permitted = permitted;
    new_cred.cap_inheritable = inheritable;
    // Note: bset and ambient are not modified by capset

    // Commit the new credentials
    super::commit_creds(alloc::sync::Arc::new(new_cred));

    0
}

// ============================================================================
// pidfd syscalls
// ============================================================================

/// sys_pidfd_open - obtain a file descriptor for a process
///
/// # Arguments
/// * `pid` - Process ID to obtain pidfd for
/// * `flags` - Flags (PIDFD_NONBLOCK only)
///
/// # Returns
/// * >= 0: File descriptor on success
/// * -EINVAL: Invalid flags or pid
/// * -ESRCH: No such process
pub fn sys_pidfd_open(pid: i64, flags: u32) -> i64 {
    // Validate flags - only O_NONBLOCK (0o4000) is allowed
    const PIDFD_NONBLOCK: u32 = 0o4000;
    if flags & !PIDFD_NONBLOCK != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Validate pid
    if pid <= 0 {
        return KernelError::InvalidArgument.sysret();
    }

    let target_pid = pid as Pid;

    // Check if process exists
    {
        let table = super::percpu::TASK_TABLE.lock();
        if !table.tasks.iter().any(|t| t.pid == target_pid) {
            return KernelError::NoProcess.sysret();
        }
    }

    // Create pidfd
    let pidfd_file = match crate::pidfd::create_pidfd(target_pid, flags) {
        Ok(file) => file,
        Err(_) => return KernelError::OutOfMemory.sysret(),
    };

    // Allocate FD in current task's FD table
    let current_tid = super::percpu::current_tid();
    let fd_table = match super::fdtable::get_task_fd(current_tid) {
        Some(table) => table,
        None => return KernelError::NoProcess.sysret(),
    };

    let mut table = fd_table.lock();

    // Get NOFILE limit
    let nofile = {
        let limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_NOFILE);
        if limit == crate::rlimit::RLIM_INFINITY {
            u64::MAX
        } else {
            limit
        }
    };

    // Check if we need FD_CLOEXEC (O_CLOEXEC is 0o2000000)
    let fd_flags = if flags & 0o2000000 != 0 {
        super::FD_CLOEXEC
    } else {
        0
    };

    match table.alloc_with_flags(pidfd_file, fd_flags, nofile) {
        Ok(fd) => fd as i64,
        Err(e) => e as i64,
    }
}

/// sys_pidfd_send_signal - send a signal to a process via a pidfd
///
/// # Arguments
/// * `pidfd` - File descriptor referring to the target process
/// * `sig` - Signal number to send
/// * `info` - Optional siginfo_t pointer (not used currently)
/// * `flags` - Flags (must be 0)
///
/// # Returns
/// * 0 on success
/// * -EBADF: Invalid file descriptor
/// * -EINVAL: Invalid signal number or flags
/// * -ESRCH: Process no longer exists
pub fn sys_pidfd_send_signal(pidfd: i32, sig: i32, _info: u64, flags: u32) -> i64 {
    // Flags must be 0
    if flags != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Validate signal number (0 is allowed as a null signal for checking permissions)
    if !(0..=64).contains(&sig) {
        return KernelError::InvalidArgument.sysret();
    }

    // Get the file from FD table
    let current_tid = super::percpu::current_tid();
    let fd_table = match super::fdtable::get_task_fd(current_tid) {
        Some(table) => table,
        None => return KernelError::NoProcess.sysret(),
    };

    let file = {
        let table = fd_table.lock();
        match table.get(pidfd) {
            Some(file) => file,
            None => return KernelError::BadFd.sysret(),
        }
    };

    // Validate it's a pidfd and get target PID
    let target_pid = match crate::pidfd::get_pidfd_pid(&file) {
        Some(pid) => pid,
        None => return KernelError::BadFd.sysret(), // not a pidfd
    };

    // Check if process still exists
    {
        let table = super::percpu::TASK_TABLE.lock();
        if !table.tasks.iter().any(|t| t.pid == target_pid) {
            return KernelError::NoProcess.sysret();
        }
    }

    // Signal 0 is a null signal - just check if process exists
    if sig == 0 {
        return 0;
    }

    // Send the signal
    crate::signal::send_signal_to_process(target_pid, sig as u32) as i64
}

/// sys_pidfd_getfd - obtain a duplicate of another process's file descriptor
///
/// This syscall duplicates a file descriptor from another process identified
/// by a pidfd. The new fd is allocated in the caller's fd table with O_CLOEXEC set.
///
/// # Arguments
/// * `pidfd` - File descriptor referring to the target process (from pidfd_open)
/// * `targetfd` - File descriptor number in the target process to duplicate
/// * `flags` - Flags (must be 0, reserved for future use)
///
/// # Returns
/// * >= 0: New file descriptor on success
/// * -EBADF: pidfd is not a valid fd or not a pidfd, or targetfd is invalid in target
/// * -ESRCH: Target process doesn't exist or has exited
/// * -EPERM: Permission denied (caller cannot access target's fds)
/// * -EINVAL: flags is non-zero
/// * -EMFILE: Too many open files in caller's process
///
/// # Permission Model
/// Simplified PTRACE_MODE_ATTACH: allow if caller has CAP_SYS_PTRACE or same euid.
pub fn sys_pidfd_getfd(pidfd: i32, targetfd: i32, flags: u32) -> i64 {
    // Validate flags (must be 0)
    if flags != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Get caller's fd table and the pidfd file
    let caller_tid = super::percpu::current_tid();
    let caller_fd_table = match super::fdtable::get_task_fd(caller_tid) {
        Some(t) => t,
        None => return KernelError::NoProcess.sysret(),
    };

    let pidfd_file = {
        let table = caller_fd_table.lock();
        match table.get(pidfd) {
            Some(f) => f,
            None => return KernelError::BadFd.sysret(),
        }
    };

    // Verify it's actually a pidfd and get the target PID
    let target_pid = match crate::pidfd::get_pidfd_pid(&pidfd_file) {
        Some(pid) => pid,
        None => return KernelError::BadFd.sysret(), // not a pidfd
    };

    // Find the target task by PID and check permissions
    let target_tid = match find_task_by_pid(target_pid) {
        Some(tid) => tid,
        None => return KernelError::NoProcess.sysret(),
    };

    // Permission check: CAP_SYS_PTRACE or same euid
    if !check_pidfd_getfd_permission(target_tid) {
        return KernelError::NotPermitted.sysret();
    }

    // Get target's fd table
    let target_fd_table = match super::fdtable::get_task_fd(target_tid) {
        Some(t) => t,
        None => return KernelError::NoProcess.sysret(), // Process exiting
    };

    // Get the file from target's fd table
    let target_file = {
        let table = target_fd_table.lock();
        match table.get(targetfd) {
            Some(f) => f,
            None => return KernelError::BadFd.sysret(),
        }
    };

    // Allocate new fd in caller's fd table with FD_CLOEXEC
    let nofile = crate::rlimit::rlimit(crate::rlimit::RLIMIT_NOFILE);
    let new_fd = {
        let mut table = caller_fd_table.lock();
        match table.alloc_with_flags(target_file, super::FD_CLOEXEC, nofile) {
            Ok(fd) => fd,
            Err(e) => return e as i64,
        }
    };

    new_fd as i64
}

/// Find a task by PID (returns TID of the main thread)
fn find_task_by_pid(pid: super::Pid) -> Option<super::Tid> {
    let table = super::percpu::TASK_TABLE.lock();
    table.tasks.iter().find(|t| t.pid == pid).map(|t| t.tid)
}

/// Check permission for pidfd_getfd
///
/// Simplified PTRACE_MODE_ATTACH check:
/// - Allow if caller has CAP_SYS_PTRACE
/// - Allow if same effective UID
fn check_pidfd_getfd_permission(target_tid: super::Tid) -> bool {
    // CAP_SYS_PTRACE bypasses all checks
    if super::capable(super::CAP_SYS_PTRACE) {
        return true;
    }

    // Get caller credentials
    let caller_cred = super::percpu::current_cred();

    // Get target credentials from task table
    let target_euid = {
        let table = super::percpu::TASK_TABLE.lock();
        table
            .tasks
            .iter()
            .find(|t| t.tid == target_tid)
            .map(|t| t.cred.euid)
    };

    // Same effective UID check
    match target_euid {
        Some(euid) => caller_cred.euid == euid,
        None => false, // Target doesn't exist
    }
}

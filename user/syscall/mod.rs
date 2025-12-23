//! Architecture-specific syscall wrappers
//!
//! This module provides a common interface for Linux syscalls across different
//! architectures (x86_64 and aarch64). Each architecture has different syscall
//! numbers and calling conventions.
//!
//! # Architecture Differences
//!
//! | Aspect | x86_64 | aarch64 |
//! |--------|--------|---------|
//! | Instruction | `syscall` | `svc #0` |
//! | Syscall Number | RAX | X8 |
//! | Arguments | RDI, RSI, RDX, R10, R8, R9 | X0-X5 |
//! | Return Value | RAX | X0 |
//!
//! Additionally, aarch64 uses different syscall numbers and has removed some
//! legacy syscalls (open, fork, dup2) in favor of newer alternatives (openat,
//! clone, dup3).

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::*;

// ============================================================================
// Common types used by syscalls (architecture-independent)
// ============================================================================

/// Timespec structure for nanosleep and related syscalls
#[repr(C)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

/// Timeval structure for select syscall
#[repr(C)]
pub struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

/// pollfd structure for poll syscall
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PollFd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}

impl PollFd {
    pub const fn new(fd: i32, events: i16) -> Self {
        Self { fd, events, revents: 0 }
    }
}

/// fd_set for select syscall (1024 bits = 128 bytes)
#[repr(C)]
pub struct FdSet {
    pub bits: [u64; 16],
}

impl FdSet {
    pub const fn new() -> Self {
        Self { bits: [0; 16] }
    }

    pub fn zero(&mut self) {
        // Use volatile writes to ensure compiler doesn't optimize away the zeroing
        for i in 0..16 {
            unsafe { core::ptr::write_volatile(&mut self.bits[i], 0) };
        }
    }

    pub fn set(&mut self, fd: i32) {
        if fd >= 0 && fd < 1024 {
            let idx = fd as usize / 64;
            let bit = fd as usize % 64;
            self.bits[idx] |= 1u64 << bit;
        }
    }

    pub fn is_set(&self, fd: i32) -> bool {
        if fd >= 0 && fd < 1024 {
            let idx = fd as usize / 64;
            let bit = fd as usize % 64;
            (self.bits[idx] >> bit) & 1 != 0
        } else {
            false
        }
    }
}

// Poll event flags
pub const POLLIN: i16 = 0x0001;
pub const POLLPRI: i16 = 0x0002;
pub const POLLOUT: i16 = 0x0004;
pub const POLLERR: i16 = 0x0008;
pub const POLLHUP: i16 = 0x0010;
pub const POLLNVAL: i16 = 0x0020;

/// iovec structure for readv/writev
#[repr(C)]
pub struct IoVec {
    pub iov_base: *const u8,
    pub iov_len: usize,
}

/// siginfo_t structure for waitid (simplified)
#[repr(C)]
pub struct SigInfo {
    pub si_signo: i32,
    pub si_errno: i32,
    pub si_code: i32,
    pub _pad0: i32,
    pub si_pid: i32,
    pub si_uid: u32,
    pub si_status: i32,
    pub _pad: [u8; 128 - 28], // Padding to match Linux size
}

/// Linux stat structure (common layout)
#[repr(C)]
pub struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub _pad0: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: i64,
    pub st_mtime: i64,
    pub st_mtime_nsec: i64,
    pub st_ctime: i64,
    pub st_ctime_nsec: i64,
    pub _unused: [i64; 3],
}

/// Linux dirent64 structure
#[repr(C, packed)]
#[allow(dead_code)]
pub struct LinuxDirent64 {
    pub d_ino: u64,
    pub d_off: i64,
    pub d_reclen: u16,
    pub d_type: u8,
    // d_name follows
}

// ============================================================================
// Common constants (architecture-independent)
// ============================================================================

// Open flags
pub const O_RDONLY: u32 = 0;
pub const O_WRONLY: u32 = 1;
pub const O_RDWR: u32 = 2;
pub const O_CREAT: u32 = 0o100;
pub const O_TRUNC: u32 = 0o1000;
pub const O_DIRECTORY: u32 = 0o200000;

// lseek whence constants
pub const SEEK_SET: i32 = 0;
pub const SEEK_CUR: i32 = 1;
pub const SEEK_END: i32 = 2;

// Clone flags
pub const CLONE_VM: u64 = 0x00000100;
pub const CLONE_SIGHAND: u64 = 0x00000800;
pub const CLONE_PARENT: u64 = 0x00008000;
pub const CLONE_SYSVSEM: u64 = 0x00040000;
pub const CLONE_SETTLS: u64 = 0x00080000;
pub const CLONE_IO: u64 = 0x80000000;
pub const CLONE_CLEAR_SIGHAND: u64 = 0x100000000;

// I/O priority constants
pub const IOPRIO_CLASS_NONE: u16 = 0;
pub const IOPRIO_CLASS_RT: u16 = 1;
pub const IOPRIO_CLASS_BE: u16 = 2;
pub const IOPRIO_CLASS_IDLE: u16 = 3;

pub const IOPRIO_WHO_PROCESS: i32 = 1;
pub const IOPRIO_WHO_PGRP: i32 = 2;
pub const IOPRIO_WHO_USER: i32 = 3;

/// Construct ioprio value from class and level
pub const fn ioprio_prio_value(class: u16, level: u16) -> i32 {
    (((class & 0x7) << 13) | (level & 0x1fff)) as i32
}

// waitid idtype values
pub const P_ALL: i32 = 0;
pub const P_PID: i32 = 1;
#[allow(dead_code)]
pub const P_PGID: i32 = 2;

// waitid options
pub const WEXITED: i32 = 4;

// Priority "which" values for getpriority/setpriority
pub const PRIO_PROCESS: i32 = 0;
#[allow(dead_code)]
pub const PRIO_PGRP: i32 = 1;
#[allow(dead_code)]
pub const PRIO_USER: i32 = 2;

// Scheduling policies
pub const SCHED_NORMAL: i32 = 0;
pub const SCHED_FIFO: i32 = 1;
pub const SCHED_RR: i32 = 2;
#[allow(dead_code)]
pub const SCHED_BATCH: i32 = 3;
#[allow(dead_code)]
pub const SCHED_IDLE: i32 = 5;

/// sched_param structure for sched_setscheduler/sched_getparam
#[repr(C)]
pub struct SchedParam {
    pub sched_priority: i32,
}

// Clock IDs
pub const CLOCK_REALTIME: i32 = 0;
pub const CLOCK_MONOTONIC: i32 = 1;

// utimensat special values
pub const UTIME_NOW: i64 = 0x3fffffff;
pub const UTIME_OMIT: i64 = 0x3ffffffe;

// Linux reboot magic numbers and commands
pub const LINUX_REBOOT_MAGIC1: u64 = 0xfee1dead;
pub const LINUX_REBOOT_MAGIC2: u64 = 0x28121969;
pub const LINUX_REBOOT_CMD_POWER_OFF: u64 = 0x4321fedc;

// AT_FDCWD for *at() syscalls
pub const AT_FDCWD: i32 = -100;

// ============================================================================
// Futex constants
// ============================================================================

/// Wait if *uaddr == val
pub const FUTEX_WAIT: u32 = 0;
/// Wake up to val waiters
pub const FUTEX_WAKE: u32 = 1;
/// Requeue waiters from uaddr to uaddr2
pub const FUTEX_REQUEUE: u32 = 3;
/// Requeue if *uaddr == val3
pub const FUTEX_CMP_REQUEUE: u32 = 4;
/// Wait with bitset matching
pub const FUTEX_WAIT_BITSET: u32 = 9;
/// Wake with bitset matching
pub const FUTEX_WAKE_BITSET: u32 = 10;

/// Private futex (no shared memory)
pub const FUTEX_PRIVATE_FLAG: u32 = 128;
/// Use CLOCK_REALTIME for timeout
pub const FUTEX_CLOCK_REALTIME: u32 = 256;

/// Match any bit in bitset operations
pub const FUTEX_BITSET_MATCH_ANY: u32 = 0xffffffff;

/// There are waiters on this futex
pub const FUTEX_WAITERS: u32 = 0x80000000;
/// Owner died without unlocking
pub const FUTEX_OWNER_DIED: u32 = 0x40000000;
/// Mask for TID in futex value
pub const FUTEX_TID_MASK: u32 = 0x3fffffff;

/// Robust list head structure (matches Linux ABI)
#[repr(C)]
pub struct RobustListHead {
    /// The head of the list. Points back to itself if empty.
    pub list: u64,
    /// Relative offset from list entry to the futex field
    pub futex_offset: i64,
    /// Address of lock being acquired (for race with exit)
    pub list_op_pending: u64,
}

impl RobustListHead {
    /// Size of the robust list head structure
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

// mmap protection flags
pub const PROT_NONE: u32 = 0;
pub const PROT_READ: u32 = 1;
pub const PROT_WRITE: u32 = 2;
pub const PROT_EXEC: u32 = 4;
/// mprotect: extend change to start of growsdown VMA
pub const PROT_GROWSDOWN: u32 = 0x0100_0000;
/// mprotect: extend change to end of growsup VMA (always EINVAL on x86-64/aarch64)
pub const PROT_GROWSUP: u32 = 0x0200_0000;

// mmap flags
pub const MAP_SHARED: u32 = 0x01;
pub const MAP_PRIVATE: u32 = 0x02;
pub const MAP_FIXED: u32 = 0x10;
pub const MAP_ANONYMOUS: u32 = 0x20;
/// Stack-like segment that grows downward on page faults
pub const MAP_GROWSDOWN: u32 = 0x0100;
pub const MAP_DENYWRITE: u32 = 0x0800;
pub const MAP_EXECUTABLE: u32 = 0x1000;
pub const MAP_LOCKED: u32 = 0x2000;
/// Prefault page tables (populate pages immediately after mmap)
pub const MAP_POPULATE: u32 = 0x8000;
/// Don't block on I/O when used with MAP_POPULATE (skips populate)
pub const MAP_NONBLOCK: u32 = 0x10000;
/// Stack allocation hint (no-op on systems without THP)
pub const MAP_STACK: u32 = 0x20000;

// mlock2 flags
pub const MLOCK_ONFAULT: i32 = 0x01;

// mlockall flags
pub const MCL_CURRENT: i32 = 1;
pub const MCL_FUTURE: i32 = 2;
pub const MCL_ONFAULT: i32 = 4;

// Resource limits (rlimit constants)
/// CPU time limit (seconds)
pub const RLIMIT_CPU: u32 = 0;
/// Maximum file size (bytes)
pub const RLIMIT_FSIZE: u32 = 1;
/// Maximum data segment size (bytes)
pub const RLIMIT_DATA: u32 = 2;
/// Maximum stack size (bytes)
pub const RLIMIT_STACK: u32 = 3;
/// Maximum core file size (bytes)
pub const RLIMIT_CORE: u32 = 4;
/// Maximum resident set size (unused)
pub const RLIMIT_RSS: u32 = 5;
/// Maximum processes per user
pub const RLIMIT_NPROC: u32 = 6;
/// Maximum open files
pub const RLIMIT_NOFILE: u32 = 7;
/// Maximum locked memory (bytes)
pub const RLIMIT_MEMLOCK: u32 = 8;
/// Maximum address space (bytes)
pub const RLIMIT_AS: u32 = 9;
/// Maximum file locks
pub const RLIMIT_LOCKS: u32 = 10;
/// Maximum pending signals
pub const RLIMIT_SIGPENDING: u32 = 11;
/// Maximum POSIX message queue bytes
pub const RLIMIT_MSGQUEUE: u32 = 12;
/// Maximum nice priority
pub const RLIMIT_NICE: u32 = 13;
/// Maximum realtime priority
pub const RLIMIT_RTPRIO: u32 = 14;
/// Maximum realtime CPU time (microseconds)
pub const RLIMIT_RTTIME: u32 = 15;
/// Number of resource limits
pub const RLIM_NLIMITS: u32 = 16;
/// Unlimited resource value
pub const RLIM_INFINITY: u64 = !0u64;

/// Resource limit structure (matches Linux struct rlimit64)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RLimit {
    /// Soft limit (current enforced limit)
    pub rlim_cur: u64,
    /// Hard limit (maximum allowed)
    pub rlim_max: u64,
}

impl RLimit {
    /// Create a new RLimit
    pub const fn new(cur: u64, max: u64) -> Self {
        Self { rlim_cur: cur, rlim_max: max }
    }
}

// Signal numbers
pub const SIGHUP: u32 = 1;
pub const SIGINT: u32 = 2;
pub const SIGQUIT: u32 = 3;
pub const SIGILL: u32 = 4;
pub const SIGTRAP: u32 = 5;
pub const SIGABRT: u32 = 6;
pub const SIGBUS: u32 = 7;
pub const SIGFPE: u32 = 8;
pub const SIGKILL: u32 = 9;
pub const SIGUSR1: u32 = 10;
pub const SIGSEGV: u32 = 11;
pub const SIGUSR2: u32 = 12;
pub const SIGPIPE: u32 = 13;
pub const SIGALRM: u32 = 14;
pub const SIGTERM: u32 = 15;
pub const SIGCHLD: u32 = 17;

// Signal mask operations
pub const SIG_BLOCK: i32 = 0;
pub const SIG_UNBLOCK: i32 = 1;
pub const SIG_SETMASK: i32 = 2;

// Special signal handler values
pub const SIG_DFL: u64 = 0;
pub const SIG_IGN: u64 = 1;

/// UTS name structure for uname syscall (Linux ABI compatible)
///
/// This structure matches Linux's `struct new_utsname` exactly.
/// Each field is 65 bytes (64 chars + NUL terminator).
#[repr(C)]
pub struct UtsName {
    /// Operating system name (e.g., "Linux", "hk")
    pub sysname: [u8; 65],
    /// Hostname (set via sethostname)
    pub nodename: [u8; 65],
    /// Kernel release (e.g., "6.1.0")
    pub release: [u8; 65],
    /// Kernel version (e.g., "#1 SMP")
    pub version: [u8; 65],
    /// Hardware type (e.g., "x86_64")
    pub machine: [u8; 65],
    /// NIS domain name (set via setdomainname)
    pub domainname: [u8; 65],
}

impl Default for UtsName {
    fn default() -> Self {
        Self {
            sysname: [0u8; 65],
            nodename: [0u8; 65],
            release: [0u8; 65],
            version: [0u8; 65],
            machine: [0u8; 65],
            domainname: [0u8; 65],
        }
    }
}

// ============================================================================
// Socket types and constants
// ============================================================================

/// Socket address for IPv4 (struct sockaddr_in)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockAddrIn {
    /// Address family (AF_INET)
    pub sin_family: u16,
    /// Port number (network byte order / big-endian)
    pub sin_port: u16,
    /// IPv4 address (network byte order / big-endian)
    pub sin_addr: u32,
    /// Padding to match sockaddr size
    pub sin_zero: [u8; 8],
}

impl SockAddrIn {
    /// Create a new socket address
    pub const fn new(family: u16, port: u16, addr: u32) -> Self {
        Self {
            sin_family: family,
            sin_port: port,
            sin_addr: addr,
            sin_zero: [0; 8],
        }
    }

    /// Create an address for INADDR_ANY:0
    pub const fn any() -> Self {
        Self::new(AF_INET as u16, 0, 0)
    }
}

// Address families
pub const AF_UNIX: i32 = 1;
pub const AF_INET: i32 = 2;
pub const AF_INET6: i32 = 10;

// Socket types
pub const SOCK_STREAM: i32 = 1;
pub const SOCK_DGRAM: i32 = 2;
pub const SOCK_RAW: i32 = 3;

// Socket type flags (can be ORed with socket type)
pub const SOCK_NONBLOCK: i32 = 0o4000;
pub const SOCK_CLOEXEC: i32 = 0o2000000;

// Shutdown "how" values
pub const SHUT_RD: i32 = 0;
pub const SHUT_WR: i32 = 1;
pub const SHUT_RDWR: i32 = 2;

// Protocol numbers
pub const IPPROTO_TCP: i32 = 6;
pub const IPPROTO_UDP: i32 = 17;

// Error codes (positive values, syscalls return negative)
pub const EAFNOSUPPORT: i64 = 97;
pub const ECONNREFUSED: i64 = 111;
pub const EINPROGRESS: i64 = 115;
pub const ENOTCONN: i64 = 107;

/// Convert host byte order to network byte order (big-endian) for u16
#[inline]
pub const fn htons(val: u16) -> u16 {
    val.to_be()
}

/// Convert network byte order to host byte order for u16
#[inline]
pub const fn ntohs(val: u16) -> u16 {
    u16::from_be(val)
}

/// Convert host byte order to network byte order (big-endian) for u32
#[inline]
pub const fn htonl(val: u32) -> u32 {
    val.to_be()
}

/// Convert network byte order to host byte order for u32
#[inline]
pub const fn ntohl(val: u32) -> u32 {
    u32::from_be(val)
}

/// Create an IPv4 address from four octets (e.g., make_ipv4(10, 0, 2, 2))
#[inline]
pub const fn make_ipv4(a: u8, b: u8, c: u8, d: u8) -> u32 {
    ((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | (d as u32)
}

// ============================================================================
// SysV IPC types and constants
// ============================================================================

/// Create new IPC object
pub const IPC_CREAT: i32 = 0o1000;
/// Fail if key exists
pub const IPC_EXCL: i32 = 0o2000;
/// Test for existence
pub const IPC_NOWAIT: i32 = 0o4000;
/// Private key (always create new)
pub const IPC_PRIVATE: i32 = 0;

/// IPC control commands
pub const IPC_RMID: i32 = 0;
pub const IPC_SET: i32 = 1;
pub const IPC_STAT: i32 = 2;
pub const IPC_INFO: i32 = 3;

/// Shared memory flags
pub const SHM_RDONLY: i32 = 0o10000;
pub const SHM_RND: i32 = 0o20000;

/// Semaphore buffer structure for semop
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sembuf {
    /// Semaphore index
    pub sem_num: u16,
    /// Operation (positive = increment, negative = decrement, 0 = wait for zero)
    pub sem_op: i16,
    /// Operation flags (IPC_NOWAIT, SEM_UNDO)
    pub sem_flg: i16,
}

impl Sembuf {
    /// Create a new semaphore operation buffer
    pub const fn new(sem_num: u16, sem_op: i16, sem_flg: i16) -> Self {
        Self { sem_num, sem_op, sem_flg }
    }
}

/// Semaphore undo on exit
pub const SEM_UNDO: i16 = 0x1000;

/// Semctl commands
pub const GETVAL: i32 = 12;
pub const SETVAL: i32 = 16;
pub const GETALL: i32 = 13;
pub const SETALL: i32 = 17;
pub const GETNCNT: i32 = 14;
pub const GETZCNT: i32 = 15;

/// Message queue flags
pub const MSG_NOERROR: i32 = 0o10000;
pub const MSG_EXCEPT: i32 = 0o20000;
pub const MSG_COPY: i32 = 0o40000;

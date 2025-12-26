//! Common types used by syscalls (architecture-independent)

// ============================================================================
// Time structures
// ============================================================================

/// Timespec structure for nanosleep and related syscalls
#[repr(C)]
#[derive(Clone, Copy)]
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

// ============================================================================
// Poll/Select structures
// ============================================================================

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

// ============================================================================
// I/O structures
// ============================================================================

/// iovec structure for readv/writev
#[repr(C)]
pub struct IoVec {
    pub iov_base: *const u8,
    pub iov_len: usize,
}

// ============================================================================
// Signal structures
// ============================================================================

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

// ============================================================================
// Stat structures
// ============================================================================

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
pub struct LinuxDirent64 {
    pub d_ino: u64,
    pub d_off: i64,
    pub d_reclen: u16,
    pub d_type: u8,
    // d_name follows
}

// ============================================================================
// Open/file flags
// ============================================================================

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

// ============================================================================
// Clone flags
// ============================================================================

pub const CLONE_VM: u64 = 0x00000100;
pub const CLONE_SIGHAND: u64 = 0x00000800;
pub const CLONE_PARENT: u64 = 0x00008000;
pub const CLONE_NEWNS: u64 = 0x0002_0000;
pub const CLONE_SYSVSEM: u64 = 0x00040000;
pub const CLONE_SETTLS: u64 = 0x00080000;
pub const CLONE_NEWUTS: u64 = 0x0400_0000;
pub const CLONE_NEWIPC: u64 = 0x0800_0000;
pub const CLONE_NEWUSER: u64 = 0x1000_0000;
pub const CLONE_NEWPID: u64 = 0x2000_0000;
pub const CLONE_NEWNET: u64 = 0x4000_0000;
pub const CLONE_IO: u64 = 0x80000000;
pub const CLONE_CLEAR_SIGHAND: u64 = 0x100000000;

// ============================================================================
// I/O priority
// ============================================================================

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

// ============================================================================
// Wait/process constants
// ============================================================================

// waitid idtype values
pub const P_ALL: i32 = 0;
pub const P_PID: i32 = 1;
pub const P_PGID: i32 = 2;
pub const P_PIDFD: i32 = 3;

// waitid options
pub const WEXITED: i32 = 4;

// Priority "which" values for getpriority/setpriority
pub const PRIO_PROCESS: i32 = 0;
pub const PRIO_PGRP: i32 = 1;
pub const PRIO_USER: i32 = 2;

// ============================================================================
// Scheduling
// ============================================================================

pub const SCHED_NORMAL: i32 = 0;
pub const SCHED_FIFO: i32 = 1;
pub const SCHED_RR: i32 = 2;
pub const SCHED_BATCH: i32 = 3;
pub const SCHED_IDLE: i32 = 5;

/// sched_param structure for sched_setscheduler/sched_getparam
#[repr(C)]
pub struct SchedParam {
    pub sched_priority: i32,
}

// ============================================================================
// Clock constants
// ============================================================================

pub const CLOCK_REALTIME: i32 = 0;
pub const CLOCK_MONOTONIC: i32 = 1;

// utimensat special values
pub const UTIME_NOW: i64 = 0x3fffffff;
pub const UTIME_OMIT: i64 = 0x3ffffffe;

// ============================================================================
// Reboot constants
// ============================================================================

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

// ============================================================================
// mmap/mprotect constants
// ============================================================================

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
/// Like MAP_FIXED but fails with EEXIST instead of unmapping existing mappings
pub const MAP_FIXED_NOREPLACE: u32 = 0x100000;

// msync flags
/// Schedule write but don't wait (no-op in modern kernels)
pub const MS_ASYNC: i32 = 1;
/// Invalidate cached pages
pub const MS_INVALIDATE: i32 = 2;
/// Synchronously write dirty pages to disk
pub const MS_SYNC: i32 = 4;

// madvise flags
/// No special treatment (default)
pub const MADV_NORMAL: i32 = 0;
/// Expect random page references
pub const MADV_RANDOM: i32 = 1;
/// Expect sequential page references
pub const MADV_SEQUENTIAL: i32 = 2;
/// Will need these pages soon (prefault)
pub const MADV_WILLNEED: i32 = 3;
/// Don't need these pages (zap and free)
pub const MADV_DONTNEED: i32 = 4;
/// Mark pages as lazily freeable
pub const MADV_FREE: i32 = 8;
/// Don't copy this VMA on fork
pub const MADV_DONTFORK: i32 = 10;
/// Do copy this VMA on fork (undo MADV_DONTFORK)
pub const MADV_DOFORK: i32 = 11;
/// Don't include in core dumps
pub const MADV_DONTDUMP: i32 = 16;
/// Include in core dumps (undo MADV_DONTDUMP)
pub const MADV_DODUMP: i32 = 17;

// mlock2 flags
pub const MLOCK_ONFAULT: i32 = 0x01;

// mlockall flags
pub const MCL_CURRENT: i32 = 1;
pub const MCL_FUTURE: i32 = 2;
pub const MCL_ONFAULT: i32 = 4;

// mremap flags
/// Allow kernel to move mapping if can't resize in-place
pub const MREMAP_MAYMOVE: u32 = 1;
/// Move to exact new_addr (implies MREMAP_MAYMOVE)
pub const MREMAP_FIXED: u32 = 2;
/// Keep original mapping after move
pub const MREMAP_DONTUNMAP: u32 = 4;

// ============================================================================
// Resource limits
// ============================================================================

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

// ============================================================================
// Signals
// ============================================================================

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

// ============================================================================
// UTS name structure
// ============================================================================

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

// ============================================================================
// Message header structures for sendmsg/recvmsg
// ============================================================================

/// Message header for sendmsg/recvmsg (struct msghdr)
#[repr(C)]
pub struct MsgHdr {
    /// Optional address
    pub msg_name: *mut SockAddrIn,
    /// Size of address
    pub msg_namelen: u32,
    /// Padding
    _pad1: u32,
    /// Scatter/gather array
    pub msg_iov: *mut IoVec,
    /// Number of elements in iov
    pub msg_iovlen: usize,
    /// Ancillary data
    pub msg_control: *mut u8,
    /// Ancillary data length
    pub msg_controllen: usize,
    /// Flags on received message
    pub msg_flags: i32,
    /// Padding
    _pad2: i32,
}

impl MsgHdr {
    /// Create a new MsgHdr with iovec
    pub fn new(iov: *mut IoVec, iovlen: usize) -> Self {
        Self {
            msg_name: core::ptr::null_mut(),
            msg_namelen: 0,
            _pad1: 0,
            msg_iov: iov,
            msg_iovlen: iovlen,
            msg_control: core::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
            _pad2: 0,
        }
    }

    /// Create a MsgHdr with destination address (for UDP sendmsg)
    pub fn with_addr(addr: *mut SockAddrIn, iov: *mut IoVec, iovlen: usize) -> Self {
        Self {
            msg_name: addr,
            msg_namelen: core::mem::size_of::<SockAddrIn>() as u32,
            _pad1: 0,
            msg_iov: iov,
            msg_iovlen: iovlen,
            msg_control: core::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
            _pad2: 0,
        }
    }
}

/// Multi-message header for sendmmsg/recvmmsg (struct mmsghdr)
#[repr(C)]
pub struct MMsgHdr {
    /// Message header
    pub msg_hdr: MsgHdr,
    /// Number of bytes transmitted/received
    pub msg_len: u32,
    /// Padding
    _pad: u32,
}

impl MMsgHdr {
    /// Create a new MMsgHdr
    pub fn new(hdr: MsgHdr) -> Self {
        Self {
            msg_hdr: hdr,
            msg_len: 0,
            _pad: 0,
        }
    }
}

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

// ============================================================================
// Filesystem statistics types
// ============================================================================

/// Linux statfs structure (64-bit)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LinuxStatFs {
    /// Filesystem type magic
    pub f_type: i64,
    /// Optimal transfer block size
    pub f_bsize: i64,
    /// Total data blocks
    pub f_blocks: i64,
    /// Free blocks
    pub f_bfree: i64,
    /// Free blocks for unprivileged user
    pub f_bavail: i64,
    /// Total inodes
    pub f_files: i64,
    /// Free inodes
    pub f_ffree: i64,
    /// Filesystem ID
    pub f_fsid: [i32; 2],
    /// Maximum filename length
    pub f_namelen: i64,
    /// Fragment size
    pub f_frsize: i64,
    /// Mount flags
    pub f_flags: i64,
    /// Padding
    pub f_spare: [i64; 4],
}

// Filesystem magic numbers
pub const RAMFS_MAGIC: i64 = 0x858458f6;
pub const PROC_SUPER_MAGIC: i64 = 0x9fa0;
pub const MSDOS_SUPER_MAGIC: i64 = 0x4d44;

// ============================================================================
// statx types and constants
// ============================================================================

/// statx timestamp structure
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct StatxTimestamp {
    pub tv_sec: i64,
    pub tv_nsec: u32,
    pub __reserved: i32,
}

/// Linux statx structure (256 bytes)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Statx {
    /// What results were written
    pub stx_mask: u32,
    /// Preferred I/O size
    pub stx_blksize: u32,
    /// File attributes
    pub stx_attributes: u64,
    /// Hard links
    pub stx_nlink: u32,
    /// User ID
    pub stx_uid: u32,
    /// Group ID
    pub stx_gid: u32,
    /// File type and mode
    pub stx_mode: u16,
    pub __spare0: [u16; 1],
    /// Inode number
    pub stx_ino: u64,
    /// File size
    pub stx_size: u64,
    /// 512-byte blocks allocated
    pub stx_blocks: u64,
    /// Supported attributes
    pub stx_attributes_mask: u64,
    /// Access time
    pub stx_atime: StatxTimestamp,
    /// Birth/creation time
    pub stx_btime: StatxTimestamp,
    /// Status change time
    pub stx_ctime: StatxTimestamp,
    /// Modification time
    pub stx_mtime: StatxTimestamp,
    /// Device major for device files
    pub stx_rdev_major: u32,
    /// Device minor for device files
    pub stx_rdev_minor: u32,
    /// Filesystem device major
    pub stx_dev_major: u32,
    /// Filesystem device minor
    pub stx_dev_minor: u32,
    /// Mount ID
    pub stx_mnt_id: u64,
    /// DIO memory alignment
    pub stx_dio_mem_align: u32,
    /// DIO offset alignment
    pub stx_dio_offset_align: u32,
    /// Subvolume ID
    pub stx_subvol: u64,
    /// Atomic write min
    pub stx_atomic_write_unit_min: u32,
    /// Atomic write max
    pub stx_atomic_write_unit_max: u32,
    /// Atomic write segments max
    pub stx_atomic_write_segments_max: u32,
    /// DIO read offset alignment
    pub stx_dio_read_offset_align: u32,
    /// Atomic write max opt
    pub stx_atomic_write_unit_max_opt: u32,
    pub __spare2: [u32; 1],
    pub __spare3: [u64; 8],
}

// STATX mask bits
pub const STATX_TYPE: u32 = 0x0001;
pub const STATX_MODE: u32 = 0x0002;
pub const STATX_NLINK: u32 = 0x0004;
pub const STATX_UID: u32 = 0x0008;
pub const STATX_GID: u32 = 0x0010;
pub const STATX_ATIME: u32 = 0x0020;
pub const STATX_MTIME: u32 = 0x0040;
pub const STATX_CTIME: u32 = 0x0080;
pub const STATX_INO: u32 = 0x0100;
pub const STATX_SIZE: u32 = 0x0200;
pub const STATX_BLOCKS: u32 = 0x0400;
pub const STATX_BASIC_STATS: u32 = 0x07ff;
pub const STATX_BTIME: u32 = 0x0800;

// AT_* flags for statx
pub const AT_EMPTY_PATH: i32 = 0x1000;
pub const AT_SYMLINK_NOFOLLOW: i32 = 0x100;

// ============================================================================
// Timerfd types and constants
// ============================================================================

/// itimerspec structure for timerfd
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ITimerSpec {
    /// Interval for periodic timer (0 = one-shot)
    pub it_interval: Timespec,
    /// Initial expiration time
    pub it_value: Timespec,
}

impl ITimerSpec {
    /// Create a new itimerspec
    pub const fn new(value_sec: i64, value_nsec: i64, interval_sec: i64, interval_nsec: i64) -> Self {
        Self {
            it_value: Timespec { tv_sec: value_sec, tv_nsec: value_nsec },
            it_interval: Timespec { tv_sec: interval_sec, tv_nsec: interval_nsec },
        }
    }

    /// Create a one-shot timer with the given expiration
    pub const fn oneshot(sec: i64, nsec: i64) -> Self {
        Self::new(sec, nsec, 0, 0)
    }

    /// Create a periodic timer
    pub const fn periodic(sec: i64, nsec: i64) -> Self {
        Self::new(sec, nsec, sec, nsec)
    }

    /// Create a disarmed timer
    pub const fn disarmed() -> Self {
        Self::new(0, 0, 0, 0)
    }
}

impl Default for ITimerSpec {
    fn default() -> Self {
        Self::disarmed()
    }
}

/// timerfd_create flags
pub const TFD_CLOEXEC: i32 = 0o2000000;
pub const TFD_NONBLOCK: i32 = 0o4000;

/// timerfd_settime flags
pub const TFD_TIMER_ABSTIME: i32 = 1;
pub const TFD_TIMER_CANCEL_ON_SET: i32 = 2;

/// eventfd flags
pub const EFD_SEMAPHORE: i32 = 1;
pub const EFD_CLOEXEC: i32 = 0o2000000;
pub const EFD_NONBLOCK: i32 = 0o4000;

/// signalfd flags
pub const SFD_CLOEXEC: i32 = 0o2000000;
pub const SFD_NONBLOCK: i32 = 0o4000;

/// signalfd_siginfo structure - Linux ABI (128 bytes)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SignalfdSiginfo {
    /// Signal number
    pub ssi_signo: u32,
    /// Error number
    pub ssi_errno: i32,
    /// Signal code
    pub ssi_code: i32,
    /// Sender's PID
    pub ssi_pid: u32,
    /// Sender's UID
    pub ssi_uid: u32,
    /// File descriptor (SIGIO)
    pub ssi_fd: i32,
    /// Sender's TID
    pub ssi_tid: u32,
    /// Band event (SIGIO)
    pub ssi_band: u32,
    /// POSIX timer overrun count
    pub ssi_overrun: u32,
    /// Trap number
    pub ssi_trapno: u32,
    /// Exit status/signal (SIGCHLD)
    pub ssi_status: i32,
    /// sigqueue() integer
    pub ssi_int: i32,
    /// sigqueue() pointer
    pub ssi_ptr: u64,
    /// User CPU time (SIGCHLD)
    pub ssi_utime: u64,
    /// System CPU time (SIGCHLD)
    pub ssi_stime: u64,
    /// Fault address
    pub ssi_addr: u64,
    /// LSB of address
    pub ssi_addr_lsb: u16,
    __pad2: u16,
    /// System call number
    pub ssi_syscall: i32,
    /// Address of system call instruction
    pub ssi_call_addr: u64,
    /// Architecture
    pub ssi_arch: u32,
    __pad: [u8; 28],
}

// ============================================================================
// prctl constants (Section 10.4)
// ============================================================================

/// prctl operation codes
pub const PR_GET_DUMPABLE: i32 = 3;
pub const PR_SET_DUMPABLE: i32 = 4;
pub const PR_SET_NAME: i32 = 15;
pub const PR_GET_NAME: i32 = 16;
pub const PR_SET_TIMERSLACK: i32 = 29;
pub const PR_GET_TIMERSLACK: i32 = 30;
pub const PR_SET_NO_NEW_PRIVS: i32 = 38;
pub const PR_GET_NO_NEW_PRIVS: i32 = 39;

/// Dumpable flag values
pub const SUID_DUMP_DISABLE: i32 = 0;
pub const SUID_DUMP_USER: i32 = 1;
pub const SUID_DUMP_ROOT: i32 = 2;

// ============================================================================
// POSIX timer types and constants (Section 6.2)
// ============================================================================

/// POSIX timer_settime flags
pub const TIMER_ABSTIME: i32 = 1;

/// POSIX timer notification types
pub mod sigev_notify {
    /// Notify via signal
    pub const SIGEV_SIGNAL: i32 = 0;
    /// No notification
    pub const SIGEV_NONE: i32 = 1;
    /// Notify via thread (not supported)
    pub const SIGEV_THREAD: i32 = 2;
    /// Signal specific thread
    pub const SIGEV_THREAD_ID: i32 = 4;
}

/// union sigval - data passed with signal notification
#[repr(C)]
#[derive(Clone, Copy)]
pub union SigVal {
    pub sival_int: i32,
    pub sival_ptr: u64,
}

impl Default for SigVal {
    fn default() -> Self {
        Self { sival_int: 0 }
    }
}

/// struct sigevent - Linux ABI compatible
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SigEvent {
    /// Data passed with notification
    pub sigev_value: SigVal,
    /// Signal number
    pub sigev_signo: i32,
    /// Notification method (SIGEV_SIGNAL, SIGEV_NONE, etc.)
    pub sigev_notify: i32,
    /// Thread ID for SIGEV_THREAD_ID
    pub sigev_notify_thread_id: i32,
    /// Padding to match Linux layout (56 bytes total)
    pub _pad: [i32; 11],
}

impl Default for SigEvent {
    fn default() -> Self {
        Self {
            sigev_value: SigVal::default(),
            sigev_signo: SIGALRM as i32,
            sigev_notify: sigev_notify::SIGEV_SIGNAL,
            sigev_notify_thread_id: 0,
            _pad: [0; 11],
        }
    }
}

impl SigEvent {
    /// Create a new sigevent for signal notification
    pub const fn signal(signo: i32) -> Self {
        Self {
            sigev_value: SigVal { sival_int: 0 },
            sigev_signo: signo,
            sigev_notify: sigev_notify::SIGEV_SIGNAL,
            sigev_notify_thread_id: 0,
            _pad: [0; 11],
        }
    }

    /// Create a sigevent that disables notification
    pub const fn none() -> Self {
        Self {
            sigev_value: SigVal { sival_int: 0 },
            sigev_signo: 0,
            sigev_notify: sigev_notify::SIGEV_NONE,
            sigev_notify_thread_id: 0,
            _pad: [0; 11],
        }
    }
}

// ============================================================================
// POSIX message queue types and constants (Section 7.4)
// ============================================================================

/// Message queue attributes structure (matches Linux struct mq_attr)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MqAttr {
    /// Message queue flags (O_NONBLOCK)
    pub mq_flags: i64,
    /// Maximum number of messages in queue
    pub mq_maxmsg: i64,
    /// Maximum message size (bytes)
    pub mq_msgsize: i64,
    /// Current number of messages in queue (read-only)
    pub mq_curmsgs: i64,
    /// Reserved for future use
    pub __reserved: [i64; 4],
}

impl MqAttr {
    /// Create new mq_attr with specified limits
    pub const fn new(maxmsg: i64, msgsize: i64) -> Self {
        Self {
            mq_flags: 0,
            mq_maxmsg: maxmsg,
            mq_msgsize: msgsize,
            mq_curmsgs: 0,
            __reserved: [0; 4],
        }
    }

    /// Create with non-blocking flag
    pub const fn nonblocking(maxmsg: i64, msgsize: i64) -> Self {
        Self {
            mq_flags: O_NONBLOCK as i64,
            mq_maxmsg: maxmsg,
            mq_msgsize: msgsize,
            mq_curmsgs: 0,
            __reserved: [0; 4],
        }
    }
}

impl Default for MqAttr {
    fn default() -> Self {
        Self {
            mq_flags: 0,
            mq_maxmsg: 10,    // DFLT_MSGMAX
            mq_msgsize: 8192, // DFLT_MSGSIZEMAX
            mq_curmsgs: 0,
            __reserved: [0; 4],
        }
    }
}

/// Maximum message priority + 1
pub const MQ_PRIO_MAX: u32 = 32768;

/// Open flag for non-blocking queue operations
pub const O_NONBLOCK: u32 = 0o4000;

/// O_CLOEXEC flag for file descriptors
pub const O_CLOEXEC: u32 = 0o2000000;

/// O_EXCL flag for exclusive creation
pub const O_EXCL: u32 = 0o200;

// ============================================================================
// Futex waitv types and constants (Linux 5.16+)
// ============================================================================

/// Maximum number of futexes in a single futex_waitv call
pub const FUTEX_WAITV_MAX: u32 = 128;

/// FUTEX2 size flags - specifies the size of the futex word
pub const FUTEX2_SIZE_U8: u32 = 0x00;
pub const FUTEX2_SIZE_U16: u32 = 0x01;
pub const FUTEX2_SIZE_U32: u32 = 0x02;
pub const FUTEX2_SIZE_U64: u32 = 0x03;
pub const FUTEX2_SIZE_MASK: u32 = 0x03;

/// FUTEX2 NUMA flag (not currently supported)
pub const FUTEX2_NUMA: u32 = 0x04;

/// FUTEX2 private flag - futex is process-private (same as FUTEX_PRIVATE_FLAG)
pub const FUTEX2_PRIVATE: u32 = 128;

/// struct futex_waitv - A waiter for vectorized wait
///
/// Matches Linux ABI exactly (24 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FutexWaitv {
    /// Expected value at uaddr
    pub val: u64,
    /// User address to wait on
    pub uaddr: u64,
    /// Flags for this waiter (FUTEX2_SIZE_*, FUTEX2_PRIVATE)
    pub flags: u32,
    /// Reserved member - must be 0
    pub __reserved: u32,
}

impl FutexWaitv {
    /// Create a new futex_waitv entry
    pub const fn new(uaddr: u64, val: u64, flags: u32) -> Self {
        Self {
            val,
            uaddr,
            flags,
            __reserved: 0,
        }
    }

    /// Create a private 32-bit futex waiter
    pub const fn private32(uaddr: u64, val: u32) -> Self {
        Self {
            val: val as u64,
            uaddr,
            flags: FUTEX2_SIZE_U32 | FUTEX2_PRIVATE,
            __reserved: 0,
        }
    }
}

// ============================================================================
// Capabilities types and constants (Section 10.2)
// ============================================================================

/// User-space capability header (for capget/capset syscalls)
///
/// Matches Linux's `struct __user_cap_header_struct`
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CapUserHeader {
    pub version: u32,
    pub pid: i32,
}

/// User-space capability data (for capget/capset syscalls)
///
/// Matches Linux's `struct __user_cap_data_struct`
/// Note: For version 3, an array of 2 of these is used (low/high 32 bits)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CapUserData {
    pub effective: u32,
    pub permitted: u32,
    pub inheritable: u32,
}

/// Linux capability version 3 (current, supports 64 capabilities)
pub const _LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;

// Capability constants (CAP_* values for capability bitmask operations)
/// Override chown restrictions
pub const CAP_CHOWN: u32 = 0;
/// Override DAC access restrictions
pub const CAP_DAC_OVERRIDE: u32 = 1;
/// Override DAC read/search restrictions
pub const CAP_DAC_READ_SEARCH: u32 = 2;
/// Override file ownership checks
pub const CAP_FOWNER: u32 = 3;
/// Override setuid/setgid bits
pub const CAP_FSETID: u32 = 4;
/// Override signal sending restrictions
pub const CAP_KILL: u32 = 5;
/// Allow setgid manipulation
pub const CAP_SETGID: u32 = 6;
/// Allow setuid manipulation
pub const CAP_SETUID: u32 = 7;
/// Transfer/remove capabilities
pub const CAP_SETPCAP: u32 = 8;
/// Modify S_IMMUTABLE and S_APPEND attributes
pub const CAP_LINUX_IMMUTABLE: u32 = 9;
/// Bind to ports below 1024
pub const CAP_NET_BIND_SERVICE: u32 = 10;
/// Allow broadcasting/multicasting
pub const CAP_NET_BROADCAST: u32 = 11;
/// Allow network administration
pub const CAP_NET_ADMIN: u32 = 12;
/// Allow raw sockets
pub const CAP_NET_RAW: u32 = 13;
/// Lock memory (mlock, mlockall, etc.)
pub const CAP_IPC_LOCK: u32 = 14;
/// Override IPC ownership checks
pub const CAP_IPC_OWNER: u32 = 15;
/// Insert/remove kernel modules
pub const CAP_SYS_MODULE: u32 = 16;
/// Allow raw I/O access
pub const CAP_SYS_RAWIO: u32 = 17;
/// Use chroot()
pub const CAP_SYS_CHROOT: u32 = 18;
/// Allow ptrace of any process
pub const CAP_SYS_PTRACE: u32 = 19;
/// Configure process accounting
pub const CAP_SYS_PACCT: u32 = 20;
/// System administration capabilities
pub const CAP_SYS_ADMIN: u32 = 21;
/// Use reboot()
pub const CAP_SYS_BOOT: u32 = 22;
/// Raise process nice value, set real-time priorities
pub const CAP_SYS_NICE: u32 = 23;
/// Override resource limits
pub const CAP_SYS_RESOURCE: u32 = 24;
/// Manipulate system clock
pub const CAP_SYS_TIME: u32 = 25;
/// Configure TTY devices
pub const CAP_SYS_TTY_CONFIG: u32 = 26;
/// Privileged mknod operations
pub const CAP_MKNOD: u32 = 27;
/// Take file leases
pub const CAP_LEASE: u32 = 28;
/// Write to audit log
pub const CAP_AUDIT_WRITE: u32 = 29;
/// Configure audit
pub const CAP_AUDIT_CONTROL: u32 = 30;
/// Set file capabilities
pub const CAP_SETFCAP: u32 = 31;
/// Override MAC access
pub const CAP_MAC_OVERRIDE: u32 = 32;
/// Configure MAC
pub const CAP_MAC_ADMIN: u32 = 33;
/// Configure syslog
pub const CAP_SYSLOG: u32 = 34;
/// Trigger wake alarms
pub const CAP_WAKE_ALARM: u32 = 35;
/// Prevent system suspend
pub const CAP_BLOCK_SUSPEND: u32 = 36;
/// Read audit log
pub const CAP_AUDIT_READ: u32 = 37;
/// Performance monitoring
pub const CAP_PERFMON: u32 = 38;
/// BPF operations
pub const CAP_BPF: u32 = 39;
/// Checkpoint/restore operations
pub const CAP_CHECKPOINT_RESTORE: u32 = 40;
/// Last valid capability number
pub const CAP_LAST_CAP: u32 = 40;

// ============================================================================
// epoll types and constants
// ============================================================================

/// epoll_event structure (Linux ABI)
///
/// Note: This is packed to match Linux's x86-64 ABI where the structure
/// is 12 bytes (not 16). The data field is a union in Linux but we use u64.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct EpollEvent {
    /// Event mask (EPOLLIN, EPOLLOUT, etc.)
    pub events: u32,
    /// User data (passed back unchanged)
    pub data: u64,
}

impl EpollEvent {
    /// Create a new epoll_event
    pub const fn new(events: u32, data: u64) -> Self {
        Self { events, data }
    }

    /// Create an empty epoll_event
    pub const fn empty() -> Self {
        Self { events: 0, data: 0 }
    }
}

impl Default for EpollEvent {
    fn default() -> Self {
        Self::empty()
    }
}

// epoll_ctl operations
/// Add a file descriptor to the epoll interest list
pub const EPOLL_CTL_ADD: i32 = 1;
/// Remove a file descriptor from the epoll interest list
pub const EPOLL_CTL_DEL: i32 = 2;
/// Modify the event mask for an existing file descriptor
pub const EPOLL_CTL_MOD: i32 = 3;

// epoll event masks (input - what to monitor)
/// Data available for reading
pub const EPOLLIN: u32 = 0x001;
/// Urgent/priority data available
pub const EPOLLPRI: u32 = 0x002;
/// Ready for writing
pub const EPOLLOUT: u32 = 0x004;
/// Normal data readable (same as POLLIN for most cases)
pub const EPOLLRDNORM: u32 = 0x040;
/// Priority band data readable
pub const EPOLLRDBAND: u32 = 0x080;
/// Normal data writable
pub const EPOLLWRNORM: u32 = 0x100;
/// Priority band data writable
pub const EPOLLWRBAND: u32 = 0x200;
/// Message available
pub const EPOLLMSG: u32 = 0x400;
/// Remote peer closed connection or shut down writing half
pub const EPOLLRDHUP: u32 = 0x2000;

// epoll event masks (output only - always reported)
/// Error condition
pub const EPOLLERR: u32 = 0x008;
/// Hang up / EOF
pub const EPOLLHUP: u32 = 0x010;

// epoll behavior modifiers
/// Edge-triggered mode (only notify once per state change)
pub const EPOLLET: u32 = 1 << 31;
/// One-shot mode (disable after first event, require EPOLL_CTL_MOD to re-arm)
pub const EPOLLONESHOT: u32 = 1 << 30;
/// Wake up system even during suspend
pub const EPOLLWAKEUP: u32 = 1 << 29;
/// Exclusive wakeup (for load balancing with multiple epoll waiters)
pub const EPOLLEXCLUSIVE: u32 = 1 << 28;

// epoll_create1 flags
/// Set close-on-exec flag on the new file descriptor
pub const EPOLL_CLOEXEC: i32 = 0o2000000;

// ============================================================================
// Inotify constants
// ============================================================================

// inotify_init1 flags
/// Set close-on-exec flag on the new file descriptor
pub const IN_CLOEXEC: i32 = 0o2000000;
/// Set non-blocking flag on the new file descriptor
pub const IN_NONBLOCK: i32 = 0o4000;

// inotify event mask bits (watch events)
/// File was accessed
pub const IN_ACCESS: u32 = 0x00000001;
/// File was modified
pub const IN_MODIFY: u32 = 0x00000002;
/// Metadata changed
pub const IN_ATTRIB: u32 = 0x00000004;
/// Writable file was closed
pub const IN_CLOSE_WRITE: u32 = 0x00000008;
/// Unwritable file closed
pub const IN_CLOSE_NOWRITE: u32 = 0x00000010;
/// File was opened
pub const IN_OPEN: u32 = 0x00000020;
/// File was moved from X
pub const IN_MOVED_FROM: u32 = 0x00000040;
/// File was moved to Y
pub const IN_MOVED_TO: u32 = 0x00000080;
/// Subfile was created
pub const IN_CREATE: u32 = 0x00000100;
/// Subfile was deleted
pub const IN_DELETE: u32 = 0x00000200;
/// Self was deleted
pub const IN_DELETE_SELF: u32 = 0x00000400;
/// Self was moved
pub const IN_MOVE_SELF: u32 = 0x00000800;

// Helper masks
/// Close (both write and nowrite)
pub const IN_CLOSE: u32 = IN_CLOSE_WRITE | IN_CLOSE_NOWRITE;
/// Move (both from and to)
pub const IN_MOVE: u32 = IN_MOVED_FROM | IN_MOVED_TO;
/// All events user can watch for
pub const IN_ALL_EVENTS: u32 = IN_ACCESS | IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE
    | IN_CLOSE_NOWRITE | IN_OPEN | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE
    | IN_CREATE | IN_DELETE_SELF | IN_MOVE_SELF;

// Events sent by the kernel
/// Backing fs was unmounted
pub const IN_UNMOUNT: u32 = 0x00002000;
/// Event queue overflowed
pub const IN_Q_OVERFLOW: u32 = 0x00004000;
/// File was ignored (watch removed)
pub const IN_IGNORED: u32 = 0x00008000;

// inotify_add_watch flags
/// Only watch if path is directory
pub const IN_ONLYDIR: u32 = 0x01000000;
/// Don't follow symlink
pub const IN_DONT_FOLLOW: u32 = 0x02000000;
/// Exclude events on unlinked objects
pub const IN_EXCL_UNLINK: u32 = 0x04000000;
/// Only create watches (error if exists)
pub const IN_MASK_CREATE: u32 = 0x10000000;
/// Add to mask of existing watch
pub const IN_MASK_ADD: u32 = 0x20000000;
/// Event occurred against directory
pub const IN_ISDIR: u32 = 0x40000000;
/// Only send event once
pub const IN_ONESHOT: u32 = 0x80000000;

/// Inotify event header structure (Linux ABI)
///
/// The event header is followed by `len` bytes of null-terminated filename
/// (if len > 0). The filename is padded to a multiple of the struct size.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct InotifyEvent {
    /// Watch descriptor
    pub wd: i32,
    /// Watch mask / event type
    pub mask: u32,
    /// Cookie for rename synchronization
    pub cookie: u32,
    /// Length of name (including nulls)
    pub len: u32,
    // Followed by name bytes
}

// ============================================================================
// clone3 syscall types
// ============================================================================

/// clone_args structure for clone3 syscall (matches Linux struct clone_args)
///
/// The structure is versioned by size, allowing future extensions.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CloneArgs {
    /// Clone flags (CLONE_* constants)
    pub flags: u64,
    /// File descriptor for pidfd (CLONE_PIDFD)
    pub pidfd: u64,
    /// Address to store child TID in child's memory (CLONE_CHILD_SETTID)
    pub child_tid: u64,
    /// Address to store child TID in parent's memory (CLONE_PARENT_SETTID)
    pub parent_tid: u64,
    /// Exit signal for child
    pub exit_signal: u64,
    /// Lowest address of the stack
    pub stack: u64,
    /// Size of the stack in bytes
    pub stack_size: u64,
    /// TLS pointer for child (CLONE_SETTLS)
    pub tls: u64,
    /// Array of PIDs for set_tid feature (not implemented)
    pub set_tid: u64,
    /// Size of set_tid array
    pub set_tid_size: u64,
    /// Cgroup file descriptor (not implemented)
    pub cgroup: u64,
}

/// Size of clone_args version 0 (flags through tls)
pub const CLONE_ARGS_SIZE_VER0: usize = 64;

// Common personality values
/// Default Linux personality
pub const PER_LINUX: u32 = 0;
/// Query personality without changing it
pub const PERSONALITY_QUERY: u32 = 0xFFFFFFFF;

// ============================================================================
// adjtimex types and constants
// ============================================================================

/// Timeval for timex structure
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TimexTimeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

/// Linux __kernel_timex structure for adjtimex syscall
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Timex {
    /// Mode selector (ADJ_* flags)
    pub modes: u32,
    _pad1: i32,
    /// Time offset (usec or nsec depending on ADJ_NANO)
    pub offset: i64,
    /// Frequency offset (scaled PPM)
    pub freq: i64,
    /// Maximum error (usec)
    pub maxerror: i64,
    /// Estimated error (usec)
    pub esterror: i64,
    /// Clock status (STA_* flags)
    pub status: i32,
    _pad2: i32,
    /// PLL time constant
    pub constant: i64,
    /// Clock precision (usec, read-only)
    pub precision: i64,
    /// Clock frequency tolerance (ppm, read-only)
    pub tolerance: i64,
    /// Current time (read-only except for ADJ_SETOFFSET)
    pub time: TimexTimeval,
    /// Usec between clock ticks
    pub tick: i64,
    /// PPS frequency (scaled ppm, read-only)
    pub ppsfreq: i64,
    /// PPS jitter (usec, read-only)
    pub jitter: i64,
    /// Interval duration shift (read-only)
    pub shift: i32,
    _pad3: i32,
    /// PPS stability (scaled ppm, read-only)
    pub stabil: i64,
    /// Jitter limit exceeded (read-only)
    pub jitcnt: i64,
    /// Calibration intervals (read-only)
    pub calcnt: i64,
    /// Calibration errors (read-only)
    pub errcnt: i64,
    /// Stability limit exceeded (read-only)
    pub stbcnt: i64,
    /// TAI offset (read-only)
    pub tai: i32,
    /// Padding for 11 more i32 fields
    _reserved: [i32; 11],
}

impl Default for Timex {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

/// ADJ_* mode flags for adjtimex
pub const ADJ_OFFSET: u32 = 0x0001;
pub const ADJ_FREQUENCY: u32 = 0x0002;
pub const ADJ_MAXERROR: u32 = 0x0004;
pub const ADJ_ESTERROR: u32 = 0x0008;
pub const ADJ_STATUS: u32 = 0x0010;
pub const ADJ_TIMECONST: u32 = 0x0020;
pub const ADJ_TAI: u32 = 0x0080;
pub const ADJ_SETOFFSET: u32 = 0x0100;
pub const ADJ_MICRO: u32 = 0x1000;
pub const ADJ_NANO: u32 = 0x2000;
pub const ADJ_TICK: u32 = 0x4000;

/// STA_* status flags
pub const STA_PLL: i32 = 0x0001;
pub const STA_PPSFREQ: i32 = 0x0002;
pub const STA_PPSTIME: i32 = 0x0004;
pub const STA_FLL: i32 = 0x0008;
pub const STA_INS: i32 = 0x0010;
pub const STA_DEL: i32 = 0x0020;
pub const STA_UNSYNC: i32 = 0x0040;
pub const STA_FREQHOLD: i32 = 0x0080;
pub const STA_NANO: i32 = 0x2000;

/// Time state return values
pub const TIME_OK: i32 = 0;
pub const TIME_INS: i32 = 1;
pub const TIME_DEL: i32 = 2;
pub const TIME_OOP: i32 = 3;
pub const TIME_WAIT: i32 = 4;
pub const TIME_ERROR: i32 = 5;

// ============================================================================
// io_uring structures and constants
// ============================================================================

/// mmap offsets for io_uring ring buffers
pub const IORING_OFF_SQ_RING: u64 = 0;
pub const IORING_OFF_CQ_RING: u64 = 0x8000000;
pub const IORING_OFF_SQES: u64 = 0x10000000;

/// io_uring_setup flags
pub const IORING_SETUP_IOPOLL: u32 = 1 << 0;
pub const IORING_SETUP_SQPOLL: u32 = 1 << 1;
pub const IORING_SETUP_SQ_AFF: u32 = 1 << 2;
pub const IORING_SETUP_CQSIZE: u32 = 1 << 3;
pub const IORING_SETUP_CLAMP: u32 = 1 << 4;
pub const IORING_SETUP_ATTACH_WQ: u32 = 1 << 5;
pub const IORING_SETUP_R_DISABLED: u32 = 1 << 6;

/// io_uring_enter flags
pub const IORING_ENTER_GETEVENTS: u32 = 1 << 0;
pub const IORING_ENTER_SQ_WAKEUP: u32 = 1 << 1;
pub const IORING_ENTER_SQ_WAIT: u32 = 1 << 2;
pub const IORING_ENTER_EXT_ARG: u32 = 1 << 3;

/// SQE flags
pub const IOSQE_FIXED_FILE: u8 = 1 << 0;
pub const IOSQE_IO_DRAIN: u8 = 1 << 1;
pub const IOSQE_IO_LINK: u8 = 1 << 2;
pub const IOSQE_IO_HARDLINK: u8 = 1 << 3;
pub const IOSQE_ASYNC: u8 = 1 << 4;
pub const IOSQE_BUFFER_SELECT: u8 = 1 << 5;
pub const IOSQE_CQE_SKIP_SUCCESS: u8 = 1 << 6;

/// CQE flags
pub const IORING_CQE_F_BUFFER: u32 = 1 << 0;
pub const IORING_CQE_F_MORE: u32 = 1 << 1;

/// SQ ring flags
pub const IORING_SQ_NEED_WAKEUP: u32 = 1 << 0;
pub const IORING_SQ_CQ_OVERFLOW: u32 = 1 << 1;

/// io_uring operation codes
pub const IORING_OP_NOP: u8 = 0;
pub const IORING_OP_READV: u8 = 1;
pub const IORING_OP_WRITEV: u8 = 2;
pub const IORING_OP_FSYNC: u8 = 3;
pub const IORING_OP_READ_FIXED: u8 = 4;
pub const IORING_OP_WRITE_FIXED: u8 = 5;
pub const IORING_OP_POLL_ADD: u8 = 6;
pub const IORING_OP_POLL_REMOVE: u8 = 7;
pub const IORING_OP_SYNC_FILE_RANGE: u8 = 8;
pub const IORING_OP_SENDMSG: u8 = 9;
pub const IORING_OP_RECVMSG: u8 = 10;
pub const IORING_OP_TIMEOUT: u8 = 11;
pub const IORING_OP_TIMEOUT_REMOVE: u8 = 12;
pub const IORING_OP_ACCEPT: u8 = 13;
pub const IORING_OP_ASYNC_CANCEL: u8 = 14;
pub const IORING_OP_LINK_TIMEOUT: u8 = 15;
pub const IORING_OP_CONNECT: u8 = 16;
pub const IORING_OP_FALLOCATE: u8 = 17;
pub const IORING_OP_OPENAT: u8 = 18;
pub const IORING_OP_CLOSE: u8 = 19;
pub const IORING_OP_FILES_UPDATE: u8 = 20;
pub const IORING_OP_STATX: u8 = 21;
pub const IORING_OP_READ: u8 = 22;
pub const IORING_OP_WRITE: u8 = 23;
pub const IORING_OP_SEND: u8 = 26;
pub const IORING_OP_RECV: u8 = 27;
pub const IORING_OP_OPENAT2: u8 = 28;
pub const IORING_OP_SHUTDOWN: u8 = 34;

/// io_uring_register opcodes
pub const IORING_REGISTER_BUFFERS: u32 = 0;
pub const IORING_UNREGISTER_BUFFERS: u32 = 1;
pub const IORING_REGISTER_FILES: u32 = 2;
pub const IORING_UNREGISTER_FILES: u32 = 3;
pub const IORING_REGISTER_FILES_UPDATE: u32 = 6;

/// Feature flags (returned in params.features)
pub const IORING_FEAT_SINGLE_MMAP: u32 = 1 << 0;
pub const IORING_FEAT_NODROP: u32 = 1 << 1;
pub const IORING_FEAT_SUBMIT_STABLE: u32 = 1 << 2;
pub const IORING_FEAT_RW_CUR_POS: u32 = 1 << 3;
pub const IORING_FEAT_CUR_PERSONALITY: u32 = 1 << 4;
pub const IORING_FEAT_FAST_POLL: u32 = 1 << 5;
pub const IORING_FEAT_POLL_32BITS: u32 = 1 << 6;

/// SQ ring offsets
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SqRingOffsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub flags: u32,
    pub dropped: u32,
    pub array: u32,
    pub resv1: u32,
    pub user_addr: u64,
}

/// CQ ring offsets
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CqRingOffsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub overflow: u32,
    pub cqes: u32,
    pub flags: u32,
    pub resv1: u32,
    pub user_addr: u64,
}

/// io_uring_params - passed to io_uring_setup (248 bytes)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IoUringParams {
    pub sq_entries: u32,
    pub cq_entries: u32,
    pub flags: u32,
    pub sq_thread_cpu: u32,
    pub sq_thread_idle: u32,
    pub features: u32,
    pub wq_fd: u32,
    pub resv: [u32; 3],
    pub sq_off: SqRingOffsets,
    pub cq_off: CqRingOffsets,
}

impl Default for IoUringParams {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

/// io_uring submission queue entry (64 bytes)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct IoUringSqe {
    pub opcode: u8,
    pub flags: u8,
    pub ioprio: u16,
    pub fd: i32,
    pub off: u64,
    pub addr: u64,
    pub len: u32,
    pub op_flags: u32,
    pub user_data: u64,
    pub buf_index: u16,
    pub personality: u16,
    pub splice_fd_in: i32,
    pub __pad2: [u64; 2],
}

/// io_uring completion queue entry (16 bytes)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct IoUringCqe {
    pub user_data: u64,
    pub res: i32,
    pub flags: u32,
}

// ============================================================================
// Keyring types and constants
// ============================================================================

// Special keyring IDs (KEY_SPEC_*)
/// Thread-specific keyring
pub const KEY_SPEC_THREAD_KEYRING: i32 = -1;
/// Process-specific keyring
pub const KEY_SPEC_PROCESS_KEYRING: i32 = -2;
/// Session keyring
pub const KEY_SPEC_SESSION_KEYRING: i32 = -3;
/// User-specific keyring
pub const KEY_SPEC_USER_KEYRING: i32 = -4;
/// User default session keyring
pub const KEY_SPEC_USER_SESSION_KEYRING: i32 = -5;
/// Group-specific keyring
pub const KEY_SPEC_GROUP_KEYRING: i32 = -6;
/// Requestor's thread keyring
pub const KEY_SPEC_REQKEY_AUTH_KEY: i32 = -7;

// Keyctl commands (KEYCTL_*)
/// Get keyring ID
pub const KEYCTL_GET_KEYRING_ID: i32 = 0;
/// Join session keyring
pub const KEYCTL_JOIN_SESSION_KEYRING: i32 = 1;
/// Update key payload
pub const KEYCTL_UPDATE: i32 = 2;
/// Revoke key
pub const KEYCTL_REVOKE: i32 = 3;
/// Change key ownership
pub const KEYCTL_CHOWN: i32 = 4;
/// Set key permissions
pub const KEYCTL_SETPERM: i32 = 5;
/// Describe key
pub const KEYCTL_DESCRIBE: i32 = 6;
/// Clear keyring contents
pub const KEYCTL_CLEAR: i32 = 7;
/// Link key to keyring
pub const KEYCTL_LINK: i32 = 8;
/// Unlink key from keyring
pub const KEYCTL_UNLINK: i32 = 9;
/// Search keyring tree
pub const KEYCTL_SEARCH: i32 = 10;
/// Read key payload
pub const KEYCTL_READ: i32 = 11;
/// Instantiate key
pub const KEYCTL_INSTANTIATE: i32 = 12;
/// Negate key
pub const KEYCTL_NEGATE: i32 = 13;
/// Set key timeout
pub const KEYCTL_SET_TIMEOUT: i32 = 14;
/// Assume request_key authority
pub const KEYCTL_ASSUME_AUTHORITY: i32 = 15;
/// Get key security label
pub const KEYCTL_GET_SECURITY: i32 = 17;
/// Start session management
pub const KEYCTL_SESSION_TO_PARENT: i32 = 18;
/// Reject key
pub const KEYCTL_REJECT: i32 = 19;
/// Instantiate key with iovec
pub const KEYCTL_INSTANTIATE_IOV: i32 = 20;
/// Invalidate key
pub const KEYCTL_INVALIDATE: i32 = 21;
/// Get persistent keyring
pub const KEYCTL_GET_PERSISTENT: i32 = 22;

// Key permission bits
/// Possessor can view key attributes
pub const KEY_POS_VIEW: u32 = 0x01000000;
/// Possessor can read key payload
pub const KEY_POS_READ: u32 = 0x02000000;
/// Possessor can update key
pub const KEY_POS_WRITE: u32 = 0x04000000;
/// Possessor can search keyring
pub const KEY_POS_SEARCH: u32 = 0x08000000;
/// Possessor can link key
pub const KEY_POS_LINK: u32 = 0x10000000;
/// Possessor can set key attributes
pub const KEY_POS_SETATTR: u32 = 0x20000000;
/// All possessor permissions
pub const KEY_POS_ALL: u32 = 0x3f000000;

/// User can view key attributes
pub const KEY_USR_VIEW: u32 = 0x00010000;
/// User can read key payload
pub const KEY_USR_READ: u32 = 0x00020000;
/// User can update key
pub const KEY_USR_WRITE: u32 = 0x00040000;
/// User can search keyring
pub const KEY_USR_SEARCH: u32 = 0x00080000;
/// User can link key
pub const KEY_USR_LINK: u32 = 0x00100000;
/// User can set key attributes
pub const KEY_USR_SETATTR: u32 = 0x00200000;
/// All user permissions
pub const KEY_USR_ALL: u32 = 0x003f0000;

/// Group can view key attributes
pub const KEY_GRP_VIEW: u32 = 0x00000100;
/// Group can read key payload
pub const KEY_GRP_READ: u32 = 0x00000200;
/// Group can update key
pub const KEY_GRP_WRITE: u32 = 0x00000400;
/// Group can search keyring
pub const KEY_GRP_SEARCH: u32 = 0x00000800;
/// Group can link key
pub const KEY_GRP_LINK: u32 = 0x00001000;
/// Group can set key attributes
pub const KEY_GRP_SETATTR: u32 = 0x00002000;
/// All group permissions
pub const KEY_GRP_ALL: u32 = 0x00003f00;

/// Others can view key attributes
pub const KEY_OTH_VIEW: u32 = 0x00000001;
/// Others can read key payload
pub const KEY_OTH_READ: u32 = 0x00000002;
/// Others can update key
pub const KEY_OTH_WRITE: u32 = 0x00000004;
/// Others can search keyring
pub const KEY_OTH_SEARCH: u32 = 0x00000008;
/// Others can link key
pub const KEY_OTH_LINK: u32 = 0x00000010;
/// Others can set key attributes
pub const KEY_OTH_SETATTR: u32 = 0x00000020;
/// All other permissions
pub const KEY_OTH_ALL: u32 = 0x0000003f;

// ============================================================================
// kcmp comparison types
// ============================================================================

/// Compare file descriptors
pub const KCMP_FILE: i32 = 0;
/// Compare memory address spaces (mm_struct)
pub const KCMP_VM: i32 = 1;
/// Compare file descriptor tables
pub const KCMP_FILES: i32 = 2;
/// Compare filesystem context (cwd, root)
pub const KCMP_FS: i32 = 3;
/// Compare signal handlers
pub const KCMP_SIGHAND: i32 = 4;
/// Compare I/O context
pub const KCMP_IO: i32 = 5;
/// Compare SysV semaphore undo lists
pub const KCMP_SYSVSEM: i32 = 6;
/// Compare epoll target fds (not supported)
pub const KCMP_EPOLL_TFD: i32 = 7;
/// Number of comparison types
pub const KCMP_TYPES: i32 = 8;

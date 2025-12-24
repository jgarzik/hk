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

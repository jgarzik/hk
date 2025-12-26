//! aarch64 Linux syscall wrappers
//!
//! This module provides syscall wrappers for the aarch64 (ARM64) architecture.
//!
//! # Calling Convention
//! - Syscall number in X8
//! - Arguments in X0-X5
//! - Return value in X0
//!
//! # Key Differences from x86_64
//! - Different syscall numbers (ARM64 uses newer Linux ABI)
//! - Some legacy syscalls removed:
//!   - No `open` - use `openat` with AT_FDCWD
//!   - No `fork` - use `clone`
//!   - No `dup2` - use `dup3`
//!   - No `mkdir`, `rmdir`, `unlink`, `symlink`, `readlink`, `link` - use *at variants
//!   - No `stat`, `lstat` - use fstatat
//!   - No `rename` - use renameat
//!   - No `chmod`, `chown`, `lchown` - use *at variants
//!   - No `truncate` - use ftruncate with openat

use crate::types::{CloneArgs, EpollEvent, FdSet, IoVec, MqAttr, PollFd, RLimit, SigEvent, SigInfo, Stat, Timespec, Timeval, Timex, UtsName, AT_FDCWD};

// ============================================================================
// Syscall macros for aarch64
// ============================================================================

/// Raw syscall with 0 arguments
macro_rules! syscall0 {
    ($nr:expr) => {{
        let ret: i64;
        core::arch::asm!(
            "svc #0",
            in("x8") $nr,
            lateout("x0") ret,
            options(nostack),
        );
        ret
    }};
}

/// Raw syscall with 1 argument
macro_rules! syscall1 {
    ($nr:expr, $a0:expr) => {{
        let ret: i64;
        core::arch::asm!(
            "svc #0",
            in("x8") $nr,
            in("x0") $a0 as u64,
            lateout("x0") ret,
            options(nostack),
        );
        ret
    }};
}

/// Raw syscall with 2 arguments
macro_rules! syscall2 {
    ($nr:expr, $a0:expr, $a1:expr) => {{
        let ret: i64;
        core::arch::asm!(
            "svc #0",
            in("x8") $nr,
            in("x0") $a0 as u64,
            in("x1") $a1 as u64,
            lateout("x0") ret,
            options(nostack),
        );
        ret
    }};
}

/// Raw syscall with 3 arguments
macro_rules! syscall3 {
    ($nr:expr, $a0:expr, $a1:expr, $a2:expr) => {{
        let ret: i64;
        core::arch::asm!(
            "svc #0",
            in("x8") $nr,
            in("x0") $a0 as u64,
            in("x1") $a1 as u64,
            in("x2") $a2 as u64,
            lateout("x0") ret,
            options(nostack),
        );
        ret
    }};
}

/// Raw syscall with 4 arguments
macro_rules! syscall4 {
    ($nr:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr) => {{
        let ret: i64;
        core::arch::asm!(
            "svc #0",
            in("x8") $nr,
            in("x0") $a0 as u64,
            in("x1") $a1 as u64,
            in("x2") $a2 as u64,
            in("x3") $a3 as u64,
            lateout("x0") ret,
            options(nostack),
        );
        ret
    }};
}

/// Raw syscall with 5 arguments
macro_rules! syscall5 {
    ($nr:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr) => {{
        let ret: i64;
        core::arch::asm!(
            "svc #0",
            in("x8") $nr,
            in("x0") $a0 as u64,
            in("x1") $a1 as u64,
            in("x2") $a2 as u64,
            in("x3") $a3 as u64,
            in("x4") $a4 as u64,
            lateout("x0") ret,
            options(nostack),
        );
        ret
    }};
}

/// Raw syscall with 6 arguments
macro_rules! syscall6 {
    ($nr:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr) => {{
        let ret: i64;
        core::arch::asm!(
            "svc #0",
            in("x8") $nr,
            in("x0") $a0 as u64,
            in("x1") $a1 as u64,
            in("x2") $a2 as u64,
            in("x3") $a3 as u64,
            in("x4") $a4 as u64,
            in("x5") $a5 as u64,
            lateout("x0") ret,
            options(nostack),
        );
        ret
    }};
}

// ============================================================================
// aarch64 Linux syscall numbers (different from x86_64!)
// ============================================================================

pub const SYS_DUP3: u64 = 24;
pub const SYS_MKDIRAT: u64 = 34;
pub const SYS_UNLINKAT: u64 = 35;
pub const SYS_SYMLINKAT: u64 = 36;
pub const SYS_LINKAT: u64 = 37;
pub const SYS_RENAMEAT: u64 = 38;
pub const SYS_FTRUNCATE: u64 = 46;
pub const SYS_FCHMODAT: u64 = 53;
pub const SYS_FCHOWNAT: u64 = 54;
pub const SYS_OPENAT: u64 = 56;
pub const SYS_CLOSE: u64 = 57;
pub const SYS_GETDENTS64: u64 = 61;
pub const SYS_LSEEK: u64 = 62;
pub const SYS_READ: u64 = 63;
pub const SYS_WRITE: u64 = 64;
pub const SYS_READV: u64 = 65;
pub const SYS_WRITEV: u64 = 66;
pub const SYS_PREAD64: u64 = 67;
pub const SYS_PWRITE64: u64 = 68;
pub const SYS_PREADV: u64 = 69;
pub const SYS_PWRITEV: u64 = 70;
pub const SYS_PREADV2: u64 = 286;
pub const SYS_PWRITEV2: u64 = 287;
pub const SYS_READLINKAT: u64 = 78;
pub const SYS_FSTATAT: u64 = 79;
pub const SYS_FCHMOD: u64 = 52;
pub const SYS_FCHOWN: u64 = 55;
pub const SYS_EXIT: u64 = 93;
pub const SYS_EXIT_GROUP: u64 = 94;
pub const SYS_NANOSLEEP: u64 = 101;
pub const SYS_CLOCK_SETTIME: u64 = 112;
pub const SYS_CLOCK_GETTIME: u64 = 113;
pub const SYS_CLOCK_GETRES: u64 = 114;
pub const SYS_CLOCK_NANOSLEEP: u64 = 115;
pub const SYS_TIMERFD_CREATE: u64 = 85;
pub const SYS_TIMERFD_SETTIME: u64 = 86;
pub const SYS_TIMERFD_GETTIME: u64 = 87;
pub const SYS_ADJTIMEX: u64 = 171;
pub const SYS_CAPGET: u64 = 90;
pub const SYS_CAPSET: u64 = 91;

// eventfd syscalls (Section 7.1)
// NOTE: aarch64 only has eventfd2, not the legacy eventfd
pub const SYS_EVENTFD2: u64 = 19;

// signalfd syscalls (Section 5)
// NOTE: aarch64 only has signalfd4, not the legacy signalfd
pub const SYS_SIGNALFD4: u64 = 74;

// epoll syscalls (Section 9.1) - NOTE: aarch64 only has epoll_create1, not legacy epoll_create
pub const SYS_EPOLL_CREATE1: u64 = 20;
pub const SYS_EPOLL_CTL: u64 = 21;
pub const SYS_EPOLL_PWAIT: u64 = 22;
pub const SYS_EPOLL_PWAIT2: u64 = 441;

// POSIX timer syscalls (Section 6.2)
pub const SYS_TIMER_CREATE: u64 = 107;
pub const SYS_TIMER_GETTIME: u64 = 108;
pub const SYS_TIMER_GETOVERRUN: u64 = 109;
pub const SYS_TIMER_SETTIME: u64 = 110;
pub const SYS_TIMER_DELETE: u64 = 111;

// POSIX message queue syscalls (Section 7.4)
pub const SYS_MQ_OPEN: u64 = 180;
pub const SYS_MQ_UNLINK: u64 = 181;
pub const SYS_MQ_TIMEDSEND: u64 = 182;
pub const SYS_MQ_TIMEDRECEIVE: u64 = 183;
pub const SYS_MQ_NOTIFY: u64 = 184;
pub const SYS_MQ_GETSETATTR: u64 = 185;

pub const SYS_REBOOT: u64 = 142;
pub const SYS_SETPGID: u64 = 154;
pub const SYS_GETPGID: u64 = 155;
pub const SYS_GETSID: u64 = 156;
pub const SYS_SETSID: u64 = 157;
pub const SYS_UMASK: u64 = 166;
pub const SYS_GETCPU: u64 = 168;
// Scheduling priority (aarch64 numbers - note: swapped from x86_64)
pub const SYS_SETPRIORITY: u64 = 140;
pub const SYS_GETPRIORITY: u64 = 141;
pub const SYS_SETREGID: u64 = 143;
pub const SYS_SETGID: u64 = 144;
pub const SYS_SETREUID: u64 = 145;
pub const SYS_SETUID: u64 = 146;
pub const SYS_SETRESUID: u64 = 147;
pub const SYS_GETRESUID: u64 = 148;
pub const SYS_SETRESGID: u64 = 149;
pub const SYS_GETRESGID: u64 = 150;
pub const SYS_SETFSUID: u64 = 151;
pub const SYS_SETFSGID: u64 = 152;
pub const SYS_GETPID: u64 = 172;
pub const SYS_GETPPID: u64 = 173;
pub const SYS_GETUID: u64 = 174;
pub const SYS_GETEUID: u64 = 175;
pub const SYS_GETGID: u64 = 176;
pub const SYS_GETEGID: u64 = 177;
pub const SYS_GETTID: u64 = 178;
pub const SYS_CLONE: u64 = 220;
pub const SYS_EXECVE: u64 = 221;
pub const SYS_WAIT4: u64 = 260;
pub const SYS_WAITID: u64 = 95;
pub const SYS_UTIMENSAT: u64 = 88;
pub const SYS_MKNODAT: u64 = 33;
pub const SYS_MOUNT: u64 = 40;
pub const SYS_UMOUNT2: u64 = 39;
pub const SYS_PIVOT_ROOT: u64 = 41;
pub const SYS_SWAPON: u64 = 224;
pub const SYS_SWAPOFF: u64 = 225;
pub const SYS_SYNC: u64 = 81;
pub const SYS_FSYNC: u64 = 82;
pub const SYS_FDATASYNC: u64 = 83;
pub const SYS_SYNCFS: u64 = 267;

// UTS namespace syscalls
pub const SYS_UNAME: u64 = 160;
pub const SYS_SETHOSTNAME: u64 = 161;
pub const SYS_SETDOMAINNAME: u64 = 162;

// Namespace syscalls
pub const SYS_UNSHARE: u64 = 97;
pub const SYS_SETNS: u64 = 268;

// Signal syscalls (aarch64 numbers)
pub const SYS_KILL: u64 = 129;
pub const SYS_TKILL: u64 = 130;
pub const SYS_TGKILL: u64 = 131;
pub const SYS_SIGALTSTACK: u64 = 132;
pub const SYS_RT_SIGACTION: u64 = 134;
pub const SYS_RT_SIGPROCMASK: u64 = 135;
pub const SYS_RT_SIGPENDING: u64 = 136;
pub const SYS_RT_SIGTIMEDWAIT: u64 = 137;
pub const SYS_RT_SIGQUEUEINFO: u64 = 128;
pub const SYS_RT_SIGSUSPEND: u64 = 133;
pub const SYS_RT_TGSIGQUEUEINFO: u64 = 240;

// Memory barrier syscall
pub const SYS_MEMBARRIER: u64 = 283;

// File readahead syscall
pub const SYS_READAHEAD: u64 = 213;

// Pipe/poll/select syscalls (aarch64 numbers)
pub const SYS_PIPE2: u64 = 59;
pub const SYS_PPOLL: u64 = 73;
pub const SYS_PSELECT6: u64 = 72;

// Memory management syscalls
pub const SYS_BRK: u64 = 214;
pub const SYS_MUNMAP: u64 = 215;
pub const SYS_MMAP: u64 = 222;
pub const SYS_MPROTECT: u64 = 226;
pub const SYS_MLOCK: u64 = 228;
pub const SYS_MUNLOCK: u64 = 229;
pub const SYS_MLOCKALL: u64 = 230;
pub const SYS_MUNLOCKALL: u64 = 231;
pub const SYS_MLOCK2: u64 = 284;
pub const SYS_MSYNC: u64 = 227;
pub const SYS_MINCORE: u64 = 232;
pub const SYS_MADVISE: u64 = 233;
pub const SYS_MREMAP: u64 = 216;

// System information syscalls
pub const SYS_GETRUSAGE: u64 = 165;
pub const SYS_SYSINFO: u64 = 179;
pub const SYS_GETRANDOM: u64 = 278;

// File control
pub const SYS_FCNTL: u64 = 25;
pub const SYS_IOCTL: u64 = 29;

// I/O priority syscalls
pub const SYS_IOPRIO_SET: u64 = 30;
pub const SYS_IOPRIO_GET: u64 = 31;

// Scheduling syscalls (aarch64 numbers)
pub const SYS_SCHED_SETPARAM: u64 = 118;
pub const SYS_SCHED_SETSCHEDULER: u64 = 119;
pub const SYS_SCHED_GETSCHEDULER: u64 = 120;
pub const SYS_SCHED_GETPARAM: u64 = 121;
pub const SYS_SCHED_SETAFFINITY: u64 = 122;
pub const SYS_SCHED_GETAFFINITY: u64 = 123;
pub const SYS_SCHED_RR_GET_INTERVAL: u64 = 127;

// Resource limits syscalls
pub const SYS_GETRLIMIT: u64 = 163;
pub const SYS_SETRLIMIT: u64 = 164;
pub const SYS_PRLIMIT64: u64 = 261;

// Socket syscalls
pub const SYS_SOCKET: u64 = 198;
pub const SYS_SOCKETPAIR: u64 = 199;
pub const SYS_BIND: u64 = 200;
pub const SYS_LISTEN: u64 = 201;
pub const SYS_ACCEPT: u64 = 202;
pub const SYS_CONNECT: u64 = 203;
pub const SYS_GETSOCKNAME: u64 = 204;
pub const SYS_GETPEERNAME: u64 = 205;
pub const SYS_SENDTO: u64 = 206;
pub const SYS_RECVFROM: u64 = 207;
pub const SYS_SETSOCKOPT: u64 = 208;
pub const SYS_GETSOCKOPT: u64 = 209;
pub const SYS_SHUTDOWN: u64 = 210;
pub const SYS_SENDMSG: u64 = 211;
pub const SYS_RECVMSG: u64 = 212;
pub const SYS_RECVMMSG: u64 = 243;
pub const SYS_SENDMMSG: u64 = 269;

// SysV IPC syscalls (shared memory, semaphores, message queues)
pub const SYS_SHMGET: u64 = 194;
pub const SYS_SHMAT: u64 = 196;
pub const SYS_SHMCTL: u64 = 195;
pub const SYS_SHMDT: u64 = 197;
pub const SYS_SEMGET: u64 = 190;
pub const SYS_SEMOP: u64 = 193;
pub const SYS_SEMCTL: u64 = 191;
pub const SYS_SEMTIMEDOP: u64 = 192;
pub const SYS_MSGGET: u64 = 186;
pub const SYS_MSGSND: u64 = 189;
pub const SYS_MSGRCV: u64 = 188;
pub const SYS_MSGCTL: u64 = 187;

// TLS syscalls
pub const SYS_SET_TID_ADDRESS: u64 = 96;

// New syscall numbers
pub const SYS_CLONE3: u64 = 435;
pub const SYS_PERSONALITY: u64 = 92;
pub const SYS_SYSLOG: u64 = 116;

// Futex syscalls
pub const SYS_FUTEX: u64 = 98;
pub const SYS_SET_ROBUST_LIST: u64 = 99;
pub const SYS_GET_ROBUST_LIST: u64 = 100;
pub const SYS_FUTEX_WAITV: u64 = 449;
pub const SYS_SENDFILE: u64 = 71;
pub const SYS_VMSPLICE: u64 = 75;
pub const SYS_SPLICE: u64 = 76;
pub const SYS_TEE: u64 = 77;
pub const SYS_STATFS: u64 = 43;
pub const SYS_FSTATFS: u64 = 44;
pub const SYS_STATX: u64 = 291;

// Extended attribute syscalls (aarch64 uses low syscall numbers 5-16)
pub const SYS_SETXATTR: u64 = 5;
pub const SYS_LSETXATTR: u64 = 6;
pub const SYS_FSETXATTR: u64 = 7;
pub const SYS_GETXATTR: u64 = 8;
pub const SYS_LGETXATTR: u64 = 9;
pub const SYS_FGETXATTR: u64 = 10;
pub const SYS_LISTXATTR: u64 = 11;
pub const SYS_LLISTXATTR: u64 = 12;
pub const SYS_FLISTXATTR: u64 = 13;
pub const SYS_REMOVEXATTR: u64 = 14;
pub const SYS_LREMOVEXATTR: u64 = 15;
pub const SYS_FREMOVEXATTR: u64 = 16;

// Extended attribute flags
pub const XATTR_CREATE: i32 = 0x1;
pub const XATTR_REPLACE: i32 = 0x2;
pub const SYS_CHROOT: u64 = 51;
pub const SYS_FCHMODAT2: u64 = 452;

// ============================================================================
// Syscall wrapper functions
// ============================================================================

/// write(fd, buf, len)
#[inline(always)]
pub fn sys_write(fd: u64, buf: *const u8, len: u64) -> i64 {
    unsafe { syscall3!(SYS_WRITE, fd, buf, len) }
}

/// read(fd, buf, len)
#[inline(always)]
pub fn sys_read(fd: u64, buf: *mut u8, len: u64) -> i64 {
    unsafe { syscall3!(SYS_READ, fd, buf, len) }
}

/// openat(dirfd, path, flags, mode)
#[inline(always)]
pub fn sys_openat(dirfd: i32, path: *const u8, flags: u32, mode: u32) -> i64 {
    unsafe { syscall4!(SYS_OPENAT, dirfd, path, flags, mode) }
}

/// open(path, flags, mode) - compatibility wrapper using openat with AT_FDCWD
#[inline(always)]
pub fn sys_open(path: *const u8, flags: u32, mode: u32) -> i64 {
    sys_openat(AT_FDCWD, path, flags, mode)
}

/// close(fd)
#[inline(always)]
pub fn sys_close(fd: u64) -> i64 {
    unsafe { syscall1!(SYS_CLOSE, fd) }
}

/// getpid()
#[inline(always)]
pub fn sys_getpid() -> i64 {
    unsafe { syscall0!(SYS_GETPID) }
}

/// getppid()
#[inline(always)]
pub fn sys_getppid() -> i64 {
    unsafe { syscall0!(SYS_GETPPID) }
}

/// getuid()
#[inline(always)]
pub fn sys_getuid() -> i64 {
    unsafe { syscall0!(SYS_GETUID) }
}

/// geteuid()
#[inline(always)]
pub fn sys_geteuid() -> i64 {
    unsafe { syscall0!(SYS_GETEUID) }
}

/// getgid()
#[inline(always)]
pub fn sys_getgid() -> i64 {
    unsafe { syscall0!(SYS_GETGID) }
}

/// getegid()
#[inline(always)]
pub fn sys_getegid() -> i64 {
    unsafe { syscall0!(SYS_GETEGID) }
}

/// getpgid(pid)
#[inline(always)]
pub fn sys_getpgid(pid: u64) -> i64 {
    unsafe { syscall1!(SYS_GETPGID, pid) }
}

/// getsid(pid)
#[inline(always)]
pub fn sys_getsid(pid: u64) -> i64 {
    unsafe { syscall1!(SYS_GETSID, pid) }
}

/// setpgid(pid, pgid)
#[inline(always)]
#[allow(dead_code)]
pub fn sys_setpgid(pid: u64, pgid: u64) -> i64 {
    unsafe { syscall2!(SYS_SETPGID, pid, pgid) }
}

/// setsid()
#[inline(always)]
#[allow(dead_code)]
pub fn sys_setsid() -> i64 {
    unsafe { syscall0!(SYS_SETSID) }
}

/// gettid()
#[inline(always)]
pub fn sys_gettid() -> i64 {
    unsafe { syscall0!(SYS_GETTID) }
}

/// clone(flags, child_stack, parent_tidptr, child_tidptr, tls)
#[inline(always)]
pub fn sys_clone(flags: u64, child_stack: u64, parent_tidptr: u64, child_tidptr: u64, tls: u64) -> i64 {
    unsafe { syscall5!(SYS_CLONE, flags, child_stack, parent_tidptr, child_tidptr, tls) }
}

/// fork() - compatibility wrapper using clone
#[inline(always)]
pub fn sys_fork() -> i64 {
    // SIGCHLD (17) as flags for fork semantics
    sys_clone(17, 0, 0, 0, 0)
}

/// vfork() - compatibility wrapper using clone with CLONE_VFORK | CLONE_VM
#[inline(always)]
pub fn sys_vfork() -> i64 {
    const CLONE_VFORK: u64 = 0x00004000;
    const CLONE_VM: u64 = 0x00000100;
    const SIGCHLD: u64 = 17;
    sys_clone(CLONE_VFORK | CLONE_VM | SIGCHLD, 0, 0, 0, 0)
}

/// wait4(pid, wstatus, options, rusage)
#[inline(always)]
pub fn sys_wait4(pid: i64, wstatus: *mut i32, options: i32, rusage: u64) -> i64 {
    unsafe { syscall4!(SYS_WAIT4, pid, wstatus, options, rusage) }
}

/// getdents64(fd, dirp, count)
#[inline(always)]
pub fn sys_getdents64(fd: u64, dirp: *mut u8, count: u64) -> i64 {
    unsafe { syscall3!(SYS_GETDENTS64, fd, dirp, count) }
}

/// nanosleep(req, rem)
#[inline(always)]
pub fn sys_nanosleep(req: *const Timespec, rem: *mut Timespec) -> i64 {
    unsafe { syscall2!(SYS_NANOSLEEP, req, rem) }
}

/// clock_nanosleep(clockid, flags, req, rem)
#[inline(always)]
pub fn sys_clock_nanosleep(clockid: i32, flags: i32, req: *const Timespec, rem: *mut Timespec) -> i64 {
    unsafe { syscall4!(SYS_CLOCK_NANOSLEEP, clockid, flags, req, rem) }
}

/// clock_getres(clockid, res)
#[inline(always)]
pub fn sys_clock_getres(clockid: i32, res: *mut Timespec) -> i64 {
    unsafe { syscall2!(SYS_CLOCK_GETRES, clockid, res) }
}

/// clock_gettime(clockid, tp)
#[inline(always)]
pub fn sys_clock_gettime(clockid: i32, tp: *mut Timespec) -> i64 {
    unsafe { syscall2!(SYS_CLOCK_GETTIME, clockid, tp) }
}

/// clock_settime(clockid, tp)
#[inline(always)]
pub fn sys_clock_settime(clockid: i32, tp: *const Timespec) -> i64 {
    unsafe { syscall2!(SYS_CLOCK_SETTIME, clockid, tp) }
}

// --- Timerfd ---

use crate::types::ITimerSpec;

/// timerfd_create(clockid, flags)
#[inline(always)]
pub fn sys_timerfd_create(clockid: i32, flags: i32) -> i64 {
    unsafe { syscall2!(SYS_TIMERFD_CREATE, clockid, flags) }
}

/// timerfd_settime(fd, flags, new_value, old_value)
#[inline(always)]
pub fn sys_timerfd_settime(fd: i32, flags: i32, new_value: *const ITimerSpec, old_value: *mut ITimerSpec) -> i64 {
    unsafe { syscall4!(SYS_TIMERFD_SETTIME, fd, flags, new_value, old_value) }
}

/// timerfd_gettime(fd, curr_value)
#[inline(always)]
pub fn sys_timerfd_gettime(fd: i32, curr_value: *mut ITimerSpec) -> i64 {
    unsafe { syscall2!(SYS_TIMERFD_GETTIME, fd, curr_value) }
}

// --- eventfd ---

/// eventfd2(initval, flags) - create eventfd with flags
/// NOTE: aarch64 only has eventfd2, not the legacy eventfd
#[inline(always)]
pub fn sys_eventfd2(initval: u32, flags: i32) -> i64 {
    unsafe { syscall2!(SYS_EVENTFD2, initval, flags) }
}

// --- prctl ---

/// prctl syscall number
pub const SYS_PRCTL: u64 = 167;

/// prctl(option, arg2, arg3, arg4, arg5) - process/thread control
#[inline(always)]
pub fn sys_prctl(option: i32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> i64 {
    unsafe { syscall5!(SYS_PRCTL, option, arg2, arg3, arg4, arg5) }
}

// --- signalfd ---

/// signalfd4(fd, mask, sizemask, flags) - create/update signalfd
/// NOTE: aarch64 only has signalfd4, not the legacy signalfd
#[inline(always)]
pub fn sys_signalfd4(fd: i32, mask: *const u64, sizemask: usize, flags: i32) -> i64 {
    unsafe { syscall4!(SYS_SIGNALFD4, fd, mask, sizemask, flags) }
}

// --- epoll ---
// NOTE: aarch64 only has epoll_create1, epoll_ctl, and epoll_pwait
// We provide compatibility wrappers for epoll_create and epoll_wait

/// epoll_create(size) - create an epoll instance
/// On aarch64, this is implemented via epoll_create1(0)
#[inline(always)]
pub fn sys_epoll_create(size: i32) -> i64 {
    if size <= 0 {
        return -22; // EINVAL
    }
    sys_epoll_create1(0)
}

/// epoll_create1(flags) - create an epoll instance with flags (EPOLL_CLOEXEC)
#[inline(always)]
pub fn sys_epoll_create1(flags: i32) -> i64 {
    unsafe { syscall1!(SYS_EPOLL_CREATE1, flags) }
}

/// epoll_ctl(epfd, op, fd, event) - control an epoll instance
#[inline(always)]
pub fn sys_epoll_ctl(epfd: i32, op: i32, fd: i32, event: *const EpollEvent) -> i64 {
    unsafe { syscall4!(SYS_EPOLL_CTL, epfd, op, fd, event) }
}

/// epoll_wait(epfd, events, maxevents, timeout) - wait for events
/// On aarch64, this is implemented via epoll_pwait with null sigmask
#[inline(always)]
pub fn sys_epoll_wait(epfd: i32, events: *mut EpollEvent, maxevents: i32, timeout: i32) -> i64 {
    sys_epoll_pwait(epfd, events, maxevents, timeout, core::ptr::null(), 0)
}

/// epoll_pwait(epfd, events, maxevents, timeout, sigmask, sigsetsize) - wait with signal mask
#[inline(always)]
pub fn sys_epoll_pwait(
    epfd: i32,
    events: *mut EpollEvent,
    maxevents: i32,
    timeout: i32,
    sigmask: *const u64,
    sigsetsize: usize,
) -> i64 {
    unsafe { syscall6!(SYS_EPOLL_PWAIT, epfd, events, maxevents, timeout, sigmask, sigsetsize) }
}

/// epoll_pwait2(epfd, events, maxevents, timeout, sigmask, sigsetsize) - wait with timespec timeout
#[inline(always)]
pub fn sys_epoll_pwait2(
    epfd: i32,
    events: *mut EpollEvent,
    maxevents: i32,
    timeout: *const Timespec,
    sigmask: *const u64,
    sigsetsize: usize,
) -> i64 {
    unsafe { syscall6!(SYS_EPOLL_PWAIT2, epfd, events, maxevents, timeout, sigmask, sigsetsize) }
}

// --- POSIX Timers ---

/// timer_create(clockid, sigevent, timerid)
#[inline(always)]
pub fn sys_timer_create(clockid: i32, sevp: *const SigEvent, timerid: *mut i32) -> i64 {
    unsafe { syscall3!(SYS_TIMER_CREATE, clockid, sevp, timerid) }
}

/// timer_settime(timerid, flags, new_value, old_value)
#[inline(always)]
pub fn sys_timer_settime(timerid: i32, flags: i32, new_value: *const ITimerSpec, old_value: *mut ITimerSpec) -> i64 {
    unsafe { syscall4!(SYS_TIMER_SETTIME, timerid, flags, new_value, old_value) }
}

/// timer_gettime(timerid, curr_value)
#[inline(always)]
pub fn sys_timer_gettime(timerid: i32, curr_value: *mut ITimerSpec) -> i64 {
    unsafe { syscall2!(SYS_TIMER_GETTIME, timerid, curr_value) }
}

/// timer_getoverrun(timerid)
#[inline(always)]
pub fn sys_timer_getoverrun(timerid: i32) -> i64 {
    unsafe { syscall1!(SYS_TIMER_GETOVERRUN, timerid) }
}

/// timer_delete(timerid)
#[inline(always)]
pub fn sys_timer_delete(timerid: i32) -> i64 {
    unsafe { syscall1!(SYS_TIMER_DELETE, timerid) }
}

/// adjtimex(txc) - read/set kernel clock parameters
#[inline(always)]
pub fn sys_adjtimex(txc: *mut Timex) -> i64 {
    unsafe { syscall1!(SYS_ADJTIMEX, txc) }
}

// --- POSIX Message Queues ---

/// mq_open(name, oflag, mode, attr)
#[inline(always)]
pub fn sys_mq_open(name: *const u8, oflag: i32, mode: u32, attr: *const MqAttr) -> i64 {
    unsafe { syscall4!(SYS_MQ_OPEN, name, oflag, mode, attr) }
}

/// mq_unlink(name)
#[inline(always)]
pub fn sys_mq_unlink(name: *const u8) -> i64 {
    unsafe { syscall1!(SYS_MQ_UNLINK, name) }
}

/// mq_timedsend(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout)
#[inline(always)]
pub fn sys_mq_timedsend(mqdes: i32, msg: *const u8, len: usize, prio: u32, timeout: *const Timespec) -> i64 {
    unsafe { syscall5!(SYS_MQ_TIMEDSEND, mqdes, msg, len, prio, timeout) }
}

/// mq_timedreceive(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout)
#[inline(always)]
pub fn sys_mq_timedreceive(mqdes: i32, msg: *mut u8, len: usize, prio: *mut u32, timeout: *const Timespec) -> i64 {
    unsafe { syscall5!(SYS_MQ_TIMEDRECEIVE, mqdes, msg, len, prio, timeout) }
}

/// mq_notify(mqdes, sevp)
#[inline(always)]
pub fn sys_mq_notify(mqdes: i32, sevp: *const SigEvent) -> i64 {
    unsafe { syscall2!(SYS_MQ_NOTIFY, mqdes, sevp) }
}

/// mq_getsetattr(mqdes, newattr, oldattr)
#[inline(always)]
pub fn sys_mq_getsetattr(mqdes: i32, newattr: *const MqAttr, oldattr: *mut MqAttr) -> i64 {
    unsafe { syscall3!(SYS_MQ_GETSETATTR, mqdes, newattr, oldattr) }
}

/// waitid(idtype, id, infop, options)
#[inline(always)]
pub fn sys_waitid(idtype: i32, id: u64, infop: *mut SigInfo, options: i32) -> i64 {
    unsafe { syscall4!(SYS_WAITID, idtype, id, infop, options) }
}

/// execve(pathname, argv, envp)
#[inline(always)]
pub fn sys_execve(pathname: *const u8, argv: *const *const u8, envp: *const *const u8) -> i64 {
    unsafe { syscall3!(SYS_EXECVE, pathname, argv, envp) }
}

/// readv(fd, iov, iovcnt)
#[inline(always)]
pub fn sys_readv(fd: u64, iov: *const IoVec, iovcnt: u64) -> i64 {
    unsafe { syscall3!(SYS_READV, fd, iov, iovcnt) }
}

/// writev(fd, iov, iovcnt)
#[inline(always)]
pub fn sys_writev(fd: u64, iov: *const IoVec, iovcnt: u64) -> i64 {
    unsafe { syscall3!(SYS_WRITEV, fd, iov, iovcnt) }
}

/// pread64(fd, buf, count, offset)
#[inline(always)]
pub fn sys_pread64(fd: i32, buf: *mut u8, count: u64, offset: i64) -> i64 {
    unsafe { syscall4!(SYS_PREAD64, fd, buf, count, offset) }
}

/// pwrite64(fd, buf, count, offset)
#[inline(always)]
pub fn sys_pwrite64(fd: i32, buf: *const u8, count: u64, offset: i64) -> i64 {
    unsafe { syscall4!(SYS_PWRITE64, fd, buf, count, offset) }
}

/// preadv(fd, iov, iovcnt, offset)
#[inline(always)]
pub fn sys_preadv(fd: i32, iov: *const IoVec, iovcnt: i32, offset: i64) -> i64 {
    unsafe { syscall4!(SYS_PREADV, fd, iov, iovcnt, offset) }
}

/// pwritev(fd, iov, iovcnt, offset)
#[inline(always)]
pub fn sys_pwritev(fd: i32, iov: *const IoVec, iovcnt: i32, offset: i64) -> i64 {
    unsafe { syscall4!(SYS_PWRITEV, fd, iov, iovcnt, offset) }
}

/// preadv2(fd, iov, iovcnt, offset, flags)
#[inline(always)]
pub fn sys_preadv2(fd: i32, iov: *const IoVec, iovcnt: i32, offset: i64, flags: i32) -> i64 {
    unsafe { syscall5!(SYS_PREADV2, fd, iov, iovcnt, offset, flags) }
}

/// pwritev2(fd, iov, iovcnt, offset, flags)
#[inline(always)]
pub fn sys_pwritev2(fd: i32, iov: *const IoVec, iovcnt: i32, offset: i64, flags: i32) -> i64 {
    unsafe { syscall5!(SYS_PWRITEV2, fd, iov, iovcnt, offset, flags) }
}

/// mkdirat(dirfd, pathname, mode)
#[inline(always)]
pub fn sys_mkdirat(dirfd: i32, pathname: *const u8, mode: u32) -> i64 {
    unsafe { syscall3!(SYS_MKDIRAT, dirfd, pathname, mode) }
}

/// mkdir(pathname, mode) - compatibility wrapper
#[inline(always)]
pub fn sys_mkdir(pathname: *const u8, mode: u32) -> i64 {
    sys_mkdirat(AT_FDCWD, pathname, mode)
}

/// unlinkat(dirfd, pathname, flags)
#[inline(always)]
pub fn sys_unlinkat(dirfd: i32, pathname: *const u8, flags: i32) -> i64 {
    unsafe { syscall3!(SYS_UNLINKAT, dirfd, pathname, flags) }
}

/// rmdir(pathname) - compatibility wrapper using unlinkat with AT_REMOVEDIR
#[inline(always)]
pub fn sys_rmdir(pathname: *const u8) -> i64 {
    const AT_REMOVEDIR: i32 = 0x200;
    sys_unlinkat(AT_FDCWD, pathname, AT_REMOVEDIR)
}

/// unlink(pathname) - compatibility wrapper
#[inline(always)]
pub fn sys_unlink(pathname: *const u8) -> i64 {
    sys_unlinkat(AT_FDCWD, pathname, 0)
}

/// mknodat(dirfd, pathname, mode, dev)
#[inline(always)]
pub fn sys_mknodat(dirfd: i32, pathname: *const u8, mode: u32, dev: u64) -> i64 {
    unsafe { syscall4!(SYS_MKNODAT, dirfd, pathname, mode, dev) }
}

/// mknod(pathname, mode, dev) - compatibility wrapper
#[inline(always)]
pub fn sys_mknod(pathname: *const u8, mode: u32, dev: u64) -> i64 {
    sys_mknodat(AT_FDCWD, pathname, mode, dev)
}

/// symlinkat(target, newdirfd, linkpath)
#[inline(always)]
pub fn sys_symlinkat(target: *const u8, newdirfd: i32, linkpath: *const u8) -> i64 {
    unsafe { syscall3!(SYS_SYMLINKAT, target, newdirfd, linkpath) }
}

/// symlink(target, linkpath) - compatibility wrapper
#[inline(always)]
pub fn sys_symlink(target: *const u8, linkpath: *const u8) -> i64 {
    sys_symlinkat(target, AT_FDCWD, linkpath)
}

/// readlinkat(dirfd, pathname, buf, bufsiz)
#[inline(always)]
pub fn sys_readlinkat(dirfd: i32, pathname: *const u8, buf: *mut u8, bufsiz: u64) -> i64 {
    unsafe { syscall4!(SYS_READLINKAT, dirfd, pathname, buf, bufsiz) }
}

/// readlink(pathname, buf, bufsiz) - compatibility wrapper
#[inline(always)]
pub fn sys_readlink(pathname: *const u8, buf: *mut u8, bufsiz: u64) -> i64 {
    sys_readlinkat(AT_FDCWD, pathname, buf, bufsiz)
}

/// linkat(olddirfd, oldpath, newdirfd, newpath, flags)
#[inline(always)]
pub fn sys_linkat(olddirfd: i32, oldpath: *const u8, newdirfd: i32, newpath: *const u8, flags: i32) -> i64 {
    unsafe { syscall5!(SYS_LINKAT, olddirfd, oldpath, newdirfd, newpath, flags) }
}

/// link(oldpath, newpath) - compatibility wrapper
#[inline(always)]
pub fn sys_link(oldpath: *const u8, newpath: *const u8) -> i64 {
    sys_linkat(AT_FDCWD, oldpath, AT_FDCWD, newpath, 0)
}

/// lseek(fd, offset, whence)
pub fn sys_lseek(fd: i32, offset: i64, whence: i32) -> i64 {
    unsafe { syscall3!(SYS_LSEEK, fd, offset, whence) }
}

/// ftruncate(fd, length)
pub fn sys_ftruncate(fd: i32, length: i64) -> i64 {
    unsafe { syscall2!(SYS_FTRUNCATE, fd, length) }
}

/// truncate(pathname, length) - compatibility wrapper
pub fn sys_truncate(pathname: *const u8, length: i64) -> i64 {
    let fd = sys_openat(AT_FDCWD, pathname, 1, 0); // O_WRONLY = 1
    if fd < 0 {
        return fd;
    }
    let ret = sys_ftruncate(fd as i32, length);
    sys_close(fd as u64);
    ret
}

/// fchmodat(dirfd, pathname, mode, flags)
#[inline(always)]
pub fn sys_fchmodat(dirfd: i32, pathname: *const u8, mode: u32, flags: i32) -> i64 {
    unsafe { syscall4!(SYS_FCHMODAT, dirfd, pathname, mode, flags) }
}

/// chmod(pathname, mode) - compatibility wrapper
pub fn sys_chmod(pathname: *const u8, mode: u32) -> i64 {
    sys_fchmodat(AT_FDCWD, pathname, mode, 0)
}

/// fchmod(fd, mode)
pub fn sys_fchmod(fd: i32, mode: u32) -> i64 {
    unsafe { syscall2!(SYS_FCHMOD, fd, mode) }
}

/// fchownat(dirfd, pathname, owner, group, flags)
#[inline(always)]
pub fn sys_fchownat(dirfd: i32, pathname: *const u8, owner: u32, group: u32, flags: i32) -> i64 {
    unsafe { syscall5!(SYS_FCHOWNAT, dirfd, pathname, owner, group, flags) }
}

/// chown(pathname, owner, group) - compatibility wrapper
pub fn sys_chown(pathname: *const u8, owner: u32, group: u32) -> i64 {
    sys_fchownat(AT_FDCWD, pathname, owner, group, 0)
}

/// lchown(pathname, owner, group) - compatibility wrapper
pub fn sys_lchown(pathname: *const u8, owner: u32, group: u32) -> i64 {
    const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
    sys_fchownat(AT_FDCWD, pathname, owner, group, AT_SYMLINK_NOFOLLOW)
}

/// fchown(fd, owner, group)
pub fn sys_fchown(fd: i32, owner: u32, group: u32) -> i64 {
    unsafe { syscall3!(SYS_FCHOWN, fd, owner, group) }
}

/// fstatat(dirfd, pathname, statbuf, flags)
#[inline(always)]
pub fn sys_fstatat(dirfd: i32, pathname: *const u8, statbuf: *mut Stat, flags: i32) -> i64 {
    unsafe { syscall4!(SYS_FSTATAT, dirfd, pathname, statbuf, flags) }
}

/// stat(pathname, statbuf) - compatibility wrapper
pub fn sys_stat(pathname: *const u8, statbuf: *mut Stat) -> i64 {
    sys_fstatat(AT_FDCWD, pathname, statbuf, 0)
}

/// lstat(pathname, statbuf) - compatibility wrapper
pub fn sys_lstat(pathname: *const u8, statbuf: *mut Stat) -> i64 {
    const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
    sys_fstatat(AT_FDCWD, pathname, statbuf, AT_SYMLINK_NOFOLLOW)
}

/// umask(mask)
pub fn sys_umask(mask: u32) -> i64 {
    unsafe { syscall1!(SYS_UMASK, mask) }
}

/// chroot(pathname)
pub fn sys_chroot(pathname: *const u8) -> i64 {
    unsafe { syscall1!(SYS_CHROOT, pathname) }
}

/// fchmodat2(dirfd, pathname, mode, flags)
pub fn sys_fchmodat2(dirfd: i32, pathname: *const u8, mode: u32, flags: i32) -> i64 {
    unsafe { syscall4!(SYS_FCHMODAT2, dirfd, pathname, mode, flags) }
}

/// utimensat(dirfd, pathname, times, flags)
pub fn sys_utimensat(dirfd: i32, pathname: *const u8, times: *const Timespec, flags: i32) -> i64 {
    unsafe { syscall4!(SYS_UTIMENSAT, dirfd, pathname, times, flags) }
}

/// renameat(olddirfd, oldpath, newdirfd, newpath)
#[inline(always)]
pub fn sys_renameat(olddirfd: i32, oldpath: *const u8, newdirfd: i32, newpath: *const u8) -> i64 {
    unsafe { syscall4!(SYS_RENAMEAT, olddirfd, oldpath, newdirfd, newpath) }
}

/// rename(oldpath, newpath) - compatibility wrapper
pub fn sys_rename(oldpath: *const u8, newpath: *const u8) -> i64 {
    sys_renameat(AT_FDCWD, oldpath, AT_FDCWD, newpath)
}

/// mount(source, target, fstype, flags, data)
pub fn sys_mount(source: *const u8, target: *const u8, fstype: *const u8, flags: u64, data: u64) -> i64 {
    unsafe { syscall5!(SYS_MOUNT, source, target, fstype, flags, data) }
}

/// umount2(target, flags)
pub fn sys_umount2(target: *const u8, flags: u64) -> i64 {
    unsafe { syscall2!(SYS_UMOUNT2, target, flags) }
}

/// pivot_root(new_root, put_old) - change the root filesystem
#[inline(always)]
pub fn sys_pivot_root(new_root: *const u8, put_old: *const u8) -> i64 {
    unsafe { syscall2!(SYS_PIVOT_ROOT, new_root, put_old) }
}

/// swapon(path, swapflags) - enable a swap device/file
#[inline(always)]
pub fn sys_swapon(path: *const u8, swapflags: i32) -> i64 {
    unsafe { syscall2!(SYS_SWAPON, path, swapflags as u64) }
}

/// swapoff(path) - disable a swap device/file
#[inline(always)]
pub fn sys_swapoff(path: *const u8) -> i64 {
    unsafe { syscall1!(SYS_SWAPOFF, path) }
}

/// sync() - synchronize cached writes to persistent storage
#[inline(always)]
pub fn sys_sync() -> i64 {
    unsafe { syscall0!(SYS_SYNC) }
}

/// fsync(fd) - synchronize a file's in-core state with storage device
#[inline(always)]
pub fn sys_fsync(fd: i32) -> i64 {
    unsafe { syscall1!(SYS_FSYNC, fd) }
}

/// fdatasync(fd) - synchronize a file's in-core data with storage device
#[inline(always)]
pub fn sys_fdatasync(fd: i32) -> i64 {
    unsafe { syscall1!(SYS_FDATASYNC, fd) }
}

/// syncfs(fd) - synchronize filesystem containing file referred to by fd
#[inline(always)]
pub fn sys_syncfs(fd: i32) -> i64 {
    unsafe { syscall1!(SYS_SYNCFS, fd) }
}

/// reboot(magic1, magic2, cmd) - does not return
#[inline(always)]
pub fn sys_reboot(magic1: u64, magic2: u64, cmd: u64) -> ! {
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_REBOOT,
            in("x0") magic1,
            in("x1") magic2,
            in("x2") cmd,
            in("x3") 0u64,  // arg (unused for power off)
            options(noreturn, nostack),
        );
    }
}

/// exit(status) - does not return
#[inline(always)]
pub fn sys_exit(status: u64) -> ! {
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_EXIT,
            in("x0") status,
            options(noreturn, nostack),
        );
    }
}

// ============================================================================
// UTS namespace syscalls
// ============================================================================

/// uname(buf) - get system identification
#[inline(always)]
pub fn sys_uname(buf: *mut UtsName) -> i64 {
    unsafe { syscall1!(SYS_UNAME, buf) }
}

/// sethostname(name, len) - set hostname
#[inline(always)]
pub fn sys_sethostname(name: *const u8, len: u64) -> i64 {
    unsafe { syscall2!(SYS_SETHOSTNAME, name, len) }
}

/// setdomainname(name, len) - set NIS domain name
#[inline(always)]
pub fn sys_setdomainname(name: *const u8, len: u64) -> i64 {
    unsafe { syscall2!(SYS_SETDOMAINNAME, name, len) }
}

// ============================================================================
// Signal syscalls
// ============================================================================

/// rt_sigaction(sig, act, oact, sigsetsize) - examine and change signal action
#[inline(always)]
pub fn sys_rt_sigaction(sig: u32, act: u64, oact: u64, sigsetsize: u64) -> i64 {
    unsafe { syscall4!(SYS_RT_SIGACTION, sig, act, oact, sigsetsize) }
}

/// rt_sigprocmask(how, set, oset, sigsetsize) - examine and change blocked signals
#[inline(always)]
pub fn sys_rt_sigprocmask(how: i32, set: u64, oset: u64, sigsetsize: u64) -> i64 {
    unsafe { syscall4!(SYS_RT_SIGPROCMASK, how, set, oset, sigsetsize) }
}

/// rt_sigpending(set, sigsetsize) - examine pending signals
#[inline(always)]
pub fn sys_rt_sigpending(set: u64, sigsetsize: u64) -> i64 {
    unsafe { syscall2!(SYS_RT_SIGPENDING, set, sigsetsize) }
}

/// rt_sigtimedwait(set, info, ts, sigsetsize) - wait for signal
#[inline(always)]
pub fn sys_rt_sigtimedwait(set: u64, info: u64, ts: u64, sigsetsize: u64) -> i64 {
    unsafe { syscall4!(SYS_RT_SIGTIMEDWAIT, set, info, ts, sigsetsize) }
}

/// sigaltstack(ss, oss) - set/get alternate signal stack
#[inline(always)]
pub fn sys_sigaltstack(ss: u64, oss: u64) -> i64 {
    unsafe { syscall2!(SYS_SIGALTSTACK, ss, oss) }
}

/// kill(pid, sig) - send signal to process
#[inline(always)]
pub fn sys_kill(pid: i64, sig: u32) -> i64 {
    unsafe { syscall2!(SYS_KILL, pid, sig) }
}

/// tgkill(tgid, tid, sig) - send signal to specific thread
#[inline(always)]
pub fn sys_tgkill(tgid: i64, tid: i64, sig: u32) -> i64 {
    unsafe { syscall3!(SYS_TGKILL, tgid, tid, sig) }
}

/// tkill(tid, sig) - send signal to thread (deprecated)
#[inline(always)]
pub fn sys_tkill(tid: i64, sig: u32) -> i64 {
    unsafe { syscall2!(SYS_TKILL, tid, sig) }
}

/// rt_sigqueueinfo(pid, sig, uinfo) - send signal with info to process
#[inline(always)]
pub fn sys_rt_sigqueueinfo(pid: i64, sig: u32, uinfo: u64) -> i64 {
    unsafe { syscall3!(SYS_RT_SIGQUEUEINFO, pid, sig, uinfo) }
}

/// rt_sigsuspend(mask, sigsetsize) - wait for signal with temporary mask
#[inline(always)]
pub fn sys_rt_sigsuspend(mask: u64, sigsetsize: u64) -> i64 {
    unsafe { syscall2!(SYS_RT_SIGSUSPEND, mask, sigsetsize) }
}

/// rt_tgsigqueueinfo(tgid, tid, sig, uinfo) - send signal with info to thread
#[inline(always)]
pub fn sys_rt_tgsigqueueinfo(tgid: i64, tid: i64, sig: u32, uinfo: u64) -> i64 {
    unsafe { syscall4!(SYS_RT_TGSIGQUEUEINFO, tgid, tid, sig, uinfo) }
}

// ============================================================================
// Pipe/Poll/Select syscalls (aarch64 only has pipe2, ppoll, pselect6)
// ============================================================================

/// pipe2(pipefd, flags) - create a pipe with flags
#[inline(always)]
pub fn sys_pipe2(pipefd: *mut i32, flags: u32) -> i64 {
    unsafe { syscall2!(SYS_PIPE2, pipefd, flags) }
}

/// sys_pipe - wrapper that calls pipe2 with flags=0
#[inline(always)]
pub fn sys_pipe(pipefd: *mut i32) -> i64 {
    sys_pipe2(pipefd, 0)
}

/// ppoll(fds, nfds, tmo_p, sigmask, sigsetsize) - wait for events on file descriptors
#[inline(always)]
pub fn sys_ppoll(fds: *mut PollFd, nfds: u32, tmo_p: *const Timespec, sigmask: u64, sigsetsize: u64) -> i64 {
    unsafe { syscall5!(SYS_PPOLL, fds, nfds, tmo_p, sigmask, sigsetsize) }
}

/// sys_poll - wrapper that calls ppoll with NULL sigmask
#[inline(always)]
pub fn sys_poll(fds: *mut PollFd, nfds: u32, timeout: i32) -> i64 {
    if timeout < 0 {
        // Infinite wait - NULL timeout
        sys_ppoll(fds, nfds, core::ptr::null(), 0, 0)
    } else {
        // Convert milliseconds to timespec
        let ts = Timespec {
            tv_sec: (timeout / 1000) as i64,
            tv_nsec: ((timeout % 1000) * 1_000_000) as i64,
        };
        sys_ppoll(fds, nfds, &ts, 0, 0)
    }
}

/// pselect6(nfds, readfds, writefds, exceptfds, timeout, sigmask)
#[inline(always)]
#[allow(dead_code)]
pub fn sys_pselect6(nfds: i32, readfds: *mut FdSet, writefds: *mut FdSet, exceptfds: *mut FdSet, timeout: *const Timespec, sigmask: u64) -> i64 {
    unsafe { syscall6!(SYS_PSELECT6, nfds, readfds, writefds, exceptfds, timeout, sigmask) }
}

/// sys_select - wrapper that calls pselect6 with NULL sigmask
#[inline(always)]
pub fn sys_select(nfds: i32, readfds: *mut FdSet, writefds: *mut FdSet, exceptfds: *mut FdSet, timeout: *mut Timeval) -> i64 {
    if timeout.is_null() {
        // Infinite wait - NULL timeout
        sys_pselect6(nfds, readfds, writefds, exceptfds, core::ptr::null(), 0)
    } else {
        // Convert timeval to timespec
        let tv = unsafe { &*timeout };
        let ts = Timespec {
            tv_sec: tv.tv_sec,
            tv_nsec: tv.tv_usec * 1000,
        };
        sys_pselect6(nfds, readfds, writefds, exceptfds, &ts, 0)
    }
}

// ============================================================================
// Memory mapping syscalls
// ============================================================================

/// mmap(addr, length, prot, flags, fd, offset) - map memory
#[inline(always)]
pub fn sys_mmap(addr: u64, length: u64, prot: u32, flags: u32, fd: i32, offset: u64) -> i64 {
    unsafe { syscall6!(SYS_MMAP, addr, length, prot, flags, fd, offset) }
}

/// mprotect(addr, len, prot) - change memory protection
#[inline(always)]
pub fn sys_mprotect(addr: u64, len: u64, prot: u32) -> i64 {
    unsafe { syscall3!(SYS_MPROTECT, addr, len, prot) }
}

/// munmap(addr, length) - unmap memory
#[inline(always)]
pub fn sys_munmap(addr: u64, length: u64) -> i64 {
    unsafe { syscall2!(SYS_MUNMAP, addr, length) }
}

/// brk(addr) - change program break
#[inline(always)]
pub fn sys_brk(addr: u64) -> i64 {
    unsafe { syscall1!(SYS_BRK, addr) }
}

/// mlock(addr, len) - lock pages in memory
#[inline(always)]
pub fn sys_mlock(addr: u64, len: u64) -> i64 {
    unsafe { syscall2!(SYS_MLOCK, addr, len) }
}

/// mlock2(addr, len, flags) - lock pages in memory with flags
#[inline(always)]
pub fn sys_mlock2(addr: u64, len: u64, flags: i32) -> i64 {
    unsafe { syscall3!(SYS_MLOCK2, addr, len, flags) }
}

/// munlock(addr, len) - unlock pages
#[inline(always)]
pub fn sys_munlock(addr: u64, len: u64) -> i64 {
    unsafe { syscall2!(SYS_MUNLOCK, addr, len) }
}

/// mlockall(flags) - lock all current and/or future mappings
#[inline(always)]
pub fn sys_mlockall(flags: i32) -> i64 {
    unsafe { syscall1!(SYS_MLOCKALL, flags) }
}

/// munlockall() - unlock all mappings
#[inline(always)]
pub fn sys_munlockall() -> i64 {
    unsafe { syscall0!(SYS_MUNLOCKALL) }
}

/// msync(addr, length, flags) - synchronize a file with a memory map
#[inline(always)]
pub fn sys_msync(addr: u64, length: u64, flags: i32) -> i64 {
    unsafe { syscall3!(SYS_MSYNC, addr, length, flags) }
}

/// mincore(addr, length, vec) - determine whether pages are resident in memory
#[inline(always)]
pub fn sys_mincore(addr: u64, length: u64, vec: *mut u8) -> i64 {
    unsafe { syscall3!(SYS_MINCORE, addr, length, vec) }
}

/// madvise(addr, length, advice) - give advice about use of memory
#[inline(always)]
pub fn sys_madvise(addr: u64, length: u64, advice: i32) -> i64 {
    unsafe { syscall3!(SYS_MADVISE, addr, length, advice) }
}

/// mremap(old_addr, old_len, new_len, flags, new_addr) - remap a virtual memory region
#[inline(always)]
pub fn sys_mremap(old_addr: u64, old_len: u64, new_len: u64, flags: u32, new_addr: u64) -> i64 {
    unsafe { syscall5!(SYS_MREMAP, old_addr, old_len, new_len, flags, new_addr) }
}

/// getcpu(cpup, nodep) - get CPU and NUMA node for calling thread
#[inline(always)]
pub fn sys_getcpu(cpup: *mut u32, nodep: *mut u32) -> i64 {
    unsafe { syscall3!(SYS_GETCPU, cpup, nodep, 0u64) }
}

/// getpriority(which, who) - get program scheduling priority
#[inline(always)]
pub fn sys_getpriority(which: i32, who: u64) -> i64 {
    unsafe { syscall2!(SYS_GETPRIORITY, which, who) }
}

/// setpriority(which, who, niceval) - set program scheduling priority
#[inline(always)]
pub fn sys_setpriority(which: i32, who: u64, niceval: i32) -> i64 {
    unsafe { syscall3!(SYS_SETPRIORITY, which, who, niceval) }
}

/// setuid(uid) - set user identity
#[inline(always)]
pub fn sys_setuid(uid: u32) -> i64 {
    unsafe { syscall1!(SYS_SETUID, uid) }
}

/// setgid(gid) - set group identity
#[inline(always)]
pub fn sys_setgid(gid: u32) -> i64 {
    unsafe { syscall1!(SYS_SETGID, gid) }
}

/// getresuid(ruid, euid, suid) - get real, effective, and saved user IDs
#[inline(always)]
pub fn sys_getresuid(ruid: *mut u32, euid: *mut u32, suid: *mut u32) -> i64 {
    unsafe { syscall3!(SYS_GETRESUID, ruid, euid, suid) }
}

/// getresgid(rgid, egid, sgid) - get real, effective, and saved group IDs
#[inline(always)]
pub fn sys_getresgid(rgid: *mut u32, egid: *mut u32, sgid: *mut u32) -> i64 {
    unsafe { syscall3!(SYS_GETRESGID, rgid, egid, sgid) }
}

/// setresuid(ruid, euid, suid) - set real, effective, and saved user IDs
#[inline(always)]
pub fn sys_setresuid(ruid: u32, euid: u32, suid: u32) -> i64 {
    unsafe { syscall3!(SYS_SETRESUID, ruid, euid, suid) }
}

/// setresgid(rgid, egid, sgid) - set real, effective, and saved group IDs
#[inline(always)]
pub fn sys_setresgid(rgid: u32, egid: u32, sgid: u32) -> i64 {
    unsafe { syscall3!(SYS_SETRESGID, rgid, egid, sgid) }
}

/// setreuid(ruid, euid) - set real and effective user IDs
#[inline(always)]
pub fn sys_setreuid(ruid: u32, euid: u32) -> i64 {
    unsafe { syscall2!(SYS_SETREUID, ruid, euid) }
}

/// setregid(rgid, egid) - set real and effective group IDs
#[inline(always)]
pub fn sys_setregid(rgid: u32, egid: u32) -> i64 {
    unsafe { syscall2!(SYS_SETREGID, rgid, egid) }
}

/// setfsuid(uid) - set filesystem UID
#[inline(always)]
pub fn sys_setfsuid(uid: u32) -> i64 {
    unsafe { syscall1!(SYS_SETFSUID, uid) }
}

/// setfsgid(gid) - set filesystem GID
#[inline(always)]
pub fn sys_setfsgid(gid: u32) -> i64 {
    unsafe { syscall1!(SYS_SETFSGID, gid) }
}

// ============================================================================
// System information syscalls
// ============================================================================

/// sysinfo(info) - return system information
#[inline(always)]
pub fn sys_sysinfo(info: *mut u8) -> i64 {
    unsafe { syscall1!(SYS_SYSINFO, info) }
}

/// getrusage(who, usage) - get resource usage
#[inline(always)]
pub fn sys_getrusage(who: i32, usage: *mut u8) -> i64 {
    unsafe { syscall2!(SYS_GETRUSAGE, who, usage) }
}

/// fcntl(fd, cmd, arg) - file control operations
#[inline(always)]
pub fn sys_fcntl(fd: i32, cmd: i32, arg: u64) -> i64 {
    unsafe { syscall3!(SYS_FCNTL, fd, cmd, arg) }
}

/// ioctl(fd, request, arg) - device control operations
#[inline(always)]
pub fn sys_ioctl(fd: i32, request: u64, arg: u64) -> i64 {
    unsafe { syscall3!(SYS_IOCTL, fd, request, arg) }
}

/// getrandom(buf, buflen, flags) - get random bytes
#[inline(always)]
pub fn sys_getrandom(buf: *mut u8, buflen: usize, flags: u32) -> i64 {
    unsafe { syscall3!(SYS_GETRANDOM, buf, buflen, flags) }
}

// ============================================================================
// Scheduling syscalls
// ============================================================================

/// sched_getscheduler(pid) - get scheduling policy
#[inline(always)]
pub fn sys_sched_getscheduler(pid: i64) -> i64 {
    unsafe { syscall1!(SYS_SCHED_GETSCHEDULER, pid) }
}

/// sched_setscheduler(pid, policy, param) - set scheduling policy and parameters
#[inline(always)]
pub fn sys_sched_setscheduler(pid: i64, policy: i32, param: *const super::SchedParam) -> i64 {
    unsafe { syscall3!(SYS_SCHED_SETSCHEDULER, pid, policy, param) }
}

/// sched_getparam(pid, param) - get scheduling parameters
#[inline(always)]
pub fn sys_sched_getparam(pid: i64, param: *mut super::SchedParam) -> i64 {
    unsafe { syscall2!(SYS_SCHED_GETPARAM, pid, param) }
}

/// sched_setparam(pid, param) - set scheduling parameters
#[inline(always)]
pub fn sys_sched_setparam(pid: i64, param: *const super::SchedParam) -> i64 {
    unsafe { syscall2!(SYS_SCHED_SETPARAM, pid, param) }
}

/// sched_getaffinity(pid, cpusetsize, mask) - get CPU affinity mask
#[inline(always)]
pub fn sys_sched_getaffinity(pid: i64, cpusetsize: usize, mask: *mut u64) -> i64 {
    unsafe { syscall3!(SYS_SCHED_GETAFFINITY, pid, cpusetsize, mask) }
}

/// sched_setaffinity(pid, cpusetsize, mask) - set CPU affinity mask
#[inline(always)]
pub fn sys_sched_setaffinity(pid: i64, cpusetsize: usize, mask: *const u64) -> i64 {
    unsafe { syscall3!(SYS_SCHED_SETAFFINITY, pid, cpusetsize, mask) }
}

/// sched_rr_get_interval(pid, tp) - get round-robin time quantum
#[inline(always)]
pub fn sys_sched_rr_get_interval(pid: i64, tp: *mut Timespec) -> i64 {
    unsafe { syscall2!(SYS_SCHED_RR_GET_INTERVAL, pid, tp) }
}

// ============================================================================
// Resource limits syscalls
// ============================================================================

/// getrlimit(resource, rlim) - get resource limits
#[inline(always)]
pub fn sys_getrlimit(resource: u32, rlim: *mut RLimit) -> i64 {
    unsafe { syscall2!(SYS_GETRLIMIT, resource, rlim) }
}

/// setrlimit(resource, rlim) - set resource limits
#[inline(always)]
pub fn sys_setrlimit(resource: u32, rlim: *const RLimit) -> i64 {
    unsafe { syscall2!(SYS_SETRLIMIT, resource, rlim) }
}

/// prlimit64(pid, resource, new_rlim, old_rlim) - get/set resource limits
#[inline(always)]
pub fn sys_prlimit64(pid: i32, resource: u32, new_rlim: *const RLimit, old_rlim: *mut RLimit) -> i64 {
    unsafe { syscall4!(SYS_PRLIMIT64, pid, resource, new_rlim, old_rlim) }
}

// ============================================================================
// Namespace syscalls
// ============================================================================

/// unshare(flags) - disassociate parts of process execution context
#[inline(always)]
pub fn sys_unshare(flags: u64) -> i64 {
    unsafe { syscall1!(SYS_UNSHARE, flags) }
}

/// setns(fd, nstype) - reassociate thread with a namespace
#[inline(always)]
pub fn sys_setns(fd: i32, nstype: i32) -> i64 {
    unsafe { syscall2!(SYS_SETNS, fd, nstype) }
}

// ============================================================================
// Socket syscalls
// ============================================================================

/// socket(domain, type, protocol) - create a socket
#[inline(always)]
pub fn sys_socket(domain: i32, sock_type: i32, protocol: i32) -> i64 {
    unsafe { syscall3!(SYS_SOCKET, domain, sock_type, protocol) }
}

/// connect(fd, addr, addrlen) - initiate a connection on a socket
#[inline(always)]
pub fn sys_connect(fd: i32, addr: *const u8, addrlen: u32) -> i64 {
    unsafe { syscall3!(SYS_CONNECT, fd, addr, addrlen) }
}

/// bind(fd, addr, addrlen) - bind a name to a socket
#[inline(always)]
pub fn sys_bind(fd: i32, addr: *const u8, addrlen: u32) -> i64 {
    unsafe { syscall3!(SYS_BIND, fd, addr, addrlen) }
}

/// listen(fd, backlog) - listen for connections on a socket
#[inline(always)]
pub fn sys_listen(fd: i32, backlog: i32) -> i64 {
    unsafe { syscall2!(SYS_LISTEN, fd, backlog) }
}

/// accept(fd, addr, addrlen) - accept a connection on a socket
#[inline(always)]
pub fn sys_accept(fd: i32, addr: *mut u8, addrlen: *mut u32) -> i64 {
    unsafe { syscall3!(SYS_ACCEPT, fd, addr, addrlen) }
}

/// shutdown(fd, how) - shut down part of a full-duplex connection
#[inline(always)]
pub fn sys_shutdown(fd: i32, how: i32) -> i64 {
    unsafe { syscall2!(SYS_SHUTDOWN, fd, how) }
}

/// getsockname(fd, addr, addrlen) - get socket name
#[inline(always)]
pub fn sys_getsockname(fd: i32, addr: *mut u8, addrlen: *mut u32) -> i64 {
    unsafe { syscall3!(SYS_GETSOCKNAME, fd, addr, addrlen) }
}

/// getpeername(fd, addr, addrlen) - get name of connected peer socket
#[inline(always)]
pub fn sys_getpeername(fd: i32, addr: *mut u8, addrlen: *mut u32) -> i64 {
    unsafe { syscall3!(SYS_GETPEERNAME, fd, addr, addrlen) }
}

/// sendto(fd, buf, len, flags, dest_addr, addrlen) - send a message on a socket
#[inline(always)]
pub fn sys_sendto(fd: i32, buf: *const u8, len: usize, flags: i32, dest_addr: *const u8, addrlen: u32) -> i64 {
    unsafe { syscall6!(SYS_SENDTO, fd, buf, len, flags, dest_addr, addrlen) }
}

/// recvfrom(fd, buf, len, flags, src_addr, addrlen) - receive a message from a socket
#[inline(always)]
pub fn sys_recvfrom(fd: i32, buf: *mut u8, len: usize, flags: i32, src_addr: *mut u8, addrlen: *mut u32) -> i64 {
    unsafe { syscall6!(SYS_RECVFROM, fd, buf, len, flags, src_addr, addrlen) }
}

/// setsockopt(fd, level, optname, optval, optlen) - set socket options
#[inline(always)]
pub fn sys_setsockopt(fd: i32, level: i32, optname: i32, optval: *const u8, optlen: u32) -> i64 {
    unsafe { syscall5!(SYS_SETSOCKOPT, fd, level, optname, optval, optlen) }
}

/// getsockopt(fd, level, optname, optval, optlen) - get socket options
#[inline(always)]
pub fn sys_getsockopt(fd: i32, level: i32, optname: i32, optval: *mut u8, optlen: *mut u32) -> i64 {
    unsafe { syscall5!(SYS_GETSOCKOPT, fd, level, optname, optval, optlen) }
}

/// socketpair(domain, type, protocol, sv) - create a pair of connected sockets
#[inline(always)]
pub fn sys_socketpair(domain: i32, sock_type: i32, protocol: i32, sv: *mut [i32; 2]) -> i64 {
    unsafe { syscall4!(SYS_SOCKETPAIR, domain, sock_type, protocol, sv) }
}

/// sendmsg(fd, msg, flags) - send a message on a socket
#[inline(always)]
pub fn sys_sendmsg(fd: i32, msg: *const super::MsgHdr, flags: i32) -> i64 {
    unsafe { syscall3!(SYS_SENDMSG, fd, msg, flags) }
}

/// recvmsg(fd, msg, flags) - receive a message from a socket
#[inline(always)]
pub fn sys_recvmsg(fd: i32, msg: *mut super::MsgHdr, flags: i32) -> i64 {
    unsafe { syscall3!(SYS_RECVMSG, fd, msg, flags) }
}

/// sendmmsg(fd, msgvec, vlen, flags) - send multiple messages
#[inline(always)]
pub fn sys_sendmmsg(fd: i32, msgvec: *mut super::MMsgHdr, vlen: u32, flags: i32) -> i64 {
    unsafe { syscall4!(SYS_SENDMMSG, fd, msgvec, vlen, flags) }
}

/// recvmmsg(fd, msgvec, vlen, flags, timeout) - receive multiple messages
#[inline(always)]
pub fn sys_recvmmsg(fd: i32, msgvec: *mut super::MMsgHdr, vlen: u32, flags: i32, timeout: *const Timespec) -> i64 {
    unsafe { syscall5!(SYS_RECVMMSG, fd, msgvec, vlen, flags, timeout) }
}

// ============================================================================
// Futex syscalls
// ============================================================================

/// futex(uaddr, op, val, timeout, uaddr2, val3) - fast userspace mutex
#[inline(always)]
pub fn sys_futex(uaddr: *mut u32, op: u32, val: u32, timeout: *const Timespec, uaddr2: *mut u32, val3: u32) -> i64 {
    unsafe { syscall6!(SYS_FUTEX, uaddr, op, val, timeout, uaddr2, val3) }
}

/// set_robust_list(head, len) - register robust futex list
#[inline(always)]
pub fn sys_set_robust_list(head: *const super::RobustListHead, len: usize) -> i64 {
    unsafe { syscall2!(SYS_SET_ROBUST_LIST, head, len) }
}

/// get_robust_list(pid, head_ptr, len_ptr) - get robust futex list
#[inline(always)]
pub fn sys_get_robust_list(pid: i32, head_ptr: *mut *const super::RobustListHead, len_ptr: *mut usize) -> i64 {
    unsafe { syscall3!(SYS_GET_ROBUST_LIST, pid, head_ptr, len_ptr) }
}

/// futex_waitv - wait on multiple futexes
///
/// # Arguments
/// * `waiters` - Pointer to array of FutexWaitv structures
/// * `nr_futexes` - Number of futexes in the array (1-128)
/// * `flags` - Syscall flags (must be 0)
/// * `timeout` - Optional pointer to absolute timeout (struct timespec)
/// * `clockid` - Clock for timeout (CLOCK_MONOTONIC=1 or CLOCK_REALTIME=0)
///
/// # Returns
/// * >= 0: Index of woken futex
/// * -EINVAL: Invalid arguments
/// * -EAGAIN: Value mismatch
/// * -ETIMEDOUT: Timeout expired
#[inline(always)]
pub fn sys_futex_waitv(
    waiters: *const super::FutexWaitv,
    nr_futexes: u32,
    flags: u32,
    timeout: *const Timespec,
    clockid: i32,
) -> i64 {
    unsafe { syscall5!(SYS_FUTEX_WAITV, waiters, nr_futexes, flags, timeout, clockid) }
}

// ============================================================================
// TLS syscall wrappers
// ============================================================================

/// set_tid_address(tidptr) - set pointer to thread ID
#[inline(always)]
pub fn sys_set_tid_address(tidptr: *mut i32) -> i64 {
    unsafe { syscall1!(SYS_SET_TID_ADDRESS, tidptr) }
}

// ============================================================================
// SysV IPC syscall wrappers
// ============================================================================

/// shmget(key, size, shmflg) - allocate a shared memory segment
#[inline(always)]
pub fn sys_shmget(key: i32, size: usize, shmflg: i32) -> i64 {
    unsafe { syscall3!(SYS_SHMGET, key, size, shmflg) }
}

/// shmat(shmid, shmaddr, shmflg) - attach a shared memory segment
#[inline(always)]
pub fn sys_shmat(shmid: i32, shmaddr: u64, shmflg: i32) -> i64 {
    unsafe { syscall3!(SYS_SHMAT, shmid, shmaddr, shmflg) }
}

/// shmdt(shmaddr) - detach a shared memory segment
#[inline(always)]
pub fn sys_shmdt(shmaddr: u64) -> i64 {
    unsafe { syscall1!(SYS_SHMDT, shmaddr) }
}

/// shmctl(shmid, cmd, buf) - shared memory control
#[inline(always)]
pub fn sys_shmctl(shmid: i32, cmd: i32, buf: u64) -> i64 {
    unsafe { syscall3!(SYS_SHMCTL, shmid, cmd, buf) }
}

/// semget(key, nsems, semflg) - get a semaphore set
#[inline(always)]
pub fn sys_semget(key: i32, nsems: i32, semflg: i32) -> i64 {
    unsafe { syscall3!(SYS_SEMGET, key, nsems, semflg) }
}

/// semop(semid, sops, nsops) - semaphore operations
#[inline(always)]
pub fn sys_semop(semid: i32, sops: *const super::Sembuf, nsops: usize) -> i64 {
    unsafe { syscall3!(SYS_SEMOP, semid, sops, nsops) }
}

/// semtimedop(semid, sops, nsops, timeout) - semaphore operations with timeout
#[inline(always)]
pub fn sys_semtimedop(semid: i32, sops: *const super::Sembuf, nsops: usize, timeout: *const Timespec) -> i64 {
    unsafe { syscall4!(SYS_SEMTIMEDOP, semid, sops, nsops, timeout) }
}

/// semctl(semid, semnum, cmd, arg) - semaphore control
#[inline(always)]
pub fn sys_semctl(semid: i32, semnum: i32, cmd: i32, arg: u64) -> i64 {
    unsafe { syscall4!(SYS_SEMCTL, semid, semnum, cmd, arg) }
}

/// msgget(key, msgflg) - get a message queue
#[inline(always)]
pub fn sys_msgget(key: i32, msgflg: i32) -> i64 {
    unsafe { syscall2!(SYS_MSGGET, key, msgflg) }
}

/// msgsnd(msqid, msgp, msgsz, msgflg) - send a message to a queue
#[inline(always)]
pub fn sys_msgsnd(msqid: i32, msgp: *const u8, msgsz: usize, msgflg: i32) -> i64 {
    unsafe { syscall4!(SYS_MSGSND, msqid, msgp, msgsz, msgflg) }
}

/// msgrcv(msqid, msgp, msgsz, msgtyp, msgflg) - receive a message from a queue
#[inline(always)]
pub fn sys_msgrcv(msqid: i32, msgp: *mut u8, msgsz: usize, msgtyp: i64, msgflg: i32) -> i64 {
    unsafe { syscall5!(SYS_MSGRCV, msqid, msgp, msgsz, msgtyp, msgflg) }
}

/// msgctl(msqid, cmd, buf) - message queue control
#[inline(always)]
pub fn sys_msgctl(msqid: i32, cmd: i32, buf: u64) -> i64 {
    unsafe { syscall3!(SYS_MSGCTL, msqid, cmd, buf) }
}

/// ioprio_set(which, who, ioprio) - set I/O priority
#[inline(always)]
pub fn sys_ioprio_set(which: i32, who: i32, ioprio: i32) -> i64 {
    unsafe { syscall3!(SYS_IOPRIO_SET, which, who, ioprio) }
}

/// ioprio_get(which, who) - get I/O priority
#[inline(always)]
pub fn sys_ioprio_get(which: i32, who: i32) -> i64 {
    unsafe { syscall2!(SYS_IOPRIO_GET, which, who) }
}

// --- Splice / Sendfile ---

/// sendfile(out_fd, in_fd, offset, count) - transfer data between file descriptors
#[inline(always)]
pub fn sys_sendfile(out_fd: i32, in_fd: i32, offset: *mut i64, count: usize) -> i64 {
    unsafe { syscall4!(SYS_SENDFILE, out_fd, in_fd, offset, count) }
}

/// splice(fd_in, off_in, fd_out, off_out, len, flags) - splice data between fds
#[inline(always)]
pub fn sys_splice(fd_in: i32, off_in: *mut i64, fd_out: i32, off_out: *mut i64, len: usize, flags: u32) -> i64 {
    unsafe { syscall6!(SYS_SPLICE, fd_in, off_in, fd_out, off_out, len, flags) }
}

/// tee(fd_in, fd_out, len, flags) - duplicate pipe content
#[inline(always)]
pub fn sys_tee(fd_in: i32, fd_out: i32, len: usize, flags: u32) -> i64 {
    unsafe { syscall4!(SYS_TEE, fd_in, fd_out, len, flags) }
}

/// vmsplice(fd, iov, nr_segs, flags) - splice user pages into a pipe
#[inline(always)]
pub fn sys_vmsplice(fd: i32, iov: *const super::IoVec, nr_segs: usize, flags: u32) -> i64 {
    unsafe { syscall4!(SYS_VMSPLICE, fd, iov, nr_segs, flags) }
}

// --- Filesystem Statistics ---

/// statfs(pathname, buf) - get filesystem statistics
#[inline(always)]
pub fn sys_statfs(pathname: *const u8, buf: *mut super::LinuxStatFs) -> i64 {
    unsafe { syscall2!(SYS_STATFS, pathname, buf) }
}

/// fstatfs(fd, buf) - get filesystem statistics by file descriptor
#[inline(always)]
pub fn sys_fstatfs(fd: i32, buf: *mut super::LinuxStatFs) -> i64 {
    unsafe { syscall2!(SYS_FSTATFS, fd, buf) }
}

/// statx(dirfd, pathname, flags, mask, buf) - get extended file status
#[inline(always)]
pub fn sys_statx(dirfd: i32, pathname: *const u8, flags: i32, mask: u32, buf: *mut super::Statx) -> i64 {
    unsafe { syscall5!(SYS_STATX, dirfd, pathname, flags, mask, buf) }
}

// ============================================================================
// Extended attributes syscalls
// ============================================================================

/// setxattr(path, name, value, size, flags) - set extended attribute
#[inline(always)]
pub fn sys_setxattr(path: *const u8, name: *const u8, value: *const u8, size: usize, flags: i32) -> i64 {
    unsafe { syscall5!(SYS_SETXATTR, path, name, value, size, flags) }
}

/// lsetxattr(path, name, value, size, flags) - set extended attribute (no symlink follow)
#[inline(always)]
pub fn sys_lsetxattr(path: *const u8, name: *const u8, value: *const u8, size: usize, flags: i32) -> i64 {
    unsafe { syscall5!(SYS_LSETXATTR, path, name, value, size, flags) }
}

/// fsetxattr(fd, name, value, size, flags) - set extended attribute by fd
#[inline(always)]
pub fn sys_fsetxattr(fd: i32, name: *const u8, value: *const u8, size: usize, flags: i32) -> i64 {
    unsafe { syscall5!(SYS_FSETXATTR, fd, name, value, size, flags) }
}

/// getxattr(path, name, value, size) - get extended attribute
#[inline(always)]
pub fn sys_getxattr(path: *const u8, name: *const u8, value: *mut u8, size: usize) -> i64 {
    unsafe { syscall4!(SYS_GETXATTR, path, name, value, size) }
}

/// lgetxattr(path, name, value, size) - get extended attribute (no symlink follow)
#[inline(always)]
pub fn sys_lgetxattr(path: *const u8, name: *const u8, value: *mut u8, size: usize) -> i64 {
    unsafe { syscall4!(SYS_LGETXATTR, path, name, value, size) }
}

/// fgetxattr(fd, name, value, size) - get extended attribute by fd
#[inline(always)]
pub fn sys_fgetxattr(fd: i32, name: *const u8, value: *mut u8, size: usize) -> i64 {
    unsafe { syscall4!(SYS_FGETXATTR, fd, name, value, size) }
}

/// listxattr(path, list, size) - list extended attributes
#[inline(always)]
pub fn sys_listxattr(path: *const u8, list: *mut u8, size: usize) -> i64 {
    unsafe { syscall3!(SYS_LISTXATTR, path, list, size) }
}

/// llistxattr(path, list, size) - list extended attributes (no symlink follow)
#[inline(always)]
pub fn sys_llistxattr(path: *const u8, list: *mut u8, size: usize) -> i64 {
    unsafe { syscall3!(SYS_LLISTXATTR, path, list, size) }
}

/// flistxattr(fd, list, size) - list extended attributes by fd
#[inline(always)]
pub fn sys_flistxattr(fd: i32, list: *mut u8, size: usize) -> i64 {
    unsafe { syscall3!(SYS_FLISTXATTR, fd, list, size) }
}

/// removexattr(path, name) - remove extended attribute
#[inline(always)]
pub fn sys_removexattr(path: *const u8, name: *const u8) -> i64 {
    unsafe { syscall2!(SYS_REMOVEXATTR, path, name) }
}

/// lremovexattr(path, name) - remove extended attribute (no symlink follow)
#[inline(always)]
pub fn sys_lremovexattr(path: *const u8, name: *const u8) -> i64 {
    unsafe { syscall2!(SYS_LREMOVEXATTR, path, name) }
}

/// fremovexattr(fd, name) - remove extended attribute by fd
#[inline(always)]
pub fn sys_fremovexattr(fd: i32, name: *const u8) -> i64 {
    unsafe { syscall2!(SYS_FREMOVEXATTR, fd, name) }
}

// ============================================================================
// Capabilities (capget, capset)
// ============================================================================

use crate::types::{CapUserData, CapUserHeader};

/// capget - get capabilities of a process
///
/// Gets the capabilities of the target process specified in the header.
/// Use pid=0 for the calling process.
///
/// For version 3, datap must point to an array of 2 CapUserData structs.
#[inline(always)]
pub fn sys_capget(hdrp: *mut CapUserHeader, datap: *mut CapUserData) -> i64 {
    unsafe { syscall2!(SYS_CAPGET, hdrp, datap) }
}

/// capset - set capabilities of current process
///
/// Sets the capabilities of the current process.
/// The pid in the header must be 0 or the calling process's pid.
///
/// For version 3, datap must point to an array of 2 CapUserData structs.
#[inline(always)]
pub fn sys_capset(hdrp: *const CapUserHeader, datap: *const CapUserData) -> i64 {
    unsafe { syscall2!(SYS_CAPSET, hdrp, datap) }
}

// ============================================================================
// Inotify
// NOTE: aarch64 only has inotify_init1, not legacy inotify_init
// ============================================================================

/// inotify_init1(flags) - syscall number
pub const SYS_INOTIFY_INIT1: u64 = 26;
/// inotify_add_watch(fd, pathname, mask) - syscall number
pub const SYS_INOTIFY_ADD_WATCH: u64 = 27;
/// inotify_rm_watch(fd, wd) - syscall number
pub const SYS_INOTIFY_RM_WATCH: u64 = 28;

/// inotify_init1(flags) - create inotify instance with flags
#[inline(always)]
pub fn sys_inotify_init1(flags: i32) -> i64 {
    unsafe { syscall1!(SYS_INOTIFY_INIT1, flags) }
}

/// inotify_add_watch(fd, pathname, mask) - add watch to inotify instance
#[inline(always)]
pub fn sys_inotify_add_watch(fd: i32, pathname: *const u8, mask: u32) -> i64 {
    unsafe { syscall3!(SYS_INOTIFY_ADD_WATCH, fd, pathname, mask) }
}

/// inotify_rm_watch(fd, wd) - remove watch from inotify instance
#[inline(always)]
pub fn sys_inotify_rm_watch(fd: i32, wd: i32) -> i64 {
    unsafe { syscall2!(SYS_INOTIFY_RM_WATCH, fd, wd) }
}

// ============================================================================
// Membarrier
// ============================================================================

/// membarrier command constants
pub const MEMBARRIER_CMD_QUERY: i32 = 0;
pub const MEMBARRIER_CMD_GLOBAL: i32 = 1 << 0;
pub const MEMBARRIER_CMD_PRIVATE_EXPEDITED: i32 = 1 << 3;
pub const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED: i32 = 1 << 4;

/// membarrier(cmd, flags, cpu_id) - memory barrier across threads
#[inline(always)]
pub fn sys_membarrier(cmd: i32, flags: u32, cpu_id: i32) -> i64 {
    unsafe { syscall3!(SYS_MEMBARRIER, cmd, flags, cpu_id) }
}

// ============================================================================
// Readahead
// ============================================================================

/// readahead(fd, offset, count) - initiate file readahead
#[inline(always)]
pub fn sys_readahead(fd: i32, offset: i64, count: usize) -> i64 {
    unsafe { syscall3!(SYS_READAHEAD, fd, offset, count) }
}

// ============================================================================
// clone3 (modern extensible clone)
// ============================================================================

/// clone3(uargs, size) - create a new process with extended arguments
#[inline(always)]
pub fn sys_clone3(args: *const CloneArgs, size: usize) -> i64 {
    unsafe { syscall2!(SYS_CLONE3, args, size) }
}

// ============================================================================
// personality (execution domain)
// ============================================================================

/// personality(persona) - set process execution domain
///
/// If persona is 0xFFFFFFFF, returns current personality without changing it.
/// Otherwise, sets new personality and returns old value.
#[inline(always)]
pub fn sys_personality(persona: u32) -> i64 {
    unsafe { syscall1!(SYS_PERSONALITY, persona) }
}

// ============================================================================
// syslog (kernel logging)
// ============================================================================

/// syslog(type, buf, len) - read and/or clear kernel message ring buffer
#[inline(always)]
pub fn sys_syslog(type_: i32, buf: *mut u8, len: i32) -> i64 {
    unsafe { syscall3!(SYS_SYSLOG, type_, buf, len) }
}

/// syslog action codes
pub const SYSLOG_ACTION_CLOSE: i32 = 0;
pub const SYSLOG_ACTION_OPEN: i32 = 1;
pub const SYSLOG_ACTION_READ: i32 = 2;
pub const SYSLOG_ACTION_READ_ALL: i32 = 3;
pub const SYSLOG_ACTION_READ_CLEAR: i32 = 4;
pub const SYSLOG_ACTION_CLEAR: i32 = 5;
pub const SYSLOG_ACTION_CONSOLE_OFF: i32 = 6;
pub const SYSLOG_ACTION_CONSOLE_ON: i32 = 7;
pub const SYSLOG_ACTION_CONSOLE_LEVEL: i32 = 8;
pub const SYSLOG_ACTION_SIZE_UNREAD: i32 = 9;
pub const SYSLOG_ACTION_SIZE_BUFFER: i32 = 10;

// ============================================================================
// pidfd - process file descriptors
// ============================================================================

/// pidfd_open syscall number (aarch64)
pub const SYS_PIDFD_OPEN: u64 = 434;
/// pidfd_send_signal syscall number (aarch64)
pub const SYS_PIDFD_SEND_SIGNAL: u64 = 424;
/// pidfd_getfd syscall number (aarch64)
pub const SYS_PIDFD_GETFD: u64 = 438;

/// pidfd_open(pid, flags) - create pidfd for a process
///
/// Creates a file descriptor that refers to the process specified by pid.
/// The flags argument is a bit mask of flags that modify the behavior:
/// - 0: Default behavior
/// - O_NONBLOCK (0o4000): Open in non-blocking mode
///
/// Returns the file descriptor on success, or a negative error code on failure.
#[inline(always)]
pub fn sys_pidfd_open(pid: i32, flags: u32) -> i64 {
    unsafe { syscall2!(SYS_PIDFD_OPEN, pid, flags) }
}

/// pidfd_send_signal(pidfd, sig, info, flags) - send signal via pidfd
///
/// Sends the signal sig to the process referred to by the pidfd.
/// The info argument is an optional pointer to siginfo_t for queued signals.
/// The flags argument is reserved and must be 0.
///
/// Returns 0 on success, or a negative error code on failure.
#[inline(always)]
pub fn sys_pidfd_send_signal(pidfd: i32, sig: i32, info: *const u8, flags: u32) -> i64 {
    unsafe { syscall4!(SYS_PIDFD_SEND_SIGNAL, pidfd, sig, info, flags) }
}

/// pidfd_getfd(pidfd, targetfd, flags) - obtain duplicate of another process's FD
///
/// This syscall duplicates a file descriptor from the process referred to by pidfd.
/// Currently returns -ENOSYS as it requires PTRACE capabilities.
///
/// Returns the new file descriptor on success, or a negative error code on failure.
#[inline(always)]
pub fn sys_pidfd_getfd(pidfd: i32, targetfd: i32, flags: u32) -> i64 {
    unsafe { syscall3!(SYS_PIDFD_GETFD, pidfd, targetfd, flags) }
}

// --- io_uring ---

/// io_uring_setup syscall number (aarch64)
pub const SYS_IO_URING_SETUP: u64 = 425;
/// io_uring_enter syscall number (aarch64)
pub const SYS_IO_URING_ENTER: u64 = 426;
/// io_uring_register syscall number (aarch64)
pub const SYS_IO_URING_REGISTER: u64 = 427;

/// io_uring_setup(entries, params) - set up an io_uring instance
///
/// Creates a new io_uring instance with the specified number of submission queue entries.
/// The params structure is used to pass in additional setup parameters and receive
/// ring offsets on output.
///
/// Returns a file descriptor on success, or a negative error code on failure.
#[inline(always)]
pub fn sys_io_uring_setup(entries: u32, params: *mut crate::types::IoUringParams) -> i64 {
    unsafe { syscall2!(SYS_IO_URING_SETUP, entries, params) }
}

/// io_uring_enter(fd, to_submit, min_complete, flags, argp, argsz) - submit and wait for io_uring completions
///
/// Submits I/O requests to the io_uring instance referenced by fd and optionally
/// waits for completions.
///
/// - fd: io_uring file descriptor
/// - to_submit: number of submissions to process from the SQ ring
/// - min_complete: minimum number of completions to wait for (if IORING_ENTER_GETEVENTS)
/// - flags: operation flags (IORING_ENTER_GETEVENTS, IORING_ENTER_SQ_WAKEUP, etc.)
/// - argp: optional pointer to additional arguments
/// - argsz: size of the argp structure
///
/// Returns the number of submissions processed, or a negative error code.
#[inline(always)]
pub fn sys_io_uring_enter(
    fd: u32,
    to_submit: u32,
    min_complete: u32,
    flags: u32,
    argp: u64,
    argsz: usize,
) -> i64 {
    unsafe { syscall6!(SYS_IO_URING_ENTER, fd, to_submit, min_complete, flags, argp, argsz) }
}

/// io_uring_register(fd, opcode, arg, nr_args) - register resources with io_uring
///
/// Registers or unregisters resources (files, buffers, eventfds) with the io_uring
/// instance for more efficient access during I/O operations.
///
/// - fd: io_uring file descriptor
/// - opcode: registration operation (IORING_REGISTER_*, IORING_UNREGISTER_*)
/// - arg: pointer to arguments (depends on opcode)
/// - nr_args: number of arguments
///
/// Returns 0 on success, or a negative error code on failure.
#[inline(always)]
pub fn sys_io_uring_register(fd: u32, opcode: u32, arg: u64, nr_args: u32) -> i64 {
    unsafe { syscall4!(SYS_IO_URING_REGISTER, fd, opcode, arg, nr_args) }
}

// Keyring syscalls
pub const SYS_ADD_KEY: u64 = 217;
pub const SYS_REQUEST_KEY: u64 = 218;
pub const SYS_KEYCTL: u64 = 219;
/// kcmp syscall number (aarch64)
pub const SYS_KCMP: u64 = 272;

/// add_key(type, description, payload, plen, keyring) - add a key to the kernel's key management facility
///
/// Creates a new key of the specified type with the given description and payload,
/// and links it to the specified keyring.
///
/// - type_ptr: pointer to NUL-terminated key type name (e.g., "user", "keyring")
/// - desc_ptr: pointer to NUL-terminated key description
/// - payload_ptr: pointer to the key payload data
/// - plen: length of the payload in bytes
/// - keyring: destination keyring (KEY_SPEC_* or positive serial number)
///
/// Returns the key serial number on success, or a negative error code.
#[inline(always)]
pub fn sys_add_key(
    type_ptr: *const u8,
    desc_ptr: *const u8,
    payload_ptr: *const u8,
    plen: usize,
    keyring: i32,
) -> i64 {
    unsafe { syscall5!(SYS_ADD_KEY, type_ptr, desc_ptr, payload_ptr, plen, keyring) }
}

/// request_key(type, description, callout_info, dest_keyring) - request a key from the kernel
///
/// Searches for a key of the specified type and description in the process keyrings.
/// If found, the key is linked to the destination keyring (if specified).
///
/// - type_ptr: pointer to NUL-terminated key type name
/// - desc_ptr: pointer to NUL-terminated key description
/// - callout_info_ptr: pointer to callout info (can be NULL)
/// - dest_keyring: destination keyring to link found key (0 for none)
///
/// Returns the key serial number on success, or a negative error code.
#[inline(always)]
pub fn sys_request_key(
    type_ptr: *const u8,
    desc_ptr: *const u8,
    callout_info_ptr: *const u8,
    dest_keyring: i32,
) -> i64 {
    unsafe { syscall4!(SYS_REQUEST_KEY, type_ptr, desc_ptr, callout_info_ptr, dest_keyring) }
}

/// keyctl(cmd, arg2, arg3, arg4, arg5) - manipulate the kernel's key management facility
///
/// Performs various operations on keys and keyrings based on the command.
///
/// - cmd: KEYCTL_* command
/// - arg2-arg5: command-specific arguments
///
/// Returns command-specific value on success, or a negative error code.
#[inline(always)]
pub fn sys_keyctl(cmd: i32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> i64 {
    unsafe { syscall5!(SYS_KEYCTL, cmd, arg2, arg3, arg4, arg5) }
}

/// kcmp(pid1, pid2, type, idx1, idx2) - compare kernel resources between processes
///
/// Compares kernel resources (file descriptors, memory maps, etc.) between two processes.
/// Used by container runtimes and process inspection tools.
///
/// # Arguments
/// * `pid1` - First process ID
/// * `pid2` - Second process ID
/// * `type_` - Comparison type (KCMP_FILE, KCMP_VM, KCMP_FILES, KCMP_FS, etc.)
/// * `idx1` - First index (fd number for KCMP_FILE, ignored otherwise)
/// * `idx2` - Second index (fd number for KCMP_FILE, ignored otherwise)
///
/// # Returns
/// * 0 if resources are equal (same kernel object)
/// * 1 if first < second (obfuscated pointer comparison)
/// * 2 if first > second
/// * Negative error code on failure (ESRCH, EBADF, EINVAL, EOPNOTSUPP)
#[inline(always)]
pub fn sys_kcmp(pid1: u64, pid2: u64, type_: i32, idx1: u64, idx2: u64) -> i64 {
    unsafe { syscall5!(SYS_KCMP, pid1, pid2, type_, idx1, idx2) }
}

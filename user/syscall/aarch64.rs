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

use super::{FdSet, IoVec, PollFd, RLimit, SigInfo, Stat, Timespec, Timeval, UtsName, AT_FDCWD};

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
pub const SYS_READLINKAT: u64 = 78;
pub const SYS_FSTATAT: u64 = 79;
pub const SYS_FCHMOD: u64 = 52;
pub const SYS_FCHOWN: u64 = 55;
pub const SYS_EXIT: u64 = 93;
pub const SYS_EXIT_GROUP: u64 = 94;
pub const SYS_NANOSLEEP: u64 = 101;
pub const SYS_CLOCK_GETRES: u64 = 114;
pub const SYS_CLOCK_NANOSLEEP: u64 = 115;
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
pub const SYS_RT_SIGACTION: u64 = 134;
pub const SYS_RT_SIGPROCMASK: u64 = 135;
pub const SYS_RT_SIGPENDING: u64 = 136;

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
pub const SYS_MADVISE: u64 = 233;

// System information syscalls
pub const SYS_GETRUSAGE: u64 = 165;
pub const SYS_SYSINFO: u64 = 179;
pub const SYS_GETRANDOM: u64 = 278;

// File control
pub const SYS_FCNTL: u64 = 25;

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
pub const SYS_BIND: u64 = 200;
pub const SYS_LISTEN: u64 = 201;
pub const SYS_CONNECT: u64 = 203;
pub const SYS_GETSOCKNAME: u64 = 204;
pub const SYS_GETPEERNAME: u64 = 205;
pub const SYS_SENDTO: u64 = 206;
pub const SYS_RECVFROM: u64 = 207;
pub const SYS_SETSOCKOPT: u64 = 208;
pub const SYS_GETSOCKOPT: u64 = 209;
pub const SYS_SHUTDOWN: u64 = 210;

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

// ============================================================================
// Syscall wrapper functions
// ============================================================================

/// write(fd, buf, len)
#[inline(always)]
pub fn sys_write(fd: u64, buf: *const u8, len: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_WRITE,
            in("x0") fd,
            in("x1") buf,
            in("x2") len,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// read(fd, buf, len)
#[inline(always)]
pub fn sys_read(fd: u64, buf: *mut u8, len: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_READ,
            in("x0") fd,
            in("x1") buf,
            in("x2") len,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// openat(dirfd, path, flags, mode)
#[inline(always)]
pub fn sys_openat(dirfd: i32, path: *const u8, flags: u32, mode: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_OPENAT,
            in("x0") dirfd as i64,
            in("x1") path,
            in("x2") flags as u64,
            in("x3") mode as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// open(path, flags, mode) - compatibility wrapper using openat with AT_FDCWD
#[inline(always)]
pub fn sys_open(path: *const u8, flags: u32, mode: u32) -> i64 {
    sys_openat(AT_FDCWD, path, flags, mode)
}

/// close(fd)
#[inline(always)]
pub fn sys_close(fd: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_CLOSE,
            in("x0") fd,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// getpid()
#[inline(always)]
pub fn sys_getpid() -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_GETPID,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// getppid()
#[inline(always)]
pub fn sys_getppid() -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_GETPPID,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// getuid()
#[inline(always)]
pub fn sys_getuid() -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_GETUID,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// geteuid()
#[inline(always)]
pub fn sys_geteuid() -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_GETEUID,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// getgid()
#[inline(always)]
pub fn sys_getgid() -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_GETGID,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// getegid()
#[inline(always)]
pub fn sys_getegid() -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_GETEGID,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// getpgid(pid)
#[inline(always)]
pub fn sys_getpgid(pid: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_GETPGID,
            in("x0") pid,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// getsid(pid)
#[inline(always)]
pub fn sys_getsid(pid: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_GETSID,
            in("x0") pid,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// setpgid(pid, pgid)
#[inline(always)]
#[allow(dead_code)]
pub fn sys_setpgid(pid: u64, pgid: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SETPGID,
            in("x0") pid,
            in("x1") pgid,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// setsid()
#[inline(always)]
#[allow(dead_code)]
pub fn sys_setsid() -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SETSID,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// gettid()
#[inline(always)]
pub fn sys_gettid() -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_GETTID,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// clone(flags, child_stack, parent_tidptr, child_tidptr, tls)
#[inline(always)]
pub fn sys_clone(flags: u64, child_stack: u64, parent_tidptr: u64, child_tidptr: u64, tls: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_CLONE,
            in("x0") flags,
            in("x1") child_stack,
            in("x2") parent_tidptr,
            in("x3") child_tidptr,
            in("x4") tls,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
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
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_WAIT4,
            in("x0") pid,
            in("x1") wstatus as u64,
            in("x2") options as u64,
            in("x3") rusage,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// getdents64(fd, dirp, count)
#[inline(always)]
pub fn sys_getdents64(fd: u64, dirp: *mut u8, count: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_GETDENTS64,
            in("x0") fd,
            in("x1") dirp,
            in("x2") count,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// nanosleep(req, rem)
#[inline(always)]
pub fn sys_nanosleep(req: *const Timespec, rem: *mut Timespec) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_NANOSLEEP,
            in("x0") req,
            in("x1") rem,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// clock_nanosleep(clockid, flags, req, rem)
#[inline(always)]
pub fn sys_clock_nanosleep(clockid: i32, flags: i32, req: *const Timespec, rem: *mut Timespec) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_CLOCK_NANOSLEEP,
            in("x0") clockid as u64,
            in("x1") flags as u64,
            in("x2") req,
            in("x3") rem,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// clock_getres(clockid, res)
#[inline(always)]
pub fn sys_clock_getres(clockid: i32, res: *mut Timespec) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_CLOCK_GETRES,
            in("x0") clockid as u64,
            in("x1") res,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// waitid(idtype, id, infop, options)
#[inline(always)]
pub fn sys_waitid(idtype: i32, id: u64, infop: *mut SigInfo, options: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_WAITID,
            in("x0") idtype as u64,
            in("x1") id,
            in("x2") infop as u64,
            in("x3") options as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// execve(pathname, argv, envp)
#[inline(always)]
pub fn sys_execve(pathname: *const u8, argv: *const *const u8, envp: *const *const u8) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_EXECVE,
            in("x0") pathname as u64,
            in("x1") argv as u64,
            in("x2") envp as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// readv(fd, iov, iovcnt)
#[inline(always)]
pub fn sys_readv(fd: u64, iov: *const IoVec, iovcnt: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_READV,
            in("x0") fd,
            in("x1") iov,
            in("x2") iovcnt,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// writev(fd, iov, iovcnt)
#[inline(always)]
pub fn sys_writev(fd: u64, iov: *const IoVec, iovcnt: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_WRITEV,
            in("x0") fd,
            in("x1") iov,
            in("x2") iovcnt,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// pread64(fd, buf, count, offset) - read from file at given offset without changing file position
#[inline(always)]
pub fn sys_pread64(fd: i32, buf: *mut u8, count: u64, offset: i64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_PREAD64,
            in("x0") fd as i64,
            in("x1") buf,
            in("x2") count,
            in("x3") offset,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// pwrite64(fd, buf, count, offset) - write to file at given offset without changing file position
#[inline(always)]
pub fn sys_pwrite64(fd: i32, buf: *const u8, count: u64, offset: i64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_PWRITE64,
            in("x0") fd as i64,
            in("x1") buf,
            in("x2") count,
            in("x3") offset,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// preadv(fd, iov, iovcnt, offset) - scatter read at given offset without changing file position
#[inline(always)]
pub fn sys_preadv(fd: i32, iov: *const IoVec, iovcnt: i32, offset: i64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_PREADV,
            in("x0") fd as i64,
            in("x1") iov,
            in("x2") iovcnt as u64,
            in("x3") offset,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// pwritev(fd, iov, iovcnt, offset) - gather write at given offset without changing file position
#[inline(always)]
pub fn sys_pwritev(fd: i32, iov: *const IoVec, iovcnt: i32, offset: i64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_PWRITEV,
            in("x0") fd as i64,
            in("x1") iov,
            in("x2") iovcnt as u64,
            in("x3") offset,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// mkdirat(dirfd, pathname, mode)
#[inline(always)]
pub fn sys_mkdirat(dirfd: i32, pathname: *const u8, mode: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_MKDIRAT,
            in("x0") dirfd as i64,
            in("x1") pathname,
            in("x2") mode as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// mkdir(pathname, mode) - compatibility wrapper
#[inline(always)]
pub fn sys_mkdir(pathname: *const u8, mode: u32) -> i64 {
    sys_mkdirat(AT_FDCWD, pathname, mode)
}

/// unlinkat(dirfd, pathname, flags)
#[inline(always)]
pub fn sys_unlinkat(dirfd: i32, pathname: *const u8, flags: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_UNLINKAT,
            in("x0") dirfd as i64,
            in("x1") pathname,
            in("x2") flags as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
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
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_MKNODAT,
            in("x0") dirfd as i64,
            in("x1") pathname,
            in("x2") mode as u64,
            in("x3") dev,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// mknod(pathname, mode, dev) - compatibility wrapper
#[inline(always)]
pub fn sys_mknod(pathname: *const u8, mode: u32, dev: u64) -> i64 {
    sys_mknodat(AT_FDCWD, pathname, mode, dev)
}

/// symlinkat(target, newdirfd, linkpath)
#[inline(always)]
pub fn sys_symlinkat(target: *const u8, newdirfd: i32, linkpath: *const u8) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SYMLINKAT,
            in("x0") target,
            in("x1") newdirfd as i64,
            in("x2") linkpath,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// symlink(target, linkpath) - compatibility wrapper
#[inline(always)]
pub fn sys_symlink(target: *const u8, linkpath: *const u8) -> i64 {
    sys_symlinkat(target, AT_FDCWD, linkpath)
}

/// readlinkat(dirfd, pathname, buf, bufsiz)
#[inline(always)]
pub fn sys_readlinkat(dirfd: i32, pathname: *const u8, buf: *mut u8, bufsiz: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_READLINKAT,
            in("x0") dirfd as i64,
            in("x1") pathname,
            in("x2") buf,
            in("x3") bufsiz,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// readlink(pathname, buf, bufsiz) - compatibility wrapper
#[inline(always)]
pub fn sys_readlink(pathname: *const u8, buf: *mut u8, bufsiz: u64) -> i64 {
    sys_readlinkat(AT_FDCWD, pathname, buf, bufsiz)
}

/// linkat(olddirfd, oldpath, newdirfd, newpath, flags)
#[inline(always)]
pub fn sys_linkat(olddirfd: i32, oldpath: *const u8, newdirfd: i32, newpath: *const u8, flags: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_LINKAT,
            in("x0") olddirfd as i64,
            in("x1") oldpath,
            in("x2") newdirfd as i64,
            in("x3") newpath,
            in("x4") flags as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// link(oldpath, newpath) - compatibility wrapper
#[inline(always)]
pub fn sys_link(oldpath: *const u8, newpath: *const u8) -> i64 {
    sys_linkat(AT_FDCWD, oldpath, AT_FDCWD, newpath, 0)
}

/// lseek(fd, offset, whence)
pub fn sys_lseek(fd: i32, offset: i64, whence: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_LSEEK,
            in("x0") fd as i64,
            in("x1") offset,
            in("x2") whence as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// ftruncate(fd, length)
pub fn sys_ftruncate(fd: i32, length: i64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_FTRUNCATE,
            in("x0") fd as i64,
            in("x1") length,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// truncate(pathname, length) - compatibility wrapper
/// Opens file, truncates, closes
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
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_FCHMODAT,
            in("x0") dirfd as i64,
            in("x1") pathname,
            in("x2") mode as u64,
            in("x3") flags as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// chmod(pathname, mode) - compatibility wrapper
pub fn sys_chmod(pathname: *const u8, mode: u32) -> i64 {
    sys_fchmodat(AT_FDCWD, pathname, mode, 0)
}

/// fchmod(fd, mode)
pub fn sys_fchmod(fd: i32, mode: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_FCHMOD,
            in("x0") fd as i64,
            in("x1") mode as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// fchownat(dirfd, pathname, owner, group, flags)
#[inline(always)]
pub fn sys_fchownat(dirfd: i32, pathname: *const u8, owner: u32, group: u32, flags: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_FCHOWNAT,
            in("x0") dirfd as i64,
            in("x1") pathname,
            in("x2") owner as u64,
            in("x3") group as u64,
            in("x4") flags as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
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
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_FCHOWN,
            in("x0") fd as i64,
            in("x1") owner as u64,
            in("x2") group as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// fstatat(dirfd, pathname, statbuf, flags)
#[inline(always)]
pub fn sys_fstatat(dirfd: i32, pathname: *const u8, statbuf: *mut Stat, flags: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_FSTATAT,
            in("x0") dirfd as i64,
            in("x1") pathname,
            in("x2") statbuf,
            in("x3") flags as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
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
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_UMASK,
            in("x0") mask as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// utimensat(dirfd, pathname, times, flags)
pub fn sys_utimensat(dirfd: i32, pathname: *const u8, times: *const Timespec, flags: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_UTIMENSAT,
            in("x0") dirfd as i64,
            in("x1") pathname as u64,
            in("x2") times as u64,
            in("x3") flags as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// renameat(olddirfd, oldpath, newdirfd, newpath)
#[inline(always)]
pub fn sys_renameat(olddirfd: i32, oldpath: *const u8, newdirfd: i32, newpath: *const u8) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_RENAMEAT,
            in("x0") olddirfd as i64,
            in("x1") oldpath,
            in("x2") newdirfd as i64,
            in("x3") newpath,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// rename(oldpath, newpath) - compatibility wrapper
pub fn sys_rename(oldpath: *const u8, newpath: *const u8) -> i64 {
    sys_renameat(AT_FDCWD, oldpath, AT_FDCWD, newpath)
}

/// mount(source, target, fstype, flags, data)
pub fn sys_mount(source: *const u8, target: *const u8, fstype: *const u8, flags: u64, data: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_MOUNT,
            in("x0") source,
            in("x1") target,
            in("x2") fstype,
            in("x3") flags,
            in("x4") data,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// umount2(target, flags)
pub fn sys_umount2(target: *const u8, flags: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_UMOUNT2,
            in("x0") target,
            in("x1") flags,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// sync() - synchronize cached writes to persistent storage
#[inline(always)]
pub fn sys_sync() -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SYNC,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// fsync(fd) - synchronize a file's in-core state with storage device
#[inline(always)]
pub fn sys_fsync(fd: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_FSYNC,
            in("x0") fd as i64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// fdatasync(fd) - synchronize a file's in-core data with storage device
#[inline(always)]
pub fn sys_fdatasync(fd: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_FDATASYNC,
            in("x0") fd as i64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// syncfs(fd) - synchronize filesystem containing file referred to by fd
#[inline(always)]
pub fn sys_syncfs(fd: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SYNCFS,
            in("x0") fd as i64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
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
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_UNAME,
            in("x0") buf as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// sethostname(name, len) - set hostname
#[inline(always)]
pub fn sys_sethostname(name: *const u8, len: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SETHOSTNAME,
            in("x0") name as u64,
            in("x1") len,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// setdomainname(name, len) - set NIS domain name
#[inline(always)]
pub fn sys_setdomainname(name: *const u8, len: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SETDOMAINNAME,
            in("x0") name as u64,
            in("x1") len,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

// ============================================================================
// Signal syscalls
// ============================================================================

/// rt_sigaction(sig, act, oact, sigsetsize) - examine and change signal action
#[inline(always)]
pub fn sys_rt_sigaction(sig: u32, act: u64, oact: u64, sigsetsize: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_RT_SIGACTION,
            in("x0") sig as u64,
            in("x1") act,
            in("x2") oact,
            in("x3") sigsetsize,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// rt_sigprocmask(how, set, oset, sigsetsize) - examine and change blocked signals
#[inline(always)]
pub fn sys_rt_sigprocmask(how: i32, set: u64, oset: u64, sigsetsize: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_RT_SIGPROCMASK,
            in("x0") how as u64,
            in("x1") set,
            in("x2") oset,
            in("x3") sigsetsize,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// rt_sigpending(set, sigsetsize) - examine pending signals
#[inline(always)]
pub fn sys_rt_sigpending(set: u64, sigsetsize: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_RT_SIGPENDING,
            in("x0") set,
            in("x1") sigsetsize,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// kill(pid, sig) - send signal to process
#[inline(always)]
pub fn sys_kill(pid: i64, sig: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_KILL,
            in("x0") pid as u64,
            in("x1") sig as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// tgkill(tgid, tid, sig) - send signal to specific thread
#[inline(always)]
pub fn sys_tgkill(tgid: i64, tid: i64, sig: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_TGKILL,
            in("x0") tgid as u64,
            in("x1") tid as u64,
            in("x2") sig as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// tkill(tid, sig) - send signal to thread (deprecated)
#[inline(always)]
pub fn sys_tkill(tid: i64, sig: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_TKILL,
            in("x0") tid as u64,
            in("x1") sig as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

// ============================================================================
// Pipe/Poll/Select syscalls (aarch64 only has pipe2, ppoll, pselect6)
// ============================================================================

/// pipe2(pipefd, flags) - create a pipe with flags
/// Note: aarch64 doesn't have pipe(), only pipe2()
#[inline(always)]
pub fn sys_pipe2(pipefd: *mut i32, flags: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_PIPE2,
            in("x0") pipefd as u64,
            in("x1") flags as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// sys_pipe - wrapper that calls pipe2 with flags=0
/// Provides x86_64-compatible interface
#[inline(always)]
pub fn sys_pipe(pipefd: *mut i32) -> i64 {
    sys_pipe2(pipefd, 0)
}

/// ppoll(fds, nfds, tmo_p, sigmask, sigsetsize) - wait for events on file descriptors
/// Note: aarch64 doesn't have poll(), only ppoll()
#[inline(always)]
pub fn sys_ppoll(fds: *mut PollFd, nfds: u32, tmo_p: *const Timespec, sigmask: u64, sigsetsize: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_PPOLL,
            in("x0") fds as u64,
            in("x1") nfds as u64,
            in("x2") tmo_p as u64,
            in("x3") sigmask,
            in("x4") sigsetsize,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// sys_poll - wrapper that calls ppoll with NULL sigmask
/// Provides x86_64-compatible interface
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

/// pselect6(nfds, readfds, writefds, exceptfds, timeout, sigmask) - synchronous I/O multiplexing
/// Note: aarch64 doesn't have select(), only pselect6()
#[inline(always)]
#[allow(dead_code)]
pub fn sys_pselect6(nfds: i32, readfds: *mut FdSet, writefds: *mut FdSet, exceptfds: *mut FdSet, timeout: *const Timespec, sigmask: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_PSELECT6,
            in("x0") nfds as u64,
            in("x1") readfds as u64,
            in("x2") writefds as u64,
            in("x3") exceptfds as u64,
            in("x4") timeout as u64,
            in("x5") sigmask,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// sys_select - wrapper that calls pselect6 with NULL sigmask
/// Provides x86_64-compatible interface
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
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_MMAP,
            in("x0") addr,
            in("x1") length,
            in("x2") prot as u64,
            in("x3") flags as u64,
            in("x4") fd as u64,
            in("x5") offset,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// mprotect(addr, len, prot) - change memory protection
#[inline(always)]
pub fn sys_mprotect(addr: u64, len: u64, prot: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_MPROTECT,
            in("x0") addr,
            in("x1") len,
            in("x2") prot as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// munmap(addr, length) - unmap memory
#[inline(always)]
pub fn sys_munmap(addr: u64, length: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_MUNMAP,
            in("x0") addr,
            in("x1") length,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// brk(addr) - change program break
///
/// If addr is 0, returns current program break.
/// Otherwise, attempts to set program break to addr.
/// Returns new program break on success, current break on failure.
#[inline(always)]
pub fn sys_brk(addr: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_BRK,
            in("x0") addr,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// mlock(addr, len) - lock pages in memory
///
/// Returns 0 on success, negative errno on error.
#[inline(always)]
pub fn sys_mlock(addr: u64, len: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_MLOCK,
            in("x0") addr,
            in("x1") len,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// mlock2(addr, len, flags) - lock pages in memory with flags
///
/// Returns 0 on success, negative errno on error.
#[inline(always)]
pub fn sys_mlock2(addr: u64, len: u64, flags: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_MLOCK2,
            in("x0") addr,
            in("x1") len,
            in("x2") flags,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// munlock(addr, len) - unlock pages
///
/// Returns 0 on success, negative errno on error.
#[inline(always)]
pub fn sys_munlock(addr: u64, len: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_MUNLOCK,
            in("x0") addr,
            in("x1") len,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// mlockall(flags) - lock all current and/or future mappings
///
/// Returns 0 on success, negative errno on error.
#[inline(always)]
pub fn sys_mlockall(flags: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_MLOCKALL,
            in("x0") flags,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// munlockall() - unlock all mappings
///
/// Returns 0 on success, negative errno on error.
#[inline(always)]
pub fn sys_munlockall() -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_MUNLOCKALL,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// msync(addr, length, flags) - synchronize a file with a memory map
///
/// Flushes changes made to the in-core copy of a file-backed mapping back
/// to the filesystem.
///
/// Returns 0 on success, negative errno on error.
#[inline(always)]
pub fn sys_msync(addr: u64, length: u64, flags: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_MSYNC,
            in("x0") addr,
            in("x1") length,
            in("x2") flags,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// madvise(addr, length, advice) - give advice about use of memory
///
/// Advises the kernel about how to handle paging I/O in the specified
/// address range.
///
/// Returns 0 on success, negative errno on error.
#[inline(always)]
pub fn sys_madvise(addr: u64, length: u64, advice: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_MADVISE,
            in("x0") addr,
            in("x1") length,
            in("x2") advice,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// getcpu(cpup, nodep) - get CPU and NUMA node for calling thread
///
/// Returns 0 on success, negative errno on error.
/// Both pointers can be NULL if that information is not needed.
#[inline(always)]
pub fn sys_getcpu(cpup: *mut u32, nodep: *mut u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_GETCPU,
            in("x0") cpup,
            in("x1") nodep,
            in("x2") 0u64, // unused third parameter (legacy tcache)
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// getpriority(which, who) - get program scheduling priority
///
/// Returns the priority of a process, process group, or user.
/// The `which` argument selects the type: PRIO_PROCESS, PRIO_PGRP, or PRIO_USER.
/// The `who` argument selects the specific process/group/user (0 = calling process).
///
/// Returns 20 - nice value (range 1-40) on success, negative errno on error.
/// Note: To get the actual nice value, compute: 20 - return_value
#[inline(always)]
pub fn sys_getpriority(which: i32, who: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_GETPRIORITY,
            in("x0") which as u64,
            in("x1") who,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// setpriority(which, who, niceval) - set program scheduling priority
///
/// Sets the priority of a process, process group, or user.
/// The `which` argument selects the type: PRIO_PROCESS, PRIO_PGRP, or PRIO_USER.
/// The `who` argument selects the specific process/group/user (0 = calling process).
/// The `niceval` argument is the new nice value (-20 to 19).
///
/// Returns 0 on success, negative errno on error.
#[inline(always)]
pub fn sys_setpriority(which: i32, who: u64, niceval: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SETPRIORITY,
            in("x0") which as u64,
            in("x1") who,
            in("x2") niceval as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// setuid(uid) - set user identity
///
/// Sets the effective user ID of the calling process.
/// If the calling process has root privilege, also sets the real and saved UID.
///
/// Returns 0 on success, -EPERM if not permitted.
#[inline(always)]
pub fn sys_setuid(uid: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SETUID,
            in("x0") uid as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// setgid(gid) - set group identity
///
/// Sets the effective group ID of the calling process.
/// If the calling process has root privilege, also sets the real and saved GID.
///
/// Returns 0 on success, -EPERM if not permitted.
#[inline(always)]
pub fn sys_setgid(gid: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SETGID,
            in("x0") gid as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// getresuid(ruid, euid, suid) - get real, effective, and saved user IDs
///
/// Returns 0 on success, -EFAULT if pointers are invalid.
#[inline(always)]
pub fn sys_getresuid(ruid: *mut u32, euid: *mut u32, suid: *mut u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_GETRESUID,
            in("x0") ruid as u64,
            in("x1") euid as u64,
            in("x2") suid as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// getresgid(rgid, egid, sgid) - get real, effective, and saved group IDs
///
/// Returns 0 on success, -EFAULT if pointers are invalid.
#[inline(always)]
pub fn sys_getresgid(rgid: *mut u32, egid: *mut u32, sgid: *mut u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_GETRESGID,
            in("x0") rgid as u64,
            in("x1") egid as u64,
            in("x2") sgid as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// setresuid(ruid, euid, suid) - set real, effective, and saved user IDs
///
/// A value of -1 (0xFFFFFFFF) means "don't change this field".
/// Returns 0 on success, -EPERM if not permitted.
#[inline(always)]
pub fn sys_setresuid(ruid: u32, euid: u32, suid: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SETRESUID,
            in("x0") ruid as u64,
            in("x1") euid as u64,
            in("x2") suid as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// setresgid(rgid, egid, sgid) - set real, effective, and saved group IDs
///
/// A value of -1 (0xFFFFFFFF) means "don't change this field".
/// Returns 0 on success, -EPERM if not permitted.
#[inline(always)]
pub fn sys_setresgid(rgid: u32, egid: u32, sgid: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SETRESGID,
            in("x0") rgid as u64,
            in("x1") egid as u64,
            in("x2") sgid as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// setreuid(ruid, euid) - set real and effective user IDs
///
/// A value of -1 (0xFFFFFFFF) means "don't change this field".
/// Returns 0 on success, -EPERM if not permitted.
#[inline(always)]
pub fn sys_setreuid(ruid: u32, euid: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SETREUID,
            in("x0") ruid as u64,
            in("x1") euid as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// setregid(rgid, egid) - set real and effective group IDs
///
/// A value of -1 (0xFFFFFFFF) means "don't change this field".
/// Returns 0 on success, -EPERM if not permitted.
#[inline(always)]
pub fn sys_setregid(rgid: u32, egid: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SETREGID,
            in("x0") rgid as u64,
            in("x1") egid as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// setfsuid(uid) - set filesystem UID
///
/// Returns the OLD fsuid value (not an error code).
/// If permission denied or invalid, returns old fsuid without changing.
#[inline(always)]
pub fn sys_setfsuid(uid: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SETFSUID,
            in("x0") uid as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// setfsgid(gid) - set filesystem GID
///
/// Returns the OLD fsgid value (not an error code).
/// If permission denied or invalid, returns old fsgid without changing.
#[inline(always)]
pub fn sys_setfsgid(gid: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SETFSGID,
            in("x0") gid as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

// ============================================================================
// System information syscalls
// ============================================================================

/// sysinfo(info) - return system information
///
/// Returns system-wide statistics including uptime, memory, and process count.
/// Returns 0 on success, -EFAULT if pointer is invalid.
#[inline(always)]
pub fn sys_sysinfo(info: *mut u8) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SYSINFO,
            in("x0") info as u64,
            lateout("x0") ret,
            // Syscalls may clobber x1-x7, x16, x17 (temporary registers)
            clobber_abi("C"),
        );
    }
    ret
}

/// getrusage(who, usage) - get resource usage
///
/// Returns resource usage for the specified target.
/// `who`: RUSAGE_SELF (0), RUSAGE_CHILDREN (-1), or RUSAGE_THREAD (1)
/// Returns 0 on success, -EINVAL for invalid who, -EFAULT if copy fails.
#[inline(always)]
pub fn sys_getrusage(who: i32, usage: *mut u8) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_GETRUSAGE,
            in("x0") who as u64,
            in("x1") usage as u64,
            lateout("x0") ret,
            // Syscalls may clobber x1-x7, x16, x17 (temporary registers)
            clobber_abi("C"),
        );
    }
    ret
}

/// fcntl(fd, cmd, arg) - file control operations
///
/// Performs various operations on file descriptors.
/// `cmd`: F_DUPFD(0), F_GETFD(1), F_SETFD(2), F_GETFL(3), F_SETFL(4), F_DUPFD_CLOEXEC(1030)
/// Returns new fd for F_DUPFD*, flags for F_GET*, 0 for F_SET*, or negative errno.
#[inline(always)]
pub fn sys_fcntl(fd: i32, cmd: i32, arg: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_FCNTL,
            in("x0") fd as u64,
            in("x1") cmd as u64,
            in("x2") arg,
            lateout("x0") ret,
            clobber_abi("C"),
        );
    }
    ret
}

/// getrandom(buf, buflen, flags) - get random bytes
///
/// Fills buffer with random bytes from kernel CRNG.
/// `flags`: GRND_NONBLOCK(0x01), GRND_RANDOM(0x02), GRND_INSECURE(0x04)
/// Returns number of bytes written, or negative errno.
#[inline(always)]
pub fn sys_getrandom(buf: *mut u8, buflen: usize, flags: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_GETRANDOM,
            in("x0") buf as u64,
            in("x1") buflen as u64,
            in("x2") flags as u64,
            lateout("x0") ret,
            clobber_abi("C"),
        );
    }
    ret
}

// ============================================================================
// Scheduling syscalls
// ============================================================================

/// sched_getscheduler(pid) - get scheduling policy
///
/// Returns the scheduling policy of the specified process.
/// `pid`: Process ID (0 = calling process)
/// Returns policy (SCHED_NORMAL=0, SCHED_FIFO=1, SCHED_RR=2, etc.) or negative errno.
#[inline(always)]
pub fn sys_sched_getscheduler(pid: i64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SCHED_GETSCHEDULER,
            in("x0") pid as u64,
            lateout("x0") ret,
            clobber_abi("C"),
        );
    }
    ret
}

/// sched_setscheduler(pid, policy, param) - set scheduling policy and parameters
///
/// Sets the scheduling policy and parameters for the specified process.
/// `pid`: Process ID (0 = calling process)
/// `policy`: SCHED_NORMAL(0), SCHED_FIFO(1), SCHED_RR(2), etc.
/// `param`: Pointer to sched_param struct (contains sched_priority)
/// Returns 0 on success, or negative errno.
#[inline(always)]
pub fn sys_sched_setscheduler(pid: i64, policy: i32, param: *const super::SchedParam) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SCHED_SETSCHEDULER,
            in("x0") pid as u64,
            in("x1") policy as u64,
            in("x2") param as u64,
            lateout("x0") ret,
            clobber_abi("C"),
        );
    }
    ret
}

/// sched_getparam(pid, param) - get scheduling parameters
///
/// Gets the scheduling parameters for the specified process.
/// `pid`: Process ID (0 = calling process)
/// `param`: Pointer to sched_param struct to fill
/// Returns 0 on success, or negative errno.
#[inline(always)]
pub fn sys_sched_getparam(pid: i64, param: *mut super::SchedParam) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SCHED_GETPARAM,
            in("x0") pid as u64,
            in("x1") param as u64,
            lateout("x0") ret,
            clobber_abi("C"),
        );
    }
    ret
}

/// sched_setparam(pid, param) - set scheduling parameters
///
/// Sets the scheduling parameters for the specified process.
/// `pid`: Process ID (0 = calling process)
/// `param`: Pointer to sched_param struct
/// Returns 0 on success, or negative errno.
#[inline(always)]
pub fn sys_sched_setparam(pid: i64, param: *const super::SchedParam) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SCHED_SETPARAM,
            in("x0") pid as u64,
            in("x1") param as u64,
            lateout("x0") ret,
            clobber_abi("C"),
        );
    }
    ret
}

/// sched_getaffinity(pid, cpusetsize, mask) - get CPU affinity mask
///
/// Gets the CPU affinity mask for the specified process.
/// `pid`: Process ID (0 = calling process)
/// `cpusetsize`: Size of the mask buffer in bytes
/// `mask`: Pointer to buffer for CPU mask
/// Returns number of bytes written on success, or negative errno.
#[inline(always)]
pub fn sys_sched_getaffinity(pid: i64, cpusetsize: usize, mask: *mut u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SCHED_GETAFFINITY,
            in("x0") pid as u64,
            in("x1") cpusetsize as u64,
            in("x2") mask as u64,
            lateout("x0") ret,
            clobber_abi("C"),
        );
    }
    ret
}

/// sched_setaffinity(pid, cpusetsize, mask) - set CPU affinity mask
///
/// Sets the CPU affinity mask for the specified process.
/// `pid`: Process ID (0 = calling process)
/// `cpusetsize`: Size of the mask buffer in bytes
/// `mask`: Pointer to CPU mask
/// Returns 0 on success, or negative errno.
#[inline(always)]
pub fn sys_sched_setaffinity(pid: i64, cpusetsize: usize, mask: *const u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SCHED_SETAFFINITY,
            in("x0") pid as u64,
            in("x1") cpusetsize as u64,
            in("x2") mask as u64,
            lateout("x0") ret,
            clobber_abi("C"),
        );
    }
    ret
}

/// sched_rr_get_interval(pid, tp) - get round-robin time quantum
///
/// Gets the round-robin time quantum for the specified process.
/// `pid`: Process ID (0 = calling process)
/// `tp`: Pointer to timespec struct to fill
/// Returns 0 on success, or negative errno.
#[inline(always)]
pub fn sys_sched_rr_get_interval(pid: i64, tp: *mut Timespec) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SCHED_RR_GET_INTERVAL,
            in("x0") pid as u64,
            in("x1") tp as u64,
            lateout("x0") ret,
            clobber_abi("C"),
        );
    }
    ret
}

// ============================================================================
// Resource limits syscalls
// ============================================================================

/// getrlimit(resource, rlim) - get resource limits
///
/// Gets the soft and hard limits for the specified resource.
/// Returns 0 on success, or negative errno.
#[inline(always)]
pub fn sys_getrlimit(resource: u32, rlim: *mut RLimit) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_GETRLIMIT,
            in("x0") resource as u64,
            in("x1") rlim as u64,
            lateout("x0") ret,
            clobber_abi("C"),
        );
    }
    ret
}

/// setrlimit(resource, rlim) - set resource limits
///
/// Sets the soft and hard limits for the specified resource.
/// Returns 0 on success, or negative errno.
#[inline(always)]
pub fn sys_setrlimit(resource: u32, rlim: *const RLimit) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SETRLIMIT,
            in("x0") resource as u64,
            in("x1") rlim as u64,
            lateout("x0") ret,
            clobber_abi("C"),
        );
    }
    ret
}

/// prlimit64(pid, resource, new_rlim, old_rlim) - get/set resource limits
///
/// Gets and/or sets resource limits for a process.
/// `pid`: Process ID (0 = calling process)
/// `resource`: Resource type (RLIMIT_*)
/// `new_rlim`: New limits (NULL to only get)
/// `old_rlim`: Buffer for old limits (NULL to only set)
/// Returns 0 on success, or negative errno.
#[inline(always)]
pub fn sys_prlimit64(pid: i32, resource: u32, new_rlim: *const RLimit, old_rlim: *mut RLimit) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_PRLIMIT64,
            in("x0") pid as u64,
            in("x1") resource as u64,
            in("x2") new_rlim as u64,
            in("x3") old_rlim as u64,
            lateout("x0") ret,
            clobber_abi("C"),
        );
    }
    ret
}

// ============================================================================
// Namespace syscalls
// ============================================================================

/// Namespace clone flags
pub const CLONE_NEWNS: u64 = 0x0002_0000;
pub const CLONE_NEWUTS: u64 = 0x0400_0000;
pub const CLONE_NEWIPC: u64 = 0x0800_0000;
pub const CLONE_NEWUSER: u64 = 0x1000_0000;
pub const CLONE_NEWPID: u64 = 0x2000_0000;
pub const CLONE_NEWNET: u64 = 0x4000_0000;

/// unshare(flags) - disassociate parts of process execution context
#[inline(always)]
pub fn sys_unshare(flags: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_UNSHARE,
            in("x0") flags,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// setns(fd, nstype) - reassociate thread with a namespace
#[inline(always)]
pub fn sys_setns(fd: i32, nstype: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SETNS,
            in("x0") fd as u64,
            in("x1") nstype as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

// ============================================================================
// Socket syscalls
// ============================================================================

/// socket(domain, type, protocol) - create a socket
///
/// Creates a socket for network communication.
/// Returns file descriptor on success, or negative errno.
#[inline(always)]
pub fn sys_socket(domain: i32, sock_type: i32, protocol: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SOCKET,
            in("x0") domain as u64,
            in("x1") sock_type as u64,
            in("x2") protocol as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// connect(fd, addr, addrlen) - initiate a connection on a socket
///
/// Connects the socket to the address specified.
/// Returns 0 on success, or negative errno.
#[inline(always)]
pub fn sys_connect(fd: i32, addr: *const u8, addrlen: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_CONNECT,
            in("x0") fd as u64,
            in("x1") addr as u64,
            in("x2") addrlen as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// bind(fd, addr, addrlen) - bind a name to a socket
///
/// Assigns the address to the socket.
/// Returns 0 on success, or negative errno.
#[inline(always)]
pub fn sys_bind(fd: i32, addr: *const u8, addrlen: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_BIND,
            in("x0") fd as u64,
            in("x1") addr as u64,
            in("x2") addrlen as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// listen(fd, backlog) - listen for connections on a socket
///
/// Marks the socket as a passive socket for accepting connections.
/// Returns 0 on success, or negative errno.
#[inline(always)]
pub fn sys_listen(fd: i32, backlog: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_LISTEN,
            in("x0") fd as u64,
            in("x1") backlog as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// shutdown(fd, how) - shut down part of a full-duplex connection
///
/// Shuts down the connection. `how`: SHUT_RD(0), SHUT_WR(1), SHUT_RDWR(2)
/// Returns 0 on success, or negative errno.
#[inline(always)]
pub fn sys_shutdown(fd: i32, how: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SHUTDOWN,
            in("x0") fd as u64,
            in("x1") how as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// getsockname(fd, addr, addrlen) - get socket name
///
/// Returns the current address bound to the socket.
/// Returns 0 on success, or negative errno.
#[inline(always)]
pub fn sys_getsockname(fd: i32, addr: *mut u8, addrlen: *mut u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_GETSOCKNAME,
            in("x0") fd as u64,
            in("x1") addr as u64,
            in("x2") addrlen as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// getpeername(fd, addr, addrlen) - get name of connected peer socket
///
/// Returns the address of the peer connected to the socket.
/// Returns 0 on success, or negative errno.
#[inline(always)]
pub fn sys_getpeername(fd: i32, addr: *mut u8, addrlen: *mut u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_GETPEERNAME,
            in("x0") fd as u64,
            in("x1") addr as u64,
            in("x2") addrlen as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// sendto(fd, buf, len, flags, dest_addr, addrlen) - send a message on a socket
///
/// Sends data to a socket. For connected sockets, dest_addr can be NULL.
/// Returns number of bytes sent, or negative errno.
#[inline(always)]
pub fn sys_sendto(fd: i32, buf: *const u8, len: usize, flags: i32, dest_addr: *const u8, addrlen: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SENDTO,
            in("x0") fd as u64,
            in("x1") buf as u64,
            in("x2") len as u64,
            in("x3") flags as u64,
            in("x4") dest_addr as u64,
            in("x5") addrlen as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// recvfrom(fd, buf, len, flags, src_addr, addrlen) - receive a message from a socket
///
/// Receives data from a socket.
/// Returns number of bytes received, or negative errno.
#[inline(always)]
pub fn sys_recvfrom(fd: i32, buf: *mut u8, len: usize, flags: i32, src_addr: *mut u8, addrlen: *mut u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_RECVFROM,
            in("x0") fd as u64,
            in("x1") buf as u64,
            in("x2") len as u64,
            in("x3") flags as u64,
            in("x4") src_addr as u64,
            in("x5") addrlen as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// setsockopt(fd, level, optname, optval, optlen) - set socket options
///
/// Sets options on a socket.
/// Returns 0 on success, or negative errno.
#[inline(always)]
pub fn sys_setsockopt(fd: i32, level: i32, optname: i32, optval: *const u8, optlen: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SETSOCKOPT,
            in("x0") fd as u64,
            in("x1") level as u64,
            in("x2") optname as u64,
            in("x3") optval as u64,
            in("x4") optlen as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// getsockopt(fd, level, optname, optval, optlen) - get socket options
///
/// Gets options on a socket.
/// Returns 0 on success, or negative errno.
#[inline(always)]
pub fn sys_getsockopt(fd: i32, level: i32, optname: i32, optval: *mut u8, optlen: *mut u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_GETSOCKOPT,
            in("x0") fd as u64,
            in("x1") level as u64,
            in("x2") optname as u64,
            in("x3") optval as u64,
            in("x4") optlen as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

// ============================================================================
// Futex syscalls
// ============================================================================

pub const SYS_FUTEX: u64 = 98;
pub const SYS_SET_ROBUST_LIST: u64 = 99;
pub const SYS_GET_ROBUST_LIST: u64 = 100;

/// futex(uaddr, op, val, timeout, uaddr2, val3) - fast userspace mutex
///
/// Performs a futex operation on a userspace futex.
/// Returns depend on operation:
/// - FUTEX_WAIT: 0 on wake, negative errno on error
/// - FUTEX_WAKE: number of waiters woken
/// - FUTEX_REQUEUE: number woken + requeued
#[inline(always)]
pub fn sys_futex(uaddr: *mut u32, op: u32, val: u32, timeout: *const Timespec, uaddr2: *mut u32, val3: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_FUTEX,
            in("x0") uaddr as u64,
            in("x1") op as u64,
            in("x2") val as u64,
            in("x3") timeout as u64,
            in("x4") uaddr2 as u64,
            in("x5") val3 as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// set_robust_list(head, len) - register robust futex list
///
/// Registers the robust futex list for the current task.
/// Returns 0 on success, -EINVAL if len != sizeof(robust_list_head).
#[inline(always)]
pub fn sys_set_robust_list(head: *const super::RobustListHead, len: usize) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SET_ROBUST_LIST,
            in("x0") head as u64,
            in("x1") len as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// get_robust_list(pid, head_ptr, len_ptr) - get robust futex list
///
/// Gets the robust futex list for a task.
/// Returns 0 on success, -ESRCH if task not found.
#[inline(always)]
pub fn sys_get_robust_list(pid: i32, head_ptr: *mut *const super::RobustListHead, len_ptr: *mut usize) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_GET_ROBUST_LIST,
            in("x0") pid as u64,
            in("x1") head_ptr as u64,
            in("x2") len_ptr as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

// ============================================================================
// TLS syscall wrappers
// ============================================================================

/// set_tid_address(tidptr) - set pointer to thread ID
///
/// Sets the clear_child_tid address for the calling thread.
/// When the thread exits, the kernel will write 0 to this address
/// and wake any futex waiters on it (used for pthread_join).
///
/// Returns the caller's thread ID.
#[inline(always)]
pub fn sys_set_tid_address(tidptr: *mut i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SET_TID_ADDRESS,
            in("x0") tidptr as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

// ============================================================================
// SysV IPC syscall wrappers
// ============================================================================

/// shmget(key, size, shmflg) - allocate a shared memory segment
#[inline(always)]
pub fn sys_shmget(key: i32, size: usize, shmflg: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SHMGET,
            in("x0") key as u64,
            in("x1") size as u64,
            in("x2") shmflg as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// shmat(shmid, shmaddr, shmflg) - attach a shared memory segment
#[inline(always)]
pub fn sys_shmat(shmid: i32, shmaddr: u64, shmflg: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SHMAT,
            in("x0") shmid as u64,
            in("x1") shmaddr,
            in("x2") shmflg as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// shmdt(shmaddr) - detach a shared memory segment
#[inline(always)]
pub fn sys_shmdt(shmaddr: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SHMDT,
            in("x0") shmaddr,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// shmctl(shmid, cmd, buf) - shared memory control
#[inline(always)]
pub fn sys_shmctl(shmid: i32, cmd: i32, buf: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SHMCTL,
            in("x0") shmid as u64,
            in("x1") cmd as u64,
            in("x2") buf,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// semget(key, nsems, semflg) - get a semaphore set
#[inline(always)]
pub fn sys_semget(key: i32, nsems: i32, semflg: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SEMGET,
            in("x0") key as u64,
            in("x1") nsems as u64,
            in("x2") semflg as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// semop(semid, sops, nsops) - semaphore operations
#[inline(always)]
pub fn sys_semop(semid: i32, sops: *const super::Sembuf, nsops: usize) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SEMOP,
            in("x0") semid as u64,
            in("x1") sops as u64,
            in("x2") nsops as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// semtimedop(semid, sops, nsops, timeout) - semaphore operations with timeout
#[inline(always)]
pub fn sys_semtimedop(semid: i32, sops: *const super::Sembuf, nsops: usize, timeout: *const Timespec) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SEMTIMEDOP,
            in("x0") semid as u64,
            in("x1") sops as u64,
            in("x2") nsops as u64,
            in("x3") timeout as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// semctl(semid, semnum, cmd, arg) - semaphore control
#[inline(always)]
pub fn sys_semctl(semid: i32, semnum: i32, cmd: i32, arg: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_SEMCTL,
            in("x0") semid as u64,
            in("x1") semnum as u64,
            in("x2") cmd as u64,
            in("x3") arg,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// msgget(key, msgflg) - get a message queue
#[inline(always)]
pub fn sys_msgget(key: i32, msgflg: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_MSGGET,
            in("x0") key as u64,
            in("x1") msgflg as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// msgsnd(msqid, msgp, msgsz, msgflg) - send a message to a queue
#[inline(always)]
pub fn sys_msgsnd(msqid: i32, msgp: *const u8, msgsz: usize, msgflg: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_MSGSND,
            in("x0") msqid as u64,
            in("x1") msgp as u64,
            in("x2") msgsz as u64,
            in("x3") msgflg as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// msgrcv(msqid, msgp, msgsz, msgtyp, msgflg) - receive a message from a queue
#[inline(always)]
pub fn sys_msgrcv(msqid: i32, msgp: *mut u8, msgsz: usize, msgtyp: i64, msgflg: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_MSGRCV,
            in("x0") msqid as u64,
            in("x1") msgp as u64,
            in("x2") msgsz as u64,
            in("x3") msgtyp as u64,
            in("x4") msgflg as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// msgctl(msqid, cmd, buf) - message queue control
#[inline(always)]
pub fn sys_msgctl(msqid: i32, cmd: i32, buf: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_MSGCTL,
            in("x0") msqid as u64,
            in("x1") cmd as u64,
            in("x2") buf,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// ioprio_set(which, who, ioprio) - set I/O priority
#[inline(always)]
pub fn sys_ioprio_set(which: i32, who: i32, ioprio: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_IOPRIO_SET,
            in("x0") which as u64,
            in("x1") who as u64,
            in("x2") ioprio as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// ioprio_get(which, who) - get I/O priority
#[inline(always)]
pub fn sys_ioprio_get(which: i32, who: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_IOPRIO_GET,
            in("x0") which as u64,
            in("x1") who as u64,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

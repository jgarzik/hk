//! x86_64 Linux syscall wrappers
//!
//! This module provides syscall wrappers for the x86_64 architecture.
//!
//! # Calling Convention
//! - Syscall number in RAX
//! - Arguments in RDI, RSI, RDX, R10, R8, R9
//! - Return value in RAX
//! - RCX and R11 are clobbered by the syscall instruction

use super::{FdSet, IoVec, PollFd, SigInfo, Stat, Timespec, Timeval, UtsName};

// ============================================================================
// x86_64 Linux syscall numbers
// ============================================================================

pub const SYS_READ: u64 = 0;
pub const SYS_WRITE: u64 = 1;
pub const SYS_OPEN: u64 = 2;
pub const SYS_PREAD64: u64 = 17;
pub const SYS_PWRITE64: u64 = 18;
pub const SYS_CLOSE: u64 = 3;
pub const SYS_STAT: u64 = 4;
pub const SYS_LSTAT: u64 = 6;
pub const SYS_LSEEK: u64 = 8;
pub const SYS_READV: u64 = 19;
pub const SYS_WRITEV: u64 = 20;
pub const SYS_PREADV: u64 = 295;
pub const SYS_PWRITEV: u64 = 296;
pub const SYS_NANOSLEEP: u64 = 35;
pub const SYS_GETPID: u64 = 39;
pub const SYS_CLONE: u64 = 56;
pub const SYS_FORK: u64 = 57;
pub const SYS_VFORK: u64 = 58;
pub const SYS_EXECVE: u64 = 59;
pub const SYS_EXIT: u64 = 60;
pub const SYS_WAIT4: u64 = 61;
pub const SYS_TRUNCATE: u64 = 76;
pub const SYS_FTRUNCATE: u64 = 77;
pub const SYS_RENAME: u64 = 82;
pub const SYS_MKDIR: u64 = 83;
pub const SYS_RMDIR: u64 = 84;
pub const SYS_LINK: u64 = 86;
pub const SYS_UNLINK: u64 = 87;
pub const SYS_SYMLINK: u64 = 88;
pub const SYS_READLINK: u64 = 89;
pub const SYS_CHMOD: u64 = 90;
pub const SYS_FCHMOD: u64 = 91;
pub const SYS_CHOWN: u64 = 92;
pub const SYS_FCHOWN: u64 = 93;
pub const SYS_LCHOWN: u64 = 94;
pub const SYS_UMASK: u64 = 95;
pub const SYS_GETUID: u64 = 102;
pub const SYS_GETGID: u64 = 104;
pub const SYS_SETUID: u64 = 105;
pub const SYS_SETGID: u64 = 106;
pub const SYS_GETEUID: u64 = 107;
pub const SYS_GETEGID: u64 = 108;
pub const SYS_SETPGID: u64 = 109;
pub const SYS_SETREUID: u64 = 113;
pub const SYS_SETREGID: u64 = 114;
pub const SYS_SETRESUID: u64 = 117;
pub const SYS_GETRESUID: u64 = 118;
pub const SYS_SETRESGID: u64 = 119;
pub const SYS_GETRESGID: u64 = 120;
pub const SYS_SETFSUID: u64 = 122;
pub const SYS_SETFSGID: u64 = 123;
pub const SYS_GETPPID: u64 = 110;
pub const SYS_SETSID: u64 = 112;
pub const SYS_GETPGID: u64 = 121;
pub const SYS_GETSID: u64 = 124;
pub const SYS_MKNOD: u64 = 133;
pub const SYS_REBOOT: u64 = 169;
pub const SYS_GETTID: u64 = 186;
pub const SYS_GETDENTS64: u64 = 217;
pub const SYS_TIME: u64 = 201;
pub const SYS_CLOCK_GETRES: u64 = 229;
pub const SYS_CLOCK_NANOSLEEP: u64 = 230;
pub const SYS_WAITID: u64 = 247;
pub const SYS_FSYNC: u64 = 74;
pub const SYS_FDATASYNC: u64 = 75;
pub const SYS_SYNC: u64 = 162;
pub const SYS_MOUNT: u64 = 165;
pub const SYS_UMOUNT2: u64 = 166;
pub const SYS_UTIMENSAT: u64 = 280;
pub const SYS_SYNCFS: u64 = 306;

// UTS namespace syscalls
pub const SYS_UNAME: u64 = 63;
pub const SYS_SETHOSTNAME: u64 = 170;
pub const SYS_SETDOMAINNAME: u64 = 171;

// Signal syscalls
pub const SYS_RT_SIGACTION: u64 = 13;
pub const SYS_RT_SIGPROCMASK: u64 = 14;
pub const SYS_RT_SIGPENDING: u64 = 127;
pub const SYS_KILL: u64 = 62;
pub const SYS_TGKILL: u64 = 234;
pub const SYS_TKILL: u64 = 200;

// Pipe/poll/select syscalls
pub const SYS_PIPE: u64 = 22;
pub const SYS_PIPE2: u64 = 293;
pub const SYS_POLL: u64 = 7;
pub const SYS_SELECT: u64 = 23;

// Memory management syscalls
pub const SYS_MMAP: u64 = 9;
pub const SYS_MUNMAP: u64 = 11;
pub const SYS_BRK: u64 = 12;

// System information syscalls
pub const SYS_GETCPU: u64 = 309;
pub const SYS_GETRUSAGE: u64 = 98;
pub const SYS_SYSINFO: u64 = 99;
pub const SYS_GETRANDOM: u64 = 318;

// File control
pub const SYS_FCNTL: u64 = 72;

// Scheduling priority syscalls
pub const SYS_GETPRIORITY: u64 = 140;
pub const SYS_SETPRIORITY: u64 = 141;

// Scheduling syscalls
pub const SYS_SCHED_SETPARAM: u64 = 142;
pub const SYS_SCHED_GETPARAM: u64 = 143;
pub const SYS_SCHED_SETSCHEDULER: u64 = 144;
pub const SYS_SCHED_GETSCHEDULER: u64 = 145;
pub const SYS_SCHED_RR_GET_INTERVAL: u64 = 148;
pub const SYS_SCHED_SETAFFINITY: u64 = 203;
pub const SYS_SCHED_GETAFFINITY: u64 = 204;

// ============================================================================
// Syscall wrapper functions
// ============================================================================

/// write(fd, buf, len)
#[inline(always)]
pub fn sys_write(fd: u64, buf: *const u8, len: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_WRITE,
            in("rdi") fd,
            in("rsi") buf,
            in("rdx") len,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_READ,
            in("rdi") fd,
            in("rsi") buf,
            in("rdx") len,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// open(path, flags, mode)
#[inline(always)]
pub fn sys_open(path: *const u8, flags: u32, mode: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_OPEN,
            in("rdi") path,
            in("rsi") flags as u64,
            in("rdx") mode as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// close(fd)
#[inline(always)]
pub fn sys_close(fd: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_CLOSE,
            in("rdi") fd,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_GETPID,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_GETPPID,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_GETUID,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_GETEUID,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_GETGID,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_GETEGID,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_GETPGID,
            in("rdi") pid,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_GETSID,
            in("rdi") pid,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_SETPGID,
            in("rdi") pid,
            in("rsi") pgid,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_SETSID,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_GETTID,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_CLONE,
            in("rdi") flags,
            in("rsi") child_stack,
            in("rdx") parent_tidptr,
            in("r10") child_tidptr,
            in("r8") tls,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// wait4(pid, wstatus, options, rusage)
#[inline(always)]
pub fn sys_wait4(pid: i64, wstatus: *mut i32, options: i32, rusage: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_WAIT4,
            in("rdi") pid as u64,
            in("rsi") wstatus as u64,
            in("rdx") options as u64,
            in("r10") rusage,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_GETDENTS64,
            in("rdi") fd,
            in("rsi") dirp,
            in("rdx") count,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_NANOSLEEP,
            in("rdi") req,
            in("rsi") rem,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_CLOCK_NANOSLEEP,
            in("rdi") clockid as u64,
            in("rsi") flags as u64,
            in("rdx") req,
            in("r10") rem,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_CLOCK_GETRES,
            in("rdi") clockid as u64,
            in("rsi") res,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// time(tloc) - get time in seconds since epoch
#[inline(always)]
pub fn sys_time(tloc: *mut i64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_TIME,
            in("rdi") tloc as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// fork()
#[inline(always)]
pub fn sys_fork() -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_FORK,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// vfork()
#[inline(always)]
pub fn sys_vfork() -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_VFORK,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_WAITID,
            in("rdi") idtype as u64,
            in("rsi") id,
            in("rdx") infop as u64,
            in("r10") options as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_EXECVE,
            in("rdi") pathname as u64,
            in("rsi") argv as u64,
            in("rdx") envp as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_READV,
            in("rdi") fd,
            in("rsi") iov,
            in("rdx") iovcnt,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_WRITEV,
            in("rdi") fd,
            in("rsi") iov,
            in("rdx") iovcnt,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_PREAD64,
            in("rdi") fd as u64,
            in("rsi") buf,
            in("rdx") count,
            in("r10") offset as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_PWRITE64,
            in("rdi") fd as u64,
            in("rsi") buf,
            in("rdx") count,
            in("r10") offset as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_PREADV,
            in("rdi") fd as u64,
            in("rsi") iov,
            in("rdx") iovcnt as u64,
            in("r10") offset as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_PWRITEV,
            in("rdi") fd as u64,
            in("rsi") iov,
            in("rdx") iovcnt as u64,
            in("r10") offset as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// mkdir(pathname, mode)
#[inline(always)]
pub fn sys_mkdir(pathname: *const u8, mode: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_MKDIR,
            in("rdi") pathname,
            in("rsi") mode as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// rmdir(pathname)
#[inline(always)]
pub fn sys_rmdir(pathname: *const u8) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_RMDIR,
            in("rdi") pathname,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// mknod(pathname, mode, dev)
#[inline(always)]
pub fn sys_mknod(pathname: *const u8, mode: u32, dev: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_MKNOD,
            in("rdi") pathname,
            in("rsi") mode as u64,
            in("rdx") dev,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// symlink(target, linkpath)
#[inline(always)]
pub fn sys_symlink(target: *const u8, linkpath: *const u8) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_SYMLINK,
            in("rdi") target,
            in("rsi") linkpath,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// readlink(pathname, buf, bufsiz)
#[inline(always)]
pub fn sys_readlink(pathname: *const u8, buf: *mut u8, bufsiz: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_READLINK,
            in("rdi") pathname,
            in("rsi") buf,
            in("rdx") bufsiz,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// link(oldpath, newpath)
#[inline(always)]
pub fn sys_link(oldpath: *const u8, newpath: *const u8) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_LINK,
            in("rdi") oldpath,
            in("rsi") newpath,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// unlink(pathname)
pub fn sys_unlink(pathname: *const u8) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_UNLINK,
            in("rdi") pathname,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// lseek(fd, offset, whence)
pub fn sys_lseek(fd: i32, offset: i64, whence: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_LSEEK,
            in("rdi") fd,
            in("rsi") offset,
            in("rdx") whence,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_FTRUNCATE,
            in("rdi") fd,
            in("rsi") length,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// truncate(pathname, length)
pub fn sys_truncate(pathname: *const u8, length: i64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_TRUNCATE,
            in("rdi") pathname,
            in("rsi") length,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// chmod(pathname, mode)
pub fn sys_chmod(pathname: *const u8, mode: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_CHMOD,
            in("rdi") pathname,
            in("rsi") mode as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// fchmod(fd, mode)
pub fn sys_fchmod(fd: i32, mode: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_FCHMOD,
            in("rdi") fd as u64,
            in("rsi") mode as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// chown(pathname, owner, group)
pub fn sys_chown(pathname: *const u8, owner: u32, group: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_CHOWN,
            in("rdi") pathname as u64,
            in("rsi") owner as u64,
            in("rdx") group as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// fchown(fd, owner, group)
pub fn sys_fchown(fd: i32, owner: u32, group: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_FCHOWN,
            in("rdi") fd as u64,
            in("rsi") owner as u64,
            in("rdx") group as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// lchown(pathname, owner, group)
pub fn sys_lchown(pathname: *const u8, owner: u32, group: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_LCHOWN,
            in("rdi") pathname as u64,
            in("rsi") owner as u64,
            in("rdx") group as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// stat(pathname, statbuf)
pub fn sys_stat(pathname: *const u8, statbuf: *mut Stat) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_STAT,
            in("rdi") pathname,
            in("rsi") statbuf,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// lstat(pathname, statbuf)
pub fn sys_lstat(pathname: *const u8, statbuf: *mut Stat) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_LSTAT,
            in("rdi") pathname,
            in("rsi") statbuf,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// umask(mask)
pub fn sys_umask(mask: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_UMASK,
            in("rdi") mask as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_UTIMENSAT,
            in("rdi") dirfd as u64,
            in("rsi") pathname as u64,
            in("rdx") times as u64,
            in("r10") flags as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// rename(oldpath, newpath)
pub fn sys_rename(oldpath: *const u8, newpath: *const u8) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_RENAME,
            in("rdi") oldpath as u64,
            in("rsi") newpath as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// mount(source, target, fstype, flags, data)
pub fn sys_mount(source: *const u8, target: *const u8, fstype: *const u8, flags: u64, data: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_MOUNT,
            in("rdi") source,
            in("rsi") target,
            in("rdx") fstype,
            in("r10") flags,
            in("r8") data,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_UMOUNT2,
            in("rdi") target,
            in("rsi") flags,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_REBOOT,
            in("rdi") magic1,
            in("rsi") magic2,
            in("rdx") cmd,
            in("r10") 0u64,  // arg (unused for power off)
            options(noreturn, nostack),
        );
    }
}

/// exit(status) - does not return
#[inline(always)]
pub fn sys_exit(status: u64) -> ! {
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_EXIT,
            in("rdi") status,
            options(noreturn, nostack),
        );
    }
}

/// sync() - sync all filesystems
#[inline(always)]
pub fn sys_sync() -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_SYNC,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// fsync(fd) - sync file data and metadata
#[inline(always)]
pub fn sys_fsync(fd: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_FSYNC,
            in("rdi") fd as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// fdatasync(fd) - sync file data only
#[inline(always)]
pub fn sys_fdatasync(fd: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_FDATASYNC,
            in("rdi") fd as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// syncfs(fd) - sync filesystem containing fd
#[inline(always)]
pub fn sys_syncfs(fd: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_SYNCFS,
            in("rdi") fd as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
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
            "syscall",
            in("rax") SYS_UNAME,
            in("rdi") buf as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_SETHOSTNAME,
            in("rdi") name as u64,
            in("rsi") len,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_SETDOMAINNAME,
            in("rdi") name as u64,
            in("rsi") len,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_RT_SIGACTION,
            in("rdi") sig as u64,
            in("rsi") act,
            in("rdx") oact,
            in("r10") sigsetsize,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_RT_SIGPROCMASK,
            in("rdi") how as u64,
            in("rsi") set,
            in("rdx") oset,
            in("r10") sigsetsize,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_RT_SIGPENDING,
            in("rdi") set,
            in("rsi") sigsetsize,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_KILL,
            in("rdi") pid as u64,
            in("rsi") sig as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_TGKILL,
            in("rdi") tgid as u64,
            in("rsi") tid as u64,
            in("rdx") sig as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_TKILL,
            in("rdi") tid as u64,
            in("rsi") sig as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

// ============================================================================
// Pipe/Poll/Select syscalls
// ============================================================================

/// pipe(pipefd) - create a pipe
#[inline(always)]
pub fn sys_pipe(pipefd: *mut i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_PIPE,
            in("rdi") pipefd as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// pipe2(pipefd, flags) - create a pipe with flags
#[inline(always)]
pub fn sys_pipe2(pipefd: *mut i32, flags: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_PIPE2,
            in("rdi") pipefd as u64,
            in("rsi") flags as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// poll(fds, nfds, timeout) - wait for events on file descriptors
#[inline(always)]
pub fn sys_poll(fds: *mut PollFd, nfds: u32, timeout: i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_POLL,
            in("rdi") fds as u64,
            in("rsi") nfds as u64,
            in("rdx") timeout as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// select(nfds, readfds, writefds, exceptfds, timeout) - synchronous I/O multiplexing
#[inline(always)]
pub fn sys_select(nfds: i32, readfds: *mut FdSet, writefds: *mut FdSet, exceptfds: *mut FdSet, timeout: *mut Timeval) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_SELECT,
            in("rdi") nfds as u64,
            in("rsi") readfds as u64,
            in("rdx") writefds as u64,
            in("r10") exceptfds as u64,
            in("r8") timeout as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
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
            "syscall",
            in("rax") SYS_MMAP,
            in("rdi") addr,
            in("rsi") length,
            in("rdx") prot as u64,
            in("r10") flags as u64,
            in("r8") fd as u64,
            in("r9") offset,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_MUNMAP,
            in("rdi") addr,
            in("rsi") length,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_BRK,
            in("rdi") addr,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_GETCPU,
            in("rdi") cpup,
            in("rsi") nodep,
            in("rdx") 0u64, // unused third parameter (legacy tcache)
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_GETPRIORITY,
            in("rdi") which as u64,
            in("rsi") who,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_SETPRIORITY,
            in("rdi") which as u64,
            in("rsi") who,
            in("rdx") niceval as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_SETUID,
            in("rdi") uid as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_SETGID,
            in("rdi") gid as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_GETRESUID,
            in("rdi") ruid as u64,
            in("rsi") euid as u64,
            in("rdx") suid as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_GETRESGID,
            in("rdi") rgid as u64,
            in("rsi") egid as u64,
            in("rdx") sgid as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_SETRESUID,
            in("rdi") ruid as u64,
            in("rsi") euid as u64,
            in("rdx") suid as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_SETRESGID,
            in("rdi") rgid as u64,
            in("rsi") egid as u64,
            in("rdx") sgid as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_SETREUID,
            in("rdi") ruid as u64,
            in("rsi") euid as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_SETREGID,
            in("rdi") rgid as u64,
            in("rsi") egid as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_SETFSUID,
            in("rdi") uid as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_SETFSGID,
            in("rdi") gid as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") SYS_SYSINFO,
            in("rdi") info as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
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
            "syscall",
            in("rax") SYS_GETRUSAGE,
            in("rdi") who as u64,
            in("rsi") usage as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
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
            "syscall",
            in("rax") SYS_FCNTL,
            in("rdi") fd as u64,
            in("rsi") cmd as u64,
            in("rdx") arg,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
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
            "syscall",
            in("rax") SYS_GETRANDOM,
            in("rdi") buf as u64,
            in("rsi") buflen as u64,
            in("rdx") flags as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
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
            "syscall",
            in("rax") SYS_SCHED_GETSCHEDULER,
            in("rdi") pid as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
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
            "syscall",
            in("rax") SYS_SCHED_SETSCHEDULER,
            in("rdi") pid as u64,
            in("rsi") policy as u64,
            in("rdx") param as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
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
            "syscall",
            in("rax") SYS_SCHED_GETPARAM,
            in("rdi") pid as u64,
            in("rsi") param as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
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
            "syscall",
            in("rax") SYS_SCHED_SETPARAM,
            in("rdi") pid as u64,
            in("rsi") param as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
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
            "syscall",
            in("rax") SYS_SCHED_GETAFFINITY,
            in("rdi") pid as u64,
            in("rsi") cpusetsize as u64,
            in("rdx") mask as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
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
            "syscall",
            in("rax") SYS_SCHED_SETAFFINITY,
            in("rdi") pid as u64,
            in("rsi") cpusetsize as u64,
            in("rdx") mask as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
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
            "syscall",
            in("rax") SYS_SCHED_RR_GET_INTERVAL,
            in("rdi") pid as u64,
            in("rsi") tp as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

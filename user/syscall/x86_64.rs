//! x86_64 Linux syscall wrappers
//!
//! This module provides syscall wrappers for the x86_64 architecture.
//!
//! # Calling Convention
//! - Syscall number in RAX
//! - Arguments in RDI, RSI, RDX, R10, R8, R9
//! - Return value in RAX
//! - RCX and R11 are clobbered by the syscall instruction

use crate::types::{FdSet, IoVec, PollFd, RLimit, SigInfo, Stat, Timespec, Timeval, UtsName};

// ============================================================================
// Syscall helper macros
// ============================================================================

/// Raw syscall with 0 arguments
macro_rules! syscall0 {
    ($nr:expr) => {{
        let ret: i64;
        core::arch::asm!(
            "syscall",
            in("rax") $nr,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") $nr,
            in("rdi") $a0 as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") $nr,
            in("rdi") $a0 as u64,
            in("rsi") $a1 as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") $nr,
            in("rdi") $a0 as u64,
            in("rsi") $a1 as u64,
            in("rdx") $a2 as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") $nr,
            in("rdi") $a0 as u64,
            in("rsi") $a1 as u64,
            in("rdx") $a2 as u64,
            in("r10") $a3 as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") $nr,
            in("rdi") $a0 as u64,
            in("rsi") $a1 as u64,
            in("rdx") $a2 as u64,
            in("r10") $a3 as u64,
            in("r8") $a4 as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
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
            "syscall",
            in("rax") $nr,
            in("rdi") $a0 as u64,
            in("rsi") $a1 as u64,
            in("rdx") $a2 as u64,
            in("r10") $a3 as u64,
            in("r8") $a4 as u64,
            in("r9") $a5 as u64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
        ret
    }};
}

// ============================================================================
// x86_64 Linux syscall numbers
// ============================================================================

pub const SYS_READ: u64 = 0;
pub const SYS_WRITE: u64 = 1;
pub const SYS_OPEN: u64 = 2;
pub const SYS_CLOSE: u64 = 3;
pub const SYS_STAT: u64 = 4;
pub const SYS_LSTAT: u64 = 6;
pub const SYS_POLL: u64 = 7;
pub const SYS_LSEEK: u64 = 8;
pub const SYS_MMAP: u64 = 9;
pub const SYS_MPROTECT: u64 = 10;
pub const SYS_MUNMAP: u64 = 11;
pub const SYS_BRK: u64 = 12;
pub const SYS_RT_SIGACTION: u64 = 13;
pub const SYS_RT_SIGPROCMASK: u64 = 14;
pub const SYS_IOCTL: u64 = 16;
pub const SYS_PREAD64: u64 = 17;
pub const SYS_PWRITE64: u64 = 18;
pub const SYS_READV: u64 = 19;
pub const SYS_WRITEV: u64 = 20;
pub const SYS_PIPE: u64 = 22;
pub const SYS_SELECT: u64 = 23;
pub const SYS_MREMAP: u64 = 25;
pub const SYS_MSYNC: u64 = 26;
pub const SYS_MINCORE: u64 = 27;
pub const SYS_MADVISE: u64 = 28;
pub const SYS_SHMGET: u64 = 29;
pub const SYS_SHMAT: u64 = 30;
pub const SYS_SHMCTL: u64 = 31;
pub const SYS_NANOSLEEP: u64 = 35;
pub const SYS_GETPID: u64 = 39;
pub const SYS_SOCKET: u64 = 41;
pub const SYS_CONNECT: u64 = 42;
pub const SYS_SENDTO: u64 = 44;
pub const SYS_RECVFROM: u64 = 45;
pub const SYS_SHUTDOWN: u64 = 48;
pub const SYS_BIND: u64 = 49;
pub const SYS_LISTEN: u64 = 50;
pub const SYS_GETSOCKNAME: u64 = 51;
pub const SYS_GETPEERNAME: u64 = 52;
pub const SYS_SETSOCKOPT: u64 = 54;
pub const SYS_GETSOCKOPT: u64 = 55;
pub const SYS_CLONE: u64 = 56;
pub const SYS_FORK: u64 = 57;
pub const SYS_VFORK: u64 = 58;
pub const SYS_EXECVE: u64 = 59;
pub const SYS_EXIT: u64 = 60;
pub const SYS_WAIT4: u64 = 61;
pub const SYS_KILL: u64 = 62;
pub const SYS_UNAME: u64 = 63;
pub const SYS_SEMGET: u64 = 64;
pub const SYS_SEMOP: u64 = 65;
pub const SYS_SEMCTL: u64 = 66;
pub const SYS_SHMDT: u64 = 67;
pub const SYS_MSGGET: u64 = 68;
pub const SYS_MSGSND: u64 = 69;
pub const SYS_MSGRCV: u64 = 70;
pub const SYS_MSGCTL: u64 = 71;
pub const SYS_FCNTL: u64 = 72;
pub const SYS_FSYNC: u64 = 74;
pub const SYS_FDATASYNC: u64 = 75;
pub const SYS_TRUNCATE: u64 = 76;
pub const SYS_FTRUNCATE: u64 = 77;
pub const SYS_GETDENTS64: u64 = 217;
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
pub const SYS_GETRLIMIT: u64 = 97;
pub const SYS_GETRUSAGE: u64 = 98;
pub const SYS_SYSINFO: u64 = 99;
pub const SYS_GETUID: u64 = 102;
pub const SYS_GETGID: u64 = 104;
pub const SYS_SETUID: u64 = 105;
pub const SYS_SETGID: u64 = 106;
pub const SYS_GETEUID: u64 = 107;
pub const SYS_GETEGID: u64 = 108;
pub const SYS_SETPGID: u64 = 109;
pub const SYS_GETPPID: u64 = 110;
pub const SYS_SETSID: u64 = 112;
pub const SYS_SETREUID: u64 = 113;
pub const SYS_SETREGID: u64 = 114;
pub const SYS_SETRESUID: u64 = 117;
pub const SYS_GETRESUID: u64 = 118;
pub const SYS_SETRESGID: u64 = 119;
pub const SYS_GETRESGID: u64 = 120;
pub const SYS_GETPGID: u64 = 121;
pub const SYS_SETFSUID: u64 = 122;
pub const SYS_SETFSGID: u64 = 123;
pub const SYS_GETSID: u64 = 124;
pub const SYS_RT_SIGPENDING: u64 = 127;
pub const SYS_MKNOD: u64 = 133;
pub const SYS_GETPRIORITY: u64 = 140;
pub const SYS_SETPRIORITY: u64 = 141;
pub const SYS_SCHED_SETPARAM: u64 = 142;
pub const SYS_SCHED_GETPARAM: u64 = 143;
pub const SYS_SCHED_SETSCHEDULER: u64 = 144;
pub const SYS_SCHED_GETSCHEDULER: u64 = 145;
pub const SYS_SCHED_RR_GET_INTERVAL: u64 = 148;
pub const SYS_MLOCK: u64 = 149;
pub const SYS_MUNLOCK: u64 = 150;
pub const SYS_MLOCKALL: u64 = 151;
pub const SYS_MUNLOCKALL: u64 = 152;
pub const SYS_ARCH_PRCTL: u64 = 158;
pub const SYS_SETRLIMIT: u64 = 160;
pub const SYS_SYNC: u64 = 162;
pub const SYS_MOUNT: u64 = 165;
pub const SYS_UMOUNT2: u64 = 166;
pub const SYS_REBOOT: u64 = 169;
pub const SYS_SETHOSTNAME: u64 = 170;
pub const SYS_SETDOMAINNAME: u64 = 171;
pub const SYS_GETTID: u64 = 186;
pub const SYS_TKILL: u64 = 200;
pub const SYS_TIME: u64 = 201;
pub const SYS_FUTEX: u64 = 202;
pub const SYS_SCHED_SETAFFINITY: u64 = 203;
pub const SYS_SCHED_GETAFFINITY: u64 = 204;
pub const SYS_SET_TID_ADDRESS: u64 = 218;
pub const SYS_SEMTIMEDOP: u64 = 220;
pub const SYS_CLOCK_SETTIME: u64 = 227;
pub const SYS_CLOCK_GETTIME: u64 = 228;
pub const SYS_CLOCK_GETRES: u64 = 229;
pub const SYS_CLOCK_NANOSLEEP: u64 = 230;
pub const SYS_TIMERFD_CREATE: u64 = 283;
pub const SYS_TIMERFD_SETTIME: u64 = 286;
pub const SYS_TIMERFD_GETTIME: u64 = 287;

// POSIX timer syscalls (Section 6.2)
pub const SYS_TIMER_CREATE: u64 = 222;
pub const SYS_TIMER_SETTIME: u64 = 223;
pub const SYS_TIMER_GETTIME: u64 = 224;
pub const SYS_TIMER_GETOVERRUN: u64 = 225;
pub const SYS_TIMER_DELETE: u64 = 226;
pub const SYS_GETTIMEOFDAY: u64 = 96;
pub const SYS_SETTIMEOFDAY: u64 = 164;
pub const SYS_TGKILL: u64 = 234;
pub const SYS_WAITID: u64 = 247;
pub const SYS_IOPRIO_SET: u64 = 251;
pub const SYS_IOPRIO_GET: u64 = 252;
pub const SYS_UNSHARE: u64 = 272;
pub const SYS_SET_ROBUST_LIST: u64 = 273;
pub const SYS_GET_ROBUST_LIST: u64 = 274;
pub const SYS_UTIMENSAT: u64 = 280;
pub const SYS_PIPE2: u64 = 293;
pub const SYS_PREADV: u64 = 295;
pub const SYS_PWRITEV: u64 = 296;
pub const SYS_PREADV2: u64 = 327;
pub const SYS_PWRITEV2: u64 = 328;
pub const SYS_PRLIMIT64: u64 = 302;
pub const SYS_SYNCFS: u64 = 306;
pub const SYS_SETNS: u64 = 308;
pub const SYS_GETCPU: u64 = 309;
pub const SYS_GETRANDOM: u64 = 318;
pub const SYS_MLOCK2: u64 = 325;
pub const SYS_SENDFILE: u64 = 40;
pub const SYS_SPLICE: u64 = 275;
pub const SYS_TEE: u64 = 276;
pub const SYS_VMSPLICE: u64 = 278;
pub const SYS_STATFS: u64 = 137;
pub const SYS_FSTATFS: u64 = 138;
pub const SYS_STATX: u64 = 332;
pub const SYS_CHROOT: u64 = 161;
pub const SYS_FCHMODAT2: u64 = 452;

// Extended attributes syscalls
pub const SYS_SETXATTR: u64 = 188;
pub const SYS_LSETXATTR: u64 = 189;
pub const SYS_FSETXATTR: u64 = 190;
pub const SYS_GETXATTR: u64 = 191;
pub const SYS_LGETXATTR: u64 = 192;
pub const SYS_FGETXATTR: u64 = 193;
pub const SYS_LISTXATTR: u64 = 194;
pub const SYS_LLISTXATTR: u64 = 195;
pub const SYS_FLISTXATTR: u64 = 196;
pub const SYS_REMOVEXATTR: u64 = 197;
pub const SYS_LREMOVEXATTR: u64 = 198;
pub const SYS_FREMOVEXATTR: u64 = 199;

// xattr flags
pub const XATTR_CREATE: i32 = 0x1;
pub const XATTR_REPLACE: i32 = 0x2;

// arch_prctl operation codes
pub const ARCH_SET_GS: i32 = 0x1001;
pub const ARCH_SET_FS: i32 = 0x1002;
pub const ARCH_GET_FS: i32 = 0x1003;
pub const ARCH_GET_GS: i32 = 0x1004;

// ============================================================================
// Syscall wrapper functions
// ============================================================================

// --- File I/O ---

#[inline(always)]
pub fn sys_write(fd: u64, buf: *const u8, len: u64) -> i64 {
    unsafe { syscall3!(SYS_WRITE, fd, buf, len) }
}

#[inline(always)]
pub fn sys_read(fd: u64, buf: *mut u8, len: u64) -> i64 {
    unsafe { syscall3!(SYS_READ, fd, buf, len) }
}

#[inline(always)]
pub fn sys_open(path: *const u8, flags: u32, mode: u32) -> i64 {
    unsafe { syscall3!(SYS_OPEN, path, flags, mode) }
}

#[inline(always)]
pub fn sys_close(fd: u64) -> i64 {
    unsafe { syscall1!(SYS_CLOSE, fd) }
}

#[inline(always)]
pub fn sys_lseek(fd: i32, offset: i64, whence: i32) -> i64 {
    unsafe { syscall3!(SYS_LSEEK, fd, offset, whence) }
}

#[inline(always)]
pub fn sys_readv(fd: u64, iov: *const IoVec, iovcnt: u64) -> i64 {
    unsafe { syscall3!(SYS_READV, fd, iov, iovcnt) }
}

#[inline(always)]
pub fn sys_writev(fd: u64, iov: *const IoVec, iovcnt: u64) -> i64 {
    unsafe { syscall3!(SYS_WRITEV, fd, iov, iovcnt) }
}

#[inline(always)]
pub fn sys_pread64(fd: i32, buf: *mut u8, count: u64, offset: i64) -> i64 {
    unsafe { syscall4!(SYS_PREAD64, fd, buf, count, offset) }
}

#[inline(always)]
pub fn sys_pwrite64(fd: i32, buf: *const u8, count: u64, offset: i64) -> i64 {
    unsafe { syscall4!(SYS_PWRITE64, fd, buf, count, offset) }
}

#[inline(always)]
pub fn sys_preadv(fd: i32, iov: *const IoVec, iovcnt: i32, offset: i64) -> i64 {
    unsafe { syscall4!(SYS_PREADV, fd, iov, iovcnt, offset) }
}

#[inline(always)]
pub fn sys_pwritev(fd: i32, iov: *const IoVec, iovcnt: i32, offset: i64) -> i64 {
    unsafe { syscall4!(SYS_PWRITEV, fd, iov, iovcnt, offset) }
}

#[inline(always)]
pub fn sys_preadv2(fd: i32, iov: *const IoVec, iovcnt: i32, offset: i64, flags: i32) -> i64 {
    unsafe { syscall5!(SYS_PREADV2, fd, iov, iovcnt, offset, flags) }
}

#[inline(always)]
pub fn sys_pwritev2(fd: i32, iov: *const IoVec, iovcnt: i32, offset: i64, flags: i32) -> i64 {
    unsafe { syscall5!(SYS_PWRITEV2, fd, iov, iovcnt, offset, flags) }
}

#[inline(always)]
pub fn sys_getdents64(fd: u64, dirp: *mut u8, count: u64) -> i64 {
    unsafe { syscall3!(SYS_GETDENTS64, fd, dirp, count) }
}

#[inline(always)]
pub fn sys_fcntl(fd: i32, cmd: i32, arg: u64) -> i64 {
    unsafe { syscall3!(SYS_FCNTL, fd, cmd, arg) }
}

#[inline(always)]
pub fn sys_ioctl(fd: i32, request: u64, arg: u64) -> i64 {
    unsafe { syscall3!(SYS_IOCTL, fd, request, arg) }
}

#[inline(always)]
pub fn sys_getrandom(buf: *mut u8, buflen: usize, flags: u32) -> i64 {
    unsafe { syscall3!(SYS_GETRANDOM, buf, buflen, flags) }
}

// --- File/Directory Operations ---

#[inline(always)]
pub fn sys_mkdir(pathname: *const u8, mode: u32) -> i64 {
    unsafe { syscall2!(SYS_MKDIR, pathname, mode) }
}

#[inline(always)]
pub fn sys_rmdir(pathname: *const u8) -> i64 {
    unsafe { syscall1!(SYS_RMDIR, pathname) }
}

#[inline(always)]
pub fn sys_mknod(pathname: *const u8, mode: u32, dev: u64) -> i64 {
    unsafe { syscall3!(SYS_MKNOD, pathname, mode, dev) }
}

#[inline(always)]
pub fn sys_symlink(target: *const u8, linkpath: *const u8) -> i64 {
    unsafe { syscall2!(SYS_SYMLINK, target, linkpath) }
}

#[inline(always)]
pub fn sys_readlink(pathname: *const u8, buf: *mut u8, bufsiz: u64) -> i64 {
    unsafe { syscall3!(SYS_READLINK, pathname, buf, bufsiz) }
}

#[inline(always)]
pub fn sys_link(oldpath: *const u8, newpath: *const u8) -> i64 {
    unsafe { syscall2!(SYS_LINK, oldpath, newpath) }
}

#[inline(always)]
pub fn sys_unlink(pathname: *const u8) -> i64 {
    unsafe { syscall1!(SYS_UNLINK, pathname) }
}

#[inline(always)]
pub fn sys_rename(oldpath: *const u8, newpath: *const u8) -> i64 {
    unsafe { syscall2!(SYS_RENAME, oldpath, newpath) }
}

#[inline(always)]
pub fn sys_ftruncate(fd: i32, length: i64) -> i64 {
    unsafe { syscall2!(SYS_FTRUNCATE, fd, length) }
}

#[inline(always)]
pub fn sys_truncate(pathname: *const u8, length: i64) -> i64 {
    unsafe { syscall2!(SYS_TRUNCATE, pathname, length) }
}

// --- File Permissions/Ownership ---

#[inline(always)]
pub fn sys_chmod(pathname: *const u8, mode: u32) -> i64 {
    unsafe { syscall2!(SYS_CHMOD, pathname, mode) }
}

#[inline(always)]
pub fn sys_fchmod(fd: i32, mode: u32) -> i64 {
    unsafe { syscall2!(SYS_FCHMOD, fd, mode) }
}

#[inline(always)]
pub fn sys_chown(pathname: *const u8, owner: u32, group: u32) -> i64 {
    unsafe { syscall3!(SYS_CHOWN, pathname, owner, group) }
}

#[inline(always)]
pub fn sys_fchown(fd: i32, owner: u32, group: u32) -> i64 {
    unsafe { syscall3!(SYS_FCHOWN, fd, owner, group) }
}

#[inline(always)]
pub fn sys_lchown(pathname: *const u8, owner: u32, group: u32) -> i64 {
    unsafe { syscall3!(SYS_LCHOWN, pathname, owner, group) }
}

#[inline(always)]
pub fn sys_umask(mask: u32) -> i64 {
    unsafe { syscall1!(SYS_UMASK, mask) }
}

#[inline(always)]
pub fn sys_chroot(pathname: *const u8) -> i64 {
    unsafe { syscall1!(SYS_CHROOT, pathname) }
}

#[inline(always)]
pub fn sys_fchmodat2(dirfd: i32, pathname: *const u8, mode: u32, flags: i32) -> i64 {
    unsafe { syscall4!(SYS_FCHMODAT2, dirfd, pathname, mode, flags) }
}

// --- File Stats ---

#[inline(always)]
pub fn sys_stat(pathname: *const u8, statbuf: *mut Stat) -> i64 {
    unsafe { syscall2!(SYS_STAT, pathname, statbuf) }
}

#[inline(always)]
pub fn sys_lstat(pathname: *const u8, statbuf: *mut Stat) -> i64 {
    unsafe { syscall2!(SYS_LSTAT, pathname, statbuf) }
}

#[inline(always)]
pub fn sys_utimensat(dirfd: i32, pathname: *const u8, times: *const Timespec, flags: i32) -> i64 {
    unsafe { syscall4!(SYS_UTIMENSAT, dirfd, pathname, times, flags) }
}

// --- Filesystem Operations ---

#[inline(always)]
pub fn sys_mount(source: *const u8, target: *const u8, fstype: *const u8, flags: u64, data: u64) -> i64 {
    unsafe { syscall5!(SYS_MOUNT, source, target, fstype, flags, data) }
}

#[inline(always)]
pub fn sys_umount2(target: *const u8, flags: u64) -> i64 {
    unsafe { syscall2!(SYS_UMOUNT2, target, flags) }
}

#[inline(always)]
pub fn sys_sync() -> i64 {
    unsafe { syscall0!(SYS_SYNC) }
}

#[inline(always)]
pub fn sys_fsync(fd: i32) -> i64 {
    unsafe { syscall1!(SYS_FSYNC, fd) }
}

#[inline(always)]
pub fn sys_fdatasync(fd: i32) -> i64 {
    unsafe { syscall1!(SYS_FDATASYNC, fd) }
}

#[inline(always)]
pub fn sys_syncfs(fd: i32) -> i64 {
    unsafe { syscall1!(SYS_SYNCFS, fd) }
}

// --- Process Management ---

#[inline(always)]
pub fn sys_getpid() -> i64 {
    unsafe { syscall0!(SYS_GETPID) }
}

#[inline(always)]
pub fn sys_getppid() -> i64 {
    unsafe { syscall0!(SYS_GETPPID) }
}

#[inline(always)]
pub fn sys_gettid() -> i64 {
    unsafe { syscall0!(SYS_GETTID) }
}

#[inline(always)]
pub fn sys_getpgid(pid: u64) -> i64 {
    unsafe { syscall1!(SYS_GETPGID, pid) }
}

#[inline(always)]
pub fn sys_getsid(pid: u64) -> i64 {
    unsafe { syscall1!(SYS_GETSID, pid) }
}

#[inline(always)]
pub fn sys_setpgid(pid: u64, pgid: u64) -> i64 {
    unsafe { syscall2!(SYS_SETPGID, pid, pgid) }
}

#[inline(always)]
pub fn sys_setsid() -> i64 {
    unsafe { syscall0!(SYS_SETSID) }
}

#[inline(always)]
pub fn sys_clone(flags: u64, child_stack: u64, parent_tidptr: u64, child_tidptr: u64, tls: u64) -> i64 {
    unsafe { syscall5!(SYS_CLONE, flags, child_stack, parent_tidptr, child_tidptr, tls) }
}

#[inline(always)]
pub fn sys_fork() -> i64 {
    unsafe { syscall0!(SYS_FORK) }
}

#[inline(always)]
pub fn sys_vfork() -> i64 {
    unsafe { syscall0!(SYS_VFORK) }
}

#[inline(always)]
pub fn sys_execve(pathname: *const u8, argv: *const *const u8, envp: *const *const u8) -> i64 {
    unsafe { syscall3!(SYS_EXECVE, pathname, argv, envp) }
}

#[inline(always)]
pub fn sys_exit(status: u64) -> ! {
    unsafe { syscall1!(SYS_EXIT, status) };
    loop {}
}

#[inline(always)]
pub fn sys_wait4(pid: i64, wstatus: *mut i32, options: i32, rusage: u64) -> i64 {
    unsafe { syscall4!(SYS_WAIT4, pid, wstatus, options, rusage) }
}

#[inline(always)]
pub fn sys_waitid(idtype: i32, id: u64, infop: *mut SigInfo, options: i32) -> i64 {
    unsafe { syscall4!(SYS_WAITID, idtype, id, infop, options) }
}

// --- User/Group IDs ---

#[inline(always)]
pub fn sys_getuid() -> i64 {
    unsafe { syscall0!(SYS_GETUID) }
}

#[inline(always)]
pub fn sys_geteuid() -> i64 {
    unsafe { syscall0!(SYS_GETEUID) }
}

#[inline(always)]
pub fn sys_getgid() -> i64 {
    unsafe { syscall0!(SYS_GETGID) }
}

#[inline(always)]
pub fn sys_getegid() -> i64 {
    unsafe { syscall0!(SYS_GETEGID) }
}

#[inline(always)]
pub fn sys_setuid(uid: u32) -> i64 {
    unsafe { syscall1!(SYS_SETUID, uid) }
}

#[inline(always)]
pub fn sys_setgid(gid: u32) -> i64 {
    unsafe { syscall1!(SYS_SETGID, gid) }
}

#[inline(always)]
pub fn sys_getresuid(ruid: *mut u32, euid: *mut u32, suid: *mut u32) -> i64 {
    unsafe { syscall3!(SYS_GETRESUID, ruid, euid, suid) }
}

#[inline(always)]
pub fn sys_getresgid(rgid: *mut u32, egid: *mut u32, sgid: *mut u32) -> i64 {
    unsafe { syscall3!(SYS_GETRESGID, rgid, egid, sgid) }
}

#[inline(always)]
pub fn sys_setresuid(ruid: u32, euid: u32, suid: u32) -> i64 {
    unsafe { syscall3!(SYS_SETRESUID, ruid, euid, suid) }
}

#[inline(always)]
pub fn sys_setresgid(rgid: u32, egid: u32, sgid: u32) -> i64 {
    unsafe { syscall3!(SYS_SETRESGID, rgid, egid, sgid) }
}

#[inline(always)]
pub fn sys_setreuid(ruid: u32, euid: u32) -> i64 {
    unsafe { syscall2!(SYS_SETREUID, ruid, euid) }
}

#[inline(always)]
pub fn sys_setregid(rgid: u32, egid: u32) -> i64 {
    unsafe { syscall2!(SYS_SETREGID, rgid, egid) }
}

#[inline(always)]
pub fn sys_setfsuid(uid: u32) -> i64 {
    unsafe { syscall1!(SYS_SETFSUID, uid) }
}

#[inline(always)]
pub fn sys_setfsgid(gid: u32) -> i64 {
    unsafe { syscall1!(SYS_SETFSGID, gid) }
}

// --- Time ---

#[inline(always)]
pub fn sys_nanosleep(req: *const Timespec, rem: *mut Timespec) -> i64 {
    unsafe { syscall2!(SYS_NANOSLEEP, req, rem) }
}

#[inline(always)]
pub fn sys_clock_nanosleep(clockid: i32, flags: i32, req: *const Timespec, rem: *mut Timespec) -> i64 {
    unsafe { syscall4!(SYS_CLOCK_NANOSLEEP, clockid, flags, req, rem) }
}

#[inline(always)]
pub fn sys_clock_getres(clockid: i32, res: *mut Timespec) -> i64 {
    unsafe { syscall2!(SYS_CLOCK_GETRES, clockid, res) }
}

#[inline(always)]
pub fn sys_time(tloc: *mut i64) -> i64 {
    unsafe { syscall1!(SYS_TIME, tloc) }
}

#[inline(always)]
pub fn sys_clock_gettime(clockid: i32, tp: *mut Timespec) -> i64 {
    unsafe { syscall2!(SYS_CLOCK_GETTIME, clockid, tp) }
}

#[inline(always)]
pub fn sys_clock_settime(clockid: i32, tp: *const Timespec) -> i64 {
    unsafe { syscall2!(SYS_CLOCK_SETTIME, clockid, tp) }
}

#[inline(always)]
pub fn sys_gettimeofday(tv: *mut Timeval, tz: *mut u8) -> i64 {
    unsafe { syscall2!(SYS_GETTIMEOFDAY, tv, tz) }
}

#[inline(always)]
pub fn sys_settimeofday(tv: *const Timeval, tz: *const u8) -> i64 {
    unsafe { syscall2!(SYS_SETTIMEOFDAY, tv, tz) }
}

// --- Timerfd ---

use crate::types::ITimerSpec;

#[inline(always)]
pub fn sys_timerfd_create(clockid: i32, flags: i32) -> i64 {
    unsafe { syscall2!(SYS_TIMERFD_CREATE, clockid, flags) }
}

#[inline(always)]
pub fn sys_timerfd_settime(fd: i32, flags: i32, new_value: *const ITimerSpec, old_value: *mut ITimerSpec) -> i64 {
    unsafe { syscall4!(SYS_TIMERFD_SETTIME, fd, flags, new_value, old_value) }
}

#[inline(always)]
pub fn sys_timerfd_gettime(fd: i32, curr_value: *mut ITimerSpec) -> i64 {
    unsafe { syscall2!(SYS_TIMERFD_GETTIME, fd, curr_value) }
}

// --- POSIX Timers ---

use crate::types::SigEvent;

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

// --- Signals ---

#[inline(always)]
pub fn sys_rt_sigaction(sig: u32, act: u64, oact: u64, sigsetsize: u64) -> i64 {
    unsafe { syscall4!(SYS_RT_SIGACTION, sig, act, oact, sigsetsize) }
}

#[inline(always)]
pub fn sys_rt_sigprocmask(how: i32, set: u64, oset: u64, sigsetsize: u64) -> i64 {
    unsafe { syscall4!(SYS_RT_SIGPROCMASK, how, set, oset, sigsetsize) }
}

#[inline(always)]
pub fn sys_rt_sigpending(set: u64, sigsetsize: u64) -> i64 {
    unsafe { syscall2!(SYS_RT_SIGPENDING, set, sigsetsize) }
}

#[inline(always)]
pub fn sys_kill(pid: i64, sig: u32) -> i64 {
    unsafe { syscall2!(SYS_KILL, pid, sig) }
}

#[inline(always)]
pub fn sys_tgkill(tgid: i64, tid: i64, sig: u32) -> i64 {
    unsafe { syscall3!(SYS_TGKILL, tgid, tid, sig) }
}

#[inline(always)]
pub fn sys_tkill(tid: i64, sig: u32) -> i64 {
    unsafe { syscall2!(SYS_TKILL, tid, sig) }
}

// --- Pipe/Poll/Select ---

#[inline(always)]
pub fn sys_pipe(pipefd: *mut i32) -> i64 {
    unsafe { syscall1!(SYS_PIPE, pipefd) }
}

#[inline(always)]
pub fn sys_pipe2(pipefd: *mut i32, flags: u32) -> i64 {
    unsafe { syscall2!(SYS_PIPE2, pipefd, flags) }
}

#[inline(always)]
pub fn sys_poll(fds: *mut PollFd, nfds: u32, timeout: i32) -> i64 {
    unsafe { syscall3!(SYS_POLL, fds, nfds, timeout) }
}

#[inline(always)]
pub fn sys_select(nfds: i32, readfds: *mut FdSet, writefds: *mut FdSet, exceptfds: *mut FdSet, timeout: *mut Timeval) -> i64 {
    unsafe { syscall5!(SYS_SELECT, nfds, readfds, writefds, exceptfds, timeout) }
}

// --- Memory Management ---

#[inline(always)]
pub fn sys_mmap(addr: u64, length: u64, prot: u32, flags: u32, fd: i32, offset: u64) -> i64 {
    unsafe { syscall6!(SYS_MMAP, addr, length, prot, flags, fd, offset) }
}

#[inline(always)]
pub fn sys_mprotect(addr: u64, len: u64, prot: u32) -> i64 {
    unsafe { syscall3!(SYS_MPROTECT, addr, len, prot) }
}

#[inline(always)]
pub fn sys_munmap(addr: u64, length: u64) -> i64 {
    unsafe { syscall2!(SYS_MUNMAP, addr, length) }
}

#[inline(always)]
pub fn sys_brk(addr: u64) -> i64 {
    unsafe { syscall1!(SYS_BRK, addr) }
}

#[inline(always)]
pub fn sys_mlock(addr: u64, len: u64) -> i64 {
    unsafe { syscall2!(SYS_MLOCK, addr, len) }
}

#[inline(always)]
pub fn sys_mlock2(addr: u64, len: u64, flags: i32) -> i64 {
    unsafe { syscall3!(SYS_MLOCK2, addr, len, flags) }
}

#[inline(always)]
pub fn sys_munlock(addr: u64, len: u64) -> i64 {
    unsafe { syscall2!(SYS_MUNLOCK, addr, len) }
}

#[inline(always)]
pub fn sys_mlockall(flags: i32) -> i64 {
    unsafe { syscall1!(SYS_MLOCKALL, flags) }
}

#[inline(always)]
pub fn sys_munlockall() -> i64 {
    unsafe { syscall0!(SYS_MUNLOCKALL) }
}

#[inline(always)]
pub fn sys_msync(addr: u64, length: u64, flags: i32) -> i64 {
    unsafe { syscall3!(SYS_MSYNC, addr, length, flags) }
}

#[inline(always)]
pub fn sys_mincore(addr: u64, length: u64, vec: *mut u8) -> i64 {
    unsafe { syscall3!(SYS_MINCORE, addr, length, vec) }
}

#[inline(always)]
pub fn sys_madvise(addr: u64, length: u64, advice: i32) -> i64 {
    unsafe { syscall3!(SYS_MADVISE, addr, length, advice) }
}

#[inline(always)]
pub fn sys_mremap(old_addr: u64, old_len: u64, new_len: u64, flags: u32, new_addr: u64) -> i64 {
    unsafe { syscall5!(SYS_MREMAP, old_addr, old_len, new_len, flags, new_addr) }
}

// --- System Information ---

#[inline(always)]
pub fn sys_uname(buf: *mut UtsName) -> i64 {
    unsafe { syscall1!(SYS_UNAME, buf) }
}

#[inline(always)]
pub fn sys_sethostname(name: *const u8, len: u64) -> i64 {
    unsafe { syscall2!(SYS_SETHOSTNAME, name, len) }
}

#[inline(always)]
pub fn sys_setdomainname(name: *const u8, len: u64) -> i64 {
    unsafe { syscall2!(SYS_SETDOMAINNAME, name, len) }
}

#[inline(always)]
pub fn sys_reboot(magic1: u64, magic2: u64, cmd: u64) -> ! {
    unsafe { syscall3!(SYS_REBOOT, magic1, magic2, cmd) };
    loop {}
}

#[inline(always)]
pub fn sys_getcpu(cpup: *mut u32, nodep: *mut u32) -> i64 {
    unsafe { syscall2!(SYS_GETCPU, cpup, nodep) }
}

#[inline(always)]
pub fn sys_sysinfo(info: *mut u8) -> i64 {
    unsafe { syscall1!(SYS_SYSINFO, info) }
}

#[inline(always)]
pub fn sys_getrusage(who: i32, usage: *mut u8) -> i64 {
    unsafe { syscall2!(SYS_GETRUSAGE, who, usage) }
}

// --- Scheduling ---

#[inline(always)]
pub fn sys_getpriority(which: i32, who: u64) -> i64 {
    unsafe { syscall2!(SYS_GETPRIORITY, which, who) }
}

#[inline(always)]
pub fn sys_setpriority(which: i32, who: u64, niceval: i32) -> i64 {
    unsafe { syscall3!(SYS_SETPRIORITY, which, who, niceval) }
}

#[inline(always)]
pub fn sys_sched_getscheduler(pid: i64) -> i64 {
    unsafe { syscall1!(SYS_SCHED_GETSCHEDULER, pid) }
}

#[inline(always)]
pub fn sys_sched_setscheduler(pid: i64, policy: i32, param: *const super::SchedParam) -> i64 {
    unsafe { syscall3!(SYS_SCHED_SETSCHEDULER, pid, policy, param) }
}

#[inline(always)]
pub fn sys_sched_getparam(pid: i64, param: *mut super::SchedParam) -> i64 {
    unsafe { syscall2!(SYS_SCHED_GETPARAM, pid, param) }
}

#[inline(always)]
pub fn sys_sched_setparam(pid: i64, param: *const super::SchedParam) -> i64 {
    unsafe { syscall2!(SYS_SCHED_SETPARAM, pid, param) }
}

#[inline(always)]
pub fn sys_sched_getaffinity(pid: i64, cpusetsize: usize, mask: *mut u64) -> i64 {
    unsafe { syscall3!(SYS_SCHED_GETAFFINITY, pid, cpusetsize, mask) }
}

#[inline(always)]
pub fn sys_sched_setaffinity(pid: i64, cpusetsize: usize, mask: *const u64) -> i64 {
    unsafe { syscall3!(SYS_SCHED_SETAFFINITY, pid, cpusetsize, mask) }
}

#[inline(always)]
pub fn sys_sched_rr_get_interval(pid: i64, tp: *mut Timespec) -> i64 {
    unsafe { syscall2!(SYS_SCHED_RR_GET_INTERVAL, pid, tp) }
}

// --- I/O Priority ---

#[inline(always)]
pub fn sys_ioprio_set(which: i32, who: i32, ioprio: i32) -> i64 {
    unsafe { syscall3!(SYS_IOPRIO_SET, which, who, ioprio) }
}

#[inline(always)]
pub fn sys_ioprio_get(which: i32, who: i32) -> i64 {
    unsafe { syscall2!(SYS_IOPRIO_GET, which, who) }
}

// --- Resource Limits ---

#[inline(always)]
pub fn sys_getrlimit(resource: u32, rlim: *mut RLimit) -> i64 {
    unsafe { syscall2!(SYS_GETRLIMIT, resource, rlim) }
}

#[inline(always)]
pub fn sys_setrlimit(resource: u32, rlim: *const RLimit) -> i64 {
    unsafe { syscall2!(SYS_SETRLIMIT, resource, rlim) }
}

#[inline(always)]
pub fn sys_prlimit64(pid: i32, resource: u32, new_rlim: *const RLimit, old_rlim: *mut RLimit) -> i64 {
    unsafe { syscall4!(SYS_PRLIMIT64, pid, resource, new_rlim, old_rlim) }
}

// --- Namespaces ---

#[inline(always)]
pub fn sys_unshare(flags: u64) -> i64 {
    unsafe { syscall1!(SYS_UNSHARE, flags) }
}

#[inline(always)]
pub fn sys_setns(fd: i32, nstype: i32) -> i64 {
    unsafe { syscall2!(SYS_SETNS, fd, nstype) }
}

// --- Sockets ---

#[inline(always)]
pub fn sys_socket(domain: i32, sock_type: i32, protocol: i32) -> i64 {
    unsafe { syscall3!(SYS_SOCKET, domain, sock_type, protocol) }
}

#[inline(always)]
pub fn sys_connect(fd: i32, addr: *const u8, addrlen: u32) -> i64 {
    unsafe { syscall3!(SYS_CONNECT, fd, addr, addrlen) }
}

#[inline(always)]
pub fn sys_bind(fd: i32, addr: *const u8, addrlen: u32) -> i64 {
    unsafe { syscall3!(SYS_BIND, fd, addr, addrlen) }
}

#[inline(always)]
pub fn sys_listen(fd: i32, backlog: i32) -> i64 {
    unsafe { syscall2!(SYS_LISTEN, fd, backlog) }
}

#[inline(always)]
pub fn sys_shutdown(fd: i32, how: i32) -> i64 {
    unsafe { syscall2!(SYS_SHUTDOWN, fd, how) }
}

#[inline(always)]
pub fn sys_getsockname(fd: i32, addr: *mut u8, addrlen: *mut u32) -> i64 {
    unsafe { syscall3!(SYS_GETSOCKNAME, fd, addr, addrlen) }
}

#[inline(always)]
pub fn sys_getpeername(fd: i32, addr: *mut u8, addrlen: *mut u32) -> i64 {
    unsafe { syscall3!(SYS_GETPEERNAME, fd, addr, addrlen) }
}

#[inline(always)]
pub fn sys_sendto(fd: i32, buf: *const u8, len: usize, flags: i32, dest_addr: *const u8, addrlen: u32) -> i64 {
    unsafe { syscall6!(SYS_SENDTO, fd, buf, len, flags, dest_addr, addrlen) }
}

#[inline(always)]
pub fn sys_recvfrom(fd: i32, buf: *mut u8, len: usize, flags: i32, src_addr: *mut u8, addrlen: *mut u32) -> i64 {
    unsafe { syscall6!(SYS_RECVFROM, fd, buf, len, flags, src_addr, addrlen) }
}

#[inline(always)]
pub fn sys_setsockopt(fd: i32, level: i32, optname: i32, optval: *const u8, optlen: u32) -> i64 {
    unsafe { syscall5!(SYS_SETSOCKOPT, fd, level, optname, optval, optlen) }
}

#[inline(always)]
pub fn sys_getsockopt(fd: i32, level: i32, optname: i32, optval: *mut u8, optlen: *mut u32) -> i64 {
    unsafe { syscall5!(SYS_GETSOCKOPT, fd, level, optname, optval, optlen) }
}

// --- SysV IPC: Shared Memory ---

#[inline(always)]
pub fn sys_shmget(key: i32, size: usize, shmflg: i32) -> i64 {
    unsafe { syscall3!(SYS_SHMGET, key, size, shmflg) }
}

#[inline(always)]
pub fn sys_shmat(shmid: i32, shmaddr: u64, shmflg: i32) -> i64 {
    unsafe { syscall3!(SYS_SHMAT, shmid, shmaddr, shmflg) }
}

#[inline(always)]
pub fn sys_shmdt(shmaddr: u64) -> i64 {
    unsafe { syscall1!(SYS_SHMDT, shmaddr) }
}

#[inline(always)]
pub fn sys_shmctl(shmid: i32, cmd: i32, buf: u64) -> i64 {
    unsafe { syscall3!(SYS_SHMCTL, shmid, cmd, buf) }
}

// --- SysV IPC: Semaphores ---

#[inline(always)]
pub fn sys_semget(key: i32, nsems: i32, semflg: i32) -> i64 {
    unsafe { syscall3!(SYS_SEMGET, key, nsems, semflg) }
}

#[inline(always)]
pub fn sys_semop(semid: i32, sops: *const super::Sembuf, nsops: usize) -> i64 {
    unsafe { syscall3!(SYS_SEMOP, semid, sops, nsops) }
}

#[inline(always)]
pub fn sys_semtimedop(semid: i32, sops: *const super::Sembuf, nsops: usize, timeout: *const Timespec) -> i64 {
    unsafe { syscall4!(SYS_SEMTIMEDOP, semid, sops, nsops, timeout) }
}

#[inline(always)]
pub fn sys_semctl(semid: i32, semnum: i32, cmd: i32, arg: u64) -> i64 {
    unsafe { syscall4!(SYS_SEMCTL, semid, semnum, cmd, arg) }
}

// --- SysV IPC: Message Queues ---

#[inline(always)]
pub fn sys_msgget(key: i32, msgflg: i32) -> i64 {
    unsafe { syscall2!(SYS_MSGGET, key, msgflg) }
}

#[inline(always)]
pub fn sys_msgsnd(msqid: i32, msgp: *const u8, msgsz: usize, msgflg: i32) -> i64 {
    unsafe { syscall4!(SYS_MSGSND, msqid, msgp, msgsz, msgflg) }
}

#[inline(always)]
pub fn sys_msgrcv(msqid: i32, msgp: *mut u8, msgsz: usize, msgtyp: i64, msgflg: i32) -> i64 {
    unsafe { syscall5!(SYS_MSGRCV, msqid, msgp, msgsz, msgtyp, msgflg) }
}

#[inline(always)]
pub fn sys_msgctl(msqid: i32, cmd: i32, buf: u64) -> i64 {
    unsafe { syscall3!(SYS_MSGCTL, msqid, cmd, buf) }
}

// --- Futex ---

#[inline(always)]
pub fn sys_futex(uaddr: *mut u32, op: u32, val: u32, timeout: *const Timespec, uaddr2: *mut u32, val3: u32) -> i64 {
    unsafe { syscall6!(SYS_FUTEX, uaddr, op, val, timeout, uaddr2, val3) }
}

#[inline(always)]
pub fn sys_set_robust_list(head: *const super::RobustListHead, len: usize) -> i64 {
    unsafe { syscall2!(SYS_SET_ROBUST_LIST, head, len) }
}

#[inline(always)]
pub fn sys_get_robust_list(pid: i32, head_ptr: *mut *const super::RobustListHead, len_ptr: *mut usize) -> i64 {
    unsafe { syscall3!(SYS_GET_ROBUST_LIST, pid, head_ptr, len_ptr) }
}

// --- TLS ---

#[inline(always)]
pub fn sys_arch_prctl(code: i32, addr: u64) -> i64 {
    unsafe { syscall2!(SYS_ARCH_PRCTL, code, addr) }
}

#[inline(always)]
pub fn sys_set_tid_address(tidptr: *mut i32) -> i64 {
    unsafe { syscall1!(SYS_SET_TID_ADDRESS, tidptr) }
}

// --- Splice / Sendfile ---

#[inline(always)]
pub fn sys_sendfile(out_fd: i32, in_fd: i32, offset: *mut i64, count: usize) -> i64 {
    unsafe { syscall4!(SYS_SENDFILE, out_fd, in_fd, offset, count) }
}

#[inline(always)]
pub fn sys_splice(fd_in: i32, off_in: *mut i64, fd_out: i32, off_out: *mut i64, len: usize, flags: u32) -> i64 {
    unsafe { syscall6!(SYS_SPLICE, fd_in, off_in, fd_out, off_out, len, flags) }
}

#[inline(always)]
pub fn sys_tee(fd_in: i32, fd_out: i32, len: usize, flags: u32) -> i64 {
    unsafe { syscall4!(SYS_TEE, fd_in, fd_out, len, flags) }
}

#[inline(always)]
pub fn sys_vmsplice(fd: i32, iov: *const super::IoVec, nr_segs: usize, flags: u32) -> i64 {
    unsafe { syscall4!(SYS_VMSPLICE, fd, iov, nr_segs, flags) }
}

// --- Filesystem Statistics ---

#[inline(always)]
pub fn sys_statfs(pathname: *const u8, buf: *mut super::LinuxStatFs) -> i64 {
    unsafe { syscall2!(SYS_STATFS, pathname, buf) }
}

#[inline(always)]
pub fn sys_fstatfs(fd: i32, buf: *mut super::LinuxStatFs) -> i64 {
    unsafe { syscall2!(SYS_FSTATFS, fd, buf) }
}

#[inline(always)]
pub fn sys_statx(dirfd: i32, pathname: *const u8, flags: i32, mask: u32, buf: *mut super::Statx) -> i64 {
    unsafe { syscall5!(SYS_STATX, dirfd, pathname, flags, mask, buf) }
}

// --- Extended Attributes ---

#[inline(always)]
pub fn sys_setxattr(path: *const u8, name: *const u8, value: *const u8, size: usize, flags: i32) -> i64 {
    unsafe { syscall5!(SYS_SETXATTR, path, name, value, size, flags) }
}

#[inline(always)]
pub fn sys_lsetxattr(path: *const u8, name: *const u8, value: *const u8, size: usize, flags: i32) -> i64 {
    unsafe { syscall5!(SYS_LSETXATTR, path, name, value, size, flags) }
}

#[inline(always)]
pub fn sys_fsetxattr(fd: i32, name: *const u8, value: *const u8, size: usize, flags: i32) -> i64 {
    unsafe { syscall5!(SYS_FSETXATTR, fd, name, value, size, flags) }
}

#[inline(always)]
pub fn sys_getxattr(path: *const u8, name: *const u8, value: *mut u8, size: usize) -> i64 {
    unsafe { syscall4!(SYS_GETXATTR, path, name, value, size) }
}

#[inline(always)]
pub fn sys_lgetxattr(path: *const u8, name: *const u8, value: *mut u8, size: usize) -> i64 {
    unsafe { syscall4!(SYS_LGETXATTR, path, name, value, size) }
}

#[inline(always)]
pub fn sys_fgetxattr(fd: i32, name: *const u8, value: *mut u8, size: usize) -> i64 {
    unsafe { syscall4!(SYS_FGETXATTR, fd, name, value, size) }
}

#[inline(always)]
pub fn sys_listxattr(path: *const u8, list: *mut u8, size: usize) -> i64 {
    unsafe { syscall3!(SYS_LISTXATTR, path, list, size) }
}

#[inline(always)]
pub fn sys_llistxattr(path: *const u8, list: *mut u8, size: usize) -> i64 {
    unsafe { syscall3!(SYS_LLISTXATTR, path, list, size) }
}

#[inline(always)]
pub fn sys_flistxattr(fd: i32, list: *mut u8, size: usize) -> i64 {
    unsafe { syscall3!(SYS_FLISTXATTR, fd, list, size) }
}

#[inline(always)]
pub fn sys_removexattr(path: *const u8, name: *const u8) -> i64 {
    unsafe { syscall2!(SYS_REMOVEXATTR, path, name) }
}

#[inline(always)]
pub fn sys_lremovexattr(path: *const u8, name: *const u8) -> i64 {
    unsafe { syscall2!(SYS_LREMOVEXATTR, path, name) }
}

#[inline(always)]
pub fn sys_fremovexattr(fd: i32, name: *const u8) -> i64 {
    unsafe { syscall2!(SYS_FREMOVEXATTR, fd, name) }
}

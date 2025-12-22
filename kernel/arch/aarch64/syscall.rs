//! AArch64 Linux syscall implementation
//!
//! Key differences from x86_64:
//! - Syscall number in X8 (not RAX)
//! - Arguments in X0-X5 (not RDI/RSI/RDX/R10/R8/R9)
//! - Different syscall numbers (ARM64 uses newer Linux ABI)
//! - Some legacy syscalls removed (open, fork, dup2)

// Syscall numbers are a reference table for Linux ABI compatibility
#![allow(dead_code)]

use crate::printkln;

// ============================================================================
// AArch64 Linux syscall numbers (different from x86_64!)
// ============================================================================

// I/O syscalls
/// fcntl(fd, cmd, arg)
pub const SYS_FCNTL: u64 = 25;
pub const SYS_DUP3: u64 = 24;
pub const SYS_PIPE2: u64 = 59;
pub const SYS_PPOLL: u64 = 73;
pub const SYS_PSELECT6: u64 = 72;
pub const SYS_MKNODAT: u64 = 33;
pub const SYS_MKDIRAT: u64 = 34;
pub const SYS_UNLINKAT: u64 = 35;
pub const SYS_SYMLINKAT: u64 = 36;
pub const SYS_LINKAT: u64 = 37;
pub const SYS_RENAMEAT: u64 = 38;
pub const SYS_UMOUNT2: u64 = 39;
pub const SYS_MOUNT: u64 = 40;
pub const SYS_FTRUNCATE: u64 = 46;
pub const SYS_FCHMOD: u64 = 52;
pub const SYS_FCHMODAT: u64 = 53;
pub const SYS_FCHOWNAT: u64 = 54;
pub const SYS_FCHOWN: u64 = 55;
pub const SYS_OPENAT: u64 = 56;
pub const SYS_CLOSE: u64 = 57;
pub const SYS_GETDENTS64: u64 = 61;
pub const SYS_LSEEK: u64 = 62;
pub const SYS_READ: u64 = 63;
pub const SYS_WRITE: u64 = 64;
pub const SYS_READV: u64 = 65;
pub const SYS_WRITEV: u64 = 66;
/// pread64(fd, buf, count, offset)
pub const SYS_PREAD64: u64 = 67;
/// pwrite64(fd, buf, count, offset)
pub const SYS_PWRITE64: u64 = 68;
/// preadv(fd, iov, iovcnt, offset)
pub const SYS_PREADV: u64 = 69;
/// pwritev(fd, iov, iovcnt, offset)
pub const SYS_PWRITEV: u64 = 70;
pub const SYS_READLINKAT: u64 = 78;
pub const SYS_FSTATAT: u64 = 79;
pub const SYS_UTIMENSAT: u64 = 88;

// Sync syscalls
pub const SYS_SYNC: u64 = 81;
pub const SYS_FSYNC: u64 = 82;
pub const SYS_FDATASYNC: u64 = 83;
pub const SYS_SYNCFS: u64 = 267;

// UTS namespace syscalls
pub const SYS_UNAME: u64 = 160;
pub const SYS_SETHOSTNAME: u64 = 161;
pub const SYS_SETDOMAINNAME: u64 = 162;

// Namespace syscalls
/// unshare(flags) - disassociate parts of process execution context
pub const SYS_UNSHARE: u64 = 97;
/// setns(fd, nstype) - reassociate thread with a namespace
pub const SYS_SETNS: u64 = 268;

// Process syscalls
pub const SYS_EXIT: u64 = 93;
pub const SYS_EXIT_GROUP: u64 = 94;
pub const SYS_WAITID: u64 = 95;
pub const SYS_NANOSLEEP: u64 = 101;
pub const SYS_CLOCK_GETTIME: u64 = 113;
pub const SYS_CLOCK_GETRES: u64 = 114;
pub const SYS_CLOCK_NANOSLEEP: u64 = 115;
pub const SYS_REBOOT: u64 = 142;
pub const SYS_SETPGID: u64 = 154;
pub const SYS_GETPGID: u64 = 155;
pub const SYS_GETSID: u64 = 156;
pub const SYS_SETSID: u64 = 157;
pub const SYS_UMASK: u64 = 166;
/// getcpu(cpup, nodep, unused)
pub const SYS_GETCPU: u64 = 168;
pub const SYS_GETPID: u64 = 172;
pub const SYS_GETPPID: u64 = 173;
/// setregid(rgid, egid)
pub const SYS_SETREGID: u64 = 143;
pub const SYS_SETGID: u64 = 144;
/// setreuid(ruid, euid)
pub const SYS_SETREUID: u64 = 145;
pub const SYS_SETUID: u64 = 146;
/// setresuid(ruid, euid, suid)
pub const SYS_SETRESUID: u64 = 147;
/// getresuid(ruid*, euid*, suid*)
pub const SYS_GETRESUID: u64 = 148;
/// setresgid(rgid, egid, sgid)
pub const SYS_SETRESGID: u64 = 149;
/// getresgid(rgid*, egid*, sgid*)
pub const SYS_GETRESGID: u64 = 150;
/// setfsuid(uid)
pub const SYS_SETFSUID: u64 = 151;
/// setfsgid(gid)
pub const SYS_SETFSGID: u64 = 152;
pub const SYS_GETUID: u64 = 174;
pub const SYS_GETEUID: u64 = 175;
pub const SYS_GETGID: u64 = 176;
pub const SYS_GETEGID: u64 = 177;
pub const SYS_GETTID: u64 = 178;

// Memory syscalls
pub const SYS_BRK: u64 = 214;
pub const SYS_MUNMAP: u64 = 215;
pub const SYS_CLONE: u64 = 220;
pub const SYS_EXECVE: u64 = 221;
pub const SYS_MMAP: u64 = 222;
pub const SYS_MPROTECT: u64 = 226;
/// mlock(addr, len)
pub const SYS_MLOCK: u64 = 228;
/// munlock(addr, len)
pub const SYS_MUNLOCK: u64 = 229;
/// mlockall(flags)
pub const SYS_MLOCKALL: u64 = 230;
/// munlockall()
pub const SYS_MUNLOCKALL: u64 = 231;
/// mlock2(addr, len, flags)
pub const SYS_MLOCK2: u64 = 284;
pub const SYS_WAIT4: u64 = 260;

// Signal syscalls (aarch64 numbers)
pub const SYS_KILL: u64 = 129;
pub const SYS_TKILL: u64 = 130;
pub const SYS_TGKILL: u64 = 131;
pub const SYS_RT_SIGACTION: u64 = 134;
pub const SYS_RT_SIGPROCMASK: u64 = 135;
pub const SYS_RT_SIGPENDING: u64 = 136;
#[allow(dead_code)] // Infrastructure for future signal delivery
pub const SYS_RT_SIGRETURN: u64 = 139;

// Scheduling priority (aarch64 numbers - note: swapped from x86_64)
/// setpriority(which, who, niceval)
pub const SYS_SETPRIORITY: u64 = 140;
/// getpriority(which, who)
pub const SYS_GETPRIORITY: u64 = 141;

// System information
/// getrusage(who, usage)
pub const SYS_GETRUSAGE: u64 = 165;
/// sysinfo(info)
pub const SYS_SYSINFO: u64 = 179;
/// getrandom(buf, buflen, flags)
pub const SYS_GETRANDOM: u64 = 278;

// Scheduling syscalls (aarch64 numbers)
/// sched_setparam(pid, param)
pub const SYS_SCHED_SETPARAM: u64 = 118;
/// sched_setscheduler(pid, policy, param)
pub const SYS_SCHED_SETSCHEDULER: u64 = 119;
/// sched_getscheduler(pid)
pub const SYS_SCHED_GETSCHEDULER: u64 = 120;
/// sched_getparam(pid, param)
pub const SYS_SCHED_GETPARAM: u64 = 121;
/// sched_setaffinity(pid, cpusetsize, mask)
pub const SYS_SCHED_SETAFFINITY: u64 = 122;
/// sched_getaffinity(pid, cpusetsize, mask)
pub const SYS_SCHED_GETAFFINITY: u64 = 123;
/// sched_yield()
pub const SYS_SCHED_YIELD: u64 = 124;
/// sched_rr_get_interval(pid, tp)
pub const SYS_SCHED_RR_GET_INTERVAL: u64 = 127;

// Resource limits
/// getrlimit(resource, rlim)
pub const SYS_GETRLIMIT: u64 = 163;
/// setrlimit(resource, rlim)
pub const SYS_SETRLIMIT: u64 = 164;
/// prlimit64(pid, resource, new_rlim, old_rlim)
pub const SYS_PRLIMIT64: u64 = 261;

// Socket syscalls (aarch64 numbers)
/// socket(domain, type, protocol)
pub const SYS_SOCKET: u64 = 198;
/// bind(fd, addr, addrlen)
pub const SYS_BIND: u64 = 200;
/// listen(fd, backlog)
pub const SYS_LISTEN: u64 = 201;
/// accept(fd, addr, addrlen)
pub const SYS_ACCEPT: u64 = 202;
/// connect(fd, addr, addrlen)
pub const SYS_CONNECT: u64 = 203;
/// getsockname(fd, addr, addrlen)
pub const SYS_GETSOCKNAME: u64 = 204;
/// getpeername(fd, addr, addrlen)
pub const SYS_GETPEERNAME: u64 = 205;
/// sendto(fd, buf, len, flags, dest_addr, addrlen)
pub const SYS_SENDTO: u64 = 206;
/// recvfrom(fd, buf, len, flags, src_addr, addrlen)
pub const SYS_RECVFROM: u64 = 207;
/// setsockopt(fd, level, optname, optval, optlen)
pub const SYS_SETSOCKOPT: u64 = 208;
/// getsockopt(fd, level, optname, optval, optlen)
pub const SYS_GETSOCKOPT: u64 = 209;
/// shutdown(fd, how)
pub const SYS_SHUTDOWN: u64 = 210;
/// accept4(fd, addr, addrlen, flags)
pub const SYS_ACCEPT4: u64 = 242;

// Futex syscalls (aarch64 numbers)
/// futex(uaddr, futex_op, val, timeout, uaddr2, val3)
pub const SYS_FUTEX: u64 = 98;
/// set_robust_list(head, len)
pub const SYS_SET_ROBUST_LIST: u64 = 99;
/// get_robust_list(pid, head_ptr, len_ptr)
pub const SYS_GET_ROBUST_LIST: u64 = 100;

// SysV IPC syscalls (aarch64 numbers)
/// msgget(key, msgflg)
pub const SYS_MSGGET: u64 = 186;
/// msgctl(msqid, cmd, buf)
pub const SYS_MSGCTL: u64 = 187;
/// msgrcv(msqid, msgp, msgsz, msgtyp, msgflg)
pub const SYS_MSGRCV: u64 = 188;
/// msgsnd(msqid, msgp, msgsz, msgflg)
pub const SYS_MSGSND: u64 = 189;
/// semget(key, nsems, semflg)
pub const SYS_SEMGET: u64 = 190;
/// semctl(semid, semnum, cmd, ...)
pub const SYS_SEMCTL: u64 = 191;
/// semtimedop(semid, sops, nsops, timeout)
pub const SYS_SEMTIMEDOP: u64 = 192;
/// semop(semid, sops, nsops)
pub const SYS_SEMOP: u64 = 193;
/// shmget(key, size, shmflg)
pub const SYS_SHMGET: u64 = 194;
/// shmctl(shmid, cmd, buf)
pub const SYS_SHMCTL: u64 = 195;
/// shmat(shmid, shmaddr, shmflg)
pub const SYS_SHMAT: u64 = 196;
/// shmdt(shmaddr)
pub const SYS_SHMDT: u64 = 197;

// ============================================================================
// Syscall dispatcher
// ============================================================================

/// Dispatch syscall based on ARM64 syscall number
pub fn aarch64_syscall_dispatch(
    num: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    _arg5: u64,
) -> u64 {
    use crate::fs::syscall::{
        sys_close, sys_dup3, sys_fchmod, sys_fchmodat, sys_fchown, sys_fchownat, sys_fcntl,
        sys_fdatasync, sys_fstatat, sys_fsync, sys_ftruncate, sys_getdents64, sys_linkat,
        sys_lseek, sys_mkdirat, sys_mknodat, sys_mount, sys_openat, sys_pipe2, sys_ppoll,
        sys_pread64, sys_preadv, sys_pselect6, sys_pwrite64, sys_pwritev, sys_read, sys_readlinkat,
        sys_readv, sys_renameat, sys_symlinkat, sys_sync, sys_syncfs, sys_umask, sys_umount2,
        sys_unlinkat, sys_utimensat, sys_write, sys_writev,
    };
    use crate::task::exec::sys_execve;
    use crate::task::percpu;
    use crate::task::syscall::{
        sys_clone, sys_exit, sys_getegid, sys_geteuid, sys_getgid, sys_getpgid, sys_getpid,
        sys_getppid, sys_getsid, sys_gettid, sys_getuid, sys_setpgid, sys_setsid, sys_wait4,
        sys_waitid,
    };
    use crate::time_syscall::{
        sys_clock_getres, sys_clock_gettime, sys_clock_nanosleep, sys_nanosleep,
    };

    match num {
        // I/O syscalls
        SYS_READ => sys_read(arg0 as i32, arg1, arg2) as u64,
        SYS_WRITE => sys_write(arg0 as i32, arg1, arg2) as u64,
        SYS_READV => sys_readv(arg0 as i32, arg1, arg2 as i32) as u64,
        SYS_WRITEV => sys_writev(arg0 as i32, arg1, arg2 as i32) as u64,
        SYS_PREAD64 => sys_pread64(arg0 as i32, arg1, arg2, arg3 as i64) as u64,
        SYS_PWRITE64 => sys_pwrite64(arg0 as i32, arg1, arg2, arg3 as i64) as u64,
        SYS_PREADV => sys_preadv(arg0 as i32, arg1, arg2 as i32, arg3 as i64) as u64,
        SYS_PWRITEV => sys_pwritev(arg0 as i32, arg1, arg2 as i32, arg3 as i64) as u64,
        SYS_OPENAT => sys_openat(arg0 as i32, arg1, arg2 as u32, arg3 as u32) as u64,
        SYS_CLOSE => sys_close(arg0 as i32) as u64,
        SYS_LSEEK => sys_lseek(arg0 as i32, arg1 as i64, arg2 as i32) as u64,
        SYS_FTRUNCATE => sys_ftruncate(arg0 as i32, arg1 as i64) as u64,
        SYS_DUP3 => sys_dup3(arg0 as i32, arg1 as i32, arg2 as u32) as u64,
        SYS_FCNTL => sys_fcntl(arg0 as i32, arg1 as i32, arg2) as u64,
        SYS_PIPE2 => sys_pipe2(arg0, arg1 as u32) as u64,
        SYS_PPOLL => sys_ppoll(arg0, arg1 as u32, arg2, arg3, arg4) as u64,
        SYS_PSELECT6 => sys_pselect6(arg0 as i32, arg1, arg2, arg3, arg4, _arg5) as u64,
        SYS_GETDENTS64 => sys_getdents64(arg0 as i32, arg1, arg2) as u64,

        // Directory operations
        SYS_MKNODAT => sys_mknodat(arg0 as i32, arg1, arg2 as u32, arg3) as u64,
        SYS_MKDIRAT => sys_mkdirat(arg0 as i32, arg1, arg2 as u32) as u64,
        SYS_UNLINKAT => sys_unlinkat(arg0 as i32, arg1, arg2 as i32) as u64,
        SYS_SYMLINKAT => sys_symlinkat(arg0, arg1 as i32, arg2) as u64,
        SYS_LINKAT => sys_linkat(arg0 as i32, arg1, arg2 as i32, arg3, arg4 as i32) as u64,
        SYS_READLINKAT => sys_readlinkat(arg0 as i32, arg1, arg2, arg3) as u64,
        SYS_RENAMEAT => sys_renameat(arg0 as i32, arg1, arg2 as i32, arg3) as u64,
        SYS_MOUNT => sys_mount(arg0, arg1, arg2, arg3, arg4) as u64,
        SYS_UMOUNT2 => sys_umount2(arg0, arg1 as i32) as u64,
        SYS_FCHMOD => sys_fchmod(arg0 as i32, arg1 as u32) as u64,
        SYS_FCHMODAT => sys_fchmodat(arg0 as i32, arg1, arg2 as u32, arg3 as i32) as u64,
        SYS_FCHOWNAT => {
            sys_fchownat(arg0 as i32, arg1, arg2 as u32, arg3 as u32, arg4 as i32) as u64
        }
        SYS_FCHOWN => sys_fchown(arg0 as i32, arg1 as u32, arg2 as u32) as u64,
        SYS_FSTATAT => sys_fstatat(arg0 as i32, arg1, arg2, arg3 as i32) as u64,
        SYS_UTIMENSAT => sys_utimensat(arg0 as i32, arg1, arg2, arg3 as i32) as u64,
        SYS_UMASK => sys_umask(arg0 as u32) as u64,

        // System information
        SYS_GETCPU => {
            use crate::arch::{PerCpuOps, Uaccess};
            crate::task::syscall::sys_getcpu::<Uaccess>(
                crate::arch::CurrentArch::try_current_cpu_id().unwrap_or(0),
                arg0,
                arg1,
            ) as u64
        }

        // Sync operations
        SYS_SYNC => sys_sync() as u64,
        SYS_FSYNC => sys_fsync(arg0 as i32) as u64,
        SYS_FDATASYNC => sys_fdatasync(arg0 as i32) as u64,
        SYS_SYNCFS => sys_syncfs(arg0 as i32) as u64,

        // Process info syscalls
        SYS_GETPID => sys_getpid(percpu::current_pid()) as u64,
        SYS_GETTID => sys_gettid(percpu::current_tid()) as u64,
        SYS_GETPPID => sys_getppid(percpu::current_ppid()) as u64,
        SYS_GETPGID => sys_getpgid(arg0, percpu::current_pid(), percpu::current_pgid()) as u64,
        SYS_GETSID => sys_getsid(arg0, percpu::current_pid(), percpu::current_sid()) as u64,
        SYS_SETPGID => sys_setpgid(
            arg0,
            arg1,
            percpu::current_pid(),
            percpu::current_pgid(),
            percpu::current_sid(),
        ) as u64,
        SYS_SETSID => sys_setsid(percpu::current_pid(), percpu::current_pgid()) as u64,

        // Credentials
        SYS_GETUID => sys_getuid(percpu::current_cred().uid) as u64,
        SYS_GETEUID => sys_geteuid(percpu::current_cred().euid) as u64,
        SYS_GETGID => sys_getgid(percpu::current_cred().gid) as u64,
        SYS_GETEGID => sys_getegid(percpu::current_cred().egid) as u64,
        SYS_SETUID => {
            use crate::task::syscall::sys_setuid;
            sys_setuid(arg0 as u32, percpu::current_cred()) as u64
        }
        SYS_SETGID => {
            use crate::task::syscall::sys_setgid;
            sys_setgid(arg0 as u32, percpu::current_cred()) as u64
        }
        SYS_SETRESUID => {
            use crate::task::syscall::sys_setresuid;
            sys_setresuid(
                arg0 as u32,
                arg1 as u32,
                arg2 as u32,
                percpu::current_cred(),
            ) as u64
        }
        SYS_GETRESUID => {
            use crate::arch::Uaccess;
            use crate::task::syscall::sys_getresuid;
            sys_getresuid::<Uaccess>(arg0, arg1, arg2, percpu::current_cred()) as u64
        }
        SYS_SETRESGID => {
            use crate::task::syscall::sys_setresgid;
            sys_setresgid(
                arg0 as u32,
                arg1 as u32,
                arg2 as u32,
                percpu::current_cred(),
            ) as u64
        }
        SYS_GETRESGID => {
            use crate::arch::Uaccess;
            use crate::task::syscall::sys_getresgid;
            sys_getresgid::<Uaccess>(arg0, arg1, arg2, percpu::current_cred()) as u64
        }
        SYS_SETREUID => {
            use crate::task::syscall::sys_setreuid;
            sys_setreuid(arg0 as u32, arg1 as u32, percpu::current_cred()) as u64
        }
        SYS_SETREGID => {
            use crate::task::syscall::sys_setregid;
            sys_setregid(arg0 as u32, arg1 as u32, percpu::current_cred()) as u64
        }
        SYS_SETFSUID => {
            use crate::task::syscall::sys_setfsuid;
            sys_setfsuid(arg0 as u32, percpu::current_cred()) as u64
        }
        SYS_SETFSGID => {
            use crate::task::syscall::sys_setfsgid;
            sys_setfsgid(arg0 as u32, percpu::current_cred()) as u64
        }

        // Time syscalls
        SYS_CLOCK_GETTIME => sys_clock_gettime(arg0 as i32, arg1) as u64,
        SYS_CLOCK_GETRES => sys_clock_getres(arg0 as i32, arg1) as u64,
        SYS_NANOSLEEP => sys_nanosleep(arg0, arg1) as u64,
        SYS_CLOCK_NANOSLEEP => sys_clock_nanosleep(arg0 as i32, arg1 as i32, arg2, arg3) as u64,

        // Process lifecycle
        SYS_EXIT | SYS_EXIT_GROUP => sys_exit(arg0 as i32),
        SYS_WAITID => sys_waitid(arg0 as i32, arg1, arg2, arg3 as i32) as u64,
        SYS_CLONE => sys_clone(arg0, arg1, arg2, arg3, arg4) as u64,
        SYS_EXECVE => sys_execve(arg0, arg1, arg2) as u64,
        SYS_WAIT4 => sys_wait4(arg0 as i64, arg1, arg2 as i32, arg3) as u64,

        // Power management
        SYS_REBOOT => crate::power::sys_reboot(arg0 as u32, arg1 as u32, arg2 as u32, arg3) as u64,

        // UTS namespace (hostname, domainname, system info)
        SYS_UNAME => crate::ns::uts::sys_uname(arg0) as u64,
        SYS_SETHOSTNAME => crate::ns::uts::sys_sethostname(arg0, arg1) as u64,
        SYS_SETDOMAINNAME => crate::ns::uts::sys_setdomainname(arg0, arg1) as u64,

        // Namespace syscalls
        SYS_UNSHARE => crate::ns::sys_unshare(arg0) as u64,
        SYS_SETNS => crate::ns::sys_setns(arg0 as i32, arg1 as i32) as u64,

        // Signal syscalls
        SYS_RT_SIGACTION => {
            crate::signal::syscall::sys_rt_sigaction(arg0 as u32, arg1, arg2, arg3) as u64
        }
        SYS_RT_SIGPROCMASK => {
            crate::signal::syscall::sys_rt_sigprocmask(arg0 as i32, arg1, arg2, arg3) as u64
        }
        SYS_RT_SIGPENDING => crate::signal::syscall::sys_rt_sigpending(arg0, arg1) as u64,
        SYS_KILL => crate::signal::syscall::sys_kill(arg0 as i64, arg1 as u32) as u64,
        SYS_TGKILL => {
            crate::signal::syscall::sys_tgkill(arg0 as i64, arg1 as i64, arg2 as u32) as u64
        }
        SYS_TKILL => crate::signal::syscall::sys_tkill(arg0 as i64, arg1 as u32) as u64,

        // Scheduling priority
        SYS_GETPRIORITY => {
            use crate::task::syscall::sys_getpriority;
            sys_getpriority(arg0 as i32, arg1, percpu::current_pid()) as u64
        }
        SYS_SETPRIORITY => {
            use crate::task::syscall::sys_setpriority;
            sys_setpriority(
                arg0 as i32,
                arg1,
                arg2 as i32,
                percpu::current_pid(),
                percpu::current_cred().euid,
            ) as u64
        }

        // Scheduling syscalls (Section 1.3)
        SYS_SCHED_YIELD => {
            use crate::task::syscall::sys_sched_yield;
            sys_sched_yield();
            0
        }
        SYS_SCHED_GETSCHEDULER => {
            use crate::task::syscall::sys_sched_getscheduler;
            sys_sched_getscheduler(arg0 as i64, percpu::current_pid()) as u64
        }
        SYS_SCHED_SETSCHEDULER => {
            use crate::arch::Uaccess;
            use crate::task::syscall::sys_sched_setscheduler;
            sys_sched_setscheduler::<Uaccess>(
                arg0 as i64,
                arg1 as i32,
                arg2,
                percpu::current_pid(),
                percpu::current_cred().euid,
            ) as u64
        }
        SYS_SCHED_GETPARAM => {
            use crate::arch::Uaccess;
            use crate::task::syscall::sys_sched_getparam;
            sys_sched_getparam::<Uaccess>(arg0 as i64, arg1, percpu::current_pid()) as u64
        }
        SYS_SCHED_SETPARAM => {
            use crate::arch::Uaccess;
            use crate::task::syscall::sys_sched_setparam;
            sys_sched_setparam::<Uaccess>(
                arg0 as i64,
                arg1,
                percpu::current_pid(),
                percpu::current_cred().euid,
            ) as u64
        }
        SYS_SCHED_GETAFFINITY => {
            use crate::arch::Uaccess;
            use crate::task::syscall::sys_sched_getaffinity;
            sys_sched_getaffinity::<Uaccess>(arg0 as i64, arg1, arg2, percpu::current_pid()) as u64
        }
        SYS_SCHED_SETAFFINITY => {
            use crate::arch::Uaccess;
            use crate::task::syscall::sys_sched_setaffinity;
            sys_sched_setaffinity::<Uaccess>(
                arg0 as i64,
                arg1,
                arg2,
                percpu::current_pid(),
                percpu::current_cred().euid,
            ) as u64
        }
        SYS_SCHED_RR_GET_INTERVAL => {
            use crate::arch::Uaccess;
            use crate::task::syscall::sys_sched_rr_get_interval;
            sys_sched_rr_get_interval::<Uaccess>(arg0 as i64, arg1, percpu::current_pid()) as u64
        }

        // Memory management syscalls
        SYS_MMAP => {
            crate::mm::syscall::sys_mmap(arg0, arg1, arg2 as u32, arg3 as u32, arg4 as i32, _arg5)
                as u64
        }
        SYS_MUNMAP => crate::mm::syscall::sys_munmap(arg0, arg1) as u64,
        SYS_BRK => crate::mm::syscall::sys_brk(arg0) as u64,
        SYS_MLOCK => crate::mm::syscall::sys_mlock(arg0, arg1) as u64,
        SYS_MUNLOCK => crate::mm::syscall::sys_munlock(arg0, arg1) as u64,
        SYS_MLOCKALL => crate::mm::syscall::sys_mlockall(arg0 as i32) as u64,
        SYS_MUNLOCKALL => crate::mm::syscall::sys_munlockall() as u64,
        SYS_MLOCK2 => crate::mm::syscall::sys_mlock2(arg0, arg1, arg2 as i32) as u64,

        // System information
        SYS_SYSINFO => {
            use crate::arch::Uaccess;
            use crate::task::syscall::sys_sysinfo;
            sys_sysinfo::<Uaccess>(arg0) as u64
        }
        SYS_GETRUSAGE => {
            use crate::arch::Uaccess;
            use crate::task::syscall::sys_getrusage;
            sys_getrusage::<Uaccess>(arg0 as i32, arg1) as u64
        }
        SYS_GETRANDOM => {
            use crate::arch::Uaccess;
            use crate::task::syscall::sys_getrandom;
            sys_getrandom::<Uaccess>(arg0, arg1 as usize, arg2 as u32) as u64
        }

        // Resource limits
        SYS_GETRLIMIT => crate::rlimit::sys_getrlimit(arg0 as u32, arg1) as u64,
        SYS_SETRLIMIT => crate::rlimit::sys_setrlimit(arg0 as u32, arg1) as u64,
        SYS_PRLIMIT64 => crate::rlimit::sys_prlimit64(arg0 as i32, arg1 as u32, arg2, arg3) as u64,

        // Socket syscalls
        SYS_SOCKET => {
            use crate::net::syscall::sys_socket;
            sys_socket(arg0 as i32, arg1 as i32, arg2 as i32) as u64
        }
        SYS_CONNECT => {
            use crate::net::syscall::sys_connect;
            sys_connect(arg0 as i32, arg1, arg2) as u64
        }
        SYS_BIND => {
            use crate::net::syscall::sys_bind;
            sys_bind(arg0 as i32, arg1, arg2) as u64
        }
        SYS_LISTEN => {
            use crate::net::syscall::sys_listen;
            sys_listen(arg0 as i32, arg1 as i32) as u64
        }
        SYS_ACCEPT => {
            use crate::net::syscall::sys_accept;
            sys_accept(arg0 as i32, arg1, arg2) as u64
        }
        SYS_ACCEPT4 => {
            use crate::net::syscall::sys_accept4;
            sys_accept4(arg0 as i32, arg1, arg2, arg3 as i32) as u64
        }
        SYS_SHUTDOWN => {
            use crate::net::syscall::sys_shutdown;
            sys_shutdown(arg0 as i32, arg1 as i32) as u64
        }
        SYS_GETSOCKNAME => {
            use crate::net::syscall::sys_getsockname;
            sys_getsockname(arg0 as i32, arg1, arg2) as u64
        }
        SYS_GETPEERNAME => {
            use crate::net::syscall::sys_getpeername;
            sys_getpeername(arg0 as i32, arg1, arg2) as u64
        }
        SYS_SETSOCKOPT => {
            use crate::net::syscall::sys_setsockopt;
            sys_setsockopt(arg0 as i32, arg1 as i32, arg2 as i32, arg3, arg4) as u64
        }
        SYS_GETSOCKOPT => {
            use crate::net::syscall::sys_getsockopt;
            sys_getsockopt(arg0 as i32, arg1 as i32, arg2 as i32, arg3, arg4) as u64
        }
        SYS_SENDTO => {
            use crate::net::syscall::sys_sendto;
            sys_sendto(arg0 as i32, arg1, arg2, arg3 as i32, arg4, _arg5) as u64
        }
        SYS_RECVFROM => {
            use crate::net::syscall::sys_recvfrom;
            sys_recvfrom(arg0 as i32, arg1, arg2, arg3 as i32, arg4, _arg5) as u64
        }

        // Futex syscalls
        SYS_FUTEX => {
            crate::futex::sys_futex(arg0, arg1 as u32, arg2 as u32, arg3, arg4, _arg5 as u32) as u64
        }
        SYS_SET_ROBUST_LIST => crate::futex::sys_set_robust_list(arg0, arg1) as u64,
        SYS_GET_ROBUST_LIST => crate::futex::sys_get_robust_list(arg0 as i32, arg1, arg2) as u64,

        // SysV IPC syscalls
        SYS_SHMGET => crate::ipc::sys_shmget(arg0 as i32, arg1 as usize, arg2 as i32) as u64,
        SYS_SHMAT => crate::ipc::sys_shmat(arg0 as i32, arg1, arg2 as i32) as u64,
        SYS_SHMDT => crate::ipc::sys_shmdt(arg0) as u64,
        SYS_SHMCTL => crate::ipc::sys_shmctl(arg0 as i32, arg1 as i32, arg2) as u64,
        SYS_SEMGET => crate::ipc::sys_semget(arg0 as i32, arg1 as i32, arg2 as i32) as u64,
        SYS_SEMOP => crate::ipc::sys_semop(arg0 as i32, arg1, arg2 as usize) as u64,
        SYS_SEMTIMEDOP => crate::ipc::sys_semtimedop(arg0 as i32, arg1, arg2 as usize, arg3) as u64,
        SYS_SEMCTL => crate::ipc::sys_semctl(arg0 as i32, arg1 as i32, arg2 as i32, arg3) as u64,
        SYS_MSGGET => crate::ipc::sys_msgget(arg0 as i32, arg1 as i32) as u64,
        SYS_MSGSND => crate::ipc::sys_msgsnd(arg0 as i32, arg1, arg2 as usize, arg3 as i32) as u64,
        SYS_MSGRCV => {
            crate::ipc::sys_msgrcv(arg0 as i32, arg1, arg2 as usize, arg3 as i64, arg4 as i32)
                as u64
        }
        SYS_MSGCTL => crate::ipc::sys_msgctl(arg0 as i32, arg1 as i32, arg2) as u64,

        // Unimplemented syscalls
        _ => {
            printkln!("SYSCALL: unimplemented syscall {} on aarch64", num);
            (-38i64) as u64 // -ENOSYS
        }
    }
}

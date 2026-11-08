//! The syscall table, shared by every architecture (Linux
//! sys_call_table): [`Sys`] names a call, each arch maps its numbers
//! to it (`arch::*::syscall::sys_of`).

use crate::arch::Uaccess;
use crate::uaccess::UserPtr;
use crate::util::error::{KernelError, SysRet};

/// A system call, independent of its per-arch number
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sys {
    Accept,
    Accept4,
    Acct,
    AddKey,
    Adjtimex,
    Bind,
    Bpf,
    Brk,
    Capget,
    Capset,
    Chdir,
    Chroot,
    ClockGetres,
    ClockGettime,
    ClockNanosleep,
    ClockSettime,
    Clone,
    Clone3,
    Close,
    CloseRange,
    Connect,
    CopyFileRange,
    Dup,
    Dup3,
    EpollCreate1,
    EpollCtl,
    EpollPwait,
    EpollPwait2,
    Eventfd2,
    Execve,
    Execveat,
    Exit,
    ExitGroup,
    Faccessat,
    Faccessat2,
    Fadvise64,
    Fallocate,
    FanotifyInit,
    FanotifyMark,
    Fchdir,
    Fchmod,
    Fchmodat,
    Fchmodat2,
    Fchown,
    Fchownat,
    Fcntl,
    Fdatasync,
    Fgetxattr,
    Flistxattr,
    Flock,
    Fremovexattr,
    Fsetxattr,
    Fstat,
    Fstatfs,
    Fsync,
    Ftruncate,
    Futex,
    FutexWaitv,
    Getcpu,
    Getcwd,
    Getdents64,
    Getegid,
    Geteuid,
    Getgid,
    Getgroups,
    Getitimer,
    Getpeername,
    Getpgid,
    Getpid,
    Getppid,
    Getpriority,
    Getrandom,
    Getresgid,
    Getresuid,
    Getrlimit,
    Getrusage,
    Getsid,
    Getsockname,
    Getsockopt,
    Gettid,
    Gettimeofday,
    Getuid,
    Getxattr,
    GetMempolicy,
    GetRobustList,
    InotifyAddWatch,
    InotifyInit1,
    InotifyRmWatch,
    Ioctl,
    IoprioGet,
    IoprioSet,
    IoUringEnter,
    IoUringRegister,
    IoUringSetup,
    Kcmp,
    KexecLoad,
    Keyctl,
    Kill,
    Lgetxattr,
    Linkat,
    Listen,
    Listxattr,
    Llistxattr,
    Lremovexattr,
    Lseek,
    Lsetxattr,
    Madvise,
    Mbind,
    Membarrier,
    MigratePages,
    Mincore,
    Mkdirat,
    Mknodat,
    Mlock,
    Mlock2,
    Mlockall,
    Mmap,
    Mount,
    MovePages,
    Mprotect,
    MqGetsetattr,
    MqNotify,
    MqOpen,
    MqTimedreceive,
    MqTimedsend,
    MqUnlink,
    Mremap,
    Msgctl,
    Msgget,
    Msgrcv,
    Msgsnd,
    Msync,
    Munlock,
    Munlockall,
    Munmap,
    Nanosleep,
    Newfstatat,
    Openat,
    PerfEventOpen,
    Personality,
    PidfdGetfd,
    PidfdOpen,
    PidfdSendSignal,
    Pipe2,
    PivotRoot,
    Ppoll,
    Prctl,
    Pread64,
    Preadv,
    Preadv2,
    Prlimit64,
    ProcessVmReadv,
    ProcessVmWritev,
    Pselect6,
    Ptrace,
    Pwrite64,
    Pwritev,
    Pwritev2,
    Read,
    Readahead,
    Readlinkat,
    Readv,
    Reboot,
    Recvfrom,
    Recvmmsg,
    Recvmsg,
    Removexattr,
    Renameat,
    Renameat2,
    RequestKey,
    Rseq,
    RtSigaction,
    RtSigpending,
    RtSigprocmask,
    RtSigqueueinfo,
    RtSigsuspend,
    RtSigtimedwait,
    RtTgsigqueueinfo,
    SchedGetaffinity,
    SchedGetparam,
    SchedGetscheduler,
    SchedRrGetInterval,
    SchedSetaffinity,
    SchedSetparam,
    SchedSetscheduler,
    SchedYield,
    Seccomp,
    Semctl,
    Semget,
    Semop,
    Semtimedop,
    Sendfile,
    Sendmmsg,
    Sendmsg,
    Sendto,
    Setdomainname,
    Setfsgid,
    Setfsuid,
    Setgid,
    Setgroups,
    Sethostname,
    Setitimer,
    Setns,
    Setpgid,
    Setpriority,
    Setregid,
    Setresgid,
    Setresuid,
    Setreuid,
    Setrlimit,
    Setsid,
    Setsockopt,
    Settimeofday,
    Setuid,
    Setxattr,
    SetMempolicy,
    SetRobustList,
    SetTidAddress,
    Shmat,
    Shmctl,
    Shmdt,
    Shmget,
    Shutdown,
    Sigaltstack,
    Signalfd4,
    Socket,
    Socketpair,
    Splice,
    Statfs,
    Statx,
    Swapoff,
    Swapon,
    Symlinkat,
    Sync,
    Syncfs,
    SyncFileRange,
    Sysinfo,
    Syslog,
    Tee,
    Tgkill,
    TimerfdCreate,
    TimerfdGettime,
    TimerfdSettime,
    TimerCreate,
    TimerDelete,
    TimerGetoverrun,
    TimerGettime,
    TimerSettime,
    Times,
    Tkill,
    Truncate,
    Umask,
    Umount2,
    Uname,
    Unlinkat,
    Unshare,
    Utimensat,
    Vhangup,
    Vmsplice,
    Wait4,
    Waitid,
    Write,
    Writev,
}

/// Run `sys` with the raw argument registers `a`; the return register
pub fn dispatch(sys: Sys, a: [u64; 6]) -> u64 {
    match sys {
        Sys::Accept => {
            crate::net::syscall::sys_accept(a[0] as i32, UserPtr::new(a[1]), UserPtr::new(a[2]))
                .ret() as u64
        }
        Sys::Accept4 => crate::net::syscall::sys_accept4(
            a[0] as i32,
            UserPtr::new(a[1]),
            UserPtr::new(a[2]),
            a[3] as i32,
        )
        .ret() as u64,
        Sys::Acct => crate::task::acct::sys_acct(a[0]).ret() as u64,
        Sys::AddKey => crate::keys::sys_add_key(a[0], a[1], a[2], a[3], a[4] as i32).ret() as u64,
        Sys::Adjtimex => crate::time::time_syscall::sys_adjtimex(a[0]).ret() as u64,
        Sys::Bind => {
            crate::net::syscall::sys_bind(a[0] as i32, UserPtr::new(a[1]), a[2]).ret() as u64
        }
        Sys::Bpf => crate::bpf::sys_bpf(a[0] as i32, a[1], a[2] as u32).ret() as u64,
        Sys::Brk => crate::mm::syscall::sys_brk(a[0]).ret() as u64,
        Sys::Capget => crate::task::syscall::sys_capget::<Uaccess>(a[0], a[1]).ret() as u64,
        Sys::Capset => crate::task::syscall::sys_capset::<Uaccess>(a[0], a[1]).ret() as u64,
        Sys::Chdir => crate::fs::syscall::sys_chdir(a[0]).ret() as u64,
        Sys::Chroot => crate::fs::syscall::sys_chroot(a[0]).ret() as u64,
        Sys::ClockGetres => {
            crate::time::time_syscall::sys_clock_getres(a[0] as i32, a[1]).ret() as u64
        }
        Sys::ClockGettime => {
            crate::time::time_syscall::sys_clock_gettime(a[0] as i32, a[1]).ret() as u64
        }
        Sys::ClockNanosleep => {
            crate::time::time_syscall::sys_clock_nanosleep(a[0] as i32, a[1] as i32, a[2], a[3])
                as u64
        }
        Sys::ClockSettime => {
            crate::time::time_syscall::sys_clock_settime(a[0] as i32, a[1]).ret() as u64
        }
        Sys::Clone => {
            let (ctid, tls) = if crate::arch::CLONE_BACKWARDS {
                (a[4], a[3])
            } else {
                (a[3], a[4])
            };
            crate::task::syscall::sys_clone(a[0], a[1], a[2], ctid, tls).ret() as u64
        }
        Sys::Clone3 => crate::task::syscall::sys_clone3(a[0], a[1]).ret() as u64,
        Sys::Close => crate::fs::syscall::sys_close(a[0] as i32).ret() as u64,
        Sys::CloseRange => {
            crate::fs::syscall::sys_close_range(a[0] as u32, a[1] as u32, a[2] as u32).ret() as u64
        }
        Sys::Connect => {
            crate::net::syscall::sys_connect(a[0] as i32, UserPtr::new(a[1]), a[2]).ret() as u64
        }
        Sys::CopyFileRange => crate::fs::splice::sys_copy_file_range(
            a[0] as i32,
            a[1],
            a[2] as i32,
            a[3],
            a[4],
            a[5] as u32,
        )
        .ret() as u64,
        Sys::Dup => crate::fs::syscall::sys_dup(a[0] as i32).ret() as u64,
        Sys::Dup3 => {
            crate::fs::syscall::sys_dup3(a[0] as i32, a[1] as i32, a[2] as u32).ret() as u64
        }
        Sys::EpollCreate1 => crate::io::epoll::sys_epoll_create1(a[0] as i32).ret() as u64,
        Sys::EpollCtl => crate::io::epoll::sys_epoll_ctl(
            a[0] as i32,
            a[1] as i32,
            a[2] as i32,
            UserPtr::new(a[3]),
        )
        .ret() as u64,
        Sys::EpollPwait => crate::io::epoll::sys_epoll_pwait(
            a[0] as i32,
            UserPtr::new(a[1]),
            a[2] as i32,
            a[3] as i32,
            UserPtr::new(a[4]),
            a[5],
        )
        .ret() as u64,
        Sys::EpollPwait2 => crate::io::epoll::sys_epoll_pwait2(
            a[0] as i32,
            UserPtr::new(a[1]),
            a[2] as i32,
            UserPtr::new(a[3]),
            UserPtr::new(a[4]),
            a[5],
        )
        .ret() as u64,
        Sys::Eventfd2 => {
            crate::time::time_syscall::sys_eventfd2(a[0] as u32, a[1] as i32).ret() as u64
        }
        Sys::Execve => crate::task::exec::sys_execve(a[0], a[1], a[2]).ret() as u64,
        Sys::Execveat => {
            crate::task::exec::sys_execveat(a[0] as i32, a[1], a[2], a[3], a[4] as i32).ret() as u64
        }
        Sys::Exit => crate::task::syscall::sys_exit(a[0] as i32),
        Sys::ExitGroup => crate::task::proc::sys_exit_group(a[0] as i32),
        Sys::Faccessat => {
            crate::fs::syscall::sys_faccessat(a[0] as i32, a[1], a[2] as i32).ret() as u64
        }
        Sys::Faccessat2 => {
            crate::fs::syscall::sys_faccessat2(a[0] as i32, a[1], a[2] as i32, a[3] as i32).ret()
                as u64
        }
        Sys::Fadvise64 => {
            crate::fs::syscall::sys_fadvise64(a[0] as i32, a[1] as i64, a[2] as i64, a[3] as i32)
                as u64
        }
        Sys::Fallocate => {
            crate::fs::misc::sys_fallocate(a[0] as i32, a[1] as i32, a[2] as i64, a[3] as i64)
                as u64
        }
        Sys::FanotifyInit => {
            crate::io::fanotify::sys_fanotify_init(a[0] as u32, a[1] as u32).ret() as u64
        }
        Sys::FanotifyMark => crate::io::fanotify::sys_fanotify_mark(
            a[0] as i32,
            a[1] as u32,
            a[2],
            a[3] as i32,
            UserPtr::new(a[4]),
        )
        .ret() as u64,
        Sys::Fchdir => crate::fs::syscall::sys_fchdir(a[0] as i32).ret() as u64,
        Sys::Fchmod => crate::fs::syscall::sys_fchmod(a[0] as i32, a[1] as u32).ret() as u64,
        Sys::Fchmodat => {
            crate::fs::syscall::sys_fchmodat(a[0] as i32, a[1], a[2] as u32, a[3] as i32).ret()
                as u64
        }
        Sys::Fchmodat2 => {
            crate::fs::syscall::sys_fchmodat2(a[0] as i32, a[1], a[2] as u32, a[3] as i32).ret()
                as u64
        }
        Sys::Fchown => {
            crate::fs::syscall::sys_fchown(a[0] as i32, a[1] as u32, a[2] as u32).ret() as u64
        }
        Sys::Fchownat => crate::fs::syscall::sys_fchownat(
            a[0] as i32,
            a[1],
            a[2] as u32,
            a[3] as u32,
            a[4] as i32,
        )
        .ret() as u64,
        Sys::Fcntl => crate::fs::syscall::sys_fcntl(a[0] as i32, a[1] as i32, a[2]).ret() as u64,
        Sys::Fdatasync => crate::fs::syscall::sys_fdatasync(a[0] as i32).ret() as u64,
        Sys::Fgetxattr => {
            crate::fs::syscall::sys_fgetxattr(a[0] as i32, a[1], a[2], a[3]).ret() as u64
        }
        Sys::Flistxattr => crate::fs::syscall::sys_flistxattr(a[0] as i32, a[1], a[2]).ret() as u64,
        Sys::Flock => crate::fs::flock::sys_flock(a[0] as i32, a[1] as i32).ret() as u64,
        Sys::Fremovexattr => crate::fs::syscall::sys_fremovexattr(a[0] as i32, a[1]).ret() as u64,
        Sys::Fsetxattr => {
            crate::fs::syscall::sys_fsetxattr(a[0] as i32, a[1], a[2], a[3], a[4] as i32).ret()
                as u64
        }
        Sys::Fstat => crate::fs::syscall::sys_fstat(a[0] as i32, a[1]).ret() as u64,
        Sys::Fstatfs => crate::fs::syscall::sys_fstatfs(a[0] as i32, a[1]).ret() as u64,
        Sys::Fsync => crate::fs::syscall::sys_fsync(a[0] as i32).ret() as u64,
        Sys::Ftruncate => crate::fs::syscall::sys_ftruncate(a[0] as i32, a[1] as i64).ret() as u64,
        Sys::Futex => {
            crate::task::futex::sys_futex(a[0], a[1] as u32, a[2] as u32, a[3], a[4], a[5] as u32)
                as u64
        }
        Sys::FutexWaitv => {
            crate::task::futex::sys_futex_waitv(a[0], a[1] as u32, a[2] as u32, a[3], a[4] as i32)
                as u64
        }
        Sys::Getcpu => {
            crate::task::syscall::sys_getcpu::<Uaccess>(crate::cpu::this_id(), a[0], a[1]).ret()
                as u64
        }
        Sys::Getcwd => crate::fs::syscall::sys_getcwd(a[0], a[1]).ret() as u64,
        Sys::Getdents64 => crate::fs::syscall::sys_getdents64(a[0] as i32, a[1], a[2]).ret() as u64,
        Sys::Getegid => {
            crate::task::syscall::sys_getegid(crate::task::percpu::current_cred().egid).ret() as u64
        }
        Sys::Geteuid => {
            crate::task::syscall::sys_geteuid(crate::task::percpu::current_cred().euid).ret() as u64
        }
        Sys::Getgid => {
            crate::task::syscall::sys_getgid(crate::task::percpu::current_cred().gid).ret() as u64
        }
        Sys::Getgroups => {
            crate::task::syscall::sys_getgroups::<Uaccess>(a[0] as i32, a[1]).ret() as u64
        }
        Sys::Getitimer => crate::time::posix_timer::sys_getitimer(a[0] as i32, a[1]).ret() as u64,
        Sys::Getpeername => crate::net::syscall::sys_getpeername(
            a[0] as i32,
            UserPtr::new(a[1]),
            UserPtr::new(a[2]),
        )
        .ret() as u64,
        Sys::Getpgid => crate::task::syscall::sys_getpgid(
            a[0] as i32,
            crate::task::percpu::current_pid(),
            crate::task::percpu::current_pgid(),
        )
        .ret() as u64,
        Sys::Getpid => crate::task::syscall::sys_getpid().ret() as u64,
        Sys::Getppid => crate::task::syscall::sys_getppid().ret() as u64,
        Sys::Getpriority => {
            crate::task::syscall::sys_getpriority(a[0] as i32, a[1] as i32).ret() as u64
        }
        Sys::Getrandom => {
            crate::task::syscall::sys_getrandom::<Uaccess>(a[0], a[1] as usize, a[2] as u32).ret()
                as u64
        }
        Sys::Getresgid => crate::task::syscall::sys_getresgid::<Uaccess>(
            a[0],
            a[1],
            a[2],
            crate::task::percpu::current_cred(),
        )
        .ret() as u64,
        Sys::Getresuid => crate::task::syscall::sys_getresuid::<Uaccess>(
            a[0],
            a[1],
            a[2],
            crate::task::percpu::current_cred(),
        )
        .ret() as u64,
        Sys::Getrlimit => crate::task::rlimit::sys_getrlimit(a[0] as u32, a[1]).ret() as u64,
        Sys::Getrusage => {
            crate::task::syscall::sys_getrusage::<Uaccess>(a[0] as i32, a[1]).ret() as u64
        }
        Sys::Getsid => crate::task::syscall::sys_getsid(
            a[0] as i32,
            crate::task::percpu::current_pid(),
            crate::task::percpu::current_sid(),
        )
        .ret() as u64,
        Sys::Getsockname => crate::net::syscall::sys_getsockname(
            a[0] as i32,
            UserPtr::new(a[1]),
            UserPtr::new(a[2]),
        )
        .ret() as u64,
        Sys::Getsockopt => crate::net::syscall::sys_getsockopt(
            a[0] as i32,
            a[1] as i32,
            a[2] as i32,
            UserPtr::new(a[3]),
            UserPtr::new(a[4]),
        )
        .ret() as u64,
        Sys::Gettid => crate::task::syscall::sys_gettid().ret() as u64,
        Sys::Gettimeofday => crate::time::time_syscall::sys_gettimeofday(a[0], a[1]).ret() as u64,
        Sys::Getuid => {
            crate::task::syscall::sys_getuid(crate::task::percpu::current_cred().uid).ret() as u64
        }
        Sys::Getxattr => crate::fs::syscall::sys_getxattr(a[0], a[1], a[2], a[3]).ret() as u64,
        Sys::GetMempolicy => crate::mm::mempolicy::sys_get_mempolicy(
            UserPtr::new(a[0]),
            UserPtr::new(a[1]),
            a[2],
            a[3],
            a[4],
        )
        .ret() as u64,
        Sys::GetRobustList => {
            crate::task::futex::sys_get_robust_list(a[0] as i32, a[1], a[2]).ret() as u64
        }
        Sys::InotifyAddWatch => {
            crate::io::inotify::sys_inotify_add_watch(a[0] as i32, UserPtr::new(a[1]), a[2] as u32)
                .ret() as u64
        }
        Sys::InotifyInit1 => crate::io::inotify::sys_inotify_init1(a[0] as i32).ret() as u64,
        Sys::InotifyRmWatch => {
            crate::io::inotify::sys_inotify_rm_watch(a[0] as i32, a[1] as i32).ret() as u64
        }
        Sys::Ioctl => crate::fs::syscall::sys_ioctl(a[0] as i32, a[1] as u32, a[2]).ret() as u64,
        Sys::IoprioGet => {
            crate::task::syscall::sys_ioprio_get(a[0] as i32, a[1] as i32).ret() as u64
        }
        Sys::IoprioSet => {
            crate::task::syscall::sys_ioprio_set(a[0] as i32, a[1] as i32, a[2] as i32).ret() as u64
        }
        Sys::IoUringEnter => crate::io::io_uring::sys_io_uring_enter(
            a[0] as u32,
            a[1] as u32,
            a[2] as u32,
            a[3] as u32,
            a[4],
            a[5] as usize,
        )
        .ret() as u64,
        Sys::IoUringRegister => {
            crate::io::io_uring::sys_io_uring_register(a[0] as u32, a[1] as u32, a[2], a[3] as u32)
                .ret() as u64
        }
        Sys::IoUringSetup => {
            crate::io::io_uring::sys_io_uring_setup(a[0] as u32, UserPtr::new(a[1])).ret() as u64
        }
        Sys::Kcmp => crate::task::kcmp::sys_kcmp(a[0] as i32, a[1] as i32, a[2] as i32, a[3], a[4])
            .ret() as u64,
        Sys::KexecLoad => {
            if !crate::task::capable(crate::task::CAP_SYS_BOOT) {
                KernelError::NotPermitted.sysret() as u64
            } else {
                KernelError::NotImplemented.sysret() as u64
            }
        }
        Sys::Keyctl => crate::keys::sys_keyctl(a[0] as i32, a[1], a[2], a[3], a[4]).ret() as u64,
        Sys::Kill => {
            crate::signal::syscall::sys_kill(i64::from(a[0] as i32), a[1] as u32).ret() as u64
        }
        Sys::Lgetxattr => crate::fs::syscall::sys_lgetxattr(a[0], a[1], a[2], a[3]).ret() as u64,
        Sys::Linkat => {
            crate::fs::syscall::sys_linkat(a[0] as i32, a[1], a[2] as i32, a[3], a[4] as i32).ret()
                as u64
        }
        Sys::Listen => crate::net::syscall::sys_listen(a[0] as i32, a[1] as i32).ret() as u64,
        Sys::Listxattr => crate::fs::syscall::sys_listxattr(a[0], a[1], a[2]).ret() as u64,
        Sys::Llistxattr => crate::fs::syscall::sys_llistxattr(a[0], a[1], a[2]).ret() as u64,
        Sys::Lremovexattr => crate::fs::syscall::sys_lremovexattr(a[0], a[1]).ret() as u64,
        Sys::Lseek => {
            crate::fs::syscall::sys_lseek(a[0] as i32, a[1] as i64, a[2] as i32).ret() as u64
        }
        Sys::Lsetxattr => {
            crate::fs::syscall::sys_lsetxattr(a[0], a[1], a[2], a[3], a[4] as i32).ret() as u64
        }
        Sys::Madvise => crate::mm::madvise::sys_madvise(a[0], a[1], a[2] as i32).ret() as u64,
        Sys::Mbind => {
            crate::mm::mempolicy::sys_mbind(a[0], a[1], a[2], UserPtr::new(a[3]), a[4], a[5] as u32)
                .ret() as u64
        }
        Sys::Membarrier => {
            crate::task::membarrier::sys_membarrier(a[0] as i32, a[1] as u32, a[2] as i32).ret()
                as u64
        }
        Sys::MigratePages => crate::mm::mempolicy::sys_migrate_pages(
            i64::from(a[0] as i32),
            a[1],
            UserPtr::new(a[2]),
            UserPtr::new(a[3]),
        )
        .ret() as u64,
        Sys::Mincore => {
            crate::mm::syscall::sys_mincore(a[0], a[1], UserPtr::new(a[2])).ret() as u64
        }
        Sys::Mkdirat => {
            crate::fs::syscall::sys_mkdirat(a[0] as i32, a[1], a[2] as u32).ret() as u64
        }
        Sys::Mknodat => {
            crate::fs::syscall::sys_mknodat(a[0] as i32, a[1], a[2] as u32, a[3]).ret() as u64
        }
        Sys::Mlock => crate::mm::syscall::sys_mlock(a[0], a[1]).ret() as u64,
        Sys::Mlock2 => crate::mm::syscall::sys_mlock2(a[0], a[1], a[2] as i32).ret() as u64,
        Sys::Mlockall => crate::mm::syscall::sys_mlockall(a[0] as i32).ret() as u64,
        Sys::Mmap => {
            crate::mm::syscall::sys_mmap(a[0], a[1], a[2] as u32, a[3] as u32, a[4] as i32, a[5])
                .ret() as u64
        }
        Sys::Mount => crate::fs::syscall::sys_mount(a[0], a[1], a[2], a[3], a[4]).ret() as u64,
        Sys::MovePages => crate::mm::mempolicy::sys_move_pages(
            i64::from(a[0] as i32),
            a[1],
            UserPtr::new(a[2]),
            UserPtr::new(a[3]),
            UserPtr::new(a[4]),
            a[5] as i32,
        )
        .ret() as u64,
        Sys::Mprotect => crate::mm::syscall::sys_mprotect(a[0], a[1], a[2] as u32).ret() as u64,
        Sys::MqGetsetattr => {
            crate::ipc::sys_mq_getsetattr(a[0] as i32, UserPtr::new(a[1]), UserPtr::new(a[2])).ret()
                as u64
        }
        Sys::MqNotify => crate::ipc::sys_mq_notify(a[0] as i32, UserPtr::new(a[1])).ret() as u64,
        Sys::MqOpen => crate::ipc::sys_mq_open(
            UserPtr::new(a[0]),
            a[1] as i32,
            a[2] as u32,
            UserPtr::new(a[3]),
        )
        .ret() as u64,
        Sys::MqTimedreceive => crate::ipc::sys_mq_timedreceive(
            a[0] as i32,
            UserPtr::new(a[1]),
            a[2] as usize,
            UserPtr::new(a[3]),
            UserPtr::new(a[4]),
        )
        .ret() as u64,
        Sys::MqTimedsend => crate::ipc::sys_mq_timedsend(
            a[0] as i32,
            UserPtr::new(a[1]),
            a[2] as usize,
            a[3] as u32,
            UserPtr::new(a[4]),
        )
        .ret() as u64,
        Sys::MqUnlink => crate::ipc::sys_mq_unlink(UserPtr::new(a[0])).ret() as u64,
        Sys::Mremap => {
            crate::mm::syscall::sys_mremap(a[0], a[1], a[2], a[3] as u32, a[4]).ret() as u64
        }
        Sys::Msgctl => {
            crate::ipc::sys_msgctl(a[0] as i32, a[1] as i32, UserPtr::new(a[2])).ret() as u64
        }
        Sys::Msgget => crate::ipc::sys_msgget(a[0] as i32, a[1] as i32).ret() as u64,
        Sys::Msgrcv => crate::ipc::sys_msgrcv(
            a[0] as i32,
            UserPtr::new(a[1]),
            a[2] as usize,
            a[3] as i64,
            a[4] as i32,
        )
        .ret() as u64,
        Sys::Msgsnd => {
            crate::ipc::sys_msgsnd(a[0] as i32, UserPtr::new(a[1]), a[2] as usize, a[3] as i32)
                .ret() as u64
        }
        Sys::Msync => crate::mm::syscall::sys_msync(a[0], a[1], a[2] as i32).ret() as u64,
        Sys::Munlock => crate::mm::syscall::sys_munlock(a[0], a[1]).ret() as u64,
        Sys::Munlockall => crate::mm::syscall::sys_munlockall().ret() as u64,
        Sys::Munmap => crate::mm::syscall::sys_munmap(a[0], a[1]).ret() as u64,
        Sys::Nanosleep => crate::time::time_syscall::sys_nanosleep(a[0], a[1]).ret() as u64,
        Sys::Newfstatat => {
            crate::fs::stat::sys_fstatat(a[0] as i32, a[1], a[2], a[3] as i32).ret() as u64
        }
        Sys::Openat => {
            crate::fs::syscall::sys_openat(a[0] as i32, a[1], a[2] as u32, a[3] as u32).ret() as u64
        }
        Sys::PerfEventOpen => KernelError::OperationNotSupported.sysret() as u64,
        Sys::Personality => crate::task::syscall::sys_personality(a[0] as u32).ret() as u64,
        Sys::PidfdGetfd => {
            crate::task::syscall::sys_pidfd_getfd(a[0] as i32, a[1] as i32, a[2] as u32).ret()
                as u64
        }
        Sys::PidfdOpen => {
            crate::task::syscall::sys_pidfd_open(i64::from(a[0] as i32), a[1] as u32).ret() as u64
        }
        Sys::PidfdSendSignal => {
            crate::task::syscall::sys_pidfd_send_signal(a[0] as i32, a[1] as i32, a[2], a[3] as u32)
                as u64
        }
        Sys::Pipe2 => crate::fs::syscall::sys_pipe2(a[0], a[1] as u32).ret() as u64,
        Sys::PivotRoot => crate::fs::syscall::sys_pivot_root(a[0], a[1]).ret() as u64,
        Sys::Ppoll => {
            crate::fs::syscall::sys_ppoll(a[0], a[1] as u32, a[2], a[3], a[4]).ret() as u64
        }
        Sys::Prctl => {
            crate::task::syscall::sys_prctl(a[0] as i32, a[1], a[2], a[3], a[4]).ret() as u64
        }
        Sys::Pread64 => {
            crate::fs::syscall::sys_pread64(a[0] as i32, a[1], a[2], a[3] as i64).ret() as u64
        }
        Sys::Preadv => {
            crate::fs::syscall::sys_preadv(a[0] as i32, a[1], a[2] as i32, a[3] as i64).ret() as u64
        }
        Sys::Preadv2 => crate::fs::syscall::sys_preadv2(
            a[0] as i32,
            a[1],
            a[2] as i32,
            a[3] as i64,
            a[5] as i32,
        )
        .ret() as u64,
        Sys::Prlimit64 => {
            crate::task::rlimit::sys_prlimit64(a[0] as i32, a[1] as u32, a[2], a[3]).ret() as u64
        }
        Sys::ProcessVmReadv => {
            crate::task::process_vm::sys_process_vm_readv(a[0] as i32, a[1], a[2], a[3], a[4], a[5])
                as u64
        }
        Sys::ProcessVmWritev => crate::task::process_vm::sys_process_vm_writev(
            a[0] as i32,
            a[1],
            a[2],
            a[3],
            a[4],
            a[5],
        )
        .ret() as u64,
        Sys::Pselect6 => {
            crate::fs::syscall::sys_pselect6(a[0] as i32, a[1], a[2], a[3], a[4], a[5]).ret() as u64
        }
        Sys::Ptrace => {
            crate::task::ptrace::sys_ptrace(a[0] as i64, i64::from(a[1] as i32), a[2], a[3]).ret()
                as u64
        }
        Sys::Pwrite64 => {
            crate::fs::syscall::sys_pwrite64(a[0] as i32, a[1], a[2], a[3] as i64).ret() as u64
        }
        Sys::Pwritev => {
            crate::fs::syscall::sys_pwritev(a[0] as i32, a[1], a[2] as i32, a[3] as i64).ret()
                as u64
        }
        Sys::Pwritev2 => crate::fs::syscall::sys_pwritev2(
            a[0] as i32,
            a[1],
            a[2] as i32,
            a[3] as i64,
            a[5] as i32,
        )
        .ret() as u64,
        Sys::Read => crate::fs::syscall::sys_read(a[0] as i32, a[1], a[2]).ret() as u64,
        Sys::Readahead => {
            crate::fs::syscall::sys_readahead(a[0] as i32, a[1] as i64, a[2] as usize).ret() as u64
        }
        Sys::Readlinkat => {
            crate::fs::syscall::sys_readlinkat(a[0] as i32, a[1], a[2], a[3]).ret() as u64
        }
        Sys::Readv => crate::fs::syscall::sys_readv(a[0] as i32, a[1], a[2] as i32).ret() as u64,
        Sys::Reboot => {
            crate::power::sys_reboot(a[0] as u32, a[1] as u32, a[2] as u32, a[3]).ret() as u64
        }
        Sys::Recvfrom => crate::net::syscall::sys_recvfrom(
            a[0] as i32,
            UserPtr::new(a[1]),
            a[2],
            a[3] as i32,
            UserPtr::new(a[4]),
            UserPtr::new(a[5]),
        )
        .ret() as u64,
        Sys::Recvmmsg => crate::net::syscall::sys_recvmmsg(
            a[0] as i32,
            UserPtr::new(a[1]),
            a[2] as u32,
            a[3] as i32,
            UserPtr::new(a[4]),
        )
        .ret() as u64,
        Sys::Recvmsg => {
            crate::net::syscall::sys_recvmsg(a[0] as i32, UserPtr::new(a[1]), a[2] as i32).ret()
                as u64
        }
        Sys::Removexattr => crate::fs::syscall::sys_removexattr(a[0], a[1]).ret() as u64,
        Sys::Renameat => {
            crate::fs::syscall::sys_renameat(a[0] as i32, a[1], a[2] as i32, a[3]).ret() as u64
        }
        Sys::Renameat2 => {
            crate::fs::syscall::sys_renameat2(a[0] as i32, a[1], a[2] as i32, a[3], a[4] as u32)
                as u64
        }
        Sys::RequestKey => crate::keys::sys_request_key(a[0], a[1], a[2], a[3] as i32).ret() as u64,
        Sys::Rseq => KernelError::NotImplemented.sysret() as u64,
        Sys::RtSigaction => {
            crate::signal::syscall::sys_rt_sigaction(a[0] as u32, a[1], a[2], a[3]).ret() as u64
        }
        Sys::RtSigpending => crate::signal::syscall::sys_rt_sigpending(a[0], a[1]).ret() as u64,
        Sys::RtSigprocmask => {
            crate::signal::syscall::sys_rt_sigprocmask(a[0] as i32, a[1], a[2], a[3]).ret() as u64
        }
        Sys::RtSigqueueinfo => {
            crate::signal::syscall::sys_rt_sigqueueinfo(i64::from(a[0] as i32), a[1] as u32, a[2])
                as u64
        }
        Sys::RtSigsuspend => crate::signal::syscall::sys_rt_sigsuspend(a[0], a[1]).ret() as u64,
        Sys::RtSigtimedwait => {
            crate::signal::syscall::sys_rt_sigtimedwait(a[0], a[1], a[2], a[3]).ret() as u64
        }
        Sys::RtTgsigqueueinfo => crate::signal::syscall::sys_rt_tgsigqueueinfo(
            i64::from(a[0] as i32),
            i64::from(a[1] as i32),
            a[2] as u32,
            a[3],
        )
        .ret() as u64,
        Sys::SchedGetaffinity => crate::task::syscall::sys_sched_getaffinity::<Uaccess>(
            i64::from(a[0] as i32),
            a[1],
            a[2],
        )
        .ret() as u64,
        Sys::SchedGetparam => {
            crate::task::syscall::sys_sched_getparam::<Uaccess>(i64::from(a[0] as i32), a[1]).ret()
                as u64
        }
        Sys::SchedGetscheduler => {
            crate::task::syscall::sys_sched_getscheduler(i64::from(a[0] as i32)).ret() as u64
        }
        Sys::SchedRrGetInterval => {
            crate::task::syscall::sys_sched_rr_get_interval::<Uaccess>(i64::from(a[0] as i32), a[1])
                as u64
        }
        Sys::SchedSetaffinity => crate::task::syscall::sys_sched_setaffinity::<Uaccess>(
            i64::from(a[0] as i32),
            a[1],
            a[2],
        )
        .ret() as u64,
        Sys::SchedSetparam => {
            crate::task::syscall::sys_sched_setparam::<Uaccess>(i64::from(a[0] as i32), a[1]).ret()
                as u64
        }
        Sys::SchedSetscheduler => crate::task::syscall::sys_sched_setscheduler::<Uaccess>(
            i64::from(a[0] as i32),
            a[1] as i32,
            a[2],
        )
        .ret() as u64,
        Sys::SchedYield => {
            crate::task::syscall::sys_sched_yield();
            0
        }
        Sys::Seccomp => crate::seccomp::sys_seccomp(a[0], a[1], a[2]).ret() as u64,
        Sys::Semctl => {
            crate::ipc::sys_semctl(a[0] as i32, a[1] as i32, a[2] as i32, a[3]).ret() as u64
        }
        Sys::Semget => crate::ipc::sys_semget(a[0] as i32, a[1] as i32, a[2] as i32).ret() as u64,
        Sys::Semop => {
            crate::ipc::sys_semop(a[0] as i32, UserPtr::new(a[1]), a[2] as usize).ret() as u64
        }
        Sys::Semtimedop => crate::ipc::sys_semtimedop(
            a[0] as i32,
            UserPtr::new(a[1]),
            a[2] as usize,
            UserPtr::new(a[3]),
        )
        .ret() as u64,
        Sys::Sendfile => {
            crate::fs::splice::sys_sendfile64(a[0] as i32, a[1] as i32, a[2], a[3] as usize).ret()
                as u64
        }
        Sys::Sendmmsg => crate::net::syscall::sys_sendmmsg(
            a[0] as i32,
            UserPtr::new(a[1]),
            a[2] as u32,
            a[3] as i32,
        )
        .ret() as u64,
        Sys::Sendmsg => {
            crate::net::syscall::sys_sendmsg(a[0] as i32, UserPtr::new(a[1]), a[2] as i32).ret()
                as u64
        }
        Sys::Sendto => crate::net::syscall::sys_sendto(
            a[0] as i32,
            UserPtr::new(a[1]),
            a[2],
            a[3] as i32,
            UserPtr::new(a[4]),
            a[5],
        )
        .ret() as u64,
        Sys::Setdomainname => crate::ns::uts::sys_setdomainname(a[0], a[1]).ret() as u64,
        Sys::Setfsgid => {
            crate::task::syscall::sys_setfsgid(a[0] as u32, crate::task::percpu::current_cred())
                as u64
        }
        Sys::Setfsuid => {
            crate::task::syscall::sys_setfsuid(a[0] as u32, crate::task::percpu::current_cred())
                as u64
        }
        Sys::Setgid => {
            crate::task::syscall::sys_setgid(a[0] as u32, crate::task::percpu::current_cred())
                as u64
        }
        Sys::Setgroups => {
            crate::task::syscall::sys_setgroups::<Uaccess>(a[0] as i32, a[1]).ret() as u64
        }
        Sys::Sethostname => crate::ns::uts::sys_sethostname(a[0], a[1]).ret() as u64,
        Sys::Setitimer => {
            crate::time::posix_timer::sys_setitimer(a[0] as i32, a[1], a[2]).ret() as u64
        }
        Sys::Setns => crate::ns::sys_setns(a[0] as i32, a[1] as i32).ret() as u64,
        Sys::Setpgid => crate::task::syscall::sys_setpgid(
            a[0] as i32,
            a[1] as i32,
            crate::task::percpu::current_pid(),
            crate::task::percpu::current_pgid(),
            crate::task::percpu::current_sid(),
        )
        .ret() as u64,
        Sys::Setpriority => {
            crate::task::syscall::sys_setpriority(a[0] as i32, a[1] as i32, a[2] as i32).ret()
                as u64
        }
        Sys::Setregid => crate::task::syscall::sys_setregid(
            a[0] as u32,
            a[1] as u32,
            crate::task::percpu::current_cred(),
        )
        .ret() as u64,
        Sys::Setresgid => crate::task::syscall::sys_setresgid(
            a[0] as u32,
            a[1] as u32,
            a[2] as u32,
            crate::task::percpu::current_cred(),
        )
        .ret() as u64,
        Sys::Setresuid => crate::task::syscall::sys_setresuid(
            a[0] as u32,
            a[1] as u32,
            a[2] as u32,
            crate::task::percpu::current_cred(),
        )
        .ret() as u64,
        Sys::Setreuid => crate::task::syscall::sys_setreuid(
            a[0] as u32,
            a[1] as u32,
            crate::task::percpu::current_cred(),
        )
        .ret() as u64,
        Sys::Setrlimit => crate::task::rlimit::sys_setrlimit(a[0] as u32, a[1]).ret() as u64,
        Sys::Setsid => {
            crate::task::syscall::sys_setsid(crate::task::percpu::current_pid()).ret() as u64
        }
        Sys::Setsockopt => crate::net::syscall::sys_setsockopt(
            a[0] as i32,
            a[1] as i32,
            a[2] as i32,
            UserPtr::new(a[3]),
            a[4] as i32,
        )
        .ret() as u64,
        Sys::Settimeofday => crate::time::time_syscall::sys_settimeofday(a[0], a[1]).ret() as u64,
        Sys::Setuid => {
            crate::task::syscall::sys_setuid(a[0] as u32, crate::task::percpu::current_cred())
                as u64
        }
        Sys::Setxattr => {
            crate::fs::syscall::sys_setxattr(a[0], a[1], a[2], a[3], a[4] as i32).ret() as u64
        }
        Sys::SetMempolicy => {
            crate::mm::mempolicy::sys_set_mempolicy(a[0] as i32, UserPtr::new(a[1]), a[2]).ret()
                as u64
        }
        Sys::SetRobustList => crate::task::futex::sys_set_robust_list(a[0], a[1]).ret() as u64,
        Sys::SetTidAddress => crate::task::syscall::sys_set_tid_address(a[0]).ret() as u64,
        Sys::Shmat => crate::ipc::sys_shmat(a[0] as i32, a[1], a[2] as i32).ret() as u64,
        Sys::Shmctl => {
            crate::ipc::sys_shmctl(a[0] as i32, a[1] as i32, UserPtr::new(a[2])).ret() as u64
        }
        Sys::Shmdt => crate::ipc::sys_shmdt(a[0]).ret() as u64,
        Sys::Shmget => crate::ipc::sys_shmget(a[0] as i32, a[1] as usize, a[2] as i32).ret() as u64,
        Sys::Shutdown => crate::net::syscall::sys_shutdown(a[0] as i32, a[1] as i32).ret() as u64,
        Sys::Sigaltstack => crate::signal::syscall::sys_sigaltstack(a[0], a[1]).ret() as u64,
        Sys::Signalfd4 => {
            crate::signal::syscall::sys_signalfd4(a[0] as i32, a[1], a[2], a[3] as i32).ret() as u64
        }
        Sys::Socket => {
            crate::net::syscall::sys_socket(a[0] as i32, a[1] as i32, a[2] as i32).ret() as u64
        }
        Sys::Socketpair => crate::net::syscall::sys_socketpair(
            a[0] as i32,
            a[1] as i32,
            a[2] as i32,
            UserPtr::new(a[3]),
        )
        .ret() as u64,
        Sys::Splice => crate::fs::splice::sys_splice(
            a[0] as i32,
            a[1],
            a[2] as i32,
            a[3],
            a[4] as usize,
            a[5] as u32,
        )
        .ret() as u64,
        Sys::Statfs => crate::fs::syscall::sys_statfs(a[0], a[1]).ret() as u64,
        Sys::Statx => {
            crate::fs::syscall::sys_statx(a[0] as i32, a[1], a[2] as i32, a[3] as u32, a[4]).ret()
                as u64
        }
        Sys::Swapoff => crate::mm::sys_swapoff(UserPtr::new(a[0])).ret() as u64,
        Sys::Swapon => crate::mm::sys_swapon(UserPtr::new(a[0]), a[1] as i32).ret() as u64,
        Sys::Symlinkat => crate::fs::syscall::sys_symlinkat(a[0], a[1] as i32, a[2]).ret() as u64,
        Sys::Sync => crate::fs::syscall::sys_sync().ret() as u64,
        Sys::Syncfs => crate::fs::syscall::sys_syncfs(a[0] as i32).ret() as u64,
        Sys::SyncFileRange => crate::fs::syscall::sys_sync_file_range(
            a[0] as i32,
            a[1] as i64,
            a[2] as i64,
            a[3] as u32,
        )
        .ret() as u64,
        Sys::Sysinfo => crate::task::syscall::sys_sysinfo::<Uaccess>(a[0]).ret() as u64,
        Sys::Syslog => {
            crate::task::syscall::sys_syslog::<Uaccess>(a[0] as i32, a[1], a[2] as i32).ret() as u64
        }
        Sys::Tee => {
            crate::fs::splice::sys_tee(a[0] as i32, a[1] as i32, a[2] as usize, a[3] as u32).ret()
                as u64
        }
        Sys::Tgkill => crate::signal::syscall::sys_tgkill(
            i64::from(a[0] as i32),
            i64::from(a[1] as i32),
            a[2] as u32,
        )
        .ret() as u64,
        Sys::TimerfdCreate => {
            crate::time::time_syscall::sys_timerfd_create(a[0] as i32, a[1] as i32).ret() as u64
        }
        Sys::TimerfdGettime => {
            crate::time::time_syscall::sys_timerfd_gettime(a[0] as i32, a[1]).ret() as u64
        }
        Sys::TimerfdSettime => {
            crate::time::time_syscall::sys_timerfd_settime(a[0] as i32, a[1] as i32, a[2], a[3])
                as u64
        }
        Sys::TimerCreate => {
            crate::time::posix_timer::sys_timer_create(a[0] as i32, a[1], a[2]).ret() as u64
        }
        Sys::TimerDelete => crate::time::posix_timer::sys_timer_delete(a[0] as i32).ret() as u64,
        Sys::TimerGetoverrun => {
            crate::time::posix_timer::sys_timer_getoverrun(a[0] as i32).ret() as u64
        }
        Sys::TimerGettime => {
            crate::time::posix_timer::sys_timer_gettime(a[0] as i32, a[1]).ret() as u64
        }
        Sys::TimerSettime => {
            crate::time::posix_timer::sys_timer_settime(a[0] as i32, a[1] as i32, a[2], a[3]).ret()
                as u64
        }
        Sys::Times => crate::task::syscall::sys_times::<Uaccess>(a[0]).ret() as u64,
        Sys::Tkill => {
            crate::signal::syscall::sys_tkill(i64::from(a[0] as i32), a[1] as u32).ret() as u64
        }
        Sys::Truncate => crate::fs::syscall::sys_truncate(a[0], a[1] as i64).ret() as u64,
        Sys::Umask => crate::fs::syscall::sys_umask(a[0] as u32).ret() as u64,
        Sys::Umount2 => crate::fs::syscall::sys_umount2(a[0], a[1] as i32).ret() as u64,
        Sys::Uname => crate::ns::uts::sys_uname(a[0]).ret() as u64,
        Sys::Unlinkat => {
            crate::fs::syscall::sys_unlinkat(a[0] as i32, a[1], a[2] as i32).ret() as u64
        }
        Sys::Unshare => crate::ns::sys_unshare(a[0]).ret() as u64,
        Sys::Utimensat => {
            crate::fs::syscall::sys_utimensat(a[0] as i32, a[1], a[2], a[3] as i32).ret() as u64
        }
        Sys::Vhangup => crate::tty::sys_vhangup().ret() as u64,
        Sys::Vmsplice => {
            crate::fs::splice::sys_vmsplice(a[0] as i32, a[1], a[2] as usize, a[3] as u32).ret()
                as u64
        }
        Sys::Wait4 => {
            crate::task::syscall::sys_wait4(i64::from(a[0] as i32), a[1], a[2] as i32, a[3]).ret()
                as u64
        }
        Sys::Waitid => crate::task::syscall::sys_waitid(a[0] as i32, a[1], a[2], a[3] as i32, a[4])
            .ret() as u64,
        Sys::Write => crate::fs::syscall::sys_write(a[0] as i32, a[1], a[2]).ret() as u64,
        Sys::Writev => crate::fs::syscall::sys_writev(a[0] as i32, a[1], a[2] as i32).ret() as u64,
    }
}

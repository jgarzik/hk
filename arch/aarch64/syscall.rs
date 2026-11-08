//! AArch64 Linux syscall implementation
//!
//! Key differences from x86_64:
//! - Syscall number in X8 (not RAX)
//! - Arguments in X0-X5 (not RDI/RSI/RDX/R10/R8/R9)
//! - Different syscall numbers (ARM64 uses newer Linux ABI)
//! - Some legacy syscalls removed (open, fork, dup2)

// Syscall numbers are a reference table for Linux ABI compatibility

use crate::syscall::Sys;
use crate::util::error::SysRet;

// ============================================================================
// AArch64 Linux syscall numbers (different from x86_64!)
// ============================================================================

// I/O syscalls
/// fcntl(fd, cmd, arg)
pub const SYS_FCNTL: u64 = 25;
pub const SYS_DUP: u64 = 23;
pub const SYS_DUP3: u64 = 24;
pub const SYS_GETCWD: u64 = 17;
pub const SYS_EXECVEAT: u64 = 281;
pub const SYS_GETTIMEOFDAY: u64 = 169;
pub const SYS_SETTIMEOFDAY: u64 = 170;
pub const SYS_PIPE2: u64 = 59;
pub const SYS_PPOLL: u64 = 73;
pub const SYS_PSELECT6: u64 = 72;
pub const SYS_MKNODAT: u64 = 33;
pub const SYS_MKDIRAT: u64 = 34;
pub const SYS_UNLINKAT: u64 = 35;
pub const SYS_SYMLINKAT: u64 = 36;
pub const SYS_LINKAT: u64 = 37;
pub const SYS_RENAMEAT: u64 = 38;
pub const SYS_RENAMEAT2: u64 = 276;
pub const SYS_UMOUNT2: u64 = 39;
pub const SYS_MOUNT: u64 = 40;
/// pivot_root(new_root, put_old)
pub const SYS_PIVOT_ROOT: u64 = 41;
pub const SYS_SWAPON: u64 = 224;
pub const SYS_SWAPOFF: u64 = 225;
pub const SYS_FTRUNCATE: u64 = 46;
pub const SYS_TRUNCATE: u64 = 45;
pub const SYS_FACCESSAT: u64 = 48;
pub const SYS_CHDIR: u64 = 49;
pub const SYS_FCHDIR: u64 = 50;
pub const SYS_CHROOT: u64 = 51;
pub const SYS_FACCESSAT2: u64 = 439;
pub const SYS_FCHMOD: u64 = 52;
pub const SYS_FCHMODAT: u64 = 53;
pub const SYS_FCHOWNAT: u64 = 54;
/// fchmodat2(dirfd, pathname, mode, flags) - extended fchmodat with flags
pub const SYS_FCHMODAT2: u64 = 452;
pub const SYS_FCHOWN: u64 = 55;
pub const SYS_OPENAT: u64 = 56;
pub const SYS_CLOSE: u64 = 57;
pub const SYS_CLOSE_RANGE: u64 = 436;
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
/// preadv2(fd, iov, iovcnt, offset, flags)
pub const SYS_PREADV2: u64 = 286;
/// pwritev2(fd, iov, iovcnt, offset, flags)
pub const SYS_PWRITEV2: u64 = 287;
/// statfs(path, buf)
pub const SYS_STATFS: u64 = 43;
/// fstatfs(fd, buf)
pub const SYS_FSTATFS: u64 = 44;
pub const SYS_READLINKAT: u64 = 78;
pub const SYS_FSTATAT: u64 = 79;
pub const SYS_FSTAT: u64 = 80;
pub const SYS_UTIMENSAT: u64 = 88;

// Sync syscalls
pub const SYS_SYNC: u64 = 81;
pub const SYS_FSYNC: u64 = 82;
pub const SYS_FDATASYNC: u64 = 83;
pub const SYS_SYNCFS: u64 = 267;

// Extended attributes (xattr) syscalls - aarch64 numbers
/// setxattr(path, name, value, size, flags)
pub const SYS_SETXATTR: u64 = 5;
/// lsetxattr(path, name, value, size, flags)
pub const SYS_LSETXATTR: u64 = 6;
/// fsetxattr(fd, name, value, size, flags)
pub const SYS_FSETXATTR: u64 = 7;
/// getxattr(path, name, value, size)
pub const SYS_GETXATTR: u64 = 8;
/// lgetxattr(path, name, value, size)
pub const SYS_LGETXATTR: u64 = 9;
/// fgetxattr(fd, name, value, size)
pub const SYS_FGETXATTR: u64 = 10;
/// listxattr(path, list, size)
pub const SYS_LISTXATTR: u64 = 11;
/// llistxattr(path, list, size)
pub const SYS_LLISTXATTR: u64 = 12;
/// flistxattr(fd, list, size)
pub const SYS_FLISTXATTR: u64 = 13;
/// removexattr(path, name)
pub const SYS_REMOVEXATTR: u64 = 14;
/// lremovexattr(path, name)
pub const SYS_LREMOVEXATTR: u64 = 15;
/// fremovexattr(fd, name)
pub const SYS_FREMOVEXATTR: u64 = 16;

/// ioctl(fd, request, arg)
pub const SYS_IOCTL: u64 = 29;

// Splice/sendfile/copy syscalls
/// flock(fd, operation)
pub const SYS_FLOCK: u64 = 32;
/// fallocate(fd, mode, offset, len)
pub const SYS_FALLOCATE: u64 = 47;
/// sendfile(out_fd, in_fd, offset, count)
pub const SYS_SENDFILE: u64 = 71;
/// vmsplice(fd, iov, nr_segs, flags)
pub const SYS_VMSPLICE: u64 = 75;
/// splice(fd_in, off_in, fd_out, off_out, len, flags)
pub const SYS_SPLICE: u64 = 76;
/// tee(fd_in, fd_out, len, flags)
pub const SYS_TEE: u64 = 77;
/// copy_file_range(fd_in, off_in, fd_out, off_out, len, flags)
pub const SYS_COPY_FILE_RANGE: u64 = 285;

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
/// clock_settime(clockid, tp)
pub const SYS_CLOCK_SETTIME: u64 = 112;
pub const SYS_CLOCK_GETTIME: u64 = 113;
pub const SYS_CLOCK_GETRES: u64 = 114;
pub const SYS_CLOCK_NANOSLEEP: u64 = 115;
/// timerfd_create(clockid, flags)
pub const SYS_TIMERFD_CREATE: u64 = 85;
/// timerfd_settime(fd, flags, new_value, old_value)
pub const SYS_TIMERFD_SETTIME: u64 = 86;
/// timerfd_gettime(fd, curr_value)
pub const SYS_TIMERFD_GETTIME: u64 = 87;
/// adjtimex(txc) - read/set kernel clock parameters
pub const SYS_ADJTIMEX: u64 = 171;

// eventfd syscalls (Section 7.1)
/// eventfd2(initval, flags) - NOTE: aarch64 only has eventfd2, not legacy eventfd
pub const SYS_EVENTFD2: u64 = 19;

// signalfd syscalls (Section 5) - NOTE: aarch64 only has signalfd4, not legacy signalfd
/// signalfd4(fd, mask, sizemask, flags)
pub const SYS_SIGNALFD4: u64 = 74;

// inotify syscalls (Section 9.2) - NOTE: aarch64 only has inotify_init1, not legacy inotify_init
/// inotify_init1(flags)
pub const SYS_INOTIFY_INIT1: u64 = 26;
/// inotify_add_watch(fd, pathname, mask)
pub const SYS_INOTIFY_ADD_WATCH: u64 = 27;
/// inotify_rm_watch(fd, wd)
pub const SYS_INOTIFY_RM_WATCH: u64 = 28;

// fanotify syscalls (Section 9.2)
/// fanotify_init(flags, event_f_flags)
pub const SYS_FANOTIFY_INIT: u64 = 262;
/// fanotify_mark(fanotify_fd, flags, mask, dirfd, pathname)
pub const SYS_FANOTIFY_MARK: u64 = 263;

// epoll syscalls (Section 9.1) - NOTE: aarch64 only has epoll_create1, not legacy epoll_create
/// epoll_create1(flags)
pub const SYS_EPOLL_CREATE1: u64 = 20;
/// epoll_ctl(epfd, op, fd, event)
pub const SYS_EPOLL_CTL: u64 = 21;
/// epoll_pwait(epfd, events, maxevents, timeout, sigmask, sigsetsize)
pub const SYS_EPOLL_PWAIT: u64 = 22;
/// epoll_pwait2(epfd, events, maxevents, timeout, sigmask, sigsetsize)
pub const SYS_EPOLL_PWAIT2: u64 = 441;

// io_uring syscalls (Section 9.3)
/// io_uring_setup(entries, params)
pub const SYS_IO_URING_SETUP: u64 = 425;
/// io_uring_enter(fd, to_submit, min_complete, flags, argp, argsz)
pub const SYS_IO_URING_ENTER: u64 = 426;
/// io_uring_register(fd, opcode, arg, nr_args)
pub const SYS_IO_URING_REGISTER: u64 = 427;

// POSIX timer syscalls (Section 6.2)
/// timer_create(clockid, sigevent, timerid)
pub const SYS_GETITIMER: u64 = 102;
pub const SYS_SETITIMER: u64 = 103;
pub const SYS_TIMER_CREATE: u64 = 107;
/// timer_gettime(timerid, curr_value)
pub const SYS_TIMER_GETTIME: u64 = 108;
/// timer_getoverrun(timerid)
pub const SYS_TIMER_GETOVERRUN: u64 = 109;
/// timer_settime(timerid, flags, new_value, old_value)
pub const SYS_TIMER_SETTIME: u64 = 110;
/// timer_delete(timerid)
pub const SYS_TIMER_DELETE: u64 = 111;

// POSIX message queue syscalls (Section 7.4)
/// mq_open(name, oflag, mode, attr)
pub const SYS_MQ_OPEN: u64 = 180;
/// mq_unlink(name)
pub const SYS_MQ_UNLINK: u64 = 181;
/// mq_timedsend(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout)
pub const SYS_MQ_TIMEDSEND: u64 = 182;
/// mq_timedreceive(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout)
pub const SYS_MQ_TIMEDRECEIVE: u64 = 183;
/// mq_notify(mqdes, sevp)
pub const SYS_MQ_NOTIFY: u64 = 184;
/// mq_getsetattr(mqdes, newattr, oldattr)
pub const SYS_MQ_GETSETATTR: u64 = 185;

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
pub const SYS_GETGROUPS: u64 = 158;
pub const SYS_SETGROUPS: u64 = 159;
pub const SYS_SETRESGID: u64 = 149;
/// getresgid(rgid*, egid*, sgid*)
pub const SYS_GETRESGID: u64 = 150;
/// setfsuid(uid)
pub const SYS_SETFSUID: u64 = 151;
/// setfsgid(gid)
pub const SYS_SETFSGID: u64 = 152;
/// capget(hdrp, datap)
pub const SYS_CAPGET: u64 = 90;
/// capset(hdrp, datap)
pub const SYS_CAPSET: u64 = 91;
pub const SYS_GETUID: u64 = 174;
pub const SYS_GETEUID: u64 = 175;
pub const SYS_GETGID: u64 = 176;
pub const SYS_GETEGID: u64 = 177;
pub const SYS_GETTID: u64 = 178;

// Memory syscalls
pub const SYS_BRK: u64 = 214;
pub const SYS_MUNMAP: u64 = 215;
pub const SYS_CLONE: u64 = 220;
/// clone3(uargs, size) - Modern extensible clone
pub const SYS_CLONE3: u64 = 435;
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
/// msync(addr, length, flags)
pub const SYS_MSYNC: u64 = 227;
/// mincore(addr, length, vec)
pub const SYS_MINCORE: u64 = 232;
/// madvise(addr, length, advice)
pub const SYS_MADVISE: u64 = 233;
/// mremap(old_addr, old_len, new_len, flags, new_addr)
pub const SYS_MREMAP: u64 = 216;
pub const SYS_WAIT4: u64 = 260;

// Signal syscalls (aarch64 numbers)
pub const SYS_KILL: u64 = 129;
pub const SYS_TKILL: u64 = 130;
pub const SYS_TGKILL: u64 = 131;
pub const SYS_SIGALTSTACK: u64 = 132;
pub const SYS_RT_SIGACTION: u64 = 134;
pub const SYS_RT_SIGPROCMASK: u64 = 135;
pub const SYS_RT_SIGPENDING: u64 = 136;
pub const SYS_RT_SIGTIMEDWAIT: u64 = 137;
pub const SYS_RT_SIGRETURN: u64 = 139;
/// rt_sigqueueinfo(pid, sig, uinfo)
pub const SYS_RT_SIGQUEUEINFO: u64 = 138;
/// rt_sigsuspend(mask, sigsetsize)
pub const SYS_RT_SIGSUSPEND: u64 = 133;
/// rt_tgsigqueueinfo(tgid, tid, sig, uinfo)
pub const SYS_RT_TGSIGQUEUEINFO: u64 = 240;

// Memory barrier syscall
pub const SYS_MEMBARRIER: u64 = 283;

// File readahead syscall
pub const SYS_FADVISE64: u64 = 223;
pub const SYS_SYNC_FILE_RANGE: u64 = 84;
pub const SYS_READAHEAD: u64 = 213;

// NUMA memory policy (Section 4.2)
/// mbind(start, len, mode, nodemask, maxnode, flags)
pub const SYS_MBIND: u64 = 235;
/// get_mempolicy(policy, nodemask, maxnode, addr, flags)
pub const SYS_GET_MEMPOLICY: u64 = 236;
/// set_mempolicy(mode, nodemask, maxnode)
pub const SYS_SET_MEMPOLICY: u64 = 237;
/// migrate_pages(pid, maxnode, old_nodes, new_nodes)
pub const SYS_MIGRATE_PAGES: u64 = 238;
/// move_pages(pid, nr_pages, pages, nodes, status, flags)
pub const SYS_MOVE_PAGES: u64 = 239;

// Scheduling priority (aarch64 numbers - note: swapped from x86_64)
/// setpriority(which, who, niceval)
pub const SYS_SETPRIORITY: u64 = 140;
/// getpriority(which, who)
pub const SYS_GETPRIORITY: u64 = 141;

// I/O priority
/// ioprio_set(which, who, ioprio)
pub const SYS_IOPRIO_SET: u64 = 30;
/// ioprio_get(which, who)
pub const SYS_IOPRIO_GET: u64 = 31;

// Thread-local storage and process control
/// prctl(option, arg2, arg3, arg4, arg5) - Process/thread control
pub const SYS_PRCTL: u64 = 167;
/// set_tid_address(tidptr) - Set pointer for child thread ID on exit
pub const SYS_SET_TID_ADDRESS: u64 = 96;
/// seccomp(operation, flags, args) - Operate on Secure Computing state
pub const SYS_SECCOMP: u64 = 277;
/// bpf(cmd, attr, size) - BPF syscall for maps and programs
pub const SYS_BPF: u64 = 280;

// System information
/// getrusage(who, usage)
pub const SYS_GETRUSAGE: u64 = 165;
/// times(buf) - process times in clock ticks
pub const SYS_TIMES: u64 = 153;
/// sysinfo(info)
pub const SYS_SYSINFO: u64 = 179;
/// getrandom(buf, buflen, flags)
pub const SYS_GETRANDOM: u64 = 278;
/// acct(filename) - Enable/disable process accounting
pub const SYS_ACCT: u64 = 89;
/// statx(dirfd, pathname, flags, mask, statxbuf)
pub const SYS_STATX: u64 = 291;

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
/// socketpair(domain, type, protocol, sv)
pub const SYS_SOCKETPAIR: u64 = 199;
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
/// sendmsg(fd, msg, flags)
pub const SYS_SENDMSG: u64 = 211;
/// recvmsg(fd, msg, flags)
pub const SYS_RECVMSG: u64 = 212;
/// accept4(fd, addr, addrlen, flags)
pub const SYS_ACCEPT4: u64 = 242;
/// recvmmsg(fd, msgvec, vlen, flags, timeout)
pub const SYS_RECVMMSG: u64 = 243;
/// sendmmsg(fd, msgvec, vlen, flags)
pub const SYS_SENDMMSG: u64 = 269;

// Futex syscalls (aarch64 numbers)
/// futex(uaddr, futex_op, val, timeout, uaddr2, val3)
pub const SYS_FUTEX: u64 = 98;
/// set_robust_list(head, len)
pub const SYS_SET_ROBUST_LIST: u64 = 99;
/// get_robust_list(pid, head_ptr, len_ptr)
pub const SYS_GET_ROBUST_LIST: u64 = 100;
/// futex_waitv(waiters, nr_futexes, flags, timeout, clockid)
pub const SYS_FUTEX_WAITV: u64 = 449;

// Personality (execution domain)
/// personality(persona) - Set process execution domain
pub const SYS_PERSONALITY: u64 = 92;

// System logging
/// syslog(type, buf, len) - Read/control kernel message ring buffer
pub const SYS_SYSLOG: u64 = 116;
/// ptrace(request, pid, addr, data) - Process tracing
pub const SYS_PTRACE: u64 = 117;

// TTY control
/// vhangup() - Simulate hangup on controlling terminal
pub const SYS_VHANGUP: u64 = 58;

// pidfd syscalls
/// pidfd_send_signal(pidfd, sig, info, flags) - Send signal to process via pidfd
pub const SYS_PIDFD_SEND_SIGNAL: u64 = 424;
/// pidfd_open(pid, flags) - Obtain file descriptor for process
pub const SYS_PIDFD_OPEN: u64 = 434;
/// pidfd_getfd(pidfd, targetfd, flags) - Get file descriptor from another process
pub const SYS_PIDFD_GETFD: u64 = 438;

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

// Keyring syscalls (Section 10.3)
/// add_key(type, description, payload, plen, keyring)
pub const SYS_ADD_KEY: u64 = 217;
/// request_key(type, description, callout_info, dest_keyring)
pub const SYS_REQUEST_KEY: u64 = 218;
/// keyctl(cmd, arg2, arg3, arg4, arg5)
pub const SYS_KEYCTL: u64 = 219;
/// process_vm_readv(pid, local_iov, liovcnt, remote_iov, riovcnt, flags)
pub const SYS_PROCESS_VM_READV: u64 = 270;
/// process_vm_writev(pid, local_iov, liovcnt, remote_iov, riovcnt, flags)
pub const SYS_PROCESS_VM_WRITEV: u64 = 271;
/// kcmp(pid1, pid2, type, idx1, idx2)
pub const SYS_KCMP: u64 = 272;

// Syscalls that return stubs (not fully implemented)
/// kexec_load(entry, nr_segments, segments, flags) - load new kernel
pub const SYS_KEXEC_LOAD: u64 = 104;
/// perf_event_open(attr, pid, cpu, group_fd, flags) - performance monitoring
pub const SYS_PERF_EVENT_OPEN: u64 = 241;
/// rseq(rseq, rseq_len, flags, sig) - restartable sequences
pub const SYS_RSEQ: u64 = 293;

// ============================================================================
// Syscall dispatcher
// ============================================================================

/// Dispatch syscall `num` with the argument registers
pub fn aarch64_syscall_dispatch(
    num: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> u64 {
    let args = [arg0, arg1, arg2, arg3, arg4, arg5];
    match num {
        SYS_RT_SIGRETURN => super::signal::sys_rt_sigreturn().ret() as u64,
        _ => match sys_of(num) {
            Some(s) => crate::syscall::dispatch(s, args),
            None => crate::util::error::KernelError::NotImplemented.sysret() as u64,
        },
    }
}

/// The call this architecture numbers `nr` (Linux unistd.h)
pub fn sys_of(nr: u64) -> Option<Sys> {
    Some(match nr {
        SYS_ACCEPT => Sys::Accept,
        SYS_ACCEPT4 => Sys::Accept4,
        SYS_ACCT => Sys::Acct,
        SYS_ADD_KEY => Sys::AddKey,
        SYS_ADJTIMEX => Sys::Adjtimex,
        SYS_BIND => Sys::Bind,
        SYS_BPF => Sys::Bpf,
        SYS_BRK => Sys::Brk,
        SYS_CAPGET => Sys::Capget,
        SYS_CAPSET => Sys::Capset,
        SYS_CHDIR => Sys::Chdir,
        SYS_CHROOT => Sys::Chroot,
        SYS_CLOCK_GETRES => Sys::ClockGetres,
        SYS_CLOCK_GETTIME => Sys::ClockGettime,
        SYS_CLOCK_NANOSLEEP => Sys::ClockNanosleep,
        SYS_CLOCK_SETTIME => Sys::ClockSettime,
        SYS_CLONE => Sys::Clone,
        SYS_CLONE3 => Sys::Clone3,
        SYS_CLOSE => Sys::Close,
        SYS_CLOSE_RANGE => Sys::CloseRange,
        SYS_CONNECT => Sys::Connect,
        SYS_COPY_FILE_RANGE => Sys::CopyFileRange,
        SYS_DUP => Sys::Dup,
        SYS_DUP3 => Sys::Dup3,
        SYS_EPOLL_CREATE1 => Sys::EpollCreate1,
        SYS_EPOLL_CTL => Sys::EpollCtl,
        SYS_EPOLL_PWAIT => Sys::EpollPwait,
        SYS_EPOLL_PWAIT2 => Sys::EpollPwait2,
        SYS_EVENTFD2 => Sys::Eventfd2,
        SYS_EXECVE => Sys::Execve,
        SYS_EXECVEAT => Sys::Execveat,
        SYS_EXIT => Sys::Exit,
        SYS_EXIT_GROUP => Sys::ExitGroup,
        SYS_FACCESSAT => Sys::Faccessat,
        SYS_FACCESSAT2 => Sys::Faccessat2,
        SYS_FADVISE64 => Sys::Fadvise64,
        SYS_FALLOCATE => Sys::Fallocate,
        SYS_FANOTIFY_INIT => Sys::FanotifyInit,
        SYS_FANOTIFY_MARK => Sys::FanotifyMark,
        SYS_FCHDIR => Sys::Fchdir,
        SYS_FCHMOD => Sys::Fchmod,
        SYS_FCHMODAT => Sys::Fchmodat,
        SYS_FCHMODAT2 => Sys::Fchmodat2,
        SYS_FCHOWN => Sys::Fchown,
        SYS_FCHOWNAT => Sys::Fchownat,
        SYS_FCNTL => Sys::Fcntl,
        SYS_FDATASYNC => Sys::Fdatasync,
        SYS_FGETXATTR => Sys::Fgetxattr,
        SYS_FLISTXATTR => Sys::Flistxattr,
        SYS_FLOCK => Sys::Flock,
        SYS_FREMOVEXATTR => Sys::Fremovexattr,
        SYS_FSETXATTR => Sys::Fsetxattr,
        SYS_FSTAT => Sys::Fstat,
        SYS_FSTATAT => Sys::Newfstatat,
        SYS_FSTATFS => Sys::Fstatfs,
        SYS_FSYNC => Sys::Fsync,
        SYS_FTRUNCATE => Sys::Ftruncate,
        SYS_FUTEX => Sys::Futex,
        SYS_FUTEX_WAITV => Sys::FutexWaitv,
        SYS_GETCPU => Sys::Getcpu,
        SYS_GETCWD => Sys::Getcwd,
        SYS_GETDENTS64 => Sys::Getdents64,
        SYS_GETEGID => Sys::Getegid,
        SYS_GETEUID => Sys::Geteuid,
        SYS_GETGID => Sys::Getgid,
        SYS_GETGROUPS => Sys::Getgroups,
        SYS_GETITIMER => Sys::Getitimer,
        SYS_GETPEERNAME => Sys::Getpeername,
        SYS_GETPGID => Sys::Getpgid,
        SYS_GETPID => Sys::Getpid,
        SYS_GETPPID => Sys::Getppid,
        SYS_GETPRIORITY => Sys::Getpriority,
        SYS_GETRANDOM => Sys::Getrandom,
        SYS_GETRESGID => Sys::Getresgid,
        SYS_GETRESUID => Sys::Getresuid,
        SYS_GETRLIMIT => Sys::Getrlimit,
        SYS_GETRUSAGE => Sys::Getrusage,
        SYS_GETSID => Sys::Getsid,
        SYS_GETSOCKNAME => Sys::Getsockname,
        SYS_GETSOCKOPT => Sys::Getsockopt,
        SYS_GETTID => Sys::Gettid,
        SYS_GETTIMEOFDAY => Sys::Gettimeofday,
        SYS_GETUID => Sys::Getuid,
        SYS_GETXATTR => Sys::Getxattr,
        SYS_GET_MEMPOLICY => Sys::GetMempolicy,
        SYS_GET_ROBUST_LIST => Sys::GetRobustList,
        SYS_INOTIFY_ADD_WATCH => Sys::InotifyAddWatch,
        SYS_INOTIFY_INIT1 => Sys::InotifyInit1,
        SYS_INOTIFY_RM_WATCH => Sys::InotifyRmWatch,
        SYS_IOCTL => Sys::Ioctl,
        SYS_IOPRIO_GET => Sys::IoprioGet,
        SYS_IOPRIO_SET => Sys::IoprioSet,
        SYS_IO_URING_ENTER => Sys::IoUringEnter,
        SYS_IO_URING_REGISTER => Sys::IoUringRegister,
        SYS_IO_URING_SETUP => Sys::IoUringSetup,
        SYS_KCMP => Sys::Kcmp,
        SYS_KEXEC_LOAD => Sys::KexecLoad,
        SYS_KEYCTL => Sys::Keyctl,
        SYS_KILL => Sys::Kill,
        SYS_LGETXATTR => Sys::Lgetxattr,
        SYS_LINKAT => Sys::Linkat,
        SYS_LISTEN => Sys::Listen,
        SYS_LISTXATTR => Sys::Listxattr,
        SYS_LLISTXATTR => Sys::Llistxattr,
        SYS_LREMOVEXATTR => Sys::Lremovexattr,
        SYS_LSEEK => Sys::Lseek,
        SYS_LSETXATTR => Sys::Lsetxattr,
        SYS_MADVISE => Sys::Madvise,
        SYS_MBIND => Sys::Mbind,
        SYS_MEMBARRIER => Sys::Membarrier,
        SYS_MIGRATE_PAGES => Sys::MigratePages,
        SYS_MINCORE => Sys::Mincore,
        SYS_MKDIRAT => Sys::Mkdirat,
        SYS_MKNODAT => Sys::Mknodat,
        SYS_MLOCK => Sys::Mlock,
        SYS_MLOCK2 => Sys::Mlock2,
        SYS_MLOCKALL => Sys::Mlockall,
        SYS_MMAP => Sys::Mmap,
        SYS_MOUNT => Sys::Mount,
        SYS_MOVE_PAGES => Sys::MovePages,
        SYS_MPROTECT => Sys::Mprotect,
        SYS_MQ_GETSETATTR => Sys::MqGetsetattr,
        SYS_MQ_NOTIFY => Sys::MqNotify,
        SYS_MQ_OPEN => Sys::MqOpen,
        SYS_MQ_TIMEDRECEIVE => Sys::MqTimedreceive,
        SYS_MQ_TIMEDSEND => Sys::MqTimedsend,
        SYS_MQ_UNLINK => Sys::MqUnlink,
        SYS_MREMAP => Sys::Mremap,
        SYS_MSGCTL => Sys::Msgctl,
        SYS_MSGGET => Sys::Msgget,
        SYS_MSGRCV => Sys::Msgrcv,
        SYS_MSGSND => Sys::Msgsnd,
        SYS_MSYNC => Sys::Msync,
        SYS_MUNLOCK => Sys::Munlock,
        SYS_MUNLOCKALL => Sys::Munlockall,
        SYS_MUNMAP => Sys::Munmap,
        SYS_NANOSLEEP => Sys::Nanosleep,
        SYS_OPENAT => Sys::Openat,
        SYS_PERF_EVENT_OPEN => Sys::PerfEventOpen,
        SYS_PERSONALITY => Sys::Personality,
        SYS_PIDFD_GETFD => Sys::PidfdGetfd,
        SYS_PIDFD_OPEN => Sys::PidfdOpen,
        SYS_PIDFD_SEND_SIGNAL => Sys::PidfdSendSignal,
        SYS_PIPE2 => Sys::Pipe2,
        SYS_PIVOT_ROOT => Sys::PivotRoot,
        SYS_PPOLL => Sys::Ppoll,
        SYS_PRCTL => Sys::Prctl,
        SYS_PREAD64 => Sys::Pread64,
        SYS_PREADV => Sys::Preadv,
        SYS_PREADV2 => Sys::Preadv2,
        SYS_PRLIMIT64 => Sys::Prlimit64,
        SYS_PROCESS_VM_READV => Sys::ProcessVmReadv,
        SYS_PROCESS_VM_WRITEV => Sys::ProcessVmWritev,
        SYS_PSELECT6 => Sys::Pselect6,
        SYS_PTRACE => Sys::Ptrace,
        SYS_PWRITE64 => Sys::Pwrite64,
        SYS_PWRITEV => Sys::Pwritev,
        SYS_PWRITEV2 => Sys::Pwritev2,
        SYS_READ => Sys::Read,
        SYS_READAHEAD => Sys::Readahead,
        SYS_READLINKAT => Sys::Readlinkat,
        SYS_READV => Sys::Readv,
        SYS_REBOOT => Sys::Reboot,
        SYS_RECVFROM => Sys::Recvfrom,
        SYS_RECVMMSG => Sys::Recvmmsg,
        SYS_RECVMSG => Sys::Recvmsg,
        SYS_REMOVEXATTR => Sys::Removexattr,
        SYS_RENAMEAT => Sys::Renameat,
        SYS_RENAMEAT2 => Sys::Renameat2,
        SYS_REQUEST_KEY => Sys::RequestKey,
        SYS_RSEQ => Sys::Rseq,
        SYS_RT_SIGACTION => Sys::RtSigaction,
        SYS_RT_SIGPENDING => Sys::RtSigpending,
        SYS_RT_SIGPROCMASK => Sys::RtSigprocmask,
        SYS_RT_SIGQUEUEINFO => Sys::RtSigqueueinfo,
        SYS_RT_SIGSUSPEND => Sys::RtSigsuspend,
        SYS_RT_SIGTIMEDWAIT => Sys::RtSigtimedwait,
        SYS_RT_TGSIGQUEUEINFO => Sys::RtTgsigqueueinfo,
        SYS_SCHED_GETAFFINITY => Sys::SchedGetaffinity,
        SYS_SCHED_GETPARAM => Sys::SchedGetparam,
        SYS_SCHED_GETSCHEDULER => Sys::SchedGetscheduler,
        SYS_SCHED_RR_GET_INTERVAL => Sys::SchedRrGetInterval,
        SYS_SCHED_SETAFFINITY => Sys::SchedSetaffinity,
        SYS_SCHED_SETPARAM => Sys::SchedSetparam,
        SYS_SCHED_SETSCHEDULER => Sys::SchedSetscheduler,
        SYS_SCHED_YIELD => Sys::SchedYield,
        SYS_SECCOMP => Sys::Seccomp,
        SYS_SEMCTL => Sys::Semctl,
        SYS_SEMGET => Sys::Semget,
        SYS_SEMOP => Sys::Semop,
        SYS_SEMTIMEDOP => Sys::Semtimedop,
        SYS_SENDFILE => Sys::Sendfile,
        SYS_SENDMMSG => Sys::Sendmmsg,
        SYS_SENDMSG => Sys::Sendmsg,
        SYS_SENDTO => Sys::Sendto,
        SYS_SETDOMAINNAME => Sys::Setdomainname,
        SYS_SETFSGID => Sys::Setfsgid,
        SYS_SETFSUID => Sys::Setfsuid,
        SYS_SETGID => Sys::Setgid,
        SYS_SETGROUPS => Sys::Setgroups,
        SYS_SETHOSTNAME => Sys::Sethostname,
        SYS_SETITIMER => Sys::Setitimer,
        SYS_SETNS => Sys::Setns,
        SYS_SETPGID => Sys::Setpgid,
        SYS_SETPRIORITY => Sys::Setpriority,
        SYS_SETREGID => Sys::Setregid,
        SYS_SETRESGID => Sys::Setresgid,
        SYS_SETRESUID => Sys::Setresuid,
        SYS_SETREUID => Sys::Setreuid,
        SYS_SETRLIMIT => Sys::Setrlimit,
        SYS_SETSID => Sys::Setsid,
        SYS_SETSOCKOPT => Sys::Setsockopt,
        SYS_SETTIMEOFDAY => Sys::Settimeofday,
        SYS_SETUID => Sys::Setuid,
        SYS_SETXATTR => Sys::Setxattr,
        SYS_SET_MEMPOLICY => Sys::SetMempolicy,
        SYS_SET_ROBUST_LIST => Sys::SetRobustList,
        SYS_SET_TID_ADDRESS => Sys::SetTidAddress,
        SYS_SHMAT => Sys::Shmat,
        SYS_SHMCTL => Sys::Shmctl,
        SYS_SHMDT => Sys::Shmdt,
        SYS_SHMGET => Sys::Shmget,
        SYS_SHUTDOWN => Sys::Shutdown,
        SYS_SIGALTSTACK => Sys::Sigaltstack,
        SYS_SIGNALFD4 => Sys::Signalfd4,
        SYS_SOCKET => Sys::Socket,
        SYS_SOCKETPAIR => Sys::Socketpair,
        SYS_SPLICE => Sys::Splice,
        SYS_STATFS => Sys::Statfs,
        SYS_STATX => Sys::Statx,
        SYS_SWAPOFF => Sys::Swapoff,
        SYS_SWAPON => Sys::Swapon,
        SYS_SYMLINKAT => Sys::Symlinkat,
        SYS_SYNC => Sys::Sync,
        SYS_SYNCFS => Sys::Syncfs,
        SYS_SYNC_FILE_RANGE => Sys::SyncFileRange,
        SYS_SYSINFO => Sys::Sysinfo,
        SYS_SYSLOG => Sys::Syslog,
        SYS_TEE => Sys::Tee,
        SYS_TGKILL => Sys::Tgkill,
        SYS_TIMERFD_CREATE => Sys::TimerfdCreate,
        SYS_TIMERFD_GETTIME => Sys::TimerfdGettime,
        SYS_TIMERFD_SETTIME => Sys::TimerfdSettime,
        SYS_TIMER_CREATE => Sys::TimerCreate,
        SYS_TIMER_DELETE => Sys::TimerDelete,
        SYS_TIMER_GETOVERRUN => Sys::TimerGetoverrun,
        SYS_TIMER_GETTIME => Sys::TimerGettime,
        SYS_TIMER_SETTIME => Sys::TimerSettime,
        SYS_TIMES => Sys::Times,
        SYS_TKILL => Sys::Tkill,
        SYS_TRUNCATE => Sys::Truncate,
        SYS_UMASK => Sys::Umask,
        SYS_UMOUNT2 => Sys::Umount2,
        SYS_UNAME => Sys::Uname,
        SYS_UNLINKAT => Sys::Unlinkat,
        SYS_UNSHARE => Sys::Unshare,
        SYS_UTIMENSAT => Sys::Utimensat,
        SYS_VHANGUP => Sys::Vhangup,
        SYS_VMSPLICE => Sys::Vmsplice,
        SYS_WAIT4 => Sys::Wait4,
        SYS_WAITID => Sys::Waitid,
        SYS_WRITE => Sys::Write,
        SYS_WRITEV => Sys::Writev,
        _ => return None,
    })
}

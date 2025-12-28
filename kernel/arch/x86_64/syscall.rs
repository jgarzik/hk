//! x86-64 Syscall entry/exit and dispatch
//!
//! This module handles:
//! - Syscall instruction MSR configuration
//! - Syscall entry point (assembly)
//! - Syscall number dispatch to generic handlers
//!
//! The SYS_* constants are x86-64 Linux ABI specific. Other architectures
//! (e.g., aarch64) have different syscall numbers.

use super::cpu::{KERNEL_CODE_SELECTOR, USER_CODE_SELECTOR, USER_DATA_SELECTOR};

// =============================================================================
// Linux x86-64 syscall numbers
// =============================================================================

/// read(fd, buf, count)
pub const SYS_READ: u64 = 0;
/// write(fd, buf, count)
pub const SYS_WRITE: u64 = 1;
/// open(pathname, flags, mode)
pub const SYS_OPEN: u64 = 2;
/// pread64(fd, buf, count, offset)
pub const SYS_PREAD64: u64 = 17;
/// pwrite64(fd, buf, count, offset)
pub const SYS_PWRITE64: u64 = 18;
/// readv(fd, iov, iovcnt)
pub const SYS_READV: u64 = 19;
/// ioctl(fd, request, arg)
pub const SYS_IOCTL: u64 = 16;
/// writev(fd, iov, iovcnt)
pub const SYS_WRITEV: u64 = 20;
/// preadv(fd, iov, iovcnt, offset)
pub const SYS_PREADV: u64 = 295;
/// pwritev(fd, iov, iovcnt, offset)
pub const SYS_PWRITEV: u64 = 296;
/// preadv2(fd, iov, iovcnt, offset, flags)
pub const SYS_PREADV2: u64 = 327;
/// pwritev2(fd, iov, iovcnt, offset, flags)
pub const SYS_PWRITEV2: u64 = 328;
/// statfs(pathname, buf)
pub const SYS_STATFS: u64 = 137;
/// fstatfs(fd, buf)
pub const SYS_FSTATFS: u64 = 138;
/// statx(dirfd, pathname, flags, mask, statxbuf)
pub const SYS_STATX: u64 = 332;
/// pipe(pipefd)
pub const SYS_PIPE: u64 = 22;
/// poll(fds, nfds, timeout)
pub const SYS_POLL: u64 = 7;
/// ppoll(fds, nfds, tmo_p, sigmask, sigsetsize)
pub const SYS_PPOLL: u64 = 271;
/// select(nfds, readfds, writefds, exceptfds, timeout)
pub const SYS_SELECT: u64 = 23;
/// pselect6(nfds, readfds, writefds, exceptfds, timeout, sigmask)
pub const SYS_PSELECT6: u64 = 270;
/// close(fd)
pub const SYS_CLOSE: u64 = 3;
/// stat(pathname, statbuf)
pub const SYS_STAT: u64 = 4;
/// fstat(fd, statbuf)
pub const SYS_FSTAT: u64 = 5;
/// lstat(pathname, statbuf) - like stat but don't follow symlinks
pub const SYS_LSTAT: u64 = 6;
/// lseek(fd, offset, whence)
pub const SYS_LSEEK: u64 = 8;
/// mmap(addr, length, prot, flags, fd, offset)
pub const SYS_MMAP: u64 = 9;
/// mprotect(addr, len, prot)
pub const SYS_MPROTECT: u64 = 10;
/// munmap(addr, length)
pub const SYS_MUNMAP: u64 = 11;
/// brk(addr)
pub const SYS_BRK: u64 = 12;
/// mlock(addr, len)
pub const SYS_MLOCK: u64 = 149;
/// munlock(addr, len)
pub const SYS_MUNLOCK: u64 = 150;
/// mlockall(flags)
pub const SYS_MLOCKALL: u64 = 151;
/// munlockall()
pub const SYS_MUNLOCKALL: u64 = 152;
/// mlock2(addr, len, flags)
pub const SYS_MLOCK2: u64 = 325;
/// msync(addr, length, flags)
pub const SYS_MSYNC: u64 = 26;
/// mincore(addr, length, vec)
pub const SYS_MINCORE: u64 = 27;
/// madvise(addr, length, advice)
pub const SYS_MADVISE: u64 = 28;
/// ftruncate(fd, length)
pub const SYS_FTRUNCATE: u64 = 77;
/// truncate(path, length)
pub const SYS_TRUNCATE: u64 = 76;
/// dup(oldfd)
pub const SYS_DUP: u64 = 32;
/// dup2(oldfd, newfd)
pub const SYS_DUP2: u64 = 33;
/// fcntl(fd, cmd, arg)
pub const SYS_FCNTL: u64 = 72;
/// sched_yield()
pub const SYS_SCHED_YIELD: u64 = 24;
/// mremap(old_addr, old_len, new_len, flags, new_addr)
pub const SYS_MREMAP: u64 = 25;
/// getpid()
pub const SYS_GETPID: u64 = 39;
/// exit(status)
pub const SYS_EXIT: u64 = 60;
/// gettimeofday(tv, tz)
pub const SYS_GETTIMEOFDAY: u64 = 96;
/// gettid()
pub const SYS_GETTID: u64 = 186;
/// getdents64(fd, dirp, count)
pub const SYS_GETDENTS64: u64 = 217;
/// clock_gettime(clockid, tp)
pub const SYS_CLOCK_GETTIME: u64 = 228;
/// nanosleep(req, rem)
pub const SYS_NANOSLEEP: u64 = 35;
/// clock_nanosleep(clockid, flags, req, rem)
pub const SYS_CLOCK_NANOSLEEP: u64 = 230;
/// clock_getres(clockid, res)
pub const SYS_CLOCK_GETRES: u64 = 229;
/// clock_settime(clockid, tp)
pub const SYS_CLOCK_SETTIME: u64 = 227;
/// settimeofday(tv, tz)
pub const SYS_SETTIMEOFDAY: u64 = 164;
/// time(tloc)
pub const SYS_TIME: u64 = 201;
/// timerfd_create(clockid, flags)
pub const SYS_TIMERFD_CREATE: u64 = 283;
/// timerfd_settime(fd, flags, new_value, old_value)
pub const SYS_TIMERFD_SETTIME: u64 = 286;
/// timerfd_gettime(fd, curr_value)
pub const SYS_TIMERFD_GETTIME: u64 = 287;
/// adjtimex(txc) - read/set kernel clock parameters
pub const SYS_ADJTIMEX: u64 = 159;

// eventfd syscalls (Section 7.1)
/// eventfd(initval)
pub const SYS_EVENTFD: u64 = 284;
/// eventfd2(initval, flags)
pub const SYS_EVENTFD2: u64 = 290;

// signalfd syscalls (Section 5)
/// signalfd(fd, mask, flags) - legacy
pub const SYS_SIGNALFD: u64 = 282;
/// signalfd4(fd, mask, sizemask, flags)
pub const SYS_SIGNALFD4: u64 = 289;

// inotify syscalls (Section 9.2)
/// inotify_init()
pub const SYS_INOTIFY_INIT: u64 = 253;
/// inotify_add_watch(fd, pathname, mask)
pub const SYS_INOTIFY_ADD_WATCH: u64 = 254;
/// inotify_rm_watch(fd, wd)
pub const SYS_INOTIFY_RM_WATCH: u64 = 255;
/// inotify_init1(flags)
pub const SYS_INOTIFY_INIT1: u64 = 294;

// fanotify syscalls (Section 9.2)
/// fanotify_init(flags, event_f_flags)
pub const SYS_FANOTIFY_INIT: u64 = 300;
/// fanotify_mark(fanotify_fd, flags, mask, dirfd, pathname)
pub const SYS_FANOTIFY_MARK: u64 = 301;

// epoll syscalls (Section 9.1)
/// epoll_create(size)
pub const SYS_EPOLL_CREATE: u64 = 213;
/// epoll_wait(epfd, events, maxevents, timeout)
pub const SYS_EPOLL_WAIT: u64 = 232;
/// epoll_ctl(epfd, op, fd, event)
pub const SYS_EPOLL_CTL: u64 = 233;
/// epoll_pwait(epfd, events, maxevents, timeout, sigmask, sigsetsize)
pub const SYS_EPOLL_PWAIT: u64 = 281;
/// epoll_create1(flags)
pub const SYS_EPOLL_CREATE1: u64 = 291;
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
pub const SYS_TIMER_CREATE: u64 = 222;
/// timer_settime(timerid, flags, new_value, old_value)
pub const SYS_TIMER_SETTIME: u64 = 223;
/// timer_gettime(timerid, curr_value)
pub const SYS_TIMER_GETTIME: u64 = 224;
/// timer_getoverrun(timerid)
pub const SYS_TIMER_GETOVERRUN: u64 = 225;
/// timer_delete(timerid)
pub const SYS_TIMER_DELETE: u64 = 226;

// POSIX message queue syscalls (Section 7.4)
/// mq_open(name, oflag, mode, attr)
pub const SYS_MQ_OPEN: u64 = 240;
/// mq_unlink(name)
pub const SYS_MQ_UNLINK: u64 = 241;
/// mq_timedsend(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout)
pub const SYS_MQ_TIMEDSEND: u64 = 242;
/// mq_timedreceive(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout)
pub const SYS_MQ_TIMEDRECEIVE: u64 = 243;
/// mq_notify(mqdes, sevp)
pub const SYS_MQ_NOTIFY: u64 = 244;
/// mq_getsetattr(mqdes, newattr, oldattr)
pub const SYS_MQ_GETSETATTR: u64 = 245;

// Process IDs & basic info (Section 1.2)
/// setpgid(pid, pgid)
pub const SYS_SETPGID: u64 = 109;
/// getppid()
pub const SYS_GETPPID: u64 = 110;
/// setsid()
pub const SYS_SETSID: u64 = 112;
/// getpgid(pid)
pub const SYS_GETPGID: u64 = 121;
/// getsid(pid)
pub const SYS_GETSID: u64 = 124;

// Credentials (Section 10.1)
/// getuid()
pub const SYS_GETUID: u64 = 102;
/// getgid()
pub const SYS_GETGID: u64 = 104;
/// setuid(uid)
pub const SYS_SETUID: u64 = 105;
/// setgid(gid)
pub const SYS_SETGID: u64 = 106;
/// geteuid()
pub const SYS_GETEUID: u64 = 107;
/// getegid()
pub const SYS_GETEGID: u64 = 108;
/// setreuid(ruid, euid)
pub const SYS_SETREUID: u64 = 113;
/// setregid(rgid, egid)
pub const SYS_SETREGID: u64 = 114;
/// setresuid(ruid, euid, suid)
pub const SYS_SETRESUID: u64 = 117;
/// getresuid(ruid*, euid*, suid*)
pub const SYS_GETRESUID: u64 = 118;
/// setresgid(rgid, egid, sgid)
pub const SYS_SETRESGID: u64 = 119;
/// getresgid(rgid*, egid*, sgid*)
pub const SYS_GETRESGID: u64 = 120;
/// setfsuid(uid)
pub const SYS_SETFSUID: u64 = 122;
/// setfsgid(gid)
pub const SYS_SETFSGID: u64 = 123;
/// capget(hdrp, datap)
pub const SYS_CAPGET: u64 = 125;
/// capset(hdrp, datap)
pub const SYS_CAPSET: u64 = 126;

// Process creation (Section 1.1)
/// clone(flags, child_stack, parent_tidptr, child_tidptr, tls)
pub const SYS_CLONE: u64 = 56;
/// fork()
pub const SYS_FORK: u64 = 57;
/// vfork()
pub const SYS_VFORK: u64 = 58;
/// execve(pathname, argv, envp)
pub const SYS_EXECVE: u64 = 59;
/// wait4(pid, wstatus, options, rusage)
pub const SYS_WAIT4: u64 = 61;
/// exit_group(status)
pub const SYS_EXIT_GROUP: u64 = 231;
/// waitid(idtype, id, infop, options)
pub const SYS_WAITID: u64 = 247;
/// execveat(dirfd, pathname, argv, envp, flags)
pub const SYS_EXECVEAT: u64 = 322;
/// reboot(magic1, magic2, cmd, arg)
pub const SYS_REBOOT: u64 = 169;

// Filesystem syscalls (Section 2.1 / 3.1)
/// access(pathname, mode)
pub const SYS_ACCESS: u64 = 21;
/// getcwd(buf, size)
pub const SYS_GETCWD: u64 = 79;
/// chdir(pathname)
pub const SYS_CHDIR: u64 = 80;
/// fchdir(fd)
pub const SYS_FCHDIR: u64 = 81;
/// chroot(pathname)
pub const SYS_CHROOT: u64 = 161;
/// openat(dirfd, pathname, flags, mode)
pub const SYS_OPENAT: u64 = 257;
/// faccessat(dirfd, pathname, mode, flags)
pub const SYS_FACCESSAT: u64 = 269;
/// dup3(oldfd, newfd, flags)
pub const SYS_DUP3: u64 = 292;
/// pipe2(pipefd, flags)
pub const SYS_PIPE2: u64 = 293;
/// link(oldpath, newpath)
pub const SYS_LINK: u64 = 86;
/// symlink(target, linkpath)
pub const SYS_SYMLINK: u64 = 88;
/// readlink(pathname, buf, bufsiz)
pub const SYS_READLINK: u64 = 89;
/// linkat(olddirfd, oldpath, newdirfd, newpath, flags)
pub const SYS_LINKAT: u64 = 265;
/// symlinkat(target, newdirfd, linkpath)
pub const SYS_SYMLINKAT: u64 = 266;
/// readlinkat(dirfd, pathname, buf, bufsiz)
pub const SYS_READLINKAT: u64 = 267;
/// faccessat2(dirfd, pathname, mode, flags)
pub const SYS_FACCESSAT2: u64 = 439;

// Directory/node creation (Section 3.1)
/// mkdir(pathname, mode)
pub const SYS_MKDIR: u64 = 83;
/// rmdir(pathname)
pub const SYS_RMDIR: u64 = 84;
/// mknod(pathname, mode, dev)
pub const SYS_MKNOD: u64 = 133;
/// mkdirat(dirfd, pathname, mode)
pub const SYS_MKDIRAT: u64 = 258;
/// mknodat(dirfd, pathname, mode, dev)
pub const SYS_MKNODAT: u64 = 259;
/// unlink(pathname)
pub const SYS_UNLINK: u64 = 87;
/// unlinkat(dirfd, pathname, flags)
pub const SYS_UNLINKAT: u64 = 263;

// Filesystem mounting (Section 2.2)
/// mount(source, target, filesystemtype, mountflags, data)
pub const SYS_MOUNT: u64 = 165;
/// umount2(target, flags)
pub const SYS_UMOUNT2: u64 = 166;
/// pivot_root(new_root, put_old)
pub const SYS_PIVOT_ROOT: u64 = 155;

// Swap management
/// swapon(path, swapflags)
pub const SYS_SWAPON: u64 = 167;
/// swapoff(path)
pub const SYS_SWAPOFF: u64 = 168;

// Permissions and ownership (Section 3.2)
/// chmod(pathname, mode)
pub const SYS_CHMOD: u64 = 90;
/// fchmod(fd, mode)
pub const SYS_FCHMOD: u64 = 91;
/// chown(pathname, owner, group)
pub const SYS_CHOWN: u64 = 92;
/// fchown(fd, owner, group)
pub const SYS_FCHOWN: u64 = 93;
/// lchown(pathname, owner, group)
pub const SYS_LCHOWN: u64 = 94;
/// umask(mask)
pub const SYS_UMASK: u64 = 95;
/// utime(pathname, times)
pub const SYS_UTIME: u64 = 132;
/// utimes(pathname, times)
pub const SYS_UTIMES: u64 = 235;
/// fchownat(dirfd, pathname, owner, group, flags)
pub const SYS_FCHOWNAT: u64 = 260;
/// fchmodat(dirfd, pathname, mode, flags)
pub const SYS_FCHMODAT: u64 = 268;
/// fchmodat2(dirfd, pathname, mode, flags) - extended fchmodat with flags
pub const SYS_FCHMODAT2: u64 = 452;
/// utimensat(dirfd, pathname, times, flags)
pub const SYS_UTIMENSAT: u64 = 280;
/// rename(oldpath, newpath)
pub const SYS_RENAME: u64 = 82;
/// renameat(olddirfd, oldpath, newdirfd, newpath)
pub const SYS_RENAMEAT: u64 = 264;
/// renameat2(olddirfd, oldpath, newdirfd, newpath, flags)
pub const SYS_RENAMEAT2: u64 = 316;

// Extended attributes (xattr) syscalls
/// setxattr(path, name, value, size, flags)
pub const SYS_SETXATTR: u64 = 188;
/// lsetxattr(path, name, value, size, flags)
pub const SYS_LSETXATTR: u64 = 189;
/// fsetxattr(fd, name, value, size, flags)
pub const SYS_FSETXATTR: u64 = 190;
/// getxattr(path, name, value, size)
pub const SYS_GETXATTR: u64 = 191;
/// lgetxattr(path, name, value, size)
pub const SYS_LGETXATTR: u64 = 192;
/// fgetxattr(fd, name, value, size)
pub const SYS_FGETXATTR: u64 = 193;
/// listxattr(path, list, size)
pub const SYS_LISTXATTR: u64 = 194;
/// llistxattr(path, list, size)
pub const SYS_LLISTXATTR: u64 = 195;
/// flistxattr(fd, list, size)
pub const SYS_FLISTXATTR: u64 = 196;
/// removexattr(path, name)
pub const SYS_REMOVEXATTR: u64 = 197;
/// lremovexattr(path, name)
pub const SYS_LREMOVEXATTR: u64 = 198;
/// fremovexattr(fd, name)
pub const SYS_FREMOVEXATTR: u64 = 199;

// Sync syscalls
/// fsync(fd)
pub const SYS_FSYNC: u64 = 74;
/// fdatasync(fd)
pub const SYS_FDATASYNC: u64 = 75;
/// sync()
pub const SYS_SYNC: u64 = 162;
/// syncfs(fd)
pub const SYS_SYNCFS: u64 = 306;

// Splice/sendfile/copy syscalls
/// sendfile64(out_fd, in_fd, offset, count)
pub const SYS_SENDFILE: u64 = 40;
/// flock(fd, operation)
pub const SYS_FLOCK: u64 = 73;
/// splice(fd_in, off_in, fd_out, off_out, len, flags)
pub const SYS_SPLICE: u64 = 275;
/// tee(fd_in, fd_out, len, flags)
pub const SYS_TEE: u64 = 276;
/// vmsplice(fd, iov, nr_segs, flags)
pub const SYS_VMSPLICE: u64 = 278;
/// fallocate(fd, mode, offset, len)
pub const SYS_FALLOCATE: u64 = 285;
/// copy_file_range(fd_in, off_in, fd_out, off_out, len, flags)
pub const SYS_COPY_FILE_RANGE: u64 = 326;

// UTS namespace syscalls
/// uname(buf)
pub const SYS_UNAME: u64 = 63;
/// sethostname(name, len)
pub const SYS_SETHOSTNAME: u64 = 170;
/// setdomainname(name, len)
pub const SYS_SETDOMAINNAME: u64 = 171;

// Signal syscalls
/// rt_sigaction(sig, act, oact, sigsetsize)
pub const SYS_RT_SIGACTION: u64 = 13;
/// rt_sigprocmask(how, set, oset, sigsetsize)
pub const SYS_RT_SIGPROCMASK: u64 = 14;
/// rt_sigreturn() - return from signal handler
#[allow(dead_code)] // Infrastructure for future signal delivery
pub const SYS_RT_SIGRETURN: u64 = 15;
/// kill(pid, sig)
pub const SYS_KILL: u64 = 62;
/// rt_sigpending(set, sigsetsize)
pub const SYS_RT_SIGPENDING: u64 = 127;
/// tkill(tid, sig)
pub const SYS_TKILL: u64 = 200;
/// tgkill(tgid, tid, sig)
pub const SYS_TGKILL: u64 = 234;
/// rt_sigtimedwait(set, info, ts, sigsetsize)
pub const SYS_RT_SIGTIMEDWAIT: u64 = 128;
/// sigaltstack(ss, oss)
pub const SYS_SIGALTSTACK: u64 = 131;
/// rt_sigqueueinfo(pid, sig, uinfo)
pub const SYS_RT_SIGQUEUEINFO: u64 = 129;
/// rt_sigsuspend(mask, sigsetsize)
pub const SYS_RT_SIGSUSPEND: u64 = 130;
/// rt_tgsigqueueinfo(tgid, tid, sig, uinfo)
pub const SYS_RT_TGSIGQUEUEINFO: u64 = 297;

// Memory barrier (Section 13)
/// membarrier(cmd, flags, cpu_id)
pub const SYS_MEMBARRIER: u64 = 324;

// File readahead (Section 2.3)
/// readahead(fd, offset, count)
pub const SYS_READAHEAD: u64 = 187;

// NUMA memory policy (Section 4.2)
/// mbind(start, len, mode, nodemask, maxnode, flags)
pub const SYS_MBIND: u64 = 237;
/// set_mempolicy(mode, nodemask, maxnode)
pub const SYS_SET_MEMPOLICY: u64 = 238;
/// get_mempolicy(policy, nodemask, maxnode, addr, flags)
pub const SYS_GET_MEMPOLICY: u64 = 239;
/// migrate_pages(pid, maxnode, old_nodes, new_nodes)
pub const SYS_MIGRATE_PAGES: u64 = 256;
/// move_pages(pid, nr_pages, pages, nodes, status, flags)
pub const SYS_MOVE_PAGES: u64 = 279;

// Scheduling priority
/// getpriority(which, who)
pub const SYS_GETPRIORITY: u64 = 140;
/// setpriority(which, who, niceval)
pub const SYS_SETPRIORITY: u64 = 141;

// I/O priority
/// ioprio_set(which, who, ioprio)
pub const SYS_IOPRIO_SET: u64 = 251;
/// ioprio_get(which, who)
pub const SYS_IOPRIO_GET: u64 = 252;

// Thread-local storage and process control
/// prctl(option, arg2, arg3, arg4, arg5) - Process/thread control
pub const SYS_PRCTL: u64 = 157;
/// arch_prctl(code, addr) - Architecture-specific thread state
pub const SYS_ARCH_PRCTL: u64 = 158;

// Ptrace (debugging/tracing)
/// ptrace(request, pid, addr, data) - Process tracing
pub const SYS_PTRACE: u64 = 101;
/// set_tid_address(tidptr) - Set pointer for child thread ID on exit
pub const SYS_SET_TID_ADDRESS: u64 = 218;
/// seccomp(operation, flags, args) - Operate on Secure Computing state
pub const SYS_SECCOMP: u64 = 317;
/// bpf(cmd, attr, size) - BPF syscall for maps and programs
pub const SYS_BPF: u64 = 321;

// System information
/// getcpu(cpup, nodep, unused)
pub const SYS_GETCPU: u64 = 309;
/// getrusage(who, usage)
pub const SYS_GETRUSAGE: u64 = 98;
/// sysinfo(info)
pub const SYS_SYSINFO: u64 = 99;
/// getrandom(buf, buflen, flags)
pub const SYS_GETRANDOM: u64 = 318;
/// acct(filename) - Enable/disable process accounting
pub const SYS_ACCT: u64 = 163;

// Scheduling syscalls
/// sched_setparam(pid, param)
pub const SYS_SCHED_SETPARAM: u64 = 142;
/// sched_getparam(pid, param)
pub const SYS_SCHED_GETPARAM: u64 = 143;
/// sched_setscheduler(pid, policy, param)
pub const SYS_SCHED_SETSCHEDULER: u64 = 144;
/// sched_getscheduler(pid)
pub const SYS_SCHED_GETSCHEDULER: u64 = 145;
/// sched_rr_get_interval(pid, tp)
pub const SYS_SCHED_RR_GET_INTERVAL: u64 = 148;
/// sched_setaffinity(pid, cpusetsize, mask)
pub const SYS_SCHED_SETAFFINITY: u64 = 203;
/// sched_getaffinity(pid, cpusetsize, mask)
pub const SYS_SCHED_GETAFFINITY: u64 = 204;
/// nice(inc)
pub const SYS_NICE: u64 = 34;

// Resource limits
/// getrlimit(resource, rlim)
pub const SYS_GETRLIMIT: u64 = 97;
/// setrlimit(resource, rlim)
pub const SYS_SETRLIMIT: u64 = 160;
/// prlimit64(pid, resource, new_rlim, old_rlim)
pub const SYS_PRLIMIT64: u64 = 302;

// Namespaces
/// unshare(flags) - disassociate parts of process execution context
pub const SYS_UNSHARE: u64 = 272;
/// setns(fd, nstype) - reassociate thread with a namespace
pub const SYS_SETNS: u64 = 308;

// Socket syscalls
/// socket(domain, type, protocol)
pub const SYS_SOCKET: u64 = 41;
/// connect(fd, addr, addrlen)
pub const SYS_CONNECT: u64 = 42;
/// accept(fd, addr, addrlen)
pub const SYS_ACCEPT: u64 = 43;
/// sendto(fd, buf, len, flags, dest_addr, addrlen)
pub const SYS_SENDTO: u64 = 44;
/// recvfrom(fd, buf, len, flags, src_addr, addrlen)
pub const SYS_RECVFROM: u64 = 45;
/// sendmsg(fd, msg, flags)
pub const SYS_SENDMSG: u64 = 46;
/// recvmsg(fd, msg, flags)
pub const SYS_RECVMSG: u64 = 47;
/// shutdown(fd, how)
pub const SYS_SHUTDOWN: u64 = 48;
/// bind(fd, addr, addrlen)
pub const SYS_BIND: u64 = 49;
/// listen(fd, backlog)
pub const SYS_LISTEN: u64 = 50;
/// getsockname(fd, addr, addrlen)
pub const SYS_GETSOCKNAME: u64 = 51;
/// getpeername(fd, addr, addrlen)
pub const SYS_GETPEERNAME: u64 = 52;
/// socketpair(domain, type, protocol, sv)
pub const SYS_SOCKETPAIR: u64 = 53;
/// setsockopt(fd, level, optname, optval, optlen)
pub const SYS_SETSOCKOPT: u64 = 54;
/// getsockopt(fd, level, optname, optval, optlen)
pub const SYS_GETSOCKOPT: u64 = 55;
/// accept4(fd, addr, addrlen, flags)
pub const SYS_ACCEPT4: u64 = 288;
/// recvmmsg(fd, msgvec, vlen, flags, timeout)
pub const SYS_RECVMMSG: u64 = 299;
/// sendmmsg(fd, msgvec, vlen, flags)
pub const SYS_SENDMMSG: u64 = 307;

// Futex syscalls (Section 7.2)
/// futex(uaddr, futex_op, val, timeout, uaddr2, val3)
pub const SYS_FUTEX: u64 = 202;
/// set_robust_list(head, len)
pub const SYS_SET_ROBUST_LIST: u64 = 273;
/// get_robust_list(pid, head_ptr, len_ptr)
pub const SYS_GET_ROBUST_LIST: u64 = 274;
/// futex_waitv(waiters, nr_futexes, flags, timeout, clockid)
pub const SYS_FUTEX_WAITV: u64 = 449;

// SysV IPC syscalls (Section 7.1)
/// shmget(key, size, shmflg)
pub const SYS_SHMGET: u64 = 29;
/// shmat(shmid, shmaddr, shmflg)
pub const SYS_SHMAT: u64 = 30;
/// shmctl(shmid, cmd, buf)
pub const SYS_SHMCTL: u64 = 31;
/// semget(key, nsems, semflg)
pub const SYS_SEMGET: u64 = 64;
/// semop(semid, sops, nsops)
pub const SYS_SEMOP: u64 = 65;
/// semctl(semid, semnum, cmd, ...)
pub const SYS_SEMCTL: u64 = 66;
/// shmdt(shmaddr)
pub const SYS_SHMDT: u64 = 67;
/// msgget(key, msgflg)
pub const SYS_MSGGET: u64 = 68;
/// msgsnd(msqid, msgp, msgsz, msgflg)
pub const SYS_MSGSND: u64 = 69;
/// msgrcv(msqid, msgp, msgsz, msgtyp, msgflg)
pub const SYS_MSGRCV: u64 = 70;
/// msgctl(msqid, cmd, buf)
pub const SYS_MSGCTL: u64 = 71;
/// semtimedop(semid, sops, nsops, timeout)
pub const SYS_SEMTIMEDOP: u64 = 220;

// New process/thread creation
/// clone3(uargs, size) - Modern extensible clone
pub const SYS_CLONE3: u64 = 435;

// System logging
/// syslog(type, buf, len) - Read/control kernel message ring buffer
pub const SYS_SYSLOG: u64 = 103;

// TTY control
/// vhangup() - Simulate hangup on controlling terminal
pub const SYS_VHANGUP: u64 = 153;

// Process personality/execution domain
/// personality(persona) - Set process execution domain
pub const SYS_PERSONALITY: u64 = 135;

// I/O port permissions (x86-64 only)
/// iopl(level) - Set I/O privilege level (0-3)
pub const SYS_IOPL: u64 = 172;
/// ioperm(from, num, turn_on) - Set port permissions for first 0x3ff ports
pub const SYS_IOPERM: u64 = 173;

// pidfd syscalls
/// pidfd_send_signal(pidfd, sig, info, flags) - Send signal to process via pidfd
pub const SYS_PIDFD_SEND_SIGNAL: u64 = 424;
/// pidfd_open(pid, flags) - Obtain file descriptor for process
pub const SYS_PIDFD_OPEN: u64 = 434;
/// pidfd_getfd(pidfd, targetfd, flags) - Get file descriptor from another process
pub const SYS_PIDFD_GETFD: u64 = 438;

// Keyring syscalls (Section 10.3)
/// add_key(type, description, payload, plen, keyring)
pub const SYS_ADD_KEY: u64 = 248;
/// request_key(type, description, callout_info, dest_keyring)
pub const SYS_REQUEST_KEY: u64 = 249;
/// keyctl(cmd, arg2, arg3, arg4, arg5)
pub const SYS_KEYCTL: u64 = 250;
/// process_vm_readv(pid, local_iov, liovcnt, remote_iov, riovcnt, flags)
pub const SYS_PROCESS_VM_READV: u64 = 310;
/// process_vm_writev(pid, local_iov, liovcnt, remote_iov, riovcnt, flags)
pub const SYS_PROCESS_VM_WRITEV: u64 = 311;
/// kcmp(pid1, pid2, type, idx1, idx2)
pub const SYS_KCMP: u64 = 312;

// Syscalls that return stubs (not fully implemented)
/// kexec_load(entry, nr_segments, segments, flags) - load new kernel
pub const SYS_KEXEC_LOAD: u64 = 246;
/// perf_event_open(attr, pid, cpu, group_fd, flags) - performance monitoring
pub const SYS_PERF_EVENT_OPEN: u64 = 298;
/// rseq(rseq, rseq_len, flags, sig) - restartable sequences
pub const SYS_RSEQ: u64 = 334;

/// Model Specific Registers for syscall
const MSR_EFER: u32 = 0xC000_0080; // Extended Feature Enable Register
const MSR_STAR: u32 = 0xC000_0081; // Segment selectors for syscall/sysret
const MSR_LSTAR: u32 = 0xC000_0082; // Target RIP for syscall (64-bit mode)
const MSR_SFMASK: u32 = 0xC000_0084; // RFLAGS mask for syscall

/// EFER.SCE - Syscall Enable bit
const EFER_SCE: u64 = 1 << 0;

/// RFLAGS bits to clear on syscall entry
const SYSCALL_FLAG_MASK: u64 = 0x4700; // Clear TF, DF, IF, AC

/// Initialize syscall/sysret mechanism
pub fn init() {
    // Enable SYSCALL instruction by setting EFER.SCE
    unsafe {
        let efer = rdmsr(MSR_EFER);
        wrmsr(MSR_EFER, efer | EFER_SCE);
    }

    // STAR: segment selectors for syscall/sysret
    // Bits 47:32 = kernel CS (for syscall)
    // Bits 63:48 = user CS - 16 (for sysret; CPU adds 16 for CS, 8 for SS)
    // sysret loads: CS = STAR[63:48] + 16, SS = STAR[63:48] + 8
    // So we put (USER_DATA_SELECTOR - 8) in bits 63:48

    let star = ((KERNEL_CODE_SELECTOR as u64) << 32) | (((USER_DATA_SELECTOR as u64) - 8) << 48);

    // LSTAR: target RIP for syscall
    let lstar = syscall_entry as *const () as u64;

    // SFMASK: flags to clear on syscall
    let sfmask = SYSCALL_FLAG_MASK;

    unsafe {
        wrmsr(MSR_STAR, star);
        wrmsr(MSR_LSTAR, lstar);
        wrmsr(MSR_SFMASK, sfmask);
    }
}

/// Write to MSR
#[inline]
unsafe fn wrmsr(msr: u32, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;
    unsafe {
        ::core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") low,
            in("edx") high,
            options(nostack, preserves_flags)
        );
    }
}

/// Read from MSR
#[inline]
#[allow(dead_code)]
unsafe fn rdmsr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        ::core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nostack, preserves_flags)
        );
    }
    ((high as u64) << 32) | (low as u64)
}

/// Kernel stack pointer for syscall entry
/// This is loaded when switching from user to kernel mode
static mut SYSCALL_KERNEL_STACK: u64 = 0;

/// Set the kernel stack pointer used by syscall entry
///
/// Called from switch_to.S assembly during initial context switch.
#[unsafe(no_mangle)]
pub extern "C" fn set_syscall_kernel_stack(stack: u64) {
    unsafe {
        SYSCALL_KERNEL_STACK = stack;
    }
}

/// Get the current syscall kernel stack value (for debugging)
#[allow(dead_code)]
pub fn get_syscall_kernel_stack() -> u64 {
    unsafe { SYSCALL_KERNEL_STACK }
}

/// Syscall entry point
///
/// On entry (from user mode):
/// - RCX = user RIP (return address)
/// - R11 = user RFLAGS
/// - RSP = user stack pointer
/// - RAX = syscall number
/// - RDI, RSI, RDX, R10, R8, R9 = arguments
///
/// Stack frame layout (growing down, top of stack first):
///   [callee-saved r15 placeholder] <- pushed for consistency
///   [r14]
///   [r13]
///   [r12]
///   [rbp]
///   [rbx]
///   [user r11/RFLAGS]
///   [user rcx/RIP]
///   [user RSP]  <- bottom of our frame
///
/// Must:
/// 1. Switch to kernel stack
/// 2. Save user state
/// 3. Call syscall handler
/// 4. Restore user state
/// 5. Switch back to user stack
/// 6. sysret back to user
#[unsafe(naked)]
unsafe extern "C" fn syscall_entry() {
    core::arch::naked_asm!(
        // On entry from user mode via syscall instruction:
        // RCX = user RIP (saved by syscall instruction)
        // R11 = user RFLAGS (saved by syscall instruction)
        // RSP = user stack (syscall doesn't switch stacks!)
        // RAX = syscall number
        // RDI = arg0, RSI = arg1, RDX = arg2, R10 = arg3, R8 = arg4, R9 = arg5
        //
        // Linux syscall ABI: all registers preserved except RAX (retval), RCX, R11
        // This means we MUST save/restore RDI, RSI, RDX, R10, R8, R9, and callee-saved regs

        // Switch to kernel stack, saving user RSP
        "xchg rsp, [rip + {kstack}]",
        // Now RSP = kernel stack, [kstack] = user RSP

        // Build our stack frame. We'll restore everything on exit.
        // Save user RSP (currently in kstack variable)
        "push [rip + {kstack}]",

        // Save syscall-clobbered registers
        "push rcx",        // User RIP
        "push r11",        // User RFLAGS

        // Save callee-saved registers (C ABI requires we preserve these)
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",

        // Save caller-saved registers that syscall ABI says we must preserve
        // Save RAX (syscall number) as part of the frame - return value will go here
        "push rax",
        "push rdi",
        "push rsi",
        "push rdx",
        "push r10",
        "push r8",
        "push r9",

        // Save RCX (user RIP), R11 (user RFLAGS), user RSP, and callee-saved regs
        // for clone()/fork(). The child needs to inherit ALL parent registers.
        // Stack layout at this point (from top):
        //   RSP+0:   r9
        //   RSP+8:   r8
        //   RSP+16:  r10
        //   RSP+24:  rdx
        //   RSP+32:  rsi
        //   RSP+40:  rdi
        //   RSP+48:  rax (syscall num / return value slot)
        //   RSP+56:  r15
        //   RSP+64:  r14
        //   RSP+72:  r13
        //   RSP+80:  r12
        //   RSP+88:  rbp
        //   RSP+96:  rbx
        //   RSP+104: r11 (user RFLAGS)
        //   RSP+112: rcx (user RIP)
        //   RSP+120: user_rsp
        //
        // save_syscall_state(rip, rflags, rsp, rbx, rbp, r12, r13, r14, r15)
        // ABI: rdi, rsi, rdx, rcx, r8, r9, [stack+0], [stack+8], [stack+16]
        //
        // First 6 args in registers, last 3 on stack
        // Push stack args in reverse order (r15, r14, r13)
        "push [rsp + 56]",       // r15 -> stack arg 3 (at rsp+0 after 3 pushes)
        "push [rsp + 72]",       // r14 -> stack arg 2 (offset +8 due to push)
        "push [rsp + 88]",       // r13 -> stack arg 1 (offset +16 due to 2 pushes)
        // Now set up register args
        "mov rdi, [rsp + 136]",  // rcx (user RIP) -> rdi (offset: 112 + 24)
        "mov rsi, [rsp + 128]",  // r11 (user RFLAGS) -> rsi (offset: 104 + 24)
        "mov rdx, [rsp + 144]",  // user_rsp -> rdx (offset: 120 + 24)
        "mov rcx, [rsp + 120]",  // rbx -> rcx (offset: 96 + 24)
        "mov r8, [rsp + 112]",   // rbp -> r8 (offset: 88 + 24)
        "mov r9, [rsp + 104]",   // r12 -> r9 (offset: 80 + 24)
        "call {save_syscall_state}",
        // Remove stack args
        "add rsp, 24",

        // Save caller-saved registers for fork() (Linux ABI preserves these across syscalls)
        // save_syscall_caller_saved(rdi, rsi, rdx, r8, r9, r10)
        // Stack layout: [r9, r8, r10, rdx, rsi, rdi, rax, ...]
        "mov rdi, [rsp + 40]",   // saved RDI
        "mov rsi, [rsp + 32]",   // saved RSI
        "mov rdx, [rsp + 24]",   // saved RDX
        "mov rcx, [rsp + 8]",    // saved R8
        "mov r8, [rsp + 0]",     // saved R9
        "mov r9, [rsp + 16]",    // saved R10
        "call {save_syscall_caller_saved}",

        // Now set up arguments for C handler
        // syscall_handler(num, arg0, arg1, arg2, arg3, arg4, arg5)
        // C ABI: rdi, rsi, rdx, rcx, r8, r9, [stack]
        //
        // Stack values (offsets after save_syscall_state call):
        // [RSP + 0] = saved R9 (arg5)
        // [RSP + 8] = saved R8 (arg4)
        // [RSP + 16] = saved R10 (arg3)
        // [RSP + 24] = saved RDX (arg2)
        // [RSP + 32] = saved RSI (arg1)
        // [RSP + 40] = saved RDI (arg0)
        // [RSP + 48] = saved RAX (syscall num)

        // Push arg5 for 7th parameter
        "push [rsp + 0]",  // Push saved R9 (arg5) for 7th param

        // Do the shuffle carefully using stack values (offsets +8 due to push above)
        "mov r15, [rsp + 48]",  // arg0 (saved RDI) -> r15 (temp)
        "mov r9, [rsp + 16]",   // arg4 (saved R8) -> r9
        "mov r8, [rsp + 24]",   // arg3 (saved R10) -> r8
        "mov rcx, [rsp + 32]",  // arg2 (saved RDX) -> rcx
        "mov rdx, [rsp + 40]",  // arg1 (saved RSI) -> rdx
        "mov rsi, r15",         // arg0 (temp) -> rsi
        "mov rdi, [rsp + 56]",  // syscall num (saved RAX) -> rdi

        // Call the handler (returns result in RAX)
        "call {handler}",

        // Remove arg5 from stack
        "add rsp, 8",

        // IMPORTANT: Write return value (RAX) back to the saved RAX slot in the frame
        // This ensures it survives context switches (following Linux pt_regs model)
        //
        // Stack layout after add rsp, 8 (removing arg5):
        // [RSP + 0]  = r9
        // [RSP + 8]  = r8
        // [RSP + 16] = r10
        // [RSP + 24] = rdx
        // [RSP + 32] = rsi
        // [RSP + 40] = rdi
        // [RSP + 48] = rax (return value slot)
        // [RSP + 56] = r15
        // [RSP + 64] = r14
        // [RSP + 72] = r13
        // [RSP + 80] = r12
        // [RSP + 88] = rbp
        // [RSP + 96] = rbx
        // [RSP + 104] = r11 (user RFLAGS)
        // [RSP + 112] = rcx (user RIP)
        // [RSP + 120] = user_rsp
        "mov [rsp + 48], rax",

        // Update stack frame from percpu if signal delivery modified the context
        // Pass RSP as the frame base pointer
        "mov rdi, rsp",
        "call {update_frame}",

        // Restore caller-saved registers (in reverse order of pushes)
        // Push order was: rax, rdi, rsi, rdx, r10, r8, r9
        // So pop order is: r9, r8, r10, rdx, rsi, rdi, rax
        "pop r9",
        "pop r8",
        "pop r10",
        "pop rdx",
        "pop rsi",
        "pop rdi",
        "pop rax",   // Restore return value from saved slot

        // Restore callee-saved registers (except R15 which we'll use as scratch)
        // We need to save SYSCALL_KERNEL_STACK before clobbering any user regs
        //
        // Current stack layout:
        // [RSP + 0] = r15
        // [RSP + 8] = r14
        // [RSP + 16] = r13
        // [RSP + 24] = r12
        // [RSP + 32] = rbp
        // [RSP + 40] = rbx
        // [RSP + 48] = r11 (user RFLAGS)
        // [RSP + 56] = rcx (user RIP)
        // [RSP + 64] = user_rsp
        //
        // After all pops (r15-rbx, r11, rcx, user_rsp), RSP will be at current+72
        // Save that for next syscall entry

        "lea r15, [rsp + 72]",             // Calculate final kernel RSP
        "mov [rip + {kstack}], r15",       // Save it for next syscall entry

        // Now restore callee-saved registers
        "pop r15",                         // Now safe - we've saved kstack
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",

        // Restore user RFLAGS and RIP for sysretq
        "pop r11",         // User RFLAGS
        "pop rcx",         // User RIP

        // Switch to user stack
        // [RSP] = user_rsp
        "pop rsp",         // Load user RSP directly into RSP

        // Return to user mode
        // RAX = return value, RCX = user RIP, R11 = user RFLAGS
        // All other registers have been properly restored
        "sysretq",

        handler = sym syscall_handler,
        kstack = sym SYSCALL_KERNEL_STACK,
        save_syscall_state = sym super::percpu::save_syscall_state,
        save_syscall_caller_saved = sym super::percpu::save_syscall_caller_saved,
        update_frame = sym super::percpu::update_syscall_return_frame,
    );
}

/// Syscall handler callback type
pub type SyscallHandler = fn(u64, u64, u64, u64, u64, u64, u64) -> u64;

/// Global syscall handler - set by kernel
static mut SYSCALL_HANDLER_CALLBACK: Option<SyscallHandler> = None;

/// Set the syscall handler callback
pub fn set_syscall_handler(handler: SyscallHandler) {
    unsafe {
        SYSCALL_HANDLER_CALLBACK = Some(handler);
    }
}

/// Syscall handler (called from assembly)
extern "C" fn syscall_handler(
    num: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> u64 {
    // If kernel has registered a handler, use it
    if let Some(handler) = unsafe { SYSCALL_HANDLER_CALLBACK } {
        return handler(num, arg0, arg1, arg2, arg3, arg4, arg5);
    }

    // Default minimal handler (before VFS is initialized)
    const SYS_WRITE: u64 = 1;
    const SYS_EXIT: u64 = 60;

    match num {
        SYS_WRITE => {
            // write(fd, buf, count) -> count
            let fd = arg0;
            let buf = arg1 as *const u8;
            let count = arg2 as usize;

            if fd == 1 || fd == 2 {
                // stdout/stderr -> serial console
                for i in 0..count {
                    let byte = unsafe { *buf.add(i) };
                    super::io::outb(0x3F8, byte);
                }
                count as u64
            } else {
                (-9i64) as u64 // EBADF
            }
        }
        SYS_EXIT => {
            // exit(status)
            loop {
                unsafe {
                    ::core::arch::asm!("hlt");
                }
            }
        }
        _ => {
            // Unknown syscall
            (-38i64) as u64 // ENOSYS
        }
    }
}

/// Jump to user mode using IRETQ
///
/// This function sets up the stack for iretq and enters ring 3.
/// It never returns.
///
/// # Arguments
/// * `entry` - User mode entry point (RIP)
/// * `user_stack` - User mode stack pointer (RSP)
/// * `cr3` - User page table physical address
/// * `kernel_stack` - Kernel stack pointer to save in TSS for syscall return
///
/// # Safety
/// The caller must ensure:
/// * `entry` points to valid user-mode code
/// * `user_stack` points to valid user-mode stack
/// * `cr3` points to a valid page table with kernel mapped
/// * `kernel_stack` points to valid kernel stack
#[unsafe(naked)]
pub unsafe extern "C" fn jump_to_user_iret(
    entry: u64,        // rdi
    user_stack: u64,   // rsi
    cr3: u64,          // rdx
    kernel_stack: u64, // rcx
) -> ! {
    core::arch::naked_asm!(
        // Save all input registers - they will be clobbered by function calls
        "push rdi",        // entry
        "push rsi",        // user_stack
        "push rdx",        // cr3
        "push rcx",        // kernel_stack

        // Set kernel stack in TSS for interrupt return path
        "mov rdi, rcx",
        "call {set_kstack}",

        // Set kernel stack for syscall entry
        "mov rdi, [rsp]",  // kernel_stack is at top of our saved regs
        "call {set_syscall_kstack}",

        // Restore all input registers
        "pop rcx",
        "pop rdx",
        "pop rsi",
        "pop rdi",

        // Switch to user page table
        "mov cr3, rdx",

        // Build IRET frame on current stack
        // Stack layout for iretq (pushed in reverse order):
        //   SS     (offset +32)
        //   RSP    (offset +24)
        //   RFLAGS (offset +16)
        //   CS     (offset +8)
        //   RIP    (offset +0)

        // Push SS (user data selector, ring 3)
        "push {user_ss}",
        // Push RSP (user stack)
        "push rsi",
        // Push RFLAGS (IF=1 for interrupts, bit 1 reserved must be 1)
        "push 0x202",
        // Push CS (user code selector, ring 3)
        "push {user_cs}",
        // Push RIP (entry point)
        "push rdi",

        // Clear all general-purpose registers for security
        // (don't leak kernel data to user mode)
        "xor rax, rax",
        "xor rbx, rbx",
        "xor rcx, rcx",
        "xor rdx, rdx",
        "xor rdi, rdi",
        "xor rsi, rsi",
        "xor rbp, rbp",
        "xor r8, r8",
        "xor r9, r9",
        "xor r10, r10",
        "xor r11, r11",
        "xor r12, r12",
        "xor r13, r13",
        "xor r14, r14",
        "xor r15, r15",

        // Return to user mode
        "iretq",

        set_kstack = sym super::cpu::set_kernel_stack,
        set_syscall_kstack = sym set_syscall_kernel_stack,
        user_cs = const USER_CODE_SELECTOR as u64,
        user_ss = const USER_DATA_SELECTOR as u64,
    );
}

// =============================================================================
// x86-64 syscall dispatcher
// =============================================================================

/// x86-64 syscall dispatcher
///
/// This function dispatches syscalls based on Linux x86-64 syscall numbers.
/// It calls generic handlers in vfs_syscall, time_syscall, and sched_syscall.
///
/// This is the arch-specific entry point that should be registered with
/// `set_syscall_handler()`.
pub fn x86_64_syscall_dispatch(
    num: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> u64 {
    use crate::fs::syscall::{
        sys_access,
        sys_chdir,
        sys_chmod,
        sys_chown,
        sys_chroot,
        sys_close,
        sys_dup,
        sys_dup2,
        sys_dup3,
        sys_faccessat,
        sys_faccessat2,
        sys_fchdir,
        sys_fchmod,
        sys_fchmodat,
        sys_fchmodat2,
        sys_fchown,
        sys_fchownat,
        // fcntl
        sys_fcntl,
        // Sync syscalls
        sys_fdatasync,
        sys_fgetxattr,
        sys_flistxattr,
        sys_fremovexattr,
        sys_fsetxattr,
        sys_fstat,
        sys_fstatfs,
        sys_fsync,
        sys_ftruncate,
        sys_getcwd,
        sys_getdents64,
        sys_getxattr,
        // ioctl
        sys_ioctl,
        sys_lchown,
        sys_lgetxattr,
        sys_link,
        sys_linkat,
        sys_listxattr,
        sys_llistxattr,
        sys_lremovexattr,
        sys_lseek,
        sys_lsetxattr,
        sys_lstat,
        sys_mkdir,
        sys_mkdirat,
        sys_mknod,
        sys_mknodat,
        sys_mount,
        sys_open,
        sys_openat,
        // Pipe syscalls
        sys_pipe,
        sys_pipe2,
        sys_pivot_root,
        // Poll syscalls
        sys_poll,
        sys_ppoll,
        // Positioned read/write syscalls
        sys_pread64,
        sys_preadv,
        sys_preadv2,
        // Select syscalls
        sys_pselect6,
        sys_pwrite64,
        sys_pwritev,
        sys_pwritev2,
        sys_read,
        sys_readlink,
        sys_readlinkat,
        sys_readv,
        sys_removexattr,
        sys_rename,
        sys_renameat,
        sys_renameat2,
        sys_rmdir,
        sys_select,
        // Extended attributes
        sys_setxattr,
        sys_stat,
        sys_statfs,
        sys_statx,
        sys_symlink,
        sys_symlinkat,
        sys_sync,
        sys_syncfs,
        sys_truncate,
        sys_umask,
        sys_umount2,
        sys_unlink,
        sys_unlinkat,
        sys_utime,
        sys_utimensat,
        sys_utimes,
        sys_write,
        sys_writev,
    };
    use crate::task::exec::{sys_execve, sys_execveat};
    use crate::task::percpu;
    use crate::task::syscall::{
        sys_clone, sys_exit, sys_fork, sys_getegid, sys_geteuid, sys_getgid, sys_getpgid,
        sys_getpid, sys_getppid, sys_getsid, sys_gettid, sys_getuid, sys_sched_yield, sys_setpgid,
        sys_setsid, sys_vfork, sys_wait4, sys_waitid,
    };
    use crate::time_syscall::{
        sys_adjtimex, sys_clock_getres, sys_clock_gettime, sys_clock_nanosleep, sys_clock_settime,
        sys_eventfd, sys_eventfd2, sys_gettimeofday, sys_nanosleep, sys_settimeofday, sys_time,
        sys_timerfd_create, sys_timerfd_gettime, sys_timerfd_settime,
    };

    // Account for entering kernel mode
    percpu::account_syscall_enter();

    // Check seccomp policy before executing syscall
    // Note: ip is not available here, pass 0 for now
    if let Some(result) =
        crate::seccomp::check::check_syscall_x86_64(num, 0, arg0, arg1, arg2, arg3, arg4, arg5)
    {
        percpu::account_syscall_exit();
        return result;
    }

    let result = match num {
        SYS_READ => sys_read(arg0 as i32, arg1, arg2) as u64,
        SYS_WRITE => sys_write(arg0 as i32, arg1, arg2) as u64,
        SYS_READV => sys_readv(arg0 as i32, arg1, arg2 as i32) as u64,
        SYS_WRITEV => sys_writev(arg0 as i32, arg1, arg2 as i32) as u64,
        SYS_PREAD64 => sys_pread64(arg0 as i32, arg1, arg2, arg3 as i64) as u64,
        SYS_PWRITE64 => sys_pwrite64(arg0 as i32, arg1, arg2, arg3 as i64) as u64,
        SYS_PREADV => sys_preadv(arg0 as i32, arg1, arg2 as i32, arg3 as i64) as u64,
        SYS_PWRITEV => sys_pwritev(arg0 as i32, arg1, arg2 as i32, arg3 as i64) as u64,
        SYS_PREADV2 => sys_preadv2(arg0 as i32, arg1, arg2 as i32, arg3 as i64, arg4 as i32) as u64,
        SYS_PWRITEV2 => {
            sys_pwritev2(arg0 as i32, arg1, arg2 as i32, arg3 as i64, arg4 as i32) as u64
        }
        SYS_OPEN => sys_open(arg0, arg1 as u32, arg2 as u32) as u64,
        SYS_CLOSE => sys_close(arg0 as i32) as u64,
        SYS_LSEEK => sys_lseek(arg0 as i32, arg1 as i64, arg2 as i32) as u64,
        SYS_MMAP => {
            crate::mm::syscall::sys_mmap(arg0, arg1, arg2 as u32, arg3 as u32, arg4 as i32, arg5)
                as u64
        }
        SYS_MPROTECT => crate::mm::syscall::sys_mprotect(arg0, arg1, arg2 as u32) as u64,
        SYS_MUNMAP => crate::mm::syscall::sys_munmap(arg0, arg1) as u64,
        SYS_BRK => crate::mm::syscall::sys_brk(arg0) as u64,
        SYS_MLOCK => crate::mm::syscall::sys_mlock(arg0, arg1) as u64,
        SYS_MUNLOCK => crate::mm::syscall::sys_munlock(arg0, arg1) as u64,
        SYS_MLOCKALL => crate::mm::syscall::sys_mlockall(arg0 as i32) as u64,
        SYS_MUNLOCKALL => crate::mm::syscall::sys_munlockall() as u64,
        SYS_MLOCK2 => crate::mm::syscall::sys_mlock2(arg0, arg1, arg2 as i32) as u64,
        SYS_MSYNC => crate::mm::syscall::sys_msync(arg0, arg1, arg2 as i32) as u64,
        SYS_MINCORE => crate::mm::syscall::sys_mincore(arg0, arg1, arg2) as u64,
        SYS_MADVISE => crate::mm::syscall::sys_madvise(arg0, arg1, arg2 as i32) as u64,
        SYS_MREMAP => crate::mm::syscall::sys_mremap(arg0, arg1, arg2, arg3 as u32, arg4) as u64,
        SYS_FTRUNCATE => sys_ftruncate(arg0 as i32, arg1 as i64) as u64,
        SYS_TRUNCATE => sys_truncate(arg0, arg1 as i64) as u64,
        SYS_STAT => sys_stat(arg0, arg1) as u64,
        SYS_FSTAT => sys_fstat(arg0 as i32, arg1) as u64,
        SYS_STATFS => sys_statfs(arg0, arg1) as u64,
        SYS_FSTATFS => sys_fstatfs(arg0 as i32, arg1) as u64,
        SYS_STATX => sys_statx(arg0 as i32, arg1, arg2 as i32, arg3 as u32, arg4) as u64,
        SYS_DUP => sys_dup(arg0 as i32) as u64,
        SYS_DUP2 => sys_dup2(arg0 as i32, arg1 as i32) as u64,
        SYS_FCNTL => sys_fcntl(arg0 as i32, arg1 as i32, arg2) as u64,
        SYS_GETPID => sys_getpid(percpu::current_pid()) as u64,
        SYS_GETTIMEOFDAY => sys_gettimeofday(arg0, arg1) as u64,
        SYS_GETTID => sys_gettid(percpu::current_tid()) as u64,
        SYS_GETDENTS64 => sys_getdents64(arg0 as i32, arg1, arg2) as u64,
        SYS_CLOCK_GETTIME => sys_clock_gettime(arg0 as i32, arg1) as u64,
        SYS_CLOCK_GETRES => sys_clock_getres(arg0 as i32, arg1) as u64,
        SYS_TIME => sys_time(arg0) as u64,
        SYS_CLOCK_SETTIME => sys_clock_settime(arg0 as i32, arg1) as u64,
        SYS_SETTIMEOFDAY => sys_settimeofday(arg0, arg1) as u64,
        SYS_NANOSLEEP => sys_nanosleep(arg0, arg1) as u64,
        SYS_CLOCK_NANOSLEEP => sys_clock_nanosleep(arg0 as i32, arg1 as i32, arg2, arg3) as u64,
        SYS_TIMERFD_CREATE => sys_timerfd_create(arg0 as i32, arg1 as i32) as u64,
        SYS_TIMERFD_SETTIME => sys_timerfd_settime(arg0 as i32, arg1 as i32, arg2, arg3) as u64,
        SYS_TIMERFD_GETTIME => sys_timerfd_gettime(arg0 as i32, arg1) as u64,
        SYS_ADJTIMEX => sys_adjtimex(arg0) as u64,
        SYS_EVENTFD => sys_eventfd(arg0 as u32) as u64,
        SYS_EVENTFD2 => sys_eventfd2(arg0 as u32, arg1 as i32) as u64,

        // signalfd syscalls (Section 5)
        SYS_SIGNALFD => crate::signal::syscall::sys_signalfd(arg0 as i32, arg1, arg2 as i32) as u64,
        SYS_SIGNALFD4 => {
            crate::signal::syscall::sys_signalfd4(arg0 as i32, arg1, arg2, arg3 as i32) as u64
        }

        // inotify syscalls (Section 9.2)
        SYS_INOTIFY_INIT => crate::inotify::sys_inotify_init() as u64,
        SYS_INOTIFY_INIT1 => crate::inotify::sys_inotify_init1(arg0 as i32) as u64,
        SYS_INOTIFY_ADD_WATCH => {
            crate::inotify::sys_inotify_add_watch(arg0 as i32, arg1, arg2 as u32) as u64
        }
        SYS_INOTIFY_RM_WATCH => {
            crate::inotify::sys_inotify_rm_watch(arg0 as i32, arg1 as i32) as u64
        }

        // fanotify syscalls (Section 9.2)
        SYS_FANOTIFY_INIT => crate::fanotify::sys_fanotify_init(arg0 as u32, arg1 as u32) as u64,
        SYS_FANOTIFY_MARK => {
            crate::fanotify::sys_fanotify_mark(arg0 as i32, arg1 as u32, arg2, arg3 as i32, arg4)
                as u64
        }

        // epoll syscalls (Section 9.1)
        SYS_EPOLL_CREATE => crate::epoll::sys_epoll_create(arg0 as i32) as u64,
        SYS_EPOLL_CREATE1 => crate::epoll::sys_epoll_create1(arg0 as i32) as u64,
        SYS_EPOLL_CTL => {
            crate::epoll::sys_epoll_ctl(arg0 as i32, arg1 as i32, arg2 as i32, arg3) as u64
        }
        SYS_EPOLL_WAIT => {
            crate::epoll::sys_epoll_wait(arg0 as i32, arg1, arg2 as i32, arg3 as i32) as u64
        }
        SYS_EPOLL_PWAIT => {
            crate::epoll::sys_epoll_pwait(arg0 as i32, arg1, arg2 as i32, arg3 as i32, arg4, arg5)
                as u64
        }
        SYS_EPOLL_PWAIT2 => {
            crate::epoll::sys_epoll_pwait2(arg0 as i32, arg1, arg2 as i32, arg3, arg4, arg5) as u64
        }

        // io_uring syscalls (Section 9.3)
        SYS_IO_URING_SETUP => crate::io_uring::sys_io_uring_setup(arg0 as u32, arg1) as u64,
        SYS_IO_URING_ENTER => crate::io_uring::sys_io_uring_enter(
            arg0 as u32,
            arg1 as u32,
            arg2 as u32,
            arg3 as u32,
            arg4,
            arg5 as usize,
        ) as u64,
        SYS_IO_URING_REGISTER => {
            crate::io_uring::sys_io_uring_register(arg0 as u32, arg1 as u32, arg2, arg3 as u32)
                as u64
        }

        // POSIX timer syscalls (Section 6.2)
        SYS_TIMER_CREATE => crate::posix_timer::sys_timer_create(arg0 as i32, arg1, arg2) as u64,
        SYS_TIMER_SETTIME => {
            crate::posix_timer::sys_timer_settime(arg0 as i32, arg1 as i32, arg2, arg3) as u64
        }
        SYS_TIMER_GETTIME => crate::posix_timer::sys_timer_gettime(arg0 as i32, arg1) as u64,
        SYS_TIMER_GETOVERRUN => crate::posix_timer::sys_timer_getoverrun(arg0 as i32) as u64,
        SYS_TIMER_DELETE => crate::posix_timer::sys_timer_delete(arg0 as i32) as u64,

        // POSIX message queue syscalls (Section 7.4)
        SYS_MQ_OPEN => crate::ipc::sys_mq_open(arg0, arg1 as i32, arg2 as u32, arg3) as u64,
        SYS_MQ_UNLINK => crate::ipc::sys_mq_unlink(arg0) as u64,
        SYS_MQ_TIMEDSEND => {
            crate::ipc::sys_mq_timedsend(arg0 as i32, arg1, arg2 as usize, arg3 as u32, arg4) as u64
        }
        SYS_MQ_TIMEDRECEIVE => {
            crate::ipc::sys_mq_timedreceive(arg0 as i32, arg1, arg2 as usize, arg3, arg4) as u64
        }
        SYS_MQ_NOTIFY => crate::ipc::sys_mq_notify(arg0 as i32, arg1) as u64,
        SYS_MQ_GETSETATTR => crate::ipc::sys_mq_getsetattr(arg0 as i32, arg1, arg2) as u64,

        SYS_SCHED_YIELD => {
            sys_sched_yield();
            0
        }
        SYS_EXIT => sys_exit(arg0 as i32),

        // Process IDs & basic info (Section 1.2)
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

        // Credentials (Section 10.1)
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
        SYS_CAPGET => {
            use crate::arch::Uaccess;
            use crate::task::syscall::sys_capget;
            sys_capget::<Uaccess>(arg0, arg1) as u64
        }
        SYS_CAPSET => {
            use crate::arch::Uaccess;
            use crate::task::syscall::sys_capset;
            sys_capset::<Uaccess>(arg0, arg1) as u64
        }

        // Process creation (Section 1.1)
        SYS_CLONE => sys_clone(arg0, arg1, arg2, arg3, arg4) as u64,
        SYS_CLONE3 => {
            use crate::task::syscall::sys_clone3;
            sys_clone3(arg0, arg1) as u64
        }
        SYS_FORK => sys_fork() as u64,
        SYS_VFORK => sys_vfork() as u64,
        SYS_EXECVE => sys_execve(arg0, arg1, arg2) as u64,
        SYS_EXECVEAT => sys_execveat(arg0 as i32, arg1, arg2, arg3, arg4 as i32) as u64,
        SYS_WAIT4 => sys_wait4(arg0 as i64, arg1, arg2 as i32, arg3) as u64,
        SYS_WAITID => sys_waitid(arg0 as i32, arg1, arg2, arg3 as i32) as u64,
        SYS_EXIT_GROUP => sys_exit(arg0 as i32), // For single-threaded, same as _exit

        // Personality (execution domain)
        SYS_PERSONALITY => {
            use crate::task::syscall::sys_personality;
            sys_personality(arg0 as u32) as u64
        }

        // I/O port permissions (x86-64 only)
        SYS_IOPL => {
            use crate::task::syscall::sys_iopl;
            sys_iopl(arg0 as u32) as u64
        }
        SYS_IOPERM => {
            use crate::task::syscall::sys_ioperm;
            sys_ioperm(arg0, arg1, arg2 as i32) as u64
        }

        // System logging
        SYS_SYSLOG => {
            use crate::arch::Uaccess;
            use crate::task::syscall::sys_syslog;
            sys_syslog::<Uaccess>(arg0 as i32, arg1, arg2 as i32) as u64
        }

        // TTY control
        SYS_VHANGUP => crate::tty::sys_vhangup() as u64,

        // pidfd syscalls
        SYS_PIDFD_OPEN => {
            use crate::task::syscall::sys_pidfd_open;
            sys_pidfd_open(arg0 as i64, arg1 as u32) as u64
        }
        SYS_PIDFD_SEND_SIGNAL => {
            use crate::task::syscall::sys_pidfd_send_signal;
            sys_pidfd_send_signal(arg0 as i32, arg1 as i32, arg2, arg3 as u32) as u64
        }
        SYS_PIDFD_GETFD => {
            use crate::task::syscall::sys_pidfd_getfd;
            sys_pidfd_getfd(arg0 as i32, arg1 as i32, arg2 as u32) as u64
        }

        // Power management
        SYS_REBOOT => crate::power::sys_reboot(arg0 as u32, arg1 as u32, arg2 as u32, arg3) as u64,

        // Filesystem syscalls (Section 2.1 / 3.1)
        SYS_ACCESS => sys_access(arg0, arg1 as i32) as u64,
        SYS_GETCWD => sys_getcwd(arg0, arg1) as u64,
        SYS_CHDIR => sys_chdir(arg0) as u64,
        SYS_FCHDIR => sys_fchdir(arg0 as i32) as u64,
        SYS_CHROOT => sys_chroot(arg0) as u64,
        SYS_OPENAT => sys_openat(arg0 as i32, arg1, arg2 as u32, arg3 as u32) as u64,
        SYS_FACCESSAT => sys_faccessat(arg0 as i32, arg1, arg2 as i32, arg3 as i32) as u64,
        SYS_DUP3 => sys_dup3(arg0 as i32, arg1 as i32, arg2 as u32) as u64,
        SYS_PIPE => sys_pipe(arg0) as u64,
        SYS_PIPE2 => sys_pipe2(arg0, arg1 as u32) as u64,
        SYS_POLL => sys_poll(arg0, arg1 as u32, arg2 as i32) as u64,
        SYS_PPOLL => sys_ppoll(arg0, arg1 as u32, arg2, arg3, arg4) as u64,
        SYS_SELECT => sys_select(arg0 as i32, arg1, arg2, arg3, arg4) as u64,
        SYS_PSELECT6 => sys_pselect6(arg0 as i32, arg1, arg2, arg3, arg4, arg5) as u64,
        SYS_FACCESSAT2 => sys_faccessat2(arg0 as i32, arg1, arg2 as i32, arg3 as i32) as u64,

        // Symlinks and hard links
        SYS_LSTAT => sys_lstat(arg0, arg1) as u64,
        SYS_LINK => sys_link(arg0, arg1) as u64,
        SYS_SYMLINK => sys_symlink(arg0, arg1) as u64,
        SYS_READLINK => sys_readlink(arg0, arg1, arg2) as u64,
        SYS_LINKAT => sys_linkat(arg0 as i32, arg1, arg2 as i32, arg3, arg4 as i32) as u64,
        SYS_SYMLINKAT => sys_symlinkat(arg0, arg1 as i32, arg2) as u64,
        SYS_READLINKAT => sys_readlinkat(arg0 as i32, arg1, arg2, arg3) as u64,

        // Directory creation/removal
        SYS_MKDIR => sys_mkdir(arg0, arg1 as u32) as u64,
        SYS_MKDIRAT => sys_mkdirat(arg0 as i32, arg1, arg2 as u32) as u64,
        SYS_RMDIR => sys_rmdir(arg0) as u64,

        // File deletion
        SYS_UNLINK => sys_unlink(arg0) as u64,
        SYS_UNLINKAT => sys_unlinkat(arg0 as i32, arg1, arg2 as i32) as u64,

        // Node creation
        SYS_MKNOD => sys_mknod(arg0, arg1 as u32, arg2) as u64,
        SYS_MKNODAT => sys_mknodat(arg0 as i32, arg1, arg2 as u32, arg3) as u64,

        // Filesystem mounting
        SYS_MOUNT => sys_mount(arg0, arg1, arg2, arg3, arg4) as u64,
        SYS_UMOUNT2 => sys_umount2(arg0, arg1 as i32) as u64,
        SYS_PIVOT_ROOT => sys_pivot_root(arg0, arg1) as u64,

        // Swap management
        SYS_SWAPON => crate::mm::sys_swapon(arg0, arg1 as i32) as u64,
        SYS_SWAPOFF => crate::mm::sys_swapoff(arg0) as u64,

        // Sync operations
        SYS_SYNC => sys_sync() as u64,
        SYS_FSYNC => sys_fsync(arg0 as i32) as u64,
        SYS_FDATASYNC => sys_fdatasync(arg0 as i32) as u64,
        SYS_SYNCFS => sys_syncfs(arg0 as i32) as u64,

        // ioctl
        SYS_IOCTL => sys_ioctl(arg0 as i32, arg1 as u32, arg2) as u64,

        // splice/sendfile/copy/flock
        SYS_SENDFILE => {
            crate::fs::splice::sys_sendfile64(arg0 as i32, arg1 as i32, arg2, arg3 as usize) as u64
        }
        SYS_FLOCK => crate::fs::flock::sys_flock(arg0 as i32, arg1 as i32) as u64,
        SYS_SPLICE => crate::fs::splice::sys_splice(
            arg0 as i32,
            arg1,
            arg2 as i32,
            arg3,
            arg4 as usize,
            arg5 as u32,
        ) as u64,
        SYS_TEE => {
            crate::fs::splice::sys_tee(arg0 as i32, arg1 as i32, arg2 as usize, arg3 as u32) as u64
        }
        SYS_VMSPLICE => {
            crate::fs::splice::sys_vmsplice(arg0 as i32, arg1, arg2 as usize, arg3 as u32) as u64
        }
        SYS_FALLOCATE => {
            crate::fs::misc::sys_fallocate(arg0 as i32, arg1 as i32, arg2 as i64, arg3 as i64)
                as u64
        }
        SYS_COPY_FILE_RANGE => crate::fs::splice::sys_copy_file_range(
            arg0 as i32,
            arg1,
            arg2 as i32,
            arg3,
            arg4,
            arg5 as u32,
        ) as u64,

        // Permissions
        SYS_CHMOD => sys_chmod(arg0, arg1 as u32) as u64,
        SYS_FCHMOD => sys_fchmod(arg0 as i32, arg1 as u32) as u64,
        SYS_FCHMODAT => sys_fchmodat(arg0 as i32, arg1, arg2 as u32, arg3 as i32) as u64,
        SYS_FCHMODAT2 => sys_fchmodat2(arg0 as i32, arg1, arg2 as u32, arg3 as i32) as u64,

        // Ownership
        SYS_CHOWN => sys_chown(arg0, arg1 as u32, arg2 as u32) as u64,
        SYS_FCHOWN => sys_fchown(arg0 as i32, arg1 as u32, arg2 as u32) as u64,
        SYS_LCHOWN => sys_lchown(arg0, arg1 as u32, arg2 as u32) as u64,
        SYS_FCHOWNAT => {
            sys_fchownat(arg0 as i32, arg1, arg2 as u32, arg3 as u32, arg4 as i32) as u64
        }

        // File creation mask
        SYS_UMASK => sys_umask(arg0 as u32) as u64,

        // Timestamps
        SYS_UTIME => sys_utime(arg0, arg1) as u64,
        SYS_UTIMES => sys_utimes(arg0, arg1) as u64,
        SYS_UTIMENSAT => sys_utimensat(arg0 as i32, arg1, arg2, arg3 as i32) as u64,

        // Rename
        SYS_RENAME => sys_rename(arg0, arg1) as u64,
        SYS_RENAMEAT => sys_renameat(arg0 as i32, arg1, arg2 as i32, arg3) as u64,
        SYS_RENAMEAT2 => sys_renameat2(arg0 as i32, arg1, arg2 as i32, arg3, arg4 as u32) as u64,

        // Extended attributes
        SYS_SETXATTR => sys_setxattr(arg0, arg1, arg2, arg3, arg4 as i32) as u64,
        SYS_LSETXATTR => sys_lsetxattr(arg0, arg1, arg2, arg3, arg4 as i32) as u64,
        SYS_FSETXATTR => sys_fsetxattr(arg0 as i32, arg1, arg2, arg3, arg4 as i32) as u64,
        SYS_GETXATTR => sys_getxattr(arg0, arg1, arg2, arg3) as u64,
        SYS_LGETXATTR => sys_lgetxattr(arg0, arg1, arg2, arg3) as u64,
        SYS_FGETXATTR => sys_fgetxattr(arg0 as i32, arg1, arg2, arg3) as u64,
        SYS_LISTXATTR => sys_listxattr(arg0, arg1, arg2) as u64,
        SYS_LLISTXATTR => sys_llistxattr(arg0, arg1, arg2) as u64,
        SYS_FLISTXATTR => sys_flistxattr(arg0 as i32, arg1, arg2) as u64,
        SYS_REMOVEXATTR => sys_removexattr(arg0, arg1) as u64,
        SYS_LREMOVEXATTR => sys_lremovexattr(arg0, arg1) as u64,
        SYS_FREMOVEXATTR => sys_fremovexattr(arg0 as i32, arg1) as u64,

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
        SYS_RT_SIGTIMEDWAIT => {
            crate::signal::syscall::sys_rt_sigtimedwait(arg0, arg1, arg2, arg3) as u64
        }
        SYS_SIGALTSTACK => crate::signal::syscall::sys_sigaltstack(arg0, arg1) as u64,
        SYS_KILL => crate::signal::syscall::sys_kill(arg0 as i64, arg1 as u32) as u64,
        SYS_TGKILL => {
            crate::signal::syscall::sys_tgkill(arg0 as i64, arg1 as i64, arg2 as u32) as u64
        }
        SYS_TKILL => crate::signal::syscall::sys_tkill(arg0 as i64, arg1 as u32) as u64,
        SYS_RT_SIGQUEUEINFO => {
            crate::signal::syscall::sys_rt_sigqueueinfo(arg0 as i64, arg1 as u32, arg2) as u64
        }
        SYS_RT_SIGSUSPEND => crate::signal::syscall::sys_rt_sigsuspend(arg0, arg1) as u64,
        SYS_RT_SIGRETURN => super::signal::sys_rt_sigreturn() as u64,
        SYS_RT_TGSIGQUEUEINFO => crate::signal::syscall::sys_rt_tgsigqueueinfo(
            arg0 as i64,
            arg1 as i64,
            arg2 as u32,
            arg3,
        ) as u64,

        // membarrier syscall
        SYS_MEMBARRIER => {
            crate::membarrier::sys_membarrier(arg0 as i32, arg1 as u32, arg2 as i32) as u64
        }

        // readahead syscall
        SYS_READAHEAD => {
            crate::fs::syscall::sys_readahead(arg0 as i32, arg1 as i64, arg2 as usize) as u64
        }

        // NUMA memory policy
        SYS_GET_MEMPOLICY => {
            crate::mm::mempolicy::sys_get_mempolicy(arg0, arg1, arg2, arg3, arg4) as u64
        }
        SYS_SET_MEMPOLICY => {
            crate::mm::mempolicy::sys_set_mempolicy(arg0 as i32, arg1, arg2) as u64
        }
        SYS_MBIND => {
            crate::mm::mempolicy::sys_mbind(arg0, arg1, arg2, arg3, arg4, arg5 as u32) as u64
        }
        SYS_MIGRATE_PAGES => {
            crate::mm::mempolicy::sys_migrate_pages(arg0 as i64, arg1, arg2, arg3) as u64
        }
        SYS_MOVE_PAGES => {
            crate::mm::mempolicy::sys_move_pages(arg0 as i64, arg1, arg2, arg3, arg4, arg5 as i32)
                as u64
        }

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

        // I/O priority
        SYS_IOPRIO_SET => {
            use crate::task::syscall::sys_ioprio_set;
            sys_ioprio_set(arg0 as i32, arg1 as i32, arg2 as i32) as u64
        }
        SYS_IOPRIO_GET => {
            use crate::task::syscall::sys_ioprio_get;
            sys_ioprio_get(arg0 as i32, arg1 as i32) as u64
        }

        // Thread-local storage and process control
        SYS_PRCTL => {
            use crate::task::syscall::sys_prctl;
            sys_prctl(arg0 as i32, arg1, arg2, arg3, arg4) as u64
        }
        SYS_ARCH_PRCTL => {
            use crate::task::syscall::sys_arch_prctl;
            sys_arch_prctl(arg0 as i32, arg1) as u64
        }

        // Ptrace (debugging/tracing)
        SYS_PTRACE => crate::task::ptrace::sys_ptrace(arg0 as i64, arg1 as i64, arg2, arg3) as u64,
        SYS_SET_TID_ADDRESS => {
            use crate::task::syscall::sys_set_tid_address;
            sys_set_tid_address(arg0) as u64
        }
        SYS_SECCOMP => crate::seccomp::sys_seccomp(arg0, arg1, arg2) as u64,
        SYS_BPF => crate::bpf::sys_bpf(arg0 as i32, arg1, arg2 as u32) as u64,

        // Scheduling syscalls (Section 1.3)
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
        SYS_NICE => {
            use crate::task::syscall::sys_nice;
            sys_nice(
                arg0 as i32,
                percpu::current_pid(),
                percpu::current_cred().euid,
            ) as u64
        }

        // System information
        SYS_GETCPU => {
            use crate::arch::{PerCpuOps, Uaccess};
            crate::task::syscall::sys_getcpu::<Uaccess>(
                crate::arch::CurrentArch::try_current_cpu_id().unwrap_or(0),
                arg0,
                arg1,
            ) as u64
        }
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
        SYS_ACCT => crate::acct::sys_acct(arg0) as u64,

        // Resource limits
        SYS_GETRLIMIT => crate::rlimit::sys_getrlimit(arg0 as u32, arg1) as u64,
        SYS_SETRLIMIT => crate::rlimit::sys_setrlimit(arg0 as u32, arg1) as u64,
        SYS_PRLIMIT64 => crate::rlimit::sys_prlimit64(arg0 as i32, arg1 as u32, arg2, arg3) as u64,

        // Socket syscalls
        SYS_SOCKET => crate::net::syscall::sys_socket(arg0 as i32, arg1 as i32, arg2 as i32) as u64,
        SYS_CONNECT => crate::net::syscall::sys_connect(arg0 as i32, arg1, arg2) as u64,
        SYS_ACCEPT => crate::net::syscall::sys_accept(arg0 as i32, arg1, arg2) as u64,
        SYS_SENDTO => {
            crate::net::syscall::sys_sendto(arg0 as i32, arg1, arg2, arg3 as i32, arg4, arg5) as u64
        }
        SYS_RECVFROM => {
            crate::net::syscall::sys_recvfrom(arg0 as i32, arg1, arg2, arg3 as i32, arg4, arg5)
                as u64
        }
        SYS_SHUTDOWN => crate::net::syscall::sys_shutdown(arg0 as i32, arg1 as i32) as u64,
        SYS_BIND => crate::net::syscall::sys_bind(arg0 as i32, arg1, arg2) as u64,
        SYS_LISTEN => crate::net::syscall::sys_listen(arg0 as i32, arg1 as i32) as u64,
        SYS_GETSOCKNAME => crate::net::syscall::sys_getsockname(arg0 as i32, arg1, arg2) as u64,
        SYS_GETPEERNAME => crate::net::syscall::sys_getpeername(arg0 as i32, arg1, arg2) as u64,
        SYS_SETSOCKOPT => {
            crate::net::syscall::sys_setsockopt(arg0 as i32, arg1 as i32, arg2 as i32, arg3, arg4)
                as u64
        }
        SYS_GETSOCKOPT => {
            crate::net::syscall::sys_getsockopt(arg0 as i32, arg1 as i32, arg2 as i32, arg3, arg4)
                as u64
        }
        SYS_ACCEPT4 => {
            crate::net::syscall::sys_accept4(arg0 as i32, arg1, arg2, arg3 as i32) as u64
        }
        SYS_SOCKETPAIR => {
            crate::net::syscall::sys_socketpair(arg0 as i32, arg1 as i32, arg2 as i32, arg3) as u64
        }
        SYS_SENDMSG => crate::net::syscall::sys_sendmsg(arg0 as i32, arg1, arg2 as i32) as u64,
        SYS_RECVMSG => crate::net::syscall::sys_recvmsg(arg0 as i32, arg1, arg2 as i32) as u64,
        SYS_SENDMMSG => {
            crate::net::syscall::sys_sendmmsg(arg0 as i32, arg1, arg2 as u32, arg3 as i32) as u64
        }
        SYS_RECVMMSG => {
            crate::net::syscall::sys_recvmmsg(arg0 as i32, arg1, arg2 as u32, arg3 as i32, arg4)
                as u64
        }

        // Futex syscalls
        SYS_FUTEX => {
            crate::futex::sys_futex(arg0, arg1 as u32, arg2 as u32, arg3, arg4, arg5 as u32) as u64
        }
        SYS_SET_ROBUST_LIST => crate::futex::sys_set_robust_list(arg0, arg1) as u64,
        SYS_GET_ROBUST_LIST => crate::futex::sys_get_robust_list(arg0 as i32, arg1, arg2) as u64,
        SYS_FUTEX_WAITV => {
            crate::futex::sys_futex_waitv(arg0, arg1 as u32, arg2 as u32, arg3, arg4 as i32) as u64
        }

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

        // Keyring syscalls (Section 10.3)
        SYS_ADD_KEY => crate::keys::sys_add_key(arg0, arg1, arg2, arg3, arg4 as i32) as u64,
        SYS_REQUEST_KEY => crate::keys::sys_request_key(arg0, arg1, arg2, arg3 as i32) as u64,
        SYS_KEYCTL => crate::keys::sys_keyctl(arg0 as i32, arg1, arg2, arg3, arg4) as u64,

        // Cross-process memory access
        SYS_PROCESS_VM_READV => {
            crate::task::process_vm::sys_process_vm_readv(arg0 as i32, arg1, arg2, arg3, arg4, arg5)
                as u64
        }
        SYS_PROCESS_VM_WRITEV => crate::task::process_vm::sys_process_vm_writev(
            arg0 as i32,
            arg1,
            arg2,
            arg3,
            arg4,
            arg5,
        ) as u64,

        // Process inspection (Section 13)
        SYS_KCMP => crate::kcmp::sys_kcmp(arg0, arg1, arg2 as i32, arg3, arg4) as u64,

        // Syscall stubs (not fully implemented)
        SYS_RSEQ => {
            // Restartable sequences - not implemented, return ENOSYS
            (-38i64) as u64 // ENOSYS
        }
        SYS_PERF_EVENT_OPEN => {
            // Performance monitoring - not supported, return EOPNOTSUPP
            (-95i64) as u64 // EOPNOTSUPP
        }
        SYS_KEXEC_LOAD => {
            // Kernel execution load - check capability, return ENOSYS
            if !crate::task::capable(crate::task::CAP_SYS_BOOT) {
                (-1i64) as u64 // EPERM
            } else {
                (-38i64) as u64 // ENOSYS
            }
        }

        _ => (-38i64) as u64, // ENOSYS
    };

    // Check for pending signals before returning to userspace
    // This may modify the saved user context to invoke the signal handler
    crate::signal::do_signal();

    // Account for exiting kernel mode
    percpu::account_syscall_exit();

    result
}

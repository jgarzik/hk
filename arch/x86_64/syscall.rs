//! x86-64 Syscall entry/exit and dispatch
//!
//! This module handles:
//! - Syscall instruction MSR configuration
//! - Syscall entry point (assembly)
//! - Syscall number dispatch to generic handlers
//!
//! The SYS_* constants are x86-64 Linux ABI specific. Other architectures
//! (e.g., aarch64) have different syscall numbers.
#![allow(clippy::undocumented_unsafe_blocks)] // TODO(unsafe): SAFETY comments (doc/UNSAFE.md)

use crate::syscall::Sys;

use super::cpu::{KERNEL_CODE_SELECTOR, USER_DATA_SELECTOR};

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
/// close_range(fd, max_fd, flags)
pub const SYS_CLOSE_RANGE: u64 = 436;
/// stat(pathname, statbuf)
pub const SYS_STAT: u64 = 4;
/// fstat(fd, statbuf)
pub const SYS_FSTAT: u64 = 5;
pub const SYS_NEWFSTATAT: u64 = 262;
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
/// getdents(fd, dirp, count) (legacy struct linux_dirent)
pub const SYS_GETDENTS: u64 = 78;
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
pub const SYS_GETITIMER: u64 = 36;
pub const SYS_ALARM: u64 = 37;
pub const SYS_SETITIMER: u64 = 38;
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
pub const SYS_GETGROUPS: u64 = 115;
pub const SYS_SETGROUPS: u64 = 116;
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
/// waitid(idtype, id, infop, options, rusage)
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
pub const SYS_FADVISE64: u64 = 221;
pub const SYS_SYNC_FILE_RANGE: u64 = 277;
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
/// times(buf) - process times in clock ticks
pub const SYS_TIMES: u64 = 100;
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
/// pause()
pub const SYS_PAUSE: u64 = 34;

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

/// RFLAGS bits to clear on syscall entry (Linux syscall_init): the
/// arithmetic flags, TF, IF (on again once the entry has saved the user
/// state), DF (string instructions run forward), IOPL, NT, RF, AC (SMAP
/// stays in force) and ID
const SYSCALL_FLAG_MASK: u64 = 0x25_7fd5;

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
    let lstar = super::entry::syscall_entry as *const () as u64;

    // SFMASK: flags to clear on syscall
    let sfmask = SYSCALL_FLAG_MASK;

    unsafe {
        wrmsr(MSR_STAR, star);
        wrmsr(MSR_LSTAR, lstar);
        wrmsr(MSR_SFMASK, sfmask);
    }
}

use super::msr::{rdmsr, wrmsr};

// =============================================================================
// x86-64 syscall dispatcher
// =============================================================================

/// Dispatch syscall `num` with the argument registers
pub fn x86_64_syscall_dispatch(
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
        SYS_ACCESS => crate::fs::syscall::sys_access(args[0], args[1] as i32) as u64,
        SYS_ALARM => crate::time::posix_timer::sys_alarm(args[0] as u32) as u64,
        SYS_ARCH_PRCTL => crate::task::syscall::sys_arch_prctl(args[0] as i32, args[1]) as u64,
        SYS_CHMOD => crate::fs::syscall::sys_chmod(args[0], args[1] as u32) as u64,
        SYS_CHOWN => crate::fs::syscall::sys_chown(args[0], args[1] as u32, args[2] as u32) as u64,
        SYS_DUP2 => crate::fs::syscall::sys_dup2(args[0] as i32, args[1] as i32) as u64,
        SYS_EPOLL_CREATE => crate::io::epoll::sys_epoll_create(args[0] as i32) as u64,
        SYS_EPOLL_WAIT => crate::io::epoll::sys_epoll_wait(
            args[0] as i32,
            args[1],
            args[2] as i32,
            args[3] as i32,
        ) as u64,
        SYS_EVENTFD => crate::time::time_syscall::sys_eventfd(args[0] as u32) as u64,
        SYS_FORK => crate::task::syscall::sys_fork() as u64,
        SYS_GETDENTS => crate::fs::syscall::sys_getdents(args[0] as i32, args[1], args[2]) as u64,
        SYS_INOTIFY_INIT => crate::io::inotify::sys_inotify_init() as u64,
        SYS_IOPERM => crate::task::syscall::sys_ioperm(args[0], args[1], args[2] as i32) as u64,
        SYS_IOPL => crate::task::syscall::sys_iopl(args[0] as u32) as u64,
        SYS_LCHOWN => {
            crate::fs::syscall::sys_lchown(args[0], args[1] as u32, args[2] as u32) as u64
        }
        SYS_LINK => crate::fs::syscall::sys_link(args[0], args[1]) as u64,
        SYS_LSTAT => crate::fs::syscall::sys_lstat(args[0], args[1]) as u64,
        SYS_MKDIR => crate::fs::syscall::sys_mkdir(args[0], args[1] as u32) as u64,
        SYS_MKNOD => crate::fs::syscall::sys_mknod(args[0], args[1] as u32, args[2]) as u64,
        SYS_OPEN => crate::fs::syscall::sys_open(args[0], args[1] as u32, args[2] as u32) as u64,
        SYS_PAUSE => crate::signal::syscall::sys_pause() as u64,
        SYS_PIPE => crate::fs::syscall::sys_pipe(args[0]) as u64,
        SYS_POLL => crate::fs::syscall::sys_poll(args[0], args[1] as u32, args[2] as i32) as u64,
        SYS_READLINK => crate::fs::syscall::sys_readlink(args[0], args[1], args[2]) as u64,
        SYS_RENAME => crate::fs::syscall::sys_rename(args[0], args[1]) as u64,
        SYS_RMDIR => crate::fs::syscall::sys_rmdir(args[0]) as u64,
        SYS_RT_SIGRETURN => super::signal::sys_rt_sigreturn() as u64,
        SYS_SELECT => {
            crate::fs::syscall::sys_select(args[0] as i32, args[1], args[2], args[3], args[4])
                as u64
        }
        SYS_SIGNALFD => {
            crate::signal::syscall::sys_signalfd(args[0] as i32, args[1], args[2] as i32) as u64
        }
        SYS_STAT => crate::fs::syscall::sys_stat(args[0], args[1]) as u64,
        SYS_SYMLINK => crate::fs::syscall::sys_symlink(args[0], args[1]) as u64,
        SYS_TIME => crate::time::time_syscall::sys_time(args[0]) as u64,
        SYS_UNLINK => crate::fs::syscall::sys_unlink(args[0]) as u64,
        SYS_UTIME => crate::fs::syscall::sys_utime(args[0], args[1]) as u64,
        SYS_UTIMES => crate::fs::syscall::sys_utimes(args[0], args[1]) as u64,
        SYS_VFORK => crate::task::syscall::sys_vfork() as u64,
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
        SYS_NEWFSTATAT => Sys::Newfstatat,
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

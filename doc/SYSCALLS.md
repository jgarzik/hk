1. Process / thread / scheduling
1.1 Process creation & termination

- [x] fork (x86-64 only, legacy; use clone)
- [x] vfork (x86-64 only, legacy; use clone with CLONE_VFORK)
- [x] clone (Linux thread/process creation)
- [x] clone3
- [x] execve
- [x] execveat
- [x] _exit
- [x] exit_group
- [x] wait4
- [x] waitid

1.2 Process IDs & basic info

- [x] getpid
- [x] getppid
- [x] gettid
- [x] getpgid
- [x] setpgid
- [x] setsid
- [x] getsid

1.3 Scheduling, priorities, affinity

- [x] sched_yield
- [x] sched_getaffinity
- [x] sched_setaffinity
- [x] sched_getscheduler
- [x] sched_setscheduler
- [x] sched_getparam
- [x] sched_setparam
- [x] sched_rr_get_interval
- [x] getpriority
- [x] setpriority

1.4 Process resource limits & usage

- [x] getrlimit
- [x] setrlimit
- [x] prlimit64
- [x] getrusage

2. File descriptors & basic I/O

(Linux treats "everything as a file", so these are fundamental.)

2.1 FD lifecycle

- [x] open (x86-64 only, legacy; use openat)
- [x] openat
- [x] close
- [x] creat (x86-64 only, legacy; use openat with O_CREAT)
- [x] dup
- [x] dup2 (x86-64 only, legacy; use dup3)
- [x] dup3
- [x] fcntl (F_DUPFD, F_GETFD, F_SETFD, F_GETFL, F_SETFL, F_GETLK, F_SETLK, F_SETLKW)

2.2 Read/write + position

- [x] read
- [x] write
- [x] pread64
- [x] pwrite64
- [x] readv
- [x] writev
- [x] preadv
- [x] preadv2
- [x] pwritev
- [x] pwritev2
- [x] lseek
- [x] truncate (x86-64 only, legacy)
- [x] ftruncate (x86-64 only, legacy)

2.3 Special I/O helpers

- [x] sendfile (x86-64 only, legacy)
- [x] splice
- [x] tee
- [x] vmsplice
- [x] copy_file_range
- [x] ioctl (FIONBIO, FIOASYNC, FIOCLEX, FIONCLEX, FIONREAD, TIOCGWINSZ, terminal/tty, virtio-blk, xHCI USB)
- [x] sync
- [x] fsync
- [x] fdatasync
- [x] syncfs
- [x] sync_file_range (x86-64) / sync_file_range2 (aarch64; different arg order)
- [x] flock (advisory file locking)
- [x] fallocate (file space manipulation)

3. Filesystem / path / metadata
3.1 Paths & directory ops

- [x] mkdir (x86-64 only, legacy; use mkdirat)
- [x] mkdirat
- [x] rmdir (x86-64 only, legacy; use unlinkat with AT_REMOVEDIR)
- [x] link (x86-64 only, legacy; use linkat)
- [x] linkat
- [x] unlink (x86-64 only, legacy; use unlinkat)
- [x] unlinkat
- [x] rename (x86-64 only, legacy; use renameat2)
- [x] renameat (x86-64 only, legacy; use renameat2)
- [x] renameat2
- [x] symlink (x86-64 only, legacy; use symlinkat)
- [x] symlinkat
- [x] readlink (x86-64 only, legacy; use readlinkat)
- [x] readlinkat
- [x] mknod (x86-64 only, legacy; use mknodat)
- [x] mknodat
- [x] chdir
- [x] fchdir
- [x] getcwd
- [x] chroot

3.2 Stat & attributes

New kernels mostly use statx; older ones use stat/lstat/fstat.

- [x] stat (x86-64 only, legacy; use fstatat/statx)
- [x] lstat (x86-64 only, legacy; use fstatat/statx)
- [x] fstat (x86-64 only, legacy; use fstatat/statx)
- [x] newfstatat (fstatat on aarch64)
- [x] statfs (x86-64 only, legacy)
- [x] fstatfs (x86-64 only, legacy)
- [x] statx (modern richer interface)

Permissions and ownership:

- [x] access (x86-64 only, legacy; use faccessat)
- [x] faccessat
- [x] faccessat2
- [x] chmod (x86-64 only, legacy; use fchmodat)
- [x] fchmod
- [x] fchmodat
- [x] fchmodat2
- [x] chown (x86-64 only, legacy; use fchownat)
- [x] fchown
- [x] lchown (x86-64 only, legacy; use fchownat with AT_SYMLINK_NOFOLLOW)
- [x] fchownat
- [x] umask

Timestamps:

- [x] utime (x86-64 only, legacy; use utimensat)
- [x] utimes (x86-64 only, legacy; use utimensat)
- [x] utimensat

Extended attributes (Linux-specific):

- [x] getxattr
- [x] lgetxattr
- [x] fgetxattr
- [x] setxattr
- [x] lsetxattr
- [x] fsetxattr
- [x] listxattr
- [x] llistxattr
- [x] flistxattr
- [x] removexattr
- [x] lremovexattr
- [x] fremovexattr

3.3 Directory enumeration

- [x] getdents (x86-64 only, legacy; use getdents64)
- [x] getdents64

4. Memory management
4.1 Heap & anonymous mappings

- [x] brk
- [x] mmap
- [ ] mmap2 (32-bit variants)
- [x] munmap
- [x] mprotect
- [x] mremap
- [x] msync
- [x] mlock
- [x] munlock
- [x] mlockall
- [x] munlockall
- [x] mlock2
- [x] madvise
- [x] mincore
- [ ] remap_file_pages (legacy)

4.2 NUMA / memory policy (optional but Linuxy)

- [x] get_mempolicy
- [x] set_mempolicy
- [x] mbind
- [x] migrate_pages
- [x] move_pages

5. Signals

Linux has an "old" and a "rt_*" (real-time) signal set; modern userspace uses the rt_ syscalls.

- [x] rt_sigaction
- [x] rt_sigprocmask
- [x] rt_sigpending
- [x] rt_sigtimedwait
- [x] rt_sigqueueinfo
- [x] rt_sigsuspend
- [x] rt_tgsigqueueinfo
- [x] sigaltstack
- [x] signalfd (x86-64 only, legacy; use signalfd4)
- [x] signalfd4
- [x] tgkill (targeted kill by tid)
- [x] kill
- [x] tkill (legacy)

6. Time & timers
6.1 Basic time

- [x] time (x86-64 only, legacy; use clock_gettime)
- [x] gettimeofday
- [x] settimeofday
- [x] adjtimex (NTP)
- [x] clock_gettime
- [x] clock_settime
- [x] clock_getres
- [x] clock_nanosleep
- [x] nanosleep

6.2 POSIX timers

- [x] timer_create
- [x] timer_settime
- [x] timer_gettime
- [x] timer_getoverrun
- [x] timer_delete

6.3 Timer FDs

- [x] timerfd_create
- [x] timerfd_settime
- [x] timerfd_gettime

7. IPC: pipes, futex, SysV IPC, POSIX MQ, pidfd
7.1 Pipes & simple IPC

- [x] pipe (x86-64 only, legacy; use pipe2)
- [x] pipe2
- [x] eventfd (x86-64 only, legacy; use eventfd2)
- [x] eventfd2
- [x] pidfd_open
- [x] pidfd_send_signal
- [x] pidfd_getfd

7.2 Futex (core for modern libs/threads)

- [x] futex (WAIT, WAKE, WAIT_BITSET, WAKE_BITSET, REQUEUE, CMP_REQUEUE)
- [x] set_robust_list
- [x] get_robust_list
- [x] futex_waitv (newer multi-wait variant on some kernels)

7.3 SysV IPC

- [x] shmget
- [x] shmat
- [x] shmdt
- [x] shmctl
- [x] semget
- [x] semop
- [x] semtimedop
- [x] semctl
- [x] msgget
- [x] msgsnd
- [x] msgrcv
- [x] msgctl

7.4 POSIX message queues

- [x] mq_open
- [x] mq_unlink
- [x] mq_timedsend
- [x] mq_timedreceive
- [x] mq_notify
- [x] mq_getsetattr

8. Networking & sockets

Linux groups the socket syscalls as their own "network" category.

- [x] socket
- [x] socketpair
- [x] bind
- [x] listen
- [x] accept
- [x] accept4
- [x] connect
- [x] getsockname
- [x] getpeername
- [x] getsockopt (SO_REUSEADDR, SO_ERROR, SO_TYPE, SO_DOMAIN, SO_PROTOCOL, SO_BROADCAST, SO_DONTROUTE, SO_LINGER, SO_SNDBUF, SO_RCVBUF, SO_KEEPALIVE, TCP_NODELAY, TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT)
- [x] setsockopt (SO_REUSEADDR, SO_BROADCAST, SO_DONTROUTE, SO_LINGER, SO_SNDBUF, SO_RCVBUF, SO_KEEPALIVE, TCP_NODELAY, TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT)
- [x] sendto
- [x] recvfrom
- [x] sendmsg
- [x] recvmsg
- [x] sendmmsg
- [x] recvmmsg
- [x] shutdown

9. Polling & event notification
9.1 Select/poll/epoll

- [x] select (x86-64 only, legacy; use pselect6)
- [x] pselect6
- [x] poll (x86-64 only, legacy; use ppoll)
- [x] ppoll
- [x] epoll_create (x86-64 only, legacy; use epoll_create1)
- [x] epoll_create1
- [x] epoll_ctl
- [x] epoll_wait (x86-64 only, legacy; use epoll_pwait)
- [x] epoll_pwait
- [x] epoll_pwait2

9.2 Inotify & fanotify (fs events)

- [x] inotify_init (x86-64 only, legacy; use inotify_init1)
- [x] inotify_init1
- [x] inotify_add_watch
- [x] inotify_rm_watch
- [x] fanotify_init
- [x] fanotify_mark

9.3 io_uring (modern async I/O)

- [x] io_uring_setup
- [x] io_uring_enter
- [x] io_uring_register

10. Credentials, security, keyrings
10.1 UIDs / GIDs

- [x] getuid
- [x] geteuid
- [x] getgid
- [x] getegid
- [x] getresuid
- [x] getresgid
- [x] setuid
- [x] setgid
- [x] setreuid
- [x] setregid
- [x] setresuid
- [x] setresgid
- [x] setfsuid
- [x] setfsgid

10.2 Capabilities

- [x] capget
- [x] capset

10.3 Keyrings (Linux key management)

- [x] add_key
- [x] request_key
- [x] keyctl (GET_KEYRING_ID, UPDATE, REVOKE, CHOWN, SETPERM, DESCRIBE, CLEAR, LINK, UNLINK, SEARCH, READ, INVALIDATE)

10.4 Misc security / sandboxing

- [x] seccomp (SECCOMP_SET_MODE_STRICT, SECCOMP_SET_MODE_FILTER with eBPF support)
- [x] prctl (PR_SET/GET_NAME, PR_SET/GET_DUMPABLE, PR_SET/GET_NO_NEW_PRIVS, PR_SET/GET_TIMERSLACK, PR_SET/GET_SECCOMP, PR_SET/GET_KEEPCAPS, PR_SET/GET_CHILD_SUBREAPER, PR_SET/GET_THP_DISABLE, PR_SET/GET_TSC [x86-64], PR_SET/GET_CPUID [x86-64])
- [x] mlock / mlockall (already listed under memory)

11. Namespaces, containers, mounts, cgroups
11.1 Mounts & root

- [x] mount
- [x] umount (via umount2)
- [x] umount2
- [x] pivot_root
- [x] chroot

11.2 Namespaces

- [x] unshare
- [x] setns
- [x] clone with namespace flags

11.3 Host identity

- [x] sethostname
- [x] setdomainname

11.4 Cgroup-related (mostly FS-based in practice)

There are very few direct "cgroup_*" syscalls; the cgroup v1/v2 APIs are primarily via virtual filesystems (cgroupfs / cgroup2). You may opt to implement only the FS side at first.

12. System information & control

- [x] uname
- [x] sysinfo
- [x] getrandom
- [x] reboot
- [x] kexec_load (stub, returns -ENOSYS; requires CAP_SYS_BOOT)
- [x] syslog
- [x] acct
- [x] swapon
- [x] swapoff
- [x] getcpu

13. Debugging, perf, BPF

- [x] ptrace (TRACEME, ATTACH, SEIZE, DETACH, PEEKDATA, POKEDATA, GETREGS, SETREGS, CONT, SYSCALL, SINGLESTEP, KILL, SETOPTIONS, GETEVENTMSG)
- [x] perf_event_open (stub, returns -EOPNOTSUPP)
- [x] bpf (BPF_MAP_CREATE, BPF_MAP_LOOKUP/UPDATE/DELETE_ELEM, BPF_MAP_GET_NEXT_KEY, BPF_PROG_LOAD, BPF_OBJ_GET_INFO_BY_FD; map types: HASH, ARRAY; program type: SOCKET_FILTER)
- [x] membarrier
- [x] kcmp (compare processes)
- [x] process_vm_readv
- [x] process_vm_writev
- [x] rseq (stub, returns -ENOSYS)

14. Thread-local, arch-specific, misc

- [x] arch_prctl (x86-64 only; TLS, FS/GS base)
- [x] iopl (x86-64 only; I/O port privilege level)
- [x] ioperm (x86-64 only; returns ENOSYS - requires TSS I/O bitmap)
- [ ] modify_ldt (x86-64 only; LDT manipulation)

Misc utilities that don't fit elsewhere:

- [x] personality
- [x] vhangup
- [x] readahead
- [x] alarm (x86-64 only, legacy; use timer APIs)
- [x] pause (x86-64 only, legacy; use sigsuspend/ppoll)
- [x] getpgrp (x86-64 only, legacy; use getpgid(0))
- [x] ustat (x86-64 only, legacy; deprecated filesystem syscall)

15. "Probably later" / niche syscalls

When you get further along and want Linux feature-parity, you'll eventually look at:

- Key management and NUMA sets you skipped
- Crypto-related syscalls if they appear (most crypto is via /dev/* or libraries)
- Very new syscalls that might not yet be widely used in userland

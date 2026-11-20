1. Process / thread / scheduling
1.1 Process creation & termination

- [x] fork (x86-64 only, legacy)
- [x] vfork (x86-64 only, legacy)
- [x] clone (CLONE_PIDFD)
- [x] clone3 (set_tid, CLONE_INTO_CGROUP)
- [x] execve (ELF, #! scripts)
- [x] execveat (AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW)
- [x] _exit
- [x] set_tid_address
- [x] exit_group
- [x] wait4
- [x] waitid (P_PIDFD)

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
- [x] ioprio_get
- [x] ioprio_set

1.4 Process resource limits & usage

- [x] getrlimit
- [x] setrlimit
- [x] prlimit64
- [x] getrusage
- [x] times (children's times 0)

2. File descriptors & basic I/O
2.1 FD lifecycle

- [x] open (x86-64 only, legacy)
- [x] openat (O_TMPFILE, O_PATH, O_EMPTYPATH, O_DIRECT)
- [x] openat2 (all RESOLVE_* flags, OPENAT2_REGULAR)
- [x] close
- [x] close_range (UNSHARE, CLOEXEC)
- [ ] creat (x86-64 only, legacy)
- [x] dup
- [x] dup2 (x86-64 only, legacy)
- [x] dup3
- [x] fcntl (DUPFD, FD/FL flags, locks, OWN/SIG, seals, O_ASYNC, PIPE_SZ)

2.2 Read/write + position

- [x] read
- [x] write
- [x] pread64
- [x] pwrite64
- [x] readv
- [x] writev
- [x] preadv
- [x] preadv2 (RWF_NOWAIT on block devices)
- [x] pwritev
- [x] pwritev2 (RWF_DSYNC, RWF_SYNC, RWF_NOWAIT)
- [x] lseek
- [x] truncate
- [x] ftruncate

2.3 Special I/O helpers

- [x] sendfile
- [x] splice
- [x] tee
- [x] vmsplice
- [x] copy_file_range
- [x] ioctl (FIO*, tty, block, socket SIOC*, NS_*, xHCI USB)
- [x] sync
- [x] fsync
- [x] fdatasync
- [x] syncfs
- [x] sync_file_range
- [x] fadvise64 (aarch64: fadvise64_64)
- [x] flock
- [x] fallocate

3. Filesystem / path / metadata
3.1 Paths & directory ops

- [x] mkdir (x86-64 only, legacy)
- [x] mkdirat
- [x] rmdir (x86-64 only, legacy)
- [x] link (x86-64 only, legacy)
- [x] linkat (AT_SYMLINK_FOLLOW, AT_EMPTY_PATH)
- [x] unlink (x86-64 only, legacy)
- [x] unlinkat
- [x] rename (x86-64 only, legacy)
- [x] renameat (legacy)
- [x] renameat2 (NOREPLACE, EXCHANGE; no WHITEOUT)
- [x] symlink (x86-64 only, legacy)
- [x] symlinkat
- [x] readlink (x86-64 only, legacy)
- [x] readlinkat
- [x] mknod (x86-64 only, legacy)
- [x] mknodat
- [x] chdir
- [x] fchdir
- [x] getcwd
- [x] chroot
- [x] name_to_handle_at (no AT_HANDLE_CONNECTABLE)
- [x] open_by_handle_at

3.2 Stat & attributes

- [x] stat (x86-64 only, legacy)
- [x] lstat (x86-64 only, legacy)
- [x] fstat
- [x] newfstatat
- [x] statfs
- [x] fstatfs
- [x] statx (STATX_DIOALIGN)

Permissions and ownership:

- [x] access (x86-64 only, legacy)
- [x] faccessat
- [x] faccessat2
- [x] chmod (x86-64 only, legacy)
- [x] fchmod
- [x] fchmodat
- [x] fchmodat2
- [x] chown (x86-64 only, legacy)
- [x] fchown
- [x] lchown (x86-64 only, legacy)
- [x] fchownat
- [x] umask

Timestamps:

- [x] utime (x86-64 only, legacy)
- [x] utimes (x86-64 only, legacy)
- [x] utimensat

Extended attributes:

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

- [x] getdents (x86-64 only, legacy)
- [x] getdents64

4. Memory management
4.1 Heap & anonymous mappings

- [x] brk
- [x] mmap
- [ ] mmap2 (32-bit only)
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
- [x] memfd_create (sealing, NOEXEC_SEAL/EXEC; no MFD_HUGETLB)
- [ ] remap_file_pages (legacy)

4.2 NUMA / memory policy

- [x] get_mempolicy
- [x] set_mempolicy
- [x] mbind
- [x] migrate_pages
- [x] move_pages

5. Signals

- [x] rt_sigaction
- [x] rt_sigprocmask
- [x] rt_sigpending
- [x] rt_sigtimedwait
- [x] rt_sigqueueinfo
- [x] rt_sigsuspend
- [x] rt_sigreturn
- [x] rt_tgsigqueueinfo
- [x] sigaltstack
- [x] signalfd (x86-64 only, legacy)
- [x] signalfd4
- [x] tgkill
- [x] kill
- [x] tkill (legacy)

6. Time & timers
6.1 Basic time

- [x] time (x86-64 only, legacy)
- [x] gettimeofday
- [x] settimeofday
- [x] adjtimex
- [x] clock_gettime (all clocks, incl. CPU clocks)
- [x] clock_settime
- [x] clock_getres
- [x] clock_nanosleep (no thread CPU clocks)
- [x] nanosleep

6.2 POSIX timers

- [x] setitimer (REAL, VIRTUAL, PROF)
- [x] getitimer (REAL, VIRTUAL, PROF)
- [x] timer_create (incl. own process/thread CPU clocks)
- [x] timer_settime
- [x] timer_gettime
- [x] timer_getoverrun
- [x] timer_delete

6.3 Timer FDs

- [x] timerfd_create (realtime, monotonic, boottime, alarms)
- [x] timerfd_settime
- [x] timerfd_gettime

7. IPC: pipes, futex, SysV IPC, POSIX MQ, pidfd
7.1 Pipes & simple IPC

- [x] pipe (x86-64 only, legacy)
- [x] pipe2 (O_CLOEXEC, O_NONBLOCK, O_DIRECT)
- [x] eventfd (x86-64 only, legacy)
- [x] eventfd2
- [x] pidfd_open (PIDFD_NONBLOCK, PIDFD_THREAD)
- [x] pidfd_send_signal (no PIDFD_SELF_*)
- [x] pidfd_getfd

7.2 Futex

- [x] futex (WAIT, WAKE, *_BITSET, REQUEUE, CMP_REQUEUE)
- [x] set_robust_list
- [x] get_robust_list
- [x] futex_waitv

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

- [x] socket (AF_INET, AF_UNIX, AF_NETLINK, AF_PACKET; no AF_INET6)
- [x] socketpair (AF_UNIX)
- [x] bind
- [x] listen
- [x] accept
- [x] accept4 (SOCK_NONBLOCK, SOCK_CLOEXEC)
- [x] connect
- [x] getsockname
- [x] getpeername
- [x] getsockopt / setsockopt (SOL_SOCKET, SOL_IP, IPPROTO_TCP, SOL_NETLINK, SOL_PACKET subsets)
- [x] sendto
- [x] recvfrom
- [x] sendmsg
- [x] recvmsg (MSG_PEEK, MSG_TRUNC, MSG_WAITALL, MSG_ERRQUEUE)
- [x] sendmmsg
- [x] recvmmsg
- [x] shutdown

9. Polling & event notification
9.1 Select/poll/epoll

- [x] select (x86-64 only, legacy)
- [x] pselect6
- [x] poll (x86-64 only, legacy)
- [x] ppoll
- [x] epoll_create (x86-64 only, legacy)
- [x] epoll_create1
- [x] epoll_ctl
- [x] epoll_wait (x86-64 only, legacy)
- [x] epoll_pwait
- [x] epoll_pwait2

9.2 Inotify & fanotify

- [x] inotify_init (x86-64 only, legacy)
- [x] inotify_init1
- [x] inotify_add_watch (few events delivered)
- [x] inotify_rm_watch
- [x] fanotify_init
- [x] fanotify_mark

9.3 Linux native AIO and io_uring

- [x] io_setup
- [x] io_destroy
- [x] io_submit (PREAD(V), PWRITE(V), FSYNC, FDSYNC, POLL)
- [x] io_cancel (POLL only)
- [x] io_getevents
- [x] io_pgetevents

- [x] io_uring_setup (CQSIZE, CLAMP, IOPOLL; no SQPOLL)
- [x] io_uring_enter (GETEVENTS, EXT_ARG)
- [x] io_uring_register (FILES, BUFFERS)

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
- [x] getgroups
- [x] setgroups
- [x] setfsuid
- [x] setfsgid

10.2 Capabilities

- [x] capget
- [x] capset

10.3 Keyrings

- [x] add_key
- [x] request_key
- [x] keyctl (subset)

10.4 Misc security / sandboxing

- [x] seccomp (STRICT, FILTER; no TRACE, USER_NOTIF)
- [x] prctl (subset)

11. Namespaces, containers, mounts, cgroups
11.1 Mounts & root

- [x] mount
- [x] umount (via umount2)
- [x] umount2
- [x] pivot_root
- [x] chroot

11.2 Namespaces

- [x] unshare
- [x] setns (namespace file or pidfd)
- [x] listns
- [x] clone with namespace flags

11.3 Host identity

- [x] sethostname
- [x] setdomainname

12. System information & control

- [x] uname
- [x] sysinfo
- [x] getrandom
- [x] reboot (CAD_ON/CAD_OFF, RESTART2)
- [x] kexec_load (stub: ENOSYS)
- [x] syslog (console actions no-ops)
- [x] acct
- [x] swapon
- [x] swapoff
- [x] getcpu

13. Debugging, perf, BPF

- [x] ptrace (subset)
- [x] perf_event_open (stub: EOPNOTSUPP)
- [x] bpf (HASH/ARRAY maps, SOCKET_FILTER; not attachable)
- [x] membarrier
- [x] kcmp
- [x] process_vm_readv
- [x] process_vm_writev
- [x] rseq (stub: ENOSYS)

14. Thread-local, arch-specific, misc

- [x] arch_prctl (x86-64 only; FS/GS base, CPUID; no CPUID faulting)
- [x] iopl (x86-64 only)
- [x] ioperm (x86-64 only; ENOSYS)
- [ ] modify_ldt (x86-64 only)

Misc:

- [x] personality
- [x] vhangup
- [x] readahead
- [x] alarm (x86-64 only, legacy)
- [x] pause (x86-64 only, legacy)
- [ ] getpgrp (x86-64 only, legacy)
- [ ] ustat (x86-64 only, legacy)

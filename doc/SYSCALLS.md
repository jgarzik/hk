1. Process / thread / scheduling
1.1 Process creation & termination

- [x] fork

- [x] vfork

- [x] clone / clone3 (Linux thread/process creation)

- [x] execve

- [x] execveat

- [x] _exit

- [x] exit_group

- [x] wait4

- [x] waitid

- [ ] waitpid (on some architectures; often a libc wrapper around wait4/waitid)

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

- [x] nice (usually via setpriority)

- [x] getpriority

- [x] setpriority

1.4 Process resource limits & usage

- [x] getrlimit

- [x] setrlimit

- [x] prlimit64

- [x] getrusage

2. File descriptors & basic I/O

(Linux treats “everything as a file”, so these are fundamental.)
linasm.sourceforge.net

2.1 FD lifecycle

- [x] open

- [x] openat

- [x] close

- [x] creat (via open with O_CREAT)

- [x] dup

- [x] dup2

- [x] dup3

- [x] fcntl

2.2 Read/write + position

- [x] read

- [x] write

- [x] pread64

- [x] pwrite64

- [x] readv

- [x] writev

- [x] preadv

- [ ] preadv2

- [x] pwritev

- [ ] pwritev2

- [x] lseek

- [x] truncate

- [x] ftruncate

2.3 Special I/O helpers

- [ ] sendfile

- [ ] splice

- [ ] tee

- [ ] vmsplice

- [ ] ioctl

- [x] sync

- [x] fsync

- [x] fdatasync

- [x] syncfs

3. Filesystem / path / metadata
3.1 Paths & directory ops

- [x] mkdir

- [x] mkdirat

- [x] rmdir

- [x] link

- [x] linkat

- [x] unlink

- [x] unlinkat

- [x] rename

- [x] renameat

- [x] renameat2

- [x] symlink

- [x] symlinkat

- [x] readlink

- [x] readlinkat

- [x] mknod

- [x] mknodat

- [x] chdir

- [x] fchdir

- [x] getcwd

- [ ] chroot

3.2 Stat & attributes

New kernels mostly use statx; older ones use stat/lstat/fstat.
man7.org

- [x] stat

- [x] lstat

- [x] fstat

- [ ] newfstatat / fstatat64

- [ ] statfs

- [ ] fstatfs

- [ ] statx (modern richer interface)

Permissions and ownership:

- [x] access

- [x] faccessat

- [x] faccessat2

- [x] chmod

- [x] fchmod

- [x] fchmodat

- [ ] fchmodat2

- [x] chown

- [x] fchown

- [x] lchown

- [x] fchownat

- [x] umask

Timestamps:

- [x] utime

- [x] utimes

- [x] utimensat

Extended attributes (Linux-specific):

- [ ] getxattr

- [ ] lgetxattr

- [ ] fgetxattr

- [ ] setxattr

- [ ] lsetxattr

- [ ] fsetxattr

- [ ] listxattr

- [ ] llistxattr

- [ ] flistxattr

- [ ] removexattr

- [ ] lremovexattr

- [ ] fremovexattr

3.3 Directory enumeration

- [ ] getdents

- [x] getdents64

4. Memory management
4.1 Heap & anonymous mappings

- [x] brk

- [x] mmap

- [ ] mmap2 (32-bit variants)

- [x] munmap

- [ ] mprotect

- [ ] mremap

- [ ] msync

- [x] mlock

- [x] munlock

- [x] mlockall

- [x] munlockall

- [ ] mincore

- [ ] madvise

- [ ] remap_file_pages (legacy)

4.2 NUMA / memory policy (optional but Linuxy)
linasm.sourceforge.net

- [ ] get_mempolicy

- [ ] set_mempolicy

- [ ] mbind

- [ ] migrate_pages

- [ ] move_pages

5. Signals

Linux has an "old" and a "rt_*" (real-time) signal set; modern userspace uses the rt_ syscalls.
linasm.sourceforge.net

- [x] rt_sigaction

- [x] rt_sigprocmask

- [x] rt_sigpending

- [ ] rt_sigtimedwait

- [ ] rt_sigqueueinfo

- [ ] rt_sigsuspend

- [ ] sigaltstack

- [ ] signalfd

- [ ] signalfd4

- [x] tgkill (targeted kill by tid)

- [x] kill

- [x] tkill (legacy)

6. Time & timers
6.1 Basic time

- [x] time

- [x] gettimeofday

- [ ] settimeofday

- [ ] adjtimex

- [x] clock_gettime

- [ ] clock_settime

- [x] clock_getres

- [x] clock_nanosleep

- [x] nanosleep

6.2 POSIX timers

- [ ] timer_create

- [ ] timer_settime

- [ ] timer_gettime

- [ ] timer_getoverrun

- [ ] timer_delete

6.3 Timer FDs

- [ ] timerfd_create

- [ ] timerfd_settime

- [ ] timerfd_gettime

7. IPC: pipes, futex, SysV IPC, POSIX MQ
7.1 Pipes & simple IPC

- [x] pipe

- [x] pipe2

- [ ] eventfd

- [ ] eventfd2

- [ ] eventfd2 (flags)

7.2 Futex (core for modern libs/threads)

- [x] futex (WAIT, WAKE, WAIT_BITSET, WAKE_BITSET, REQUEUE, CMP_REQUEUE)

- [x] set_robust_list

- [x] get_robust_list

- [ ] futex_waitv (newer multi-wait variant on some kernels)

7.3 SysV IPC

- [ ] shmget

- [ ] shmat

- [ ] shmdt

- [ ] shmctl

- [ ] semget

- [ ] semop

- [ ] semtimedop

- [ ] semctl

- [ ] msgget

- [ ] msgsnd

- [ ] msgrcv

- [ ] msgctl

7.4 POSIX message queues

- [ ] mq_open

- [ ] mq_unlink

- [ ] mq_timedsend

- [ ] mq_timedreceive

- [ ] mq_notify

- [ ] mq_getsetattr

8. Networking & sockets

Linux groups the socket syscalls as their own “network” category.
linasm.sourceforge.net

- [ ] socket

- [ ] socketpair

- [ ] bind

- [ ] listen

- [ ] accept

- [ ] accept4

- [ ] connect

- [ ] getsockname

- [ ] getpeername

- [ ] getsockopt

- [ ] setsockopt

- [ ] sendto

- [ ] recvfrom

- [ ] sendmsg

- [ ] recvmsg

- [ ] sendmmsg

- [ ] recvmmsg

- [ ] shutdown

Ancillary:

- [ ] recvmmsg

- [ ] sendmmsg

- [ ] getsockopt

- [ ] setsockopt

9. Polling & event notification
9.1 Select/poll/epoll

- [x] select

- [x] pselect6

- [x] poll

- [x] ppoll

- [ ] epoll_create

- [ ] epoll_create1

- [ ] epoll_ctl

- [ ] epoll_wait

- [ ] epoll_pwait

- [ ] epoll_pwait2 (newer)

9.2 Inotify & fanotify (fs events)

- [ ] inotify_init

- [ ] inotify_init1

- [ ] inotify_add_watch

- [ ] inotify_rm_watch

- [ ] fanotify_init

- [ ] fanotify_mark

9.3 io_uring (optional but modern)

- [ ] io_uring_setup

- [ ] io_uring_enter

- [ ] io_uring_register

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

- [ ] capget

- [ ] capset

10.3 Keyrings (Linux key management)
linasm.sourceforge.net

- [ ] add_key

- [ ] request_key

- [ ] keyctl

10.4 Misc security / sandboxing

- [ ] seccomp

- [ ] prctl (lots of knobs: dumpable, NO_NEW_PRIVS, etc.)

- [x] mlock / mlockall (already listed under memory)

- [ ] settimeofday / adjtimex (privileged)

11. Namespaces, containers, mounts, cgroups
11.1 Mounts & root

- [x] mount

- [x] umount (via umount2)

- [x] umount2

- [ ] pivot_root

- [ ] chroot (legacy but used)

11.2 Namespaces

- [x] unshare
- [x] setns
- [x] clone / clone3 with namespace flags

11.3 Host identity

- [x] sethostname

- [x] setdomainname

11.4 Cgroup-related (mostly FS-based in practice)

There are very few direct “cgroup_*” syscalls; the cgroup v1/v2 APIs are primarily via virtual filesystems (cgroupfs / cgroup2). You may opt to implement only the FS side at first.

12. System information & control

- [x] uname

- [x] sysinfo

- [x] getrandom

- [x] reboot

- [ ] kexec_load

- [ ] syslog

- [ ] acct

- [ ] swapon

- [ ] swapoff

- [ ] sysfs (legacy)

- [x] getcpu

- [ ] getpid / getppid (already listed)

- [ ] gettimeofday (already listed)

13. Debugging, perf, BPF

- [ ] ptrace

- [ ] perf_event_open

- [ ] bpf

- [ ] membarrier

- [ ] kcmp (compare processes)

- [ ] rseq (restartable sequences)

14. Thread-local, arch-specific, misc

- [ ] arch_prctl (TLS, FS/GS base on x86-64)

- [ ] set_thread_area / get_thread_area (32-bit oriented)

- [ ] get_thread_area (arch-specific)

Misc utilities that don’t fit elsewhere:

- [ ] getpgid / setpgid (already listed)

- [ ] personality

- [x] umount / umount2 (already listed)

- [ ] vhangup

- [ ] readahead

- [ ] sysfs (legacy)

 fanotify_* (already listed)

 landlock_add_rule, landlock_restrict_self (if you want Landlock later)

15. “Probably later” / niche syscalls

When you get further along and want Linux feature-parity, you’ll eventually look at:

Key management and NUMA sets you skipped

Crypto-related syscalls if they appear (most crypto is via /dev/* or libraries)

Very new syscalls that might not yet be widely used in userland


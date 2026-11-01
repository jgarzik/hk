1. Process / thread / scheduling
1.1 Process creation & termination

- [x] fork (x86-64 only, legacy; use clone)
- [x] vfork (x86-64 only, legacy; use clone with CLONE_VFORK)
- [x] clone (Linux thread/process creation)
- [x] clone3
- [x] execve
- [x] execveat (dirfd, AT_EMPTY_PATH for fexecve, AT_SYMLINK_NOFOLLOW)
- [x] _exit
- [x] set_tid_address
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
- [x] ioprio_get
- [x] ioprio_set

1.4 Process resource limits & usage

- [x] getrlimit
- [x] setrlimit
- [x] prlimit64
- [x] getrusage
- [x] times (children's times not tracked: 0)

2. File descriptors & basic I/O

(Linux treats "everything as a file", so these are fundamental.)

2.1 FD lifecycle

- [x] open (x86-64 only, legacy; use openat)
- [x] openat
- [x] close
- [x] close_range (CLOSE_RANGE_UNSHARE, CLOSE_RANGE_CLOEXEC)
- [ ] creat (x86-64 only, legacy; use openat with O_CREAT)
- [x] dup
- [x] dup2 (x86-64 only, legacy; use dup3)
- [x] dup3
- [x] fcntl (F_DUPFD, F_DUPFD_CLOEXEC, F_GETFD, F_SETFD, F_GETFL, F_SETFL, F_GETLK, F_SETLK, F_SETLKW, F_GETOWN, F_SETOWN, F_GETSIG, F_SETSIG)

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
- [x] truncate
- [x] ftruncate

2.3 Special I/O helpers

- [x] sendfile
- [x] splice
- [x] tee
- [x] vmsplice
- [x] copy_file_range
- [x] ioctl (FIONBIO, FIOASYNC, FIOCLEX, FIONCLEX, FIONREAD, TIOCGWINSZ, terminal/tty, xHCI USB; block devices: BLKGETSIZE, BLKGETSIZE64, BLKSSZGET, BLKPBSZGET, BLKBSZGET, BLKBSZSET, BLKROGET, BLKRRPART, BLKFLSBUF; sockets: FIONREAD/SIOCINQ, SIOCOUTQ, FIOSETOWN/SIOCSPGRP, FIOGETOWN/SIOCGPGRP, SIOCGIFCONF, SIOCGIFINDEX, SIOCGIFNAME, SIOC[GS]IFFLAGS, SIOC[GS]IFADDR, SIOC[GS]IFNETMASK, SIOC[GS]IFBRDADDR, SIOCGIFHWADDR, SIOC[GS]IFMTU, SIOCADDRT, SIOCDELRT)
- [x] sync
- [x] fsync
- [x] fdatasync
- [x] syncfs
- [ ] sync_file_range (x86-64) / sync_file_range2 (aarch64; different arg order)
- [x] flock (advisory file locking)
- [x] fallocate (file space manipulation)

3. Filesystem / path / metadata
3.1 Paths & directory ops

- [x] mkdir (x86-64 only, legacy; use mkdirat)
- [x] mkdirat
- [x] rmdir (x86-64 only, legacy; use unlinkat with AT_REMOVEDIR)
- [x] link (x86-64 only, legacy; use linkat)
- [x] linkat (AT_SYMLINK_FOLLOW; AT_EMPTY_PATH needs CAP_DAC_READ_SEARCH)
- [x] unlink (x86-64 only, legacy; use unlinkat)
- [x] unlinkat
- [x] rename (x86-64 only, legacy; use renameat2)
- [x] renameat (legacy; use renameat2; arm64 keeps it, number 38)
- [x] renameat2 (RENAME_NOREPLACE, RENAME_EXCHANGE; RENAME_WHITEOUT is
  EINVAL: no file system makes whiteouts yet; vfat lacks EXCHANGE)
- [x] symlink (x86-64 only, legacy; use symlinkat)
- [x] symlinkat
- [x] readlink (x86-64 only, legacy; use readlinkat)
- [x] readlinkat
- [x] mknod (x86-64 only, legacy; use mknodat)
- [x] mknodat (S_IFSOCK makes a socket inode; FIFOs are created as
  regular files for now)
- [x] chdir
- [x] fchdir
- [x] getcwd
- [x] chroot

3.2 Stat & attributes

New kernels mostly use statx; older ones use stat/lstat/fstat.

- [x] stat (x86-64 only, legacy; use fstatat/statx)
- [x] lstat (x86-64 only, legacy; use fstatat/statx)
- [x] fstat (x86-64 and arm64: __NR3264_fstat 80)
- [x] newfstatat (fstatat on aarch64)
- [x] statfs
- [x] fstatfs
- [x] statx (modern richer interface)

Permissions and ownership:

- [x] access (x86-64 only, legacy; use faccessat)
- [x] faccessat (no flags argument; flags need faccessat2)
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
- [x] rt_sigreturn
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
- [x] clock_gettime (realtime, monotonic, raw, coarse, boottime, TAI, alarms, process/thread and per-pid CPU clocks)
- [x] clock_settime
- [x] clock_getres (1ns, a tick for coarse and PROF/VIRT CPU clocks)
- [x] clock_nanosleep (realtime, monotonic, boottime, TAI, alarms; raw/coarse EOPNOTSUPP; CPU clocks not yet)
- [x] nanosleep

6.2 POSIX timers

- [x] setitimer (ITIMER_REAL; ITIMER_VIRTUAL/PROF → EINVAL, BUGS.md)
- [x] getitimer (ITIMER_REAL)
- [x] timer_create (realtime, monotonic, boottime, alarms; TAI and CPU clocks not yet)
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

Families: AF_INET (SOCK_STREAM/TCP, SOCK_DGRAM/UDP) and AF_NETLINK
(SOCK_RAW/SOCK_DGRAM, NETLINK_ROUTE: links, IPv4 addresses and routes,
neighbours; SOL_NETLINK options ADD/DROP_MEMBERSHIP, PKTINFO, NO_ENOBUFS,
CAP_ACK, EXT_ACK, GET_STRICT_CHK, LIST_MEMBERSHIPS), AF_UNIX
(SOCK_STREAM, SOCK_DGRAM (SOCK_RAW is an alias), SOCK_SEQPACKET),
AF_PACKET (SOCK_RAW, SOCK_DGRAM). AF_INET6 is EAFNOSUPPORT for now.

Sockets are sockfs inodes (fstat S_IFSOCK, /proc/<pid>/fd -> socket:[N]).
Blocking follows the file's O_NONBLOCK at every call (fcntl, FIONBIO)
and MSG_DONTWAIT; SO_RCVTIMEO/SO_SNDTIMEO time out with EAGAIN; signals
restart per SA_RESTART unless a socket timeout is set (EINTR). EPIPE
raises SIGPIPE unless MSG_NOSIGNAL. Unknown options are ENOPROTOOPT
(EOPNOTSUPP for getsockopt at unknown levels, like Linux).

TCP (RFC 9293): all eleven states, RFC 5961 checks, retransmission with
RFC 6298 RTO (1 s initial, 200 ms - 120 s, Karn, backoff), MSS option
(536 if absent, PMTU from ICMP frag needed), RFC 6528 ISNs, TIME_WAIT
60 s (entries re-ACK a retransmitted FIN; SO_REUSEADDR rebinds; a SYN
with a newer timestamp reopens), half-close, RST on close with unread
data and with SO_LINGER {1, 0}, SO_LINGER timeouts on close, ICMP errors
(hard in SYN_SENT, soft otherwise, SO_ERROR on timeout). RFC 7323 window
scaling (scale from tcp_rmem[2], or the buffer when SO_RCVBUF is set)
and timestamps (ms clock with a keyed per-connection offset; RTT from
every echo; PAWS with Linux's RST and disordered-ACK exceptions).
Congestion control: Reno/NewReno behind a pluggable interface (only
"reno"; CUBIC is not implemented), RFC 6928 initial window, byte-counted
slow start / congestion avoidance growing only while cwnd-limited,
restart after idle. Delayed ACKs (40 ms ATO, quickack at start, ACK
every second full segment when the reader keeps up, interactive
pingpong mode), Nagle (Minshall), TCP_CORK and MSG_MORE (200 ms
ceiling), zero-window probes, keepalive, TCP_USER_TIMEOUT. Sysctls:
tcp_syn_retries, tcp_synack_retries, tcp_retries2, tcp_fin_timeout,
tcp_window_scaling, tcp_timestamps, tcp_rmem, tcp_keepalive_time/intvl/
probes, tcp_congestion_control, tcp_available_congestion_control.
/proc/net/tcp lists listeners, connections and TIME_WAIT entries. Not
yet: SACK (never advertised), receive buffer autotuning, the per-netns
challenge-ACK budget (out-of-window and challenge ACKs are limited per
connection to one per 500 ms like tcp_invalid_ratelimit); listeners keep full child sockets in SYN_RECEIVED
(no SYN cookies).

- [x] socket (AF_INET: TCP, UDP, ping SOCK_DGRAM/IPPROTO_ICMP gated by
  ping_group_range, SOCK_RAW with CAP_NET_RAW: IP_HDRINCL, SOL_RAW
  ICMP_FILTER; AF_NETLINK; AF_PACKET with CAP_NET_RAW)
- [x] socketpair (AF_UNIX all types, peer credentials of the creator;
  AF_INET/AF_NETLINK: EOPNOTSUPP like Linux)
- [x] bind (SO_REUSEADDR/SO_REUSEPORT rules, EADDRNOTAVAIL, EACCES < 1024)
- [x] listen (autobinds; backlog capped at somaxconn 4096; at most
  backlog + 1 connections wait for accept, later SYNs are dropped)
- [x] accept
- [x] accept4 (SOCK_NONBLOCK, SOCK_CLOEXEC)
- [x] connect (UDP: route + autobind, AF_UNSPEC disconnects; TCP:
  EINPROGRESS/EALREADY/EISCONN, ECONNREFUSED, ETIMEDOUT, EHOSTUNREACH;
  ephemeral ports shared by different four-tuples like Linux; AF_UNSPEC
  disconnects)
- [x] getsockname
- [x] getpeername
- [x] getsockopt / setsockopt: SOL_SOCKET (SO_TYPE, SO_DOMAIN,
  SO_PROTOCOL, SO_ERROR, SO_ACCEPTCONN, SO_REUSEADDR, SO_REUSEPORT,
  SO_KEEPALIVE, SO_BROADCAST, SO_DONTROUTE, SO_OOBINLINE, SO_LINGER,
  SO_SNDBUF/RCVBUF (+FORCE), SO_RCVLOWAT, SO_SNDLOWAT, SO_RCVTIMEO,
  SO_SNDTIMEO, SO_BINDTODEVICE, SO_BINDTOIFINDEX, SO_PRIORITY, SO_MARK,
  SO_TIMESTAMP, SO_TIMESTAMPNS, SO_RXQ_OVFL, SO_PASSCRED, SO_PEERCRED,
  SO_COOKIE, SO_DEBUG), SOL_IP (IP_TOS, IP_TTL, IP_PKTINFO, IP_RECVTTL,
  IP_RECVTOS, IP_RECVERR, IP_MTU_DISCOVER (DONT/WANT fragment, DO/PROBE
  EMSGSIZE), IP_MTU, IP_FREEBIND,
  IP_BIND_ADDRESS_NO_PORT, IP_MULTICAST_TTL/LOOP), IPPROTO_TCP
  (TCP_NODELAY, TCP_MAXSEG, TCP_CORK, TCP_KEEPIDLE, TCP_KEEPINTVL,
  TCP_KEEPCNT, TCP_SYNCNT, TCP_QUICKACK, TCP_USER_TIMEOUT, TCP_INFO
  (struct tcp_info, 280 bytes), TCP_CONGESTION ("reno"; others ENOENT),
  TCP_NOTSENT_LOWAT; TCP_DEFER_ACCEPT and TCP_FASTOPEN are accepted and
  read back but have no effect)
- [x] sendto
- [x] recvfrom
- [x] sendmsg (IP_PKTINFO/IP_TTL/IP_TOS control messages)
- [x] recvmsg (MSG_PEEK, MSG_TRUNC, MSG_WAITALL, MSG_ERRQUEUE: ICMP and
  local errors queued with IP_RECVERR, sock_extended_err + offender in
  an IP_RECVERR cmsg; IP_PKTINFO, IP_TTL, IP_TOS, SCM_TIMESTAMP(NS),
  SO_RXQ_OVFL control messages)
- [x] sendmmsg
- [x] recvmmsg (MSG_WAITFORONE, timeout)
- [x] shutdown (ENOTCONN when not connected; TCP SHUT_WR sends a FIN
  and keeps receiving; AF_UNIX mirrors it onto a stream/seqpacket peer)

AF_UNIX (Linux af_unix.c): filesystem names create an S_IFSOCK inode
(umask, DAC on the directory; EADDRINUSE if it exists; connect needs
write permission on it; unlink does not unbind), abstract names
(sun_path[0] == 0) per network namespace and socket type, autobind
("\0" + 5 hex digits) on bind with only the family or on connect/send
with SO_PASSCRED; Linux name lengths (unnamed = 2). Streams: listen
backlog (full: blocks, or EAGAIN), connect completes before accept,
reads join messages but stop after one carrying files (and, with
SO_PASSCRED, at a change of sender), SO_SNDBUF bounds what a writer has
queued, EPIPE + SIGPIPE, ECONNRESET when the peer closed with unread
data. Datagrams: boundaries, MSG_TRUNC, net.unix.max_dgram_qlen (10)
for senders the receiver is not connected back to (blocks, EAGAIN, no
POLLOUT until room), EPERM from a socket connected elsewhere,
ECONNREFUSED once when a connected peer closed. SEQPACKET: boundaries,
EOF after the peer closes, EPIPE without SIGPIPE. Ancillary data:
SCM_RIGHTS (up to 253 files per message, MSG_CTRUNC and the extra files
closed when the control buffer is short, MSG_CMSG_CLOEXEC, MSG_PEEK
duplicates), SCM_CREDENTIALS with SO_PASSCRED (senders may only claim
their own pid and ids without CAP_SYS_ADMIN/CAP_SETUID/CAP_SETGID),
SO_PEERCRED. In-flight files are capped per user near RLIMIT_NOFILE
(ETOOMANYREFS). FIONREAD/SIOCINQ/SIOCOUTQ; /proc/net/unix. Not yet:
MSG_OOB, garbage collection of unreachable in-flight sockets (the cap
bounds them), SO_PEEK_OFF, SO_PASSPIDFD/SCM_PIDFD, SO_PEERGROUPS,
SO_INQ, SIOCUNIXFILE.

AF_PACKET (Linux af_packet.c): CAP_NET_RAW (EPERM), SOCK_RAW (frames
from the link-layer header) and SOCK_DGRAM (from the network header);
the protocol (network order ETH_P_ALL or an EtherType) from socket() or
bind(sockaddr_ll: ifindex, protocol; ENODEV, ENETDOWN on the socket for
a down device). ETH_P_ALL sockets see received frames and every
transmitted one as PACKET_OUTGOING (not their own); protocol sockets
see received frames of their EtherType. recvfrom fills sockaddr_ll
(protocol, ifindex, hatype, pkttype HOST/BROADCAST/MULTICAST/OTHERHOST/
OUTGOING, source hardware address); MSG_TRUNC; SIOCINQ. Sends: SOCK_RAW
a whole frame (EINVAL below the link header, EMSGSIZE above MTU + header
unless VLAN-tagged), SOCK_DGRAM gets a header from sll_addr/
sll_protocol (EINVAL without a destination, except on lo); ENXIO
without a device, ENETDOWN when it is down. Works on interfaces without
IP addresses. Queues are bounded by SO_RCVBUF; PACKET_STATISTICS,
PACKET_AUXDATA (struct tpacket_auxdata cmsg), PACKET_ORIGDEV,
PACKET_IGNORE_OUTGOING, PACKET_ADD/DROP_MEMBERSHIP (PROMISC/ALLMULTI
counted on the device; MULTICAST/UNICAST accepted). Classic BPF socket
filters: SO_ATTACH_FILTER (Linux validation: known opcodes, forward
jumps only, scratch memory stored before loaded, no division by a zero
constant, RET last; SKF_AD_* ancillary, SKF_NET_OFF/SKF_LL_OFF loads),
SO_DETACH_FILTER (ENOENT), SO_LOCK_FILTER (EPERM). /proc/net/packet.
Not yet: SOCK_PACKET (ESOCKTNOSUPPORT), PACKET_RX_RING/TX_RING/mmap,
PACKET_FANOUT, PACKET_VERSION/VNET_HDR/QDISC_BYPASS and other options
(ENOPROTOOPT), SO_ATTACH_BPF, SO_GET_FILTER, socket filters on other
families (ENOPROTOOPT), ENETDOWN on bound sockets when their device
goes down later.

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
- [x] getgroups
- [x] setgroups (CAP_SETGID; sorted, shared per credential set)
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

- [x] seccomp (SECCOMP_SET_MODE_STRICT, SECCOMP_SET_MODE_FILTER (classic BPF, run as eBPF), SECCOMP_GET_ACTION_AVAIL)
- [x] prctl (PR_SET/GET_NAME, PR_SET/GET_PDEATHSIG, PR_SET/GET_DUMPABLE, PR_SET/GET_NO_NEW_PRIVS, PR_SET/GET_TIMERSLACK, PR_SET/GET_SECCOMP, PR_SET/GET_KEEPCAPS, PR_SET/GET_CHILD_SUBREAPER, PR_SET/GET_THP_DISABLE, PR_SET/GET_TSC [x86-64])
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
- [x] getrandom (ChaCha20 CRNG, up to MAX_RW_COUNT per call)
- [x] reboot
- [x] kexec_load (stub, returns -ENOSYS; requires CAP_SYS_BOOT)
- [x] syslog (READ, READ_ALL, READ_CLEAR, CLEAR, SIZE_UNREAD, SIZE_BUFFER over the record log; console actions no-ops; CAP_SYSLOG for all, as with dmesg_restrict=1)
- [x] acct
- [x] swapon
- [x] swapoff
- [x] getcpu

13. Debugging, perf, BPF

- [x] ptrace (TRACEME, ATTACH, SEIZE, DETACH, PEEKTEXT/PEEKDATA, POKETEXT/POKEDATA, GETREGS, SETREGS, CONT, SYSCALL, SINGLESTEP, KILL, SETOPTIONS, GETEVENTMSG)
- [x] perf_event_open (stub, returns -EOPNOTSUPP)
- [x] bpf (BPF_MAP_CREATE, BPF_MAP_LOOKUP/UPDATE/DELETE_ELEM, BPF_MAP_GET_NEXT_KEY, BPF_PROG_LOAD, BPF_OBJ_GET_INFO_BY_FD; map types: HASH, ARRAY; program type: SOCKET_FILTER)
- [x] membarrier
- [x] kcmp (compare processes)
- [x] process_vm_readv
- [x] process_vm_writev
- [x] rseq (stub, returns -ENOSYS)

14. Thread-local, arch-specific, misc

- [x] arch_prctl (x86-64 only; TLS, FS/GS base [ARCH_SET/GET_GS: the user GS base, swapgs], ARCH_GET/SET_CPUID [no CPUID faulting: SET → ENODEV])
- [x] iopl (x86-64 only; I/O port privilege level)
- [x] ioperm (x86-64 only; returns ENOSYS - requires TSS I/O bitmap)
- [ ] modify_ldt (x86-64 only; LDT manipulation)

Misc utilities that don't fit elsewhere:

- [x] personality
- [x] vhangup
- [x] readahead
- [x] alarm (x86-64 only, legacy; ITIMER_REAL in seconds)
- [x] pause (x86-64 only, legacy; use sigsuspend/ppoll)
- [ ] getpgrp (x86-64 only, legacy; use getpgid(0))
- [ ] ustat (x86-64 only, legacy; deprecated filesystem syscall)

15. "Probably later" / niche syscalls

When you get further along and want Linux feature-parity, you'll eventually look at:

- Key management and NUMA sets you skipped
- Crypto-related syscalls if they appear (most crypto is via /dev/* or libraries)
- Very new syscalls that might not yet be widely used in userland

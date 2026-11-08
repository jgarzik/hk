# Known Bugs

## Seen on both hk and the Linux reference

Failures that also occur when the boot tester runs on real Linux
(`check-linux*`). The cause may be the test, the environment, or a
real bug in Linux as well as hk: Linux is the reference, not
infallible, so each one is investigated, not written off.

- **NICE_ADJACENT flaky on the arm64 Linux reference**: one emulated
  `check-linux-arm` run had two adjacent-nice spinners' CPU share off
  (`share a:b tenths got 26`); passed on the uncached rerun. Likely
  TCG timing noise in a ratio test; widen the tolerance if it recurs.
- **RLIMIT_CPU_XCPU flaky on the x86 Linux reference**: one uncached
  `check-linux` run, run alongside `check-arm`, got `RLIMIT_CPU_XCPU:FAIL
  got 9` (SIGKILL where SIGXCPU was expected first); passed on rerun.
  Likely CPU-time accounting under a loaded host.

## Seen on hk only

- **MM_FAULT_STORM once under LOCKDEP**: one x86 `make check LOCKDEP=1`
  run reported `MM_FAULT_STORM:FAIL got 0` (no wrong value: a thread did
  not finish within the 60 s join); three later LOCKDEP runs (x86 twice,
  arm64) passed. Either LOCKDEP slowness against the join timeout or a
  missed wakeup on the contended mmap_lock; a recurrence should dump
  the stuck threads' state.

## unsafe not yet wrapped or documented (doc/UNSAFE.md)

There are 56 files with `#![expect(clippy::undocumented_unsafe_blocks)]
// TODO(unsafe)` (`git grep -l 'TODO(unsafe)' -- '*.rs' ':!user'`). Most of their
blocks belong in a missing wrapper:

- **Frames:** an owned / page-locked / PTL-held frame borrow type in
  place of the `frame_bytes` unsafe fn (17 callers: vfat, pipe, splice,
  exec, fault, filemap, swap).
- **DMA:** an owned `DmaBox<T: Pod>` with volatile field access, never
  `&T` into device-written memory: xhci rings and contexts, virtio
  rings and blk, e1000 descriptors, virtio-net buffers.
- **MMIO:** the remaining raw MMIO users move to `mmio::IoMem`: xhci's
  interrupt handler (USBSTS, IMAN), gfx framebuffer, vgacon, rtc,
  pci_quirks, aarch64 serial, x86 power.
- **Lists:** an intrusive `CursorMut` for the walk-and-remove loops
  (futex, waitqueue, sched, percpu).
- **Callbacks:** smp calls with a plain `usize` (`smp_call_function_many`
  without wait, `stop_one_cpu_nowait`, kthread `fn(usize)`) still carry
  integers or casts; the waiting forms have typed `_ref` variants.

## cgroup names must be UTF-8

**Location:** `fs/cgroupfs.rs`.

mkdir of a name that is not valid UTF-8 is EINVAL; Linux kernfs takes
any bytes.

## cgroup controller application gaps

**Location**: `cgroup/mod.rs`, `fs/cgroupfs.rs`

Enabling a controller in cgroup.subtree_control creates its state only
for cgroups made afterwards (Linux cgroup_apply_control creates it for
the existing children and migrates their tasks), and disabling it
removes nothing. A task in a cgroup without a controller is charged
nowhere; Linux charges the nearest ancestor that has it (the effective
css). The no-internal-processes rule (EBUSY when enabling in a cgroup
with tasks) is not enforced. A pids charge goes back when the task
exits; Linux keeps a zombie charged until it is reaped (pids_release
from release_task).

No controller but pids is applied: CPU bandwidth, memory and IO
limits, and cgroup.freeze are stored (and read back) but nothing is
charged, throttled or frozen. cpu.stat, memory.current/stat/events and
io.stat report zeros. When they are applied, use Linux's shapes: CPU
bandwidth under the bandwidth lock (cfs_b->lock, an IrqSpinlock: the
period timer), memory by page_counter_try_charge (add, check, roll
back up the hierarchy), the IO token bucket under the queue's lock
(blk-throttle), freezing under cgroup_mutex.

## user/ does not follow doc/UNSAFE.md

The `user/syscall` wrappers are safe `pub fn`s, and about 330 of them take
raw pointers, so `sys_read(fd, 0x1234 as *mut u8, n)` corrupts memory
without `unsafe`. The boot tester uses about 80 `static mut`, open-codes
volatile access to mmap'd memory, and defines `mem*` without
`#![no_builtins]`.

Planned fix:
- one `unsafe fn syscall6` per arch;
- wrappers that take slices, `&CStr` and `&mut T`;
- `unsafe fn` for address-space operations (mmap, munmap, brk, clone,
  futex);
- an `Mmap` RAII type for mmap'd memory;
- atomics in place of `static mut`.

## Network stack gaps

**Location**: `net/`

Listed because real traffic reaches them: TCP has no SACK (never
advertised), no CUBIC (only "reno"; Linux defaults to cubic), no
receive or send buffer autotuning (the window is SO_RCVBUF / 2; no
tcp_sndbuf_expand, so past the TCP memory hard limit a sender's
SO_SNDBUF is not shrunk, sk_stream_moderate_sndbuf; no rcv_ssthresh,
so memory pressure does not clamp windows), no orphan count limit
(tcp_max_orphans; only the memory half of tcp_out_of_resources), no per-netns
RFC 5961 challenge-ACK budget (only Linux's per-connection 500 ms
limit), and TCP_DEFER_ACCEPT / TCP_FASTOPEN are stored only.
No SYN cookies (a full listener drops SYNs). ICMP
timestamp requests are not answered.
Neighbour entries are not confirmed by TCP progress (only ARP), there is
no proxy ARP and no per-device neighbour sysctls (net/ipv4/neigh/*).
IP: no ipfrag_max_dist, no IP options on output (received options are
validated and skipped; source-routed packets are dropped), no
IP_TRANSPARENT. /proc/net/raw and
/proc/net/icmp do not exist.
UDP_CORK/MSG_MORE are not implemented (each send is one datagram) and
SO_PEEK_OFF is EOPNOTSUPP.
NIC removal: e1000 leaves the function's bus mastering and memory
space on (no pci_disable_device) and its BAR mapped (no iounmap); an
unregistered `NetDevice` lives on while queued skbs reference it
(no netdev_wait_allrefs; it is down and driverless).


The TCP send and receive queues are one contiguous `VecDeque<u8>`
each (`net/tcp/cb.rs`), grown fallibly but still a single allocation up
to SO_SNDBUF/SO_RCVBUF: a large buffer fragments the heap. Linux keeps a
queue of bounded skbs; hk should hold a queue of bounded chunks.

## Memory management gaps

**Location**: `mm/`, `arch/*/paging.rs`, `ipc/shm.rs`

Missing:

- Writeback (J): the periodic pass writes every dirty inode of a
  device (Linux only those dirty for vm.dirty_expire_centisecs, which
  is stored but unused); past vm.dirty_ratio the writer writes its own
  inode back synchronously instead of sleeping in balance_dirty_pages;
  the limits are fractions of all managed memory (Linux: dirtyable
  memory). No errseq: fsync reports a writeback error once, to the
  caller that ran the writeback, not to every open file.

- Reclaim (J) drops clean, unmapped page-cache pages inode by inode
  (no file LRU, no aging: Linux reclaims the oldest file pages; dirty
  or mapped ones stay until written back or unmapped), then swaps out
  private anonymous pages, also for MADV_PAGEOUT: no accessed-bit aging
  (pages are reclaimed oldest first), synchronous writes, no kswapd; 2MB pages stay
  off the LRU (never reclaimed whole; a split puts their 4KB pages on
  it). Pages exec copies the image into (see the heap section) are not
  on the reverse map (never swapped). Swap
  files go through their filesystem's swap_rw,
  a page at a time (walking the cluster chain each time; Linux maps
  the extents once at swapon). Page faults, swapoff, page-cache, heap
  and pipe allocations that may sleep reclaim directly; atomic heap
  allocations never do, so with anonymous memory filling RAM they fail
  at the low watermark until kswapd (J) keeps free memory above it.
- SysV shm: IPC_RMID removes the id at once (Linux keeps it, as
  IPC_PRIVATE with SHM_DEST, until the last detach: IPC_STAT and shmat
  by id still work there).
- File mappings: no fault-around (Linux maps up to 16 cached pages
  per read fault); filesystems without a page cache (procfs) still
  map a private copy.
- MADV_REMOVE of a file mapping is EOPNOTSUPP (no filesystem punches
  holes); shmdt needs the address an attachment starts at (Linux also
  finds a piece moved by mremap); SHM_EXEC is ignored.
- shmat checks RLIMIT_AS before SHM_REMAP unmaps the old
  range, and an address that SHM_RND rounds to 0 is EPERM (Linux picks
  an address).

## NUMA gaps

**Location**: `mm/numa.rs`, `mm/mempolicy.rs`, `mm/page_alloc.rs`

Topology is discovered (ACPI SRAT/SLIT, DT `numa-node-id`) and
getcpu reports it; nothing else uses it. Missing (Linux
`mm/mempolicy.c`, `mm/migrate.c`):

- Policies are not stored: set_mempolicy and mbind validate and
  return 0 (the `TaskMempolicy`/`Vma.mempolicy` fields stay default);
  get_mempolicy always reports MPOL_LOCAL (Linux: the stored mode,
  MPOL_DEFAULT when none) and ignores MPOL_F_NODE/MPOL_F_ADDR.
- One buddy zone for all RAM: no per-node zones (pg_data_t) or
  node-aware allocation, so no policy (BIND, PREFERRED, INTERLEAVE,
  local) affects where pages come from.
- No page migration: migrate_pages and move_pages validate and move
  nothing; move_pages query mode reports node 0 for every page.
- Nodemasks are one `u64` (64 nodes); the gate has no multi-node QEMU
  run (by hand: `QEMU_EXTRA="-object memory-backend-ram,id=m0,size=256M
  -object memory-backend-ram,id=m1,size=256M -numa
  node,nodeid=0,memdev=m0,cpus=0-1 -numa node,nodeid=1,memdev=m1,cpus=2-3"
  make check`).

## arm64 SPIs are all level-triggered

**Location**: `arch/aarch64/gic.rs` (`enable_spi`), `arch/aarch64/irq.rs`

Every SPI is configured level-sensitive; the trigger type in the
device tree `interrupts` cell is ignored (Linux gic_irq_domain_translate
and gic_set_type). Fine on QEMU virt, whose devices are all level.

## arm64 SMP assumes one-cell, Aff0-only CPU ids

**Location**: `arch/aarch64/dtb.rs` (`parse_dtb`), `arch/aarch64/smp.rs`
(`init`), `arch/aarch64/mod.rs` (`fallback_acpi_info`)

Fine on QEMU virt (one `reg` cell, Aff0 only); wrong on multi-cluster
hardware (Linux arm64 smp_init_cpus / of_get_cpu_hwid):

- The DT CPU list reads `reg` as one u32: with `#address-cells = 2`
  every CPU gets the Aff3 cell (0). `CpuInfo.hw_cpu_id` is a u32, so
  Aff3 is lost anyway, and it is passed as is to PSCI CPU_ON.
- The boot CPU is taken to be `reg == 0` in the DT list, and smp::init
  skips the CPU whose id equals MPIDR Aff0 (`mpidr & 0xff`): with
  clusters (0x100, ...) it can skip the wrong CPU or try to start
  itself. Linux matches the full MPIDR_HWID_BITMASK affinity.
- Without a usable DT, a hardcoded table of 4 CPUs (ids 0-3) is used
  instead of booting just the boot CPU.

## exec ignores set-user-ID / set-group-ID bits and file capabilities

**Location**: `task/exec.rs` (`do_execve`)

Linux execve of a file with S_ISUID / S_ISGID (on a mount without
nosuid, without no_new_privs or a ptracer in the way) sets the
effective (and saved) uid / gid to the file's owner, and file
capabilities (security.capability) raise the permitted set
(bprm_fill_uid, cap_bprm_creds_from_file). hk exec keeps the caller's
credentials unchanged, so set-id programs run unprivileged.

## CPU-time timer gaps

**Location**: `time/cpu_timer.rs`, `time/posix_timer.rs`

timer_create and clock_nanosleep take only the caller's own process
CPU clock (and its threads' for timer_create): another process's is
EINVAL (Linux runs those too, checked when that process runs). The
SCHED CPU clock counts utime + stime like PROF (Linux: exact runtime).
A CPU-clock clock_nanosleep's hidden timer takes a timer id from the
process's registry (Linux posix_cpu_nsleep's timer is not hashed: the
next timer_create id does not move). rseq is ENOSYS (glibc runs
without it).

## AF_PACKET gaps

**Location**: `net/packet/`

Not implemented: SOCK_PACKET (ESOCKTNOSUPPORT), the mmap rings
(PACKET_RX_RING/TX_RING, PACKET_VERSION), PACKET_FANOUT,
PACKET_VNET_HDR, PACKET_QDISC_BYPASS and the other SOL_PACKET options
(ENOPROTOOPT; Linux accepts them), SO_ATTACH_BPF, SO_GET_FILTER, and
socket filters on non-packet sockets (ENOPROTOOPT; Linux runs them on
every socket). A bound socket is not told (ENETDOWN) when its device
goes down later, only when it binds to a down device. Memberships only
count promiscuity/allmulti users (the drivers have no promiscuous or
multicast filtering; set_promisc is a no-op on e1000 and virtio-net,
which has no control queue: QEMU then delivers all frames).
PACKET_AUXDATA reports TP_STATUS_CSUM_VALID only for frames received on
lo (hk has no checksum offload states).

## fanotify gaps

**Location**: `io/fanotify.rs`

- Events carry FAN_NOFD: read opens no file with fanotify_init's
  event_f_flags (Linux copy_event_to_user / create_fd).
- fanotify_mark keeps only the mask: FAN_MARK_IGNORED_MASK,
  FAN_MARK_IGNORE, FAN_MARK_IGNORED_SURV_MODIFY and FAN_MARK_EVICTABLE
  are accepted but have no effect (Linux fanotify_add_mark).

## File lock gaps

**Location**: `fs/locks.rs`, `fs/posix_lock.rs`

No leases (F_SETLEASE) and no OFD locks (F_OFD_*).

## seccomp gaps

**Location**: `seccomp/`

No PTRACE_EVENT_SECCOMP (RET_TRACE is ENOSYS as with no tracer), no
user notification (SECCOMP_RET_USER_NOTIF, SECCOMP_GET_NOTIF_SIZES), no
FLAG_TSYNC_ESRCH / FLAG_SPEC_ALLOW / FLAG_WAIT_KILLABLE_RECV, and
nothing is logged for RET_LOG or FLAG_LOG.

## Pipe size is fixed

**Location**: `io/pipe.rs`, `fs/fd.rs` (`sys_fcntl`)

Every pipe holds 16 buffers; fcntl F_GETPIPE_SZ and F_SETPIPE_SZ are
EINVAL and there is no /proc/sys/fs/pipe-max-size (Linux pipe_fcntl,
pipe_set_size).

## vmsplice from a pipe is not done

**Location**: `fs/splice.rs` (`sys_vmsplice`)

vmsplice on a pipe or FIFO open for writing copies user memory into it
(Linux vmsplice_to_pipe). On one open only for reading Linux copies the
pipe's data into the user iovecs (vmsplice_to_user); hk returns EBADF.

## AF_UNIX gaps

**Location**: `net/unix/`

No garbage collector for in-flight sockets: a socket whose only
references are messages queued on sockets that are themselves only
reachable that way (e.g. a socket's own descriptor sent to itself, then
closed) stays allocated with its queue. Linux collects such cycles
(net/unix/garbage.c). hk bounds them instead: files in flight are
charged to the sending user and further SCM_RIGHTS sends fail with
ETOOMANYREFS once the count exceeds RLIMIT_NOFILE (Linux's
too_many_unix_fds rule), so a user can pin at most about RLIMIT_NOFILE
files (plus the queues of those sockets, each bounded by SO_SNDBUF and
max_dgram_qlen). Unlike Linux the count is also capped at 2024 (Linux's
UNIX_INFLIGHT_SANE_USER), so raising RLIMIT_NOFILE does not raise what
can be pinned.

Not implemented: MSG_OOB on streams (EOPNOTSUPP; Linux supports one
out-of-band byte), SO_PEEK_OFF, SO_PASSPIDFD / SCM_PIDFD /
SO_PEERPIDFD, SO_PEERGROUPS, SO_INQ / SCM_INQ, SO_RIGHTS_NOTRUNC,
SIOCUNIXFILE, SO_PEERSEC (ENOPROTOOPT, as on Linux without an LSM).

## File permission (DAC) gaps

**Location**: `fs/dac.rs`, `task/exec.rs`

Missing: immutable/append-only inodes (no IS_APPEND/IS_IMMUTABLE
EPERM).

## Before user namespaces grant capabilities

**Location**: `task/mod.rs` (`capable`), `fs/dac.rs`, `ns/mod.rs`,
`fs/mount.rs`, `net/netlink/rtnetlink.rs`

Safe today only because a user namespace grants no capabilities. First:
- each `capable()` becomes Linux's `ns_capable(<owner>->user_ns)` (or
  `capable`, where Linux keeps it); sockopt_ns_capable sites take the
  socket netns's user_ns, but SO_DEBUG and SO_SNDBUFFORCE/RCVBUFFORCE
  stay init-namespace (Linux sockopt_capable).
- an unprivileged CLONE_NEWNS (new user_ns) locks the copied tree
  (lock_mnt_tree: MNT_LOCKED plus MNT_LOCK_* flags) and turns shared
  mounts into slaves (CL_SHARED_TO_SLAVE).
- netlink newlink/setlink check CAP_NET_ADMIN in the target netns too
  once IFLA_NET_NS_PID/FD are implemented (`7b735ef81286`).

## Credentials have no identity

**Location**: `task/mod.rs` (`Cred`), `fs/namei.rs` (`may_linkat_empty`)

`Cred` is a value, not Linux's shared, refcounted `struct cred`. linkat
AT_EMPTY_PATH compares `f_cred` with the caller's creds by value, where
Linux compares pointers. Any commit_creds since the open, and fork's
copy_creds, gives Linux a new pointer. So an fd inherited across fork
by a same-uid child, or passed between same-cred processes, can be
linked on hk without CAP_DAC_READ_SEARCH; Linux gives ENOENT. The
capability is checked in the caller's namespace (Linux: the opener's
`user_ns`); hk has one user namespace.

User namespaces grant no capabilities: creating any namespace but a
user namespace needs the caller's own CAP_SYS_ADMIN, even together with
CLONE_NEWUSER (Linux checks in the new user namespace, where the caller
holds every capability), and /proc/<pid>/uid_map and gid_map cannot be
written.


POSIX message queues reject creation by an unprivileged user with
EACCES (`ipc/mqueue.rs`): hk has no 01777 `/dev/mqueue`, so only root
creates queues, where Linux lets any user. mq_attr_ok's soft caps
(msgsize_max 8192, msg_max 10 without CAP_SYS_RESOURCE) are therefore
unreachable today.
There is no mqueue filesystem at all: queues live only in a kernel
table, so they cannot be listed or read as files under /dev/mqueue
(Linux mqueue_fs_type).

## sysfs gaps

**Location**: `fs/kernfs/`, `fs/sysfs.rs`, `base/`, `block/genhd.rs`,
`net/sysfs.rs`, `hw/pci/driver.rs`

- No power/ directories (Linux dpm_sysfs_add: control, runtime_status,
  wakeup ...), no /sys/power, /sys/firmware/{acpi,dmi,efi} or
  /sys/class/dmi/id: the directories exist empty.
- Missing classes: rtc (PL031 has no /dev/rtc0), input (Phase V),
  misc, graphics/drm, pci_bus; no /sys/kernel/{security,debug,tracing,
  config} mount points (hk has none of those filesystems).
- Topology: places differ from Linux on QEMU: COM1's ttyS0 sits below
  /sys/devices/platform/serial8250 (Linux binds 8250_pnp to the ACPI
  PNP0501 device), PL011/PL031 are platform devices (Linux: amba bus),
  SCSI disks of USB storage are virtual (Linux: host/target/device
  below the interface), RAM disks are rdN (Linux brd: ramN).
- SCSI disks: no device/vendor, device/model or other scsi_device
  attributes (Linux sdev_attrs: sdev_show_vendor, sdev_show_model).
- PCI: no resource/resourceN/rom/enable/numa_node/local_cpus files;
  config is 256 bytes even for PCIe functions (no extended space).
- cpu: no cpuN/topology, cache/ or online files and no MODALIAS
  (CONFIG_GENERIC_CPU_AUTOPROBE); node: no meminfo/numastat/vmstat.
- net: no queues/, phys_port_*, speed/duplex, ifalias or gro files;
  interfaces cannot be renamed or moved between namespaces, so no
  "move" uevents.
- /sys/module lists built-in modules with drivers only; no parameters
  or version files (hk has no module parameters).

## uevent gaps

- `/sys/kernel/uevent_helper` stores a path, but no helper is run per
  event (Linux call_usermodehelper; hk has no usermode helper).
- NETLINK_KOBJECT_UEVENT has no kernel input: messages a
  CAP_SYS_ADMIN sender addresses to port 0 are not rebroadcast (Linux
  uevent_net_rcv, used by container managers).
- Network namespaces have no owning user namespace, so uevents go to
  every namespace; Linux sends untagged events only into namespaces
  owned by the initial user namespace (uevent_sock_list).

## TTY gaps

**Location:** `tty/`, `hw/serial.rs`, `arch/aarch64/serial.rs`.

- **No hangup:** nothing hangs a tty up (Linux __tty_hangup: vhangup,
  a session leader's exit, carrier loss), so open files stay usable.
  A leader's exit and TIOCNOTTY only send SIGHUP/SIGCONT to the
  foreground group and clear the session; vhangup(2) only checks
  CAP_SYS_TTY_CONFIG. Unbinding a serial port (serial8250, PL011)
  removes its tty devices, console and interrupt but hangs up no open
  file (Linux uart_remove_one_port: tty_port_tty_vhangup): writes to
  an open ttyS0/ttyAMA0 or /dev/console still reach the UART. No boot
  test unbinds the console UART (the test output goes there).
- **Per-process controlling tty:** it is the session's tty, so TIOCNOTTY
  by a non-leader changes nothing (Linux clears that process's
  signal->tty only).
- **No group stop:** a background process that gets SIGTTOU/SIGTTIN
  with SIG_DFL (tty_check_change) fails with EIO instead of stopping
  (see the ptrace stop gaps: stop/continue are not implemented).
- **Missing:** termio ioctls (TCGETA, TCSETA*), termios2, TIOCSTI,
  TIOCEXCL exclusivity, sending a break (TCSBRK 0), IXON/IXOFF flow
  control, packet mode, ptys, VLNEXT/VREPRINT/VDISCARD, ECHOPRT,
  IUCLC/OLCUC, IMAXBEL, PARMRK and parity/break input handling. Output
  is written synchronously by polling (TIOCOUTQ 0, no write_wait).
- **Serial ports:** ttyS1 is registered without probing COM2; only
  COM1 (and the PL011) take input.
- **No virtual terminals:** the framebuffer and VGA consoles are not
  ttys (Linux: fbcon/vgacon draw VTs, tty0..tty63, fed by the
  keyboard), so /dev/console is always a serial tty. With a screen
  console (console=tty0), Linux's /dev/console is the VT; on hk user
  console I/O stays on the serial port and the screen shows only
  printk.

## Futex gaps

**Location:** `task/futex.rs`

- **FUTEX_WAKE_OP and PI futexes** are missing.
- **futex_waitv flags:** FUTEX2_NUMA and FUTEX2_MPOL are EINVAL;
  Linux accepts them (futex_parse_waitv, FUTEX2_VALID_MASK).
- **MAP_PRIVATE file mappings:** a shared futex there is keyed by
  (mm, address) from the VMA; Linux keys a page still in the page
  cache (not yet COW'd) by inode and offset, so a MAP_SHARED mapping
  of the same file wakes it.

## Mount flag gaps

**Location**: `fs/misc.rs` sys_mount/sys_umount2, `fs/mount.rs`

Accepted without effect: MS_SILENT, MS_MANDLOCK, MS_POSIXACL,
MS_I_VERSION, MS_LAZYTIME. Propagation (`fs/pnode.rs`): a propagated
copy lands on top of what is already mounted at the target (Linux
tucks it under); a slave's master is its master's peer group, not one
mount; copies of a namespace are always peers and not locked (Linux
copy_mnt_ns for a less privileged user namespace makes shared mounts
slaves, CL_SHARED_TO_SLAVE, and locks them, lock_mnt_tree): harmless
while CLONE_NEWNS needs root and mounts ignore user namespaces, but
required before mounts become user-namespace aware. Mount options are
parsed by vfat (Linux's set; long names UTF-16 in UTF-8, iso8859-1 or
cp437 only), ramfs (mode=) and procfs (hidepid=, gid=, subset=pid);
devtmpfs and cgroupfs ignore theirs, and only procfs applies options
on a remount or shows them in /proc/mounts; mounts are not user-namespace aware (plain capable()).
Crossing into a mount scans the current mount's children (Linux hashes
(parent, mountpoint): mount_hashtable).

## nullfs gaps

**Location**: `fs/nullfs.rs`, `fs/mount.rs` init_mount_tree,
`fs/fsstruct.rs` KTHREAD_FS

The nullfs root (Linux 7.0) and the kernel threads' private nullfs
(7.3) are in place, but no user path reaches either, so what Linux 7.3
added for when they become reachable is not done: empty mount
namespaces, the nullfs that stands in for an unmounted mount and the
empty immutable regular file. Locks are not refused with ENOLCK
(31a1fb90624d), MS_REMOUNT and umount of the root are not refused on
the internal superblock (d791606bb915), and nothing marks knullfs's
root as unmountable (e22e69c2ad88: dont_mount). The rootfs is
always a ramfs; Linux fills it as tmpfs when it has CONFIG_TMPFS
(Ubuntu does), so statfs("/") on the initramfs differs until hk has a
tmpfs (doc/ROADMAP.md phase 6). Kernel code that resolves a path from a kernel thread finds nothing
(knullfs); hk has none today, and has no scoped_with_init_fs for one
that would need init's root.

## No vDSO

**Location**: `task/exec.rs`, `arch/aarch64/signal.rs`

No vDSO is mapped (no AT_SYSINFO_EHDR): libc makes real syscalls for
clock_gettime and friends. On arm64 a page holding only the signal
return trampoline stands in for the vDSO's sigtramp, shown as
[sigpage] in /proc/<pid>/maps (Linux: [vdso], [vvar]).

## ptrace stop gaps

**Location**: `task/ptrace.rs`, `task/exec.rs`,
`signal/mod.rs`

Signal-delivery and PTRACE_SYSCALL stops work. Missing: exec, fork,
clone and exit event stops (PTRACE_O_TRACEEXEC and friends,
PTRACE_EVENT_*), PTRACE_INTERRUPT/LISTEN, group-stop interaction (SIGSTOP
to an untraced task is ignored: stop/continue are not implemented).

## NETLINK_ROUTE / SIOC* subset gaps

**Location**: `net/netlink/rtnetlink.rs`, `net/devioctl.rs`

No notifications for neighbour state changes (no RTNLGRP_NEIGH); no
proxy ARP entries, NTF_USE or NDA_PROTOCOL.
Missing, each answered with a Linux errno rather than silently: link
creation and rename (EOPNOTSUPP), multipath routes and nexthop objects
(EOPNOTSUPP), input-route simulation `ip route get ... iif` (EOPNOTSUPP),
NLM_F_ECHO (not echoed), extended-ACK message/offset TLVs (plain errors),
RTM_GETRULE dumps nothing (Linux lists its three default IPv4 rules; there
is no rule engine: lookups are local then main), address lifetimes are
always infinite, promote_secondaries is off.
RTM_NEWLINK/RTM_SETLINK ignore IFLA_NET_NS_PID/IFLA_NET_NS_FD: they
return 0 without moving the device (Linux: moved, or an error).

## io_uring has no shared rings

**Location**: `io/io_uring.rs`

io_uring_setup returns ring offsets, but nothing maps the SQ ring, the
CQ ring or the SQE array (IORING_OFF_SQ_RING/CQ_RING/SQES), so user
SQEs never reach the kernel and CQEs never reach user space: submit
works on a kernel-side copy, and `post_cqe` assumes the CQ head is 0.
Missing on top of that:
- `io_uring_enter(IORING_ENTER_GETEVENTS)` never blocks (`wait_completions`
  is a stub) and ignores IORING_ENTER_EXT_ARG
- IORING_OP_TIMEOUT has no timer (nothing ever completes it), and has
  no count trigger, TIMEOUT_UPDATE or MULTISHOT
- IORING_OP_LINK_TIMEOUT returns 0 without arming anything
- poll ops never complete asynchronously; IOSQE_IO_DRAIN and ASYNC are
  ignored

The boot tests cover setup and enter return values only.

## Rare QEMU crash in the arm64 boot test (host CPU suspected)

**Location**: host, not hk (QEMU 8.2.2 TCG on the Core Ultra 9 285K
host, `make check-arm`)

qemu-system-aarch64 occasionally dies in the guest stage-1 page table
walk (arm_ldq_ptw, target/arm/ptw.c:671; once S1_ptw_translate): the
fault address differs from the pointer the faulting load holds, so the
host CPU computed a wrong address. The crashes run on CPUs 5 and 2,
the favored cores, which also lead the host's segfault count for other
programs; hk's fork/exit churn (RLIMIT_NPROC, FD_LEAK) makes QEMU walk
page tables hardest. Nothing in hk can avoid it. To do: check the BIOS
for Intel default power/turbo settings and current microcode,
stress-test CPUs 2 and 5, or keep gate QEMUs off them (taskset).

## Interrupts run on the task stack (no IRQ stacks)

**Location**: `arch/aarch64/vectors.S`, `arch/x86_64/`
(IRQ entry)

An interrupt pushes its trap frame (0x320 bytes on arm64, with the
FP/SIMD registers) and handler frames onto whatever 16 KB task stack
it lands on, so the deepest syscall path plus the deepest interrupt
must fit in one stack. An overflow faults in the guard gap below the
stack ("kernel stack overflow" panic, `mm::vmstack`). Linux has per-CPU IRQ stacks (x86 hardirq_stack,
arm64 irq_stack).

## Rare arm64 kernel instruction abort in the fault-signal tests

**Location**: unknown (CPU 0, right after `FAULT_SEGV_ACCERR`, i.e. while
`FAULT_SIGILL` runs `udf` in user mode)

One "KERNEL PANIC ... exceptions.rs:95" (kernel instruction abort) in
about 190 `make check-arm` runs (QEMU neoverse-n1 with PAN, -smp 4);
ELR/FAR were not captured. Next occurrence: capture the Message line.

## ramfs has no size limit

**Location**: `fs/ramfs.rs`, `mm/filemap.rs`,
`mm/frame_alloc.rs`

ramfs (the root filesystem and every ramfs mount) is bounded only by
memory, for every user: writes fail with ENOSPC once free frames reach
the low watermark (min_free_kbytes formula), and the memory comes back when the last link and the last
open reference of a file are gone (or on truncate). Linux's rootfs is a
tmpfs limited to half of RAM by default; tmpfs with `size=`/`nr_inodes=`
limits (and per-user accounting) comes with phase F (tmpfs).
Reads of holes need a zeroed page each and can fail with ENOMEM when
memory is at the low watermark (Linux maps the shared zero page).

## Kernel heap (slab) gaps

**Location**: `mm/slab.rs`, `mm/heap.rs`

The heap is the slab allocator over the page allocator, so it grows
with RAM; what is missing: no shrinker (caches give back empty slabs
beyond two each, but nothing asks them under pressure), no slab
merging, poisoning or red zones.

Objects are built fallibly (`util/kalloc.rs` try_box/try_arc, ENOMEM) and
buffers sized from outside through `kmem`; the `*_nofail` calls (boot
setup, NOFAIL paths) and plain `Vec`/`String` growth bounded by a sysctl
or a constant still panic when the heap cannot meet them. The heap goes down to the min
watermark while user data stops at low (also after direct reclaim:
user allocations stop at low until the OOM killer (J); then Linux's
min), so only kernel objects can get there (no memcg or OOM killer bounds what a process pins in pipes,
sockets or fds); a large allocation in atomic context (no vmalloc
fallback) can fail first (above low - min, about 700KB at 512MB, once
free memory is near the low watermark).

exec maps PT_LOAD segments from the page cache, except a static PIE
with no interpreter (hk relocates it in the kernel, so its pages are
private copies; Linux applies no relocations at all) and the partial
last page and bss of each segment (copied).

## The memory cgroup's memory.max is not enforced

**Location**: `cgroup/memory.rs`, `mm/fault.rs`, `mm/shmem.rs`

memory.max, memory.current and memory.events exist, but no page is
charged: page faults (anonymous and shmem) and page tables are never
charged, freed pages never uncharged, and memory.events oom/oom_kill
stay 0. Linux charges each page to its
memcg (folio memcg_data, mem_cgroup_charge), uncharges on free, and
over the limit reclaims, then OOM-kills a task in the cgroup
(mem_cgroup_out_of_memory).

Once enforced, OOM_FAULT_KILL and OOM_SHARED_KILL can run in a small
cgroup (say memory.max 64MB) at any RAM size, and on Linux too,
instead of filling all of RAM and being skipped above 4GB
(`user/boot_tester/mm/mm_oom.rs`).

## BPF map update flags are not checked

**Location**: `bpf/map.rs`, `bpf/syscall.rs`

BPF_MAP_UPDATE_ELEM treats any flags value but BPF_NOEXIST and
BPF_EXIST as BPF_ANY; Linux returns EINVAL for flags above BPF_EXIST
and for BPF_F_LOCK on a map without a bpf_spin_lock
(bpf_map_update_value, htab_map_update_elem).

## BPF map memory is not charged

**Location**: `bpf/map.rs`

An array or hash map refuses a size over half of free memory at
creation, but nothing adds maps up: no RLIMIT_MEMLOCK or memcg charge (Linux
bpf_map_charge_memlock / memcg accounting), so many maps can still use
up memory.

## Heap allocations under spin locks

**Location**: `mm/slab.rs` (`heap_gfp`); sites listed by LOCKDEP

The heap picks GFP_ATOMIC by itself under a spin lock, so an allocation
there takes the atomic reserve silently (Linux needs it named, and
might_alloc reports a GFP_KERNEL one in atomic context). A LOCKDEP boot
lists each lock allocated under once (`LOCKDEP:ATOMIC_ALLOC ... under
<lock> (taken at ...)`; the shutdown summary counts them): 105 locks,
mostly collections grown under spin mutexes, in fs, net, task and
ipc (procfs: only its mount-time tree building). Each wants its allocation moved out of the
lock (preallocate, or a sleeping lock as in Linux).

## Sleeping mutex has no handoff

**Location**: `sync/mutex.rs`

A woken waiter retries the CAS and sleeps again if it lost, so a task
that unlocks and relocks at once can starve the sleepers indefinitely;
Linux hands the lock to a waiter that has failed for over a jiffy
(MUTEX_FLAG_HANDOFF). Seen with a test-only 300 us delay under
`Pipe.inner` in pipe_read: a reader spinning in non-blocking reads kept
the writer off the pipe for over 10 s.

## Scheduler gaps (deviations from Linux)

**Location**: `task/fair.rs`, `task/percpu.rs`

- EEVDF scans a list per pick and computes the average vruntime per use
  (Linux: an rbtree augmented with min_vruntime and incremental sums,
  O(log n)); fine for short run queues.
- Slices end at tick granularity (10 ms; no hrtick), no reweight on a
  nice change of a queued task, no RUN_TO_PARITY or delayed dequeue.
- No PELT: load balancing counts tasks and wakeup placement looks for
  an idle CPU; one flat domain (no SMT/LLC/NUMA topology), no active
  balancing; rt tasks move at wakeup placement and in the balancer's
  pulls only (no push from an overloaded CPU).
- RT throttling has fixed values (950 ms of each 1 s): no
  sched_rt_runtime_us / sched_rt_period_us sysctls; no dl_server, no
  SCHED_DEADLINE (EINVAL).
- Kernel preemption is off: a long kernel path delays a woken task of
  a higher class until its next scheduling point.

## xHCI driver gaps on real hardware

**Location**: `hw/usb/xhci.rs`, `hw/usb/msc.rs`

QEMU's xHCI hides all of them.
- Command completions are not matched to their TRB (`wait_for_command`
  ignores `_trb_addr`): a late completion for a timed-out command is
  credited to the next one. A timed-out transfer leaves its TRB queued
  and leaks its bounce buffer; a timeout should stop the endpoint and
  move its dequeue pointer past the TRB (Linux
  xhci_handle_cmd_stop_ep).
- One controller only: the driver keeps a single global
  `USB_CONTROLLER`; a second xHCI's probe replaces the first, which is
  left running, and both device handles act on the survivor at
  shutdown (unbinding the first stops neither).
- No hub support (route string 0): devices behind a hub are not
  enumerated.
- Only bulk and interrupt endpoints are added to the controller
  (`configure_endpoints`): isochronous and non-default control
  endpoints are skipped. A control data stage is one TRB of at most a
  page: a configuration descriptor longer than 4 KiB is cut short.
- Only 4 KiB controller pages and up to 512 scratchpad buffers.
- The USB serial console drops output while `USB_CONTROLLER` is held
  (by any CPU): it only try-locks it; Linux queues console output in a
  write FIFO sent asynchronously.

## USB core gaps

**Location**: `hw/usb/usbcore.rs`, `hw/usb/xhci.rs`, `hw/usb/msc.rs`,
`hw/usb/serial.rs`

- One root hub: Linux gives an xHCI two (`usb1` USB 2.0 and `usb2`
  USB 3.0, from the Supported Protocol capabilities, each numbering
  its own ports); hk has `usb1` only and names every device
  `1-<xHCI port>`, SuperSpeed ones too (Linux: `2-<port>`).
- No hub driver (Linux "hub", hub_probe/hub_event): the root hub's
  interface `1-0:1.0` stays unbound, `maxchild` is 0, and devices are
  found once by the xHCI probe (no connect/disconnect handling).
- No usbfs: no /dev/bus/usb/BBB/DDD (char major 189), so usb_device
  uevents lack MAJOR/MINOR/DEVNAME; no "usbfs" interface driver.
- sysfs subset: no string descriptors (`manufacturer`, `product`,
  `serial`, `configuration`, interface `interface`), no `descriptors`,
  `authorized`, `removable`, `quirks`, `urbnum`, `power/`, `ep_XX/`;
  `bConfigurationValue` is read-only (Linux: writing it sets the
  configuration).
- The configuration is always the first (Linux
  usb_choose_configuration) and is set at enumeration, not by the
  generic driver's probe; no SET_INTERFACE (alternate settings stay at
  0).
- usb-storage: SCSI transparent command set over Bulk-Only Transport
  only (no CB/CBI, RBC/UFI/8070 subclasses, UAS, or unusual_devs
  quirks).
- ftdi_sio: a console only, for the FT232 (0403:6001): no usb-serial
  bus or ttyUSB0 tty device, no baud rate or modem control requests,
  the bulk IN endpoint is never read.

## No DMA for 32-bit devices with RAM above 4GB

**Location**: `hw/dma.rs`, `mm/frame_alloc.rs`,
`hw/net/e1000.rs`, `hw/usb/xhci.rs`

`DirectDmaOps` only checks the mask: a buffer or coherent frame above
the device's mask fails (`None`) instead of being bounced (Linux
swiotlb) or allocated low (Linux ZONE_DMA32 / GFP_DMA32). PCI devices
default to a 32-bit mask, so with RAM above 4GB:
- e1000 never widens its mask (Linux does only for PCI-X; QEMU's e1000
  is PCI): its ring and buffer allocations fail once frames above 4GB
  are handed out (`NIC=e1000` with `QEMU_MEM` > ~3.5G).
- An xHCI without HCCPARAMS1.AC64 gets the 32-bit mask, but its DCBAA,
  scratchpads, command and event rings come straight from the frame
  allocator with no mask check.

## x86 has no IOAPIC or MSI

**Location**: `arch/x86_64/irq.rs`, `hw/pci/mod.rs`

Device interrupts reach the CPUs only through the 8259 PIC, on the
line firmware wrote into each function's Interrupt Line register (PIC
mode, legacy BIOS boot), delivered to the boot CPU only. Real hardware
in APIC mode (UEFI boot; Linux on the Dell uses IOAPIC 16-23 and MSI)
needs IOAPIC with ACPI `_PRT` routing, or MSI/MSI-X, which xHCI, AHCI
and r8169 all support. The MADT parser skips IOAPIC entries (Linux
acpi_parse_ioapic registers them).

## ACPI power management gaps

**Location**: `hw/acpi/`, `arch/x86_64/{acpi,power}.rs`

hk has no AML interpreter: `\_S5` is found by a byte scan of the DSDT
and SSDTs for a plain `Name (_S5, Package ...)`: one returned by a
method is missed (SLP_TYP 0 is used, with a warning), and one inside
an `If` is taken whatever the condition. `_PTS` and `_TTS` are not evaluated before S5, which some
firmware needs to power off cleanly. There is no SCI handler: IRQ 9
stays masked and every fixed event and GPE is disabled at boot, so
ACPI power-button, lid and GPE events are not handled (once in ACPI
mode, a short power-button press does nothing). Only the 32-bit FADT
block fields are read (no X_ GAS forms, no hardware-reduced ACPI), and
a reset register in PCI configuration space is ignored.

## vfat file I/O walks the whole cluster chain per page

**Location**: `fs/vfat.rs` (`page_runs`)

Every read_folio, writepage and swap_rw of a vfat file rebuilds its
whole cluster chain from the FAT (through the device cache) to find a
page's clusters, so reading or writing back a file is quadratic in its
size (a 1GB file of 4KB clusters: about 3e10 FAT lookups). Linux
fat_get_cluster keeps a per-inode cache of chain positions
(fat_cache); one is needed before large vfat files or vfat swap files.

## Block layer gaps

**Location**: `block/`, `hw/virtio/blk.rs`,
`fs/blkdev_ops.rs`, `fs/vfat.rs`

- Partition tables are parsed in 512-byte sectors: on a disk with
  larger logical blocks, GPT LBAs and MBR sector counts are misread
  (Linux scales by the logical block size). MBR: no BSD, Solaris,
  UnixWare, Minix, AIX or DM6 subpartitions. GPT: like Linux without
  the `gpt` parameter, a bad primary header is not replaced by the
  backup.
- BLKRRPART is EBUSY while a partition is open, mounted or used for
  swap (any holder of the partition besides the registry); Linux also
  takes the whole disk for exclusive use during the scan
  (bd_prepare_to_claim), so a rescan can race an exclusive opener.
  BLKROSET, BLKDISCARD, BLKZEROOUT, BLKIOMIN/OPT, BLKALIGNOFF,
  BLKSECTGET, HDIO_GETGEO and the BLKPG partition ioctls are ENOTTY.
- virtio-blk: modern devices only (QEMU needs `disable-legacy=on`;
  Linux also drives transitional devices), INTx only (no MSI-X),
  capacity changes (config interrupts) are ignored, no DISCARD,
  WRITE_ZEROES, GET_ID (serial) or secure erase. The disk's queues are
  fixed at probe.
- Disk removal (`del_gendisk`) drops the page cache without writing it
  back; Linux syncs it first on an orderly removal (bdev_mark_dead with
  surprise = false: sync_blockdev), so dirty device-file data is lost
  on unbind.
- virtio-pci remove leaves the BAR mappings (common, notify, ISR,
  device config): `IoMem` windows are copyable and never unmapped, so
  each transport rebind leaks the ioremap space of one device (Linux
  vp_modern_remove iounmaps them).
- No /proc/devices block section; the first disk
  registered decides the dynamic major (254 down, like Linux, but Linux
  usually has other dynamic majors registered first).
- A mounted filesystem or active swap opens its block device, but not
  exclusively: opening it O_EXCL and BLKBSZSET on a mounted partition
  are not refused.

fallocate on a block device is EOPNOTSUPP (Linux blkdev_fallocate zeroes
or discards the range).

## Code-quality gaps, by phase

Designs that grew one commit at a time. Tag = roadmap phase
(doc/ROADMAP.md).

- **Syscalls that do not deliver** (H/C): inotify queues only
  IN_DELETE_SELF, IN_UNMOUNT and IN_IGNORED, fanotify nothing (no
  fsnotify hooks in the VFS operations); rename has no
  IN_MOVED_FROM/IN_MOVED_TO cookie pairing (Linux fsnotify_get_cookie); waitid without WEXITED is
  EINVAL (C).
- **Copied helpers** (J, or as touched): `get_nofile_limit` in five
  places; four `current_time`s; about ten user-timespec readers each validating
  (Linux get_timespec64); three iovec structs and five
  importers; three Timeval, two Timespec types.
- **Error conventions** (M1): Result<_, KernelError> about a thousand
  times beside Result<_, i32> (both signs used) and Result<_, i64>
  over a hundred and fifty; raw errno numbers and local errno
  constants in the hundreds.
- **Process-wide state per thread** (C): pgid/sid copied into every
  thread; one global CHILD_EXIT_WQ wakes every waiting parent on every
  exit.
- **`task/percpu.rs` is about 4,600 lines** (before C): scheduler core,
  do_clone (523 lines), exit, wait, credential setters, five sleep
  APIs. Split like Linux (sched/core, fork, exit, cred). Other giants:
  sys_prctl, do_semctl, sys_mmap, exec_file, sys_fcntl.
- **Arch code in generic files** (M2): over a hundred
  `cfg(target_arch)` outside `arch/` (main.rs, hw/dma.rs, percpu.rs,
  misc, pci, seccomp's audit arch), dozens of direct
  `arch::x86_64::`/`aarch64::` references, three `CurrentArch`
  redefinitions.
- **Globals where per-CPU fits** (I/C/E): TCP timers in one map run on
  softnet/0 only; CHILD_EXIT_WQ.
- **ID allocators** (J): PidMap, fdbits, IPC ids, and plain counters
  (bpf, mqueue, which wrap with no collision check): one
  IDR/IDA.
- **procfs** (H): a file is generated whole (no seq_file records): an
  open file's reads continuing one another see one generation, where
  Linux generates record by record, so a long file's later chunks are
  as old as its first.
  /proc/sys is one static tree: the sysctls Linux registers for the
  initial network namespace only (net/ipv4/tcp_mem,
  net/core/mem_pcpu_rsv) appear in every
  namespace. /proc/sys/net values act on the namespace of the task
  reading or writing, not the one the file was opened in (Linux binds
  the file to the opener's namespace): an fd passed across namespaces
  reads and writes the other one's values.
- **Stale comments and dead code** (as touched): 56 `#[expect(dead_code)]`
  and over a hundred "for now"/TODO markers; comments that
  contradict the code in `ns/mod.rs` (setns) and `task/misc.rs`.

## Review gaps, by phase

Tag = roadmap phase (doc/ROADMAP.md).

1. **pcp_free drains the hot end** (J). `mm/page_alloc.rs:441`: a
   freed page is pushed at the head and a drain pops from the head;
   Linux returns the cold tail.
2. **arm64 /reserved-memory no-map regions are linear-mapped** (D;
   real HW). `arch/aarch64/dtb.rs:192`: Linux memblock_mark_nomap
   removes them (speculative access to secure carve-outs).
3. **memblock does not grow its arrays** (J). `mm/memblock.rs`: 512
   ranges per set; RAM ranges past that are dropped with a warning (as
   Linux before memblock_allow_resize), but a reservation past it still
   panics; Linux doubles the arrays then (memblock_double_array).
4. **LRU batch refs defeat exclusivity checks** (J). `mm/fault.rs:504`
   / `:596`: refcount==1 tests fail while a page sits in the per-CPU
   add batch, so swap-in makes needless COW copies. Linux drains and
   rechecks (wp_can_reuse_anon_folio).
5. **alloc_slot linear scan under SwapInfo.map; two Vecs + sort per
   reclaimed page** (J). `mm/swap.rs:206`: cluster/free-hint
   allocator, cached sorted device list.
6. **One AnonVma per fork family, Vec chain** (J).
   `mm/anon_vma.rs:85`: O(N×VMAs) under one family write lock.
7. **reboot(2) in a pid namespace checks `capable`** (B4). It checks
   CAP_SYS_BOOT with `capable`, not in the namespace's user namespace
   (Linux ns_capable(pid_ns->user_ns)): a pid namespace has no owning
   user namespace yet.
8. **MM_LIFE_EXEC_CHAIN flake** (arm64 CI, TCG, NIC=e1000):
   `MM_LIFE_EXEC_CHAIN:FAIL -2`, a measured chain's child (busybox
   `env` x40 then `true`: 41 execs in one process) exited nonzero: a
   failed exec, not a leak. MM_LIFE prints the child's wait status;
   investigate when it repeats.
9. **SOCKCORE_CONNECT_REFUSED flake** (cause unknown):
   `SOCKCORE_CONNECT_REFUSED:FAIL SO_ERROR got 0` (hk arm64,
   `check-stress`): poll reported POLLOUT for a nonblocking connect to
   a just-closed loopback port, but no ECONNREFUSED was pending. The
   error is set under the socket lock with the move to CLOSED, so the
   connect left SYN_SENT by a SYN-ACK or a SYN: something answered on
   the dead port. Not a self-connect: bind(0) gives the dead port an
   odd offset, connect takes even ones while any is free. Not
   reproduced in 10000 looped runs (with SOCKCORE_PORT_PARITY before
   each; x86 and arm64 LOCKDEP e1000, 8 CPUs, CPU spinners, TIME_WAIT
   churn); LOCKDEP builds assert that a listener receiving a SYN owns
   its port in bhash (`TcpSock::assert_owner`). On failure the test
   prints the poll events, TCP state, local and peer ports, the port
   range and the /proc/net/tcp lines of the dead port.

## DRM dumb buffers are the boot framebuffer only

**Location**: `hw/gfx/simplegfx.rs` (`create_dumb`)

DRM_IOCTL_MODE_CREATE_DUMB returns the firmware framebuffer when the
size and depth match it, else ENOMEM; Linux simpledrm allocates any
dumb buffer from shmem and blits it on page flip
(drm_gem_shmem_dumb_create).

## Namespace files are not nsfs

**Location**: `fs/proc/mod.rs` (`ns_file`), `ns/mod.rs` (`sys_setns`)

/proc/<pid>/ns/<type> leads to a procfs inode numbered as the
namespace, not to an nsfs inode: st_dev is procfs's, and the file names
the task and the type, so setns joins the namespace that task is in at
setns time (Linux: the open file pins the namespace itself, and a bind
mount of it keeps the namespace alive). No cgroup, time,
pid_for_children or time_for_children links, no NS_GET_* ioctls, and
open(O_CREAT) through a link does not follow it.

## /proc/<pid>/mounts: no POLLERR|POLLPRI on a mount change

**Location**: `fs/proc/mod.rs` (`ProcfsFileOps::poll`)

mounts and mountinfo poll readable only: a change of the mount table
never reports POLLERR|POLLPRI (Linux mounts_poll: the namespace's
event count against the reader's).

## TSC trusted without the invariant flag

**Location**: `arch/x86_64/tsc.rs`

A TSC without the invariant flag only logs a warning and stays the
clocksource. Linux marks it unstable (check_system_tsc_reliable,
mark_tsc_unstable, the clocksource watchdog) and falls back to HPET or
the ACPI PM timer, which hk lacks.

## adjtimex does not steer the clock

**Location**: `time/time_syscall.rs`, `time/mod.rs`

adjtimex keeps and reports the NTP frequency (ADJ_FREQUENCY) and the
tick, but neither changes how fast the clock runs (Linux
ntp_update_frequency), and maxerror does not grow each second (Linux
second_overflow).

## Signal delivery ignores sigaltstack

sigaltstack() records the stack (signal/syscall.rs), but
setup_rt_frame on both arches never reads it or SA_ONSTACK: the frame
always goes on the current stack, and uc_stack reports SS_DISABLE.
A SIGSEGV handler meant to catch stack overflow (Rust std, Go) faults
on the overflowed stack and the process dies. Linux get_sigframe /
sigsp switch to the alt stack, __save_altstack fills uc_stack.

## Errno differs from Linux

- **timerfd_create, eventfd2 return EMFILE for any create failure**
  (time/time_syscall.rs): the create can only fail with ENOMEM;
  Linux returns ENOMEM. The callee's error is dropped.
- **unshare returns EINVAL for any NsProxy::copy failure** (ns/mod.rs):
  Linux returns copy's error (ENOMEM, ENOSPC at the nesting limit).
- **pid and user namespace nesting limits return EAGAIN** (ns/pid.rs,
  ns/user.rs clone_ns): Linux create_pid_namespace and create_user_ns
  return ENOSPC past MAX_*_NS_LEVEL.
- **Fixed errnos in place of the callee's** in epoll_create1,
  inotify_init1, fanotify_init, io_uring_setup and signalfd4
  (`Err(_) => return <errno>`): the callee's KernelError is dropped,
  so a new failure mode is silently remapped.

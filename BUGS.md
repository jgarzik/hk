# Known Bugs

## Seen on both hk and the Linux reference

Failures that also occur when the boot tester runs on real Linux
(`check-linux*`). The cause may be the test, the environment, or a
real bug in Linux as well as hk: Linux is the reference, not
infallible, so each one is investigated, not written off.

- **BUSYBOX_NC_LO flaky, on hk and the Linux reference** (next
  batch): `BUSYBOX_NC_LO:FAIL status=0` (nc over loopback) in 1 of 5
  x86 `check-linux` runs, and in an hk x86 boot with one CPU
  (`QEMU_SMP=1`). Cause unknown: the test waits for the listener
  (`wait_listen`) and retries the client. Seen again on 2026-11-03:
  three uncached x86 `check-linux` runs and one hk x86 boot (each
  passed on rerun).
- **SWAPOUT_PAGEOUT flaky on the Linux reference** (J): one x86
  `check-linux` run had free swap 364 kB off the expected value after
  MADV_PAGEOUT of 16 MiB (beyond the test's tolerance), passing on the
  rerun. Linux's swap accounting after pageout is not exact (swap
  cache); the tolerance may need to grow on Linux.

## Safe kernel code that can cause UB (doc/UNSAFE.md)

These are safe fns or patterns whose use leads to undefined behaviour.
None is known to fail today, but each is a soundness bug:

- **Safe fns that take addresses:**
  - aarch64/x86 paging `entry_atomic` returns `&'static AtomicU64` into
    a table that can be freed; the mm `pte` helpers take `*mut u64`.

## unsafe not yet wrapped or documented (doc/UNSAFE.md)

There are 71 files with `#![allow(clippy::undocumented_unsafe_blocks)]
// TODO(unsafe)` (`git grep -l 'TODO(unsafe)' -- '*.rs' ':!user'`). Most of their
blocks belong in a missing wrapper:

- **Frames:** an owned / page-locked / PTL-held frame borrow type in
  place of the `frame_bytes` unsafe fn (17 callers: vfat, pipe, splice,
  exec, fault, filemap, swap).
- **Page tables:** a table / `Pte` reference type made only by the
  walker and tied to the mmap_lock / PTL. It replaces `entry_atomic`,
  `pagewalk::entry` and the `*mut u64` PTE helpers (the soundness item
  above), and the boot kmap and ioremap walkers.
- **DMA:** an owned `DmaBox<T: Pod>` with volatile field access, never
  `&T` into device-written memory: xhci rings and contexts, virtio
  rings and blk, e1000 descriptors, virtio-net buffers.
- **MMIO:** the remaining raw MMIO users move to `mmio::IoMem`: xhci
  operational/runtime registers, gfx framebuffer, vgacon, rtc,
  pci_quirks, aarch64 serial, x86 power.
- **Lists:** an intrusive `CursorMut` for the walk-and-remove loops
  (futex, waitqueue, sched, percpu).
- **Callbacks:** typed callback context (`register_irq<T: Sync>`,
  timer container_of, `smp_call<T: Sync>`) in place of `*mut ()` data
  casts.

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
with tasks) is not enforced.

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

## Network stack gaps (later phases of the network chunk)

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

## Memory management gaps

**Location**: `mm/`, `arch/*/paging.rs`, `ipc/shm.rs`

Missing:

- Writeback (P5): the periodic pass writes every dirty inode of a
  device (Linux only those dirty for vm.dirty_expire_centisecs, which
  is stored but unused); past vm.dirty_ratio the writer writes its own
  inode back synchronously instead of sleeping in balance_dirty_pages;
  the limits are fractions of all managed memory (Linux: dirtyable
  memory). No errseq: fsync reports a writeback error once, to the
  caller that ran the writeback, not to every open file.

- Reclaim (P4) drops clean, unmapped page-cache pages inode by inode
  (no file LRU, no aging: Linux reclaims the oldest file pages; dirty
  or mapped ones stay until written back or unmapped), then swaps out
  private anonymous pages, also for MADV_PAGEOUT: no accessed-bit aging
  (pages are reclaimed oldest first), synchronous writes, no kswapd; 2MB pages stay
  off the LRU (never reclaimed whole; a split puts their 4KB pages on
  it). Pages exec copies the image into (see the heap section) are not
  on the reverse map (never swapped). An active swap file can still
  be mapped writable (Linux: no write access to an S_SWAPFILE inode),
  and copy_file_range into it is not refused (Linux ETXTBSY). Swap
  files go through their filesystem's swap_rw,
  a page at a time (walking the cluster chain each time; Linux maps
  the extents once at swapon). Page faults, swapoff, page-cache, heap
  and pipe allocations that may sleep reclaim directly; atomic heap
  allocations never do, so with anonymous memory filling RAM they fail
  at the low watermark until kswapd (P6) keeps free memory above it.
- SysV shm: IPC_RMID removes the id at once (Linux keeps it, as
  IPC_PRIVATE with SHM_DEST, until the last detach: IPC_STAT and shmat
  by id still work there).
- File mappings: no fault-around (Linux maps up to 16 cached pages
  per read fault); filesystems without a page cache (procfs) still
  map a private copy. A truncate racing an mremap or fork of a mapping of
  the file can miss entries in flight: mremap unlinks the old VMA from
  i_mmap before its i_mmap-locked entry move, fork copies the parent's
  entries after linking the child (Linux takes the rmap locks across
  move_vma, and fork does not copy shared file entries).
- MADV_REMOVE of a file mapping is EOPNOTSUPP (no filesystem punches
  holes); shmdt needs the address an attachment starts at (Linux also
  finds a piece moved by mremap); SHM_EXEC is ignored.
- Remote writes (ptrace POKEDATA/POKETEXT, process_vm_writev) need a
  writable VMA: POKE into read-only text fails with EIO (Linux
  FOLL_FORCE writes a private copy, e.g. for breakpoints), and a page
  not yet faulted in is not faulted (EIO / short write).
- munmap or MADV_DONTNEED of part of a 2MB page that cannot be split
  (out of memory) leaves the whole page mapped (Linux preallocates the
  page table); shmat checks RLIMIT_AS before SHM_REMAP unmaps the old
  range, and an address that SHM_RND rounds to 0 is EPERM (Linux picks
  an address).
- vm.max_map_count is enforced for mmap, brk, munmap and MAP_FIXED
  holes, mprotect, madvise and mremap, not for the splits of mlock
  (Linux mlock_fixup fails with ENOMEM there). A locked mapping grown
  by mremap is not faulted in (Linux populates it).

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
- Nodemasks are one `u64` (64 nodes); no multi-node QEMU test config.
- Node numbers are the firmware's (SRAT proximity domain, DT
  `numa-node-id`) used as is: sparse or large domains leave holes or
  are dropped (>= 64), and node 0 may not exist (Linux pxm_to_node
  numbers the domains from 0).
- The boot topology dump (`print_topology`) runs before any CPU has
  come up (`cpu_up`), so with real NUMA tables every node shows 0 CPUs.

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
CPU timer signals carry no siginfo (no si_timerid/si_overrun). rseq is
ENOSYS (glibc runs without it).

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

## File lock gaps

**Location**: `fs/locks.rs`, `fs/posix_lock.rs`

POSIX lock owners are pids, not the files_struct (Linux fl_owner):
threads of one process share them, but a CLONE_FILES child that is
another process has its own (Linux: one owner), and a process's locks
are released at its exit through a global list of the inodes with
POSIX locks (searched on each F_SETLK, scanned at each exit). No
leases (F_SETLEASE) and no OFD locks (F_OFD_*).

## seccomp gaps

**Location**: `seccomp/`

SIGSYS from SECCOMP_RET_TRAP carries no siginfo (si_code SYS_SECCOMP,
si_syscall, si_arch, si_errno, si_call_addr): hk has no siginfo queue
(signals are a bitmask). No PTRACE_EVENT_SECCOMP (RET_TRACE is ENOSYS
as with no tracer), no user notification (SECCOMP_RET_USER_NOTIF,
SECCOMP_GET_NOTIF_SIZES), no FLAG_TSYNC_ESRCH / FLAG_SPEC_ALLOW /
FLAG_WAIT_KILLABLE_RECV, and nothing is logged for RET_LOG or
FLAG_LOG.

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

Missing: fs.protected_hardlinks/symlinks/fifos/regular do not exist
(behave as their kernel default 0); no
immutable/append-only inodes (no IS_APPEND/IS_IMMUTABLE EPERM).

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
- PCI: no resource/resourceN/rom/enable/numa_node/local_cpus files;
  config is 256 bytes even for PCIe functions (no extended space).
- cpu: no cpuN/topology, cache/ or online files and no MODALIAS
  (CONFIG_GENERIC_CPU_AUTOPROBE); node: no meminfo/numastat/vmstat.
- net: no queues/, phys_port_*, speed/duplex, ifalias or gro files;
  interfaces cannot be renamed or moved between namespaces, so no
  "move" uevents.
- chmod/chown on sysfs files change the inode only: a later lookup of a
  dropped dentry shows the original mode (Linux keeps kernfs iattrs).
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
- **Pid namespaces:** TIOCGPGRP/TIOCGSID return global numbers (Linux
  pid_vnr: the caller's namespace).

## Futex gaps

**Location:** `task/futex.rs`

- **FUTEX_WAKE_OP and PI futexes** are missing (the user cmpxchg they
  need, `uaccess::cmpxchg_user_u32`, exists).
- **MAP_PRIVATE file mappings:** a shared futex there is keyed by
  (mm, address) from the VMA; Linux keys a page still in the page
  cache (not yet COW'd) by inode and offset, so a MAP_SHARED mapping
  of the same file wakes it.

## FIONREAD on pipes is 0

**Location:** `fs/misc.rs` (sys_ioctl)

The generic FIONREAD arm answers every file except chardevs with 0,
so a pipe or FIFO with data reports 0. Linux do_vfs_ioctl handles
FIONREAD only for regular files and passes the rest to f_op->ioctl
(pipe_ioctl returns the buffered bytes).

## Sleeping-lock gaps

**Location**: `sync` (RwSem)

`RwSem` has no `_interruptible` variants.

## Mount flag gaps

**Location**: `fs/misc.rs` sys_mount/sys_umount2, `fs/mount.rs`

Accepted without effect: atime flags (no atime updates), MS_SILENT,
MS_MANDLOCK, MS_POSIXACL, MS_I_VERSION, MS_LAZYTIME.
EINVAL instead of Linux behavior: MS_SYNCHRONOUS, MS_DIRSYNC and
MS_NOSYMFOLLOW. Propagation (`fs/pnode.rs`): a propagated copy lands
on top of what is already mounted at the target (Linux tucks it
under); a slave's master is its master's peer group, not one mount;
copies of a namespace are always peers and not locked (Linux
copy_mnt_ns for a less privileged user namespace makes shared mounts
slaves, CL_SHARED_TO_SLAVE, and locks them, lock_mnt_tree): harmless
while CLONE_NEWNS needs root and mounts ignore user namespaces, but
required before mounts become user-namespace aware. umount2 MNT_EXPIRE's
mark is not cleared by use (Linux mntput clears it).
Unlike Linux (MNT_WRITE_HOLD), a write access racing a read-only remount
that then fails with EBUSY can see a spurious EROFS. Mount options are parsed by vfat (Linux's set; long names
UTF-16 in UTF-8, iso8859-1 or cp437 only) and ramfs (mode=); procfs,
devtmpfs and cgroupfs ignore theirs; mounts are not user-namespace aware (plain capable()).
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

## Thread-group exit gaps

**Location**: `signal/mod.rs` (group exit), `task/exec.rs`
de_thread

- Process-directed signals go to one thread's private queue (the
  leader, or a live thread once it has exited), not the shared queue
  with Linux's thread choice at delivery; a pidfd polls readable when
  the leader exits, not when the whole group is gone.

## ptrace stop gaps

**Location**: `task/ptrace.rs`, `task/exec.rs`,
`signal/mod.rs`

Signal-delivery and PTRACE_SYSCALL stops work. Missing: exec, fork,
clone and exit event stops (PTRACE_O_TRACEEXEC and friends,
PTRACE_EVENT_*), PTRACE_INTERRUPT/LISTEN, group-stop interaction (SIGSTOP
to an untraced task is ignored: stop/continue are not implemented),
and the tracee's exit being
reported to a tracer that is not its parent.

## NETLINK_ROUTE / SIOC* subset gaps (P3)

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

**Location**: host, not hk (QEMU 8.2.2 TCG on this Core Ultra 9 285K,
microcode 0x11b, `make check-arm`)

Six qemu-system-aarch64 deaths on 2026-10-18 (kernel log: 03:59,
08:23, 10:04, 14:18, 15:05, 18:08), all in the guest stage-1 page
table walk, five at the same instruction: `mov (%rax),%r10` in
arm_ldq_ptw (target/arm/ptw.c:671, `qatomic_read(host)` of a
descriptor), the sixth a store to `env` in S1_ptw_translate
(ptw.c:576). The faults reported for that one load differ: "segfault
at 0", "segfault at fffffffe" (error 4) and three "general protection
fault" (a non-canonical address). The one core dump (apport,
/var/crash, 03:59) shows rax = 0x76fde8416008, a valid pointer into
the mapped guest RAM (the descriptor there, 0x40617003, is a valid
table entry) while the kernel saw the access at address 0, and siginfo
si_addr is 0. A load cannot fault at an address other than the one
its register holds, so the CPU computed a wrong address for it. The
three segfaults with a CPU named all ran on CPU 5; CPUs 5 and 2 are
the 7.2 GHz favored cores, and they lead the host's segfault count
since 2026-09 (28 and 21 of ~140, any program; cc1, make and valgrind
also crashed). The guest's part: hk's fork/exit churn (RLIMIT_NPROC,
FD_LEAK) makes QEMU walk page tables hardest.

Not seen in ~3 h of check-arm loops (5 to 9 QEMUs at once, all under
gdb, ~100 boots plus ~90 churn-only runs, some pinned to CPUs 5, 2 or
12) after 19:30, when the host stopped logging segfaults altogether.
Nothing in hk can avoid it. Next: check the BIOS for Intel default
power/turbo settings and current microcode, stress-test CPUs 2 and 5,
or keep gate QEMUs off them (taskset) and see whether the crash stops.

## Interrupts run on the task stack (no IRQ stacks)

**Location**: `arch/aarch64/vectors.S`, `arch/x86_64/`
(IRQ entry)

An interrupt pushes its trap frame (0x320 bytes on arm64, with the
FP/SIMD registers) and handler frames onto whatever 16 KB task stack
it lands on, so the deepest syscall path plus the deepest interrupt
must fit in one stack. An overflow now faults in the guard gap below
the stack ("kernel stack overflow" panic, `mm::vmstack`) instead of
corrupting memory. Linux has per-CPU IRQ stacks (x86 hardirq_stack,
arm64 irq_stack).

## Rare arm64 kernel instruction abort in the fault-signal tests

**Location**: unknown (CPU 0, right after `FAULT_SEGV_ACCERR`, i.e. while
`FAULT_SIGILL` runs `udf` in user mode)

Seen once in ~100 `make check-arm` runs (QEMU neoverse-n1 with PAN, -smp
4): "KERNEL PANIC ... exceptions.rs:95" (kernel instruction abort). The
panic handler then dropped formatted messages, so ELR/FAR were lost.
Not reproduced in 90 further runs (sequential and 8 in
parallel). Next occurrence: capture the Message line.

## ramfs has no size limit

**Location**: `fs/ramfs.rs`, `mm/filemap.rs`,
`mm/frame_alloc.rs`

ramfs (the root filesystem and every ramfs mount) is bounded only by
memory, for every user: writes fail with ENOSPC once free frames reach
the low watermark (min_free_kbytes formula), and the memory comes back when the last link and the last
open reference of a file are gone (or on truncate). Linux's rootfs is a
tmpfs limited to half of RAM by default; tmpfs with `size=`/`nr_inodes=`
limits (and per-user accounting) comes with the filesystem chunk.
Reads of holes need a zeroed page each and can fail with ENOMEM when
memory is at the low watermark (Linux maps the shared zero page).

## Kernel heap (slab) gaps

**Location**: `mm/slab.rs`, `mm/heap.rs`

The heap is the slab allocator over the page allocator, so it grows
with RAM; what is missing: no shrinker (caches give back empty slabs
beyond two each, but nothing asks them under pressure), no slab
merging, poisoning or red zones.

Heap allocations cannot fail gracefully (Rust's global allocator): one
the page allocator cannot meet panics. Buffers sized by a syscall
argument use `kmem::try_vec` (ENOMEM) where the size was unbounded
(listxattr, keyctl read/update, process_vm, io_uring fixed files, bpf
array maps); the many sites bounded by a sysctl or a constant still
allocate infallibly. The heap goes down to the min
watermark while user data stops at low (also after direct reclaim:
user allocations stop at low until the OOM killer (P6); then Linux's
min), so only kernel objects can get there (no memcg or OOM killer bounds what a process pins in pipes,
sockets or fds); a large contiguous kmalloc can fail first (over 4MB
always, no vmalloc; above low - min, about 700KB at 512MB, once free
memory is near the low watermark).

exec maps PT_LOAD segments from the page cache, except a static PIE
with no interpreter (hk relocates it in the kernel, so its pages are
private copies; Linux applies no relocations at all) and the partial
last page and bss of each segment (copied). Kernel object leaks cost free
memory: each fork+exec keeps two dentries and two inodes plus ~900
bytes of kmalloc (~1.3KB, measured before procfs entries of released
tasks were flushed and the dcache got a shrinker; not measured since). The MM_LIFE tests count MemFree + Slab so they check user memory only; these leaks
are listed here instead.

## The memory cgroup's memory.max is not enforced

**Location**: `cgroup/memory.rs`, `mm/fault.rs`, `mm/shmem.rs`

memory.max, memory.current and memory.events exist, but nothing calls
`try_charge_memory`/`uncharge_memory`: page faults (anonymous and
shmem) and page tables are never charged, freed pages never uncharged,
and memory.events oom/oom_kill stay 0. Linux charges each page to its
memcg (folio memcg_data, mem_cgroup_charge), uncharges on free, and
over the limit reclaims, then OOM-kills a task in the cgroup
(mem_cgroup_out_of_memory).

Once enforced, OOM_FAULT_KILL and OOM_SHARED_KILL can run in a small
cgroup (say memory.max 64MB) at any RAM size, and on Linux too,
instead of filling all of RAM and being skipped above 4GB
(`user/boot_tester/tests/mm_oom.rs`).

## BPF map memory is not charged

**Location**: `bpf/map.rs`

An array map refuses a preallocation over half of free memory, but
nothing adds maps up: no RLIMIT_MEMLOCK or memcg charge (Linux
bpf_map_charge_memlock / memcg accounting), so many maps can still use
up memory.

## Heap allocations in atomic context are not reported

**Location**: `mm/slab.rs` (`heap_gfp`), `sync/lockdep.rs`

The heap picks GFP_ATOMIC by itself under a spin lock or with
interrupts off, so an allocation there takes the atomic reserve
silently. Linux needs an explicit GFP_ATOMIC and might_alloc reports a
GFP_KERNEL allocation in atomic context. LOCKDEP has no such report
(the T0 design's `atomic_alloc()` scope): the global allocator has no
call site to attribute it to, so the sites (allocations under spin locks
across net, fs, ipc) cannot be audited yet.

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

Found while chasing the Dell OptiPlex 3020 freeze; QEMU's xHCI hides
all of them.
- Command completions are not matched to their TRB (`wait_for_command`
  ignores `_trb_addr`), and transfer events only by slot and endpoint:
  a late completion for a timed-out command or transfer is credited to
  the next one (most likely on the USB serial console, whose transfers
  time out after 100 ms). A timeout should stop the endpoint and move
  its dequeue pointer past the TRB (Linux xhci_handle_cmd_stop_ep).
  Bulk and control transfers already match their own TRBs
  (`wait_for_trbs`) and leak a timed-out transfer's bounce buffer, so
  a late completion is dropped and its write lands nowhere in use;
  commands still match by slot and endpoint only.
- One controller only: the driver keeps a single global
  `USB_CONTROLLER`; a second xHCI's probe replaces the first, which is
  left running, and both device handles act on the survivor at
  shutdown (unbinding the first stops neither).
- A timed-out bulk transfer returns early (`do_bulk_out`/`do_bulk_in`
  via `?`) without `dma_unmap` and with its TRB still queued; the
  buffer (heap, freed by the caller) can still be written by the
  controller.
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
and r8169 all support.

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

## Block layer gaps (P1)

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
- A removed kernfs binary attribute (`Kind::Bin`, e.g. PCI `config`)
  keeps its operations, and so the object behind them, while a stale
  dentry or open file holds the node (text attributes drop theirs).
- No /proc/devices block section; the first disk
  registered decides the dynamic major (254 down, like Linux, but Linux
  usually has other dynamic majors registered first).
- A mounted filesystem or active swap opens its block device, but not
  exclusively: opening it O_EXCL and BLKBSZSET on a mounted partition
  are not refused.

fallocate on a block device is EOPNOTSUPP (Linux blkdev_fallocate zeroes
or discards the range).

## Code-quality audit findings (2026-11-01), by phase

From a whole-tree audit for designs that grew one commit at a time.
Fixed already: clock setting, seccomp actions, kcmp/pidfd_getfd access,
sched pid 0, flock/POSIX release, signalfd reader, errno flattening.

- **Syscalls that do not deliver** (H/C): inotify and fanotify never
  queue an event (no fsnotify hooks in the VFS); there is no siginfo
  queue (signals are a bitmask: rt_sigqueueinfo's data, si_pid/si_uid
  and RT signal queueing are lost); waitid without WEXITED is EINVAL
  (C).
- **Copied helpers** (J, or as touched): `get_nofile_limit` in eight
  places; `find_task_by_pid` in four (all root-namespace pids); four
  `current_time`s; about ten user-timespec readers each validating
  (Linux get_timespec64); three iovec structs and five
  importers; five SigInfo, three Timeval, two Timespec types.
- **Error conventions** (as touched): Result<_, KernelError> about 618
  times, Result<_, i32> 91 (both signs used), Result<_, i64> 36; about
  187 raw errno numbers and 62 local errno constants.
- **Process-wide state per thread** (C): pgid/sid copied into every
  thread; shared pending signals beside SignalStruct; one global
  CHILD_EXIT_WQ wakes every waiting parent on every exit.
- **`task/percpu.rs` is 4,500 lines** (before C): scheduler core,
  do_clone (523 lines), exit, wait, credential setters, five sleep
  APIs. Split like Linux (sched/core, fork, exit, cred). Other giants:
  sys_prctl, do_semctl, sys_mmap, exec_file, sys_fcntl.
- **Arch code in generic files** (J): 93 `cfg(target_arch)` outside
  `arch/` (main.rs, hw/dma.rs, percpu.rs, misc, pci, seccomp's audit
  arch), 32 direct `arch::x86_64::`/`aarch64::` references, three
  `CurrentArch` redefinitions.
- **Globals where per-CPU fits** (I/C/E): TCP timers in one map run on
  softnet/0 only; CHILD_EXIT_WQ.
- **ID allocators** (J): PidMap, fdbits, IPC ids, and plain counters
  (bpf, keys, mqueue, posix timers, which wrap with no collision
  check): one IDR/IDA.
- **procfs** (H): every read regenerates the whole file and slices it
  (no seq_file records, so chunked reads of /proc/net/* can tear);
  global generators run under the procfs inode's read lock and take
  TASKLIST and network locks inside it (not in LOCKING.md).
  /proc/sys is one static tree: the sysctls Linux registers for the
  initial network namespace only (net/ipv4/tcp_mem,
  net/core/mem_pcpu_rsv) appear in every
  namespace. /proc/sys/net values act on the namespace of the task
  reading or writing, not the one the file was opened in (Linux binds
  the file to the opener's namespace): an fd passed across namespaces
  reads and writes the other one's values.
- **Stale comments and dead code** (as touched): about 155
  `#[allow(dead_code)]`, 90 "for now"/TODO markers; comments that
  contradict the code in `ns/mod.rs` (setns) and `task/misc.rs`.

## P2 review findings (open)
From the P2 /code-review (unverified). Tag = roadmap phase (doc/ROADMAP.md).
1. **pcp_free drains the hot end** (J).
   `mm/page_alloc.rs:458`: freed page pushed at head, drain
   pops from head; Linux returns the cold tail.
2. **arm64 /reserved-memory no-map regions are linear-mapped**
   (D; real HW). `arch/aarch64/dtb.rs:175`: Linux
   memblock_mark_nomap removes them (speculative access to secure
   carve-outs).

## P3 review findings (open)
From the P3 /code-review (unverified). Tag = roadmap phase (doc/ROADMAP.md).
1. **Remote write gives up after 16 COW tries** (C, with
   FOLL_FORCE).
   `mm/remote.rs:176`: spurious EFAULT; break COW and write
   under one PTE-lock hold, or loop until fatal_signal_pending.

## Fix batch 1 review findings (open)
From the fix-batch-1 /code-review (unverified). Tag = roadmap phase (doc/ROADMAP.md).
3. **memblock holds at most 128 ranges** (J). `mm/memblock.rs:18`:
   a firmware map with more RAM or reserved ranges panics at boot
   (asserts in add/remove/reserve); Linux grows the array
   (memblock_double_array).

## P4 review findings (open)
From the P4 /code-review (unverified unless noted). Tag = roadmap phase (doc/ROADMAP.md).

4. **LRU batch refs defeat exclusivity checks** (J).
   `mm/fault.rs:477` / `:545`: refcount==1 tests fail while a
   page sits in the per-CPU add batch → needless COW copies after
   swap-in. Linux drains and rechecks (wp_can_reuse_anon_folio).
5. **alloc_slot linear scan under SwapInfo.map; two Vecs + sort per
   reclaimed page** (J). `mm/swap.rs:184`: cluster/free-hint
   allocator, cached sorted device list.
7. **One AnonVma per fork family, Vec chain** (J).
   `mm/anon_vma.rs:85`: O(N×VMAs) under one family write lock.

## T0 findings (open)
Found during T0 (2026-10-19). Tag = roadmap phase (doc/ROADMAP.md).
1. **Syscalls report root-namespace pids** (C). Tasks get a number in
   every level of their pid namespace chain (`task/pid.rs`), but
   getpid/gettid/kill/wait//proc use the root number; a CLONE_NEWPID
   child is not pid 1 in its namespace. Use `Pid::nr_in(caller's ns)`
   at the syscall boundary.
6. **No ptrace exec stop** (C): a traced task's execve does not stop
   with SIGTRAP / PTRACE_EVENT_EXEC (`task/exec.rs`), so a
   tracer cannot observe a non-leader exec's tid change.
8. **MM_LIFE_EXEC_CHAIN intermittent on arm64 CI** (flake:
   investigate when it repeats). One
   GitHub `check-arm` run (TCG, NIC=e1000) reported
   `MM_LIFE_EXEC_CHAIN:FAIL -2`: both warmup chains passed, then the
   first measured one's child (busybox `env` x40 then `true`, i.e. 41
   execs in one process) exited nonzero. A failed exec, not a leak.
   MM_LIFE now prints a failing child's wait status (exit code vs
   signal); 16 eight-CPU arm64 stress boots did not repeat it.
10. **Network test flake** (suspected TcpSock.connecting beside the
   state, which phase L moved under `cb`; drop if check-stress stays clean):
   `SOCKCORE_CONNECT_REFUSED:FAIL SO_ERROR got 0` (hk arm64, 1 of 10
   `check-stress` boots: poll reported POLLOUT for a nonblocking
   connect to a just-closed loopback port, but no ECONNREFUSED was
   pending).
11. **TCP_PROC_NET flake** (cause unknown): one end of a fresh,
   accepted loopback connection is missing from /proc/net/tcp as state
   01: `client line got 0` (CI hk arm64) and `server line got 0` (1 of
   20 check-stress boots, hk arm64). Not a torn read: the file comes in
   one regeneration (well under the 64 KiB read chunk). Not ehash
   removal by key (removals check the entry). The test now prints the
   lines with either port when it fails.

## CVE-pattern audit findings (2026-11-05)

From an audit against the Linux CVE-fix pattern catalog (P# = its
pattern number). Ranked.

1. **tkill, tgkill, rt_(tg)sigqueueinfo and pidfd_send_signal skip the
   kill permission check** (P4, check skipped on one path).
   `signal/syscall.rs:405,417,456,512`, `task/misc.rs:1334`: only
   kill(2) calls `check_kill_permission`; these send straight through
   `send_signal`, so any user can SIGKILL any other user's process
   (root daemons; pidfd_open is unprivileged too). Linux runs
   check_kill_permission on all of them (do_send_specific,
   kill_pid_info_type).
2. **SIGKILL/SIGSTOP can be blocked** (P4, check skipped on one path).
   rt_sigreturn stores `uc_sigmask` as is (`arch/x86_64/signal.rs:539`,
   `arch/aarch64/signal.rs:520`) and rt_sigaction keeps them in
   `sa_mask` (`signal/syscall.rs:63`, applied at handler entry in
   `signal/mod.rs:1954`). A blocked SIGKILL is neither fatal on arrival
   nor dequeued, so a process makes itself unkillable. Linux
   set_current_blocked and do_sigaction strip both.
3. **Keys: link and destination checks missing** (P4). add_key takes a
   destination keyring by serial without KEY_NEED_WRITE
   (`keys/syscall.rs:84`); KEYCTL_LINK does not need KEY_NEED_LINK on
   the key (`keys/keyctl.rs:285`); KEYCTL_SEARCH needs no SEARCH on the
   keyring or the keys it walks and links into `dest` unchecked
   (`keys/keyctl.rs:399,409`); request_key links into `dest` unchecked
   (`keys/syscall.rs:173`). Serials are sequential, so a user links
   another user's key into its own session keyring, then possesses it
   (KEY_POS_ALL) and KEYCTL_READs the payload. Linux lookup_user_key
   with KEY_NEED_WRITE / KEY_NEED_LINK / KEY_NEED_SEARCH.
4. **Nested epoll has no loop or depth check** (P8, recursion through
   poll). `io/epoll.rs:449` refuses only adding an epoll to itself, and
   `Eventpoll::poll` (`io/epoll.rs:281`) polls its items under its own
   IrqSpinlock: A in B in A deadlocks the CPU with interrupts off on
   the first epoll_wait, and a long chain recurses off the stack. Linux
   ep_loop_check: ELOOP for cycles and nesting past EP_MAX_NESTS (4).
5. **An epoll item keeps its file open** (P1, use after teardown).
   `EpItem.file` is an `Arc<File>` (`io/epoll.rs:86`) and nothing
   removes items at the file's last close (no eventpoll_release): a
   closed pipe write end registered in an epoll never gives the reader
   EOF, a closed socket is never released, and epoll_wait keeps
   reporting it. Linux epitems hold no reference; __fput removes them.
6. **Keys have no quota** (P13). add_key (`keys/syscall.rs:42`) takes
   up to 1MB per key with no per-user count or byte limit, so any user
   can fill the kernel heap (whose exhaustion panics). Linux
   key_payload_reserve / key_user: maxkeys 200, maxbytes 20000 for
   non-root (/proc/sys/kernel/keys/*).
7. **bpf() is open to unprivileged users** (P9). `bpf/syscall.rs:228`
   has no capability check: any user creates maps (uncharged, see
   above) and loads programs. Linux's default
   kernel.unprivileged_bpf_disabled=2 (BPF_UNPRIV_DEFAULT_OFF) makes
   map_create and prog_load EPERM without CAP_BPF.
8. **mmap offset + length is not checked for wrap** (P6).
   `mm/syscall.rs:78`: a file offset near 2^64 wraps the page index of
   the mapping's pages; Linux do_mmap is EOVERFLOW when
   pgoff + (len >> PAGE_SHIFT) wraps.
9. **pwrite/write past LLONG_MAX is not refused** (P6). `fs/io.rs:210`
   checks only `offset >= 0` and there is no s_maxbytes: pos + count
   can exceed i64::MAX, giving a negative st_size and lseek results
   that read as errnos. Linux rw_verify_area (EINVAL) and
   generic_write_check_limits (EFBIG at MAX_LFS_FILESIZE).

## Review findings (2026-11-05): allocation sizing, pure code (unverified)

From a read-only review of allocation sizing (~/tmp/hk-with-capacity.md)
and of host-testable code (~/tmp/hk-unit-test-opportunities.md). Not yet
confirmed by a test. Ranked.

1. **Unprivileged kernel panics by allocation size** (heap objects are
   at most 4 MiB, MAX_KMALLOC; an infallible allocation that fails
   panics):
   - `ipc/mqueue.rs:741,803`: mq_open accepts msgsize up to 16 MiB with
     no limit check (Linux mq_attr_ok: msg_max/msgsize_max unless
     CAP_SYS_RESOURCE, RLIMIT_MSGQUEUE), then send/receive allocate
     `vec![0; msgsize]`.
   - `net/msg.rs:91` (`gather_at`): AF_UNIX dgram and netlink sends up
     to sndbuf (8 MiB unprivileged) are gathered into one Vec; also
     `net/netlink/rtnetlink.rs:170`. Fix: `kmem::try_vec`, ENOBUFS.
   - `fs/vfat.rs:862`: `extend_cluster_chain` collects every new
     cluster (ftruncate to 4 GiB with 512-byte clusters: 32 MiB).
     `sectors_per_cluster` 0 from disk divides by zero at `:166,:806`.
   - TCP receive/send VecDeques double under `cb` past 4 MiB with
     large SO_RCVBUF/SO_SNDBUF (`net/tcp/input.rs:547`, `cb.rs:945`).
   - Bounded but large, ENOMEM on Linux: io_uring rings (2 MiB), keys
     (1 MiB), `task/id.rs:625` (256 KiB).
2. **seccomp cBPF** (`bpf/convert.rs`, `bpf/interp.rs`):
   - jeq/jgt/jge against a constant >= 0x80000000 never match (the
     constant is sign-extended against a zero-extended u32): the
     `jeq #AUDIT_ARCH_X86_64` (0xC000003E) every libseccomp, systemd
     and container filter starts with fails.
   - A jump with jt=jf=0 emits no instruction but `fixup_jumps` still
     consumes an offset: later jumps shift, can index past the program
     (panic) or loop backwards (hang); reachable unprivileged with
     no_new_privs.
   - R10 is 0, so scratch-memory ST/LD always fail (KILL_THREAD).
   - `validate_cbpf` accepts what Linux rejects (H/B/IND/MSH loads,
     unaligned or out-of-range `ld [k]`, `div #0`, `ret x`); ALU32
     DIV/MOD by a constant >= 2^31 is wrong.
3. **ABI**: `acct` ac_etime is seconds where Linux has AHZ ticks, and
   encode_comp_t skips Linux's rounding; getxattr ERANGE above 64 KiB
   (Linux clamps); epoll_wait maxevents capped at 4096 and poll at
   1024 fds (Linux: ~INT_MAX/12, RLIMIT_NOFILE); sysctl integers are
   not parsed in base 0 (`0x10`, `010`) and `+5` is accepted.
4. **Minor**: `fs/posix_lock.rs:328` `-l_len` overflows at i64::MIN
   and lengths past i64::MAX are not EOVERFLOW; `arch/x86_64/rtc.rs:131`
   panics on a CMOS month >= 14; vfat short names can start with a
   space.

# Known Bugs

## Safe kernel code that can cause UB (doc/UNSAFE.md)

These are safe fns or patterns whose use leads to undefined behaviour.
None is known to fail today, but each is a soundness bug:

- **Drivers:**
  - `DmaCoherent` has public fields and `dma_free_coherent` is safe.
  - `dma_map_single` takes a raw pointer, not tied to the buffer's
    lifetime.
  - xHCI `OutputContext` hands out `&` into memory the device writes.
- **Safe fns that take addresses:**
  - `load_mm`, `dtb::blob`, `psci_cpu_on`.
  - `save_for_clone_child`, `write_fs_base`, `fpu::restore`.
  - `entry_atomic`, `virtio_net::rx_skb`.
  - mm `pte` helpers that take `*mut u64`.
  - `pfn_to_page` (checks its argument only in debug builds).
- **asm options:** `nomem` on aarch64 `enable_and_halt`, on x86
  `stac`/`clac` and on `wrmsr`.
- **Inode locks:** `unlock_rename` and `inode_lock`/`inode_unlock` are
  hand-paired, and `unlock_rename` is a safe fn.

## Path names must be valid UTF-8

**Location:** `kernel/uaccess.rs` (`strncpy_from_user`).

Linux path names are any bytes except '/' and NUL. hk's VFS holds names
as `String`, so the path copy-in takes only valid UTF-8 and rejects
anything else. Mapping the other bytes to chars would let two different
byte names alias one String.

The callers turn every copy-in error into EFAULT, including the
rejection here and an overlong path, which Linux reports as
ENAMETOOLONG. The fix is byte-string names through the VFS, with one
`user_path_at` that maps errors (Phase G).

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

## chroot() does not affect path resolution (security)

**Location**: `kernel/fs/path.rs` ~131-135 (`walk`, absolute-path lookup)

`sys_chroot` records the new root (`fs.set_root`), but path walking
always starts absolute paths at the mount namespace root
(`mnt_ns.get_root_dentry()`) and never consults the task's fs root, so a
chrooted process can still reach everything. `..` at the chroot root is
not clamped either. Boot test `CHROOT` only verifies confinement on a
Linux host (`user/boot_tester/tests/permissions.rs`).

## Network stack gaps (later phases of the network chunk)

**Location**: `kernel/net/`

Listed because real traffic reaches them: TCP has no SACK (never
advertised), no CUBIC (only "reno"; Linux defaults to cubic), no
receive buffer autotuning (the window is SO_RCVBUF / 2), no per-netns
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

## Memory management gaps

**Location**: `kernel/mm/`, `kernel/arch/*/paging.rs`, `kernel/ipc/shm.rs`

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

## exec ignores set-user-ID / set-group-ID bits and file capabilities

**Location**: `kernel/task/exec.rs` (`do_execve`)

Linux execve of a file with S_ISUID / S_ISGID (on a mount without
nosuid, without no_new_privs or a ptracer in the way) sets the
effective (and saved) uid / gid to the file's owner, and file
capabilities (security.capability) raise the permitted set
(bprm_fill_uid, cap_bprm_creds_from_file). hk exec keeps the caller's
credentials unchanged, so set-id programs run unprivileged.

## CPU-time timer gaps

**Location**: `kernel/cpu_timer.rs`, `kernel/posix_timer.rs`

timer_create and clock_nanosleep take only the caller's own process
CPU clock (and its threads' for timer_create): another process's is
EINVAL (Linux runs those too, checked when that process runs). The
SCHED CPU clock counts utime + stime like PROF (Linux: exact runtime).
CPU timer signals carry no siginfo (no si_timerid/si_overrun). rseq is
ENOSYS (glibc runs without it).

## AF_PACKET gaps

**Location**: `kernel/net/packet/`

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

**Location**: `kernel/fs/locks.rs`, `kernel/fs/posix_lock.rs`

POSIX lock owners are pids, not the files_struct (Linux fl_owner):
threads of one process share them, but a CLONE_FILES child that is
another process has its own (Linux: one owner), and a process's locks
are released at its exit through a global list of the inodes with
POSIX locks (searched on each F_SETLK, scanned at each exit). No
leases (F_SETLEASE) and no OFD locks (F_OFD_*).

## seccomp gaps

**Location**: `kernel/seccomp/`

SIGSYS from SECCOMP_RET_TRAP carries no siginfo (si_code SYS_SECCOMP,
si_syscall, si_arch, si_errno, si_call_addr): hk has no siginfo queue
(signals are a bitmask). No PTRACE_EVENT_SECCOMP (RET_TRACE is ENOSYS
as with no tracer), no user notification (SECCOMP_RET_USER_NOTIF,
SECCOMP_GET_NOTIF_SIZES), no FLAG_TSYNC_ESRCH / FLAG_SPEC_ALLOW /
FLAG_WAIT_KILLABLE_RECV, and nothing is logged for RET_LOG or
FLAG_LOG.

## vmsplice from a pipe is not done

**Location**: `kernel/fs/splice.rs` (`sys_vmsplice`)

vmsplice on a pipe or FIFO open for writing copies user memory into it
(Linux vmsplice_to_pipe). On one open only for reading Linux copies the
pipe's data into the user iovecs (vmsplice_to_user); hk returns EBADF.

## AF_UNIX gaps

**Location**: `kernel/net/unix/`

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
can be pinned. Socket paths must be UTF-8 (other bytes are EINVAL).

Not implemented: MSG_OOB on streams (EOPNOTSUPP; Linux supports one
out-of-band byte), SO_PEEK_OFF, SO_PASSPIDFD / SCM_PIDFD /
SO_PEERPIDFD, SO_PEERGROUPS, SO_INQ / SCM_INQ, SO_RIGHTS_NOTRUNC,
SIOCUNIXFILE, SO_PEERSEC (ENOPROTOOPT, as on Linux without an LSM).

## File permission (DAC) gaps

**Location**: `kernel/fs/dac.rs`, `kernel/task/exec.rs`

Missing: fs.protected_hardlinks/symlinks/fifos/regular do not exist
(behave as their kernel default 0); no
immutable/append-only inodes (no IS_APPEND/IS_IMMUTABLE EPERM).

## Spinlocks where Linux uses sleeping locks

**Location**: `kernel/sync` (Mutex, RwSem), various

Linux rw_semaphores modeled as `spin` locks include the mount
namespace/topology locks (namespace_sem, `Mount` RwLocks) and `s_umount`
(absent): their holders must not sleep (`make check LOCKDEP=1` reports
one that does). `RwSem` has no `_interruptible` variants.

## Mount flag gaps

**Location**: `kernel/fs/misc.rs` sys_mount/sys_umount2, `kernel/fs/mount.rs`

Accepted without effect: atime flags (no atime updates), MS_SILENT,
MS_MANDLOCK, MS_POSIXACL, MS_I_VERSION, MS_LAZYTIME, and
MS_PRIVATE/MS_UNBINDABLE (mounts never propagate, no bind mounts).
EINVAL instead of Linux behavior: MS_BIND (also MS_REMOUNT|MS_BIND),
MS_MOVE, MS_SHARED, MS_SLAVE, MS_SYNCHRONOUS, MS_DIRSYNC, MS_NOSYMFOLLOW
and umount2 MNT_EXPIRE. Read-only state is one flag, SB_RDONLY on the
superblock (no separate MNT_READONLY: without bind mounts a superblock
has one mount per namespace). Unlike Linux (MNT_WRITE_HOLD), a
`SuperBlock::want_write` racing a rw->ro remount that then fails with
EBUSY can see a spurious EROFS. Mount data/options strings are
ignored; mounts are not user-namespace aware (plain capable()).

A mount is found from a dentry by superblock dev_id in the caller's
namespace (`MntNamespace::find_mount_for_dentry`), not carried by the
path walk: `File.mnt` is picked that way at open, open's NODEV check
and statfs flags at the call. Two mounts of one superblock (bind
mounts, once they exist) would be told apart wrongly. Phase G
(Path{mnt, dentry} from the walk) fixes the lookup.

## Thread-group exit gaps

**Location**: `kernel/signal/mod.rs` (group exit), `kernel/task/exec.rs`
de_thread

- Process-directed signals go to one thread's private queue (the
  leader, or a live thread once it has exited), not the shared queue
  with Linux's thread choice at delivery; a pidfd polls readable when
  the leader exits, not when the whole group is gone.

## ptrace stop gaps

**Location**: `kernel/task/ptrace.rs`, `kernel/task/exec.rs`,
`kernel/signal/mod.rs`

Signal-delivery and PTRACE_SYSCALL stops work. Missing: exec, fork,
clone and exit event stops (PTRACE_O_TRACEEXEC and friends,
PTRACE_EVENT_*), PTRACE_INTERRUPT/LISTEN, group-stop interaction (SIGSTOP
to an untraced task is ignored: stop/continue are not implemented),
and the tracee's exit being
reported to a tracer that is not its parent.

## NETLINK_ROUTE / SIOC* subset gaps (P3)

**Location**: `kernel/net/netlink/rtnetlink.rs`, `kernel/net/devioctl.rs`

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

**Location**: `kernel/io_uring.rs`

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

**Location**: `kernel/arch/aarch64/vectors.S`, `kernel/arch/x86_64/`
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

**Location**: `kernel/fs/ramfs.rs`, `kernel/mm/filemap.rs`,
`kernel/frame_alloc.rs`

ramfs (the root filesystem and every ramfs mount) is bounded only by
memory, for every user: writes fail with ENOSPC once free frames reach
the low watermark (min_free_kbytes formula), and the memory comes back when the last link and the last
open reference of a file are gone (or on truncate). Linux's rootfs is a
tmpfs limited to half of RAM by default; tmpfs with `size=`/`nr_inodes=`
limits (and per-user accounting) comes with the filesystem chunk.
Reads of holes need a zeroed page each and can fail with ENOMEM when
memory is at the low watermark (Linux maps the shared zero page).

## Kernel heap (slab) gaps

**Location**: `kernel/mm/slab.rs`, `kernel/heap.rs`

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
bytes of kmalloc (~1.3KB; suspected: procfs entries of dead pids, for
the dcache work). The MM_LIFE tests count MemFree + Slab so they check user memory only; these leaks
are listed here instead.

## The memory cgroup's memory.max is not enforced

**Location**: `kernel/cgroup/memory.rs`, `kernel/mm/fault.rs`, `kernel/mm/shmem.rs`

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

**Location**: `kernel/bpf/map.rs`

An array map refuses a preallocation over half of free memory, but
nothing adds maps up: no RLIMIT_MEMLOCK or memcg charge (Linux
bpf_map_charge_memlock / memcg accounting), so many maps can still use
up memory.

## Heap allocations in atomic context are not reported

**Location**: `kernel/mm/slab.rs` (`heap_gfp`), `kernel/sync/lockdep.rs`

The heap picks GFP_ATOMIC by itself under a spin lock or with
interrupts off, so an allocation there takes the atomic reserve
silently. Linux needs an explicit GFP_ATOMIC and might_alloc reports a
GFP_KERNEL allocation in atomic context. LOCKDEP has no such report
(the T0 design's `atomic_alloc()` scope): the global allocator has no
call site to attribute it to, so the sites (allocations under spin locks
across net, fs, ipc) cannot be audited yet.

## Scheduler gaps (deviations from Linux)

**Location**: `kernel/task/fair.rs`, `kernel/task/percpu.rs`

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

**Location**: `kernel/usb/xhci.rs`, `kernel/usb/msc.rs`

Found while chasing the Dell OptiPlex 3020 freeze; QEMU's xHCI hides
all of them.
- Command completions are not matched to their TRB (`wait_for_command`
  ignores `_trb_addr`), and transfer events only by slot and endpoint:
  a late completion for a timed-out command or transfer is credited to
  the next one (most likely on the USB serial console, whose transfers
  time out after 100 ms). A timeout should stop the endpoint and move
  its dequeue pointer past the TRB (Linux xhci_handle_cmd_stop_ep).
- One controller only: the driver keeps a single global
  `USB_CONTROLLER`; a second xHCI's probe replaces the first, which is
  left running, and both device handles act on the survivor at
  shutdown.
- A timed-out bulk transfer returns early (`do_bulk_out`/`do_bulk_in`
  via `?`) without `dma_unmap` and with its TRB still queued; the
  buffer (heap, freed by the caller) can still be written by the
  controller.
- Enumeration reads no descriptors and sends no SET_CONFIGURATION
  (`control_transfer` is a stub); devices get class 0 and no
  interfaces. No hub support (route string 0).
- `UsbMscBusDriver::matches` accepts any device and assumes QEMU's
  endpoints (0x81/0x02); `main.rs` makes `sda` of the first one.
- Only 4 KiB controller pages and up to 512 scratchpad buffers.

## No DMA for 32-bit devices with RAM above 4GB

**Location**: `kernel/dma.rs`, `kernel/frame_alloc.rs`,
`kernel/net/driver/e1000.rs`, `kernel/usb/xhci.rs`

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

**Location**: `kernel/arch/x86_64/irq.rs`, `kernel/bus/pci.rs`

Device interrupts reach the CPUs only through the 8259 PIC, on the
line firmware wrote into each function's Interrupt Line register (PIC
mode, legacy BIOS boot), delivered to the boot CPU only. Real hardware
in APIC mode (UEFI boot; Linux on the Dell uses IOAPIC 16-23 and MSI)
needs IOAPIC with ACPI `_PRT` routing, or MSI/MSI-X, which xHCI, AHCI
and r8169 all support.

## ACPI power management gaps

**Location**: `kernel/acpi/`, `kernel/arch/x86_64/{acpi,power}.rs`

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

**Location**: `kernel/fs/vfat.rs` (`page_runs`)

Every read_folio, writepage and swap_rw of a vfat file rebuilds its
whole cluster chain from the FAT (through the device cache) to find a
page's clusters, so reading or writing back a file is quadratic in its
size (a 1GB file of 4KB clusters: about 3e10 FAT lookups). Linux
fat_get_cluster keeps a per-inode cache of chain positions
(fat_cache); one is needed before large vfat files or vfat swap files.

## Block layer gaps (P1)

**Location**: `kernel/storage/`, `kernel/virtio/blk.rs`,
`kernel/fs/blkdev_ops.rs`, `kernel/fs/vfat.rs`

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
  fixed at probe (no hot add/remove of virtio disks).
- No /proc/devices block section, no /sys/block; the first disk
  registered decides the dynamic major (254 down, like Linux, but Linux
  usually has other dynamic majors registered first).
- A mounted filesystem or active swap opens its block device, but not
  exclusively: opening it O_EXCL and BLKBSZSET on a mounted partition
  are not refused.

## Code-quality audit findings (2026-11-01), by phase

From a whole-tree audit for designs that grew one commit at a time.
Fixed already: clock setting, seccomp actions, kcmp/pidfd_getfd access,
sched pid 0, flock/POSIX release, signalfd reader, errno flattening.

- **Privilege by uid instead of capable()** (L): about 29 `euid == 0`
  style checks remain where Linux tests a capability (`task/id.rs` x6
  CAP_SETUID/SETGID, `ns/uts.rs` and `ns/mod.rs` CAP_SYS_ADMIN,
  `rlimit.rs` CAP_SYS_RESOURCE, `ipc/msg.rs` CAP_SYS_RESOURCE,
  `ipc/mqueue.rs` DAC_OVERRIDE, `ipc/util.rs` CAP_IPC_OWNER missing,
  `keys/key.rs` (fsuid, no root bypass), `acct.rs` ASU flag). Linux's
  own uid-0 rules (`sysctl.rs`, `fs/dac.rs`) are right as they are.
  `task::capable` should be the only privilege test.
- **Syscalls that do not deliver** (H/C): inotify and fanotify never
  queue an event (no fsnotify hooks in the VFS); there is no siginfo
  queue (signals are a bitmask: rt_sigqueueinfo's data, si_pid/si_uid
  and RT signal queueing are lost); waitid without WEXITED is EINVAL
  (C); semctl GETNCNT/GETZCNT are 0; fallocate PUNCH_HOLE succeeds
  without zeroing (F).
- **Copied helpers** (J, or as touched): `get_nofile_limit` in eight
  places; `find_task_by_pid` in four (all root-namespace pids); four
  `current_time`s; about ten user-timespec readers each validating
  (Linux get_timespec64); three iovec structs and five
  importers; five SigInfo, three Timeval, two Timespec types; two path
  splitters that disagree on `.`/`..` (G).
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
  `arch/` (main.rs, dma.rs, percpu.rs, misc, pci, seccomp's audit
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
- **Stale comments and dead code** (as touched): about 155
  `#[allow(dead_code)]`, 90 "for now"/TODO markers; comments that
  contradict the code in `task/id.rs:87`, `ns/mod.rs:558`,
  `ns/uts.rs:224`, `rlimit.rs:264`, `task/misc.rs:1311`.

## P0 review findings (open)

Found by the review of the P0 series; each confirmed against the code
(and Linux 6.8 where semantics matter). "Fix in" names the phase
expected to fix it; "next batch" means the next fix batch.

1. **Rename leaves stale dentries; the trap is bypassed** (fix in
   V1/V2, d_move). `kernel/fs/link.rs:593`: after a rename both
   dentries are only `remove_child`'d, so a dentry pinned by a cwd or
   fd keeps its old parent chain; `is_subdir` (`kernel/fs/dentry.rs:287`)
   / `lock_rename` (`kernel/fs/mod.rs:129`) compare with `Arc::ptr_eq`.
   Scenario: `mkdir -p /t/a/b; cd /t/a/b; mv /t/a /t/c; rename("/t/c",
   "z")` moves c under its own child (Linux: EINVAL). Fix: Linux d_move /
   d_exchange (dentry name under `d_lock`); vfat must then update the
   moved inode's `parent_cluster`/`short_name` (fs rename needs the
   source inode).
7. **/proc/<pid>/* owner not refreshed on stat** (fix in V2).
   `kernel/fs/procfs.rs:370`: the owner (task_dump_owner) is updated
   at lookup and in permission() only; Linux pid_revalidate updates it
   on every walk. Scenario: stat environ of a uid-1000 child, child
   sets `PR_SET_DUMPABLE 0`, stat again: hk still says uid 1000
   (Linux 0).
8. **EXDEV compares superblocks, not mounts** (fix in V1)
   (`kernel/fs/link.rs:298`, `:484`): a link or rename across two
   mounts of one superblock (bind mounts) is EXDEV on Linux. Needs
   Path{mnt,dentry}; TODO in place for linkat.

## P2 review findings (open)
From the P2 /code-review (unverified). Tag = when to fix.
1. **pcp_free drains the hot end** (next batch).
   `kernel/mm/page_alloc.rs:458`: freed page pushed at head, drain
   pops from head; Linux returns the cold tail.
2. **arm64 /reserved-memory no-map regions are linear-mapped**
   (next batch; real HW). `kernel/arch/aarch64/dtb.rs:175`: Linux
   memblock_mark_nomap removes them (speculative access to secure
   carve-outs).

## P3 review findings (open)
From the P3 /code-review (unverified). Tag = when to fix.
1. **Remote write gives up after 16 COW tries** (next batch).
   `kernel/mm/remote.rs:176`: spurious EFAULT; break COW and write
   under one PTE-lock hold, or loop until fatal_signal_pending.

## Fix batch 1 review findings (open)
From the fix-batch-1 /code-review (unverified). Tag = when to fix.
3. **memblock holds at most 128 ranges** (J). `kernel/mm/memblock.rs:18`:
   a firmware map with more RAM or reserved ranges panics at boot
   (asserts in add/remove/reserve); Linux grows the array
   (memblock_double_array).

## P4 review findings (open)
From the P4 /code-review (unverified unless noted). Tag = when to fix.

4. **LRU batch refs defeat exclusivity checks** (next batch).
   `kernel/mm/fault.rs:477` / `:545`: refcount==1 tests fail while a
   page sits in the per-CPU add batch → needless COW copies after
   swap-in. Linux drains and rechecks (wp_can_reuse_anon_folio).
5. **alloc_slot linear scan under SwapInfo.map; two Vecs + sort per
   reclaimed page** (P6). `kernel/mm/swap.rs:184`: cluster/free-hint
   allocator, cached sorted device list.
7. **One AnonVma per fork family, Vec chain** (J).
   `kernel/mm/anon_vma.rs:85`: O(N×VMAs) under one family write lock.

## T0 findings (open)
Found during T0 (2026-10-19). Tag = when to fix.
1. **Syscalls report root-namespace pids** (P9). Tasks get a number in
   every level of their pid namespace chain (`kernel/task/pid.rs`), but
   getpid/gettid/kill/wait//proc use the root number; a CLONE_NEWPID
   child is not pid 1 in its namespace. Use `Pid::nr_in(caller's ns)`
   at the syscall boundary.
5. **BUSYBOX_NC_LO flaky, on hk and the Linux reference** (next
   batch): `BUSYBOX_NC_LO:FAIL status=0` (nc over loopback) in 1 of 5
   x86 `check-linux` runs, and in an hk x86 boot with one CPU
   (`QEMU_SMP=1`). Cause unknown: the test waits for the listener
   (`wait_listen`) and retries the client.
6. **No ptrace exec stop** (P9): a traced task's execve does not stop
   with SIGTRAP / PTRACE_EVENT_EXEC (`kernel/task/exec.rs`), so a
   tracer cannot observe a non-leader exec's tid change.
8. **MM_LIFE_EXEC_CHAIN intermittent on arm64 CI** (next batch). One
   GitHub `check-arm` run (TCG, NIC=e1000) reported
   `MM_LIFE_EXEC_CHAIN:FAIL -2`: both warmup chains passed, then the
   first measured one's child (busybox `env` x40 then `true`, i.e. 41
   execs in one process) exited nonzero. A failed exec, not a leak.
   MM_LIFE now prints a failing child's wait status (exit code vs
   signal); 16 eight-CPU arm64 stress boots did not repeat it.
10. **Network test flake** (I):
   `SOCKCORE_CONNECT_REFUSED:FAIL SO_ERROR got 0` (hk arm64, 1 of 10
   `check-stress` boots: poll reported POLLOUT for a nonblocking
   connect to a just-closed loopback port, but no ECONNREFUSED was
   pending).
14. **SWAPOUT_PAGEOUT flaky on the Linux reference** (J): one x86
   `check-linux` run had free swap 364 kB off the expected value after
   MADV_PAGEOUT of 16 MiB (beyond the test's tolerance), passing on the
   rerun. Linux's swap accounting after pageout is not exact (swap
   cache); the tolerance may need to grow on Linux.
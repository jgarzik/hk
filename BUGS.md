# Known Bugs

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

- Reclaim (P4) swaps out private anonymous pages only, for
  MADV_PAGEOUT: no accessed-bit aging (pages are reclaimed oldest
  first), synchronous writes, no kswapd, no file pages; 2MB pages stay
  off the LRU (never reclaimed whole; a split puts their 4KB pages on
  it). Pages exec copies the image into are not on the reverse map
  (never swapped). Swap files go through the inode's readpage /
  writepage, a page at a time. Only page faults (and swapoff) reclaim:
  heap, pipe-buffer and page-cache allocations never do (they run
  under spinlocks or cannot sleep), so with anonymous memory filling
  RAM they fail at the low watermark until kswapd (P6) keeps free
  memory above it.
- SysV shm: IPC_RMID removes the id at once (Linux keeps it, as
  IPC_PRIVATE with SHM_DEST, until the last detach: IPC_STAT and shmat
  by id still work there).
- File mappings: MAP_SHARED of a file on a filesystem other than ramfs
  (vfat) maps a private copy (writes do not reach the file or other
  mappings); truncating a ramfs file does not unmap its shared pages
  (they keep the old data instead of raising SIGBUS); MAP_PRIVATE file
  pages are copied at fault, not shared until written.
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

## No dynamically linked executables

**Location**: `kernel/task/exec.rs` (`do_execve`)

A PT_INTERP program interpreter is never loaded: exec of a dynamic
executable fails with ENOEXEC (ENOENT if the interpreter does not
exist, as on Linux). Only static and static-pie programs run.

## CPU-time clocks: no timers or sleeps

**Location**: `kernel/time_syscall.rs`, `kernel/posix_timer.rs`

CPU-time clocks (CLOCK_PROCESS/THREAD_CPUTIME_ID, per-pid ids) can be
read but not waited on: clock_nanosleep on the process CPU clock is
EOPNOTSUPP and timer_create on any CPU clock is EINVAL (Linux
posix_cpu_nsleep / posix_cpu_timer_create run them from the tick).
timer_create on CLOCK_TAI is EINVAL too. A process clock sums its live
threads only: exited threads' time is lost (Linux keeps it in
signal_struct), and other threads' running slices are not included
until their next accounting point (Linux task_sched_runtime).

## Interval timers: ITIMER_VIRTUAL and ITIMER_PROF

**Location**: `kernel/posix_timer.rs` (`sys_setitimer`)

Only ITIMER_REAL (and alarm) exist; the CPU-time timers return EINVAL
(Linux supports them). rseq is ENOSYS (glibc runs without it).

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
mknod(S_IFIFO) still creates a regular file.

## File permission (DAC) gaps

**Location**: `kernel/fs/dac.rs`, `kernel/task/exec.rs`

Missing: fs.protected_hardlinks/symlinks/fifos/regular do not exist
(behave as their kernel default 0); execve ignores S_ISUID/S_ISGID and file
capabilities (so MS_NOSUID has nothing to suppress); no
immutable/append-only inodes (no IS_APPEND/IS_IMMUTABLE EPERM);
chmod/chown do not update ctime; ETXTBSY is not enforced.

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

A file keeps no mount (Linux file->f_path.mnt), so MNT_NOEXEC/NODEV
are found by looking the dentry up in the caller's namespace
(`mount::mnt_flags_of`). For a file from another namespace (an fd
passed over SCM_RIGHTS) none is found: exec fails closed (EACCES), but
mmap PROT_EXEC (`kernel/mm/syscall.rs:64`) and open's NODEV check
(`kernel/fs/open.rs:187`) treat the flags as 0. Phase G (Path in File)
fixes all three.

## Thread-group exit gaps

**Location**: `kernel/signal/mod.rs` (group exit), `kernel/task/exec.rs`
de_thread

- A sibling blocked uninterruptibly on its group's cred_guard (a second
  exec, or ptrace attach) while another thread's exec waits in
  de_thread never wakes: both wait (Linux takes cred_guard_mutex
  interruptibly there).
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
waiting on a tracee by process group, and the tracee's exit being
reported to a tracer that is not its parent.

## Global init is not protected from default-action signals

**Location**: `kernel/signal/mod.rs` send_signal

Linux drops signals with a default action of terminate/stop sent to
global init (SIGNAL_UNKILLABLE), e.g. SIGPIPE from a write to a broken
socket. hk delivers them, so pid 1 (the boot tester) dies. Socket tests
use MSG_NOSIGNAL / SIG_IGN and check SIGPIPE in forked children.

## The initial user stack does not grow

**Location**: `kernel/task/exec.rs` setup_user_stack, `kernel/main.rs`
(init)

The main thread's stack is mapped eagerly at exec (RLIMIT_STACK, or
1 MB when unlimited; init's is 1 MB) and is not a growable VMA: Linux maps it lazily and expands it on demand
up to RLIMIT_STACK.

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

**Location**: `kernel/fs/ramfs.rs`, `kernel/mm/page_cache.rs`,
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

exec copies the PT_LOAD segments page by page (not mapped from the
page cache like Linux binfmt_elf). Kernel object leaks cost free
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
- No RT throttling (sched_rt_runtime_us) or dl_server: a SCHED_FIFO
  spinner starves its CPU's fair tasks; no SCHED_DEADLINE (EINVAL).
- Kernel preemption is off: a long kernel path delays a woken task of
  a higher class until its next scheduling point.

## Unconfirmed: Arc<T> field corruption in the USB mass-storage driver

**Location**: `kernel/usb/msc.rs`

An early report (before this repository's history) saw `UsbMscDevice`
fields (slot id, bulk endpoints) read back corrupted from an
`Arc<UsbMscDevice>` kept in a static, and worked around it with static
atomics. No such workaround exists in this tree: since the first commit
`UsbMscDevice` keeps `slot_id`, `bulk_in_ep` and `bulk_out_ep` as plain
fields, and the USB vfat boot tests (both arches) pass on them. Kept
only as a pointer if wrong USB slot/endpoint values ever show up again.

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

## Block layer gaps (P1)

**Location**: `kernel/storage/`, `kernel/virtio/blk.rs`,
`kernel/fs/blkdev_ops.rs`, `kernel/fs/vfat.rs`

- No page cache in front of block device files (P5): reads and writes
  are synchronous bios. A filesystem's cached block device pages (vfat
  keeps the FAT, directories and data of its partition in the global
  page cache) are not coherent with I/O through the device node; Linux
  shares one bdev mapping. Two writers of the same sector through
  unaligned writes can lose one update (each reads, patches and writes
  the sector without a page lock).
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
- A mounted filesystem or active swap does not open its block device:
  opening it O_EXCL, writes to a swap partition (Linux ETXTBSY) and
  BLKBSZSET on a mounted partition are not refused.

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
2. **process_vm on own process fails from a sibling thread** (next
   batch). `kernel/task/process_vm.rs:310` exempts only
   `target_tid == current_tid()`; Linux mm_access exempts the caller's
   own mm and `__ptrace_may_access` the thread group. Scenario: a
   non-dumpable uid-1000 process; its second thread gets EPERM from
   `process_vm_readv(getpid())`.
3. **linkat AT_EMPTY_PATH capability check only for empty paths**
   (next batch). `kernel/fs/link.rs:221`: Linux 6.8 do_linkat returns
   ENOENT for AT_EMPTY_PATH without CAP_DAC_READ_SEARCH whatever the
   path. Scenario: unprivileged `linkat(AT_FDCWD, "f", AT_FDCWD, "g",
   AT_EMPTY_PATH)` succeeds on hk, ENOENT on Linux.
4. **comm bytes >= 0x80 re-encoded as UTF-8** (next batch).
   `kernel/fs/proc_array.rs:145` pushes `b as char`; Linux
   proc_task_name emits raw bytes (status escapes only `\n` and `\\`).
   Scenario: `PR_SET_NAME "\xe9"`; stat/status show `\xc3\xa9`.
5. **init has no argv/envp/auxv** (next batch). `kernel/main.rs:994`:
   init's stack is zeroed (argc 0, no auxv) and its mm has no
   arg/env/start_stack layout, so /proc/1/cmdline and environ are
   empty. Linux run_init_process: argv { "/bin/init" }, envp
   { "HOME=/", "TERM=linux" }. Fix: build it with exec's stack builder.
6. **ptrace "init only with CAP_SYS_PTRACE" guard is wrong** (next
   batch). `kernel/task/ptrace.rs:179` refuses init (tid 1) without
   CAP_SYS_PTRACE; Linux has no such rule. ptrace_attach should instead
   refuse kernel threads and the caller's own thread group (EPERM); hk
   refuses only the calling thread.
7. **/proc/<pid>/* owner not refreshed on stat** (fix in V2).
   `kernel/fs/procfs.rs:370`: the owner (task_dump_owner) is updated
   at lookup and in permission() only; Linux pid_revalidate updates it
   on every walk. Scenario: stat environ of a uid-1000 child, child
   sets `PR_SET_DUMPABLE 0`, stat again: hk still says uid 1000
   (Linux 0).
8. **Mounts in link.rs** (from the security review).
   (a) (next batch) rename, rmdir and unlink never check for a
   mountpoint (`kernel/fs/link.rs:525` rename_locked,
   `kernel/fs/path.rs:248`); Linux returns EBUSY for a mounted-on
   source or target. Scenario: mount ramfs on /tmp/m; `rmdir`,
   `rename` of /tmp/m, or renaming another dir onto it, orphans the
   mount. (Code reading; not yet test-verified.)
   (b) (fix in V1) EXDEV compares superblocks, not mounts
   (`kernel/fs/link.rs:298`, `:484`): a link or rename across two
   mounts of one superblock (bind mounts) is EXDEV on Linux. Needs
   Path{mnt,dentry}; TODO in place for linkat.

## P1 review findings (open)
From the P1 /code-review (unverified unless noted). Tag = phase that fixes it.
1. **Failed-read pages never discarded** (P5; confirmed by reading).
   `kernel/mm/page_cache.rs:892` discard_page needs refcount 0, but
   find_or_create_page returns refcount 1 and vfat read_bytes /
   write_bytes never put it, so the discard is a no-op: after an I/O
   error the zero page is served as FAT/dir data.
2. **No uptodate/page lock on block-device pages** (P5).
   `kernel/fs/vfat.rs:503` inserts the page before the bio read; a
   concurrent reader copies zeros, a concurrent partial write is
   overwritten when the DMA lands. Linux: folio locked + !uptodate
   until read completes.
3. **BLKRRPART/umount don't invalidate the bdev page cache** (P5).
   `kernel/storage/genhd.rs:118`: cache keyed by (major, minor); a
   re-created partition reusing a minor inherits stale and dirty
   pages, which write back at old offsets.
4. **logical_block_size ignored** (next batch).
   `kernel/storage/blkdev.rs:768`: partition scan and RMW issue 512B
   bios; a 4Kn disk shows no partitions and 512B pread gives EIO.
5. **parts_held uses Arc::strong_count** (next batch).
   `kernel/storage/genhd.rs:107`: transient clones (writeback,
   readpage) give spurious EBUSY; mount doesn't take open_mutex, so a
   mount can race drop_bdevs and get a dead device.
6. **Disk removal without open_mutex** (next batch).
   `kernel/storage/sd.rs:381` del_gendisk → drop_bdevs unlocked: races
   BlockDevice::open (opener of a removed partition) and BLKRRPART
   rescans (stale registry entries / /dev nodes).
7. **Segment limits** (next batch). `kernel/storage/blkdev.rs:674`
   max_io assumes PAGE/seg per page; bdev_rw_frame ignores
   max_segments: SIZE_MAX < 4096 without SEG_MAX overflows SEG_MAX /
   MAX_SEGS → EIO.
9. **Write path copies** (P5). `kernel/storage/blkdev.rs:749`:
   writes take `&mut [u8]` (to_vec + bounce copy per page); unaligned
   bdev_rw_bytes allocates a request-sized temp buffer.

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
2. **populate_pages not killable** (next batch).
   `kernel/mm/syscall.rs:570`: mlock/MAP_POPULATE ignore SIGKILL.
3. **Minor** (next batch): `kernel/uaccess.rs:235` fault_in_writeable
   unused and duplicates populate_pages; `kernel/fs/io.rs:68`
   copy_in always uses the atomic+fault-in copy (only i_rwsem writers
   need it); `kernel/task/misc.rs:244` USER_HZ duplicated, times()
   assumes TICK_MS == 10.

## Fix batch 1 review findings (open)
From the fix-batch-1 /code-review (unverified). Tag = when to fix.
1. **Fatal signal to an exiting thread or a zombie leader starts a
   group exit** (next batch). `kernel/signal/mod.rs:1076` group_kill:
   a signal to a PF_EXITING thread not yet released (or a traced
   zombie) kills the live process (Linux wants_signal skips
   PF_EXITING); a kill -9 of a zombie leader whose threads all called
   exit() overwrites its exit status.
2. **init is killable by SIG_DFL signals** (next batch).
   `kernel/signal/mod.rs:952`: no SIGNAL_UNKILLABLE check on the
   fatal-on-arrival path; kill(1, SIGTERM) by root ends the system.
3. **memblock MAX_REGIONS = 128 drops RAM silently** (next batch).
   `kernel/mm/memblock.rs:66`.
5. **group_alive duplicates group_others** (next batch).
   `kernel/task/percpu.rs:1570` vs `:1459`.

## P4 review findings (open)
From the P4 /code-review (unverified unless noted). Tag = when to fix.

1. **swapoff makes PROT_NONE swap pages readable** (next batch;
   confirmed by reading). `kernel/mm/fault.rs:478` map_swap_page (via
   unuse_pte) → mk_pte(page, area.prot) with prot 0 is PRESENT|USER
   on x86. Use a protnone PTE (Linux vm_page_prot).
3. **Swap file size not capped by i_size** (next batch).
   `kernel/mm/swap.rs:455`: header last_page sizes a heap Vec (8GB →
   panic) and slots past EOF (only block devices are capped).
4. **LRU batch refs defeat exclusivity checks** (next batch).
   `kernel/mm/fault.rs:477` / `:545`: refcount==1 tests fail while a
   page sits in the per-CPU add batch → needless COW copies after
   swap-in. Linux drains and rechecks (wp_can_reuse_anon_folio).
5. **alloc_slot linear scan under SwapInfo.map; two Vecs + sort per
   reclaimed page** (P6). `kernel/mm/swap.rs:184`: cluster/free-hint
   allocator, cached sorted device list.
6. **read_swap_page busy-yields on SWAP_HAS_CACHE** (P6).
   `kernel/mm/swap_state.rs:186`: sleep instead.
7. **One AnonVma per fork family, Vec chain** (J).
   `kernel/mm/anon_vma.rs:85`: O(N×VMAs) under one family write lock.

## T0 findings (open)
Found during T0 (2026-10-19). Tag = when to fix.
1. **Syscalls report root-namespace pids** (P9). Tasks get a number in
   every level of their pid namespace chain (`kernel/task/pid.rs`), but
   getpid/gettid/kill/wait//proc use the root number; a CLONE_NEWPID
   child is not pid 1 in its namespace. Use `Pid::nr_in(caller's ns)`
   at the syscall boundary.
3. **mremap Prep allocates page tables under the old PTE lock** (next
   batch). `kernel/mm/mremap.rs:53`: it uses CAS-only
   `paging::pte_alloc` there, skipping page_table_lock; allocate before
   taking the PTE lock (Linux move_page_tables).
4. **`virt_to_phys(p & !0xfff)` duplicated** (next batch) in
   `Move::ptes`, `PteRange::at` and `ptl::pte_lock`: add one
   `ptl::table_of_ptep()`.
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
10. **Network test flake** (I):
   `SOCKCORE_CONNECT_REFUSED:FAIL SO_ERROR got 0` (hk arm64, 1 of 10
   `check-stress` boots: poll reported POLLOUT for a nonblocking
   connect to a just-closed loopback port, but no ECONNREFUSED was
   pending).
12. **arm64 overflow check misses a frame over 32 KB** (next batch):
   vectors.S KERNEL_ENTRY tests bit 15 of SP only, so an SP that jumped
   more than 32 KB below a stack base (one huge frame) lands where the
   bit is clear and is not caught (the guard gap still faults).
13. **MM_LIFE_FORK_EXEC over its 128 kB tolerance at 8 CPUs** (next
   batch): 1 of 20 `QEMU_SMP=8 make check-stress` boots (arm64, TCG)
   lost 184 kB of MemFree+Slab over 500 fork+exec rounds, never at 4
   CPUs. Suspects that scale with CPUs: the stack area's page tables
   (never freed; more concurrent stacks reach higher slots) and frees
   deferred until other CPUs switch. Find which, then fix it or scale
   the tolerance with the CPU count.

# Known Bugs

## chroot() does not affect path resolution (security)

**Location**: `kernel/fs/path.rs` ~111-119 (absolute-path lookup)

`sys_chroot` records the new root (`fs.set_root`), but path walking
always starts absolute paths at the mount namespace root
(`mnt_ns.get_root_dentry()`) and never consults the task's fs root, so a
chrooted process can still reach everything. `..` at the chroot root is
not clamped either. Boot test `CHROOT` only verifies confinement on a
Linux host (`user/boot_tester/tests/permissions.rs`).

## PID and TID come from separate counters

**Location**: `kernel/task/percpu.rs` do_clone (`next_pid` / `next_tid`)

Linux allocates one ID per task; a single-threaded process has
pid == tid. hk draws pids and tids from separate counters, so e.g.
`fork()`/`clone()` return the child's PID (2) while the child's
`gettid()`, CLONE_PARENT_SETTID/CLONE_CHILD_SETTID stores and futex
TIDs say 3. Anything comparing those values (pthread joins, tgkill to a
returned pid, `/proc/<pid>/task`) can disagree with Linux.

## Raw user-memory access in the pre-VFS minimal write

**Location**: `kernel/arch/x86_64/syscall.rs`

All syscall paths copy user memory through the uaccess helpers (the boot
tests run with SMAP on x86 TCG `-cpu max` and PAN on arm `neoverse-n1`).
The only raw access left is the early minimal `write`, unused once the
VFS handler is registered.

## Network stack gaps (later phases of the network chunk)

**Location**: `kernel/net/`

Listed because real traffic reaches them: TCP has no SACK (never
advertised), no CUBIC (only "reno"; Linux defaults to cubic), no
receive buffer autotuning (the window is SO_RCVBUF / 2), no per-netns
RFC 5961 challenge-ACK budget (only Linux's per-connection 500 ms
limit), and TCP_DEFER_ACCEPT / TCP_FASTOPEN are stored only.
tcp_timestamps accepts 0..255 like Linux; any value but 1 sends the raw
ms clock (no offset), as in Linux. No SYN cookies (a full listener drops SYNs). ICMP
timestamp requests are not answered.
Neighbour entries are not confirmed by TCP progress (only ARP), there is
no proxy ARP and no per-device neighbour sysctls (net/ipv4/neigh/*).
IP: no ipfrag_max_dist, no IP options on output (received options are
validated and skipped; source-routed packets are dropped), no
IP_TRANSPARENT. Ping sockets check only the effective gid against
ping_group_range (hk has no supplementary groups). /proc/net/raw and
/proc/net/icmp do not exist.
UDP_CORK/MSG_MORE are not implemented (each send is one datagram) and
SO_PEEK_OFF is EOPNOTSUPP.

## Memory management gaps

**Location**: `kernel/mm/`, `kernel/arch/*/paging.rs`, `kernel/ipc/shm.rs`

Address spaces are reference counted and torn down like Linux
(doc/MEMORY.md, Address space lifetime); what is still missing:

- Page descriptors are never initialized (`init_page_descriptors` has
  no caller), so rmap, the LRU lists and swap-out are inert. Before
  enabling them: `set_anon_mapping` stores an AnonVma pointer without
  taking a reference while `clear_mapping` drops one, swap-out frees a
  frame even when the rmap walk missed a mapping, swap slots carry no
  reference counts (`free_swap_entry` frees at once), the swap cache is
  never filled (`swap_cache_add` has no caller) and freeing a slot does
  not drop a swap-cache entry (Linux SWAP_HAS_CACHE), and munmap leaks
  the slots of swap PTEs (exit frees them).
- fork fails with ENOMEM on a swap PTE (`memory::swap_pte_unsupported`,
  unreachable while swap-out is inert): copying one needs counted swap
  slots safe against a racing swap-in (Linux swap_duplicate under
  si->lock); to be done with the reclaim work.
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
- No vm.max_map_count: the number of VMAs (new mappings, splits by a
  partial mprotect or munmap) is not limited (Linux: 65530, then
  ENOMEM). A locked mapping grown by mremap is not faulted in (Linux
  populates it).
- Exited non-leader threads stay in the task table as zombies (Linux
  reaps them at once); their kernel stacks and memory are freed.
- munmap keeps page-table pages that become empty (freed at exit).
- x86 and arm64 syscalls run with interrupts off, so a CPU in a long
  syscall answers a TLB shootdown IPI only when it sleeps, returns or
  spins on the mm lock (which polls its call queue): the shooting CPU
  waits meanwhile. Spinning with interrupts off on another lock held
  across a shootdown would deadlock (doc/LOCKING.md, Cross-CPU Calls);
  none is today, and user tasks still run on CPU 0 only.

## exec ignores set-user-ID / set-group-ID bits and file capabilities

**Location**: `kernel/task/exec.rs` (`do_execve`)

Linux execve of a file with S_ISUID / S_ISGID (on a mount without
nosuid, without no_new_privs or a ptracer in the way) sets the
effective (and saved) uid / gid to the file's owner, and file
capabilities (security.capability) raise the permitted set
(bprm_fill_uid, cap_bprm_creds_from_file). hk exec keeps the caller's
credentials unchanged, so set-id programs run unprivileged. Its
AT_SECURE and dumpability already follow from the credentials
(`secureexec`), so they stay right once set-id exec exists.

## No dynamically linked executables

**Location**: `kernel/task/exec.rs` (`do_execve`)

A PT_INTERP program interpreter is never loaded: exec of a dynamic
executable fails with ENOEXEC (ENOENT if the interpreter does not
exist, as on Linux). Only static and static-pie programs run.

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

Linux DAC is enforced on the VFS paths (search on every walked directory,
may_open, may_create/may_delete with the sticky rule, owner-only attribute
changes, set-id clearing, capability overrides by fsuid/fsgid). Missing:
no supplementary groups (no setgroups/getgroups; group class checks use the
fsgid only); fs.protected_hardlinks/symlinks/fifos/regular do not exist
(behave as their kernel default 0); execve ignores S_ISUID/S_ISGID and file
capabilities (so MS_NOSUID has nothing to suppress); no
immutable/append-only inodes (no IS_APPEND/IS_IMMUTABLE EPERM);
chmod/chown do not update ctime; ETXTBSY is not enforced.

## Spinlocks where Linux uses sleeping locks

**Location**: `kernel/sync` (Mutex, RwSem), various

Sleeping locks so far: `i_rwsem`, `s_vfs_rename_mutex`, `f_pos_lock`,
RTNL, `TcpSock.rd` and the unix socket `bindlock`/`iolock`. Linux
rw_semaphores/mutexes still modeled as `spin` locks include the mmap
lock (`Mm::lock`), the mount namespace/topology locks (namespace_sem,
`Mount` RwLocks), `s_umount` (absent) and pipe locks: their holders must
not sleep (`make check LOCKDEP=1` reports one that does). There are no
`_killable`/`_interruptible`/`try` variants of the sleeping locks yet
(no callers need them).

## Mount flag gaps

**Location**: `kernel/fs/misc.rs` sys_mount/sys_umount2, `kernel/fs/mount.rs`

Honored: CAP_SYS_ADMIN (EPERM), MS_RDONLY (EROFS on every change, on the
superblock), MS_NOSUID/MS_NODEV/MS_NOEXEC (per mount), MS_REMOUNT of those
flags, statfs f_flags and /proc/mounts options. Accepted without effect
because hk already behaves that way: atime flags (no atime updates),
MS_SILENT, MS_MANDLOCK, MS_POSIXACL, MS_I_VERSION, MS_LAZYTIME, and
MS_PRIVATE/MS_UNBINDABLE (mounts never propagate, no bind mounts).
EINVAL instead of Linux behavior: MS_BIND (also MS_REMOUNT|MS_BIND),
MS_MOVE, MS_SHARED, MS_SLAVE, MS_SYNCHRONOUS, MS_DIRSYNC, MS_NOSYMFOLLOW
and umount2 MNT_EXPIRE. Read-only state is one flag, SB_RDONLY on the
superblock (no separate MNT_READONLY: without bind mounts a superblock
has one mount per namespace). Write access (`SuperBlock::want_write`,
Linux mnt_want_write) is held by open-for-write files and across each
modifying syscall; a rw->ro remount is EBUSY while any is held. Unlike
Linux (MNT_WRITE_HOLD), a want_write racing a remount that then fails
with EBUSY can see a spurious EROFS. Not done: mount data/options
strings are ignored; mounts are not user-namespace aware (plain
capable()).

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
1 MB when unlimited; init's is 1 MB: it was 16 KB, which made deep
frames fault or hang the boot tester)
and is not a growable VMA: Linux maps it lazily and expands it on demand
up to RLIMIT_STACK.

## NETLINK_ROUTE / SIOC* subset gaps (P3)

**Location**: `kernel/net/netlink/rtnetlink.rs`, `kernel/net/devioctl.rs`

Implemented: link get/dump/change (IFF_UP, MTU), IPv4 address and route
add/delete/dump, route get (output routes), neighbour get/dump/add/delete,
notifications (none yet for neighbour state changes: no RTNLGRP_NEIGH;
no proxy ARP entries, NTF_USE or NDA_PROTOCOL).
Missing, each answered with a Linux errno rather than silently: link
creation and rename (EOPNOTSUPP), multipath routes and nexthop objects
(EOPNOTSUPP), input-route simulation `ip route get ... iif` (EOPNOTSUPP),
NLM_F_ECHO (not echoed), extended-ACK message/offset TLVs (plain errors),
RTM_GETRULE dumps nothing (Linux lists its three default IPv4 rules; there
is no rule engine: lookups are local then main), address lifetimes are
always infinite, promote_secondaries is off.

## Rare arm64 kernel instruction abort in the fault-signal tests

**Location**: unknown (CPU 0, right after `FAULT_SEGV_ACCERR`, i.e. while
`FAULT_SIGILL` runs `udf` in user mode)

Seen once in ~100 `make check-arm` runs (QEMU neoverse-n1 with PAN, -smp
4): "KERNEL PANIC ... exceptions.rs:95" (kernel instruction abort). The
panic handler then dropped formatted messages, so ELR/FAR were lost; it
prints them now. Not reproduced in 90 further runs (sequential and 8 in
parallel). Next occurrence: capture the Message line.

## ramfs has no size limit

**Location**: `kernel/fs/ramfs.rs`, `kernel/mm/page_cache.rs`,
`kernel/frame_alloc.rs`

ramfs (the root filesystem and every ramfs mount) is bounded only by
memory, for every user: writes fail with ENOSPC once free frames reach
the kernel's reserve (1/32 of RAM, at least 4MB) or the kernel heap is
down to 2MB, and the memory comes back when the last link and the last
open reference of a file are gone (or on truncate). Linux's rootfs is a
tmpfs limited to half of RAM by default; tmpfs with `size=`/`nr_inodes=`
limits (and per-user accounting) comes with the filesystem chunk.
Reads of holes need a zeroed page each and can fail with ENOMEM when
memory is at the reserve (Linux maps the shared zero page).

## The kernel heap is a fixed 16MB region

**Location**: `kernel/main.rs` (`x86_64_heap`, `aarch64_heap`), `kernel/heap.rs`

The heap is one fixed range placed at boot: on x86 from above the
kernel image and multiboot modules/info up to 18MB (where the frame
allocator starts, so ~14MB minus the boot data); on aarch64 16MB at the
first 2MB boundary past the kernel image, DTB and DTB initrd, with the
frame allocator starting at its end. Both arches panic at boot if the
heap would overlap the kernel image or boot data. The heap never grows
and does not draw on the frame allocator, so heap-heavy workloads hit
allocation failure long before RAM runs out; to be fixed with the
allocator redesign (heap backed by frames, slab caches). By the time the
boot tests reach the network stress test only a few MB are free on x86:
every TCP TIME_WAIT entry keeps a full control block (about 2 KB) for
60 s, so a burst of a thousand short connections can starve a later 2 MB
allocation (busybox exec); the stress test bounds its connections.

exec no longer copies the binary into memory (it needed a 2.1MB
contiguous heap block for busybox, which the fragmented heap could not
always give: x86 `make check LOCKDEP=1` panicked "memory allocation of
2124608 bytes failed"): `kernel/task/exec.rs` reads the ELF headers in
bounded pieces and each PT_LOAD page straight into its user frame
(reserve-checked like any user page). The segments are still copied at
exec, not mapped from the page cache like Linux binfmt_elf. Each new pid that opens `/proc/self/...`
also keeps ~1.6-2.9KB of heap after exit (suspected: procfs dentries of
dead pids never freed; unconfirmed).

## Unconfirmed: Arc<T> field corruption in the USB mass-storage driver

**Location**: `kernel/usb/msc.rs`

An early report (before this repository's history) saw `UsbMscDevice`
fields (slot id, bulk endpoints) read back corrupted from an
`Arc<UsbMscDevice>` kept in a static, and worked around it with static
atomics. No such workaround exists in this tree: since the first commit
`UsbMscDevice` keeps `slot_id`, `bulk_in_ep` and `bulk_out_ep` as plain
fields, and the USB vfat boot tests (both arches) pass on them. Kept
only as a pointer if wrong USB slot/endpoint values ever show up again.

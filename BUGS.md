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
- Exited non-leader threads stay in the task table as zombies (Linux
  reaps them at once); their kernel stacks and memory are freed.

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

Sleeping locks so far: `i_rwsem`, the mmap_lock, `s_vfs_rename_mutex`,
`f_pos_lock`, RTNL, `TcpSock.rd` and the unix socket `bindlock`/`iolock`.
Linux rw_semaphores/mutexes still modeled as `spin` locks include the
mount namespace/topology locks (namespace_sem,
`Mount` RwLocks), `s_umount` (absent) and pipe locks: their holders must
not sleep (`make check LOCKDEP=1` reports one that does). `RwSem` has
`_killable` and `try` variants; `Mutex` has neither, and there are
no `_interruptible` variants.

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

## Thread-group exit gaps

**Location**: `kernel/signal/mod.rs` (group exit), `kernel/task/exec.rs`
de_thread

exit_group, fatal signals, delay_group_leader and de_thread follow
Linux; what is left:

- A sibling blocked uninterruptibly on its group's cred_guard (a second
  exec, or ptrace attach) while another thread's exec waits in
  de_thread never wakes: both wait (Linux takes cred_guard_mutex
  interruptibly there).
- After an exec from a non-leader thread the new image keeps that
  thread's tid (Linux gives it the leader's pid; hk's pids and tids
  differ anyway, see above).
- Process-directed signals go to one thread's private queue (the
  leader, or a live thread once it has exited), not the shared queue
  with Linux's thread choice at delivery; a pidfd polls readable when
  the leader exits, not when the whole group is gone.

## No signal delivery on return from an interrupt (P7)

**Location**: `kernel/arch/x86_64/interrupts.rs`,
`kernel/arch/aarch64/exceptions.rs` (IRQ return paths)

Pending signals are delivered on the way out of a syscall or a fault
only; an interrupt that arrives in user mode returns without the
signal/reschedule work check (Linux exit_to_user_mode_loop), so a
CPU-bound user task never takes SIGKILL or SIGSTOP: a thread spinning
in user mode outlives its group's exit_group or fatal signal until its
next syscall or fault, delaying the reap (and an exec's de_thread).
With SMP user scheduling (P7) this needs the IRQ-return work check plus a kick IPI
(Linux signal_wake_up -> kick_process).

## Tracees never stop

**Location**: `kernel/task/ptrace.rs` (ptrace_stop, ptrace_report_syscall),
`kernel/signal/mod.rs` (stop signals)

Nothing calls `ptrace_stop`: no signal-delivery stop, no syscall stop,
and SIGSTOP is ignored (stop/continue are not implemented), so a tracee
never enters the Traced state and every request that needs a stopped
tracee (GETREGS, SETREGS, PEEK/POKE*, CONT, ...) fails with ESRCH. The
TLS_PTRACE_RANGE boot test runs on Linux only.

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

## Rare QEMU crash in the arm64 boot test

**Location**: unknown (host QEMU 8.2.2 TCG, `make check-arm`)

Seen once (2026-10-18, during the FD_LEAK group right after
RLIMIT_NPROC): QEMU itself died with SIGSEGV ("the monitored command
dumped core"), the guest printed nothing unusual. Not reproduced in 3
reruns of the same commit. Seen again (2026-10-18, P3 gate) at the same
point, right after RLIMIT_NPROC_CHURN; 4 reruns passed. apport keeps no
core for the packaged QEMU: set core_pattern (or run QEMU under gdb) to
capture one and see whether a virtio request from the guest triggers
it.

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
the page allocator cannot meet panics. The heap goes down to the min
watermark while user data stops at low (also after direct reclaim:
user allocations stop at low until the OOM killer (P6); then Linux's
min), so only kernel objects can get there (no memcg or OOM killer bounds what a process pins in pipes,
sockets or fds); a large contiguous kmalloc can fail first (over 4MB
always, no vmalloc; above low - min, about 700KB at 512MB, once free
memory is near the low watermark).

exec copies the PT_LOAD segments page by page at exec (not mapped from
the page cache like Linux binfmt_elf). Kernel object leaks now cost
free memory (the heap is no longer a separate region): each fork+exec
keeps two dentries and two inodes plus ~900 bytes of kmalloc (~1.3KB;
suspected: procfs entries of dead pids, fixed with the dcache work);
each exited non-leader thread keeps its zombie task (~1KB). The MM_LIFE
tests count MemFree + Slab so they check user memory only; these leaks
are listed here instead.

## Unconfirmed: Arc<T> field corruption in the USB mass-storage driver

**Location**: `kernel/usb/msc.rs`

An early report (before this repository's history) saw `UsbMscDevice`
fields (slot id, bulk endpoints) read back corrupted from an
`Arc<UsbMscDevice>` kept in a static, and worked around it with static
atomics. No such workaround exists in this tree: since the first commit
`UsbMscDevice` keeps `slot_id`, `bulk_in_ep` and `bulk_out_ep` as plain
fields, and the USB vfat boot tests (both arches) pass on them. Kept
only as a pointer if wrong USB slot/endpoint values ever show up again.

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
(and Linux 6.8 where semantics matter), none fixed yet. "Fix in" names
the phase expected to fix it; "next batch" means the next fix batch.

1. **Rename leaves stale dentries; the trap is bypassed** (fix in
   V1/V2, d_move). `kernel/fs/link.rs:593`: after a rename both
   dentries are only `remove_child`'d, so a dentry pinned by a cwd or
   fd keeps its old parent chain; `is_subdir`/`lock_rename`
   (`kernel/fs/mod.rs:150`) compare with `Arc::ptr_eq`. Scenario:
   `mkdir -p /t/a/b; cd /t/a/b; mv /t/a /t/c; rename("/t/c", "z")`
   moves c under its own child (Linux: EINVAL). Fix: Linux d_move /
   d_exchange (dentry name under `d_lock`); vfat must then update the
   moved inode's `parent_cluster`/`short_name` (fs rename needs the
   source inode).
2. **process_vm on own process fails from a sibling thread** (next
   batch). `kernel/task/process_vm.rs:310` exempts only
   `target_tid == current_tid()`; Linux mm_access exempts the caller's
   own mm and `__ptrace_may_access` the thread group. Scenario: a
   non-dumpable uid-1000 process; its second thread gets EPERM from
   `process_vm_readv(getpid())`.
3. Fixed in P3: dumpability lives in the mm (`Mm::dumpable`).
4. **Context switch scans TASK_TABLE for /proc state** (fix in P7, SMP
   scheduler). `kernel/task/percpu.rs:1815` switch_info does two extra
   linear scans under the global TASK_TABLE lock per switch, only to
   record Running/Ready/Sleeping; a woken task shows S until it runs.
   Fix: per-task atomic run state shared with the rq entry, read by
   /proc.
5. **doc/LOCKING.md:596 is wrong**: /proc/<pid>/exe goes through
   mm_access (since eb8c6b6) and takes `exec_update` for reading, not
   "neither lock" (next batch).
6. **linkat AT_EMPTY_PATH capability check only for empty paths**
   (next batch). `kernel/fs/link.rs:220`: Linux 6.8 do_linkat returns
   ENOENT for AT_EMPTY_PATH without CAP_DAC_READ_SEARCH whatever the
   path. Scenario: unprivileged `linkat(AT_FDCWD, "f", AT_FDCWD, "g",
   AT_EMPTY_PATH)` succeeds on hk, ENOENT on Linux.
7. **comm bytes >= 0x80 re-encoded as UTF-8** (next batch).
   `kernel/fs/proc_array.rs:137` pushes `b as char`; Linux
   proc_task_name emits raw bytes (status escapes only `\n` and `\\`).
   Scenario: `PR_SET_NAME "\xe9"`; stat/status show `\xc3\xa9`.
8. **init has no argv/envp/auxv** (next batch). `kernel/main.rs:1149`:
   init's stack is zeroed (argc 0, no auxv) and its mm has no
   arg/env/start_stack layout, so /proc/1/cmdline and environ are
   empty. Linux run_init_process: argv { "/bin/init" }, envp
   { "HOME=/", "TERM=linux" }. Fix: build it with exec's stack builder.
9. **ptrace "init only with CAP_SYS_PTRACE" guard is wrong** (next
   batch). `kernel/task/ptrace.rs:179` tests `target_tid == 1`, which
   is the idle thread (init is tid 2); Linux has no such rule.
   ptrace_attach should instead refuse kernel threads and the caller's
   own thread group (EPERM); hk refuses only the calling thread.
10. **/proc/<pid>/* owner not refreshed on stat** (fix in V2).
    `kernel/fs/procfs.rs:365`: the owner (task_dump_owner) is updated
    at lookup and in permission() only; Linux pid_revalidate updates it
    on every walk. Scenario: stat environ of a uid-1000 child, child
    sets `PR_SET_DUMPABLE 0`, stat again: hk still says uid 1000
    (Linux 0).
11. **Mounts in link.rs** (from the security review).
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
    (c) Checked, no gap: rename's may_delete on both sides and the
    write check on a directory changing parent match vfs_rename,
    including EXCHANGE; linkat's missing may_linkat is
    fs.protected_hardlinks, whose kernel default is 0.

## P1 review findings (open)
From the P1 /code-review (unverified unless noted). Tag = phase that fixes it.
1. **Failed-read pages never discarded** (P5; confirmed by reading).
   `kernel/mm/page_cache.rs:919` discard_page needs refcount 0, but
   find_or_create_page returns refcount 1 and vfat read_bytes /
   write_bytes never put it, so f795e7a's discard is a no-op: after an
   I/O error the zero page is served as FAT/dir data.
2. **No uptodate/page lock on block-device pages** (P5).
   `kernel/fs/vfat.rs:518` inserts the page before the bio read; a
   concurrent reader copies zeros, a concurrent partial write is
   overwritten when the DMA lands. Linux: folio locked + !uptodate
   until read completes.
3. **BLKRRPART/umount don't invalidate the bdev page cache** (P5).
   `kernel/storage/genhd.rs:118`: cache keyed by (major, minor); a
   re-created partition reusing a minor inherits stale and dirty
   pages, which write back at old offsets.
4. **logical_block_size ignored** (next batch).
   `kernel/storage/blkdev.rs:572`: partition scan and RMW issue 512B
   bios; a 4Kn disk shows no partitions and 512B pread gives EIO.
5. **parts_held uses Arc::strong_count** (next batch).
   `kernel/storage/genhd.rs:107`: transient clones (writeback,
   readpage) give spurious EBUSY; mount doesn't take open_mutex, so a
   mount can race drop_bdevs and get a dead device.
6. **Disk removal without open_mutex** (next batch).
   `kernel/storage/sd.rs:374` del_gendisk → drop_bdevs unlocked: races
   BlockDevice::open (opener of a removed partition) and BLKRRPART
   rescans (stale registry entries / /dev nodes).
7. **Segment limits** (next batch). `kernel/storage/blkdev.rs:674`
   max_io assumes PAGE/seg per page; bdev_rw_frame ignores
   max_segments: SIZE_MAX < 4096 without SEG_MAX overflows SEG_MAX /
   MAX_SEGS → EIO.
8. **blk-mq run() locks every CPU's sw queue per bio** (P7).
   `kernel/storage/blk_mq.rs:136`: O(MAX_CPUS) IRQ-off lock pairs and
   cacheline bounces per submit; use a per-hctx pending bitmap (Linux
   ctx_map).
9. **Write path copies** (P5). `kernel/storage/blkdev.rs:749`:
   writes take `&mut [u8]` (to_vec + bounce copy per page); unaligned
   bdev_rw_bytes allocates a request-sized temp buffer.

## P2 review findings (open)
From the P2 /code-review (unverified). Tag = when to fix.
1. Fixed in fix batch 1: vmemmap_init walks the RAM sections one by
   one (no fixed list).
2. Fixed in fix batch 1: the x86 direct map reads every multiboot
   region in place (no 31-entry copy); RAM past the page-table pool's
   reach (48GB) is dropped from memblock as before.
3. Fixed in fix batch 1: a failed allocation drains every CPU's list
   (`Zone::drain_all`, under each list's own lock) and retries once.
4. Fixed in fix batch 1: `Zone::get` is get_page_unless_zero.
5. **pcp_free drains the hot end** (next batch).
   `kernel/mm/page_alloc.rs:425`: freed page pushed at head, drain
   pops from head; Linux returns the cold tail.
6. Fixed in fix batch 1: the per-CPU list is an IrqSpinlock with its
   count beside it (no UnsafeCell aliasing).
7. **arm64 /reserved-memory no-map regions are linear-mapped**
   (next batch; real HW). `kernel/arch/aarch64/dtb.rs:175`: Linux
   memblock_mark_nomap removes them (speculative access to secure
   carve-outs).
8. **Allocator fast-path costs** (P7, with SMP tuning):
   `kernel/heap.rs:262` every free takes the global arena IrqSpinlock
   and an AcqRel swap (compare against the static arena bounds
   instead); `kernel/mm/page_alloc.rs:154` this_cpu() does RDMSR
   GS_BASE per call (use a gs-relative load); `kernel/mm/page.rs:389`
   vmemmap uses 4KB PTEs and one memblock alloc per page (Linux: 2MB
   PMD per section).

## P3 review findings (open)
From the P3 /code-review (unverified). Tag = when to fix.
1. Fixed in fix batch 1: procfs (and other files without Linux
   f_op->mmap) can no longer be mapped (ENODEV; EIO for
   proc_dir_entry files).
2. Fixed in fix batch 1: zap_range falls back to the 4KB entries when
   take_huge_pmd loses to a split.
3. Fixed in fix batch 1: x86 FS/GS bases at or above TASK_SIZE_MAX
   are refused (arch_prctl and CLONE_SETTLS EPERM, SETREGS EIO); arm64
   TPIDR_EL0 takes any value (Linux too).
4. **Remote write gives up after 16 COW tries** (next batch).
   `kernel/mm/remote.rs:176`: spurious EFAULT; break COW and write
   under one PTE-lock hold, or loop until fatal_signal_pending.
5. **populate_pages not killable** (next batch).
   `kernel/mm/syscall.rs:569`: mlock/MAP_POPULATE ignore SIGKILL.
6. **fatal_signal_pending scans TASK_TABLE** (P7).
   `kernel/signal/mod.rs:800`: global lock + O(tasks) per killable
   wake; use a per-task flag.
7. **Minor** (next batch): `kernel/uaccess.rs:244` fault_in_writeable
   unused and duplicates populate_pages; `kernel/fs/io.rs:70`
   copy_in always uses the atomic+fault-in copy (only i_rwsem writers
   need it); `kernel/task/misc.rs:244` USER_HZ duplicated, times()
   assumes TICK_MS == 10.

## Fix batch 1 review findings (open)
From the fix-batch-1 /code-review (unverified). Tag = when to fix.
1. Fixed in P4: take_huge_pmd and split_huge_pmd clear the 2MB entry
   with an exchange under the page_table_lock (a hardware
   accessed/dirty update no longer fails them). No boot test: the race
   needs a user thread writing on another CPU, and user tasks share
   CPU 0 until P7.
2. **Fatal signal to a zombie/exiting thread starts a group exit**
   (next batch). `kernel/signal/mod.rs:999` group_kill: tgkill of an
   exited worker kills the live process (Linux ESRCH); a kill -9
   after all threads exited overwrites the reaped exit status.
   Linux wants_signal skips PF_EXITING.
3. **init is killable by SIG_DFL signals** (next batch).
   `kernel/signal/mod.rs:892`: no SIGNAL_UNKILLABLE check on the new
   fatal-on-arrival path; kill(1, SIGTERM) by root ends the system.
4. Fixed in P4: only thread-context allocations drain the per-CPU
   lists (the THP try is `Gfp::TRANSHUGE_LIGHT`), one drain at a time.
5. **memblock MAX_REGIONS = 128 drops RAM silently** (next batch).
   `kernel/mm/memblock.rs:66`.
6. **kmap direct_pages re-parses the multiboot map per 2MB chunk**
   (next batch). `kernel/arch/x86_64/kmap.rs:152`: O(regions × pages)
   at boot.
7. **group_alive duplicates group_others** (next batch).
   `kernel/task/percpu.rs:1118` vs `:1072`.
Note: d8a7e8d's GROUP_EXEC_THREAD can hang on its own (fixed by
cf0ce50); push both together.

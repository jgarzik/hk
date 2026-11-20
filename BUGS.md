# Known Bugs

## Seen on both hk and the Linux reference

Failures that also occur when the boot tester runs on real Linux
(`check-linux*`). The cause may be the test, the environment, or a
real bug in Linux as well as hk: Linux is the reference, not
infallible, so each one is investigated, not written off.

- **IO_URING_IOPOLL_READ on Linux 7.0** (`user/boot_tester/uring/iopoll.rs`):
  -95 (EOPNOTSUPP) on Ubuntu 26.04's 7.0 kernel
  (`LINUX_RELEASE=resolute ./tools/linux-boot-tester.sh`); passes on 6.8
  and hk. Likely the boot's poll queues or the 7.0 IOPOLL rules.
- **AF_UNIX GC leaks `mixed_lowpoint` on the reference kernel**
  (`user/boot_tester/net/unix_gc.rs`): Ubuntu's 6.8 kernel carries the
  graph collector (4090fa373f0e, v6.10) without 4a4263dfeaba
  ("af_unix: Unify scc_index when finalising SCC in
  __unix_walk_scc()"), so a component with two back edges is never
  freed there; hk has the fix. The test skips that one check on the
  host; drop the skip once the reference kernels carry the fix.
- **ICMP reply counted as echo reply:** Linux icmp_reply leaves
  fl4_icmp_type 0 and the ICMP control socket is SOCK_RAW, so
  __ip_make_skb's icmp_out_count counts every reply (timestamp replies
  included) as an echo reply: Icmp OutEchoReps and IcmpMsg OutType0,
  never OutTimestampReps. hk's icmp_reply matches it (the
  `IpParams::icmp_type` override); `net/icmp_ts` tests the Linux count.

## unsafe not yet wrapped or documented (doc/UNSAFE.md)

Files marked `#![expect(clippy::undocumented_unsafe_blocks)]
// TODO(unsafe)` (`git grep -l 'TODO(unsafe)' -- '*.rs' ':!user'`) remain.
Most of their blocks belong in a missing wrapper:

- **Frames:** an owned / page-locked / PTL-held frame borrow type in
  place of the `mm/page.rs` `frame_bytes` unsafe fn (callers: vfat,
  pipe, fault, filemap, swap, blkdev_ops) and `zero_frame_racy`
  (callers: buffer, mpage), and in the safe fns that take a page they
  require locked by its address alone (`fs/pageio/buffer.rs`
  block_read_full_folio, block_write_full_folio,
  folio_zero_new_buffers; `fs/pageio/mpage.rs`). `mm/filemap.rs`
  `zero_page` is still a safe fn zeroing any frame.
- **DMA:** an owned `DmaBox<T: Pod>` with volatile field access, never
  `&T` into device-written memory: xhci rings and contexts, virtio
  rings and blk, e1000 descriptors, virtio-net buffers.
- **MMIO:** the remaining raw MMIO users move to `mmio::IoMem`: gfx
  framebuffer, vgacon, rtc, pci_quirks, aarch64 serial, x86 power.
- **Lists:** an intrusive `CursorMut` for the walk-and-remove loops
  (futex, waitqueue, sched, percpu).
- **Callbacks:** smp calls with a plain `usize` (`smp_call_function_many`
  without wait, `stop_one_cpu_nowait`, kthread `fn(usize)`) still carry
  integers or casts; the waiting forms have typed `_ref` variants.

## cgroup controller application gaps

**Location**: `cgroup/mod.rs`, `cgroup/cgroupfs.rs`

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
(blk-throttle), freezing under cgroup_mutex. io.max takes any MAJ:MIN
(`cgroup/io.rs` `io_max_write`); Linux resolves it to a live whole
disk first (blkg_conf_open_bdev: ENODEV otherwise).

## user/ does not follow doc/UNSAFE.md

The `user/syscall` wrappers are safe `pub fn`s, and many of them take
raw pointers, so `sys_read(fd, 0x1234 as *mut u8, n)` corrupts memory
without `unsafe`. The boot tester uses many `static mut`, open-codes
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

Listed because real traffic reaches them: TCP has no delivery rate sampling (Linux
tcp_rate.c; only the rate sample's prior_delivered, for RACK's
reordering window), RACK checks every skb of the retransmit queue
(Linux walks tsorted_sent_queue in send order and stops early), no
SACK compression
(Linux __tcp_ack_snd_check delays the ACKs for out-of-order data
after TCP_FASTRETRANS_THRESH of them, tcp_comp_sack_delay_ns,
TCPAckCompressed: hk ACKs each at once), no CUBIC module parameters
(/sys/module/tcp_cubic/parameters: Linux's defaults are constants), no
receive or send buffer autotuning (the window is SO_RCVBUF / 2; no
tcp_sndbuf_expand, so past the TCP memory hard limit a sender's
SO_SNDBUF is not shrunk, sk_stream_moderate_sndbuf; no rcv_ssthresh,
so memory pressure does not clamp windows), no orphan count limit
(tcp_max_orphans; only the memory half of tcp_out_of_resources), no per-netns
RFC 5961 challenge-ACK budget (only Linux's per-connection 500 ms
limit), and TCP_DEFER_ACCEPT / TCP_FASTOPEN are stored only.

UDP has no hash4 (Linux udp_table.hash4: connected sockets by
four-tuple, looked up before hash2), and its compute_score lacks the
sk_incoming_cpu point (hk does not track a socket's receiving CPU).

TIME_WAIT (`net/tcp/timewait.rs`) lacks three Linux parts: an
orphan's FIN_WAIT_2 stays a full socket (Linux tcp_close hands it to
a timewait sock with tw_substate FIN_WAIT2 when tcp_fin_timeout is
at most TCP_TIMEWAIT_LEN; tcp_timewait_state_process's FIN_WAIT2
branch); a takeover SYN's connection gets a fresh ISN, not the
entry's SND.NXT + 65537 (Linux TCP_SKB_CB tcp_tw_isn); and there is
no tcp_max_tw_buckets (inet_twsk_alloc's limit, TCPTimeWaitOverflow).

skbs are linear (no paged frags, skb_shinfo frags): TCP's SACK
shifting (`sack.rs` shift, Linux tcp_shift_skb_data / skb_shift moving
page references) copies the bytes into the previous skb's tailroom and
gives up without room, retransmit collapsing copies too, and every
retransmission or transmit clone copies the payload (Linux
skb_clone shares it). No GSO/TSO: one segment per transmission, a
retransmission resends one MSS (`tcp_retransmit_skb`'s segs is 1;
Linux sends a multi-segment skb as one GSO packet), and pcount above 1
only arises when the MSS shrinks under queued skbs.
An skb holds no reference to its socket (Linux skb->sk with
sk_wmem_alloc, released by sock_wfree): a closed socket's sent frames
still queued on a device do not delay its __sk_free, so "sockets:
used" drops while they are in flight.
No SYN cookies (a full listener drops SYNs).
Neighbour entries are not confirmed by TCP progress (only ARP), there is
no proxy ARP and no per-device neighbour sysctls (net/ipv4/neigh/*).
IP: no ipfrag_max_dist, no IP options on output (received options are
validated and skipped; source-routed packets are dropped), no
IP_TRANSPARENT. /proc/net/raw and /proc/net/icmp do not exist. A UDP
socket has one receive queue (`net/udp/rxq.rs`), not Linux's
per-node producer lists (udp_prod_queue) feeding sk_receive_queue
and a reader_queue spliced from it. No tcp_can_ingest: a segment is not refused for taking
receive memory past SO_RCVBUF (only the window and tcp_mem limit it).
MIB counters (`net/mib.rs`) of mechanisms hk lacks stay 0: header
prediction (TCPHPHits, TCPHPAcks; without the fast path every pure
ACK counts TCPPureAcks, where Linux's fast path skips it), receive
coalescing and collapse, RcvPruned (no tcp_can_ingest),
Fast Open, syncookies, MD5/AO, forwarding and
multicast receive; Ip InDiscards counts few of Linux's sites.
UDP sends are not charged to SO_SNDBUF (Linux sk_wmem_alloc through
sock_alloc_send_skb, which blocks or fails a send past it; corked
data included), and SIOCOUTQ is 0. UDP_SEGMENT is segmented in
software at send (Linux hands a GSO skb to the device); UDP_GRO is
stored only (no GRO: no coalesced receive, no UDP_GRO cmsg); UDP_ENCAP
takes 0 and L2TP only (UDP_ENCAP_ESPINUDP needs XFRM, which hk lacks).
SO_NO_CHECK does not turn off the UDP send checksum (Linux udp_send_skb
sends CHECKSUM_NONE with a zero check field): `udp::UdpSock::xmit`
always computes it.
TCP has no SO_PEEK_OFF (EOPNOTSUPP; Linux inet_stream_ops sets
sk_set_peek_off and tcp_recvmsg peeks at the offset).
A device MTU change leaves path MTU exceptions (`route::NhExceptions`)
as they are (Linux NETDEV_CHANGEMTU fib_sync_mtu lowers them with it and
raises those equal to the old MTU).

## Memory management gaps

**Location**: `mm/`, `arch/*/paging.rs`, `ipc/shm.rs`, `fs/inode.rs`

Missing:

- No inode LRU (Linux inode_lru, prune_icache_sb): an inode put to
  zero while its superblock is active is evicted at once, so
  `iput_final` writes it back first (WB_SYNC_NONE) where Linux keeps
  it cached, dirty, for the flusher.
- Writeback (J): the periodic pass writes every dirty inode of a
  device (Linux only those dirty for vm.dirty_expire_centisecs, which
  is stored but unused); past vm.dirty_ratio the writer writes its own
  inode back synchronously instead of sleeping in balance_dirty_pages;
  the limits are fractions of all managed memory (Linux: dirtyable
  memory). No errseq: fsync reports a writeback error once, to the
  caller that ran the writeback, not to every open file.

- The dcache shrinker (`fs/dentry.rs` shrink_dcache) walks the whole
  tree, locking every dentry, persistent ramfs/tmpfs ones included,
  to free the unused ones (Linux keeps an LRU of unused dentries):
  each pass costs the size of the tree, not what it frees.
- Reclaim (J) drops clean, unmapped page-cache pages inode by inode
  (no file LRU, no aging: Linux reclaims the oldest file pages; dirty
  or mapped ones stay until written back or unmapped), then swaps out
  private anonymous pages, also for MADV_PAGEOUT: no accessed-bit aging
  (pages are reclaimed oldest first), synchronous writes, no kswapd; 2MB pages stay
  off the LRU (never reclaimed whole; a split puts their 4KB pages on
  it). Pages exec copies the image into (see the heap section) are not
  on the reverse map (never swapped). Page faults, swapoff, page-cache, heap
  and pipe allocations that may sleep reclaim directly; atomic heap
  allocations never do, so with anonymous memory filling RAM they fail
  at the low watermark until kswapd (J) keeps free memory above it.
- No readahead (Linux page_cache_ra_*, ->readahead): a page is read
  by its own ->read_folio when first needed, so a vfat file has no
  mpage_readahead (`fs/pageio/mpage.rs`). ->writepage is synchronous, a page
  at a time (Linux ->writepages: mpage_writepages adds contiguous
  pages to one bio and unlocks each once added): a vfat page goes to
  the disk in a bio of its own, its writer waiting.
- File mappings: no fault-around (Linux maps up to 16 cached pages
  per read fault); filesystems without a page cache (procfs) still
  map a private copy.
- A MAP_PRIVATE file mapping's copy of a page (its write fault) is not
  an anonymous page (no rmap, no LRU; Linux makes it one): a read pin
  (`mm/gup.rs` `follow_pin`) of such a copy still shared copy-on-write
  after fork pins it shared instead of first giving the mapping its own
  (Linux gup_must_unshare).
- shmdt needs the address an attachment starts at (Linux also finds a
  piece moved by mremap); SHM_EXEC is ignored.
- exec does not check RLIMIT_AS for the new image and stack (`task/exec.rs`): Linux maps each segment with vm_mmap, whose may_expand_vm makes an image past the limit fail the exec (fatal past the point of no return); hk counts them in total_vm but runs the image.

## NUMA gaps

**Location**: `mm/numa.rs`, `mm/mempolicy.rs`, `mm/page_alloc.rs`

Topology is discovered (ACPI SRAT/SLIT, DT `numa-node-id`) and
getcpu reports it; nothing else uses it. Missing (Linux
`mm/mempolicy.c`, `mm/migrate.c`):

- No shared policy: mbind on a shmem or SysV shm mapping sets only
  that VMA's `mempolicy` (Linux shmem_set_policy keeps it on the
  inode, seen by every mapping of it).
- One buddy zone for all RAM: no per-node zones (pg_data_t) or
  node-aware allocation, so no policy (BIND, PREFERRED, INTERLEAVE,
  local) affects where pages come from.
- No page migration: migrate_pages, move_pages and mbind's
  MPOL_MF_MOVE move nothing (mbind counts a page off the policy's
  nodes as not moved: EIO with MPOL_MF_STRICT); move_pages query mode
  reports node 0 for every page.
- A node is one page frame span (`NumaNode.start_pfn`..`end_pfn`,
  the bounds of all its SRAT/DT ranges): with interleaved ranges
  `pfn_to_node` gives a page the first node whose span covers it
  (Linux page_to_nid: per-section node ids), so get_mempolicy's
  MPOL_F_NODE|MPOL_F_ADDR and mbind's page check see the wrong node.
- mbind with MPOL_MF_MOVE counts a misplaced page mapped by several
  processes as not moved; Linux skips it without MPOL_MF_MOVE_ALL
  (migrate_folio_add).
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
credentials unchanged, so set-id programs run unprivileged. The fix
must read the file's mode, uid and gid under its `i_rwsem`
(bprm_fill_uid's inode_lock), so a racing chown/chmod never pairs a new
owner with the old set-id bits.

## CPU-time timer gaps

**Location**: `time/cpu_timer.rs`, `time/posix_timer.rs`

timer_create and clock_nanosleep take only the caller's own process
CPU clock (and its threads' for timer_create): another process's is
EINVAL (Linux runs those too, checked when that process runs).
A CPU-clock clock_nanosleep's hidden timer takes a timer id from the
process's registry (Linux posix_cpu_nsleep's timer is not hashed: the
next timer_create id does not move). rseq is ENOSYS (glibc runs
without it).

## AF_PACKET gaps

**Location**: `net/packet/`

Not implemented: SO_ATTACH_BPF, SO_GET_FILTER, and
socket filters on non-packet sockets (ENOPROTOOPT; Linux runs them on
every socket). Memberships only count promiscuity/allmulti users (the
drivers have no promiscuous or multicast filtering; set_promisc is a
no-op on e1000 and virtio-net, which has no control queue: QEMU then
delivers all frames).
Checksum state (TP_STATUS_CSUMNOTREADY, PACKET_VNET_HDR's NEEDS_CSUM):
only UDP over lo is CHECKSUM_PARTIAL (`SkBuff::csum_partial`); TCP
segments over lo are not marked (Linux tcp_v4_send_check makes them
CHECKSUM_PARTIAL), nor is a corked UDP datagram exempt (Linux
__ip_append_data leaves MSG_MORE sends CHECKSUM_NONE).
The TX ring copies each frame into an skb and makes it
TP_STATUS_AVAILABLE once queued; Linux sends the ring pages themselves
(zero copy) and frees the frame at the skb's completion
(tpacket_ubuf_complete), a blocking send waiting for pending frames.
The TPACKET_V3 retire timeout without tp_retire_blk_tov is always
8 ms: hk keeps no ethtool link speed (Linux prb_calc_retire_blk_tmo
derives it from the block size on links of 1 Gb/s and up, e.g. e1000,
r8169). tp_rxhash (TP_FT_REQ_FILL_RXHASH) is a jhash of the flow, not
Linux's siphash flow-dissector hash.
Fanout: PACKET_FANOUT_FLAG_DEFRAG is kept but IPv4 fragments are not
reassembled before hashing (Linux ip_check_defrag); PACKET_FANOUT_EBPF
groups take no program (hk has no bpf(2): PACKET_FANOUT_DATA is EBADF
or EINVAL, frames go to member 0); the flow hash is a jhash of the
IPv4 5-tuple, not Linux's siphash flow dissector.
PACKET_VNET_HDR: no GSO, so a send whose virtio_net_hdr asks for
segmentation (longer than gso_size) is EINVAL where Linux segments it,
and a NEEDS_CSUM checksum is completed in software before transmit
where Linux leaves it CHECKSUM_PARTIAL on lo (the bytes on the wire
differ from Linux lo, not from a device without offload).
Transmitted frames keep no skb->protocol: packet sockets tapping them
report the frame's EtherType, where Linux reports the sender's
sll_protocol / spkt_protocol (0 for a SOCK_PACKET send with a 16-byte
address).
Ring blocks are physically contiguous (`mm::shared::PgVec`): a
tp_block_size past the buddy allocator's largest order is ENOMEM where
Linux alloc_one_pg_vec_page falls back to vzalloc.

## fanotify gaps

**Location**: `io/fanotify.rs`

- Events carry FAN_NOFD: read opens no file with fanotify_init's
  event_f_flags (Linux copy_event_to_user / create_fd).
- fanotify_mark keeps only the mask: FAN_MARK_IGNORED_MASK,
  FAN_MARK_IGNORE, FAN_MARK_IGNORED_SURV_MODIFY and FAN_MARK_EVICTABLE
  are accepted but have no effect (Linux fanotify_add_mark).

## vfat gaps

**Location**: `fs/vfat/mod.rs`, `fs/vfat/fatent.rs`

- FAT32 only: `vfat_fill_super` refuses FAT12/16 (Linux fat_ent_ops
  fat12_ops / fat16_ops).
- A directory whose cluster chain breaks mid-way is EIO; Linux
  fat__get_entry ends the directory there.
- No FAT attribute bits on the inode: write_inode does not write
  them (Linux fat_make_attrs, ATTR_RO from the mode, ATTR_HIDDEN etc.
  kept in MSDOS_I(inode)->i_attrs), and the first write after one is
  cleared does not set ATTR_ARCH with the times (Linux fat_write_end).
- No `sbi->s_lock` mutex around namespace operations (Linux
  vfat_create, vfat_rename etc. take it).
- A directory's i_size is 0 and its cluster count (`VfatInodeData.clusters`,
  Linux i_blocks) not kept (Linux: its chain length, fat_calc_dir_size),
  so `fat_chain_add` counts only a file's clusters (and checks them
  against its chain).
- No FSINFO: the free count and next-free hint are kept in memory
  only (Linux fat_set_state / fat_clusters_flush).

## O_DIRECT gaps

**Location**: `fs/pageio/blkdev_ops.rs`, `block/dio.rs`, `block/blkdev.rs`,
`fs/vfat/`

- Block-device and vfat O_DIRECT from kernel virtual memory (a kernel
  `IovDest` or `IovSource`) is not pinned (`get_pages`: EOPNOTSUPP)
  and takes the cached path; Linux sends bios from it (ITER_KVEC) with
  the same alignment rules. Pinned pages (Linux ITER_BVEC: io_uring's
  registered buffers) go to bios through `dio::submit_async`.

## Linux AIO gaps

**Location**: `io/aio/`

- RWF_NOWAIT on a file without nonblocking I/O (Linux: no
  FMODE_NOWAIT) fails the request's event with EOPNOTSUPP; Linux fails
  the io_submit itself (kiocb_set_rw_flags). hk has no FMODE_NOWAIT.
- IOCB_CMD_FSYNC/FDSYNC on a file without ->fsync (pipes, sockets) is
  an event of 0: `FileOps::fsync` defaults to success (fsync(2) too);
  Linux fails the io_submit with EINVAL (aio_fsync).
- The ring is one physically contiguous `SharedRegion`: a large
  io_setup (aio-max-nr's default allows 4 MiB) can fail with ENOMEM
  under fragmentation; Linux's ring is separate pages
  (`ring::AioRing`; io_uring's rings likewise).
- FSYNC/FDSYNC and poll completion work run on `SYSTEM_WQ`'s single
  worker, one at a time; Linux's system_wq runs concurrency-managed
  pools.
- An ended O_DIRECT request is released in thread context
  (`Kiocb::put_any` -> `Kioctx::defer`: the reap list, drained by the
  next io_submit/io_getevents or a delayed work item), not where its
  bios end as Linux iocb_destroy (unpinning there unless pages must be
  dirtied under their page lock: bio_check_pages_dirty; fput's
  delayed_fput for a last file reference). The file's put is safe
  there now (a `FileRef` dropped in hardirq goes to the delayed list);
  the rest of the request's release is not yet. AIO 4K QD1 (`make check BENCH=1`,
  DIO_BENCH) is unexplained and noisy: 12k..81k IOPS across boots of
  one kernel, Linux 15k..110k on the same host; with the request
  spinning on the ring rather than sleeping, about 16.5 us per request
  (submit about 3 us), sleeping adds about 5 us.

## File lock gaps

**Location**: `fs/locks.rs`, `fs/posix_lock.rs`

No leases (F_SETLEASE) and no OFD locks (F_OFD_*).

## seccomp gaps

**Location**: `seccomp/`

No user notification (SECCOMP_RET_USER_NOTIF; FLAG_NEW_LISTENER and
FLAG_WAIT_KILLABLE_RECV are EINVAL), and nothing is logged for RET_LOG
or FLAG_LOG.

## AF_UNIX gaps

**Location**: `net/unix/`

Not implemented: SO_INQ / SCM_INQ, SO_PASSRIGHTS and SO_RIGHTS_NOTRUNC
(newer than the v6.8 reference kernels), SO_PEERSEC (ENOPROTOOPT, as on
Linux without an LSM).

## File permission (DAC) gaps

**Location**: `fs/dac.rs`, `task/exec.rs`

Missing: immutable/append-only inodes (no IS_APPEND/IS_IMMUTABLE
EPERM).

## Before user namespaces grant capabilities

**Location**: `task/mod.rs` (`capable`), `fs/dac.rs`, `ns/mod.rs`,
`fs/mount.rs`, `fs/pnode.rs`, `fs/fhandle.rs`, `net/netlink/rtnetlink.rs`

Safe today only because a user namespace grants no capabilities. First:
- each `capable()` becomes Linux's `ns_capable(<owner>->user_ns)` (or
  `capable`, where Linux keeps it); sockopt_ns_capable sites take the
  socket netns's user_ns, but SO_DEBUG and SO_SNDBUFFORCE/RCVBUFFORCE
  stay init-namespace (Linux sockopt_capable).
- netlink newlink/setlink check CAP_NET_ADMIN in the target netns too
  once IFLA_NET_NS_PID/FD are implemented (`7b735ef81286`).
- creating a namespace together with CLONE_NEWUSER checks capabilities
  in the new user namespace, where the caller holds every capability
  (today any namespace but a user namespace needs the caller's own
  CAP_SYS_ADMIN, even with CLONE_NEWUSER), and /proc/<pid>/uid_map and
  gid_map become writable.
- mounts become user-namespace aware (plain `capable()` today, Linux
  ns_capable of the mount namespace's `user_ns`).
- open_by_handle_at's `may_decode_fh` (`fs/fhandle.rs`) gains Linux's
  O_DIRECTORY path for a caller with CAP_SYS_ADMIN over the file
  system's or mount namespace's user namespace (HANDLE_CHECK_PERMS,
  HANDLE_CHECK_SUBTREE with has_locked_children, EXPORT_FH_DIR_ONLY);
  today it is CAP_DAC_READ_SEARCH or EPERM.

## File handle gaps

**Location**: `fs/exportfs/mod.rs`, `fs/fhandle.rs`, `fs/vfat/`,
`cgroup/cgroupfs.rs`, `fs/pseudo/nsfs.rs`

Only tmpfs decodes handles; elsewhere name_to_handle_at encodes a file
id (AT_HANDLE_FID) and is otherwise EOPNOTSUPP. Missing export
operations, as Linux has them:
- vfat's (fat_export_ops, FILEID_FAT_*): needs ->fh_to_parent,
  ->get_parent and ->get_name, disconnected dentries (d_obtain_alias,
  DCACHE_DISCONNECTED) and reconnect_path; with ->fh_to_parent,
  AT_HANDLE_CONNECTABLE handles (now EOPNOTSUPP everywhere).
- cgroup2's (kernfs_export_ops, FILEID_KERNFS).
- nsfs's (nsfs_export_operations, FILEID_NSFS, with ->permission and
  ->open): FD_NSFS_ROOT is accepted as a mount fd, but nothing there
  decodes.
- pidfs (FD_PIDFS_ROOT is EBADF: pidfds are anonymous inodes).

## Credentials have no identity

**Location**: `task/mod.rs` (`Cred`), `fs/namei/mod.rs` (`may_linkat_empty`)

`Cred` is a value, not Linux's shared, refcounted `struct cred`. linkat
AT_EMPTY_PATH compares `f_cred` with the caller's creds by value, where
Linux compares pointers. Any commit_creds since the open, and fork's
copy_creds, gives Linux a new pointer. So an fd inherited across fork
by a same-uid child, or passed between same-cred processes, can be
linked on hk without CAP_DAC_READ_SEARCH; Linux gives ENOENT. The
capability is checked in the caller's namespace (Linux: the opener's
`user_ns`); hk has one user namespace.

## POSIX mqueue gaps

**Location**: `ipc/mqueue.rs`

There is no mqueue filesystem at all: queues live only in a kernel
table, so they cannot be listed or read as files under /dev/mqueue
(Linux mqueue_fs_type), and an mq_open descriptor does not open again
through /proc/<pid>/fd or O_EMPTYPATH (ENXIO; Linux opens the queue
through the mqueue mount).
mq_notify with SIGEV_THREAD is EINVAL: Linux delivers that notice as
a message on a netlink socket the caller names (NETLINK_NOTIFY_COOKIE,
glibc's helper thread), and hk has no such path.

## Resource tree gaps

**Location**: `base/resource.rs`

/proc/ioports holds the x86 legacy ranges, PCI conf1 and the 8250
ports only: no PCI host bridge windows (Linux reads the root bus's
from ACPI _CRS, which needs AML), PCI BARs, ACPI register blocks,
PNP devices or vga+. There is no iomem tree (request_mem_region) and
no /proc/iomem (System RAM, Kernel code, reserved, BARs), so
TIOCSSERIAL refuses (EINVAL) a new io_type, iomem_base, regshift or
hub6, where Linux moves the port (uart_change_port).

## sysfs gaps

**Location**: `fs/kernfs/`, `fs/kernfs/sysfs.rs`, `base/`, `block/genhd.rs`,
`net/sysfs.rs`, `hw/pci/driver.rs`

- No power/ directories (Linux dpm_sysfs_add: control, runtime_status,
  wakeup ...), no /sys/power, /sys/firmware/{acpi,dmi,efi} or
  /sys/class/dmi/id: the directories exist empty.
- Missing classes: rtc (PL031 has no /dev/rtc0), input (Phase V),
  misc, graphics/drm, pci_bus; no /sys/kernel/{security,debug,config}
  mount points (hk has none of those filesystems).
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

- **Line discipline input untested:** no boot test types into a tty,
  so the N_TTY receive path (`tty/n_tty.rs`: the echo ring, inline
  ISIG signals, canonical lines, the lock-free input check poll uses)
  runs only on the console's real input. A pty (phase H) makes it
  testable from the boot tester.
- **Hangup gaps:** no carrier (DCD) loss hangs a tty up (no modem
  control). No boot test unbinds the console UART (the test output
  goes there).
- **Missing:** TIOCSTI, sending a break (TCSBRK 0), packet mode,
  ptys, VLNEXT/VREPRINT/VDISCARD, ECHOPRT, IUCLC/OLCUC, IMAXBEL,
  PARMRK and parity/break input handling, CRTSCTS (no modem
  control: IXOFF throttles by STOP/START only).
- **No driver set_termios:** a termios change never reaches the
  UART (Linux uart_set_termios -> serial8250_do_set_termios,
  pl011_set_termios): speed, character size, parity and stop bits stay
  as booted, and the speed is not clamped to the UART's range and
  encoded back (uart_get_baud_rate, tty_termios_encode_baud_rate), so
  a BOTHER speed reads back as BOTHER where Linux reports the nearest
  Bfoo; locked termios (TIOCGLCKTRMIOS, TIOCSLCKTRMIOS) and the ADDRB
  reset (tty_set_termios) are missing too.
- **Serial ports:** ttyS1 is registered without probing COM2. The
  PL011 has no startup or
  shutdown (Linux pl011_startup/pl011_shutdown): its interrupts stay
  on while the port is down.
- **No virtual terminals:** the framebuffer and VGA consoles are not
  ttys (Linux: fbcon/vgacon draw VTs, tty0..tty63, fed by the
  keyboard), so /dev/console is always a serial tty. With a screen
  console (console=tty0), Linux's /dev/console is the VT; on hk user
  console I/O stays on the serial port and the screen shows only
  printk.

## Futex gaps

**Location:** `task/futex.rs`

- **FUTEX_WAKE_OP and PI futexes** are missing.
- **FUTEX2_MPOL:** MPOL_BIND and MPOL_PREFERRED_MANY policies name no
  node (Linux: their home_node; hk has no set_mempolicy_home_node).
- **FUTEX2_NUMA:** each call takes the global `NUMA_TOPOLOGY` lock for
  the node checks (Linux numa_node_id and node_possible read per-CPU
  and static state).
- **MAP_PRIVATE file mappings:** a shared futex there is keyed by
  (mm, address) from the VMA; Linux keys a page still in the page
  cache (not yet COW'd) by inode and offset, so a MAP_SHARED mapping
  of the same file wakes it.

## Mount flag gaps

**Location**: `fs/misc.rs` sys_mount/sys_umount2, `fs/mount.rs`

Accepted without effect: MS_SILENT, MS_MANDLOCK, MS_POSIXACL,
MS_I_VERSION, MS_LAZYTIME. Mount options are
parsed by vfat (Linux's set; long names UTF-16 in UTF-8, iso8859-1 or
cp437 only), ramfs (mode=), tmpfs and devtmpfs (see "tmpfs gaps") and
procfs (hidepid=, gid=, subset=pid; devtmpfs drops a new mount's after
parsing them, as Linux 6.15+); cgroupfs ignores its own, and only
procfs, tmpfs and devtmpfs apply options on a remount or show them in
/proc/mounts.
A mount names its namespace by id (`Mount::mnt_ns`; Linux
mnt->mnt_ns points to it), so a namespace keeps no mount count:
NS_MNT_GET_INFO's nr_mounts is a walk of its tree under NAMESPACE_SEM
(Linux reads mnt_ns->nr_mounts), and there is no fs.mount-max limit
(sysctl_mount_max, count_mounts: ENOSPC).

## nullfs gaps

**Location**: `fs/nullfs.rs`, `fs/mount.rs` init_mount_tree,
`fs/fsstruct.rs` KTHREAD_FS

The nullfs root (Linux 7.0), the kernel threads' private nullfs (7.3)
and its file (7.4) are in place; a user path reaches the last two only
as a cover's stand-in (Linux 7.4 __lookup_mnt). Not done: empty mount
namespaces and the nullfs that stands in for an unmounted mount. Locks
are not refused with ENOLCK (31a1fb90624d), MS_REMOUNT and umount of the root are not refused on
the internal superblock (d791606bb915), and nothing marks knullfs's
root as unmountable (e22e69c2ad88: dont_mount). Kernel code that resolves a path from a kernel thread finds nothing
(knullfs); hk has none today, and has no scoped_with_init_fs for one
that would need init's root.

## No vDSO

**Location**: `task/exec.rs`, `arch/aarch64/signal.rs`

No vDSO is mapped (no AT_SYSINFO_EHDR): libc makes real syscalls for
clock_gettime and friends. On arm64 a page holding only the signal
return trampoline stands in for the vDSO's sigtramp, shown as
[sigpage] in /proc/<pid>/maps (Linux: [vdso], [vvar]).

## ptrace request gaps

**Location**: `task/ptrace.rs`

PTRACE_PEEKUSER/POKEUSER, PTRACE_GETFPREGS/SETFPREGS and
PTRACE_GETREGSET/SETREGSET are EINVAL (Linux arch_ptrace: gdb reads
debug registers and FP state through them).

## NETLINK_ROUTE / SIOC* subset gaps

**Location**: `net/netlink/rtnetlink.rs`, `net/devioctl.rs`

No notifications for neighbour state changes (no RTNLGRP_NEIGH); no
proxy ARP entries, NTF_USE or NDA_PROTOCOL.
Missing, each answered with a Linux errno rather than silently: link
creation and rename (EOPNOTSUPP), multipath routes and nexthop objects
(EOPNOTSUPP), input-route simulation `ip route get ... iif` (EOPNOTSUPP),
NLM_F_ECHO (not echoed), extended-ACK message/offset TLVs (plain errors),
address lifetimes are always infinite, promote_secondaries is off.
Routing rules are Linux's three IPv4 defaults, fixed: RTM_NEWRULE and
RTM_DELRULE are EOPNOTSUPP, lookups walk tables local then main and never
default (no rule engine), and rule dumps of other families are
EAFNOSUPPORT (Linux lists the IPv6 and multicast-routing defaults).
RTM_NEWLINK/RTM_SETLINK apply MTU and flags only; the rest is refused
with the errno Linux gives a device or driver lacking it, never ignored:
moving a device to another namespace (IFLA_NET_NS_PID/FD; EOPNOTSUPP, lo
EINVAL as Linux), MAC address, carrier, master, VF, proto_down, XDP and
per-family (IFLA_AF_SPEC) settings are EOPNOTSUPP. Group, alias,
broadcast address, txqlen, GSO/GRO limits, operstate and link mode, which
Linux always applies, are EOPNOTSUPP unless equal to the device's fixed
value; IFLA_TARGET_NETNSID / IFLA_LINK_NETNSID are EINVAL (no namespace
ids).

## io_uring gaps

**Location**: `io/io_uring/`

- GETEVENTS ignores io_uring_getevents_arg's min_wait_usec (Linux
  IORING_FEAT_MIN_TIMEOUT) and IORING_ENTER_ABS_TIMER (EINVAL)
- What would block goes to io-wq workers that block where Linux arms
  poll (a read of an empty pipe or socket, Linux IORING_FEAT_FAST_POLL):
  one worker per blocked request; on an O_NONBLOCK pipe or socket the
  worker's read is EAGAIN (Linux polls until it is ready). Link chains
  run in a worker, not issued inline one by one; a chain with
  poll/timeout bookkeeping runs in io_uring_enter
- A queued request with offset -1 does not move the file position (as
  Linux), an inline one does
- IORING_OP_TIMEOUT has no timer (nothing ever completes it), and has
  no count trigger, TIMEOUT_UPDATE or MULTISHOT
- IORING_OP_LINK_TIMEOUT returns 0 without arming anything
- poll ops never complete asynchronously
- Most opcodes past IORING_OP_SHUTDOWN are not handled (EINVAL CQEs)
- Setup flags: no SQPOLL (Linux allows it unprivileged), SUBMIT_ALL,
  COOP_TASKRUN, TASKRUN_FLAG, SINGLE_ISSUER, DEFER_TASKRUN,
  NO_SQARRAY, SQE128/CQE32, NO_MMAP, REGISTERED_FD_ONLY, R_DISABLED,
  ATTACH_WQ (EINVAL); no registered ring fds
  (IORING_ENTER_REGISTERED_RING), personalities, provided buffers,
  eventfd, buffer updates or tags (IORING_REGISTER_BUFFERS2,
  BUFFERS_UPDATE)

## Rare QEMU crash in the arm64 boot test (host CPU suspected)

**Location**: host, not hk (QEMU 8.2.2 TCG on the Core Ultra 9 285K
host, `make check-arm`)

qemu-system-aarch64 occasionally dies in the guest stage-1 page table
walk (arm_ldq_ptw in target/arm/ptw.c; once S1_ptw_translate): the
fault address differs from the pointer the faulting load holds, so the
host CPU computed a wrong address. The crashes run on CPUs 5 and 2,
the favored cores, which also lead the host's segfault count for other
programs; hk's fork/exit churn (RLIMIT_NPROC, FD_LEAK) makes QEMU walk
page tables hardest. Nothing in hk can avoid it. To do: check the BIOS
for Intel default power/turbo settings and current microcode,
stress-test CPUs 2 and 5, or keep gate QEMUs off them (taskset).

## Rare arm64 kernel instruction abort in the fault-signal tests

**Location**: unknown (CPU 0, right after `FAULT_SEGV_ACCERR`, i.e. while
`FAULT_SIGILL` runs `udf` in user mode)

One "KERNEL PANIC" from the arm64 `exceptions.rs` kernel instruction
abort handler, rare across many `make check-arm` runs (QEMU neoverse-n1
with PAN, -smp 4);
ELR/FAR were not captured. Next occurrence: capture the Message line.

## tmpfs gaps

**Location**: `fs/ramfs/tmpfs.rs`, `fs/ramfs/mod.rs`, `mm/filemap.rs`

tmpfs/shmem is not swap-backed (phase J): its pages, SysV shm and
shared anonymous memory included, never go to swap (the mapping is
unevictable, like ramfs; Linux shmem_writeout swaps them), and noswap
is only recorded. huge= takes only
never, mpol= and the quota options are refused (EINVAL), as on a Linux
without THP, NUMA or CONFIG_TMPFS_QUOTA. inode32 is recorded and shown
but inode numbers do not wrap at 2^32 (Linux shmem_reserve_inode).
F_SEAL_WRITE (`mm/memfd.rs` fcntl) does not wait for or refuse pages
pinned by other references (Linux memfd_wait_for_pins: EBUSY after
waiting).

## Fault injection and debugfs gaps

**Location**: `mm/fault_inject.rs`, `fs/debugfs.rs`

- Only fail-nth injects: fault_create_debugfs_attr's generic files
  (probability, interval, times, space, verbose, verbose_ratelimit_*,
  task-filter with /proc/<pid>/make-it-fail, stacktrace-depth and the
  require/reject address filters) and the failslab= / fail_page_alloc=
  boot parameters are missing, as are failslab's cache-filter (and
  /sys/kernel/slab/<cache>/failslab) and the other fault types
  (fail_futex, fail_usercopy, fail_make_request, fail_io_timeout,
  fail_function).
- The heap's page refills (`mm::slab` `KernelPages`, `mm::vmalloc`
  `alloc`) pass `Gfp::NOFAIL`, so fail_page_alloc never fails a
  kmalloc's slab refill as in Linux: the heap also serves infallible
  allocations, whose failure panics (failslab covers its fallible
  ones).
- debugfs has no removal (debugfs_remove), no debugfs= boot option
  (debugfs_allow) or lockdown check, no automount points and only the
  bool and u32 file helpers; a u32 file formats its value on every read
  (Linux simple_attr keeps it per open for a continued read).

## tracefs gaps

**Location**: `fs/tracefs.rs`

- No instances/ directory (tracefs_create_instance_dir: mkdir/rmdir of
  trace instances), so nothing removes a tracefs entry at run time.

## fsync and freeze gaps

**Location**: `fs/inode.rs` (`touch_atime`)

- No filesystem freezing (FIFREEZE/FITHAW, sb_start_write): writers
  such as touch_atime take mount write access only.

## Buffer head gaps

**Location**: `fs/pageio/buffer.rs`, `mm/filemap.rs`

- A page truncated while one of its buffers is still referenced (the
  per-CPU LRU of another CPU, a holder) leaves its mapping with its
  buffers and its frame (Linux frees both later in shrink_folio_list,
  from the file LRU, which hk lacks: Memory management gaps).
- hk's folios are a page: a block device's soft block size above a
  page (BLKBSZSET up to 64K) gives its cache page-sized buffers, and
  bdev_getblk of such a block is EINVAL (Linux makes large folios of
  one block each, mapping_set_folio_min_order).
- No __GFP_NOFAIL: bread and bdev_getblk fail ENOMEM when the
  device-cache page or its buffers cannot be allocated
  (`getblk_slow`), where Linux's (__bread_gfp, __getblk) retry until
  they can; their callers return it.
- No buffer-head count limit (Linux buffer_heads_over_limit, which
  makes reclaim strip buffers), no page migration of buffered pages,
  no BH_Delay / BH_Unwritten / BH_Boundary users.

## renameat2 flag gaps

**Location**: `fs/ramfs/`, `fs/vfat/mod.rs`

- RENAME_WHITEOUT is EINVAL everywhere; Linux tmpfs makes whiteouts
  (shmem_whiteout).
- vfat lacks RENAME_EXCHANGE (Linux vfat_rename_exchange).

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

**Location**: `cgroup/memory.rs`, `mm/fault.rs`, `mm/filemap.rs`

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

## BPF map memory is not charged

**Location**: `bpf/map.rs`

An array or hash map refuses a size over half of free memory at
creation, but nothing adds maps up: no RLIMIT_MEMLOCK or memcg charge (Linux
bpf_map_charge_memlock / memcg accounting), so many maps can still use
up memory.

## Deferred file release gaps

**Location**: `fs/file.rs` (`FileRef`, `fput`), `task/task_work.rs`,
`sync/waitqueue.rs` (`signal_pending_run_work`)

- Queued releases run inside futex and nanosleep sleeps when
  TIF_NOTIFY_SIGNAL is set (`signal_pending_run_work` runs task_work
  there); Linux runs TWA_RESUME work only on the return to user mode
  (and io_uring's own waits).
- Between the io_uring cancel and `exit_task_work` the task_work list
  is still open: a late io_uring callback's TIF_NOTIFY_SIGNAL can
  interrupt sleeps in that part of exit.

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
- The idle loop (`idle_task_entry`) halts at once: no polling before
  the halt (TIF_POLLING_NRFLAG, haltpoll), so every remote wakeup pays
  an IPI and the exit from HLT/WFI. It also runs `yield_now` and
  `sched_balance_rq` on every pass.
- `select_idle_sibling` has no wake_affine and no recent_used_cpu: a
  woken task moves between CPUs from one wakeup to the next, and with
  it the blk-mq hardware queue its I/O goes to.

## xHCI driver gaps on real hardware

**Location**: `hw/usb/xhci.rs`, `hw/usb/xhci_ring.rs`, `hw/usb/msc.rs`

QEMU's xHCI hides all of them.
- No hub support (route string 0): devices behind a hub are not
  enumerated.
- Only bulk and interrupt endpoints are added to the controller
  (`configure_endpoints`): isochronous and non-default control
  endpoints are skipped.
- Only 4 KiB controller pages and up to 512 scratchpad buffers.
- INTx only (Linux tries MSI-X, then MSI): see "x86 has no IOAPIC or
  MSI"; a controller without an INTx line is not started, as Linux
  without any interrupt.

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
  quirks). A failed command's sense is not fetched (Linux
  usb_stor_invoke_transport's REQUEST SENSE), and past a Bulk-Only
  reset there is no port reset (Linux usb_stor_port_reset,
  usb_reset_device) or SCSI error handler.
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
and r8169 all support: MSI-X exists (`hw/pci/msix.rs`, x86 vectors in
`arch/x86_64/irq.rs`) but only virtio-blk uses it, and plain MSI (the
MSI capability, which RTL8168g and some AHCI parts offer alone) is
missing. The MADT parser skips IOAPIC entries (Linux
acpi_parse_ioapic registers them).

## UEFI boot finds no ACPI tables

**Location**: `arch/x86_64/acpi.rs` (`find_rsdp`), `arch/x86_64/multiboot2.rs`

The RSDP is found only by scanning the legacy BIOS areas (EBDA,
0xE0000-0xFFFFF). Under UEFI it is not there: GRUB passes it in the
multiboot2 ACPI old/new RSDP tags (types 14 and 15; Linux takes it from
the EFI system table or boot_params.acpi_rsdp_addr), which hk ignores,
so a UEFI boot of the Dell OptiPlex 3020 panics without ACPI.

## TLB gaps

**Location**: `arch/x86_64/tlb.rs`, `mm/tlb.rs`, `arch/aarch64/`

- x86 has no PCID and no global pages (CR4.PGE clear): every CR3 write
  drops the whole TLB, kernel entries included (Linux: PCID-tagged
  ASIDs per CPU, _PAGE_GLOBAL kernel mappings), and no lazy TLB mode
  for kernel threads (Linux switch_mm_irqs_off leaves the old mm loaded).
- No ranged or broadcast invalidation hardware: arm64 FEAT_TLBIRANGE
  (Linux __flush_tlb_range_op), AMD INVLPGB/TLBSYNC (Linux
  invlpgb_flush_user_nr_nosync) and Intel RAR; every remote flush is
  an IPI on x86 and per-page TLBI on arm64.

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

## Writeback of a superblock with no block device

**Location**: `fs/pageio/fs_writeback.rs` (`__mark_inode_dirty`, `sync_inodes_sb`)

An inode dirtied on a superblock without a backing device (Linux
noop_backing_dev_info) is marked dirty but queued nowhere, and
syncfs/umount write nothing for it; its dirty mark then stays, so it
is never queued again. No such file system dirties pages for writeback
today (ramfs/tmpfs pages are unevictable or swap-backed); one that
does needs a backing device of its own, or Linux's noop wb lists with
its no-writeback skip, before it relies on sync.

## Block layer gaps

**Location**: `block/`, `hw/virtio/blk.rs`,
`fs/pageio/blkdev_ops.rs`, `fs/vfat/`

- Partition tables are parsed in 512-byte sectors: on a disk with
  larger logical blocks, GPT LBAs and MBR sector counts are misread
  (Linux scales by the logical block size). MBR: no BSD, Solaris,
  UnixWare, Minix, AIX or DM6 subpartitions. GPT: like Linux without
  the `gpt` parameter, a bad primary header is not replaced by the
  backup.
- BLKDISCARD, BLKZEROOUT, BLKSECDISCARD, BLKGETDISKSEQ, BLKROTATIONAL,
  BLKDISCARDZEROES, BLKRAGET/BLKRASET, BLKFRAGET/BLKFRASET, BLKTRACE*,
  the zone, persistent reservation and BLKPG partition ioctls are
  ENOTTY. HDIO_GETGEO is ENOTTY on sd disks (Linux sd_getgeo:
  scsicam_bios_param from the MBR, else a computed CHS).
- virtio-blk: modern devices only (QEMU needs `disable-legacy=on`;
  Linux also drives transitional devices), INTx on arm64 (no MSI: the
  GICv3 ITS has no driver; Linux uses it on QEMU virt),
  capacity changes (config interrupts) are ignored, no DISCARD,
  WRITE_ZEROES, GET_ID (serial) or secure erase. The disk's queues are
  fixed at probe.
- `VirtioDevice::reset` (`hw/virtio/pci.rs`) spins a bounded number
  of status reads and fails, where Linux vp_reset sleeps (msleep(1))
  until the status reads 0 (vp_modern_set_status, then the wait): a
  reset that does not complete makes `del_vqs` leak the rings, and
  virtio-net's remove (`virtnet_del_vqs`) its buffer pools too.
- virtio-pci remove leaves the BAR mappings (common, notify, ISR,
  device config): `IoMem` windows are copyable and never unmapped, so
  each transport rebind leaks the ioremap space of one device (Linux
  vp_modern_remove iounmaps them).
- No /proc/devices block section; the first disk
  registered decides the dynamic major (254 down, like Linux, but Linux
  usually has other dynamic majors registered first).
- Exclusive claims have no holder operations (Linux blk_holder_ops:
  mark_dead, sync, freeze, thaw of a mounted filesystem when its device
  goes away or is frozen), no BLK_OPEN_RESTRICT_WRITES and no
  disk-event blocking for write holders.

fallocate on a block device is EOPNOTSUPP (Linux blkdev_fallocate zeroes
or discards the range).

## Code-quality gaps, by phase

Designs that grew one commit at a time. Tag = roadmap phase
(doc/ROADMAP.md).

- **Syscalls that do not deliver** (H): inotify queues only
  IN_DELETE_SELF, IN_UNMOUNT, IN_IGNORED and IN_Q_OVERFLOW, fanotify
  nothing (the other events have no fsnotify hooks in the VFS
  operations); rename has no
  IN_MOVED_FROM/IN_MOVED_TO cookie pairing (Linux fsnotify_get_cookie).
- **Copied helpers** (J, or as touched): `current_time` in cgroupfs,
  perm, procfs and ramfs, `current_time_secs` in ipc msg/sem/shm;
  user-timespec readers each validating (futex `read_user_timeout`,
  poll `read_ts`, mqueue, posix_timer...; Linux get_timespec64); Timespec
  types `time::Timespec`, `LinuxTimespec` (time_syscall), `SemTimespec`
  (ipc/sem); Timeval types in task/misc and time_syscall, plus
  `TimexTimeval`.
- **ID allocators** (J): PidMap, fdbits, IPC ids, and plain counters
  (bpf map ids, mqueue ids, which wrap with no collision check) move
  onto `util/ida.rs` (or an IDR), as sd, virtio-blk, virtio and
  ns/inum already do. `util/ida.rs` is one contiguous bitmap grown a
  word at a time (Linux ida: an xarray of 1 KiB chunks), so a large
  one (UNNAMED_DEV_IDA, up to 2^20 ids) copies itself under its lock
  every 64 ids and needs one large GFP_ATOMIC block.
- **procfs** (H): a file is generated whole (no seq_file records): an
  open file's reads continuing one another see one generation, where
  Linux generates record by record, so a long file's later chunks are
  as old as its first.
  `fs/proc/mod.rs` `proc_d_delete` keeps the dentries of a dead task
  cached at their last put (Linux pid_delete_dentry, the d_delete of
  pid_dentry_operations: proc_inode_is_dead); they go only when
  `proc_revalidate` or the shrinker finds them.
- **Stale comments** (as touched): "for now"/TODO markers.

## Review gaps, by phase

Tag = roadmap phase (doc/ROADMAP.md).

1. **pcp_free drains the hot end** (J). `mm/page_alloc.rs` `pcp_free`: a
   freed page is pushed at the head and a drain pops from the head;
   Linux returns the cold tail.
2. **arm64 /reserved-memory no-map regions are linear-mapped** (D;
   real HW). `arch/aarch64/dtb.rs` `for_each_firmware_reserved`: Linux memblock_mark_nomap
   removes them (speculative access to secure carve-outs).
3. **memblock does not grow its arrays** (J). `mm/memblock.rs`: 512
   ranges per set; RAM ranges past that are dropped with a warning (as
   Linux before memblock_allow_resize), but a reservation past it still
   panics; Linux doubles the arrays then (memblock_double_array).
4. **LRU batch refs defeat exclusivity checks** (J). `mm/fault.rs`
   `map_swap_page` / `do_wp_page`: refcount==1 tests fail while a page sits in the per-CPU
   add batch, so swap-in makes needless COW copies. Linux drains and
   rechecks (wp_can_reuse_anon_folio).
5. **alloc_slot linear scan under SwapInfo.map; two Vecs + sort per
   reclaimed page** (J). `mm/swap/swapfile.rs` `alloc_slot`: cluster/free-hint
   allocator, cached sorted device list.
6. **One AnonVma per fork family, Vec chain** (J).
   `mm/anon_vma.rs` `AnonVma`: O(N×VMAs) under one family write lock.
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
   reproduced in long looped runs (with SOCKCORE_PORT_PARITY before
   each; x86 and arm64 LOCKDEP e1000, 8 CPUs, CPU spinners, TIME_WAIT
   churn); debug and LOCKDEP builds assert that a new listener owns
   its port in bhash (`TcpSock::listen`). On failure the test
   prints the poll events, TCP state, local and peer ports, the port
   range and the /proc/net/tcp lines of the dead port.

10. **TCP_ETH0_REFUSED flake** (cause unknown): `TCP_ETH0_REFUSED:FAIL
    refused got 0` (hk x86 LOCKDEP=1, once; once earlier on hk
    x86): a connect through slirp to 10.0.2.2 port 1, refused on the
    host, completed (SO_ERROR 0, POLLOUT). Not reproduced on rerun;
    the socket is an active connect (no listener-side code involved).

12. **FORK_PGRP_SIGNAL flake** (hk x86, once in three local `check`
    runs): `FORK_PGRP_SIGNAL:FAIL got 11`: in round 1 a child forked
    before the group's SIGUSR1 showed pending in its parent did not
    get it (`user/boot_tester/signal/fork_delay.rs` `round`). The
    paths match Linux: a fork's multiprocess delay is linked under the
    parent's siglock (`signal::fork_signals_begin`), a group kill
    walks the group under TASKLIST read (`pgrp_send`), and the child
    joins the group and takes the delayed set in one TASKLIST write
    hold (`copy_process`, `install_fork_signal`). A failing round now
    prints the children that missed it and their wait statuses (0:
    SIGUSR2 came first, 2: the wait failed).

14. **FD_ALLOC_SCALE flake on Linux** (`check-linux`, under host load):
    `FD_ALLOC_SCALE:FAIL 5`: the batch of dup()s at ~33000 descriptors
    took 4x or more the batch at ~2000 on the reference Linux; uncached
    reruns pass. The ratio of two wall-clock timings
    (`user/boot_tester/io/fd_scale.rs` `batch_ns`, best of three) is
    taken minutes apart in time and absorbs host contention; interleave
    the low and high batches, or compare more tries.

16. **MEM_SLAB_TIME_WAIT near its bound** (hk x86): 2000 TIME_WAIT
    entries grow Slab by 1800-2092 kB against a 2000 kB bound
    (`user/boot_tester/mm/memcore.rs` `slab_time_wait`), failing about
    one x86 boot in three; arm64 measures about 1570 kB (both measured
    with `Arc<TimeWait>` in kmalloc-512). The test's comment puts an
    entry at about 600 bytes; an `Arc<TimeWait>` is now 312 bytes from
    its own cache (`mm/slab.rs` `TW_CACHE`, no rounding) and its ehash
    `Arc<Eh>` 120 in kmalloc-128 (host build), yet the growth stayed
    near 900 bytes an entry after 3 s of settling, so it is not
    deferred frees. Find what else each entry allocates
    (`net/tcp/timewait.rs` `TimeWait::new`, its timer, bhash owner and
    ehash entries) before touching the bound.

## DRM dumb buffers are the boot framebuffer only

**Location**: `hw/gfx/simplegfx.rs` (`create_dumb`)

DRM_IOCTL_MODE_CREATE_DUMB returns the firmware framebuffer when the
size and depth match it, else ENOMEM; Linux simpledrm allocates any
dumb buffer from shmem and blits it on page flip
(drm_gem_shmem_dumb_create).

## Namespace file gaps

**Location**: `fs/pseudo/nsfs.rs`, `ns/setns.rs`

No time namespaces (CLONE_NEWTIME, the time and time_for_children
links). No nsfs file handles (File handle gaps).

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
ntp_update_frequency).

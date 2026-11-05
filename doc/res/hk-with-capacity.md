# hk: allocation sizing review (with_capacity / reserve / vec![x; n])

Tree: `updates` @ db70fb9 (read-only review). Line numbers are for that tip.

## How allocation behaves in hk (the constraints)

- `mm/heap.rs:255` the global allocator goes to `mm/slab.rs:558 kmalloc`: slab classes up to
  8 KiB (`KMALLOC_MAX`, slab.rs:488), above that whole buddy pages; `alloc_pages` returns None
  for order > `MAX_ORDER` = 10 (`mm/page_alloc.rs:39,535`). **The largest possible heap
  object is 4 MiB** (`util/kmem.rs:13 MAX_KMALLOC`). There is no vmalloc.
- An infallible allocation (`Vec::with_capacity`, `vec![]`, `push`, `extend`, `resize`,
  `reserve`) that gets null calls `handle_alloc_error`, which **panics the kernel**.
- Direct reclaim only runs when the caller may sleep and is not atomic
  (`mm/page_alloc.rs:193 may_direct_reclaim`). Under any spinlock, `IrqSpinlock`, spin
  `Mutex`/`RwLock`, or in softirq, a high-order allocation gets only what is already free.
  It is much more likely to fail, and failing panics. Allocations of order 4 or more
  (64 KiB and up) can fail under fragmentation. Linux treats order > 3 as "costly"
  for this reason.
- Fallible paths: `util/kmem.rs:17 try_vec(n, v)` checks `n * size_of::<T>()` for overflow
  and against `MAX_KMALLOC`, then calls `try_reserve_exact`, returning ENOMEM. It is used by
  xattr list, keyctl read, io_uring fds, and bpf maps. Raw `try_reserve*` is used in
  `mm/swap.rs:168`, `net/skb.rs:98`, `task/fdbits.rs:80` and `bpf/map.rs:288`.

## 1. Guidelines

**Pre-size (`with_capacity(n)` / `reserve(n)`) when:**
- the final size is known or tightly bounded and the container is filled right away. A growing
  `Vec` reallocates log2(n) times, copying each time, and its peak use is about 3n (old plus new
  buffer during the copy, plus slack up to 2n). One exact allocation removes all of that.
- the fill happens under a lock, or in a callback that runs under a lock (`readdir` actors,
  `scan` loops under `IrqSpinlock`). Allocate before taking the lock. Then the one allocation
  can still reclaim, and the critical section does no allocator work.
- the buffer is a builder with a constant budget (netlink dump parts, `DUMP_SIZE`).

**Don't bother when:**
- the container lives long and grows slowly (tables, registries, per-socket lists). Pre-sizing
  wastes memory for the object's whole life.
- it is usually empty or tiny (wait lists, error paths, typical short paths). The first push
  already allocates a small exact block.
- the value is `.collect()` from an exact-size iterator (`Vec` / slice iter, `map`, `zip`,
  ranges). `collect` already allocates exactly once. It does **not** for `filter`,
  `filter_map`, `flat_map` or `split`, whose lower size_hint is 0.
- the buffer is already `vec![0; n]`. That is pre-sized; the open question there is
  validation (part 2), not capacity.

**Correctness rule: only size from a count the kernel trusts.** A count is trusted if it is:
- a constant;
- a kernel-internal count (`len()` of a kernel container, or data already in kernel memory);
- a value already checked against a documented maximum *on every path to the allocation*:
  IOV_MAX/UIO_MAXIOV, PATH_MAX, XATTR_SIZE_MAX, FUTEX_WAITV_MAX, BPF_MAXINSNS,
  IORING_MAX_ENTRIES, NGROUPS_MAX, a sysctl maximum, and so on.

A count taken from a syscall argument, a packet, a device, or a disk structure must first be
validated (an error above the maximum), clamped (`n.min(MAX)`, as Linux does for
getxattr/listxattr/getdents), or allocated fallibly (`kmem::try_vec` /
`try_reserve_exact`, returning ENOMEM as Linux's kvmalloc callers do). Also:
- the bound must keep `n * size_of::<T>()` under `MAX_KMALLOC` (4 MiB). For an infallible
  allocation of user-driven size, the practical ceiling is about 64 KiB. Above that, use
  `try_vec`.
- compute byte sizes with `checked_mul`. `try_vec` does this already; hand-written
  `n * 4` / `n * size_of` is fine only when `n` is already bounded by a small constant.
- a pre-size must never stand in for validation. `with_capacity(user_n)` followed by
  "push until the source runs out" is as dangerous as `vec![0; user_n]`.

## 2. Validation review of existing sizing calls

139 hits for `with_capacity|vec![x; n]|reserve|resize|try_vec|try_reserve` in the kernel
crate. Constants, memblock `reserve` (address ranges, not allocations) and `#[cfg(test)]`
code are left out.

### 2a. Not bounded before the allocation (missing validation), ranked

**1. `ipc/mqueue.rs:741` (mq_timedsend) and `:803` (mq_timedreceive): unprivileged kernel
panic.**
- Source of n: `msg_len` from the user. It is checked only against the queue's `msgsize`
  (`:736`, `:793`).
- But `msgsize` comes from `mq_open`'s `mq_attr`, and `:605` lets *any* caller pick up to
  `HARD_MSGSIZEMAX` = 16 MiB. `maxmsg` likewise goes up to `HARD_MSGMAX` = 65536 (`:602`).
  There is no `CAP_SYS_RESOURCE` test, no `msgsize_max`/`msg_max`, and no RLIMIT_MSGQUEUE.
- So: `mq_open(attr.msgsize = 16M)` then `mq_send(16M)` runs `vec![0u8; 16M]`, which is
  over the 4 MiB maximum and panics. Receive does the same with `min(msg_len, msgsize)`.
- Linux (`ipc/mqueue.c:353-362`):
  - without CAP_SYS_RESOURCE, `maxmsg <= mq_msg_max` (10) and `msgsize <= mq_msgsize_max`
    (8192), else EINVAL;
  - only with the capability are the HARD_* limits used;
  - plus the `ULONG_MAX` overflow check and RLIMIT_MSGQUEUE accounting (EMFILE);
  - `load_msg` copies in page-sized pieces, so no large contiguous allocation.
- Fix:
  - add Linux's `mq_attr_ok` capability split, with per-ipc-ns `mq_msg_max` /
    `mq_msgsize_max` defaults of 10 / 8192;
  - make both buffers `kmem::try_vec(..)` (ENOMEM), because a capable caller can still ask
    for 16 MiB;
  - add RLIMIT_MSGQUEUE as a follow-up.

**2. `net/msg.rs:91` (`Iov::gather_at`, reached through `Src::take`): AF_UNIX dgram/seqpacket
and netlink sendmsg; unprivileged panic.**
- Source of n: `m.data.len()` (≤ MAX_RW_COUNT). It is bounded only by `sndbuf - 32`
  (`net/unix/dgram.rs:142`, `net/netlink/ops.rs:195`).
- `sndbuf` from SO_SNDBUF goes up to `BUF_MAX * 2` = 8 MiB unprivileged (`net/sock.rs:445`),
  and up to about 2 GiB with SO_SNDBUFFORCE.
- So: `setsockopt(SO_SNDBUF, 4M)` then a 5 MiB `send` runs `vec![0u8; 5M]`, which panics.
- Linux: unix_dgram_sendmsg builds a paged skb (sock_alloc_send_pskb), and netlink uses
  `netlink_alloc_large_skb` (vmalloc). Both fail with ENOBUFS/ENOMEM, never with an oops.
- The other `take` callers are bounded: UDP `UDP_MAX` (`net/udp.rs:447`), raw/ping 0xffff
  (`net/raw.rs:336`, `net/ping.rs:318`), packet `mtu + 18`, TCP and unix stream by
  `CHUNK` / `chunk_max` (≤ 64 KiB).
- Fix: in `gather_at`, replace `vec![0u8; want]` with `kmem::try_vec(want, 0)?`, mapping
  failure to ENOBUFS (Linux's errno from sock_alloc_send_pskb for an oversized skb). One fix
  covers every sender.
- Follow-on: `net/netlink/rtnetlink.rs:170` (`ack`) copies the whole request
  (`Vec::with_capacity(4 + orig.len())`, up to sndbuf). After the fix above it becomes
  reachable with a few MiB. Use `try_reserve`, and on failure set ENOBUFS on the socket as
  Linux `netlink_ack` does when `nlmsg_new` fails.

**3. `fs/vfat.rs:862` (`extend_cluster_chain`: `Vec::with_capacity(count)`): panic on a
writable FAT mount.**
- Source of n: `count = need - chain.len()`, where `need = size.div_ceil(cluster_size)`
  (`:166`). `size` is a truncate/write end, checked only for `<= u32::MAX`
  (`:224`, `:1928`, `:1978`).
- With 512-byte clusters, `ftruncate(fd, 4G-1)` gives `count` ≈ 8M, so `with_capacity`
  needs 32 MiB and panics. With 4 KiB clusters it needs exactly 4 MiB (order 10), and fails
  under fragmentation.
- Linux (`fat_add_cluster` / `fat_alloc_clusters`) works in small batches and never builds
  an array of the whole extension.
- Fix: `ensure_clusters` only uses `new.first()`, so have `extend_cluster_chain` return the
  first cluster and not collect anything. If a list is ever needed, pre-size
  `count.min(free_clusters)` or use `try_reserve`.
- The disk header has the same validation gap: `sectors_per_cluster` is never checked
  (`:2388`). A value of 0 divides by zero at `:806` and at `:166` (`div_ceil(0)`). Linux
  `fat_fill_super` rejects a value that is not a power of two (`fs/fat/inode.c:1483`).

**4. TCP receive/send queues grow without bound checks: `net/tcp/input.rs:547,551`
(`rcvq.extend`) and `net/tcp/cb.rs:945` (`sndq.extend`).**
- No explicit pre-size here, but `VecDeque` doubles its capacity under the socket's spin
  `Mutex` (`net/tcp/mod.rs:143`), and on the receive side in softirq. No reclaim is possible
  there.
- Source of n: queue length up to `rcv_cap` / `snd_cap` = rcvbuf/2 or sndbuf/2
  (`net/tcp/mod.rs:256-257`), which is 4 MiB unprivileged and more with *BUFFORCE.
- Doubling from a segment-sized start (e.g. 1448 × 2^k) passes 4 MiB before the queue is
  full: a queue of about 3 MiB asks for 5.9 MiB, which is null, which panics.
- Repro path (from analysis; I have not run it): `SO_RCVBUF = 4M` on a loopback TCP socket
  that never reads, with a peer that sends 4 MiB.
- Linux keeps these as skb lists, with no contiguous buffer.
- Fix:
  - short term: in `send`, cap `n` so `sndq.len() + n` fits what `try_reserve` grants (on
    failure, queue 0 bytes and wait for memory, which `wmem_schedule` already does). In
    `rcv`, `try_reserve` and drop the segment on failure (Linux `tcp_try_rmem_schedule`
    drop).
  - long term: a chunked queue (a list of segment buffers).
  - add a repro boot test with the fix.

### 2b. Bounded, but large infallible allocations (Linux would return ENOMEM)

Each of these is validated, but the bound allows order 4 or more. Infallible allocation then
means "panic under fragmentation", where Linux's kvmalloc caller returns ENOMEM. Switch each
to `kmem::try_vec`.

| site | n source / check | max bytes |
|---|---|---|
| `io/io_uring.rs:382-384` ring arrays | entries clamped at `io/io_uring.rs:1447-1458` | sqes 2 MiB, cqes 1 MiB |
| `io/io_uring.rs:908` `register_files` `with_capacity(fds.len())` | ≤ 32768 (`:1359`) | 256 KiB, allocated **under `IrqSpinlock` inner and the fd-table lock**: allocate before locking |
| `keys/syscall.rs:68` add_key payload | `plen <= MAX_PAYLOAD_SIZE` (`:44`) | 1 MiB |
| `task/id.rs:625` setgroups | `<= NGROUPS_MAX` (`:621`) | 256 KiB |
| `fs/proc/array.rs:458` cmdline/environ | `min(ARGS_MAX)` (same line) | 128 KiB |
| `fs/misc.rs:522,766,829` xattr value | `<= XATTR_SIZE_MAX` (`:508,756,819`) | 64 KiB |
| `io/epoll.rs:560` events | `maxevents <= 4096` (`:534`) | 48 KiB, zeroed on every call |

The xattr and epoll rows also hide ABI deviations; see the notes after 2c.

### 2c. Bounded, no action needed

- `fs/poll.rs:181` nfds ≤ 1024 (`:164`). Deviation: Linux allows up to RLIMIT_NOFILE, using
  page-sized chunks.
- `fs/iov.rs:63` ≤ IOV_MAX (`:49`).
- `net/msg.rs:59` ≤ UIO_MAXIOV (`:46,55`).
- `net/msg.rs:221` ≤ OPTMEM_MAX (`:218`).
- `net/msg.rs:250` ≤ SOCKADDR_MAX (`:247`).
- `net/msg.rs:420` ≤ cmsg buffer `cap`.
- `net/socket.rs:88` `len.min(max)`; every caller passes a constant max (IFNAMSIZ, NAME_MAX,
  MREQ_MAX, FPROG_LEN, `n*8` with n ≤ BPF_MAXINSNS at `net/packet/opts.rs:250`).
- `fs/misc.rs:905,951` listxattr: `try_vec(size.min(XATTR_LIST_MAX))`, matching Linux.
- `keys/keyctl.rs:85` ≤ PAGE_SIZE (`:81`).
- `keys/keyctl.rs:465` `try_vec(min(buflen, need))`.
- `mm/mempolicy.rs:196` maxnode ≤ MAX_MASK_BITS+1 (`:181`).
- `ipc/sem.rs:616` nsops ≤ semopm (`:610`). `ipc/sem.rs:935` nsems ≤ semmsl (`:537`).
- `ipc/msg.rs:327` ≤ msg_ctlmax (`:315`). The sem/msg sysctls are not writable, so these
  are constants.
- `task/futex.rs:1202` ≤ FUTEX_WAITV_MAX (`:1173`).
- `task/process_vm.rs:363` ≤ IOV_MAX (`:51,191`). `:117,257` ≤ PVM_CHUNK.
- `task/schedsys.rs:542` `min(cpumask_size())`. `:593` constant.
- `seccomp/filter.rs:172` ≤ BPF_MAXINSNS (`:160`).
- `bpf/syscall.rs:307-410` key/value sizes ≤ 256 / 64 KiB (`bpf/map.rs:131,134`).
- `bpf/syscall.rs:453` insn_cnt ≤ BPF_MAXINSNS (`:446`). That check also bounds
  `bpf/verifier.rs:208-209` and `bpf/convert.rs:54,58`.
- `bpf/map.rs:288-291` fallible, with a budget.
- `net/core/filter.rs:255` `insns.len()` ≤ BPF_MAXINSNS (`:146`).
- `net/inet/frag.rs:179` ≤ IP_MAX (same function).
- `net/tcp/output.rs:219,277` ≤ mss. `net/tcp/mod.rs:657` ≤ CHUNK (`:651`).
- `net/skb.rs:98` ≤ MAX_SKB_SIZE, fallible.
- `net/netlink/attr.rs:142` `max` is a per-family constant.
- `mm/swap.rs:168-170` `try_reserve_exact` (swap header `max`).
- `task/fdbits.rs:80` fallible; `task/mod.rs:687` goes through it, bounded by nr_open.
- `fs/io.rs:104`, `fs/file.rs:708` `min(WRITE_CHUNK)`.
- `fs/dir.rs:80` ≤ the `limit` clamp (`:111,124`).
- `block/part/efi.rs:83` ≤ MAX_ENTRIES (`:67`).
- `fs/vfat.rs:823,1299,1786` `cluster_size` ≤ 255 × 4096 ≈ 1 MiB (disk-supplied; large but
  bounded; see the vfat finding).
- `util/elf.rs` / `task/exec.rs:701` read lengths: phdr table ≤ a page (`util/elf.rs:322`),
  interp ≤ PATH_MAX (`:350`), dynamic ≤ MAX_DYNAMIC (`:377`), relocs in chunks (`:472`),
  script head ≤ BINPRM_BUF_SIZE (`task/exec.rs:646`).
- `hw/virtio/ring.rs:143-157` n ≤ u16 (128 KiB).
- `hw/usb/xhci.rs:1475` len ≤ u16.
- Kernel-internal counts: `mm/vmscan.rs:149,157` (SWAP_CLUSTER_MAX), `util/ida.rs:36`,
  `net/core/dev.rs:203`, `net/inet/port.rs:154`, `task/exec.rs:240-259`,
  `task/binfmt_script.rs:91`, `task/pid.rs:261`, `dt/mod.rs:311`, `hw/dma.rs:456`,
  `hw/virtio/blk.rs:324`, `hw/usb/transfer.rs:349`, `hw/net/e1000.rs:688`,
  `block/blkdev.rs:732,887`, `block/part/mod.rs:34`, `fs/vfat.rs:1215,1218` (name ≤ 255),
  `fs/proc/mod.rs:1155`.

**Linux-semantics deviations found along the way** (not sizing bugs, but cheap to match):
- `fs/misc.rs:756,819` getxattr/fgetxattr return ERANGE for `size > XATTR_SIZE_MAX`. Linux
  clamps the size to XATTR_SIZE_MAX (`fs/xattr.c:798`) and returns E2BIG only if the value
  really is that large.
- `io/epoll.rs:75` `EP_MAX_EVENTS = 4096`. Linux allows `INT_MAX / sizeof(epoll_event)`
  (`fs/eventpoll.c:222`), so `epoll_wait(maxevents = 8192)` is EINVAL on hk only. Fix with
  a buffer of `min(maxevents, nitems)` from `try_vec`, or copy out per scan chunk.
- `fs/poll.rs:163` `MAX_NFDS = 1024` versus Linux's RLIMIT_NOFILE.

## 3. Conversion opportunities (hot paths first)

**1. `io/epoll.rs:238` `Eventpoll::scan`: `let mut ready = Vec::new(); push` per item.**
- n = `items.len()` (kernel-internal, **trusted**).
- Better: `let ready: Vec<_> = items.into_iter().map(|(fd, f)| ..poll..).collect();` gives
  one exact allocation.
- Also `:229-236`: `filter(..).collect()` under the `IrqSpinlock` (`:124`) starts empty and
  doubles while IRQs are off. Use `Vec::with_capacity(inner.items.len())` (trusted) and
  extend: one allocation instead of log2(n) under the lock.
- Benefit: high. Runs on every epoll_wait pass and wakeup; removes reallocations inside an
  IRQ-off region.

**2. `fs/dir.rs:125` getdents: `let mut buf = Vec::new();`, grown by `put_dirent`'s
`resize` (`:80`) inside the fs `readdir` actor.**
- The comment at `:106` says readdir runs under the fs directory spinlocks.
- n = `limit` = `min(count, MAX_RW_COUNT, GETDENTS_CHUNK = 32 KiB)`:
  **trusted after the clamp at `fs/dir.rs:111,124`**.
- Convert to `Vec::with_capacity(limit)`, taken before `lock_shared` / `readdir`.
- Benefit: high. Up to 13 reallocations become one, and all allocator work leaves the
  spinlocked region.
- Cost: 32 KiB per call even for small directories. glibc passes 32 KiB anyway. Taking
  `limit.min(4096)` and letting it grow is a middle ground, but still allocates under the
  lock.

**3. `net/netlink/mod.rs:556` `dump_step`: `let mut buf = Vec::new();` filled by
`cb.fill`, then NLMSG_DONE appended.**
- n = `rtnetlink::DUMP_SIZE + NLMSG_HDRLEN + 4` (constant, **trusted**). `fill` stops at
  DUMP_SIZE (`net/netlink/rtnetlink.rs:285,292`).
- Benefit: high for `ip addr` / `ip route` / `ss`: about 6 reallocations per part become one.
- Related, in `net/netlink/attr.rs`:
  - `:105` `Msg::str` builds a temporary `Vec` only to append a NUL. Write the header,
    `s`, `0` and padding straight into `self.buf` instead (no allocation at all).
  - `:62` `Msg::new` `with_capacity(256)` is fine.

**4. `io/poll.rs:198-200` `PollContext::new`: `files` / `entries` / `owners` all
`Vec::new()`, pushed once per fd on the registering pass.**
- Add `PollContext::with_capacity(n)` with:
  - `do_poll_internal`: n = nfds, **trusted after `fs/poll.rs:164`**;
  - select: n = the bounded nfds;
  - epoll scan: n = `items.len()` (trusted).
- Benefit: medium-high for poll/select/epoll with many fds: log2(n) reallocations of each
  Vec become one.
- Separate issue: `add_entry` (`:212`) dedups with a linear scan, which is O(n²) in nfds.

**5. `fs/proc/mod.rs:1296` global /proc generators run while holding the inode's spin
`RwLock` read lock (`:336`, `crate::sync::spin::RwLock`).**
- Every `String` / `Vec` growth in meminfo, slabinfo, net/*, mounts, etc. happens without
  reclaim, and each `read()` regenerates the whole file.
- The bigger fix is not a capacity change: copy the `generator` fn pointer and drop `data`
  before calling it, as the `PidFile` branch already does at `:1289-1293`.
- After that, pre-size the large generators from trusted counts:
  - `fs/proc/mounts.rs:66,86`: `vis.len() * 64`;
  - `mm/slab.rs` `slabinfo`: `SIZES.len()` × the line width;
  - `fs/proc/mod.rs:1116`: per-entry count.
- Benefit: medium; real for big files, and it removes high-order allocations under a
  spinlock.

**6. `fs/dentry.rs:229,248` d_path, and `:265,276` dentry_path: `names` and `out` both start
empty.**
- `out`: `Vec::with_capacity(names.iter().map(|n| n.len() + 1).sum())`, a kernel-internal
  count, **trusted** (names are already in memory; each ≤ NAME_MAX).
- `names`: leave as is; depth is unknown and usually small.
- `d_path_link` (`:284`): `reserve(10)` before appending " (deleted)".
- Benefit: medium. Hot for getcwd, `/proc/*/fd` readlink, mountinfo, and audit-style
  readers.

**7. `fs/namei.rs:208` path walk: `split(..).filter(..).collect()` is not exact-size, so it
starts at capacity 4 and grows for deeper paths.**
- Best: don't collect at all. Iterate with `peekable()` and test `peek().is_none()` for
  the last component.
- Otherwise: `with_capacity(path.iter().filter(|&&c| c == b'/').count() + 1)`. The path is
  ≤ PATH_MAX (`fs/namei.rs:380`), so **trusted**.
- Benefit: medium. Every open/stat does a walk; the gain is one allocation, sometimes two.

**8. `net/tcp/cb.rs:945` / `net/tcp/input.rs:547`: see 2a#4.**
- These are **must-not-pre-size** (do not reserve `snd_cap` / `rcv_cap`, up to 4 MiB per
  socket). The right change is a fallible reserve, then a chunked queue.
- Benefit: robustness. These are the largest contiguous allocations on the network hot path.

**9. `uaccess.rs:440` `strndup_user_bytes`: `Vec::new()` plus extend in 256-byte chunks.**
- A short path gets one exact allocation already. A path over 256 bytes grows 256 → 512 →
  1024 and so on.
- `with_capacity(256.min(max_len))` would cost more for short paths. Leave as is unless
  profiling shows long paths matter.
- Classification: trusted (≤ PATH_MAX). Benefit: low.

**10. `io/epoll.rs:560` events buffer: already pre-sized, but to `maxevents` (up to 48 KiB,
zeroed) on every call.**
- Size it as `min(maxevents, items.len())` (trusted after `:534`) with `try_vec`. Together
  with lifting EP_MAX_EVENTS to Linux's limit, this fixes the deviation in 2c.
- Benefit: medium on busy epoll loops (a 48 KiB memset per wait today).

**Considered and rejected:**
- `net/tcp/cb.rs` `sndq` / `rcvq`, pre-sized to capacity: wastes up to 4 MiB per socket;
  see #8.
- `fs/io.rs:104`, `fs/file.rs:708` read/write bounce buffers: already exact
  (`min(total, 64 KiB)`). The cost is the zero-fill, which `with_capacity` can't remove
  without an uninitialized-read API.
- `net/msg.rs:91` `gather_at`: already exact; it needs `try_vec`, not a capacity change
  (2a#2).
- `net/udp.rs:673`, `net/tcp/cb.rs:491,541,575`, `net/inet/frag.rs:126`: `to_vec()` is
  already one exact allocation.
- `io/epoll.rs:229` items collect: keep it as a collect, but pre-size it (#1); it can't
  become exact-size while it filters.
- `fs/proc/mounts.rs:32` `all` / `todo`: mount tree depth/width is unknown; low value.
- `net/inet/fib.rs:331,619`, `net/inet/ifaddr.rs:243`, `net/tcp/timer.rs:388`: small,
  rarely filled.
- `fs/vfat.rs:862` with_capacity: should be **removed**, not kept (2a#3).
- `task/exec.rs:240-259`: already pre-sized from trusted counts.
- `net/netlink/attr.rs:62` `Msg::new(256)`: fine as is.

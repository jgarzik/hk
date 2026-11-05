# hk: allocation sizing (with_capacity / reserve / vec![x; n])

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

## 2. Large infallible allocations

Allocations unbounded by input are in BUGS.md ("Allocation sizing and pure-code gaps").

Each of these is validated, but the bound allows order 4 or more. Infallible allocation then
means "panic under fragmentation", where Linux's kvmalloc caller returns ENOMEM. Switch each
to `kmem::try_vec`.

| site | n source / check | max bytes |
|---|---|---|
| `io/io_uring.rs:908` `register_files` `with_capacity(fds.len())` | ≤ 32768 (`:1359`) | 256 KiB, allocated **under `IrqSpinlock` inner and the fd-table lock**: allocate before locking |
| `fs/proc/array.rs:458` cmdline/environ | `min(ARGS_MAX)` (same line) | 128 KiB |
| `fs/misc.rs:522,766,829` xattr value | `<= XATTR_SIZE_MAX` (`:508,756,819`) | 64 KiB |
| `io/epoll.rs:560` events | `maxevents <= 4096` (`:534`) | 48 KiB, zeroed on every call |

The xattr and epoll rows also hide ABI deviations (BUGS.md).

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

**8. `io/epoll.rs:560` events buffer: already pre-sized, but to `maxevents` (up to 48 KiB,
zeroed) on every call.**
- Size it as `min(maxevents, items.len())` (trusted after `:534`) with `try_vec`. Together
  with lifting EP_MAX_EVENTS to Linux's limit, this fixes that deviation (BUGS.md).
- Benefit: medium on busy epoll loops (a 48 KiB memset per wait today).

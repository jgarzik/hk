# hk: allocation sizing (with_capacity / reserve / vec![x; n])

## How allocation behaves in hk (the constraints)

- `mm/heap.rs` is kvmalloc: the global allocator tries `mm/slab.rs` kmalloc (slab classes
  up to 8 KiB, then buddy pages up to `MAX_ORDER` = 10, 4 MiB), and falls back to
  `mm/vmalloc.rs` for a larger block or a multi-page one the slab could not find
  contiguous pages for. The fallback needs a context that may sleep: under a spinlock,
  with interrupts off or in an interrupt, only the slab is tried. vmalloc memory is not
  physically contiguous (never DMA from it).
- An infallible allocation (`Vec::with_capacity`, `vec![]`, `push`, `extend`, `resize`,
  `reserve`) that gets null calls `handle_alloc_error`, which **panics the kernel**.
- Direct reclaim only runs when the caller may sleep and is not atomic
  (`mm/page_alloc.rs may_direct_reclaim`). Under any spinlock, `IrqSpinlock`, spin
  `Mutex`/`RwLock`, or in softirq, a high-order allocation gets only what is already free
  and has no vmalloc fallback: order 4 or more (64 KiB and up) can fail under
  fragmentation, and failing panics. Linux treats order > 3 as "costly" for this reason.
- Fallible paths (`util/kmem.rs`, capped at `MAX_KMALLOC` = INT_MAX as Linux kvmalloc):
  `try_vec(n, v)` for a known size, `KVec`/`KDeque` for buffers that grow (all growth
  `try_*`, ENOMEM; doubling, exact, never past the cap).

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

Validated sites whose bound allows order 4 use `kmem::try_vec`
(ENOMEM, as Linux's kvmalloc callers).

## 3. Conversion opportunities (hot paths first)

**1. `fs/dir.rs:125` getdents: `let mut buf = Vec::new();`, grown by `put_dirent`'s
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

**2. `net/netlink/mod.rs:556` `dump_step`: `let mut buf = Vec::new();` filled by
`cb.fill`, then NLMSG_DONE appended.**
- n = `rtnetlink::DUMP_SIZE + NLMSG_HDRLEN + 4` (constant, **trusted**). `fill` stops at
  DUMP_SIZE (`net/netlink/rtnetlink.rs:285,292`).
- Benefit: high for `ip addr` / `ip route` / `ss`: about 6 reallocations per part become one.
- Related, in `net/netlink/attr.rs`:
  - `:105` `Msg::str` builds a temporary `Vec` only to append a NUL. Write the header,
    `s`, `0` and padding straight into `self.buf` instead (no allocation at all).
  - `:62` `Msg::new` `with_capacity(256)` is fine.

**3. `io/poll.rs` `PollContext::new`: `files` / `entries` / `owners` all
`Vec::new()`, pushed once per fd on the registering pass.**
- Add `PollContext::with_capacity(n)` with:
  - `do_poll_internal`: n = nfds, **trusted after the RLIMIT_NOFILE check in `fs/poll.rs`**;
  - select: n = the bounded nfds.
- Benefit: medium-high for poll/select with many fds: log2(n) reallocations of each Vec
  become one.
- Separate issue: `add_entry` (`:212`) dedups with a linear scan, which is O(n²) in nfds.

**4. /proc generators grow their output one write at a time.**
- They run with no lock held (`fs/proc/mod.rs` `proc_content` copies the generator out
  of the inode data first; the process list is gathered under TASKLIST with no
  allocation, `collect_tasks`), but every `String` / `Vec` in meminfo, slabinfo, net/*,
  mounts, etc. starts empty and each `read()` regenerates the whole file.
- Pre-size the large generators from trusted counts:
  - `fs/proc/mounts.rs` `show_mounts`/`show_mountinfo`: the visible mounts × 64;
  - `mm/slab.rs` `slabinfo`: `SIZES.len()` × the line width.
- Benefit: medium; real for big files.

**5. `fs/namei.rs:208` path walk: `split(..).filter(..).collect()` is not exact-size, so it
starts at capacity 4 and grows for deeper paths.**
- Best: don't collect at all. Iterate with `peekable()` and test `peek().is_none()` for
  the last component.
- Otherwise: `with_capacity(path.iter().filter(|&&c| c == b'/').count() + 1)`. The path is
  ≤ PATH_MAX (`fs/namei.rs:380`), so **trusted**.
- Benefit: medium. Every open/stat does a walk; the gain is one allocation, sometimes two.

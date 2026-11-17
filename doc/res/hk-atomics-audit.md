# Atomics audit: where `Atomic*` replaced a design

Research only. Findings are ranked most damaging first; each names file + symbol,
category, the defect, Linux's design and the proper hk design. Categories:
(a) redundant (always under a lock), (b) torn multi-atomic invariant, (c) hot
shared RMW / cache-line traffic, (d) atomic emulating a lock, (e) ordering not
argued / published copy of locked state.

## Patterns

- **Locked RMW where Linux does a plain per-CPU or single-writer update.**
  `fetch_add`/`swap` on state that only one CPU or one task writes
  (seqcount, per-task counters, rq fields under the rq lock). On x86 each
  is a `lock`-prefixed instruction (a full barrier), on arm64 an LSE atomic or
  an LL/SC loop; Linux uses `this_cpu_inc` / plain `++` / `WRITE_ONCE`.
- **Sibling atomics of a lock.** Fields mutated only under a lock but kept as
  atomics beside it (rule 1 of LOCKING.md §5.4 violated): `SchedEntity`,
  `PerCpuScheduler`, `TimerList`, `Pcp.count`, `AddressSpace.nrpages`.
- **Published copies.** Locked state mirrored into a second set of atomics
  on every unlock for lockless readers (`Pipe` head/tail, `TcpSock.snap`),
  where Linux READ_ONCEs the real field. Costs a store
  burst per operation and makes readers combine values from different steps.
- **Global RMW on per-op paths** (`call_rcu`, inode eviction, netdev stats,
  dentry alloc, dirty throttling).
- **Atomic flags as locks** (`Softnet.busy`, `Zone.draining`, NAPI
  `sched`+`disable`).

## Findings

### 3. Dentry reads store to shared lock words — (c)
- Where: `fs/dentry.rs` `Dentry.d_lock`, `Dentry.d_name` (RwLocks): every
  path component's read lock writes the lock word, so popular
  directories become contended lines.
- Linux: path walk is RCU-walk with the `d_seq` seqcount, no stores to
  shared dentries.
- Fix: RCU-walk for dcache (its own phase).

### 4. `SchedEntity` fields owned by the rq lock kept as atomics — (a)
- Where: `task/sched.rs` `SchedEntity` `vruntime`, `deadline`, `vlag`,
  `exec_start`, `rr_left`, `requeue_tail`, `contrib_load`. Their updates
  are loads and stores under the rq lock now (no RMW), the parameters one
  word (`Params`), the run-queue counts plain under their lock.
- Wrong: still atomics only for interior mutability: the type does not
  say which lock owns them.
- Linux: plain fields of sched_entity / sched_rt_entity under the rq lock.
- Fix: an rq-lock-owned cell (accessed with the rq guard as proof, like
  `ctx`) for the fields with no lockless reader. LOCKING.md §3.1 lists
  each field's lock.

### 5. Page allocator boot-only fields as atomics — (a)
- Where: `mm/page_alloc.rs` `Zone.map`, `start`, `end`, `managed`,
  `sections`, `batch`, `high` (set at boot, atomics rather than set-once,
  rule 5). The counts and the drain lock are done.
- Fix: set-once (`Once` or the constructor) where boot order allows.



## Checked and judged legitimate (f)

- `task/ucount.rs` `Ucounts.rlimit[]`: Linux `atomic_long_t` with
  add-then-check; `inc_max` is Linux's cmpxchg loop.
- Sysctl knobs as Relaxed atomics (`net/sysctl.rs` `NetSysctl`, `io/pipe.rs`
  `PIPE_MAX_SIZE`/`PIPE_USER_PAGES_*`, `mm/writeback.rs` ratios): Linux
  READ_ONCE of sysctls; `ping_group` packs its pair in one word.
- `net/tcp/mem.rs` `ALLOCATED`/`PRESSURE`/`LIMITS` (Linux design). `SOCKETS` could be a
  `PercpuCounter` (Linux `tcp_sockets_allocated`), low.
- `time/mod.rs` `TimeKeeper` seqlock; `mm/tlb.rs` `MmContext.tlb_gen`;
  `arch/aarch64/asid.rs` (Linux's generation + per-CPU active ASID scheme).
- `fs/mount.rs` `Mount` link pointers (RCU + `MOUNT_LOCK` seqcount, Linux
  READ_ONCE) and per-CPU `mnt_pcp`/`mnt_writers`.
- `fs/dentry.rs` `d_count`, `fs/file.rs` `f_count`, `Page.refcount`,
  `Page.flags` (Linux lockref/atomic refcounts, atomic bitops).
- `task/futex.rs` `waiter_count`, `lock_ptr`; `sync/waitqueue.rs` entry
  flags; `smp.rs` `Csd.locked` (CSD_FLAG_LOCK).
- `task/sched.rs` `state`, `on_rq`, `on_cpu`; `Task.cpu`, `thread_flags`
  (Linux READ_ONCE / smp_load_acquire / atomic TIF bits).
- `signal/mod.rs` `SignalStruct.live`, `group_exit` (`start_exit` under
  `jobctl`, fork re-checks under TASKLIST); `dead_times`/`child_times`
  changed under TASKLIST write (atomics redundant but harmless).
- `cgroup/pids.rs` counters (Linux atomic64 hierarchy); `tty/n_tty.rs`
  head/tail (Linux smp_load_acquire/smp_store_release);
  `io/epoll.rs` `EpItem.events` (read by the wake callback).
- Id generators touched once per object lifetime (`MNT_ID_UNIQUE`, `NS_ID`,
  `LAST_CTX_ID`, `NEXT_FILES_ID`, `KEY_SEQ`, `DISKSEQ`): fine.

## Systemic recommendations

LOCKING.md §5.4 rules 10-12 (single writers, per-CPU areas, no published
copies) and the primitives behind them (`percpu!` areas, queued spin and
rwlocks, `cpu::LocalWord`) are in place, and `sync::LockedCell` (a cell
owned by one of many instances of a lock, first used by the timer
bases). Still to do: its rq/zone users. Each atomic field's doc
comment names its lockless reader and Linux equivalent (rule 7); a field
"under lock X" with no lockless reader is a bug to fix. Remaining phases
by blast radius: 4-6 and 15/21 (scheduler, allocator, syscall path),
then 7-14 and 19-20 (RCU, VFS, net, mm hot paths), then 10-12, 16-18
and 22 (published copies, flag locks).

# Atomics audit: where `Atomic*` replaced a design

Delete this file in the commit that closes its last finding.

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
- Where: `fs/dentry.rs` `d_lookup` (`__d_lookup` takes each candidate's
  `Dentry.d_lock` for reading, as Linux's non-RCU lookup does) and the
  path walk built on it (`fs/namei.rs` `cached`, `lookup_cached`): every
  path component's read lock and reference count write shared words,
  so popular directories become contended lines.
- Linux: path walk is RCU-walk with the `d_seq` seqcount, no stores to
  shared dentries.
- Done (stage 1): inode memory freed a grace period after its teardown
  (`fs/inode.rs` `IFree`, Linux destroy_inode / i_callback);
  `Dentry.d_seq`; `d_inode`, `d_flags`, `d_name` readable with no lock
  (`d_inode_rcu`, `Inode::igrab`, `DNameSlot`); `get_inode`,
  `is_negative`, `d_unhashed`, `is_mountpoint`, `name` take no lock;
  `__d_lookup_rcu`, `d_seq_begin`/`d_seq_retry`, `DentryRef::try_get`.
- Left (stage 2): the LOOKUP_RCU walk itself (Linux path_init /
  lookup_fast / step_into in RCU mode, try_to_unlazy, legitimize_links,
  permission checks with MAY_NOT_BLOCK).


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
owned by one of many instances of a lock: the timer bases, and the
run queues' `SchedEntity.rq`). Each atomic field's doc
comment names its lockless reader and Linux equivalent (rule 7); a field
"under lock X" with no lockless reader is a bug to fix. Remaining: 3
(dcache RCU-walk stage 2, its own phase).

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
  on every unlock for lockless readers (`Pipe` head/tail, `TcpSock.snap`,
  `Task.ppid/pgid/sid`), where Linux READ_ONCEs the real field. Costs a store
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

### 6. CPU-time accounting at every syscall boundary uses RMW seqcount — (c)(a)
- Where: `task/mod.rs` `Task::acct_begin`/`acct_end` (`acct_seq.fetch_add`),
  called by `account`, `switch_in`, `switch_out`; `task/percpu.rs`
  `account_syscall_enter`/`_exit`; `time/cpu_timer.rs`
  `GroupCputimer::charge` (shared `sums[].fetch_add` per syscall for every
  thread of a group with a process CPU timer).
- Wrong: the sequence has one writer (the task's CPU, IRQs off) yet each
  boundary does two locked RMWs plus clock read and IRQ save/restore on every
  syscall entry and exit; with a process timer armed all threads hammer one
  shared line per syscall.
- Linux: default tick-based accounting does nothing on syscall entry;
  VIRT_CPU_ACCOUNTING_GEN uses `write_seqcount_begin` (plain increment +
  `smp_wmb`) and only on nohz_full CPUs; group sums are charged from
  `update_curr` (tick/switch), not per syscall.
- Fix: `acct_seq` Relaxed load+store with the existing fences; charge the
  group cputimer at switch/tick only; decide whether per-syscall precision is
  needed at all (Linux does not provide it by default). LOCKING.md §3.1/§3.5.

### 8. Inode eviction bumps a global counter and global wait queue — (c)
- Where: `fs/icache.rs` `FREED`, `FREED_WQ`, `evict` (`fetch_add(AcqRel)` +
  `wake_all` on every hashed inode's eviction), `find`/`wait_freed`.
- Wrong: every eviction on every CPU takes the single `FREED_WQ` IrqSpinlock
  and RMWs one line, even with no waiter; waiters wake on any eviction.
- Linux: `inode_wake_up_bit` on a hashed bit wait queue (`bit_waitqueue`,
  many buckets) after `smp_mb`, skipped when `waitqueue_active` is false;
  waiters key on the inode.
- Fix: hashed wait-queue table keyed by inode address, waiter keyed wake,
  `waitqueue_active` fast path; drop the global counter (re-check the hash
  instead). LOCKING.md VFS section.

### 9. `NetDeviceStats`: shared atomics per packet — (c)
- Where: `net/device.rs` `NetDeviceStats` (`inc_rx_packets`, `rx_bytes`,
  `tx_*`), used by `lo` and every driver.
- Wrong: several locked RMWs on one shared line per packet from every CPU;
  violates LOCKING.md §5.4 rule 9.
- Linux: per-CPU `pcpu_lstats`/`pcpu_sw_netstats` (u64_stats_sync) for
  virtual devices, per-queue stats for drivers; `ndo_get_stats64` sums.
- Fix: per-CPU (cache-aligned) stats like `net/mib.rs`, summed on read.

### 10. `TcpSock.snap`: a full published copy of the control block — (e)(c)
- Where: `net/tcp/mod.rs` `Snap`, `Snap::store` (end of every locked step),
  `Snap::proc_view`.
- Wrong: every segment processed recomputes `info::ProcView::of` and stores a
  large set of fields (spanning cache lines) that only `/proc/net/tcp`
  reads; poll/wait readers combine `state` and queue sizes from different
  steps anyway. A second source of truth for TCP state.
- Linux: no copy. `tcp_poll` READ_ONCEs the real fields (`sk_state`,
  `rcv_nxt`, `copied_seq`, `write_seq`, `snd_una`); `get_tcp4_sock` reads the
  live socket racily.
- Fix: keep only the fields with lockless readers (state, rcvq, sndq,
  writable, snd_una/snd_max) as Relaxed/Release atomics written where they
  change; compute the /proc view on demand (briefly taking the socket's
  slock, or racy reads of the live fields). Update the LOCKING.md table row.

### 11. Pipe: published ring indices and counts outside the mutex — (e)(b)(a)
- Where: `io/pipe.rs` `Pipe.head`/`tail`/`max_usage` (copied by
  `PipeGuard::publish` on every unlock), `occupancy`, `ring_full`;
  `Pipe.readers`/`writers` (`remove_reader`/`remove_writer` from
  `PipeReadEnd`/`PipeWriteEnd` drop with no pipe lock; FIFO opens under the
  inode slot lock), `r_counter`/`w_counter`.
- Wrong: three extra stores per lock hold; `occupancy` loads head and tail
  separately, so a lockless reader can see a wrapped (huge) or stale
  occupancy (spurious POLLIN/POLLOUT, spurious "full"). Reader/writer counts
  change outside `Pipe.inner`, so a writer holding the mutex does not see a
  stable reader count across its write (Linux decides EPIPE under the mutex);
  the FIFO path holds a different lock than the anon path. AcqRel RMWs under a
  lock are redundant.
- Linux: `pipe->head_tail` is one union word written under `pipe->mutex`,
  read with a single `READ_ONCE` (`pipe_readable`, `pipe_writable`);
  `readers`/`writers`/`r_counter`/`w_counter` change under `pipe->mutex`
  (`pipe_release`, `fifo_open`), read with READ_ONCE.
- Fix: one `head_tail: AtomicU64` owned by the ring, written (Relaxed/Release)
  where the ring changes under the mutex, no publish-on-drop; counts changed
  under the pipe mutex (release path takes it, as Linux), Relaxed atomic only
  for the lockless poll read. LOCKING.md pipe section.

### 12. Timer wheel fields as atomics; `running` read outside the base lock — (a)(e)
- Where: `time/timer.rs` `TimerList.expires`, `not_before`, `slot` (all
  "under the base lock"), `TimerBase.running`/`runner`,
  `TimerList::del_timer_sync`; `time/hrtimer.rs` `HrTimer.expires`/`clock`,
  `HrBase.running`.
- Wrong: wheel-owned fields are atomics only to dodge `UnsafeCell`.
  `del_timer_sync` detaches under the lock, then reads `running` after
  dropping it, and `run` clears `running` without the lock; correctness
  rests on an unargued Acquire/Release pairing across the unlock, and
  `runner` is a second atomic that must agree with `running`.
- Linux: `timer->expires` and wheel index plain under `base->lock`;
  `timer_pending` is the lockless READ_ONCE; `try_to_del_timer_sync` reads
  `base->running_timer` under `base->lock`, and `__run_timers` sets/clears it
  under the lock.
- Fix: wheel fields in a base-lock-owned cell; `pending` stays atomic
  (timer_pending); set/clear/read `running` (and owner) under the base lock.

### 13. Dirty throttling sums every possible CPU's slot per write — (c)
- Where: `mm/writeback.rs` `balance_dirty_pages` -> `mm/filemap.rs`
  `nr_dirty`/`sum` over `NR_DIRTY` (every possible CPU's slot), plus
  `FRAME_ALLOCATOR.stats()`.
- Wrong: every buffered write and write fault walks the whole per-CPU array.
- Linux: `global_node_page_state` reads one atomic (per-CPU diffs folded past
  a threshold); `balance_dirty_pages_ratelimited` checks only every
  `ratelimit_pages` per CPU.
- Fix: vmstat-style counter (per-CPU diff + global atomic folded at a
  threshold, i.e. `PercpuCounter`) and a per-CPU ratelimit before the check.

### 14. Dentry allocation does global RMWs — (c)
- Where: `fs/dentry.rs` `NR_DENTRY` (`fetch_add`/`fetch_sub` per dentry
  alloc/free); `util/list.rs` `NEXT_OWNER` (`OwnedList::new`, one per
  dentry's `children` and every skb queue); `util/rcuhlist.rs` `NEXT_CHAIN`,
  `util/hlist_nulls.rs` `NEXT_BUCKET` (lazy ids).
- Wrong: two global locked RMWs per dentry creation on all CPUs.
- Linux: `nr_dentry` is a per-CPU long summed for `/proc`; lists need no
  identity.
- Fix: `NR_DENTRY` as a `PercpuCounter` (or per-CPU slots summed); derive the
  `OwnedList` id from the list's own address/owner (stable while the list
  lives) or a per-CPU batched allocator.

### 16. Mount change numbers: global atomic + `fetch_max` instead of `mount_lock` — (d)(b)
- Where: `ns/mod.rs` `MNT_EVENT`, `MntEvents.event`, `MntEvents::bump`.
- Wrong: two atomics updated separately and a `fetch_max` to repair the
  ordering between racing bumps; the comment says remount changes a namespace
  outside `namespace_sem`, so a lock-free scheme was invented.
- Linux: `event` and `ns->event` change in `touch_mnt_namespace` /
  `__touch_mnt_namespace` under `mount_lock` held for writing (remount
  included), read with READ_ONCE by `mounts_poll`.
- Fix: bump under `fs/mount.rs` `MOUNT_LOCK` write (already held at every
  tree change; take it in remount as Linux does); `MNT_EVENT` a plain field
  of the lock's data, `MntEvents.event` a Relaxed store for pollers.
  LOCKING.md §3.4.

### 17. `Task.ppid`/`pgid`/`sid`: published copies of TASKLIST state — (e)
- Where: `task/mod.rs` `Task.ppid`, `pgid`, `sid`; writers in
  `task/percpu.rs` (reparent, `setpgid`/`setsid`, fork); readers `getppid`,
  `getpgid`, `do_wait` filters, `fs/proc/array.rs`.
- Wrong: numeric mirrors of `TaskInner.pgrp`/`session`/parent link, kept in
  step by hand across every thread of a group; a lockless reader can see a
  number whose struct pid is already gone or reused, and `getpgrp` can
  disagree with a concurrent `kill(-pgrp)` decided under TASKLIST.
- Linux: no copies; `task_pgrp`/`task_session` dereference
  `signal->pids[]` under RCU, `getppid` reads `rcu_dereference(real_parent)->tgid`.
- Fix: read through the struct pid under RCU (or TASKLIST read where already
  held); delete the mirrors.

### 18. Softnet `busy` and NAPI `sched`/`disable`: flags emulating a lock / state word — (d)(b)
- Where: `net/core/dev.rs` `Softnet.busy` (`process_backlog` `swap(true)`
  trylock), `has_work`; `Napi.sched`, `Napi.disable`, `napi_schedule`,
  `napi_complete_done`, `napi_disable`.
- Wrong: `busy` is an unnamed trylock (no lockdep, wake-up hand-off argued
  in prose). NAPI state is two separate booleans; there is no MISSED state,
  so a `napi_schedule` during the poll is lost unless every driver re-checks
  its causes after completing.
- Linux: `process_backlog` is the per-CPU backlog NAPI, serialized by
  `NAPI_STATE_SCHED`; one `napi->state` word with `cmpxchg` transitions
  (SCHED, MISSED, DISABLE).
- Fix: single NAPI state word with Linux's transitions (including MISSED);
  run the backlog as a NAPI instance so `busy` disappears.

### 19. tmpfs/inode numbers from a shared per-superblock atomic — (c)
- Where: `fs/superblock.rs` `SuperBlock.next_ino` (every create on the
  filesystem).
- Linux: `get_next_ino` per-CPU batches (`LAST_INO_BATCH`); shmem
  `ino_batch` per CPU.
- Fix: per-CPU batched allocation (as `fs/anon_inodes.rs` already does).

### 22. Inode identity bits as unrelated atomics — (b), low
- Where: `fs/inode.rs` `Inode.mode`, `uid`, `gid` (chown/chmod write them
  separately), `dead`, `i_swapfile`, `i_linkable`.
- Note: Linux also reads mode/uid/gid locklessly for permission checks, but
  takes `inode_lock` in `bprm_fill_uid` so set-id exec never sees a new owner
  with the old mode. hk has no set-id exec yet; when it lands it must read
  these under `i_rwsem`. The S_* booleans belong in one `i_flags` word.

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
rwlocks, `cpu::LocalWord`) are in place. Still to provide: a lock-owned
cell (`LockedBy`-style, proof by guard) for rq/timer-base/zone fields and
a `SeqCount` type, with their first users. Each atomic field's doc
comment names its lockless reader and Linux equivalent (rule 7); a field
"under lock X" with no lockless reader is a bug to fix. Remaining phases
by blast radius: 4-6 and 15/21 (scheduler, allocator, syscall path),
then 7-14 and 19-20 (RCU, VFS, net, mm hot paths), then 10-12, 16-18
and 22 (published copies, flag locks).

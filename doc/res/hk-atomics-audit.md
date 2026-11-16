# Atomics audit: where `Atomic*` replaced a design

Research only. Findings are ranked most damaging first; each names file + symbol,
category, the defect, Linux's design and the proper hk design. Categories:
(a) redundant (always under a lock), (b) torn multi-atomic invariant, (c) hot
shared RMW / cache-line traffic, (d) atomic emulating a lock, (e) ordering not
argued / published copy of locked state.

## Patterns

- **Locked RMW where Linux does a plain per-CPU or single-writer update.**
  `fetch_add`/`swap` on state that only one CPU or one task writes (preempt
  seqcount, per-task counters, rq fields under the rq lock). On x86 each
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
  `sched`+`disable`) and the spin-lock primitive itself (`IrqSpinlock`).

## Findings

### 3. `IrqSpinlock` spins on compare-exchange; locks are unfair TAS — (c)(d)
- Where: `sync/irqspin.rs` `IrqSpinlock::lock` (loop of
  `compare_exchange_weak` with no read-only inner spin); `sync/spin.rs` wraps
  `spin::Mutex`/`spin::RwLock` (test-and-test-and-set, unfair; the RwLock
  reader count is one shared RMW word).
- Wrong: every waiter issues a locked RMW per iteration, bouncing the line
  away from the holder (who must write it to unlock): contention collapses
  throughput and there is no FIFO fairness (starvation of a remote CPU on a
  run-queue or zone lock). RwLock read side (e.g. `Dentry.d_lock`,
  `Dentry.d_name` on every path component) writes the lock word, so popular
  directories become contended lines.
- Linux: qspinlock (MCS, waiters spin on their own node; arm64 and x86) or
  ticket locks; path walk is RCU-walk with `d_seq` seqcount, no stores to
  shared dentries.
- Fix: at minimum test-and-test-and-set in `IrqSpinlock::lock`; properly a
  ticket lock (two u16 in one u32, fair) now, qspinlock later. Track RCU-walk
  for dcache separately. Update LOCKING.md §1.1 "Properties".

### 4. `SchedEntity` and run-queue counters: lock-protected state as atomics — (a)(b)
- Where: `task/sched.rs` `SchedEntity` `vruntime`, `deadline`, `vlag`,
  `exec_start`, `rr_left`, `requeue_tail`, `contrib_load`, `class`, `policy`,
  `static_prio`, `rt_priority`, `reset_on_fork`; `task/fair.rs` `update_curr`
  (`exec_start.swap`), `place`/`save_lag` (`vlag.swap`);
  `task/percpu.rs` `CpuRunQueue::update_curr_rt` (`exec_start.swap`),
  `activate` (`contrib_load.swap`), `add_nr`; `PerCpuScheduler`
  `nr_running`, `nr_uninterruptible`, `nr_switches`, `ticks`.
- Wrong: all written under the rq lock (the `unsafe impl Sync` rationale is
  "every other field is atomic"), yet `swap`/`fetch_*` make every tick,
  switch, wakeup and enqueue pay several locked RMWs. The atomics hide the
  real rule. `set_params` writes class/policy/static_prio/rt_priority as four
  separate stores; lock-free readers (`sched_getattr`, `/proc/<pid>/stat`,
  `curr_rank`-based placement) can combine a new class with an old priority.
  `nr_running` etc. sit outside the lock's `CpuRunQueue` as sibling atomics.
- Linux: `sched_entity`, `sched_rt_entity`, `rq->nr_running`,
  `rq->nr_uninterruptible`, `rq->nr_switches` are plain fields under
  `rq->__lock`; `p->policy`/`static_prio` change under `pi_lock` + rq lock and
  are read with plain loads (tolerated torn reads only in getters).
- Fix: move the fair/rt fields into an rq-lock-owned cell (accessed with the
  rq guard as proof, like `ctx`); keep atomics only for fields with a named
  lockless reader (`state`, `on_rq`, `on_cpu`, `cpu`) and use Relaxed
  load+store there. Pack class/policy/prio into one word if lockless readers
  must see a consistent tuple. Move `nr_running`/`nr_uninterruptible` into
  `CpuRunQueue` with a Relaxed shadow only for `nr_running` (Linux READ_ONCE
  readers). LOCKING.md §3.1 lists each field's lock.

### 5. Page allocator per-CPU lists: RMW under lock, shared lines, trylock flag — (a)(c)(d)
- Where: `mm/page_alloc.rs` `Pcp.count` (`pcp_push`/`pcp_pop` `fetch_add/sub`
  under `Pcp.lock`), `Zone.nr_free` (`free_one`/`take` under `Zone.lock`),
  `Zone.draining` (`drain_all`: `swap(true)` as trylock).
- Wrong: locked RMWs on every order-0 alloc/free under a lock that already
  serializes them; `draining` is an invisible lock (no lockdep class, no
  owner). Boot-only fields (`map`, `start`, `end`, `managed`, `sections`,
  `batch`, `high`) are atomics rather than set-once (rule 5).
- Linux: `pcp->count` plain under `pcp->lock`; NR_FREE_PAGES via per-CPU
  vmstat diffs folded at a threshold; `pcpu_drain_mutex` with
  `mutex_trylock`.
- Fix: plain counts inside the locked structs (Relaxed shadow only where
  `drain_lists` peeks lock-free); `draining` becomes a real trylock-able
  mutex; boot fields `Once`/constructor. LOCKING.md §3.2.

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

### 7. `call_rcu` does a global SeqCst `fetch_max` on every call — (c)
- Where: `sync/rcu.rs` `call_rcu` (`GP_REQ.fetch_max(want, SeqCst)`), also
  reached by every `kfree_rcu`.
- Wrong: a CAS loop on one global line from every CPU on every deferred free
  (sockets, dentries, files, rcuhlist nodes).
- Linux: `rdp->gp_seq_needed` per CPU; `rcu_start_this_gp` touches the
  `rcu_node` only when this CPU has not already requested that GP.
- Fix: keep a per-CPU `needed` in `RcuData` (under `cbs`); only when `want`
  exceeds it, Relaxed-load `GP_REQ` and `fetch_max` if still behind.
  LOCKING.md RCU section.

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

### 15. Single-writer state updated with RMW — (a)
- Where: `task/mod.rs` `Task.nvcsw`, `nivcsw`, `min_flt`, `maj_flt`
  (`fetch_add` by the task itself), `Task::set_flag`/`clear_flag`
  (`flags.fetch_or/and(AcqRel)`; PF_* are written by the task itself);
  `util/kalloc.rs` `with_gfp` (`GFP_CX.swap`); `task/percpu.rs`
  `scheduler_tick` (`TICK_COUNT.fetch_add`, CPU 0 only),
  `PerCpuScheduler.nr_switches`/`ticks`; `net/core/dev.rs` `Napi.polls`,
  `Softnet.processed`/`dropped`/`time_squeeze`; `time/mod.rs`
  `TimeKeeper::write_begin`/`write_end` (under its lock).
- Wrong: locked RMWs and unargued AcqRel where one writer exists.
- Linux: plain `++`/`|=` on `current`, `this_cpu_inc`, `WRITE_ONCE`.
- Fix: Relaxed load+store helper (e.g. `util::once_writer_add`) and Relaxed
  for PF flags with the "only current writes" argument in a comment; any
  PF flag set on another task must instead go through a lock.

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

### 20. Slab and page-cache counts: RMW under the owning lock — (a)
- Where: `mm/slab.rs` `take_obj`/`put_obj` (`Page.inuse.fetch_add/sub` under
  `list_lock`), `KmemCache.nr_slabs`; `mm/filemap.rs`
  `AddressSpace.nrpages` (`fetch_add/sub` under the `i_pages` lock).
- Linux: `slab->inuse` and `mapping->nrpages` plain under `list_lock` /
  `xa_lock`, `nrpages` read with READ_ONCE.
- Fix: Relaxed load+store under the lock (the `Page` fields must stay atomic
  types for interior mutability; only the RMW goes).

### 21. Two wake-queue links per task — (a)
- Where: `task/mod.rs` `Task.wake_q` (used by `task/wake_q.rs`) and
  `task/sched.rs` `SchedEntity.wake_q` (used by `task/percpu.rs` `WakeQ`).
- Wrong: two parallel implementations of Linux `wake_q`; a task can be on
  both, and each has its own claim protocol.
- Linux: one `wake_q_node` per task, claimed with `cmpxchg`.
- Fix: one implementation, one node.

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

1. Enforce LOCKING.md §5.4 rules in review; add: (10) "an atomic RMW needs
   two concurrent writers: single-writer state uses Relaxed load+store";
   (11) "per-CPU data is cache-line aligned per CPU"; (12) "no published
   copies: the lockless reader reads the real field, stored once where it
   changes".
2. Provide the missing primitives so atomics stop being the path of least
   resistance: a lock-owned cell (`LockedBy`-style, proof by guard) for
   rq/timer-base/zone fields; an aligned `PerCpu`; a `this_cpu_add`-style
   non-atomic per-CPU counter; a `SeqCount` type; a fair ticket spinlock.
3. Each atomic field's doc comment names its lockless reader and Linux
   equivalent (rule 7); a field "under lock X" with no lockless reader is a
   bug to fix, not to document.
4. Fix the LOCKING.md §5 examples that endorse the anti-patterns:
   §5.1 (`preempt_count.fetch_add`), §5.2 (`File::advance_pos` `fetch_add`
   though callers hold `f_pos_lock`), the `CachedPage` row (no such type),
   and the `TcpSock.snap` row once finding 10 lands.
5. Phase order by blast radius: 3 (every lock), then
   4-6 (scheduler, allocator, syscall path), then 7-14 (RCU, VFS, net, mm
   hot paths), the rest as their subsystems are touched.

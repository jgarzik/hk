# hk Kernel Locking Documentation

This document describes the locking primitives, lock ordering rules, and per-subsystem
locking strategies used in the hk kernel.

---

## Table of Contents

1. [Lock Types](#1-lock-types)
2. [Global Lock Ordering](#2-global-lock-ordering)
3. [Per-Subsystem Locking](#3-per-subsystem-locking)
   - [Scheduler](#31-scheduler)
   - [Memory Management](#32-memory-management)
   - [Virtual File System (VFS)](#33-virtual-file-system-vfs)
   - [Namespaces](#34-namespaces)
   - [Timekeeping](#35-timekeeping)
   - [Kernel Logging (printk)](#36-kernel-logging-printk)
   - [Signal Infrastructure](#37-signal-infrastructure)
   - [Futex Subsystem](#38-futex-subsystem)
   - [TTY and Console Subsystem](#39-tty-and-console-subsystem)
   - [Device Drivers](#310-device-drivers)
   - [Other Subsystem Locks](#311-other-subsystem-locks)
4. [Deadlock Prevention](#4-deadlock-prevention)
5. [Lock-Free Patterns](#5-lock-free-patterns)
6. [Preemption Control](#6-preemption-control)
7. [Interrupt Context Rules](#7-interrupt-context-rules)
8. [API Quick Reference](#8-api-quick-reference)
9. [Gaps vs Linux Kernel](#9-gaps-vs-linux-kernel)

---

## 1. Lock Types

The kernel uses several synchronization primitives, each suited for different use cases:

### 1.1 IrqSpinlock<T>

**Location:** `sync/irqspin.rs` (lock and guard), `sync/irqflags.rs`
(`local_irq_save`/`local_irq_restore`/`irqs_disabled`) over the arch
primitives `arch::IrqFlagsOps` (`arch/x86_64/irqflags.rs`: RFLAGS,
`pushfq; cli` / `sti`; `arch/aarch64/irqflags.rs`: DAIF, `mrs daif;
msr daifset, #2` / `msr daif`). Linux: generic `raw_spin_lock_irqsave`
over `arch_local_irq_save`.

An IRQ-safe spinlock that disables interrupts and preemption while held. This is
the primary lock for code paths that may be entered from both interrupt and
process context.

**Properties:**
- Disables interrupts on lock acquisition
- Increments `preempt_count` (prevents context switch)
- Saves and restores interrupt state on unlock
- A queued spin lock (`sync/qspinlock.rs`, Linux qspinlock): one
  32-bit word (locked byte, pending byte, tail); uncontended a
  compare-exchange to take and a byte store-release to give back; the
  first contender spins on the word as the pending waiter, later ones
  queue FIFO on per-CPU MCS nodes (four per CPU: task, softirq,
  hardirq, NMI nesting) and each spins on its own node, so waiters do
  not bounce the lock's line and are served in order. The narrow
  accesses (unlock, set_locked, clear_pending_set_locked, xchg_tail)
  are arch instructions (`arch::qspin`): Rust has no mixed-size
  atomics

**Semantics (Linux equivalent: `spin_lock_irqsave`):**
```rust
// On lock():
1. local_irq_save           // Save flags, disable interrupts
2. preempt_count++          // Disable preemption
3. queued_spin_lock         // Acquire lock
4. lockdep irqsafe_acquire

// On drop()/unlock():
1. store-release locked = 0 // Release lock
2. preempt_count--          // Re-enable preemption
3. lockdep irqsafe_release
4. local_irq_restore        // Restore interrupt state (last)
```

**Use cases:**
- Per-CPU run queues (scheduler)
- Any data structure accessed from timer interrupt handlers
- Critical sections that must not be interrupted

**Methods:**
```rust
fn lock(&self) -> IrqSpinlockGuard<'_, T>
fn try_lock(&self) -> Option<IrqSpinlockGuard<'_, T>>
fn get_mut(&mut self) -> &mut T                          // owner's teardown, no lock
unsafe fn assume_held(&self) -> IrqSpinlockGuard<'_, T>  // context switch only
unsafe fn IrqSpinlockGuard::rebind(self, lock)           // context switch only
```

**Example:**
```rust
let sched = get_percpu_sched(cpu_id);
let mut rq = sched.lock.lock();  // IRQs disabled, preemption disabled
// ... critical section ...
// IRQs and preemption restored automatically on drop
```

### 1.1.1 IrqRwLock<T>

Linux rwlock_t taken with read_lock_irqsave / write_lock_irqsave
(`sync/irqspin.rs`): readers share it, a writer excludes all; either
side masks interrupts and raises the preempt count while held, so it
is ordered like an `IrqSpinlock` (non-IRQ-safe locks such as TASKLIST
may be taken inside it, never the reverse in interrupt context). Used
for SIGIO's `Fasync.fa` and `FOwner.st` (Linux fa_lock, fown->lock).

### 1.2 Mutex<T> (`sync::spin`)

Linux spinlock_t: the queued spin lock of 1.1 without interrupt masking
(tracked by lockdep-lite in `LOCKDEP=1` builds, 1.5). Used for data
structures that are **NOT** accessed from interrupt context.

**Properties:**
- Blocking (spins until lock acquired)
- Does NOT disable interrupts
- Raises `preempt_count` while held (Linux spin_lock's
  preempt_disable): `preempt_count() == 0` with interrupts on means no
  spin lock of any kind is held, which `might_sleep` checks (6.3)
- Suitable for longer critical sections in thread context

**Use cases:**
- Page cache
- File descriptor tables

**CRITICAL CONSTRAINT:** Never acquire a `Mutex` from interrupt context. If you
need to access the data from an interrupt handler, use `IrqSpinlock` instead or
defer the work.

### 1.3 RwLock<T> (`sync::spin`)

Linux rwlock_t on qrwlock (`sync/qrwlock.rs`). Allows multiple
concurrent readers or one exclusive writer.

**Properties:**
- Multiple readers OR single writer
- Does NOT disable interrupts
- Raises `preempt_count` while held, like `Mutex` (1.2)
- Fair (Linux qrwlock): one count word (writer byte, a waiting-writer
  bit, readers) plus a queued spin lock that contenders line up on, so
  readers and writers are served in arrival order: a reader finding a
  writer, or a writer waiting, queues, and a writer marks itself
  waiting so new readers stop taking the fast path. A recursive read in
  thread context therefore deadlocks behind a waiting writer, as on
  Linux (lockdep-lite reports any lock taken again while held, 1.5); a reader in an interrupt handler does not queue (it waits only
  for a writer that holds it). `IrqRwLock` (1.1.1) is the same lock
  with interrupts masked

**Use cases:**
- TASKLIST (Linux tasklist_lock: Linux takes it with write_lock_irq;
  hk never takes it in an interrupt handler, so interrupts stay on)
- VFS structures (inodes, dentries, mounts, superblocks)
- File contents in ramfs
- Any read-heavy data structure accessed from thread context only

**Methods:**
```rust
fn read(&self) -> RwLockReadGuard<'_, T>
fn write(&self) -> RwLockWriteGuard<'_, T>
```

### 1.3.1 Bit spin lock (util/hlist_bl.rs)

Linux bit_spin_lock as hlist_bl_lock: bit 0 of a hash bucket's head
word, so a table of buckets costs one pointer each. Thread context only,
interrupts stay on; to the preempt count and lockdep it is a spin lock
(`sync::spin::raw_enter`/`raw_leave`, one class for every bucket, never
two held at once). Only writers take it: readers walk a bucket under
an RCU read guard (`BlHead::find_rcu`, Linux
hlist_bl_for_each_entry_rcu), which removal allows by keeping the
removed link's `next` (hlist_bl_del_init_rcu) for entries freed a
grace period after the bucket lets go (`RcuFreePtr`). Used for the
dentry hash table (3.3 Dentry), under `Dentry.d_lock`, with nothing
taken inside it.

### 1.3.2 Nulls hash bucket lock (util/hlist_nulls.rs)

Linux hlist_nulls with inet_ehash_lockp: a `NullsHead` bucket's chain
ends in a nulls marker carrying the bucket's value (its index), and
each bucket has its own `sync::spin::Mutex<()>` (`NullsHead.lock`, one
lockdep class for every bucket: built in `NullsHead::new`). Thread
context only, interrupts stay on; never two buckets at once (a move
between buckets is a del under one, then an add under the other); a
leaf except what its users nest under it. Writers (`NullsGuard`:
`add_head_rcu`, `del_rcu` (O(1): a link names the id of the bucket it
is in, and a bucket's first link names it symbolically, so a bucket may
move),
`find`) hold it; readers hold only
`rcu::read_lock` (`iter_rcu`, `find_rcu`: Acquire loads, every link
pointer stored with Release). An entry taken off keeps its `next` and
may be hashed again at once, here or in another bucket, with no grace
period: a reader that followed it ends at another nulls value, and
`find_rcu` then walks again (Linux __inet_lookup_established). The
bucket's reference of an entry taken off comes back as
`NullsUnlinked`, dropped no earlier than a grace period later
(`defer`: `rcu::put_rcu`; plain drop: synchronize_rcu, sleeping;
`rehash` gives it to a bucket again), so a reader may take a
reference (`NullsRef::arc`). A bucket dropped with entries waits for a
grace period first (readers of other buckets may stand on them).

### 1.3.3 Per-CPU reference with kill (util/percpu_ref.rs)

Linux percpu_ref: a count of an object's users (`PercpuRef`), a word
per CPU (`PcpSlot`). `tryget_live` and `put` add to the caller's word
under an RCU read guard, lock-free, safe under any lock in thread
context. The owner's `kill` marks it dead (later trygets fail) and
waits a grace period, so every tryget that saw it live has counted;
`wait` sleeps (uninterruptibly) until the words sum to zero, woken by
puts that see it dead, then waits one more grace period so no put
still touches the object. kill and wait sleep: no spinlock held, and
the owner must not hold anything a user waits for while holding a
reference. Not a lock to lockdep. Users: swap devices (3.2, Swap).

### 1.4 Sleeping locks: sync::Mutex<T>, sync::RwSem (sync/)

Linux `struct mutex` and `struct rw_semaphore`: a contended lock sleeps
instead of spinning (only a tid-0 caller, the boot context before pid 1
exists or an idle task, spins: neither ever meets contention), so the
holder may sleep (page locks, block I/O, user page faults, blocking
pipe/socket I/O). No optimistic spinning (hk cannot tell whether an
owner is running).

- Wait lock (both): a `sync::spin::Mutex` (Linux wait_lock; interrupts
  stay on: these locks are thread context only and nothing under the
  wait lock wakes a task). Lockdep class: the lock's construction site
  (`Mutex::new`/`RwSem::new` are `#[track_caller]`): all
  `Inode.i_rwsem` wait locks share one class. A
  leaf: held only to queue, dequeue and grant, never across a sleep, and
  nothing is taken under it. The waker queues the tasks to wake on a
  `task::wake_q::WakeQ` (Linux wake_q: a task reference each, linked
  through `Task.wake_q`, no allocation) and wakes them after dropping
  the wait lock (`pi_lock`, run-queue locks). The reference is taken
  while the waiter is still queued under the wait lock, before a reader
  sees its grant (`granted`, Release/Acquire), so the waiter may return
  (its on-stack node gone) and even exit before the wakeup. A task on
  another `WakeQ` already is not queued twice: that wakeup comes after
  the caller's store (full barriers on both sides, Linux
  __wake_q_add), and every sleeping-lock wait rechecks its condition.
- `Mutex<T>` (Linux kernel/locking/mutex.c): an owner word (the owner task's
  address with three flags in its low bits, Linux mutex->owner: never
  a tid, which a non-leader's exec changes while it holds locks) and a FIFO wait list under the wait
  lock. Flags: `WAITERS` (list not empty: unlock takes
  the slow path and wakes the first waiter), `HANDOFF` (set by the
  first waiter when a retry after its wakeup fails: the next unlock
  hands the lock to it instead of releasing it), `PICKUP` (handed to
  the task in the word; no one else may take it). So a task that
  unlocks and relocks at once cannot starve a sleeper. Debug builds
  catch recursive locking and foreign unlocks by the owner word.
  `lock_interruptible`/`lock_killable` (Linux mutex_lock_interruptible/
  _killable) give up with EINTR on a signal (any, or SIGKILL) pending
  while they wait, after one more try under the wait lock (so a waiter
  woken by an unlock never leaves the lock free with sleepers queued);
  `try_lock` (mutex_trylock) never sleeps and never takes a lock handed
  to another task. `get_mut` reaches the data through `&mut` with no
  lock (a `Drop` of the owner).
- `RwSem<T>` (typed; `RwSem<()>` guards what its owner says):
  `read`/`write` guards, `read_killable`/`write_killable` (Linux
  down_*_killable: a `Killable` sleep, woken by wakeups and SIGKILL
  only, that gives up with EINTR once SIGKILL is pending),
  `read_interruptible`/`write_interruptible` (Linux
  down_*_interruptible: any pending signal gives up with EINTR; no
  caller yet), `try_read`/`try_write`, and the raw `down_read`/`up_read`, `down_write`/
  `up_write` pairs. Linux kernel/locking/rwsem.c: one atomic count
  (writer bit, `WAITERS`, `HANDOFF`, reader count above bit 8): an
  uncontended acquire or release is one atomic op; the wait lock and
  its FIFO list of readers and writers are taken only when the count
  says so (`WAITERS` and `HANDOFF` change only under it). A free lock is
  taken at once only while nobody queues (`try_*` likewise); otherwise
  the locker queues at the tail, except that a reader may steal a lock
  no reader or writer holds and no handoff guards (then granting the
  queued readers too). Release (last reader, writer) wakes the front
  waiter (`mark_wake`): a front writer, which then competes for the
  lock, or every queued reader (up to 256, writers skipped:
  phase-fair), granted the lock by the waker before it runs. A waiter
  past `RWSEM_WAIT_TIMEOUT` (4 ms, at least a tick; at once for an RT
  writer) that still finds the lock held sets `HANDOFF`: no stealing,
  and only the front waiter may take the lock, until it has. A front
  waiter that gives up (signal) wakes the waiters behind it; the last
  waiter leaving clears `HANDOFF`.
- Rules: thread context only; never taken in IRQ context or while any
  spinlock is held (`might_sleep` asserts a zero preempt count in debug
  builds; `IrqSpinlock` raises it). Sleeping locks order ABOVE every
  spinlock: a spinlock may be taken under them, never the reverse.

**Used for:** `RwSem`: `Inode.i_rwsem`, `SignalStruct.exec_update`,
the mmap_lock (`Mm.map`), `AnonVma.chain`, `Cgroup.{children,
subsys}`; `Mutex`:
`SuperBlock.s_vfs_rename_mutex`, `File.f_pos_lock`,
`SignalStruct.cred_guard`, RTNL (Linux rtnl_mutex),
`UnixSock.bindlock`, `UnixSock.iolock`, `Disk.open_mutex`,
`VdDisk.vdev`,
`Pipe.inner` (Linux pipe->mutex), `Eventpoll.mtx` (Linux ep->mtx) and
the inotify and fanotify `mark_mutex` (Linux group->mark_mutex).
The socket owner lock `net::sock_lock::SockLock` (Linux socket_lock_t:
`TcpSock.lock`) ranks with these sleeping locks; it is described in
3.10 Network.

### 1.4.1 SeqLock (sync/seqlock.rs)

Linux seqlock_t: `write()` takes a spin lock and keeps the sequence odd
while held (Release fences around the writer's stores); lockless
readers use `read_begin`/`read_retry` and repeat a read that raced a
writer. `read_excl` takes the spin lock without moving the sequence
(Linux read_seqlock_excl). A `SeqLock<T>` owns `T`, which can be a
`sync::UniqueOwner` (the owner of `LockedBy`/`LockedByEither` cells
kept elsewhere). Thread context only. Used for `mount::MOUNT_LOCK`
(Linux mount_lock) and `dentry::RENAME_LOCK` (Linux rename_lock).
Built on `SeqCount` (Linux seqcount_t), the sequence alone.

### 1.4.2 RCU (sync/rcu.rs)

Linux RCU, the non-preemptible flavor (kernel/rcu/tree.c with one flat
level instead of the rcu_node tree). A reader holds an `RcuReadGuard`
(`rcu::read_lock`, Linux rcu_read_lock): it raises the preempt count,
so a reader never sleeps (`might_sleep` reports it), an unnamed
allocation in it fails the boot (`MIGHT_ALLOC:FAIL`, 1.5; lockdep
builds show where it began), and its CPU passes no quiescent state while it holds
one. `RcuArc<T>` is an RCU-protected pointer (Linux `__rcu`, never
NULL once initialized): `read`
borrows the current version for the guard's lifetime
(rcu_dereference, Acquire), `get` takes a reference to it, `replace`
publishes a new one (rcu_assign_pointer, Release) and returns the old
as `RcuRetired`, released after a grace period when it drops
(synchronize_rcu; it panics in atomic context, where it would wait for
its own CPU or, with one CPU, not at all; `defer` and `defer_put`
release it through `kfree_rcu` / `put_rcu` instead). Updaters
serialize under their own lock. `RcuLockedArc<T, O>` is the nullable
form whose lock is typed (Linux a `__rcu` pointer written under a
named lock: signal->pids[] under tasklist_lock): `read` under a
guard, `protected` (rcu_dereference_protected) under a borrow of the
lock's `UniqueOwner` data `O`, `replace` under a mutable borrow of
it. `RcuOnceArc<T>` is the nullable form set once and emptied once by
atomic exchanges, so it needs no lock (Linux sb->s_fs_info): `read`
under a guard, `get` a reference, `take` the version as `RcuRetired`.
`RcuPtr<T>` owns nothing (Linux task->real_parent): `set` is
rcu_assign_pointer, `get` (unsafe) rcu_dereference, valid only on
the caller's argument that its target is freed a grace period after
no reader can reach it (`Task::parent`). `util::rculist::RcuList` (Linux rculist.h) is an
intrusive list of `Arc` (or `&'static`) entries: readers walk it under
a guard (Acquire loads of `next`; `RcuRef::get` takes a reference to an
entry found), writers take its own spin leaf (`ends`) and insert at the
tail, before or after an entry chosen under it, or replace one in
place (list_add_tail_rcu, list_add_rcu at a position,
list_replace_rcu); an entry unlinked keeps its `next` for readers
standing on it and comes back as `RcuUnlinked`, whose drop waits for a
grace period, frees the link and drops the list's reference
(list_del_rcu + synchronize_rcu). The owner's teardown takes the
entries off through `&mut` (`drain`: no reader or writer is left, so
no grace period). `util::rcuhlist::RcuHList` (Linux hlist_head with
the _rcu ops: `next`/`pprev` nodes, a strong reference per entry) is a
hash chain with no lock of its own: its writers pass the `UniqueOwner`
data of the lock they hold (1.4.1's `LockedBy` proof), so a table of
chains under one lock costs a pointer and an id per bucket. An insert
claims the node atomically, so chains under different locks cannot
both link it. Readers walk it under a guard; removal is
hlist_del_init_rcu, O(1) (the node names its chain's id, so membership
is checked with no walk and the chain may move; the node is free for a
new insert at once, `next` kept for a reader on it) and hands back the
chain's reference as `RcuHRef`, released after a grace period (`defer`:
kfree_rcu; `defer_put`: `put_rcu`, for an entry that may leave chains
again before the first release ran, Linux SOCK_RCU_FREE). A table grows by moving every
entry of a chain into a new table's chains under that lock with no
grace period (`move_all`, Linux neigh_hash_grow): a reader standing on
a moved entry walks on into its new chain and may miss entries, so a
lookup that must not miss repeats under the lock.

Quiescent states, per CPU: a context switch (recorded under the rq
lock, reported later), each idle-loop pass, and a clock interrupt that
arrived with the preempt count zero outside any other interrupt (Linux
rcu_flavor_sched_clock_irq: user mode, or kernel code outside every
spin lock and reader). A grace period (`rcu_gp` kthread): under `NODE`
(IrqSpinlock leaf, Linux rcu_node.lock), copy the online CPUs into its
mask and make `GP_SEQ` odd; each CPU, at a quiescent state after seeing
it odd, takes `NODE` and clears its bit only if `GP_SEQ` is still the
value it saw (Linux rcu_report_qs_rdp: a context switch recorded in an
earlier grace period clears nothing); the last one wakes `rcu_gp`
after releasing `NODE`, which makes `GP_SEQ` even under it and wakes
`synchronize` callers (`GP_DONE`). Fences: SeqCst before a report and
around both ends of a grace period (Linux's smp_mb in
rcu_gp_init/cleanup and smp_mb__after_unlock_lock). Taken in the clock
interrupt, the idle loop and `rcu_gp`, never with another lock held.

Callbacks (Linux call_rcu, kfree_rcu, rcu_do_batch): an object that
readers may still see is released after a grace period without its
updater waiting, through an `RcuHead` embedded in it (`rcu_head!`):
`kfree_rcu(arc)`, `RcuRetired::defer`, `RcuUnlinked::defer` (the
link freed and the list's reference dropped). `call_rcu` claims the
head (queued twice is an assert, not a corrupt list), stamps it with
the grace period that must end (`snap(GP_SEQ)`, sampled after a SeqCst
fence under the list lock), links it on this CPU's list (`RcuData.cbs`:
an IrqSpinlock leaf, Linux rcu_segcblist under the rdp lock; call_rcu
may run in any context, an interrupt handler included) and asks
`rcu_gp` for that grace period, unless this CPU asked for it already
(`RcuData.needed`, under `cbs`: Linux rdp->gp_seq_needed) or the global
request is past it (a Relaxed load first; `GP_REQ.fetch_max` and the
wakeup of its wait queue only when behind, after the list lock is
released). Nothing else is taken under `cbs`. Each
CPU's clock interrupt wakes its `rcuc/N` once the first callback's
grace period is over (`RcuData.next_gp`, written under `cbs`; Linux
rcu_pending -> invoke_rcu_core); `rcuc/N` takes a batch of ready
callbacks off under `cbs` (Linux blimit 10, or pending >> 7, all past
qhimark 10000) and runs them after releasing it, with preemption off
(Linux runs them with bottom halves off): a callback is atomic, must
not sleep and allocates only with a GFP named. It runs in the `rcuc/N`
of the CPU whose list it joined, never in `rcu_gp` or a clock
interrupt. The objects it drops must be safe to drop there: their last
reference may be the one deferred. `put_rcu(arc)` is the deferred
drop that may be queued again on the same object before an earlier one
ran (a `util::hlist_nulls` or `util::rcuhlist` entry unhashed,
rehashed and unhashed within one grace period): the object embeds an `RcuPuts` (`rcu_puts!`: a head
and a count of references handed over, each leaked); the put that
takes the count from 0 queues the head, and each callback (the head
already idle again) drops one reference and, if its decrement left the
count above 0, queues the head again, so the k-th reference goes in
the k-th callback, queued after it was handed over: at least one full
grace period. No lock; the count's RMWs (AcqRel) order a put against a
callback's decrement. Same rules as `kfree_rcu` for the drop (runs in
`rcuc/N`, preemption off). `rcu_barrier` (Linux; one caller at a time under
`BARRIER_MUTEX`, sleeping) queues a callback behind each CPU's last one
and waits for them all.

Assumptions: a CPU joins grace periods (`rcu::cpu_online`) when its
scheduler starts, before it runs anything, and never leaves (no CPU
hotplug); every CPU takes the clock interrupt every tick (no NOHZ), so
idle CPUs report. `rcu_gp` starts while the boot CPU is the only one
online (before the APs get schedulers); with one CPU online
`synchronize` returns at once (Linux rcu_blocking_is_gp).

### 1.5 Lockdep-lite (`sync::lockdep`, feature `lockdep`)

Kernel code takes `crate::sync::spin::{Mutex, RwLock}` (never the `spin`
crate's types directly; `printk` and lockdep itself are the exceptions).
These wrap `spin`'s types and raise the preempt count while held (1.2).
Every build checks `might_sleep` against the preempt count, interrupt
state and interrupt depth, and reports the first violation as
`MIGHT_SLEEP:FAIL` (quiet while booting, until the scheduler runs tasks,
and once reboot(2) is shutting down: `system_state`, as Linux's
__might_resched); a context switch with any lock held besides the
run-queue lock is reported as `SCHED:FAIL scheduling while atomic`
(Linux schedule_debug). Built with `make check LOCKDEP=1` (cargo feature
`lockdep`) the wrappers are also tracked, and the kernel reports, once
each, as `LOCKDEP:FAIL` (so the boot test fails):

- **Sleeping in atomic context:** `sync::might_sleep()` (sleeping locks,
  `schedule`/`yield_now`, wait queues, `Sock::wait`, user copies via
  `might_fault`, skipped while page faults are disabled) with a tracked
  spin lock held, a nonzero preempt count (any `IrqSpinlock`), in an
  interrupt handler, or with interrupts disabled (syscalls and faults
  run with them on, 7.5). Without the feature it is the
  `MIGHT_SLEEP:FAIL` check above.
- **Lock order:** a lock's class is the source location of its `new()`
  (`#[track_caller]`, like Linux's static lock_class_key: all
  `TcpSock.lock` slocks share one class). A `#[derive(Default)]` struct's locks all get the
  derive line as their class, so derive `Default` only on a struct with
  at most one lock. Taking B while holding A records A -> B; taking B
  under A after A was taken under B reports both acquisitions. Only
  direct inversions (no transitive cycles); nesting within one class is
  not checked (listener -> child slock, `lock2` of two unix sockets).
- **IRQ safety:** a tracked lock taken in an interrupt handler (the timer
  tick and device IRQ dispatch call `lockdep::irq_enter/exit`).
- **Interrupts on with an `IrqSpinlock` held** (Linux lockdep's
  inconsistent lock state): each guard saves the interrupt state it
  found and restores it on release, so guards must be released in
  reverse order; one released early turns interrupts back on under the
  other lock, and an interrupt that takes it spins forever on its own
  CPU. A per-CPU count of held `IrqSpinlock`s (a lock held across a
  context switch counts on the CPU) catches a release that re-enables
  interrupts while the count is nonzero.

Also reported, once per site, as `MIGHT_ALLOC:FAIL LOCKDEP:ATOMIC_ALLOC`
(the boot fails on it): a heap allocation with no GFP named (implicitly
GFP_KERNEL) in atomic context, i.e. a spin lock of any kind held,
preemption or interrupts off (Linux might_alloc -> might_sleep_if,
CONFIG_DEBUG_ATOMIC_SLEEP). Builds without lockdep check it too, from
the preempt count and interrupt state alone, and report the first eight
as `MIGHT_ALLOC:FAIL` with the CPU's stack; every build reports a page
allocation whose GFP may sleep in atomic context, once per caller
(`sync::might_alloc_pages`, Linux prepare_alloc_pages' might_alloc).
Not checked where the call named a GFP, in an interrupt handler, under
PF_MEMALLOC, in a task that cannot sleep, or while booting or shutting
down (`system_state`). The site is the innermost
`IrqSpinlock` taken (`lock`/`try_lock` are `#[track_caller]` in lockdep
builds; each CPU keeps the sites of the ones it holds, report only,
like Linux's preempt_disable_ip), else the innermost tracked spin lock,
else the outermost RCU read-side section, else the `local_irq_save`
that turned interrupts off.

The held-lock stacks are per CPU (the kernel is not preemptive and a task
never sleeps holding a spin lock, which is itself checked), the edge
table is a fixed array: nothing allocates. Power-off prints a
`lockdep: N reports, M order edges, K atomic allocation sites` summary. `IrqSpinlock` acquisitions
are not tracked for order (they are leaves or near-leaves); they count
through the preempt count and the held count above.

### 1.6 Atomic Types

Lock-free atomic operations from `core::sync::atomic`. Used for simple counters,
flags, and lock-free algorithms.

**Types used:**
- `AtomicBool` - Flags, lock states
- `AtomicU32` - Sequence counters, CPU IDs, reference counts, preempt_count
- `AtomicU64` - Counters, TIDs, file positions, timestamps
- `AtomicI64` - Signed time offsets
- `AtomicPtr` - Function pointers

**Common orderings:**
- `Ordering::Relaxed` - Counters, non-synchronizing updates
- `Ordering::Acquire` - Read that synchronizes with Release write
- `Ordering::Release` - Write that synchronizes with Acquire read
- `Ordering::SeqCst` - Full sequential consistency (rare)

---

## 2. Global Lock Ordering

To prevent deadlocks, locks must be acquired in a consistent order. The global
lock ordering from outermost to innermost is:

```
fs::file DELAYED_FPUT_RUN (sync::Mutex; held across a drain of the
                         delayed fput list, whose releases take any
                         lock a file's release takes; taken with
                         nothing held: the system workqueue's worker,
                         flush_delayed_fput at boot; outermost)
    ↓
SignalStruct.cred_guard (sync::Mutex; Linux cred_guard_mutex; exec,
                         ptrace attach)
    ↓
SignalStruct.exec_update (sync::RwSem; Linux exec_update_lock; write:
                          exec installing the new mm; read: mm_access,
                          migrate_pages/move_pages;
                          exec takes TASKLIST and then the task's
                          alloc_lock under it)
    ↓
cgroup::CGROUP_MUTEX (sync::Mutex; Linux cgroup_mutex: cgroupfs mkdir,
                     rmdir and control writes under the directory's or
                     file's i_rwsem; a CLONE_INTO_CGROUP fork holds it
                     across the TASKLIST insert)
    ↓
cgroup::CGROUP_THREADGROUP_RWSEM (sync::RwSem; Linux
                     cgroup_threadgroup_rwsem: read by every fork from
                     cgroup admission to post_fork, write by a
                     cgroup.procs migration; no cgroupfs spin lock is
                     held across it)
    ↓
Cgroup.{children, subsys} (sync::RwSem, per cgroup; Linux
                     cgroup_mutex-written cgrp->subsys[] and
                     kernfs_rwsem for the children: written under
                     CGROUP_MUTEX; read by cgroupfs lookup/readdir
                     under the directory's i_rwsem (so, like
                     CGROUP_MUTEX, below a cgroupfs Inode.i_rwsem),
                     by fork under
                     CGROUP_THREADGROUP_RWSEM, by exit, and by a
                     migration before it takes Task.cgroup; one at a
                     time, nothing sleeping under them, never under a
                     spin lock)
    ↓
IpcIds.rwsem (sync::RwSem; Linux ids->rwsem; write: ipcget (lookup,
              limits and insert as one step), IPC_RMID, IPC_SET;
              shm creation makes its shmem file under it; no user
              memory is copied under it, IPC_SET copies in first)
    ↓
VFS locks (detailed order):
    File.f_pos_lock (sync::Mutex; read/write/lseek/getdents by position)
        ↓
    SuperBlock.s_vfs_rename_mutex (cross-directory rename only)
        ↓
    Inode.i_rwsem (sync::RwSem; exclusive: directory operations,
                   lock_rename, regular file write, truncate and
                   fallocate, the
                   mountpoint during attach (Linux lock_mount); shared:
                   path-walk lookup on a dcache miss, readdir;
                   parent directory -> the link/unlink/rename victim or
                   link source, two non-directories by address)
        ↓
    mount::NAMESPACE_SEM (sync::RwSem; Linux namespace_sem: write for
                   attach, umount, namespace copy; read for /proc mount
                   lists, is_local_mountpoint and a new mount's
                   mnt_already_visible, taken there with nothing held;
                   the write guard's drop is namespace_unlock: an
                   umount's mountpoints and, after a grace period,
                   references released with nothing held)
        → ns::tree NS_TREE (IrqSpinlock leaf, 3.4; graft's
                   mount namespace owner check under NAMESPACE_SEM)
        ↓
    SuperBlock.s_umount (sync::RwSem; write for remount, for a new
                   superblock from sget to its mounter's unlock (its
                   fill_super under it: inode, dentry and kernfs
                   locks, the device's I/O; a mount's caller holds
                   only the mountpoint path then, no VFS lock), and
                   for the last active reference's shutdown (taken with
                   nothing held: generic_shutdown_super takes d_locks,
                   SuperBlock.s_inodes, inotify locks, the writeback
                   pass (BdiWriteback.pass and what writeback takes)
                   and what eviction takes under it), read for a bind
                   remount and the superblock walks; trylock-read for
                   reclaim's, and for the writeback pass over every
                   superblock, per superblock under BdiWriteback.pass
                   and its list_lock, never waiting (Linux
                   __writeback_inodes_wb): no pass writes an inode of a
                   superblock being shut down or remounted)
        ↓
    mount::MOUNT_LOCK (SeqLock writer, spin; every mnt_flags write, and
                   the tree's links in attach_mnt/detach_mnt; across
                   all of umount_tree, propagate_umount included, and
                   do_umount's propagate_mount_busy, and its
                   MNT_EXPIRE check before NAMESPACE_SEM; locking
                   read in legitimize, path_is_under and a raced
                   d_path pass; its sequence read
                   lock-free by d_path and scoped walks)
        → SuperBlock.s_mounts (spin leaf: a new mount, a read-only
                   remount's walk)
        → pnode::GROUP_IDA (IrqSpinlock leaf: umount_tree's
                   bulk_make_private frees a group's id)
        ↓
    dentry::RENAME_LOCK (SeqLock, spin; Linux rename_lock: write in
                   d_move/d_exchange; locking read in a raced
                   is_subdir/d_path/dentry_path pass, inside MOUNT_LOCK
                   as Linux prepend_path and path_is_under; its
                   sequence read lock-free by those and scoped walks)
        ↓
    MntNamespace.root, Mount.{parent, mountpoint} (spin;
                   path_is_under borrows parent/mountpoint under
                   MOUNT_LOCK's locking read, d_path under an RCU
                   read guard)
        ↓
    Inode.i_lock (spin Mutex, Linux i_lock: the inode's dentries
                   (i_dentry) and its i_state writes, the dirty bits
                   and I_SYNC included; taken before the d_locks of
                   the dentry it links or unlinks and its parent; under
                   INODE_HASH_LOCK by igrab and (un)hashing, SuperBlock.s_inodes by igrab, under
                   BdiWriteback.list_lock by igrab and writeback; under
                   it a wait queue head (I_SYNC's, var_waitqueue) and
                   AddressSpace.i_pages (writeback's mapping_tagged))
        ↓
    Dentry.d_lock (single d_lock like Linux; short, never held across
                   i_rwsem; parent before child)
        → dentry hash bucket (util::hlist_bl bit lock: Linux
                   hlist_bl_lock on dentry_hashtable; leaf)
        ↓
    Inode.private
        ↓
Filesystem-internal locks (ramfs children: sleeping RwSem inside the
    directory's i_rwsem; ramfs data; procfs data, a leaf: held only to
    copy out what a lookup, readdir, readlink or read acts on, which
    then runs unlocked; never written after mount: the static tree is
    built bottom-up before it is reachable, each directory's entries
    given to its inode with no lock (`DirBuild`, Linux allocating each
    proc_dir_entry before proc_register links it); kernfs `KNode.children` sleeping RwSem,
    `KNode.{parent,iattr}` spin leaves, 3.3 kernfs)
    ↓
Leaves taken with no task lock held (their Arc is cloned out of the
Task first, under its alloc_lock or lock-free by the task itself):
UtsNamespace.name (RwLock), FsStruct.seq (SeqLock),
FutexHashBucket.waiters (spin Mutex; wakeups through a WakeQ after
unlocking)
    ↓
Global subsystem locks (TASKLIST, fd table `Files`)  ← NOT IRQ-safe;
    `Files` is a leaf: nothing is allocated, flushed or closed and no
    other lock taken under it (3.3, Descriptor Tables; RLIMIT_NOFILE is
    read before it, as Linux get_unused_fd_flags; kcmp takes a table
    out under the task's alloc_lock and locks it after dropping that);
    no user memory is accessed under any of them. A task's signal
    handlers and signal state, robust-list head and TLS base are
    fields of its `Task` read or changed under TASKLIST; its mm, fd
    table, fs context, namespaces, name, memory policy and I/O context
    under its alloc_lock (3.1.1); under them only leaves:
    SigHand.siglock (its owned state: Task.sig, SignalStruct.jobctl
    and shared, and its action table); SignalStruct.rlim (IrqSpinlock leaf;
    setrlimit/prlimit64 read the old limit, decide (with the
    lock-free capable()) and store in one hold, as Linux do_prlimit
    under task_lock); UCOUNTS (IrqSpinlock leaf, 3.1.1 Per-user
    counts); wait queue heads
    ↓
Address space: mmap_lock (sleeping RwSem; under i_rwsem: a write's user
    copy may fault) → page lock (PG_locked, sleeping; Linux folio_lock)
    [→ buffer lock (BH_Lock bit, sleeping) | AddressSpace.i_private_lock
    (spin, Linux i_private_lock) → MappingMetadataBhs.lock (spin);
    → AddressSpace.i_pages (spin leaf, Linux xa_lock; 3.2)]
    → AddressSpace.i_mmap (sleeping RwSem, Linux i_mmap_rwsem)
    → AnonVma.chain (sleeping RwSem, Linux anon_vma->rwsem)
    → page_table_lock → PTE lock (spin) [→ MMLIST (spin leaf)]
    → SwapInfo.map (spin, Linux si->lock) | swap cache (IrqSpinlock,
      Linux i_pages; never nested with SwapInfo.map) | LRU add batch
      (IrqSpinlock, per CPU) | Lruvec.lock (IrqSpinlock, Linux lru_lock;
      never nested with the others)
    ← never nested with TASKLIST (3.2)
    ↓
Memory allocator locks (Linux: ... → slab → pcp → zone->lock):
    slab per-CPU array (IRQs off) → KmemCache.list_lock (IrqSpinlock)
    → per-CPU page list lock (IrqSpinlock, one at a time) → Zone.lock
    (IrqSpinlock leaf); a type-stable cache's call_rcu after
    list_lock is dropped; 3.2 Heap Allocator, Frame Allocator

Kernel mappings (3.2 Kernel Page Tables): vmalloc FLUSH (sleeping;
    held across the allocation area's TLB flush) → vmalloc AREA (spin
    leaf; no mapping or flush under it); vmstack FLUSH (sleeping,
    thread context; held across the stack area's TLB flush) → IOREMAP,
    vmstack SLOTS (spin leaves; no mapping or flush under them); KTABLES
    (spin leaf, thread context; table frames allocated before it)

AIO (3.11, io/aio/): Kioctx.ring_lock (sleeping) → mmap_lock (the
    copy of events to user space); Mm.ioctx and AIO_NR (spin leaves);
    Kioctx.comp, Kioctx.reap (IrqSpinlock leaves, any context: a bio's
    end posts its event); PollIocb.reg (sleeping, across the file's
    poll) → Kioctx.active → file wait queue head → PollIocb.st →
    Workqueue.inner (a poll's wakeup queues its work under the queue
    head)

epoll, inotify, fanotify (3.11, io/): EPNESTED (sleeping) →
    Eventpoll.mtx (sleeping, the item map; held across epoll_ctl, the
    ready-list scans and their files' polls and copies to user: → the
    polled files' locks, mmap_lock, BTreeMap allocation, and a watched
    epoll's own Eventpoll.mtx, nested acyclically at most EP_MAX_NESTS
    deep) → EpItem.regs (spin) → file wait queue heads → Eventpoll.lock
    (IrqSpinlock leaf, the ready list; ep_poll_callback); File.f_ep
    (spin leaf); a last `FileRef` dropped under Eventpoll.mtx only
    queues the release, whose `eventpoll_release` takes it;
    Inotify.mark_mutex (sleeping) → Inotify.inner (IrqSpinlock) →
    Marks.list (spin leaf); USER_WATCHES (spin leaf);
    Fanotify.mark_mutex (sleeping, the marks), Fanotify.inner
    (IrqSpinlock leaf, the event queue); nothing allocates under any of
    the spin locks (events are allocated before the queue lock, the
    vectors grow with their lock released)

Pipes (3.11): Pipe.inner (sleeping; two in address order) → frame
    allocator, and the mmap_lock of a faulting user copy (read, write
    and vmsplice copy between pipe pages and the caller's memory under
    it, Linux pipe_read/pipe_write/vmsplice_to_pipe), and `FASYNC_LOCK` (pipe_fasync);
    a pipe-to-file splice also writes the output file under it (its
    write path: i_rwsem, page cache, socket locks; Linux
    iter_file_splice_write under pipe_lock), and a file-to-pipe splice
    reads the input file under it (its read path; Linux
    splice_file_to_pipe: do_splice_read under pipe_lock); no read or
    write path of a non-pipe file takes a Pipe.inner; no other lock
    under it, none of these above it

SIGIO (3.11, io/fasync.rs; Linux fasync_lock, f_lock, fa_lock,
    fown->lock): fasync_helper: File.f_lock → FASYNC_LOCK (spin, one
    for every list) → an entry's `fa` (IrqRwLock); kill_fasync walks a
    list under RCU, any context but hardirq, spin locks held or not:
    `fa` (read) → FOwner.st (IrqRwLock, read) → TASKLIST (read; a
    pgrp owner's group walked under it, each send in place) →
    SigHand.siglock (the receiver's), its entry GFP_ATOMIC (3.7 rule 5)

Block locks (3.10 Block Device Subsystem):
    Disk.open_mutex (sleeping) → devtmpfs root i_rwsem, INODE_HASH_LOCK
    (bdev_add/bdev_del), MAJORS, BDEV_LOCK (claims; sleeping leaf, also
    taken alone to prepare a claim); I/O sleeps under open_mutex only
    SuperBlock.s_umount → bdev inode i_rwsem (sleeping; set_blocksize
    writes it, device-file buffered I/O reads it) → mmap_lock,
    AddressSpace.invalidate_lock (sleeping; set_blocksize writes it, a
    read or fault filling a page reads it, mmap_lock → it) → page lock
    blk-mq software queue, hardware queue (IrqSpinlock leaves; the
    hardware queue also from the driver ISR, under its line's IrqDesc.lock;
    a poll queue is a hardware queue no interrupt reaches: taken by the
    polled bio's submitter and by pollers, `BlkMq::poll_queues`)
    Completion.done (IrqSpinlock) → wait queue head → run-queue lock
    VdDisk.vdev (sleeping) → virtio-blk teardown (IRQ free, hardware
    queues, rings); HDIO_GETGEO's config read takes nothing

Network locks (3.10 Network Subsystem has the full order):
    RTNL (sleeping, outermost; never under any spinlock)
        ↓
    TcpSock.lock owner / UnixSock.bindlock / UnixSock.iolock /
    UdpSock.op / PingSock.op (sleeping; TCP's held across user copies:
    → mmap_lock)
        ↓
    socket spin locks (TcpSock.lock slock, TimeWait.inner, UnixSock.st)
    → protocol tables → Inet.addr → queues, timers
        ↓ (transmit under a socket lock)
    FIB / neighbour / device TX → Softnet.backlog
    Socket wakeups (`Sock::data_ready`, `write_space`,
    `error_report`, `wake_async`) may send SIGIO (`kill_fasync`, RCU)
    under network spin locks (a packet tap fed by a transmit under its
    socket's locks; TCP's wakeups under its slock or as the owner;
    Linux the same). `Sock.wq_flags` (NOSPACE, WAITDATA) are
    atomic bits, Linux socket_wq.flags.
    Network spin locks are taken in thread context only (softnet
    threads, socket calls); ISRs only touch atomics, `Softnet.poll_list`
    and wait queues (IrqSpinlocks). No socket is released under a
    network lock or under `Files`/TASKLIST (3.3, 3.1.1).

Tasks (3.1.1, 3.7; Linux tasklist_lock → pidmap_lock → task_lock →
    siglock): TASKLIST (spin RwLock, thread context; also guards the
    `Pid.pgrp`/`session` lists, 3.1.1) → PIDMAP_LOCK
    (spin, thread context; hash chains; in practice a leaf) →
    Task.alloc_lock (spin Mutex, per task, thread context, not
    IRQ-safe; Linux task_lock; one task's at a time) →
    SigHand.siglock (spin Mutex, per handler table, thread context;
    Linux sighand->siglock, 3.7; owns each naming task's Task.sig and
    its group's SignalStruct.jobctl and shared, no locks of their own;
    its data is the action table); Task.keyrings, Task.cgroup:
    per-task leaves reached through the task (current
    or a held TaskRef), never under TASKLIST; SignalStruct.posix_timers (never under TASKLIST)
    → PosixTimer.inner (the registry's timers, the CPU itimers),
    SignalStruct.rlim (cpu_timer's expiry pass)

Wakeups (3.1; any context, under any of the above):
    WaitQueue head (IrqSpinlock) → Task.pi_lock (IrqSpinlock, per task)
    → per-CPU rq lock (IrqSpinlock) → arm64 ASID lock (IrqSpinlock
    leaf; switch_mm slow path, 3.2 TLB Flushing); a remote CPU's wake
    list is lock-free (pushed under pi_lock). Nothing else is taken
    under pi_lock or an rq lock: no TASKLIST, no allocation.

Timers (3.3 Timers): Alarm.st → TimerBase.wheel (IrqSpinlock leaf,
    per CPU; callbacks run with it dropped). Owner locks
    (PosixTimer.inner, Timerfd.inner) → HrBase.q (IrqSpinlock leaf, per
    CPU, HARD and SOFT; callbacks run with it dropped). timerfd
    CANCEL_LIST: an RcuList walked under rcu::read_lock → Timerfd.inner;
    its `ends` leaf is never held with `inner`

Timekeeping (3.5):
    TimeKeeper.lock (IrqSpinlock leaf; writers only: the CPU 0 tick,
    clock_settime, init; readers are lockless seqlock retries)

Printk locks (ALL IRQ-safe - can be acquired from interrupt context):
    OUTPUT_LOCK (IrqSpinlock, held for entire message)
        ↓
    kmsg LOG (IrqSpinlock leaf, the record log; taken and released
              before PRINTK)
    PRINTK (IrqSpinlock, ring buffer)
        ↓
    CONSOLE_REGISTRY (IrqSpinlock, console dispatch)

/dev/kmsg (kmsg.rs):
    KmsgUser.cur (spin, per open; never held across a wait or the
    copy to the reader) → LOG
    KmsgUser.rate (spin leaf)

TTYs (3.9): jobctrl CTTY_LOCK (spin) → TASKLIST (read) → Tty.ctrl
    (spin; never takes TASKLIST under it); CTTY_LOCK → TASKLIST (read)
    → SignalStruct.ctty (spin leaf, one at a time, never with
    Tty.ctrl); Tty.ldata (sleeping Mutex,
    Linux termios_rwsem's role) → Tty.termios (spin, thread context;
    termios is read under ldata by input processing and swapped under
    it by set_termios, as Linux's termios_rwsem spans both), and →
    Tty.ctrl, TASKLIST and the signal locks (ISIG signals sent under
    it, Linux __isig; input's SIGIO and read_wait wakeup too, Linux
    n_tty_receive_buf_common: kill_fasync, RCU) and the echo's driver
    writes; Tty.avail
    (atomics) is read lock-free by poll and readers; Tty.read_lock (sleeping Mutex, Linux
    atomic_read_lock) → Tty.ldata, Tty.flip: held by a reader across its
    sleeps on read_wait; Tty.write_lock (sleeping Mutex, Linux
    atomic_write_lock) → Tty.termios, TASKLIST (read) → Tty.ctrl and
    the SIGTTOU send (the TOSTOP check): held by a writer across the
    whole write(2) and its driver writes; never nested with read_lock or
    buf_lock; Tty.buf_lock (sleeping Mutex, Linux
    tty_bufhead.lock) → Tty.ldata: held by the flip thread across
    feeding input and by flush_input; Tty.flip (IrqSpinlock leaf,
    also under IrqDesc.lock in the UART handler). No tty spin lock is held
    across a signal, a sleep or a driver write; Tty.buf_lock and
    Tty.ldata are. Tty.files (sleeping, Linux tty_lock; outermost) →
    CTTY_LOCK, Tty.flow, Tty.buf_lock, UartPort.xmit and the
    write_wait sleep of the port's last close's drain; a hangup under
    it → CTTY_LOCK → Tty.ctrl, then the session leader's signals
    (TASKLIST, signal locks), the hung files' fasync removal
    (File.f_lock → FASYNC_LOCK), Tty.buf_lock → Tty.ldata,
    UartPort.xmit, Tty.throttle.
    Tty.output_lock (sleeping Mutex, Linux n_tty_data.output_lock):
    Tty.write_lock → Tty.ldata (pending echo) → Tty.output_lock →
    UartPort.xmit; the echo's driver writes take it under Tty.ldata.
    TIOCSSERIAL (Linux uart_set_info_user: termios_rwsem write,
    port->mutex): Tty.files → Tty.ldata → Tty.port (sleeping Mutex,
    Linux tty_port.mutex) → UartPort.cfg (spin leaf), UartPort.xmit
    (the port's shutdown and startup), IOPORT (a port move's
    release_port/request_port, UartPort.cfg released: claiming
    allocates); TIOCGSERIAL Tty.port → UartPort.cfg. An open
    activates the port (Linux tty_port_open: uart_startup under
    port->mutex) under Tty.files → Tty.port → UartPort.xmit, the
    driver's startup after it is released (the 8250 requests its
    interrupt there: Tty.port → IrqDesc.lock); a hangup and the last
    close take it down under Tty.files → Tty.port (the close after
    its drain, closing_wait read under Tty.port released before it)
    → UartPort.xmit, the driver's shutdown again outside it (the
    8250 frees its interrupt, waiting out a running handler, which
    takes no tty lock but Tty.flip and UartPort.xmit). A port's
    removal takes a port still up down under Device.lock → Tty.port.
    Tty.flow (spin, thread context) → UartPort.xmit
    (TCXONC, and IXON's STOP/START from input and IXON cleared by a
    termios change, both under Tty.ldata: Tty.ldata → Tty.flow;
    the driver's stop/start); Tty.ldata → Tty.throttle (sleeping
    Mutex, Linux throttle_mutex) → Tty.termios, UartPort.xmit (IXOFF's
    STOP/START, uart_throttle's send_xchar); TCIOFF/TCION send the
    character under Tty.ldata (Linux termios_rwsem) → UartPort.xmit.
    tty_fasync reads Tty.ctrl (the foreground group) after
    `Tty.fasync` is released.
```

### Key Rules

1. **IrqSpinlock is innermost for IRQ-safe locks** - When you need to hold both
   an IRQ-safe lock and a non-IRQ-safe lock, acquire the IrqSpinlock first.

2. **Never acquire non-IRQ-safe locks from interrupt context** - This is the
   fundamental rule. TASKLIST, fd tables, and allocator locks must
   NEVER be acquired from timer ISR or any interrupt handler.

3. **Parent before child** - When locking multiple inodes in a directory
   hierarchy, lock parents before children.

4. **For multiple directories** - When an operation spans multiple directories
   at the same level, lock in increasing inode number order.

5. **Release in reverse order** - Always unlock in the opposite order of acquisition.

6. **VFS locks are outer locks** - Filesystem-internal locks must always be
   acquired while holding VFS locks, never the reverse.

### Why IrqSpinlock → TASKLIST is Safe

Some IrqSpinlock holders may take `TASKLIST` (the scheduler does not:
the run queue keeps everything a switch or wakeup needs in the `Task`,
3.1):

1. `IrqSpinlock` disables interrupts on the local CPU
2. While interrupts are disabled, no ISR can run on this CPU
3. Therefore, no deadlock can occur from the timer ISR trying to acquire TASKLIST
4. This ordering is safe because TASKLIST is NEVER acquired from interrupt context

**This is the Linux-style pattern:** protect the innermost critical section with
an IRQ-safe lock, then acquire non-IRQ-safe locks while protected.

**Detailed Safety Analysis:**

```rust
// On IrqSpinlock::lock():
cli              // Step 1: Disable interrupts (no ISR can preempt)
preempt_count++  // Step 2: Disable preemption (no context switch)
acquire lock     // Step 3: Spin until acquired
```

With interrupts disabled after Step 1:
- Timer ISR cannot fire on this CPU
- No nested interrupt can try to acquire TASKLIST
- Deadlock is impossible from the local CPU

Other CPUs cannot cause deadlock because:
- Run-queue and pi locks are innermost (nothing but the ASID leaf is
  taken under them), so holding TASKLIST across a wakeup is allowed,
  though wakers drop it first where they can
- Leaves may be taken under TASKLIST (a wait queue head,
  `SigHand.siglock`,
  `SignalStruct.rlim`): they take nothing that leads back to it
- TASKLIST is NEVER acquired from interrupt context (see Section 7.4)
- Nothing is released under TASKLIST (3.1.1 rule 4): a release could
  sleep, and no task sleeps holding a spin lock

---

## 3. Per-Subsystem Locking

### 3.1 Scheduler

**Location:** `task/percpu.rs`

Each CPU has its own run queue and lock (Linux struct rq); a wakeup
takes the lock of the run queue it queues on, whichever CPU that is.

#### Global State

| Variable | Type | Purpose |
|----------|------|---------|
| `PERCPU_SCHEDS` | `PerCpu<PerCpuScheduler>` | Per-CPU scheduler array |
| `SCHED_CPUS` | `CpuMask` | CPUs that are active and run a scheduler (Linux cpu_active_mask): set once per CPU at bring-up (`sched_cpu_update`, Release fence), read lock-free by every wakeup placement and balancing pass (Acquire fence) |
| `TASKLIST` | `RwLock<GlobalTaskTable>` | Every task (Linux tasklist_lock + task list) |
| `TICK_COUNT` | `AtomicU64` | Global tick counter (jiffies, TICK_MS = 10 ms); advanced only by CPU 0's tick; every CPU's tick runs its own timers (`timer::run_local`; Timers, 3.3) |

#### Per-CPU State

Each `PerCpuScheduler` contains:
```rust
pub struct PerCpuScheduler {
    pub lock: IrqSpinlock<CpuRunQueue>,  // curr, idle, prev, class queues, dead
    pub initialized: AtomicBool,          // Init flag
    pub nr_switches: AtomicU64,           // context switches (QSBR hook)
    pub curr_mm: AtomicUsize,             // running task's Mm address (membarrier)
    pub membarrier_state: AtomicU32,      // its membarrier registrations
    pub curr_rank: AtomicU32,             // running task's importance (rt placement)
    pub ticks: AtomicU64,                 // this CPU's ticks (balancing interval)
    pub nr_running: AtomicU32,            // queued + running tasks
    pub nr_uninterruptible: AtomicI64,    // loadavg's D-state count
}
```

Each `Task` carries its scheduling entity (`Task.se`, Linux
sched_entity + `__state`/`on_rq`): `state` (`SleepState` as an
atomic), `on_rq` (queued or running), `on_cpu` (running, or its CPU
still switching away from it), the scheduling class and Linux
parameters (`params`: class, policy, static and rt priority in one
word; `reset_on_fork`; SCHED_RR's slice), the run-list `link` and the
saved switch frame (the wake queue link is `Task.wake_q`, 1.4); plus
`Task.pi_lock` (IrqSpinlock, Linux pi_lock). The run queue owns one
reference to each task of its CPU, from its first wakeup (or creation
asleep) until its final switch away (`DeadTask`; Linux: the task's own
usage count put in finish_task_switch); its lists and `curr` hold none
of their own. The class and parameters are written under the task's
pi_lock and rq lock (`change_class`: setpriority, sched_setscheduler;
a queued task is taken off its list first and put back on its new one)
and read lock-free. Classes (Linux sched_class), highest first: stop
(`migration/N`), rt (SCHED_FIFO/RR: 99 levels, FIFO never time-sliced,
RR every 100 ms, a preempted rt task keeps the head of its level), fair
(SCHED_NORMAL/BATCH/IDLE: EEVDF, `task/fair.rs`; the tick charges the
running one under its rq lock), idle (never queued). A woken task preempts a lower class, a lower rt priority, or
a fair task EEVDF would not pick at that point (not for SCHED_BATCH/IDLE).
rt bandwidth (`task/rt.rs`, Linux rt_rq->rt_time): `CpuRunQueue.rt_bw`
holds the rt time run on that CPU in the current 1 s period, under its
rq lock (charged by the tick and when an rt task switches out). Once
it reaches 950 ms, fair tasks rank above rt ones there (pick and
wakeup preemption) while any is runnable, until the period ends (the
tick of a running fair task rolls it over and reschedules).
It has no lock of its own.
Runtime (Linux update_curr): `CpuRunQueue::update_curr` charges the
running task of every class but idle for the time since its
`se.exec_start` (set when it is made current, Linux set_next_entity)
under its rq lock, at the tick, when it switches away (put_prev_task),
on fair wakeup preemption checks, and for a reader of its runtime:
`se.sum_exec_runtime` (load and store) and, while its thread group
keeps CPU timer totals, the group's sum (`GroupCputimer`, an RMW:
every thread adds from its own CPU; Linux account_group_exec_runtime).
`sum_exec_runtime` is read lock-free (thread_group_cputime);
`task_sched_runtime` (CLOCK_*_CPUTIME_ID's SCHED clock, Linux) takes the
task's rq lock (`task_rq_lock`; TASKLIST may be held) and charges it
first if it is running.
`CpuRunQueue.min_vruntime` (under the rq lock) stands for the average
when no fair task is there.

Which lock owns each `SchedEntity` field (Linux: sched_entity and
sched_rt_entity are plain under rq->lock, the task_struct scheduling
fields READ_ONCE'd where read without it):
- `se.rq` (`SeRq`: vruntime, deadline, vlag, exec_start, the RR slice
  `rr_left`, `requeue_tail`, `contrib_load`): a `sync::LockedCell`
  owned by the lock of the run queue the task is on, the one
  `Task.cpu` names (Linux task_rq). No lockless reader: every access
  goes through that `CpuRunQueue` (`ent`/`set_ent`/`with_ent`), which
  checks `Task.cpu` names it (`owns`, `IrqSpinlock::owns`). Ownership
  moves with `Task.cpu` (rule 1): under the old rq lock (and the new
  one in the balancer) for a queued task, accessed on the old queue
  before `set_task_cpu` and on the new one after; under the pi_lock
  for a task on no run queue, which nothing holding an rq lock touches
  then (a wakeup reads `on_rq` false under the old lock only after the
  sleeper's switch released it, and waits for `on_cpu`, Acquire;
  priority changes hold the pi_lock too). The fair math (`fair.rs`)
  works on copies the run queue reads out and writes back.
- `state`, `on_rq`, `on_cpu`: atomics (wakers read `state` and spin on
  `on_cpu` with no rq lock; `task_sched_runtime` reads `on_rq` and
  `on_cpu` lock-free; Linux READ_ONCE / smp_cond_load_acquire).
- `params`, `reset_on_fork`: atomics written under the pi_lock and rq
  lock, read lock-free (getpriority, sched_getattr, /proc, fork,
  wakeup placement; Linux reads p->policy, p->prio,
  sched_reset_on_fork so).
- `sum_exec_runtime`: atomic written under the rq lock, read lock-free
  (above).
- `link`, `ctx`: the rq lock (the run list; the switch frame).

Each `PerCpu` (per-CPU data) contains:
```rust
pub interrupt_depth: AtomicU32,   // Nesting depth of interrupts
pub irq_user: AtomicBool,         // The interrupt came from user mode (3.5)
pub preempt_count: AtomicU32,     // Preemption disable count
pub fpsimd_last_state: AtomicPtr<UserFpsimdState>, // arm64: user FP state bound to the registers (rule 7)
```

Each `Task` carries `thread_flags` (Linux TIF_*): TIF_NEED_RESCHED is
set by the tick (the slice is one tick) and the reschedule IPI, from
interrupt context, atomically, on the CPU's current task; it is acted on
only at that task's return to user mode (`entry::exit_to_user_mode`).

#### Locking Rules

1. **Any CPU may lock any run queue** (Linux) - `Task.cpu` names the
   run queue a task belongs to (Linux task_cpu); it changes only in
   `set_task_cpu`, under the task's pi_lock while it is on no run queue
   (a wakeup, a new task), or under its rq lock while queued (a
   migration). `task_rq_lock` locks the run queue it names and rechecks
   it. A wakeup (`try_to_wake_up`, Linux ttwu) holds the task's pi_lock
   throughout: under its rq lock it sees whether the task is still on
   it (then only sets Running, Linux ttwu_runnable); if not, it waits
   for `se.on_cpu` to clear (its old CPU is off its stack), chooses the
   CPU (`select_task_rq`), sets it and activates the task under that
   CPU's rq lock. `resched_curr` flags the running task and sends a
   reschedule IPI when the run queue is another CPU's. The rq holds no
   task reference per CPU: the scheduler's reference (rule 8) follows
   the task. A queued task moves (`move_queued_task`, from the stopper
   of its CPU) under its pi_lock: off the old list under the old rq
   lock, `set_task_cpu`, then onto the new one under the new lock, never
   both locks at once. In between it is `on_rq` on no list, so whatever
   touches a queued task on its run queue holds its pi_lock (wakeup,
   priority and affinity changes) or found it on that list. The load
   balancer (`sched_balance_rq`, Linux; from the tick, every tick on an
   idle CPU and every 8 on a busy one, and from the idle loop before it
   halts) finds the busiest CPU by `nr_running`, takes both run queues
   with `double_rq_lock` (lowest CPU first, released in reverse: one
   `DoubleRq` guard, so interrupts come back on only once both are
   free) and moves queued tasks that
   may run here, never the running one, at most 32 per pass, with no
   pi_lock: it found them on the list, and `set_task_cpu` is under both
   rq locks.

2. **Run queue lock is IRQ-safe** - Timer interrupts cannot cause deadlocks.
   Lock order: pi_lock → rq lock; two rq locks lowest CPU first
   (`double_rq_lock`); nothing is taken under an rq lock but the arm64
   ASID leaf (no TASKLIST: the switch and the wakeup use only `Task`
   atomics). Never call a wakeup (`try_to_wake_up`, `WaitQueue::wake*`)
   while holding an rq lock (it is not recursive); `schedule_timeout`'s
   HARD timer wakes its sleeper from the tick with no rq lock held. A
   waker spinning on `on_cpu` holds only the pi_lock: the CPU it waits
   for finishes its switch with interrupts off and no pi_lock, so it is
   never the waker's own CPU.

3. **Context switch happens with lock held** - The lock is released by the
   task switched to, in `finish_task_switch` (Linux), always on the run
   queue of the CPU it runs on now: a resumed task rebinds its guard to
   that CPU's rq lock (`IrqSpinlockGuard::rebind`, keeping its own saved
   interrupt state), a new task takes it over (`assume_held`, from the
   arch trampoline via `finish_context_switch`). Before the switch the
   CPU records the outgoing task in `rq.prev` and sets the incoming
   task's `se.on_cpu`; `finish_task_switch` clears `prev.se.on_cpu`
   (Release) once off its stack (Linux p->on_cpu: a task is not run
   anywhere else while it is set).

4. **`context_switch_first()`** - An exiting task (`exit_current`) keeps
   the lock held across its final switch like any other switch (the guard
   is forgotten; the next task releases it), so nothing runs on this CPU
   between leaving the dead task and the next task taking over. The
   boot-time first switch (`try_schedule`) does the same, so the per-CPU
   preempt count stays balanced (dropping the guard there and releasing
   again in `finish_task_switch` left it at -1).

5. **Timer ISR only touches local CPU** - the tick runs the local
   CPU's timers only.

9. **The idle task is never queued** - `rq.idle` runs when the lists are
   empty. Making a task runnable flags the running task NEED_RESCHED if
   it is the idle task or of lower priority (`check_preempt`, Linux
   check_preempt_curr); the idle loop halts only after checking that
   flag with interrupts off, so a wakeup is never left waiting for the
   next tick.

6. **User registers belong to the task** - every entry from user mode
   builds the arch's `PtRegs` (Linux pt_regs: x86 entry.rs, arm64
   vectors.S with orig_x0/syscallno) at the top of the task's kernel
   stack; it is the task's only copy of its user registers while it is
   in the kernel (`current_pt_regs`, `task_pt_regs`), so a switch has
   nothing to save, and signal frames (`do_signal`, `force_sig_fault`),
   fork (`do_clone` copies it), exec (`jump_to_user` rebuilds it) and
   ptrace read and write it there with no lock: the task itself, or a
   stopped tracee under TASKLIST. A tracer first waits for the tracee's
   `se.on_cpu` to clear (`wait_task_inactive`, in ptrace_check_attach):
   its TLS and GS base are saved by its switch-out, which may still be
   finishing on another CPU.

7. **User FP/SIMD state stays in the registers while its task is in the
   kernel** - the kernel never touches them (x86-64 soft-float, arm64
   general-regs-only), so no exception entry saves them; no lock is
   involved:
   - x86-64: `context_switch` XSAVEs (or FXSAVEs) the outgoing task's
     state into an area on its kernel stack and XRSTORs it when that task
     runs again (eager); a fork child gets the parent's state just below
     its pt_regs (`SchedArch::clone_child_fpu`), loaded by
     `ret_from_fork`.
   - aarch64 (Linux fpsimd.c, lazy restore): the switch saves the
     outgoing task's registers through this CPU's binding
     `fpsimd_last_state` (its `Task.thread`) unless its
     TIF_FOREIGN_FPSTATE says they are not its own, and sets the incoming
     task's TIF_FOREIGN_FPSTATE unless the binding names its state and
     its `fpsimd_cpu` names this CPU (`fpsimd::thread_switch`, interrupts
     off under the rq lock, before `make_current`: `current` is still
     the outgoing task, as in Linux __switch_to). The
     return to user mode loads a foreign state and binds it to the CPU
     (`exit_to_user_mode_work`). Signal delivery, rt_sigreturn and fork
     first save and unbind the live registers
     (`save_and_flush_current_state`), exec zeroes the state
     (`flush_thread`); from then until the return to user mode the
     memory copy is the task's state. Each claims the CPU's FP context
     with preemption disabled (Linux get_cpu_fpsimd_context, PREEMPT_RT
     form: hk has no softirqs and no kernel-mode NEON);
     `fpsimd_last_state` is this CPU's alone, written and read under it.
     A new task's `fpsimd_cpu` names no CPU, so a reused task address
     never matches a stale `fpsimd_last_state`.

8. **Dead tasks are freed by the next task (Linux finish_task_switch)** -
   `exit_current` cannot free the kernel stack it runs on, nor the
   top-level page table still loaded in CR3/TTBR0. It leaves them as a
   `DeadTask` (stack, mm_count reference, the run queue's task
   reference) in its rq's `dead` slot (one: the next task takes it
   before anything else can exit here), under
   the rq lock held across the switch. The task switched to takes it
   under the rq lock and frees it after releasing the lock
   (`finish_task_switch`):
   frame frees and the last `Arc<Mm>` drop (top-level table, heap) never
   happen under the rq lock.

#### Sleep / Wakeup Protocol (Linux set_current_state / try_to_wake_up)

The task carries the scheduling truth (`Task.se`): `state: SleepState
{Running, Interruptible, Killable, Uninterruptible, Dead}` and `on_rq`
(queued or running).

```text
sleeper                                   waker (any CPU, any context)
-------                                   -----
register on wait queue                    make condition true
set_current_state(Interruptible)          try_to_wake_up(&task, mode):
  (store state, full barrier)               lock task.pi_lock, full barrier
if condition: done                          state matches mode? else return
if signal_pending(): -ERESTARTSYS           lock task's rq: on_rq?
schedule():                                   state = Running; return
  lock rq; state Running? return            wait until !on_cpu
  on_rq = false                             cpu = select_task_rq
  switch (finish_task_switch on the         lock that rq, activate:
    next task clears on_cpu)                  state = Running, on_rq,
                                              enqueue, resched_curr
```

A sleeper whose condition lives under a lock can wait with the guard
(`WaitQueue::wait_event_interruptible_locked(&mut guard, cond)`, Linux
wait_event_interruptible_locked, Rust-for-Linux CondVar::wait): it
checks `cond` with the lock held after queueing, and the guard's
`Relock::unlocked` lets the lock go only around `schedule()`. Order:
the guard's lock, then the queue head. The waker changes the condition
under the same lock and wakes after unlocking. No other lock may be
held: the guard's is the only one released while asleep.

The sleeper tests `state` and clears `on_rq` under its rq lock; the
waker tests `on_rq` under the same lock: either it saw the sleeper still
on it and set Running first (the sleeper stays), or the sleeper is off
it and the waker queues it, once its CPU is off its stack.

`WakeMode::Interruptible` (signals) wakes only `Interruptible` sleepers;
`WakeMode::Fatal` (SIGKILL) also wakes `Killable` ones (Linux
TASK_KILLABLE); `WakeMode::Any` (wait queues, timeouts) wakes every
sleeper. `schedule_timeout(t)`
arms a timer on the sleeper's stack; whichever of wakeup and timeout comes
first ends the sleep and the timer is deleted afterwards. Spurious wakeups are allowed:
every sleeper re-checks its condition.

**Preemption model:** kernel code is non-preemptive. Switches happen only
in `schedule()`, `yield_now()`, `exit_current()`, AP startup, and on the
way back to user mode (`entry::exit_to_user_mode`, Linux
exit_to_user_mode_loop): there, with no lock held (preempt count 0,
checked as ENTRY:FAIL) and interrupts on, a task flagged
TIF_NEED_RESCHED yields (`preempt_schedule_user`; round robin within a
priority, one-tick slices) and a pending signal is delivered, so a task
spinning in user mode is preempted and killable. Therefore a
`spin::Mutex`/`RwLock` holder is never involuntarily preempted, and the only
same-CPU hazard is an IRQ handler taking a lock the interrupted code holds
(hence the IRQ rules). Every spin lock raises `preempt_count` (6.3), so a
preemption point added later can honor it. `preempt_disable` and
`preempt_enable` (`arch/*/percpu.rs`) find this CPU's block, then do an
atomic RMW on its `preempt_count`: two steps, not Linux's single
this-CPU instruction. That is sound only because the task cannot be
switched (and so cannot migrate) between them; an IRQ in between makes
a balanced increment and decrement of the same CPU's count. Kernel
preemption would first need a this-CPU RMW (or a per-task count, as
Linux arm64's `thread_info.preempt_count`). A signal for a task running
on another CPU kicks it (`kick_process`: the reschedule IPI), so its
return to user mode delivers the signal.

**RCU hook:** `PerCpuScheduler.nr_switches` counts context switches per CPU;
since kernel code cannot be preempted, a change in a CPU's counter (or the
CPU being idle) is a quiescent state for a future QSBR RCU.

#### Kernel Threads (task/kthread.rs)

`kthread_run(name, fn, arg, cpu)` creates a pid-0 task bound to one CPU
(created asleep in that CPU's rq, then woken). The thread finds its
control block through its task: `Task.kthread`
(`spin::Mutex<Option<Arc<KThread>>>`, a leaf; Linux task->worker_private
read by to_kthread), set before the first wakeup, taken when the thread
exits, never held across a wakeup or sleep. A kernel thread (`TaskKind::KernelThread`) with no fs of its
own gets the shared knullfs fs_struct from `get_task_fs` and
`current_fs` (fs/fsstruct.rs `KTHREAD_FS`; no lock).
`kthread_should_stop/should_park/parkme` and
`kthread_stop/park/unpark` use atomics + `try_to_wake_up` + the block's
`ack` WaitQueue. A thread created without a CPU gets one round-robin;
every kernel thread stays on its CPU (`cpus_mask` holds only it, Linux
kthread_bind). Standing threads: `ktimers/N` (one per CPU, runs its SOFT
timer callbacks), `rcu_gp` (RCU grace periods, 1.4.2), `rcuc/N` (one
per CPU, its RCU callbacks, 1.4.2), the system
workqueue worker, `softnet/N` (one per CPU, network receive; see 3.10),
`kselftest` (boot only).

**Stoppers (task/stop_machine.rs, Linux stop_machine.c):**
`migration/N`, one per CPU at the highest priority, runs calls queued
with `stop_one_cpu` (thread context; the caller sleeps until done). Per
CPU: `Stopper.lock` (sleeping `sync::Mutex`, one caller at a time, held
until the call completes) → `Stopper.work` (IrqSpinlock leaf, the
slot). `stop_one_cpu_nowait` (any context) only fills an empty slot:
the soft lockup detector (`time/watchdog.rs`, Linux kernel/watchdog.c) queues
a touch from each CPU's tick every `watchdog_thresh * 2 / 5` s and
reports `BUG: soft lockup` when the last one ran over `2 *
watchdog_thresh` s ago (per-CPU atomics only). `migration_cpu_stop` takes the task's pi_lock → this CPU's rq
lock: a task still queued here moves; one asleep gets `wake_cpu` (Linux
p->wake_cpu, under the pi_lock), where its next wakeup starts.
`set_cpus_allowed_ptr` (sched_setaffinity; Linux affine_move_task)
writes `cpus_mask` under pi_lock + rq lock and, if the task runs or is
queued on a CPU now excluded, calls that CPU's stopper with no lock held;
`sched_exec` (do_execve) moves the caller to the least loaded CPU the
same way. Kernel threads are PF_NO_SETAFFINITY (sched_setaffinity:
EINVAL).

Every online AP gets an idle task (`init_ap_schedulers`) and enters the
scheduler from its boot idle loop. User tasks run on every CPU:
`select_task_rq` places a new task on the allowed CPU with the fewest
tasks (`find_idlest_cpu`, Linux sched_balance_find_dst_cpu) and a
waking one on its previous CPU if idle, else an idle allowed CPU, else
its previous one (`select_idle_sibling`); all CPUs form one domain (no
topology yet). `PerCpuScheduler.nr_running` (queued or running, idle
aside; changed under the rq lock, read locklessly for placement) is
Linux rq->nr_running. `nr_uninterruptible` (Linux, per CPU, only the
sum counts) goes up under the rq lock when a task sleeps uninterruptibly
or killably (`se.contrib_load` set) and down on the run queue that wakes
it; CPU 0's tick folds both into the load averages every 5 s
(`task/loadavg.rs`, atomics only; /proc/loadavg, sysinfo). On x86-64 each CPU has its own TSS (RSP0) and
syscall entry stack top, set at each switch to a user task.

### 3.1.1 Task Struct and Credentials

**Location:** `task/mod.rs`, `task/tasklist.rs`, `task/cred.rs`

A global `TASKLIST: RwLock<GlobalTaskTable>` (Linux tasklist_lock: read
for lookups and walks, write for any change) protects the task list and
the relations, ptrace, exit and other `TaskInner` fields. Per task, as in
Linux: `Task.alloc_lock` (Linux task_lock) guards the resource pointers
(mm, files, fs, nsproxy, comm, mempolicy, io_context), `Task.pi_lock`
serializes wakers (3.1), the siglock of its handler table owns its signal state
(`Task.sig`, 3.7).

#### Data Structures

| Variable | Type | Purpose |
|----------|------|---------|
| `TASKLIST` | `RwLock<GlobalTaskTable>` | Every task: the intrusive `RcuList` `TASKS` (Linux init_task.tasks) holding a `TaskRef` (`Arc<Task>`) each, changed only under the write lock (list_add_tail_rcu, list_del_rcu: the reference goes a grace period after the unlink, `RcuUnlinked::defer`), walked under TASKLIST (`GlobalTaskTable::iter`) or an RCU read guard (`tasklist::for_each_task_rcu`, Linux for_each_process_thread under rcu_read_lock: PRIO_USER's set/getpriority, whose per-task work takes only spin locks); found by tid through the pid hash (`Pid.task`, an `RcuPtr` set and cleared under the write lock, read under it or an RCU read guard) |
| Per-CPU `curr` | `*const Task` in PerCpu | The running task (no lock) |
| `Task.cred` | `Arc<Cred>` (raw, `TaskCred`) | Credentials (Linux real_cred/cred, `__rcu`): replaced only by the task, published with Release, the old reference dropped a grace period later (`put_rcu`); read by the task lock-free, by others under an RCU read guard (Credential Handling) |
| `Task.cred_override` | `Arc<Cred>` (raw) or null | Override credentials, the task's own (no lock) |
| `Task.real_parent` | `RcuPtr<Task>` | The real parent, no reference: written under TASKLIST's write lock, read under it or an RCU read guard (Relations) |
| `Task.ptrace` | `AtomicU32` | Ptrace flags (Linux task->ptrace): written under TASKLIST's write lock (a `TaskViewMut`: attach, seize, resume, unlink, CLONE_PTRACE), read with a Relaxed load anywhere (Linux's racy reads under siglock: sig_ignored, the stop prepare's PT_SEIZED, a group kill); a decision that must hold reads it under TASKLIST (ptrace_stop, wait, the tracer's checks) |
| `Task.ptracer` | `RcuPtr<Task>` | The tracer while traced, no reference: written under TASKLIST's write lock, read under it or an RCU read guard (Relations) |
| `SignalStruct.pgrp`, `SignalStruct.session` | `RcuLockedArc<Pid, GlobalTaskTable>` | A process's group and session links (Linux signal->pids[PIDTYPE_PGID, PIDTYPE_SID]), one per process: written under TASKLIST's write lock (old reference `put_rcu`), read under it or an RCU read guard (reached through `Task::cpu_group`, set once and never cleared) |
| `Task.thread_pid` | `RcuLockedArc<Pid, GlobalTaskTable>` | Its struct pid (Linux task->thread_pid): set before the task is listed, exchanged by de_thread (`take_leadership`, Linux exchange_tids) and cleared at release (`unhash`, Linux detach_pid PIDTYPE_PID; de_thread's removed threads after their numbers are released) under TASKLIST's write lock, the replaced reference dropped a grace period later; read under TASKLIST or an RCU read guard (`Task::pid_nr_ns`, Linux task_pid_nr_ns: 0 once released). A release pins it for proc_flush_pid (Linux release_task's get_pid) |

**Pids** (`task/pid.rs`, Linux 4.14 pidmap): a `Pid` holds one
number per pid-namespace level. Numbers come from a lock-free bitmap
per namespace (pages allocated outside any lock, installed by
compare-and-swap; bits set and cleared atomically). `PIDMAP_LOCK`
(spin leaf, thread context only, nothing allocates under it)
serializes changes to the global hash chains of every live `Pid`'s
numbers (Linux pidmap_lock): `alloc_pid` links them (each `UPid`
published whole, Release), and they are unlinked and given back when
the last task leaves the `Pid` (`release_numbers` from
`GlobalTaskTable::remove`, `change_pids` and `take_leadership`, under
TASKLIST's write lock: Linux free_pid from detach_pid), or, for one
whose task never joined the list, by the fork or kernel-thread
creation that fails (`pid::NewPid`, Linux bad_fork_free_pid); from
`alloc_pid` until then the `Pid` holds an active reference to the
namespace it was made in (3.4, atomics, put after PIDMAP_LOCK is
released). Readers walk the chains under an RCU read guard with no
lock (`pid::find_pid_ns`, Linux find_pid_ns under rcu_read_lock): the
hash holds one reference to a hashed `Pid` (`Pid.hash_ref`, Linux
alloc_pid's count), dropped through `put_rcu` by `release_numbers`
(Linux delayed_put_pid), and an unlinked `UPid` keeps its `next`
(hlist_del_rcu), so a `Pid` found there, and every `UPid` of it, stays
allocated until the guard drops; `find_pid` (Linux find_get_pid) and
`get_pid` take a reference. PIDMAP_LOCK is taken under nothing but
may be taken under TASKLIST and, being a leaf, under any
thread-context lock where a `release_numbers` may run; the last
`Arc<Pid>` reference (an AF_UNIX queue's SCM credentials and
SO_PEERCRED, a tty's group, an F_SETOWN owner, a procfs inode, the
hash's in `rcuc/N`) only frees memory and puts its namespace.
A `Pid`'s task link (`Pid.task`, Linux pid->tasks[PIDTYPE_PID]) is an
`RcuPtr<Task>` holding no reference: set under TASKLIST's write lock
only to a task that is listed or joins the list in that section
(`insert`), cleared in the section that unlists it, before the list's
reference goes through `kfree_rcu` (`unhash`), so a task read through
it under an RCU read guard (`Pid::task`, Linux pid_task) stays
allocated until the guard drops (task lifetime, below), and one read
under TASKLIST (`Pid::task_locked`) is listed for the hold.
A process's pid is its leader's tid; an exec from a non-leader takes
the leader's tid and `Pid` (`take_leadership`, Linux exchange_tids)
under TASKLIST (the run queue knows tasks by reference, not by
number), the two tasks' links and `Task.thread_pid`s exchanged in one
section while both are listed and before the old leader is unlisted,
so the leader's `Pid` names one of them at every moment (Linux
hlist_replace_rcu). The idle tasks
are tid 0 and, like the boot task, not in TASKLIST.

**Pid namespaces** (Linux task_active_pid_ns, pid_nr_ns, pid_vnr,
find_vpid): a task's namespace is `Task.pid_ns`, fixed at creation (a
thread is made in its group's: CLONE_THREAD into another namespace is
EINVAL), so the current task reads its own lock-free
(`pid::current_pid_ns`), and a `Pid`'s numbers are immutable
(`Pid::nr_ns`, `vnr`: no lock). Inside the kernel tasks, groups and
sessions are named by root numbers or `Arc<Pid>`; numbers are
translated only at the user boundary: out, a root number to a
namespace's (`pid::nr_ns`, `vnr`: 0 if not visible) through the hash
(under RCU), its owner kept listed by the caller meanwhile (the
caller's own ids, or TASKLIST held for reading), or a `Pid` read
under RCU numbered in place (`Pid::nr_ns`: a parent's group, a group,
a session); in, a
caller's number to its `Pid` or root number (`pid::find_vpid`,
`from_vnr`, `find_pgrp(ns, nr)`: ESRCH if not visible) through the
hash before TASKLIST is taken, or to its task with no TASKLIST, under
one RCU read guard (Linux rcu_read_lock; find_task_by_vpid /
pid_task): `tasklist::vpid_task`, `pid_ns_task` borrow it for the
guard, `find_task_by_vpid`, `find_task_by_pid_ns`, `find_task` and,
from a held `Pid`, `get_pid_task` take a reference (get_task_struct,
`task_ref`: the list's reference keeps its count). Every pid argument
is looked up so.

**Task lookup by pid** (Linux find_task_by_vpid, get_pid_task under
rcu_read_lock, no tasklist_lock): getpgid and getsid with a pid read
the task's group or session in the same guard (`vpid_pgrp_vnr`);
kcmp, ptrace's tracee, prlimit, the sched_* / setpriority /
ioprio targets, process_vm_*, migrate_pages, a cgroup.procs write,
nsfs's pid lookups, pidfd_open's checks (Linux pidfd_prepare:
pid_has_task PIDTYPE_PID, then the task leading its group),
`pidfd_task`, setns by pidfd, every /proc/<pid> access (`ProcPid::task`,
Linux get_pid_task; `alive`, Linux pid_alive), the CPU clocks
(clock_gettime and timer_create on a thread or process clock, a
thread timer's settime and sample, Linux posix_cpu_clock_get,
cpu_timer_task_rcu) and a timer's SIGEV_THREAD_ID check
(good_sigevent) find the task so, F_SETOWN takes any hashed pid
(f_setown: find_vpid) and F_GETOWN tests a thread, process or group
owner's task the same way (a group's: `Pid::pgrp_task`, Linux
pid_task(pid, PIDTYPE_PGID)). A permission check reads the target's credentials
in the same guard or after it (`Task::cred_rcu`, Linux __task_cred):
tkill and tgkill find and check their thread under RCU (Linux
do_send_specific), as do prlimit and the sched_* / setpriority /
ioprio targets. kill(pid), rt_sigqueueinfo and pidfd_send_signal find
and check their task under RCU too (Linux kill_pid_info_type), and
every send, a POSIX or itimer timer's included, reaches the receiver's
handlers through `lock_task_sighand` (3.7), no TASKLIST; Linux takes
tasklist_lock only where it walks a group or a parent link
(__kill_pgrp_info, kill(-1), send_sigio to a group, a child's notice,
setpgid, ptrace attach and checks, wait, the PRIO_PGRP /
IOPRIO_WHO_PGRP walks), as hk does.

**A pid namespace's init** (`task/pidns.rs`; Linux child_reaper,
pid_allocated, find_child_reaper, zap_pid_ns_processes): no new lock.
`PidNamespace.alloc` (atomic, changed under PIDMAP_LOCK: thread
context, a leaf) counts the pids numbered there with two flags,
NS_ADDING (pids may be made; cleared when its init dies) and NS_INIT
(its init has joined the task list, set in that TASKLIST write
section; until then only 1 may be made: EINVAL).
`alloc_pid` admits a new `Pid` under PIDMAP_LOCK before it is built
(ENOMEM once NS_ADDING is clear) and `release_numbers` uncounts it; a
dying namespace down to its init's pids wakes its reaper after
PIDMAP_LOCK is dropped (`Pid::wake_reapers`, Linux free_pid:
wake_up_process(child_reaper)), under the TASKLIST hold of the release
(`release_unused`) or, for a pid never attached (`NewPid`, a failed
`alloc_pid_nr`), taking TASKLIST's read lock for it.
`PidNamespace.reaper` (a `Weak<Task>`, Linux child_reaper) and
`reboot` (Linux pid_ns->reboot: set by reboot(2) inside before it
SIGKILLs the reaper, read by the zap) are TASKLIST's (`TableCell`):
fork sets the reaper in the write section that lists a new process numbered 1, after checking
under that lock that every level still takes pids (Linux
copy_process: a fork racing the zap fails ENOMEM or is seen by it).
An exiting task that is its namespace's reaper hands it to another
live thread of its group in one write section; with none left
(`find_child_reaper`) it disables allocation, collects the
namespace's other live tasks under TASKLIST's read lock (room made
before it), SIGKILLs them with no lock held, then sleeps on its
group's `wait_chldexit` (uninterruptible, no lock held) reaping its children
until it has none and only its group's pids are left, all before its
own children are handed on and it becomes a zombie, so its parent
sees it exit only once the namespace is empty.

**Relations** (under TASKLIST's write lock to change, read lock to
walk): `real_parent` and `ptracer` are task pointers, never numbers,
so a recycled tid cannot inherit a parent or tracer link. `ptracer`
(`Task.ptracer`, an `RcuPtr`, Linux task->parent while ptraced) holds
no reference: it is set, under the write lock, only while the tracee
is listed (or joins the list in that section) and only to a listed
tracer not on its way out (PTRACE_ATTACH and PTRACE_SEIZE by the
caller; PTRACE_TRACEME to the real parent, refused once the parent
has PF_EXITING, Linux ptrace_traceme; CLONE_PTRACE copies the
creator's link in the write section that lists the child, Linux
ptrace_init_task), and cleared by `ptrace_unlink`, which an exiting
tracer runs for every tracee (exit_ptrace, after PF_EXITING, before
it leaves the list), so a listed task's tracer is listed. Read under
TASKLIST (`Task::tracer_locked`, the views' `tracer`/`traced_by`) or
under an RCU read guard (`Task::tracer`, Linux pid_alive(p) ?
ptrace_parent(p): /proc status TracerPid, numbered through the
tracer's thread pid, `Task::pid_nr_ns`); ptrace_signal's SI_USER
info reads it, the tracer's thread number and uid under one RCU
read guard (Linux ptrace_signal). `real_parent` (`Task.real_parent`, an
`RcuPtr`, Linux real_parent) holds no reference: it is set, under the
write lock, only to a listed task (fork, `adopt`, exec's leader
change keeps the old leader's), and a task's children are handed on
before it leaves the list (`forget_original_parent`), so a listed
task's parent is listed; one left at `remove` is a bug, reported once
as `TASK:FAIL` (Linux has no such step), and made to name no parent
(`orphan_children`) so the rule still holds. Read under TASKLIST (`Task::parent_locked`, the views'
`real_parent`/`ppid`: no count) or under an RCU read guard
(`Task::parent`, Linux pid_alive(p) ? rcu_dereference(p->real_parent)):
a task seen listed within the guard has a parent listed at some point
of it, which therefore leaves memory only after the guard (task
lifetime, below). A group leader is on its real parent's `children` (intrusive `ArcList`,
link `Task.sibling`, one strong reference each; Linux only lists
leaders); `link_child` at fork and exec's leader change, unlinked at
reap. Every thread of a process has the same `real_parent` (a
CLONE_THREAD child copies its creator's; `adopt` moves them all, Linux
forget_original_parent's for_each_thread), and a parent's pid is read
only through it: under RCU with no lock by getppid and /proc stat
(`current_ppid_vnr`; `Task::tgid_nr_ns`, Linux task_tgid_nr_ns: the
parent's `SignalStruct.leader_pid` read under the same guard, 0 once
its group is released, numbered in the reader's namespace), under
TASKLIST by the
wait scans (`has_children`, `wait_jobctl`, `reapable`: the parent's
fixed `pid` compared, through the pointer), acct and setpgid. An
exiting task first detaches its tracees (exit_ptrace), then hands its
children to another live thread
of its group, else a live thread of the nearest ancestor process in
its pid namespace that is a child subreaper
(`SignalStruct.subreaper`), else its namespace's reaper
(`forget_original_parent`, `adopt`); an exited non-leader thread
leaves the task list at once (Linux release_task), unless traced:
then when its tracer reaps it or exits (Linux wait_task_zombie,
exit_ptrace).
A group's `SignalStruct.threads` (intrusive `OwnedList`, link
`Task.thread_node` marked in `Task.thread_owner`, so a thread is
removed or stepped from safely; the leader included; Linux
signal->thread_head) lists its threads (3.7): joined in the section
that gives a task its group, left at release; de_thread leaves the
exec'ing thread on it as its zombies are released. A process is found
by its pid as its leader's tid (`get(pid)`); its threads through
`threads(pid)` (TASKLIST held; a task with no group is its own only
thread).

**Process groups and sessions** (Linux pid->tasks[PIDTYPE_PGID,
PIDTYPE_SID]): each `Pid` has a `pgrp` and a `session` list
(`RcuHListBare` chains owned by TASKLIST, links
`Task.pgrp_link`/`session_link`), changed under TASKLIST's write lock
(added at the head, Linux hlist_add_head_rcu) and walked under its
read lock (through `GlobalTaskTable::pgrp`/`pgrp_threads`) or, for
the first leader only, under an RCU read guard (`Pid::pgrp_task`,
Linux pid_task(PIDTYPE_PGID): F_GETOWN). A list holds no reference
(Linux's bare pid_links): a leader is linked only while it is in the
task list, unlinked by `detach_pids` in `unhash` before it leaves
that list, whose reference goes a grace period later (`kfree_rcu`),
so a reader on a removed leader stands on allocated memory (the
`add_head` contract, as `Pid.task`'s `RcuPtr`). Only group leaders are on
them (`TaskInner.pids_linked`), like Linux: linked when inserted
(fork), by the new leader at exec's `take_leadership`, and after a
change; unlinked at `remove` (release or reap; a zombie leader stays,
as in Linux). Each process holds one reference to its group's and
session's `Pid` (`SignalStruct.pgrp`/`session`, `RcuLockedArc`s owned
by TASKLIST, Linux signal->pids), so a `Pid` outlives its group even
after its own task is gone. They are the only record (Linux has no
copies): a task's group and session are read through them, under an
RCU read guard with no lock for the caller's own (`current_pgid`,
`current_sid`, their `_vnr` forms: getpgid(0), getsid(0), kill's
`Sender::current`, the wait scans' own group, the tty
session-leader check, ioprio/priority PGRP; Linux task_pgrp(current) under
rcu_read_lock) and /proc stat, or under TASKLIST
(`RcuLockedArc::protected`, the views' `pgrp`/`session`/`pgid`/`sid`:
kill(0) walks the group it reads, `kill_own_pgrp`; setpgid checks the
caller's session in its write section). A replaced reference is
dropped a grace period later (`RcuRetired::defer_put`: `put_rcu` on
the `Pid`'s `RcuPuts`, Linux free_pid -> delayed_put_pid), so a reader
on it keeps it; the `Pid` drop then runs in `rcuc/N` (PIDMAP_LOCK
taken there, a leaf). A released leader's links (and its group's
`leader_pid`) are cleared so (`detach_group_pids`, Linux
__unhash_process with group_dead), after its numbers are given back.
setpgid and setsid replace the process's pair in one write section
(`change_pids`: nothing is allocated); a new process copies its
creator's under the same write lock that lists it
(`install_fork_signal` -> `inherit_pids`, then `attach_pids`). The
old group and session `Pid` are handed back too and dropped after
TASKLIST (Linux ksys_setsid's pids[] and free_pids; the link's own old
reference goes through `put_rcu` in the section); a group's `Pid` is looked up by number
(`find_pgrp`, under RCU) before TASKLIST is taken. Group 0, where
init starts, is `INIT_STRUCT_PID` (Linux init_struct_pid, never
hashed). kill(-pgrp), kill(0), tty ISIG, F_SETOWN and PRIO_PGRP /
IOPRIO_WHO_PGRP walk a group's list, never the whole task list; the
signal senders (`kill_pgrp_info`, `send_sigio`) walk it under one
TASKLIST read hold and send to each process in place (Linux
__kill_pgrp_info, send_sigio under tasklist_lock), allocating nothing
but each signal's queue entry.

A `Task` has six kinds of fields: fixed at creation (`tid`, `pid`,
`pid_ns`, `kind`, `kstack_top`); hot atomics written by the task itself (or its
creator before it first runs) or under TASKLIST, and read lock-free
by anyone (`flags` = Linux PF_*, `thread_flags` = TIF_*, `cpu`,
`start_time`, `seccomp_mode`, `tls`, utime/stime
and the other counters; utime/stime are tick samples, added (a load
and a store) only by the tick of the CPU running the task, interrupts
off (3.5); `prev_cputime`, in the
task and in its SignalStruct, is an IrqSpinlock leaf (Linux
prev_cputime.lock) held only by `cputime_adjust` (times, getrusage,
wait's rusage, /proc/<pid>/stat), under TASKLIST or not); `cred` (below); the
alloc_lock fields; the RCU-read relations (`real_parent`, `ptracer`,
`pgrp`, `session`: written under TASKLIST's write lock, read under it or an
RCU read guard, above); and
the rest, `TaskInner`, in a `TableCell` (`sync::LockedBy` owned by
`GlobalTaskTable`): a borrow of the locked table is the key, `&table`
reads it and `&mut table` writes it, checked by the compiler (the
table is a `UniqueOwner`: TASKLIST holds the only one). The `Pid`
process-group and session lists are owned the same way. A `TaskRef` cloned out of the table keeps the task alive but
reads only its fixed and atomic fields without the lock. A helper
given a task (`&Task`: the signal, seccomp, rlimit, ptrace, sched,
SysV undo, robust-list and child-tid helpers) reads
or writes its `TaskInner` through `GlobalTaskTable::view` /
`view_mut`, which return None once the task is off the list (reaped:
its `tasks_link`, changed only under the write lock, is unlinked); a
tid is looked up only at the syscall boundary.

**Task lifetime** (Linux rcu_users, put_task_struct_rcu_user,
delayed_put_task_struct): the task list's reference (`tasks`, one per
listed task) is dropped through `kfree_rcu` in the write section that
unlists the task (`remove`; the embedded `Task.rcu` head, queued once:
a task is unlisted once), so a task leaves memory no sooner than a
grace period after it leaves the list, and an RCU reader that reached
it with no reference (a `Pid`'s task link, a parent link) may read it
meanwhile or take a reference (`task_ref`, Linux get_task_struct). That
reference is usually the last, so the task's drop (its `TaskInner`:
signal and sighand references, `Pid`s; its credentials, cgroup and
keyring references, its namespace) runs in `rcuc/N` with preemption
off, and must not sleep (UNSAFE.md rule 12): exit has already taken
everything that may (mm, files, fs, nsproxy, I/O context, cgroup
membership, timers; `exit_current`), and what is left frees memory or
takes only spin leaves (PIDMAP_LOCK, `UCOUNTS`, the key registry,
`DELAYED_FPUT` through `fput`).

**alloc_lock fields** (Linux task_lock(p), `p->alloc_lock`): `mm`,
`files`, `fs`, `nsproxy`, `comm`, `mempolicy`, `io_context`.
`Task.alloc_lock` is a spin Mutex (thread context only, not IRQ-safe,
one lockdep class for every task; never two tasks' at once). Owner
rule (`OwnCell`): only the task itself changes them (or its creator
before it first runs: fork attaches the child's fs, files, nsproxy
and I/O context after inserting it), always under its alloc_lock; the
task reads its own lock-free (`current().mm()`, `files()`, `fs()`,
`nsproxy()`, `comm()`; Linux current->mm etc.; fork's `fork_fs`,
`fork_task_fd` and `fork_nsproxy` read the parent's, which is current,
this way, as Linux copy_fs, copy_files and copy_namespaces read
current->fs etc.); others read them under the lock
(`Task::task_lock()` on a `TaskRef` the caller holds: a pid lookup
takes TASKLIST only to find the task; procfs, kcmp, acct, ptrace
access checks, and the `&Task` helpers `get_task_mm`, `get_task_fd`,
`get_task_fs`, `get_task_ns`, `get_task_io_context`).
`io_context` is the exception: ioprio_set installs one in another
task, so it is read under the lock only, by its own task too (fork's
`fork_io`). Exec swaps the mm and comm in
one alloc_lock section (under `exec_update` and TASKLIST, which it
holds for the page table), so a reader sees the old name with the old
mm or the new with the new (Linux exec_mmap, __set_task_comm). Order:
TASKLIST (and PIDMAP_LOCK) before alloc_lock, alloc_lock before
siglock; nothing else is taken under it (no TASKLIST, no `Files`,
no sleeping lock). `cred` keeps its own scheme (Linux RCU): lock-free
for the task, an RCU read guard for others.

#### Locking Rules

1. **TASKLIST is NOT IRQ-safe** - Never acquire from interrupt handlers
2. **IrqSpinlock → TASKLIST is safe** - IRQs disabled prevents ISR from running
3. **The tick reads no TASKLIST** - wakeups and timers use `Task` fields only
4. **Nothing is released under TASKLIST or an alloc_lock** - a task's
   shared resources (`files`, `fs`, `nsproxy`, `io_context`, `mm`
   under alloc_lock; `sighand`, `seccomp_filter`, a reaped
   `Task` under TASKLIST) are `take()`n or `replace()`d under the lock
   and dropped after it: their last reference can close sockets (TCP
   release may sleep in SO_LINGER: sleeping under a spin lock) or tear
   down a network namespace (RTNL, a sleeping lock). A reaped task's list
   reference and a replaced group or session `Pid` reference are
   queued under the lock (`kfree_rcu`, `put_rcu`: no release there)
   and dropped in `rcuc/N` a grace period later (task lifetime).
5. **PF_EXITING** - `exit_current` sets `pf::EXITING` in `Task.flags`
   before releasing anything; release paths read
   it lock-free via `current_exiting()` (TCP close skips its SO_LINGER
   wait, Linux inet_release).

#### Credential Handling (Linux Pattern)

Following Linux's `kernel/cred.c` pattern (see `include/linux/cred.h`):

1. **Reference-counted** - `Task.cred` holds an `Arc<Cred>` (as a raw
   pointer; the boot task points at a static root `Cred`)
2. **Copy-on-write** - modifications use prepare/commit
3. **Owner rule, RCU** - only the task itself replaces its
   credentials (`commit_creds`, or its creator before it first runs),
   under no lock: the new set is published with Release (Linux
   rcu_assign_pointer) and the old reference handed to `put_rcu` on
   the `Cred`'s `RcuPuts` (`Cred.rcu`; Linux put_cred_rcu: a set
   shared by threads may be retired by several within one grace
   period), dropped in `rcuc/N` (only memory and the `UCOUNTS` leaf).
   The task reads its own lock-free (`current().cred()`, Linux
   current_cred); others read them under an RCU read guard
   (`Task::cred_rcu`, Linux __task_cred; `Task::cred`, `cred_arc` and
   `ucounts` copy or count them under one: get_task_cred), whether
   they hold TASKLIST or not
4. **Override** - `Task.cred_override` (Linux task->cred apart from
   real_cred) is touched by the task alone, no lock: `override_creds`
   installs an `Arc<Cred>` its own checks use (`current().cred()`)
   until the guard drops (revert_creds); others keep reading
   `Task.cred`. io-wq workers run each request under the submitter's
   credentials of its submission this way
5. **Per-user counts** - `Cred.ucounts` (Linux cred->ucounts) is a
   counted reference to its real uid's `Ucounts` (task/ucount.rs, Linux
   kernel/ucount.c): the RLIMIT_NPROC, RLIMIT_MSGQUEUE, RLIMIT_SIGPENDING
   and io_uring locked-memory counters, atomics charged and returned with no lock.
   A uid change points the new credentials at the new uid's before
   they are committed (`set_cred_ucounts`, EAGAIN without memory), and
   commit_creds moves the task's RLIMIT_NPROC charge (Linux: increment
   the new before the switch, decrement the old after). A queued
   signal (`SigQueue`, Linux sigqueue->ucounts), a POSIX message queue
   (info->ucounts) and an io_uring ring
   and its registered buffers (Linux ctx->user) hold their own
   reference, taken from the receiver's or creator's credentials (a
   task's under RCU or by itself, `task_ucounts`). Root's is the
   static `INIT_UCOUNTS` (Linux init_ucounts). `UCOUNTS` (IrqSpinlock
   leaf, Linux ucounts_lock: a last reference may go in any context)
   is the table by uid of weak references: `alloc_ucounts` looks up,
   and on a miss allocates the entry and its rbtree node with the lock
   released, then looks again before inserting (a racer's entry wins);
   the last reference's drop unlinks its node (unless a lookup that
   found it dying already replaced it) and frees it after the unlock.
   Nothing allocates under it.

**Credential APIs (like Linux):**
- `prepare_creds()` - Clone current credentials, return mutable copy
- `commit_creds(new)` - publish `Task.cred` under no lock (clearing
  the dumpable bit on the mm and, under TASKLIST's write lock, the
  `pdeath_signal` first when the ids change); the old `Arc<Cred>` goes
  through `put_rcu`
- `copy_creds(flags, parent)` - For fork/clone: share Arc (CLONE_THREAD) or deep copy

#### Exec vs. Credential Checks (Linux cred_guard_mutex, exec_update_lock)

Two per-thread-group sleeping locks in `SignalStruct`, thread context
only, never IRQ-reachable, outermost (nothing is held when either is
taken, except `cred_guard` around `exec_update`):

- `cred_guard` (`sync::Mutex<()>`, via `signal::CredGuard`): exec
  (`do_execve`) holds it from its first credential check (RLIMIT_NPROC)
  through loading the image (path walk, file reads, the new mm's
  mmap_lock, the fd table, TASKLIST) until the new image is in
  place; an error return drops it with nothing changed. PTRACE_ATTACH /
  PTRACE_SEIZE hold the target's around the access decision and the
  attach; seccomp TSYNC holds the caller's group's around syncing the
  other threads' filters (TASKLIST written inside). These take it
  interruptibly (Linux mutex_lock_interruptible,
  ERESTARTNOINTR): a sibling waiting for it while the holder's exec
  waits in de_thread for that sibling to die is woken by the SIGKILL.
- `exec_update` (`sync::RwSem`): `exec_replace_image` holds it for
  writing, inside `cred_guard`, while it installs the new mm, name and
  dumpability under TASKLIST and the task's alloc_lock; process_vm_readv/writev (`access_mm`),
  the /proc mm_access paths (maps, environ; the stat fields gated by
  access), migrate_pages and move_pages (`mempolicy::mm_target`, Linux
  find_mm_struct), pidfd_getfd and kcmp hold it for reading
  (`signal::ExecUpdateRead`) around the access decision and what it
  guards. kcmp holds two (Linux kcmp_lock): the lower thread-group id's
  first, one if both tasks share a group.

Dumpability is an atomic in the `Mm` (Linux mm->flags MMF_DUMPABLE),
shared by every task of the address space: read lock-free (under
the task's alloc_lock where its mm is looked up), written by
PR_SET_DUMPABLE, a credential change (`commit_creds`) and exec (on
the new mm before it is installed). So no check sees the old
dumpability with the new mm or the reverse (a
non-dumpable process that execs a readable binary is not attachable or
readable while its old memory is still mapped). As in Linux the split
lets exec walk paths while holding `cred_guard`: /proc/<pid>/exe
(followed when busybox re-execs itself) goes through mm_access, so it
takes `exec_update` for reading but not `cred_guard`; the exec takes
`exec_update` for writing only later, in `exec_replace_image`. Order:
`cred_guard` -> `exec_update` -> every other lock.

#### Deferred State Updates

Wakeups do not update `Task.state: Sleeping → Ready` because:
- Run queue membership is the source of truth for runnability
- Updating would require TASKLIST lock (unsafe in ISR)
- `TaskState` is only checked for zombie detection in `waitpid()`

#### Per-CPU Current Task Access (Lock-Free)

Each CPU's per-CPU data (GS base on x86-64, swapped in by `swapgs` on
every entry from user mode; TPIDR_EL1 on aarch64) holds
`curr`, a pointer to the running `Task` (Linux `current`), set by the
scheduler at every switch with the run-queue lock held. The run queue
holds a reference to the task (then `DeadTask` until the next task
frees it), so the pointer stays valid while the task runs.
`task::percpu::current()` returns a `!Send` `Cur` handle; 0 means the
boot task `INIT_TASK` (Linux init_task: tid 0, root, never in
TASKLIST), so current is never missing. Read lock-free through it:
`tid`, `pid`, the hot atomics (`seccomp_mode`,
`flags`, `thread_flags`, accounting, `tls`), `cred` (others read it
under RCU) and the alloc_lock fields but `io_context` (Linux
current->mm/files/fs/nsproxy/comm: only the task itself changes them,
or its creator before it first runs, under its alloc_lock; other tasks
read them under it). The current task's users call `current().mm()`,
`files()`, `fs()` (`percpu::current_fs`), `nsproxy()` (fget, path
walks, the page-fault lookup, mm syscalls, `current_*_ns`), and
`signal_pending` reads `current().sigpending()`; the
`&Task` helpers (`get_task_mm`, `get_task_fd`, `get_task_fs`,
`get_task_ns`) take the task's alloc_lock.

The context switch takes no TASKLIST: `make_current` reads the next
task's kernel stack, address space and TLS from the task (it is not
running, so its owner fields are stable); /proc reads the run state
from `Task.se`.

### 3.1.2 Comparison with Linux task_struct Locking

| Linux Lock | Purpose | hk Equivalent |
|------------|---------|---------------|
| `alloc_lock` (task_lock) | mm, files, fs, nsproxy, comm, mempolicy, io_context | `Task.alloc_lock` (spin Mutex, per task) |
| `pi_lock` | Wakeups, state | `Task.pi_lock` (IrqSpinlock, per task; 3.1) |
| `sighand->siglock` | Signal state, handlers | `SigHand.siglock` with the per-task state it owns (`Task.sig`), `SignalStruct.jobctl` (group stop state) and `SignalStruct.shared` (owned too), `SignalStruct.ignored_timers`, the action table (the siglock's own data; 3.7) |
| `tasklist_lock` | Task list, parent/child, ptrace links | `TASKLIST` (global spin RwLock) |
| RCU (`real_parent`, `parent` (ptrace_parent), `signal->pids[]`, pid hash, `pid->tasks[PIDTYPE_PID]`, `pid->tasks[PIDTYPE_PGID/SID]`, the task list, task and pid lifetime) | Lockless parent, tracer, group and session reads; task lookup by pid | `Task.real_parent`, `Task.ptracer` (`RcuPtr`), `SignalStruct.pgrp`/`session` (`RcuLockedArc`), the pid hash chains (`find_pid_ns`), `Pid.task` (`RcuPtr`), `Pid.pgrp`/`session` (`RcuHListBare`), the list's task reference through `kfree_rcu`, a dropped `Pid` link and the hash's reference through `put_rcu` |
| RCU (`cred`, put_cred_rcu) | Credentials | `Task.cred` (`TaskCred`): lock-free for the task, an RCU read guard for others, the old set through `put_rcu` |

Remaining differences: the `task_struct` fields Linux leaves to the
task itself or to siglock (scheduling policy, prctl state, robust
list, seccomp filter) are `TaskInner` fields under TASKLIST.

### 3.1.3 Task State Invariants

The `TaskState` enum in `TASKLIST` is informational (and records
`Zombie(wait_status)`), not the scheduling source of truth:

**ptrace stops** (`task/ptrace.rs`, Linux ptrace_stop; JOBCTL_TRACED,
JOBCTL_PTRACE_FROZEN, exit_code and last_siginfo under siglock): a
stop is `TaskSignalState.jobctl` (`jobctl::TRACED`, `PTRACE_FROZEN`),
`ptrace_code` and `last_siginfo`, all under the tracee's siglock.
The tracee checks it is traced under TASKLIST's read lock (`ptrace`
is written under the write lock, so a detach cannot slip between) and
sets the stop under its siglock inside it, drops the siglock, wakes
its tracer's `wait_chldexit` and signals its tracer still inside that read hold
(Linux ptrace_stop: do_notify_parent_cldstop under tasklist_lock, so
a tracer that detached first gets no CLD_TRAPPED), drops TASKLIST,
then sleeps `Killable` until
the stop has ended (under siglock, rechecked after each wakeup) or
SIGKILL. PTRACE_ATTACH sends its SIGSTOP in the TASKLIST write
section that links the tracer (Linux ptrace_attach under
tasklist_lock). The tracer's wait walks its tracees under the read lock and
takes a stop's code under that tracee's siglock (Linux
wait_task_stopped); resume, detach and the tracer's exit
(`exit_ptrace`) end the stop and `try_to_wake_up` the tracee under it
(`ptrace_wake`, `ptrace_unlink`; Linux ptrace_resume and
__ptrace_unlink's ptrace_signal_wake_up under siglock), a resume and
a detach setting the code to deliver there, the tracer's exit leaving
it (a stop it never waited for delivers its signal); detach and the
tracer's exit do so in the TASKLIST write section that untraces it
(Linux __ptrace_detach under tasklist_lock).
The tracer's exit detaches one tracee per write section; a
PTRACE_O_EXITKILL tracee's SIGKILL is sent in that section before
the detach (`send_sig_info_in`, Linux exit_ptrace under tasklist_lock:
SIGKILL takes no queue entry, so nothing allocates), its group
effects and wakeups done there too, so the tracee never runs untraced
user code. SIGKILL ends the stop
under the siglock hold that queues it (`sigkill_task`, Linux
signal_wake_up(fatal) clearing JOBCTL_TRACED under siglock), so a wait
after the kill never reports the stop, and a kill needs no TASKLIST
write lock (`zap_threads` walks the group under its siglock). A
tracer's request holds the stop while it runs (`PTRACE_FROZEN`): set
by `ptrace_check_attach` under the tracee's siglock (in the stop, no
SIGKILL pending) inside TASKLIST's read lock (the tracer link), cleared
under siglock when the request's `Frozen` guard drops, and whenever
a stop begins or ends (resume, detach, the tracer's exit, the tracee
leaving `ptrace_stop`), so no stale flag outlives a stop; while it is
set, SIGKILL leaves the stop alone (`sigkill_task`, and the tracee,
woken, sleeps `Uninterruptible` once it reads frozen with SIGKILL
pending), and the guard's drop ends a stop with SIGKILL pending and
wakes the tracee under its siglock (Linux ptrace_unfreeze_traced).
The tracee's user
register frame is touched only through `ptrace::with_stopped_regs`
(the arch register and single-step helpers): TASKLIST's read lock,
then the tracee's siglock, held across the frame access (a stop
ends only under it), ESRCH unless the tracee is stopped and frozen
(Linux: regs of a task ptrace_check_attach froze); callers hold
neither. A detach clears the single-step flag while the tracee is
still frozen, before it is untraced (Linux ptrace_detach:
ptrace_disable first).
PTRACE_INTERRUPT takes TASKLIST's read lock (the tracer link), the
tracee's siglock, sets `jobctl::TRAP_STOP` and
wakes the tracee there (Linux ptrace_signal_wake_up under siglock).
PTRACE_LISTEN sets `jobctl::LISTENING` under the tracee's siglock
in a frozen PTRACE_EVENT_STOP trap; the tracee clears it under
siglock when it leaves `ptrace_stop`. While it is set, wait and
`ptrace_check_attach` skip the stop, and a trap notice (SIGCONT's
prepare, a group stop's start: `trap_notify`, both locks held) or
INTERRUPT ends the stop under siglock (`ptrace_signal_wake_up`,
Linux JOBCTL_LISTENING).

**Group stops** (`signal/stop.rs`, Linux do_signal_stop; JOBCTL_STOPPED
and TASK_STOPPED): a stopped thread has `jobctl::STOPPED` under its
siglock, set with its group's `SignalStruct.jobctl` borrowed, then sleeps
`Killable` until it is clear (rechecked after each wakeup). It is
cleared, and the thread woken, under the same locks by SIGCONT's
prepare (`WakeMode::Any`, only a thread it found STOPPED), by a fatal
signal (`sigkill_task`, `WakeMode::Fatal`) and by a tracer's attach
(it then re-traps, JOBCTL_TRAP_STOP; the attacher waits, killable,
on the `VAR_WAIT_TABLE` queue its tracee's jobctl word hashes to
(`stop::trapping_wq`, Linux wait_on_bit(JOBCTL_TRAPPING)) for
TRAPPING to clear, which wakes that queue under the tracee's
siglock: an IrqSpinlock leaf taking only run-queue locks). The parent is told (CLD_STOPPED, CLD_CONTINUED) under
TASKLIST's read lock after the siglock is dropped.

**Source of Truth for Scheduling** (owner CPU's rq, IrqSpinlock):
1. **Runnable**: entry `queued` (in `CpuRunQueue.queue`)
2. **Current**: `CpuRunQueue.current`
3. **Sleeping**: entry `state != Running`, not queued, not current; reachable
   from a wait queue, futex bucket, a timer, or a signal
4. **Zombie**: `TaskState::Zombie(status)` set AND the entry removed from the
   rq (`exit_current`)

Wakers (possibly in IRQ context) never touch `TASKLIST`; code must NOT rely
on `TaskState` for scheduling decisions. `Zombie(status)` holds the Linux
wait status word (`code << 8` or the killing signal).

### 3.2 Memory Management

#### Frame Allocator (buddy + per-CPU lists)

**Location:** `mm/page_alloc.rs` (Linux mm/page_alloc.c), API in
`mm/frame_alloc.rs`

```rust
pub struct Zone {
    lock: IrqSpinlock<FreeArea>,   // zone->lock: buddy free lists
    pcp: [Pcp; NR_CPUS],           // per_cpu_pages, one per CPU
    ...
}
```

- Order (Linux): per-CPU list lock (`Pcp.lock`, `IrqSpinlock`, one per
  CPU; Linux pcp->lock) → `Zone.lock` (`IrqSpinlock`, leaf). A CPU
  allocates and frees through its own list under its lock (the kernel
  is not preemptive, so it stays on the CPU); a refill or a past-`high`
  drain takes `Zone.lock` under it. A thread-context allocation
  (`Gfp::RECLAIM`) that fails drains every CPU's list (`drain_all`,
  Linux drain_all_pages, which also drains remote lists under their
  pcp->lock from the calling CPU) and tries once more; atomic and
  opportunistic ones (`Gfp::TRANSHUGE_LIGHT`, the fault's huge-page
  try) fail at once. A drain takes each list's lock in turn, never two
  at once, so CPUs draining each other cannot deadlock, and needs no
  IPI (it may run under any lock). One drain runs at a time
  (`Zone.drain_lock`, a sleeping mutex only ever taken with try_lock,
  Linux pcpu_drain_mutex's mutex_trylock in drain_all_pages(NULL)): a
  caller that finds one running never waits (it may hold a spinlock)
  and just retries its allocation. `Pcp.count` (under its list's lock)
  and `Zone.nr_free` (under `Zone.lock`) are loads and stores, read
  lock-free for statistics and watermarks. Allocations in interrupt context never
  drain (debug builds assert they do not pass `Gfp::RECLAIM`). A CPU
  without
  per-CPU data yet (coming up, or the boot CPU early) never touches a
  per-CPU list: it allocates and frees under `Zone.lock`, as every CPU
  does until the lists are sized. A list's page
  count is an atomic beside its lock (statistics read it lock-free).
- Set once at boot, before any allocation, single CPU: the zone's span
  (`Zone.span`: struct page base, pfn range, section checks; Linux
  zone_start_pfn / spanned_pages) in `init`, and the per-CPU lists'
  batch and high (`Zone.pcp_size`, Linux pcp->batch / pcp->high) in
  `setup_pcp` at the end of the boot handover (`init_done`). Both are
  `spin::Once` (a second set panics); before the sizes exist no CPU
  uses its list (Linux boot_pageset: high 0, batch 1, the same).
  `Zone.managed` (Linux managed_pages) grows at boot and when reserved
  boot memory is given up (`free_reserved`), under `Zone.lock` (a load
  and a store), read lock-free for statistics and list sizing.
- Both are IRQ-safe: allocating or freeing in interrupt context cannot
  deadlock against an interrupted allocator (policy is still no
  allocation in IRQ context).
- Watermarks (min/low/high, from min_free_kbytes) are set at boot and
  by vm.min_free_kbytes writes, all three under `Zone.lock` (Linux
  __setup_per_zone_wmarks), and checked lock-free against the zone's free count (an atomic
  written under `Zone.lock`) plus this CPU's list count (its atomic;
  a refill only moves pages between the two), as Linux
  zone_watermark_ok.
- Reference counts are atomics in struct page (`get`/`put`, no lock);
  the put that reaches zero frees. `get` never takes a count from zero
  (Linux get_page_unless_zero): a racing final put wins, and the
  caller sees the page as gone (fork re-reads the PTE, a swap-cache
  hit reads the slot). A count that reaches `u32::MAX`
  saturates and stays (the page leaks rather than being freed while
  uncounted references remain).
- Freeing resets each struct page and releases its mapping (an
  AnonVma reference) before any allocator lock is taken; nothing else
  is called under the allocator's locks.

#### Boot Memory (memblock)

**Location:** `mm/memblock.rs`

- `MEMBLOCK` (`spin::Mutex`, leaf): RAM and reserved ranges, used only
  on the boot CPU before SMP, in thread context (the arch fills it,
  early allocations take from it, the free ranges go to the frame
  allocator). `FRAME_ALLOCATOR` may be taken under it (handing the
  free ranges over); nothing else is.

#### struct page (vmemmap)

**Location:** `mm/page.rs`

- The memory map is built on the boot CPU before SMP and never changes
  afterwards: `pfn_valid` / `phys_to_page` read the section bitmap
  lock-free (Acquire, after the Release that published a section).
- Fields are atomics. Flags, map count and mapping are updated
  lock-free by their users (fault, fork, unmap); the list links belong
  to whoever owns the page's list (frame allocator, later slab/LRU) and
  are touched only under that owner's lock.
- An anonymous page's mapping holds an AnonVma reference until the
  page is freed (unmapping only drops the map count), so whoever holds
  a page reference can read its mapping. A freed page's struct page is
  reset (and that reference dropped) before the page goes back to the
  allocator's lists, with no allocator lock held.

#### Address Spaces (Mm: mm_users / mm_count, mmap_lock)

**Location:** `mm/mod.rs` (`Mm`, `MmRef`), `mm/memory.rs`
(`exit_mmap`), `task/exit.rs` (`exit_current`), `task/exec.rs`
(`exec_replace_image`), `task/fork.rs` (`do_clone`)

- `Mm.users` (`AtomicUsize`, Linux mm_users) counts the tasks running in
  the address space and pinned users (`MmRef`: ptrace PEEK/POKE,
  process_vm_*, a /proc/<pid>/maps read). The last `MmRef` drop runs
  `exit_mmap`, which, under the mm lock held for writing, takes the
  VMAs (dropping the rmap chains) and tears down the user half
  (`pgtable::detach_user`, a TLB flush, `UserTables::free`), then drops
  the VMAs (file references) and the executable's path with no lock held. **Never drop an `MmRef`
  under a spinlock** (TASKLIST included): take it out (`Option::take`,
  `replace`) and drop it after unlocking. `mmget_not_zero` refuses an
  address space already being torn down.
- `Arc<Mm>` (Linux mm_count) keeps the struct and its top-level table,
  freed on the last drop (`Mm::drop`, __mmdrop). Holders: every `MmRef`,
  `get_task_mm` callers (the task's own user reference keeps the mappings),
  an open /proc/<pid>/maps (Linux proc_mem_open: mmgrab only), and an
  exited task's `DeadTask` until its CPU has switched away (scheduler
  rule 8).
- `Task.mm` is set and taken under the task's `alloc_lock` (Linux
  task_lock; 3.1.1): at clone (`dup_mm` or a
  shared `MmRef`), at exec (`exec_replace_image` loads the new table, then
  drops the old user reference: a vfork parent or other CLONE_VM threads
  keep it alive), at exit (`exit_task_mm`, after the robust list and
  CLEARTID writes that still need the mappings, Linux mm_release before
  exit_mm). A task becomes a zombie only after that, so a reaping parent
  never drops a task that still uses its mm.
- `Mm.sigpage` (`AtomicU64`, Linux mm->context.vdso, arm64's signal
  return page): stored by exec before the address space is used, by
  `dup_mm` for the child, and by mremap of the page under the mmap_lock
  for writing; loaded with no lock by signal delivery (a word, as Linux
  reads its pointer).
- The mmap_lock (`Mm.map`, a sleeping `RwSem<MmStruct>`, Linux
  mm->mmap_lock; "the mm lock" below) guards the VMA tree and VM
  counters. Taken through `Mm::mmap_read` / `mmap_write` and their
  `_killable` forms (the syscalls that change mappings and the /proc
  readers give up with EINTR on SIGKILL, as in Linux). Thread context
  only, never under a spinlock (sleeping locks order above all of
  them). Readers: /proc (maps, cmdline, environ, status figures),
  mincore, msync, populate, get_mempolicy MPOL_F_ADDR and the
  futex node lookup (`Vma.mempolicy`, which mbind sets under it for
  writing), remote reads (ptrace PEEK,
  process_vm_readv), `segv_code`; every other user, the fault path
  included, takes it for writing. `dup_mm` holds the parent's mm lock for writing while
  it copies VMAs and page tables, and the child's for writing nested
  in it (Linux dup_mmap's mmap_write_lock_nested: the child is
  reachable by no one else, so it never waits; its tables are borrowed
  from that guard) (`memory::copy_page_range`: it
  write-protects the parent's private PTEs with a compare-and-swap, since
  the parent's other threads may be faulting, splits 2MB pages and takes
  frame references). munmap / MAP_FIXED / brk shrink / shmdt
  zap pages under it (`munmap_locked`). `TASKLIST` is never held
  while taking an mm lock.
- Reverse-map chains (`mm::anon_vma`, Linux anon_vma->rwsem):
  `AnonVma.chain` is a sleeping `RwSem` (thread context only, never
  under a spinlock). `MmStruct` updates a VMA's entry under it for
  writing on every change of an anonymous VMA (insert, split, merge,
  grow, shrink, removal, an mlock change, exit), always with the mm
  lock held for writing (mm lock -> AnonVma.chain). The reverse map
  holds it for reading across its page-table accesses: exit and munmap
  unlink a VMA before freeing its tables, so a walk never reaches a
  freed table. Under it: the page_table_lock and PTE locks, the TLB
  flush of a changed entry, `FRAME_ALLOCATOR`; nothing under it takes
  an mm lock (a walk names address spaces by the `Weak<Mm>` and table
  root in each entry, never through the task table).
- Shared anonymous memory and SysV shm segments are files on the
  kernel's tmpfs (Linux shmem_zero_setup, shmem_kernel_file_setup):
  their pages are page-cache pages (Per-inode page cache), faulted and
  locked like any file's; MADV_REMOVE punches the hole through the
  file system (vfs_fallocate) after the mm lock is dropped.
- A SysV shm attachment (`ipc::shm::ShmAttach`, in its VMA) is cloned
  and dropped with the VMA, possibly under the mm lock: it counts
  shm_nattch under the segment's `KernIpcPerm.lock` (a spin leaf).
  shmat counts only a segment not marked deleted; IPC_RMID of an
  attached segment sets SHM_DEST under that lock, and the detach that
  takes shm_nattch to 0 on a SHM_DEST segment marks it deleted there;
  either then takes it out of the table (`IpcIds.inner`, after the
  perm lock is released) and destroys it, exactly once.
- The page-fault path (`mm/fault.rs`, `handle_mm_fault`, shared by
  both arches) holds the mm lock for reading from the VMA lookup through
  the PTE update (Linux lock_mm_and_find_vma: a stack that must grow
  first takes it for writing, grows, and the fault starts over), so a
  fault cannot race fork's copy, munmap, mprotect or mremap of its
  range, which hold it for writing. Faults, MADV_DONTNEED/FREE/REMOVE
  and remote access (ptrace PEEK/POKE, process_vm_*, /proc cmdline and
  environ) hold it for reading and may run at once: they change entries
  under the page-table locks (Page-table locks below). Remote access
  takes it per page (`mm::remote`) and drops it to fault an absent page
  in (`handle_mm_fault` takes it itself), as Linux GUP retries. Under the mm lock:
  page-table and page allocation (`FRAME_ALLOCATOR`), rmap/LRU, and the reads that may sleep (a file page:
  `pread` or the page cache for a ramfs page; a swap slot), as in Linux
  (the mm lock is a sleeping lock, so nothing it waits for can need
  it, and the VMA cannot change meanwhile). Only files whose
  `FileOps::mmap` accepts the mapping get there (ramfs, vfat, block
  and some character devices; Linux f_op->mmap): procfs, whose
  readers take an mm lock, pipes, sockets and anon-inode files cannot
  be mapped (ENODEV/EIO). A PTE is set with a
  compare-and-swap against the value the fault read (Linux pte_same)
  under its PTE lock, the loser dropping its page. No user memory is
  accessed under the mm lock (a fault there would deadlock: a waiting
  writer blocks new readers). The debug VMA/PTE check
  (`mm::check::verify`, feature `mmcheck`) runs under it after mprotect,
  munmap, mremap and madvise: it only reads, and takes no lock. madvise
  holds the mm lock over its whole VMA walk (for writing when the
  advice changes VMAs, else for reading), and MADV_REMOVE punches the
  shared object's holes only after dropping it. msync drops the mm lock
  around each writeback (`fsync` sleeps; it holds a reference on the
  file) and looks the next VMA up again after it (Linux msync); mincore
  copies each chunk of its vector out with the mm lock dropped.
- Page-table locks (`mm/ptl.rs`; Linux page_table_lock and split
  PTE locks): `Mm.page_table_lock` (`spin::Mutex<()>`, not IRQ-safe;
  held as a `ptl::PtLock`, which the writes of a 2MB-level entry,
  `pgtable::Pmd`, take as proof) covers table-structure changes: a missing table installed
  (`PgTables::pte_alloc`, `pmd_alloc`: the frame is allocated first,
  with no lock held, and installed under the lock only if the entry is
  still empty, else freed after it; Linux __pte_alloc + pmd_install,
  __pmd_alloc), a 2MB entry mapped (`do_huge_anon`, its tables and
  frames allocated before the lock), split
  (`split_huge_pmd`), cleared (`take_huge_pmd`) or given a new
  protection (`Pmd::set_prot`, mprotect). The PTE lock of each
  PTE table page (a word in its struct page, `Page.ptl`; one lockdep
  class) covers a table's 4KB entries. One rule, whatever mm lock
  mode: **every software write of a 4KB entry is made under its
  table's PTE lock** (a fault from reading the entry to its last
  change, copy-on-write break-before-make included; a remote write's
  `unshare_for_write`; the reverse map's `try_to_unmap`; swapoff's
  `unuse_pte`); remote copies through a frame hold it too
  (`remote::with_frame`, so a racing zap cannot free it meanwhile).
  Range operations go through the one walker, `pagewalk::walk_pte_range`
  (Linux walk_page_range): it takes each PTE table's lock once for all
  of the table's entries in the range, and hands 2MB entries to a
  callback with no PTE lock held (splits take the page_table_lock):
  zap_range, fork's copy_page_range, mprotect's change_protection,
  mremap's move_prep / move_ptes, MADV_COLD / MADV_PAGEOUT, swapoff's
  scan, the RSS count and the mmcheck pass. Under the PTE lock only
  the MMU still changes an entry (accessed/dirty bits): a
  compare-and-swap is used only against that, and a writer whose CAS
  fails retries only while the entry still maps what it expects
  (`try_to_unmap` gives up when it no longer maps its page). Two PTE
  locks are nested (same lockdep class) only by fork (parent's table,
  then the child's) and mremap's `move_ptes` (the old table, then each
  new one; Linux move_ptes), both with the mmap_lock held for writing,
  so no other path holds two and the pair cannot invert. Tables
  are freed only with the mm lock held for writing: munmap and mremap
  (`memory::free_pgtables`, Linux free_pgtables, through a
  `pgtable::PgPrune` made from the `&mut MmStruct`) after the VMAs of
  their range left the reverse-map chains, and only once empty and
  outside every remaining VMA's span;
  exit (`exit_mmap`) after unlinking every VMA. So an entry stays valid
  under any mm lock hold, or under the chain lock (AnonVma.chain, a
  file's i_mmap) of a VMA it lies in (the reverse map), and
  `mm::pgtable` makes that a borrow: a `PgTables` is made from a
  borrow of the `MmStruct` (an mm lock guard) or of a held chain
  (`ChainRead::entries`, limited to the VMA's range), and the `Pte`,
  `Pmd`, `Dir` and `PteTable` (PTE lock held) handles it gives, and
  the range walker that takes it, cannot outlive it (the arch walkers
  are `unsafe fn`s reached only through it).
  Order: mm lock -> page_table_lock -> PTE lock ->
  `FRAME_ALLOCATOR` (the TLB is flushed under them); never in
  interrupt context; no sleeping under them. Both disable preemption
  (in_atomic), so an allocation under them never enters direct reclaim:
  reclaim's reverse-map walk takes PTE locks, the held one included (a
  self-deadlock). No page table is allocated under the page_table_lock
  (frees under it are fine). Allocations that must not fail are made first: fork
  and mremap allocate the destination tables before the source's PTE
  lock (`PteWalk::prepare`, mremap's prep walk reads entries unlocked
  under the write-held mmap_lock), a copy-on-write break retries its
  page allocation without the lock. A holder may flush other CPUs' TLBs: their waiters spin with
  interrupts on (syscalls and faults run with them on, 7.5) and answer
  the IPI, as in Linux. Deviation: the PTE lock is a bare lock word in
  the table's struct page (Linux: a `spinlock_t` in the ptdesc).
- TLB after a PTE loses permission or its page: flushed before the mm
  lock is released and before the old frame can be freed or written
  through by another process, always in the address space that changed
  (`mm::tlb`, see TLB Flushing below): fork write-protects the parent's
  private PTEs and flushes each VMA's range (`flush_tlb_mm_range`)
  before dropping the parent's lock (the child cannot run yet);
  mprotect rewrites the range's PTEs (`mprotect::change_protection`),
  then flushes the range before dropping the lock (its pages keep their
  references); mremap's move flushes the old range the same way; a
  copy-on-write break flushes the page it replaces (`flush_tlb_page`)
  before dropping its reference; munmap, MADV_DONTNEED/REMOVE and exit
  clear entries into a `Gather` (`mm/gather.rs`, Linux mmu_gather) that
  flushes the whole range once per batch chain and only then releases
  the frames (and, at exit, the page tables): no frame is reused while
  a CPU may still reach it through its TLB. The chain is the gather's
  own 8 frames, then pages of them allocated GFP_NOWAIT under the page
  table lock (Linux tlb_next_batch), up to MAX_GATHER_BATCH_COUNT; at
  the cap or when an allocation fails it flushes. rmap flushes in the
  chain's address space, not the one this CPU runs.
- Break-before-make: a live entry is never overwritten by one mapping
  another page or another size. A 2MB page split into a table
  (`huge_page::split_huge_pmd`, Linux pmdp_invalidate) and a copy-on-write break
  (`fault::replace_pte`, Linux ptep_clear_flush) first clear the entry
  and flush its TLB entry, then write the new one (required on arm64,
  ARM ARM D8.16; x86 needs it for the page-size change). In between
  the address faults; the fault waits for the lock the writer holds,
  then finds the new entry. A split leaves `PMD_SPLITTING` (invalid to
  the MMU, Linux's invalidated pmd) rather than 0 in between, under the
  page_table_lock: lockless walkers (`walk_pmd`, `pte_alloc`) wait it
  out (`pmd_settled`) instead of taking the slot for empty (a racing
  MADV_DONTNEED of the whole 2MB would otherwise miss the 4KB entries
  the split then installs).
- Teardown TLB: `exit_mmap` detaches the user half from the top-level
  table (`pgtable::detach_user`) into a full-mm `Gather`, which flushes
  the whole address space with its paging-structure caches
  (`flush_tlb_mm`), then frees pages and tables (`UserTables::free`). A CPU that last ran the address space
  (another thread still in `exit_current`) has it loaded until it
  switches away, so the flush reaches it (arm64 broadcast; x86 see TLB
  Flushing).

#### Page pins (mm/gup.rs; Linux mm/gup.c FOLL_PIN)

- A pin is `GUP_PIN_COUNTING_BIAS` (1024) references on a 4KB page's
  atomic count (Linux's scheme for small folios), taken at once by
  `get_n` (refused for a free page or a count near saturation) and
  dropped at once by `put_n`, whose last reference frees the page.
  `maybe_dma_pinned` reads the count lock-free.
- Pinning (`pin_user_range`) holds the mmap_lock for reading across a
  run of pages, keeping the VMA while the pages are in it, and drops it
  only to fault a page in (`handle_mm_fault` takes it; Linux
  __get_user_pages): mmap_lock (read) -> page_table_lock (a 2MB entry is
  split first) -> PTE lock, under which the entry is checked and the
  count raised. A private anonymous page still shared copy-on-write is
  first given to the mapping (`unshare_for_write`, under the same mmap
  lock hold).
- The PTE lock orders a pin against fork and reclaim, which decide
  under it too: `memory::copy_pte` copies a maybe-pinned page the
  parent owns alone for the child instead of sharing it (the copy's
  page is allocated with no PTE lock held: the walk stops at that
  entry, allocates under the mm locks only, and resumes there, Linux
  copy_pte_range's -EAGAIN); `rmap::try_to_unmap` leaves a maybe-pinned
  page mapped, and reclaim skips one before it starts. A pin that comes
  after either sees the entry they left (a copy-on-write entry: a
  write pin faults, a read pin unshares; a swap entry: it faults).
- `PG_ANON_EXCL` (Linux PG_anon_exclusive) is an atomic flag bit set
  and cleared only under the PTE lock of the entry mapping the page:
  set by a fault mapping a private mapping's own page, a copy-on-write
  copy or reuse, an exclusive swap-in and a pin of a writable private
  entry; cleared by fork sharing the page and by reclaim unmapping it;
  reset by the free. Read under the PTE lock by the write fault and
  mprotect (reuse in place, for a page out of the swap cache:
  `Page::reusable`), remote writes and fork.
- A pin holds the page only (Linux a folio reference), never the inode
  or file whose cache it is in. Unpinning (`PinnedPages` drop) of
  unwritten pages takes no lock (the count drop may free the page,
  which the allocator allows in any context); a written page not yet
  dirty is dirtied under its page lock (sleeping; Linux
  unpin_user_pages_dirty_lock -> folio_mark_dirty_lock), through its
  mapping if it is still in one (borrowed under that lock, see the
  page cache's eviction), else by its flag, so a `PinnedPages` that
  was written is dropped in thread context; a completion in an
  interrupt handler must hand it to a thread (Linux bio_dirty_work).
  A long-term pin (FOLL_LONGTERM: a registered io_uring buffer) of a
  writable shared mapping of a file that writes back is refused (Linux
  writable_file_mapping_allowed: EFAULT). Block-device direct I/O keeps its pins until the
  submitter's wait returns and drops them there (3.10).

#### Swap (mm/swap/swapfile.rs, swap_state.rs; Linux mm/swapfile.c, swap_state.c)

- `SwapInfo.map` (`spin::Mutex`, Linux si->lock): a device's slot
  counts (swap PTEs + SWAP_HAS_CACHE) and allocation hint; swapoff
  clears SWP_WRITEOK under it, and the allocator rechecks it there, so
  no slot is taken after swapoff's scans begin. Thread
  context only; a leaf taken under the PTE lock (fork's swap_duplicate,
  zap's free_swap_and_cache, swap-in's swap_free), never with a swap
  cache lock held.
- `SwapInfo.cache` (`IrqSpinlock<XArray>`, Linux i_pages xa_lock_irq):
  the swap cache of a device, page by slot. A leaf: nothing allocates
  under it (an insert missing an index node drops it, preloads and
  retries: `xarray::store_nomem`, Linux xas_nomem, as the page cache
  does; swapoff's drop walks it one slot per hold). A lookup takes its page
  reference under it (get_page_unless_zero); reclaim deletes a page
  from it by freezing its count (expected -> 0) under it, so no lookup
  revives a page being freed. Slot counts change after it is dropped.
- Page lock (`page::lock_page`, PG_locked + the hashed page wait
  queues; sleeping): held while a page enters or leaves the swap cache
  and across its swap read (a racing fault waits for the read), and by
  reclaim from unmap to free (trylock: reclaim never sleeps on it).
  Order: mmap_lock -> page lock -> AnonVma.chain -> PTE lock; under a
  spinlock only `trylock_page` (zap, a write fault's swap-cache reuse).
  I/O happens under the page lock, never under a spinlock.
- `SWAP_INFO` (spin `RwLock`, read mostly, thread context; Linux
  swap_lock and swap_info[]): the enabled devices and the types in use
  (`SwapTable.used`, Linux SWP_USED). swapon reserves the lowest free
  type under it before it opens anything (EPERM if none; Linux
  alloc_swap_info) and gives it back, after releasing what it opened,
  if it fails; swapon publishes the device under it (Linux
  enable_swap_info), swapoff finds its device among the SWP_WRITEOK
  ones and clears SWP_WRITEOK under it (so a second swapoff of the
  area is EINVAL), sets it again there if `try_to_unuse` fails (Linux
  reinsert_swap_info), takes the device out of the table under it
  once drained, and frees the type last, after the device's release:
  `SWAP_INFO` -> `SwapInfo.map`. `TOTAL_SWAP_PAGES` (Linux
  total_swap_pages) changes under it with SWP_WRITEOK (swapon's
  publication, swapoff's clear and reinsert); `swap_totals` (Linux
  si_swapinfo) reads it and the draining devices' in-use slots under
  it. Nothing sleeps under it. Swapons and swapoffs of different
  areas run in parallel, `try_to_unuse` included. There is no
  swapon_mutex: Linux takes it to serialize enable_swap_info and
  swapoff's removal (both under `SWAP_INFO` here) with /proc/swaps'
  walk, whose show sleeps; hk has no /proc/swaps.
- swapon holds the mapping host's `i_rwsem` (the swap file's inode,
  or the device's bdev inode; Linux swapon's inode_lock) from the
  IS_SWAPFILE check (EBUSY, whatever path names the file) through the
  header's read (page cache), the extents' mapping, S_SWAPFILE and the
  write-back that follows it (inode_drain_writes) to the area's
  publication: `i_rwsem` -> invalidate_lock -> page and buffer locks
  (the header read, ->bmap's FAT reads), `i_rwsem` -> `SWAP_INFO`.
  swapoff (`try_to_unuse`), no swap lock held, walks `MMLIST` and
  faults the device's swap PTEs of each address space in, its
  mmap_lock held for reading; then it clears S_SWAPFILE under the
  `i_rwsem` with no swap lock held.
- `SwapInfo.users` (`PercpuRef`, 1.3.3; Linux si->users): every use
  of a device by entry or type holds a `SwapDev` (Linux
  get_swap_device / put_swap_device), taken under `SWAP_INFO` read
  (tryget, refused once killed) and put anywhere, PTE lock included.
  swapoff, its device empty, kills and waits for it with nothing
  held, then takes the device out of `SWAP_INFO` and drops the last
  `Arc` itself: the release (block device close under
  `Disk.open_mutex`, sync, page-cache invalidate; a swap file's iput)
  sleeps, so it runs only there (`SwapInfo` drop asserts
  might_sleep).
- `MMLIST` (`spin::Mutex` leaf, mm/mod.rs; Linux init_mm.mmlist under
  mmlist_lock): an `OwnedList` of the address spaces that may hold
  swap entries, one `Arc<Mm>` each. An mm is linked the first time it
  gets one, under the PTE lock (reclaim's `try_to_unmap`, fork's copy
  of a swap PTE into the child: Linux try_to_unmap_one,
  copy_nonpresent_pte; an unlocked owner-mark check first, as Linux's
  list_empty), and unlinked by its last user after exit_mmap (Linux
  __mmput). swapoff takes each listed mm as a user
  (`mmget_not_zero`) under it, drops it for the faults and retakes it
  to step on from that mm, which its user keeps listed; the previous
  user is dropped with it released (a last drop takes it to unlink).
  Nothing allocates under it and no user reference is dropped under
  it.

#### LRU (mm/swap/lru.rs; Linux mm/swap.c lruvec)

- `Lruvec.lock` (`IrqSpinlock`, Linux lruvec->lru_lock): the LRU lists,
  linked through struct page (`next`/`prev`, owned by the list while
  PG_LRU is set). IRQ-safe because a page leaves its list when it is
  freed (`lru::page_freed`, from the allocator's release with no
  allocator lock held), and pages are freed in any context. A leaf:
  nothing is taken under it but page reference atomics; no reference is
  dropped under it (a drop may free the page and take it again).
- Per-CPU add batches (`BATCHES`, `IrqSpinlock`, one per CPU; Linux
  cpu_fbatches):
  a batch holds a reference on each page; a full batch is taken out
  under its lock, then added under `Lruvec.lock` (never both held), then
  its references dropped. `lru_add_drain_all` drains every CPU's batch
  from the caller under each batch's lock (Linux asks each CPU through
  a work item).
- Isolation (reclaim) takes a page off a list under `Lruvec.lock` only
  if it can take a reference (get_page_unless_zero): a page whose count
  reached 0 is left for `page_freed`, which takes the lock and unlinks
  it. Reclaim never takes an mmap_lock while holding it.

#### Reclaim (mm/swap/vmscan.rs; Linux mm/vmscan.c)

- `shrink_folio_list` works on pages it isolated (each with a
  reference) and holds no lock between pages. Per page: page lock by
  trylock (never waits), then swap cache add (cache lock, then slot
  counts), the reverse map (AnonVma.chain for reading -> PTE lock ->
  slot counts, TLB flush), the swap write with only the page lock
  held (block I/O sleeps), and the delete with its count frozen under
  the cache lock. It never takes an mmap_lock (callers may hold one for
  reading: MADV_PAGEOUT, a fault's direct reclaim), and holds no
  spinlock across I/O or a sleeping lock.

#### TLB Flushing (mm/tlb.rs; arch/{x86_64,aarch64}/tlb.rs)

No lock: the state is atomics and per-CPU data (Linux arch/x86/mm/tlb.c).

- `Mm.ctx` (`MmContext`): `cpumask` (atomic bit per CPU that has the
  address space loaded), `tlb_gen` (AtomicU64, bumped by every flush,
  SeqCst: a full barrier after the PTE stores), `ctx_id` and the arch
  part (arm64 ASID). Shared by every CPU: the cpumask and generation
  must be seen by all flushers, as in Linux.
- `TLB_STATE[cpu]` (`TlbState`, per CPU): `loaded_mm` (the `Mm` loaded,
  0 for the kernel table, `SWITCHING` during a switch) and `loaded_gen`.
  Written only by its own CPU with interrupts disabled (a switch, a
  local flush, the flush IPI handler); never read by another CPU.
- `switch_mm` (scheduler, before the register switch, rq lock held:
  interrupts off; exec; init's first entry) follows Linux
  switch_mm_irqs_off: `loaded_mm` = SWITCHING, the previous address
  space's cpumask bit cleared (x86 without PCID: the CR3 write drops
  all its entries), this CPU's bit set in the next one's, a full
  barrier, `tlb_gen` read, the table loaded (x86 CR3; arm64 TTBR0),
  then `loaded_mm`/`loaded_gen` set. A flusher that misses the bit made
  its PTE change before its barrier, so the walk after the load sees
  it. The loaded `Mm` stays alive until its CPU switched away: its task
  (or an exited task's `DeadTask`, scheduler rule 8) holds an mm_count
  reference until then, so a raw `loaded_mm` is safe to dereference
  there.
- A flush (`flush_tlb_mm_range`, `flush_tlb_page`, `flush_tlb_mm`)
  bumps `tlb_gen` and, with interrupts disabled, brings this CPU up to
  date if it has the address space loaded (`flush_func`: nothing if its
  `loaded_gen` already covers the flush, a ranged flush if it misses
  just this one, else all; ranges over `FLUSH_CEILING` pages flush
  all). arm64 broadcasts instead (`tlbi vale1is` / `vae1is` when page
  tables were freed, `vmalle1is` past the ceiling; the DSB ISH waits
  for every CPU). On x86 the other CPUs of the cpumask are then sent
  the flush and waited for (`smp_call_function_many`, Cross-CPU Calls:
  the wait answers this CPU's own queue, so it may run with interrupts
  off), their handler doing the same `flush_func`.
- arm64 ASIDs (`arch/aarch64/asid.rs`, `arch/aarch64/tlb.rs`, Linux
  arch/arm64/mm/context.c): `MmContext.arch.id` (AtomicU64,
  generation | ASID), per-CPU `active` / `flush_pending` atomics, and one
  global **ASID lock** (`AsidAlloc.inner`, IrqSpinlock: bitmap,
  `cur_idx`, per-CPU `reserved`). Global like Linux cpu_asid_lock: ASIDs
  are one machine-wide namespace, and the lock is only taken on the
  slow path (an address space's first switch in a generation, or a
  rollover). Taken in `switch_mm` with the run-queue lock held, so
  order: run-queue lock -> ASID lock; it is a leaf (nothing is taken
  under it) and never taken in interrupt context. The fast path is a
  compare-and-swap on this CPU's `active` entry, which a rollover zeroes
  first (Linux check_and_switch_context). TTBR0 carries the ASID
  (TCR.A1 = 0), user entries are nG, so a switch flushes nothing; a
  rollover makes every CPU flush its own TLB before its next switch.
  User flushes name the ASID (`tlbi vale1is/vae1is/aside1is`).
  LOCKDEP builds allocate from 31 ASIDs, so the boot tests roll over
  hundreds of times on real switches.
- `flush_tlb_kernel_range` (ioremap/iounmap): arm64 `tlbi vaae1is`
  (all CPUs); x86 every active CPU (`on_each_cpu`). Called with no lock
  held.
- Who may flush: thread context, never under an IrqSpinlock or a lock
  another CPU spins on with interrupts off (Cross-CPU Calls). User
  flushes run under the mm lock, whose waiters sleep (as in Linux), and
  nothing above the mm lock in section 2 is held across a flush
  (callers hold at most the mm lock and the VFS / IPC locks taken
  before it, none of which is spun on with interrupts off). arm64
  flushes never wait on another CPU's software.

#### Cross-CPU Calls (smp.rs; arch/{x86_64,aarch64}/ipi.rs)

No lock (Linux kernel/smp.c): `smp_call_function_many(mask, func,
info, wait)` runs `func(info)` on other CPUs from their call-function
IPI (x86 vector 0xfc, arm64 SGI 1); `on_each_cpu` adds this CPU;
`on_each_cpu_cond` calls only the CPUs its condition picks, run on the
caller for each CPU first (Linux on_each_cpu_cond);
`smp_send_reschedule` (x86 0xfd, arm64 SGI 0) makes a remote CPU
reschedule (`resched_curr` after queueing a task on its run queue,
`kick_process`); its handler flags the running task NEED_RESCHED.

- `QUEUE[cpu]` (per CPU): the calls queued for a CPU, a lock-free list
  (Linux llist). Senders push with a compare-and-swap (Release); only
  the owner empties it, with one swap (Acquire), so there is no ABA
  case and no lock: nothing to order against other locks, nothing to
  disable for the push (an interrupt handler may push a reschedule
  wakeup while the thread it interrupted pushes a call). A per-CPU
  IrqSpinlock would also work but would make every sender of a many-CPU
  shootdown contend on each target's lock with interrupts off. Only the
  push onto an empty queue raises the IPI.
- `CFD` (`PerCpu<Once<Box<[Csd]>>>`, per sending CPU): the sender's
  call slots, one per target CPU (`nr_cpu_ids` of them, allocated by
  `smp::init` at bring-up before any CPU is active, never freed; Linux
  cfd_data). A CPU makes one call at a time (thread
  context, kernel not preemptive); a slot's `locked` flag (set by the
  sender, cleared with Release by the target after `func` returned) is
  waited for before the slot is reused and, with `wait`, before return.
- `ACTIVE` (global `CpuMask`): CPUs that service IPIs, each set once at
  boot after its interrupt controller is up and interrupts enabled
  (`smp::set_active`, which then flushes its own TLB: a kernel-range
  flush may have skipped it), and cleared once more at the very end:
  `smp::stop_other_cpus` (halt, power-off, restart, after
  device_shutdown; Linux smp_send_stop) sends each other CPU
  `stop_this_cpu`, which clears its bit and halts with interrupts off
  inside the IPI, never releasing its call slot. The stopper waits up
  to 1 s for the bits to clear. Global: every sender needs every CPU's
  state, and it changes once per CPU.
- `func` runs in interrupt context with interrupts off (IPI handler, or
  the sender's own wait loop): it may only touch atomics, per-CPU data
  and IrqSpinlocks (7.4 applies).
- **Rules** (a broken one is a deadlock): never call from interrupt
  context or with an IrqSpinlock held (a raised preempt count with
  interrupts off; reported as `LOCKDEP:FAIL smp_call_function_many in
  atomic context`). A `spin::Mutex` may be held (e.g. a THP split's
  shootdown under the page_table_lock, as Linux under the pmd lock):
  its waiters spin with interrupts on. Never with a lock held
  that another CPU may spin on with interrupts off (TASKLIST: taken
  under run-queue locks), as that CPU cannot answer. Syscalls and faults
  run with interrupts on (7.5), so a target answers at once; a call may
  still be made with interrupts off: every wait polls this CPU's own
  queue with interrupts off (`poll`), so two CPUs calling each other,
  or a caller with interrupts off, make progress. No CPU may spin-wait
  with interrupts off for a condition another CPU sets only after its
  call returns, unless it polls its queue.
- The CFD row assumption holds with interrupts on: a CPU makes one call
  at a time because callers are thread context (never interrupt
  handlers, `check_context`) and the kernel is not preemptive, so no
  other task's call on this CPU can start before this one returns.

#### Kernel Page Tables (kernel half)

**Location:** `mm/swapper.rs` (top-level table, boot helpers),
`arch/x86_64/kmap.rs`, `arch/aarch64/kmap.rs` (layout), `mm/ioremap.rs`
(entry encoding: `arch/*/ioremap.rs`, `arch/*/kmap.rs`);
layout in `doc/MEMORY.md`

- The kernel half (direct map of RAM, kernel image, vmalloc/ioremap
  window) is built once on the BSP before SMP and before any user
  address space exists. Every top-level kernel entry is created then,
  including the (empty) vmalloc table, and never changes afterwards:
  x86 copies PML4[256..512] into each new address space
  (`copy_kernel_mappings`); arm64 keeps the kernel in TTBR1, which no
  address space owns (TTBR0 is user-only; kernel threads get an empty
  table). Linux: `preallocate_vmalloc_pages`, swapper_pg_dir.
- Direct-map and image entries are immutable after boot: read without a
  lock (page walks, `phys_to_virt`/`virt_to_phys` are pure arithmetic).
- The vmalloc area (ioremap window, kernel stack area) has lower tables
  shared by every address space. Its virtual ranges are handed out
  under `IOREMAP` (ioremap) and `vmstack::SLOTS` (stacks), both
  `spin::Mutex` leaves, thread context only; a mapping adds missing
  tables under `KTABLES` (`spin::Mutex` leaf, thread context, in
  `mm/ioremap.rs`; a table's frame is allocated before it and freed
  after it when another mapping added the table first, as Linux
  __pte_alloc_kernel). Linux: `vmap_area_lock` +
  `init_mm.page_table_lock`. Their
  entries are only accessed atomically: an upper entry is only ever
  added (a release store under `KTABLES`), so a walker that does not
  add (iounmap, a `VmArea` unmap) reads them with acquire loads and no
  lock, as Linux vunmap walks without init_mm's lock. A PTE
  of a range one owns is set or cleared without a lock: only the
  holder of the range's `vmalloc::VmArea` (Linux vm_struct; a vmalloc
  block, a kernel stack) or of an ioremap mapping changes it, and these
  kernel tables are never freed.
- TLB: iounmap clears the entries and flushes every CPU
  (`flush_tlb_kernel_range`, with `IOREMAP` not held) before the range
  is freed; arm64 broadcasts, x86 sends IPIs.
- Kernel stacks (`mm::vmstack`, Linux VMAP_STACK): 16KB of single
  pages at the start of a 64KB slot, the rest unmapped (the guard gap
  the next stack's overflow faults in). Freeing (a `VmStack` dropped, from `DeadTask::drop`,
  possibly with interrupts off) unmaps and frees the pages with a
  local flush and marks the slot dirty under `SLOTS`; `alloc` (thread
  context) flushes the whole area on every CPU once 64 slots are dirty,
  with `SLOTS` not held, before any of them is reused (Linux lazy
  vmap purge). Flushers are serialized by `FLUSH` (sleeping
  `sync::Mutex`), so one cleaning a slot set from its snapshot (the
  dirty set taken under `SLOTS` into `Slots.flushing`, which only
  `FLUSH`'s holder writes) cannot clean a slot freed again after
  another's flush. `SLOTS` is never
  taken in an interrupt handler.
- Large heap blocks (`mm::vmalloc`, Linux vmalloc/kvmalloc): page
  ranges of the 16 GiB vmalloc allocation area, each followed by an
  unmapped guard page, handed out under `vmalloc::AREA` (`spin::Mutex`
  leaf, thread context; bitmap updates only, no mapping, flush or
  allocation under it). `alloc` needs a context that may sleep
  (`in_atomic` false, else it fails); it maps single frames outside
  `AREA`. `free` unmaps and frees the pages with a local flush and marks
  them dirty under `AREA` (interrupts may be off); from an interrupt
  handler it instead pushes the block on a lock-free list in its own
  first bytes, freed by the next `alloc`. Dirty ranges are reused only
  after a flush of the whole area on every CPU, done by `alloc` once
  32 MiB wait or nothing clean fits, with `AREA` not held and purges
  serialized by `vmalloc::FLUSH` (sleeping): frees during a flush go to
  the second dirty bitmap and wait for the next purge.
- User half: per address space, changed by its tasks under the mm lock
  (the fault path, see Address Spaces);
  never contains a kernel mapping.

#### Heap Allocator (boot arena, slab)

**Location:** `mm/heap.rs` (global allocator, boot arena),
`mm/slab.rs` (Linux mm/slab.c array caches, SLUB-style lists)

- Before the page allocator is up, allocations come from a static boot
  arena (first-fit list under an `IrqSpinlock` leaf); afterwards from
  kmalloc caches. A block goes back to whichever gave it, told apart by
  the arena's static bounds (no lock on the free path).
- Each `KmemCache` has a per-CPU object array, used by its CPU with
  interrupts off (no lock), and `list_lock` (`IrqSpinlock`) over its
  partial and empty slab lists. Order: per-CPU array → `list_lock` →
  page allocator (per-CPU page list, `Zone.lock`); empty slabs are
  given back to the page allocator after `list_lock` is dropped, and a
  new slab is allocated with no `list_lock` held. A CPU without per-CPU
  data yet uses `list_lock` directly.
- A SLAB_TYPESAFE_BY_RCU cache (`KmemCache::typesafe_by_rcu`; the file
  cache `FILP_CACHE`, Linux filp_cache) gives each empty slab back only
  a grace period after it left the lists (Linux free_slab's call_rcu):
  once `list_lock` is dropped, any context, the slab's own `RcuHead`,
  made over its head struct page's list links, free list and counts
  (`Page::slab_rcu_head`, Linux struct slab's rcu_head union: no one
  else's once the slab is off its lists), is queued; its callback
  (`rcu_free_slab`, `rcuc/N`, preemption off, no lock) gives the slab to
  the page allocator.
  Objects are reused at once: an RCU reader that loaded an object's
  address touches only its constructed, type-stable part (for a file,
  its count), which the cache never writes (the free-list link is at
  `freeptr`, outside it, Linux freeptr_offset), and checks after taking
  a reference that it got the object it meant.
- All IRQ-safe (an allocation in interrupt context cannot deadlock),
  but the policy is still **no allocation in IRQ context**; IRQ paths
  reserve capacity up front (e.g. `netif_napi_add`)
- kmalloc above 8KB (or aligned above 4KB) takes pages directly from
  the page allocator. The heap has no GFP argument, so its pages take
  one from the context (`slab::heap_gfp`): the GFP the call named
  (`util::kalloc::with_gfp`, `try_box_gfp`, `try_arc_gfp`,
  `KDeque::try_push_back_gfp`; Rust-for-Linux's per-call flags), else
  GFP_KERNEL (to the min watermark; reclaiming only where the caller may
  sleep, else a drain), GFP_ATOMIC in an interrupt handler that named
  none and within reclaim (PF_MEMALLOC, over a named one). A named GFP
  is a per-CPU value set with preemption off for the call (an interrupt
  arriving does not see it, being at another interrupt depth); only a
  site where Linux allocates GFP_ATOMIC/GFP_NOWAIT in atomic context
  names one, and only around fallible allocations. An unnamed
  allocation in atomic context is listed by lockdep (1.5). A cache grows with interrupts as the caller had
  them (the per-CPU array is used with them off, the new slab is made
  after restoring them, Linux cache_grow_begin). User data stops at
  low, leaving low - min to kernel objects (a failed heap
  allocation is fatal in Rust): user allocations stop at low until the
  OOM killer (P6), even after reclaim; then Linux's min.
- Direct reclaim runs for a `Gfp::RECLAIM` allocation (GFP_KERNEL,
  GFP_USER, GFP_HIGHUSER_MOVABLE) only when the caller really may sleep
  (`page_alloc::may_direct_reclaim`): no spin lock held, interrupts on,
  a task (not tid 0) and not reclaim itself (PF_MEMALLOC). Otherwise it
  drains the per-CPU lists and retries once. Under PF_MEMALLOC_NOIO
  (Linux current_gfp_context: no __GFP_IO/__GFP_FS) reclaim frees clean
  pages only: page cache and clean swap cache, no swap writeback and no
  dcache shrink. Reclaim runs with PF_MEMALLOC set
  (`mm::memalloc_scope`, Linux memalloc_noreclaim_save), so its own
  allocations take GFP_ATOMIC and never reclaim again; swap writeback
  runs with PF_MEMALLOC_NOIO (Linux memalloc_noio_save). The reverse map
  only tries the AnonVma chain lock under PF_MEMALLOC (Linux rmap_walk
  with try_lock): an allocating task may hold it for writing. Swap
  I/O takes no filesystem lock: a swap file's slots are its blocks,
  mapped at swapon (->bmap under its i_rwsem, Linux
  generic_swapfile_activate) and written straight to its device, as
  a partition's. A page table
  is allocated before the page_table_lock is taken (Linux
  pte_alloc_one), so it may reclaim; a fault whose table still cannot
  be allocated reclaims again and retries.

#### Per-inode page cache (Linux i_pages)

**Location:** `mm/filemap.rs` (`AddressSpace`, the inode's
`i_data`), `fs/pageio/buffer.rs` (buffer heads); users: ramfs, tmpfs, vfat
files, block devices (`BlockDevice.bd_inode`). The device cache holds
its blocks in buffer heads (Buffer heads, below): vfat reads and
writes all its metadata (FAT, directories, boot sector) in them, in the device's block size, which
its mount sets to the FAT sector size (`sb_set_blocksize`), and the
device's writepage writes only dirty buffers: a device-cache page may
also hold file-data clusters, which the file's own cache writes. A
vfat file's pages hold buffers of the same block size, mapped by
fat_get_block (`fs/vfat/aops.rs`) under the file page's lock. (A new
directory cluster is zeroed in its buffers, Linux fat_zeroed_cluster;
a file block get_block maps new has its device-cache alias cleaned,
Linux clean_bdev_bh_alias: file page lock -> device page lock ->
buffer lock.)

- `AddressSpace.i_pages` (`spin::Mutex<XArray>`, Linux xa_lock): the
  cached pages by index. Thread context only (no I/O completion or
  page free touches it from an interrupt). A leaf apart from the heap
  (index nodes: tried atomically under it, else preloaded with it
  dropped, Linux xas_nomem) and page reference counts. A lookup takes
  its page reference under it (get_page_unless_zero), so a page
  removed meanwhile is never returned.
- Page lock (`PG_locked`): a page is inserted locked, filled
  (`->read_folio`), written into (`write_begin`..`write_end`) and
  removed (truncate) under it. Order: i_rwsem -> page lock ->
  i_pages. Removal also needs `i_pages`; a lookup that then locks the
  page rechecks `Page.mapping` (truncated meanwhile: retry).
  ->read_folio unlocks the page when its read ends (an I/O
  completion), uptodate if it worked, or on an error return (Linux);
  `read_page` waits for the unlock without the lock
  (`filemap_read_folio`, `wait_on_page_locked`, Linux folio_wait_locked)
  and returns the page as it then is: a truncate meanwhile may have
  removed it, its data still valid (removal leaves PG_uptodate, as
  Linux __filemap_remove_folio; do_read_cache_folio returns it), a
  read that failed is EIO, and a page found locked is waited for
  unlocked, then looked up again (a truncation is found by its
  `Page.mapping` once locked).
- `AddressSpace.invalidate_lock` (sleeping `RwSem`, thread context;
  Linux invalidate_lock): held shared by a read or fault that creates
  or fills a page (`read_page`, Linux filemap_create_folio,
  filemap_update_page, filemap_fault), exclusive by `set_blocksize`
  across a device cache's write-back and drop, so no page is filled
  on the old geometry meanwhile. i_rwsem -> it (buffered reads of a
  device file, `set_blocksize`), mmap_lock -> it (faults), it -> page
  lock.
- `AddressSpace.writable` (atomic, Linux i_mmap_writable): the
  shared writable mappings (VM_SHARED, file open for writing, not
  `VM_NOMAYWRITE`), counted by the VMA link/unlink (mmap_lock held for
  writing) and held across an mmap's insertion (`map_writable`, EPERM
  once denied); F_SEAL_WRITE denies it for good under the inode's
  i_rwsem (`deny_writable`, EBUSY while one exists). memfd seals
  (`AddressSpace.seals`) are added under i_rwsem and read lock-free.
- A tmpfs mapping charges each page to its file system's block limit
  before inserting it (`AddressSpace.acct`, a per-CPU counter: 3.11
  tmpfs accounting) and returns it on removal; a charge near the limit
  takes the counter's leaf lock.
- Page allocation (`alloc_user`, may reclaim) happens with no
  spinlock held: writes under i_rwsem, faults under the mmap_lock read
  side (mmap_lock -> page lock -> i_pages).
- The cache holds one reference per page; a MAP_SHARED PTE holds its
  own, so truncate or eviction (dropping only the cache's) never frees
  a page a mapping still uses.
- `AddressSpace.i_mmap` (the anon_vma chain type, a sleeping RwSem;
  Linux i_mmap_rwsem): every VMA mapping the file, written by the VMA
  changes (link/unlink/relink) under the mmap_lock held for writing
  (mmap_lock -> i_mmap), read by truncate (`unmap_mapping_range`,
  under i_rwsem, with no mmap_lock: the chain keeps each listed VMA's
  page tables, since an unmap unlinks the VMA first) -> PTE lock.
  mremap holds it for writing across the entry move (Linux
  take_rmap_locks). A file fault maps its page under the page lock and
  rechecks i_size there; truncate sets i_size, unmaps, removes the
  pages under their locks and unmaps again.
- Writeback write-protects a page in every mapping of it before
  writing it (`mkclean`, Linux folio_mkclean): under the page lock,
  i_mmap read -> each PTE lock, a TLB flush per entry. The entry is
  write-protected by compare-exchange, keeping accessed/dirty bits the
  MMU sets meanwhile. The write fault
  that follows makes it writable and dirties it again under the page
  lock (mmap_lock read -> page lock -> PTE lock), so writeback never
  sees it writable but clean; then it may throttle (balance_dirty_pages
  writes the inode back: mmap_lock -> page lock -> i_mmap).
- Dirty, cached, unevictable and tmpfs pages are vmstat counters
  (`mm::vmstat::VmStat`, Linux vm_node_stat): each CPU's difference is
  a word only it writes, interrupts off, folded into the global atomic
  past the threshold (Linux calculate_normal_threshold); the dirty
  limits and /proc/meminfo read the global with one load. A CPU's
  dirtied pages since its last throttle check (`BDP_RATELIMITS`, Linux
  bdp_ratelimits) gate balance_dirty_pages to once per
  `RATELIMIT_PAGES`.
- Reclaim and drop_caches (`shrink_cache`, `drop_pagecache`) walk
  the cached inodes in place, allocating nothing: one inode reference
  at a time is taken under its inode-cache bucket lock (or the block
  device registry lock), then its clean pages are dropped with no lock
  held but each page's, taken with trylock (reclaim never waits for
  one); an unevictable mapping (ramfs) is never touched.
- Eviction (`Drop for AddressSpace`, the inode's last reference)
  truncates every page under its page lock, as any truncate (Linux
  truncate_inode_pages_final), before the inode's fields go: a page's
  `mapping` word is cleared only under its lock, so the holder of a
  page's lock that finds it in a mapping may use the mapping and its
  `host` inode, with no reference, until it unlocks
  (`filemap::folio_mark_dirty_lock`, Linux folio->mapping under the
  folio lock).
- Private data (`PG_private`, `Page.private`; Linux folio private):
  attached and detached under the page lock and `i_private_lock`
  (`folio_attach_private` takes a page reference for it). Truncation
  (`truncate_folio`, Linux truncate_inode_folio) calls the
  filesystem's ->invalidate_folio under the page lock, eviction from
  the cache (`evict_folio`, Linux mapping_evict_folio, and
  `invalidate_pages2`) its ->release_folio (`filemap_release_folio`;
  default try_to_free_buffers): the expected count is the cache's,
  the caller's and the private data's.

#### Buffer heads (fs/pageio/buffer.rs; Linux fs/buffer.c)

- A page's buffers (a ring through `b_this_page`, on the page's
  private word) are made under the page lock and attached under
  `i_private_lock` too (create_empty_buffers, grow_dev_folio); they
  are freed only by `try_to_free_buffers`, under both, when none is
  referenced (`b_count`), dirty or locked. So the page lock,
  `i_private_lock` or a reference on any buffer of the ring keeps the
  whole ring; `__find_get_block` looks up under `i_private_lock`
  alone (it may not sleep), the rest under the page lock.
- `AddressSpace.i_private_lock` (spin `Mutex`, thread context; Linux
  i_private_lock): page lock -> it -> `i_pages` (block_dirty_folio
  dirties every buffer and the page under it, so a ring attached
  meanwhile comes dirty and try_to_free_buffers never frees a dirty
  one) -> `MappingMetadataBhs.lock` (drop_buffers takes buffers off
  their list). Nothing sleeps or allocates under it (the ring is
  allocated before it is taken).
- Buffer lock (BH_Lock, a sleeping bit lock over `var_waitqueue`;
  Linux lock_buffer): held across a buffer's I/O; taken under the page
  lock (block_write_full_folio, discard_buffer, clean_bdev_aliases)
  or alone (bread, sync_dirty_buffer, write_dirty_buffer), never under
  a spin lock. Unlocked from the bio's completion (hardirq), which
  touches nothing of the buffer after the bit clears.
- `b_uptodate_lock` of a ring's first buffer (`IrqSpinlock` leaf;
  Linux): the async read and write completions (hardirq) of a page's
  buffers, so exactly one ends the page's read (unlocks it,
  folio_end_read) or writeback (folio_end_writeback); the page stays
  locked (read) or under writeback, so its ring stays, until then.
  hk's ->writepage is synchronous: it keeps the page locked and waits
  for the writeback to end (`PG_writeback`, the page's wait queue),
  where Linux unlocks it after submitting.
- mpage (`fs/pageio/mpage.rs`, Linux fs/mpage.c; vfat files): a page whose
  blocks are contiguous on the disk is read or written in one bio of
  its own, mapped under its page lock through a map buffer (a
  `BufferHead::new_map` value of the caller's, Linux an on-stack
  buffer_head, never shared); the bio's completion (hardirq) ends the
  page's read (unlocks it) or writeback. The synchronous ->writepage
  waits for the writeback to end under the page lock; its outcome,
  on the writer's stack, is written by the completion before that.
- A buffer's `b_size` is its block size, which get_block stores again
  (Linux map_bh) under the page lock, never another value.
- A buffer's `b_bdev` holds a `Weak` of its device, changed only while
  unmapped (page lock) or under the buffer lock: a locked, mapped
  buffer's is stable for its bio's submission. A buffer's I/O holds no
  reference on the device: its submitter keeps it (a mounted
  filesystem's `s_bdev`, or the caller across its wait).
- Per-CPU LRU of looked-up buffers (`lru::BH_LRUS`, an `IrqSpinlock`
  per CPU, leaf; Linux bh_lrus under local_irq_disable): each slot holds
  a reference; taken by its CPU's lookups (the lock replaces the
  interrupt masking), by any CPU's `invalidate_bh_lrus` to see whether
  it holds a buffer (`has_bh_in_lru`; Linux reads it unlocked) and by
  its CPU's call of it (a cross-CPU call on those CPUs, interrupts off,
  Linux on_each_cpu_cond), which kill_bdev and invalidate_bdev make
  first, so the pages' buffers can go.
- `MappingMetadataBhs.lock` (spin, thread context; Linux mmb->lock):
  the list of a mapping's metadata buffers (`b_assoc_buffers`, `b_mmb`)
  and a sync's private list (`mmb_sync`); a buffer's `b_mmb` is read
  without it under an RCU read guard (`remove_assoc_queue`,
  `mark_buffer_write_io_error`): the list's memory is freed a grace
  period after its last buffer left (`mmb_mark_buffer_dirty`'s
  contract, Linux's RCU-freed inode).
- A write error (`mark_buffer_write_io_error`, from the completion)
  reaches the page's mapping and its superblock's `s_wb_err` with no
  reference taken (`filemap::mapping_set_error_raw`): the buffer is
  locked, and an inode's teardown waits for every buffer lock of its
  pages (truncation's discard_buffer) before it drops `i_data` and
  then its superblock reference, which keeps the superblock. A list's (`MappingMetadataBhs`)
  mapping and superblock likewise, under the RCU read guard: its drop
  empties it, then waits a grace period before its `Weak` goes, and of
  its mapping only `wb_err` (no drop glue) is touched, valid while the
  mapping's memory is (an inode's `i_data` drops at its teardown, but
  its memory, and a vfat inode's list with it, goes a grace period
  after the eviction emptied the list).
- `mark_buffer_dirty` never sleeps: the page's mapping is reached under
  an RCU read guard (`filemap::folio_mapping`: a mapping is part of an
  inode freed by RCU) for its count and DIRTY mark (`i_pages`); the
  inode is queued for writeback after the guard drops.

### 3.3 Virtual File System (VFS)

**Location:** `fs/`

The VFS uses fine-grained locking with `RwLock` for concurrent read access.
**All VFS locks are NOT IRQ-safe** and must only be accessed from thread context.

#### Global Structures

| Variable | Type | Purpose |
|----------|------|---------|
| `DCACHE` | `DentryCache` (contains `RwLock`) | Dentry cache root |

#### Descriptor Tables (Linux files_struct)

**Location:** `task/fdtable.rs`, `task/fdbits.rs` (`FdTable`, `Fdt`)

The last `Arc<Files>` closes every descriptor, whoever drops it (a
/proc reader too; Linux put_files_struct): its drop flushes and may
sleep, so a `Files` reference is never dropped under a spin lock
(the task's is swapped out under alloc_lock and dropped after it).
`Files.users` counts the tasks using the table (Linux
files_struct.count) and decides sharing for exec and unshare.

`Files` (one per task, shared by CLONE_FILES) wraps the table's
`spin::Mutex` (Linux `files->file_lock`), thread context only, a
leaf: **nothing is allocated, flushed or closed under it**. The table
(`task/fdbits.rs`: `Fdt`, Linux struct fdtable) is a fixed array of
`max_fds` slots with its open, close-on-exec and full bitmaps, all
allocated with the lock dropped:
- A new descriptor (`UnusedFd::alloc`, Linux alloc_fd) is reserved
  under the lock (open bit set, slot empty: invisible to lookups,
  close and fork's copy; dup2 onto it is EBUSY) and its file installed
  in a later hold (`UnusedFd::install`, fd_install); an `UnusedFd`
  dropped unused releases it (put_unused_fd). When the table is too
  small (`expand_files`, Linux expand_files/expand_fdtable) one task
  sets `FdTable.resize_in_progress` under the lock, drops it,
  allocates the bigger `Fdt` (ENOMEM; EMFILE past fs.nr_open), retakes
  it, moves the descriptors over, clears the flag and frees the old
  table (or the new one, if not needed after all) after the unlock,
  then wakes `Files.resize_wait` (a wait queue,
  woken with no lock held); a task that finds the flag set sleeps
  there (uninterruptible, Linux wait_event), its condition read under
  the lock, and looks again. The allocation is then retried.
  dup2/dup3 (`Files::dup3`, Linux ksys_dup3, do_dup2) grow the same
  way, then swap the file in under one hold.
- Fork and unshare (`dup_fd`) allocate the copy's table first, sized
  by the last open descriptor (Linux sane_fdtable_size); while the
  source outgrows it they drop the lock and allocate again. The copy
  takes a reference per installed file (an atomic count) under the
  lock; reserved descriptors are free in it.
- Closing detaches a file under the lock (`close_next`, `close_fd`,
  `take_cloexec`: Linux file_close_fd_locked) and flushes it after the
  unlock (`filp_close`: the closer's POSIX locks go, then the
  reference is put); close_range, exec's close-on-exec and the last
  reference's close of every descriptor (Drop for `Files`, Linux
  close_files) take one descriptor per lock hold, walking the bitmaps.
  close(2) releases its file with `fput_close_sync`, the replaced file
  of a dup2 is closed after the unlock.
- /proc/<pid>/fd and fdinfo listings look up one descriptor per hold
  (`next_installed`, Linux fget_task_next) and emit with no lock held.
Files looked up with `get` are clones taken while the table holds its
own reference, so dropping them under the lock is never the last
reference.

**Lookups under RCU** (Linux fdget, __fget_light, __fget_files_rcu):
the slots (`util/rcuslots.rs` `Slots`, Linux fdtable->fd) are an
array of file pointers that readers load under an RCU read guard with
no lock. They are written only under the table's lock, through their
one `SlotsOwner` (install, close, dup2: Linux rcu_assign_pointer).
A table that grows copies its pointers into the bigger slots, which
`Files.slots` (`RcuSlots`, Linux files->fdt; a reader borrows it for its guard only) publishes before the
lock is released; the old slots keep their pointers as stale copies
and are freed a grace period later (`RcuRetired::defer`, Linux
free_fdtable_rcu). `Files::fget` takes a reference from a slot unless
the file's count is zero, then checks that the slot and the
published slots are unchanged (Linux __get_file_rcu: the memory may
hold a newer file by then), else drops it (a put, never sleeping)
and looks again. `fdget_raw` (the path walk's dirfd, Linux
path_init's fdget_raw) does that for a table other tasks use
(`Files.users` > 1) and, for one only the caller uses, borrows the
file with no reference: only its own task changes such a table, and
the caller promises not to close the descriptor or share or change
the table while it holds the result (its `# Safety`). What makes the
RCU read safe is the file cache: SLAB_TYPESAFE_BY_RCU, so a file's
memory stays a file object, its count readable, until a grace period
after it is freed, while it may be reused at once (below).

**File references and release** (`fs/file.rs`; Linux
fs/file_table.c): a `FileRef` counts one reference in `File.f_count`
(Linux f_ref, an atomic: taken and dropped lock-free from any
context; `FileRef::try_get` takes one from a file's address unless the
count is zero, Linux file_ref_get, for a caller that keeps the memory a
file object: epoll under `Eventpoll.mtx`, which the file's release
needs before it frees the file, or an RCU reader). The last reference's drop (`fput`)
never releases the file itself: it queues the release (`__fput`,
which may sleep and takes the file's own locks, epoll's
`Eventpoll.mtx`, socket locks...) on the current task's task_work
(`Twa::Resume`, run on its way back to user mode with nothing held),
or, from interrupt context, a kernel thread or a task past
`exit_task_work`, on `DELAYED_FPUT` (IrqSpinlock leaf; a list of the
files' embedded callback heads, never allocating) drained by a
delayed work item on `SYSTEM_WQ` one tick later (queued after the
lock is released: `Workqueue.inner`), under `DELAYED_FPUT_RUN`
(sleeping, outermost: 2). So a `FileRef` may be dropped under any
lock, spin or sleeping, in any context. Only close(2) releases inline
(`fput_close_sync`, Linux the same), with no lock held. The release
drops the file's fields, in Linux __fput's order: its filesystem's
per-open data and write accesses (put_file_access) before the dentry
and mount (dput, mntput), so no inode reference of the file outlives
its mount reference, and gives its memory back to the file cache at once
(`file_free`, Linux kmem_cache_free(filp_cache)): every file is a
`FileObj` of `FILP_CACHE` (`File::alloc`, the one way to a `FileRef`),
whose count stays 0 there and is set last, Release, by the next file
put in that memory (Linux init_file), so a reader that loaded the old
address finds no count to take, or a newer file's, which its recheck
of the slot tells apart. Exit runs the
task's queued releases (`exit_task_work`) after it dropped its
descriptors, fs context, namespaces and address space, before a parent
can see it exited; boot runs pid 1's and the delayed list's after
unpacking the initramfs (`init_flush_fput`).

#### Per-Object Locks

**Inode** (`fs/inode.rs`):
```rust
pub struct Inode {
    size: AtomicU64,      // i_size: Release under i_rwsem, Acquire lock-free
    i_rwsem: RwSem,                                // Dir ops, file write/truncate
    pub private: RwLock<Option<Arc<dyn InodeData>>>, // FS-specific data
}
```

**Inode cache** (`fs/icache.rs`, Linux inode_hashtable): vfat inodes
(by directory entry; its `test` also requires the entry still set,
i_pos, so it doubles as Linux fat's position hash: an unlinked or
replaced inode, detached, stays hashed until its eviction, as in
Linux's VFS hash, but is never found) are hashed so each on-disk
object has one `Inode`, the vfat root too (found by no lookup), block devices' inodes on the bdev superblock by device
number, so a device is found by its number (3.10), and a tmpfs inode
by number plus generation once a file handle of it is made
(`insert_inode_hash_once`, checked and hashed under the lock; Linux
shmem_encode_fh's own spin lock), so open_by_handle_at finds it
(`ilookup5`, then its dentry under `Inode.i_lock`). A RAM-sized table of buckets, each an `InodeList` through the
inode's embedded `i_hash_node` (no reference per entry, nothing
allocated: an inode is unhashed under the lock by its eviction at the
latest, so a linked one is live memory), all under one `INODE_HASH_LOCK` (spin Mutex, Linux
inode_hash_lock, thread context): under it only the bucket links and
the filesystem's `test` (which may take `Inode.private`, a spin
RwLock, then vfat's `VfatInode.d`, a spin Mutex leaf held only to copy
the data in or out), and a candidate's `i_lock` (igrab's slow path,
Linux find_inode's spin_lock(&inode->i_lock)), as every hash, unhash
and rehash (one hold for a rename's move) takes the inode's `i_lock`
(Linux __insert_inode_hash, __remove_inode_hash), so its hashed state
is exact under `i_lock` (`__mark_inode_dirty` queues only a hashed
inode, or a block device's). Not IRQ-safe: an inode's last reference never goes
in an interrupt handler (pinned pages and files are released in thread
context: `PinnedPages`, `fput`), which lockdep checks (a tracked lock
taken in an interrupt handler is reported). A lookup (Linux
find_inode) runs `test` on each candidate before taking a reference,
then grabs the match (`Inode::igrab`), so no reference is dropped
under the lock (a last reference's eviction takes it); an entry in its
teardown (Linux I_WILL_FREE / I_FREEING: its last reference gone, its
teardown writing it back or evicting it while still hashed) fails the
grab, and the
lookup queues on the dying inode's address's hashed wait queue
(`var_waitqueue`, Linux bit_waitqueue) under the lock, drops it and
sleeps once (Linux __wait_on_freeing_inode; `INODE_HASH_LOCK` -> that
queue's lock), woken by the eviction after its unhash under the lock
(Linux wake_up_bit(__I_NEW)), then searches again: a lookup may sleep, so
its callers hold no spin lock (vfat's hold its directory's `i_rwsem`,
which no writeback or eviction takes). Eviction (`iput` ->
`iput_final` -> `evict` -> `icache::evict`, Linux the same) runs where
the last reference goes, which must be a context that may sleep (Linux
iput's might_sleep, checked first): never under a spin lock or with
interrupts off. A linked, hashed inode (Linux inode_generic_drop
false) is marked I_WILL_FREE and written back first with
`i_lock` released (nothing for a clean one), then marked I_FREEING:
with wait once its superblock is shut down (Linux write_inode_now(1)
for one not kept, !SB_ACTIVE, which `generic_shutdown_super` clears
after its sync_filesystem, as Linux); while it is active, WB_SYNC_NONE,
as Linux's flusher writes the inode it keeps on its LRU (hk keeps
none); then
it leaves its writeback list (under the list lock and `i_lock`, then
waiting for I_SYNC under `i_lock`, Linux inode_wait_for_writeback: a
writer holds a reference, so there is none) and its superblock list,
`->evict_inode` runs while it is still hashed (may sleep and do I/O:
vfat frees an unlinked file's clusters at once, Linux
fat_evict_inode), and `INODE_HASH_LOCK` is taken to unhash it, the
waiters woken after (Linux evict's remove_inode_hash, wake_up_bit). An
inode's superblock (`Inode.sb`, Linux i_sb) is a passive reference
(`Arc`, Linux s_passive: Linux takes none per inode, its plain pointer
staying valid by the order below), which keeps only the memory, so
its drop, the teardown's last, never shuts the filesystem down (it
takes `SB_LOCK` if it is the last, so none is dropped under that
lock). The superblock is there for the inode's whole life, and so is
the data of a filesystem whose inodes borrow it (vfat): the shutdown
evicts every inode before ->put_super, which releases the data
(`SuperBlock::kill_fs_info_rcu`, Linux call_rcu) unless an inode is
still listed (busy, below). The shutdown
belongs to the last active reference (`SbActive`, Linux s_active:
each mount's, devtmpfs's): its drop (Linux deactivate_super) takes
s_umount for writing and runs `generic_shutdown_super` (inotify
watches; the dentry tree, whose drop evicts the inodes its dentries
held; sync_filesystem; ->put_super, which puts the filesystem's own
inodes; then any inode left on s_inodes is a bug, reported as Linux's
"Busy inodes after unmount", which fails a boot test: one referenced
past its superblock's end, which nothing that pins the filesystem (a
mount, an open file, a writeback pass under s_umount, a walk under
s_umount) leaves, and no pinned page does (a pin holds the page, not
its inode). Nor does any put an inode during the shutdown, so none is
mid-eviction (off s_inodes, in ->evict_inode) when put_super's
release runs: every inode reference is held under a mount, an active
reference or s_umount and put before it (a file's write access and
per-open data before its dentry and mount, Linux __fput; a bound
AF_UNIX socket's path, mount included, Linux u->path; a link level's
inode before its path; writeback's under s_umount; the s_inodes walks'
under s_umount), an inotify watch's is waited for by the shutdown
(`s_fsnotify_watched`, Linux fsnotify_sb_watched_objects), and no
inode's RCU-freed data holds another inode (tracefs reads its root
through the superblock). Linux relies on this with no check (no count
of evictions in flight; its ->evict_inode would use what put_super
freed); hk's `evict` panics ("VFS: inode evicted across its
superblock's shutdown") if, after ->evict_inode, it finds its
superblock shut down (SB_BORN and SB_DYING), so an overlap that ran
past the shutdown is caught rather than left a silent use after free. Each busy inode is poisoned, as Linux, under the
s_inodes lock and its `i_lock`, in the one pass that finds it (`inode::sb_poison`: `I_POISON` stands
for VFS_PTR_POISON in i_op, i_sb and i_mapping, so `Inode::i_op`,
`Inode::superblock` and `Inode::i_mapping` panic "VFS: poisoned
inode" on any later use, its eviction too), and put_super left
the data: a borrow of it taken before the poison
(`msdos_sb_of`) stays valid, the data going with the superblock's
memory, which that inode keeps (Rust analogue of Linux's poison,
where such a borrow would be a use after free; with no busy inode
the release runs as Linux's call_rcu callback, a grace period on))
and the
device's release, in
thread context with nothing atomic held (mount teardown drops its
reference after MOUNT_LOCK and NAMESPACE_SEM): `might_sleep` there
reports one that does not. Deviation from Linux: no
unused-inode LRU or I_NEW state (an inode is complete before it is
hashed; the losing builder's inode is dropped unhashed).

**Inode references** (`fs/inode.rs` `InodeRef`, `Inode.i_count`,
`Inode.i_state`, `Inode.i_lock`; Linux i_count, i_state, i_lock, iput,
igrab, ihold): a holder's reference is one count of the atomic
`i_count`. ihold (a clone) adds one; iput (a drop) takes one lock-free
unless it is the last (atomic_add_unless(-1, 1)), and otherwise takes
`i_lock`, drops the count to zero under it and, still under it, marks
the inode I_FREEING (or I_WILL_FREE first, for a writeback before the
eviction: `iput_final`), then releases it before the eviction, which
sleeps. `Inode::igrab`, for an inode borrowed with no reference (an RCU
walk's `d_inode`, an entry of an `InodeList` under its lock), adds one
lock-free while the count is above zero, else takes `i_lock` and adds
one only if neither I_FREEING nor I_WILL_FREE is set (Linux igrab,
__iget): since those bits are set under `i_lock` in the same hold that
dropped the count to zero, no reference is taken to an inode in its
teardown, and the teardown runs once. `i_state` is written only under
`i_lock` and read lock-free (Linux inode_state_read_once): its writers
and `Inode::__iget` take the lock's `ILocked` borrow and assert it is
this inode's (`Inode::assert_locked`), `__iget` that neither bit is
set. `i_lock` is
a spin leaf above the d_locks (it guards the inode's dentries too,
Linux i_dentry): taken by igrab under `INODE_HASH_LOCK`,
`SuperBlock.s_inodes` or a `BdiWriteback.list_lock` (Linux:
inode_hash_lock, s_inode_list_lock and wb->list_lock before i_lock),
and never held while any of those is taken (iput_final drops it before
the eviction takes them). Every put may sleep (Linux iput's
might_sleep, checked on each put, not only the last): no reference is
put under a spin lock or in an interrupt handler, so a lookup under a
spin lock compares a dentry's inode without taking one (unix
`find_bsd`, Linux d_backing_inode), and an asynchronous direct I/O,
which may end in an interrupt handler, borrows the inode of the file
its request holds (vfat `VfatAio`, Linux struct dio's inode).

**Inode free** (`fs/inode.rs` `destroy_inode`, `i_callback`; Linux
evict -> destroy_inode -> call_rcu(&inode->i_rcu, i_callback)): the
whole teardown runs synchronously where the last reference goes, as
above: the eviction, then every field with drop glue
(`destroy_inode`: the page cache, Linux truncate_inode_pages_final;
inotify marks, file locks, the writeback state, the filesystem data, a
FIFO's pipe, and the superblock's passive reference last), each a
`ManuallyDrop` dropped through a raw pointer. Only the memory waits:
`i_callback`, queued on `i_rcu` after the teardown (no field is
touched after it), frees the block in `rcuc/N` a grace period later,
which never sleeps and takes no lock. So an RCU reader that reached an inode with
no reference (a dentry's `d_inode`) may read it until its guard ends,
a torn-down one included, but only its fields with no drop glue
(atomics, `ino`, `i_op`; Linux's RCU walk reads i_mode, i_uid, i_op
the same way), never one a teardown releases (`private`, `i_data`,
`sb`). A symlink's `i_link` (Linux inode->i_link) and a file
system's `private_rcu` data are set once before
the inode is visible (`set_link`, a `spin::Once`) and dropped only by
`i_callback`, a grace period after the teardown, so an RCU walk reads
it too. No lock is added.

**Superblock inode lists** (`fs/inode.rs`; Linux s_inodes,
inode_sb_list_add/del): every inode made with `Inode::alloc` is on its
superblock's `s_inodes` (an `InodeList` through `Inode.i_sb_list`,
holding no reference) until
its eviction (`evict`) unlinks it, under the list's own lock (`SuperBlock.s_inodes`, a spin Mutex leaf, thread
context; Linux s_inode_list_lock): the inode's superblock reference
keeps the lock's memory, and the shutdown evicts every inode while the
superblock runs (Inode cache, above). Unlinked as Linux evict's
inode_sb_list_del: after the writeback list, before ->evict_inode, so
an inode mid-eviction is not listed; none is when the shutdown's busy
check runs (Inode cache, above: nothing puts an inode during the
shutdown). Taken by an inode's eviction, with nothing held, by vfat's
put_super (`kill_fs_info_rcu`'s `sb_busy`) and by the shutdown's busy
check, which poisons in the same pass (`sb_poison`); under it only an inode's `i_lock` (igrab's
slow path, the poison bit). The
reclaim and drop_caches walks and the inotify shutdown
(`for_each_sb_inode`, Linux drop_pagecache_sb, fsnotify_unmount_inodes)
take each inode's reference under it (`Inode::igrab`) and work with it
released, dropping the previous reference unlocked.

**vfat FAT lock** (`fs/vfat/fatent.rs`, Linux fs/fat/fatent.c):
`VfatSbData.fat` (sleeping `sync::Mutex`, Linux sbi->fat_lock /
lock_fat), one per filesystem, thread context only, serializes a
free cluster's search and claim (`fat_alloc_clusters`), freeing a
chain (`fat_free_clusters`, an unlinked file's from its eviction
included) and the free count (`FatState.free`, Linux
sbi->free_clusters: counted by the first statfs,
`fat_count_free_clusters`, then kept by both). Taken under the inodes'
`i_rwsem` (write, truncate and fallocate paths), under a file page's
lock too where fat_get_block allocates the cluster a write reaches
(->write_begin; Linux fat_add_cluster under the folio lock: page lock
-> FAT lock), or from an eviction (an unlinked file's chain, a linked
one's fallocated clusters past mmu_private: fat_free_eofblocks).
Under it the FAT's blocks are read (`bread`: page lock, buffer lock,
block I/O) and changed in their pinned buffers, which go on the FAT
inode's metadata list (`MappingMetadataBhs.lock`, spin leaf; Linux
MSDOS_I(sbi->fat_inode)->i_metadata_bhs, which fsync writes) and are
copied into the other FATs (`fat_mirror_bhs`: buffer lock) by
`fat_free_clusters` under it and by `fat_alloc_clusters` after it is
released, as Linux. A claimed cluster is zeroed after it is released;
never held with `VfatInode.cache` or `VfatInode.d`. A single entry read
or written outside it (a chain walk, `fat_ent_link` linking a new
cluster, `fat_free` writing a new end; Linux fat_ent_read /
fat_ent_write) changes only its own inode's chain, which that inode's
`i_rwsem` keeps; an entry's four bytes are copied in and out of the
pinned buffer, so writers of other entries of the block never clobber
it.

**vfat entry location lock** (`fs/vfat/mod.rs`, Linux
sbi->inode_hash_lock over i_pos): `VfatSbData.ipos` (spin `Mutex<()>`
leaf but for `Inode.private` and `VfatInode.d` taken to copy an
inode's data), one per filesystem, thread context only. Every inode's
`VfatInodeData.i_pos` (its short entry's disk offset, 0 for none)
changes under it (`attach`, Linux fat_attach; `fat_detach`, i_pos 0:
an unlink's after its entry is removed, a replaced object's before
rename reuses its slot). An entry is patched under it in its block's
buffer, read (bread) and pinned before it is taken and marked dirty
after it is dropped: `fat_write_inode` (Linux __fat_write_inode,
which rechecks under it that i_pos is still the one whose block it
read, else reads again, and marks the inode I_METADATA_WRITEBACK under
its `i_lock` after) and rename's `write_entry`, so a write never lands
on a slot its inode no longer owns. Only the entry's fields past the
name are written, so a removal's deleted mark (`fat_remove_entries`,
under the directory's `i_rwsem`, no `ipos`, as Linux) is never put
back; a slot is reused only under that `i_rwsem`, after the detach.
Order: `i_rwsem` -> page and buffer locks (the bread) -> `ipos` ->
`Inode.private` -> `VfatInode.d`; nothing sleeps under it; never with
`VfatSbData.fat`.

**vfat superblock data** (`fs/vfat/mod.rs`, Linux msdos_sb_info in
s_fs_info): `VfatSbData` is the superblock's `s_fs_info` (Superblock
lists below), set by the fill before it makes any inode and released
by put_super (`fat_put_data`, Linux fat_put_super: iput of the FAT's
inode, evicted while the data is there, then call_rcu of the rest:
`kill_fs_info_rcu`, kept with the superblock's memory if an inode is
busy, which the shutdown then poisons), or by a fill that fails after
setting it (Linux out_fail: the same, every inode it made put, none
reachable but by it), in thread context. So an
operation reaches the data from its inode with no reference or lock
(`msdos_sb_of`, Linux MSDOS_SB(inode->i_sb): `SuperBlock::fs_info_ref`,
through `Inode::superblock`, which panics on a poisoned inode), as
statfs does through its mount's active reference. `VfatSbData.fat_inode`
(`FatInode`, Linux sbi->fat_inode) holds one reference from the fill
to put_super, borrowed with no lock taken: the FAT's blocks are put on
its metadata list.

**vfat directory blocks** (`fs/vfat/mod.rs`, Linux fs/fat/dir.c): a
directory is walked block by block in the device's buffers
(`dir_walk`, Linux fat_get_entry: bread, each cluster read ahead) and
its slots changed in them, under its `i_rwsem` (a rename's: both
directories'); a changed block goes on that directory's metadata list
(`VfatInodeRcu.i_metadata_bhs`, Linux i_metadata_bhs, which its
->sync_inode_metadata and eviction write; `MappingMetadataBhs.lock`,
a spin leaf), a moved directory's ".." block on the moved one's. The
list is in the inode's RCU data (`Inode::private_rcu`), dropped a
grace period after the eviction emptied it (Linux frees the inode by
RCU), so its drop need not wait one (`rcu_passed`); a completion's
write error reaches only the directory mapping's `wb_err`, in that
memory still. A
dirsync change writes and waits for exactly the buffers it changed
(sync_dirty_buffer, fat_sync_bhs: buffer lock, no other lock held),
where Linux does.

**vfat chain cache** (`fs/vfat/cache.rs`, Linux fs/fat/cache.c):
`VfatInode.cache` (spin Mutex, Linux cache_lru_lock), a leaf in
thread context only, never held with `VfatInode.d` and never across
the FAT reads. It holds the cached runs, their id (Linux
cache_valid_id) and the chain's first cluster, a copy of
`VfatInodeData.start_cluster` that `set_start` updates after the
data. A walk (fat_get_block under a page lock: reads, writeback,
->write_begin; direct I/O, ->bmap at swapon, the write and truncate
paths under `i_rwsem`) takes, in
one hold, the first cluster, the id and its starting run, so the three
always belong to one chain; it reads the FAT through the device cache
with no lock held, then caches its run only if the id is unchanged. A
new first cluster invalidates the cache (bumping the id); a cut that
keeps the first cluster (`fat_free`, under `i_rwsem`) invalidates it
before touching the FAT and again once the new end is written, before
the tail is freed: a walk that began before the second invalidation
caches nothing, and one that begins after it stops at the new end, so
no cached run can name a freed cluster. Walks that use what they find
for I/O and can race a cut: writes, truncate and direct I/O are
excluded by `i_rwsem`; page-cache reads past a shrinking end are the
pages truncate drops first (`truncate_setsize` before `fat_free`),
which discards their mapped buffers (block_invalidate_folio), so no
buffer names a freed cluster.

**vfat mmu_private** (`VfatInode.mmu_private`, Linux mmu_private):
the bytes allocated and initialized, changed only under the inode's
`i_rwsem` (cont_write_begin's zeroing and fat_get_block's allocation
from ->write_begin, truncate, a failed write) and read under it (the
direct I/O checks; fat_bmap with `create`, which only the write paths
pass for blocks past the size), or by the eviction, which nothing
else reaches (fat_free_eofblocks). An atomic only so the shared inode
can hold it; `i_rwsem` orders every access.

**Dentry** (`fs/dentry.rs`):

Following Linux's `d_lock` pattern, each dentry has a single RwLock protecting
all mutable state; the parent pointer is written under it and read
lock-free, and the name has its own leaf lock:

```rust
pub struct Dentry {
    pub sb: Weak<SuperBlock>,   // Immutable after creation
    d_count: AtomicUsize,       // DentryRef count (Linux d_lockref.count)
    d_parent: AtomicPtr<Dentry>, // A reference (Linux d_parent); d_lock
    d_rcu: RcuHead,             // The free after a grace period
    d_seq: SeqCount,            // Linux d_seq; writers hold d_lock (write)
    d_inode: AtomicPtr<Inode>,  // Linux d_inode; d_lock (write) + d_seq, read lock-free
    d_flags: AtomicU32,         // DCACHE_MOUNTED; d_lock (write), read lock-free
    d_sib: Link, d_sib_owner: Owner, // Parent's children (its d_lock)
    d_hash: Link,               // Hash bucket (its bit lock); linked = hashed
    d_hkey: AtomicU64,          // Hash key (parent's d_lock, before hashing)
    d_time: AtomicU64,          // Linux d_time: set by its lookup before hashing, read lock-free
    d_name: DNameSlot,          // Linux d_name; d_lock (write) + d_seq, read lock-free
    d_alias: Link,              // Its inode's i_dentry (that lock)
    d_lock: RwLock<DentryInner>, // Single lock (like Linux d_lock)
}

struct DentryInner {
    children: OwnedList<SibAdapter, DentryRef>, // Linux d_children
}
```

`d_seq` (Linux d_seq, a `SeqCount`) is written only under the
dentry's d_lock held for writing: a write section (plain increments,
1.4.1) surrounds setting or clearing its inode (`add`: Linux
__d_instantiate / __d_add; `d_delete` and `dentry_kill`: Linux
dentry_unlink_inode) and a move's parent and name change (`__d_move`,
both dentries' sections nested inside all four d_locks); leaving the
tree (`__d_drop`, the one helper for every unhook) moves it on by two
(Linux write_seqcount_invalidate). `d_flags` (Linux d_flags) bits are
changed with plain stores under the d_lock held for writing and read
with no lock (Acquire, Linux READ_ONCE): `is_mountpoint`. A dentry is
hashed (Linux !d_unhashed: `d_hash` linked, `Link::is_hashed`) exactly
while it is in the tree; every hash and unhash holds its d_lock for
writing, so `d_unhashed` is exact under it and otherwise a lockless
snapshot (an RCU reader confirms it by `d_seq`). A root, a pseudo
filesystem's dentry and an O_TMPFILE file's are never hashed;
`d_unlinked` (unhashed and not a root, Linux d_unlinked) is what
d_path's " (deleted)", getcwd and pivot_root test.

`d_inode` (Linux d_inode) is an atomic pointer owning the dentry's
`Arc` of its inode (`Arc::into_raw`, null when negative): set and
cleared under the dentry's d_lock held for writing inside a `d_seq`
write section (Release), the reference dropped after the locks.
`is_negative` is one Acquire load; `d_inode_rcu` borrows the inode for
an RCU read guard with no lock and no reference (Linux
READ_ONCE(dentry->d_inode)), sound because a writer clears the pointer
before dropping its reference and the inode's memory is freed a grace
period after its teardown (Inode free, above), so the reader may read
its fields with no drop glue only; `get_inode` takes a reference from
that with `Inode::igrab` (Linux igrab: refused once the last reference
went, which happens only after the pointer was cleared), so neither
stores to the dentry's lock word.

A dentry is held through `DentryRef` (Linux dget/dput on d_lockref):
the tree's two references, each child's `d_parent`, and every
holder's. The last holder's put of a hashed dentry its filesystem
keeps no unused copy of (`DentryOps::d_delete`, Linux retain_dentry:
a negative one of ramfs, tmpfs, devtmpfs, tracefs, procfs; a procfs
/proc/sys/net entry of a namespace that is going, proc_sys_delete,
its `SysctlSet` unregistering flag, read with no reference) first takes
it out of the tree as the shrinker does (`d_delete_unused` ->
`prune_one`: the parent's d_lock, then its own, both written; the
tree's references put after them), so no reference to a hashed dentry
is put under a d_lock. The last put kills it (`dentry_kill`, Linux
__dentry_kill: its inode and parent let go there, the parents it
alone held in a loop, as Linux dput) and frees its memory a grace
period later
(`call_rcu`, Linux dentry_free's __d_free), leaving `d_parent` in
place: an RCU reader may follow `d_parent` and read `d_name` of a
dentry it holds no reference to, and takes one with
`DentryRef::try_get` (Linux lockref_get_not_dead), refused once the
count is zero. The free runs in `rcuc/N` (1.4.2) and only releases
memory. `d_parent` changes under the dentry's d_lock (write; with
RENAME_LOCK once it is in the tree: d_move, d_exchange), a Release
store read with Acquire (Linux WRITE_ONCE/READ_ONCE of d_parent);
`get_parent` (Linux dget_parent) takes its reference under the
dentry's d_lock.

The tree is Linux's shape: a parent's children are an intrusive list
(`util::list::OwnedList`, Linux d_children/d_sib) under the parent's
d_lock, owning a reference to each child, and a child is found through
the global `DENTRY_HASHTABLE` (Linux dentry_hashtable): a power of two
of `util::hlist_bl` buckets, one word each with a bit lock in bit 0
(Linux hlist_bl_lock), sized by `dcache_init` from RAM like
alloc_large_system_hash (one per 8 KiB) before mnt_init, each bucket
holding a reference to its entries. The key is the name's hash, a
SipHash under a per-boot random key (`name::name_hash`, so colliding
names cannot be built offline), salted with the parent (Linux
full_name_hash's salt). A dentry is in the tree
exactly when it is on its parent's list and in its bucket: both are
added (`hash_in`) and removed (`hash_out`) together, under the parent's
d_lock held for writing, the bucket lock taken inside it (and inside
the child's d_lock where that is held: d_drop_tree). Nothing allocates
to add or remove a child. Order: RENAME_LOCK -> d_lock (parent, then
child) -> bucket lock (one bucket at a time, a spin lock to the
preempt count and lockdep, one class; a leaf).
`d_lookup` (Linux d_lookup, __d_lookup; `Dentry::lookup_child`) holds
no d_lock: it walks the bucket once under an RCU read guard with no
lock, and checks a candidate whose key and parent address match under
the candidate's own d_lock (read; Linux spin_lock(&dentry->d_lock)):
still a child of the parent, hashed, the name matching (a
filesystem's `DentryOps`, Linux d_hash/d_compare, hash and compare
where names match more than their bytes: vfat, without case or
trailing dots; procfs, a namespace's /proc/sys/net entry only for
that namespace's tasks; given the candidate, read as an RCU reader
would; no lock of their own), then takes its reference there
with `DentryRef::try_get` (Linux d_lockref.count++, refusing a dying
one). So `Dentry::add` and `d_delete`, which decide on a child's
count under that child's d_lock (write), see every lookup's
reference. That is sound: dentries are freed a grace period after
their last put and published with Release stores; the key and parent
address are atomics; the name is read with no lock (`DNameSlot`,
below) and whole under the candidate's d_lock, which every name
writer holds. A walk standing on a dentry a rename moves to
another bucket follows it there and may miss; only d_move/d_exchange
rehash, under RENAME_LOCK, so `d_lookup` repeats a miss while
RENAME_LOCK's sequence moved (read_seqbegin / read_seqretry, as
Linux). Adding or dropping a child (`add`, `d_delete`,
`remove_child`) looks up under the parent's d_lock (write) with
`d_lookup_locked`: one walk under the bucket lock, exact, since every
hash writer holds it (Linux __d_add and d_alloc_parallel decide under
hlist_bl_lock). `__d_lookup_rcu` (Linux __d_lookup_rcu, for the RCU
path walk) takes no lock and no reference and stores nothing: under
the caller's RCU read guard it walks the bucket and reads each
candidate's parent, key, name and hashed state after a raw `d_seq`
sample (Linux raw_seqcount_begin, `SeqCount::raw_begin`: an odd count
comes back even and fails the later check), the name read whole and
checked against the sample before a filesystem's `d_compare` runs
(Linux __d_lookup_rcu_op_compare); it returns the hit with the sample,
which the caller checks (`Dentry::d_seq_retry`) before trusting what
it read and again after taking a reference (`DentryRef::try_get`;
Linux legitimize_path). A walk
that misses during a rename (`__d_lookup_rcu` in an RCU walk, `cached`
without the directory lock) is fine: lookup_slow rechecks under
i_rwsem.

A name (`fs::name::DName`, Linux qstr over d_shortname or an
external_name) is inline below `DNAME_INLINE_LEN` (40) bytes, else a
refcounted `ExternalName` block allocated, fallibly, when the dentry
is made, before any lock. A dentry keeps it in a `DNameSlot` (Linux
d_name over d_shortname / external_name): the hash, the length, the
long name's block pointer and the short name's words, each an atomic,
so a reader with no lock gets a picture a rename may tear but never
reads out of bounds. Only `__d_move` writes it, under the dentry's
d_lock (write) inside its `d_seq` write section, with the dentry out
of every bucket; so it is whole under that d_lock or under a bucket
lock the dentry is in (`d_lookup_locked`), and otherwise checked by
`d_seq` (`Dentry::name`, Linux take_dentry_name_snapshot, repeats
while it moved) or by RENAME_LOCK's sequence (d_path, dentry_path:
Linux prepend_name). A long block a move replaces is let go a grace
period later (`put_rcu` on its `RcuPuts`: several dentries may give
one block up within a grace period; Linux copy_name's kfree_rcu): the
callback drops one count, and the last frees the bytes, which never
sleeps. `Dentry::name` returns a snapshot (Linux
take_dentry_name_snapshot: a byte copy or a reference) and a rename
moves names by copy or reference (copy_name, swap_names), so no name
is allocated under RENAME_LOCK or a d_lock. `d_move` takes the target
dentry: the replaced one, a cached negative one, or one the rename
preallocates (`Dentry::prealloc`) before calling the file system, so
an ENOMEM comes before any change.

A rename moves the dentry itself (`d_move`, `d_exchange`) under the
global `RENAME_LOCK` (write; Linux rename_lock), with both parents'
`i_rwsem` held by the caller, as Linux __d_move: both parents'
d_locks (the one that is an ancestor of the other first, `d_ancestor`;
otherwise the target's parent first; one when they are the same), then
the moved dentry's, then the target's, all held for the whole switch,
inside both dentries' `d_seq` write sections; whoever else takes two
d_locks takes a parent before its child, so this order meets no cycle.
Nothing is allocated or dropped last under them. The
write guard keeps the lock's sequence odd, which scoped walks check.
`is_subdir`, `dentry_path` and `d_path` read parents and names as
Linux does (read_seqbegin_or_lock, `SeqLock::read_or_lock`): a first
pass under an RCU read guard with no lock (`Dentry::parent_rcu`, the
`d_parent` load; dentries and mounts are freed a grace period after
they go, so whatever the pass reaches stays readable), trusted if
RENAME_LOCK's sequence did not move, else a second pass under its
locking read (exclusive, Linux read_seqlock_excl), which always
finishes. `d_path` also climbs mounts (`Mount::up_rcu`:
`Mount.mnt_parent`, then `Mount.mnt_mountpoint`, plain loads; the
root compared by address, `Mount::root_addr`, readable after the
teardown), checked the same way against MOUNT_LOCK's sequence, the
outer one (Linux prepend_path's order): MOUNT_LOCK -> RENAME_LOCK ->
d_lock; nothing takes MOUNT_LOCK under RENAME_LOCK.
`path_is_under` (`mount::is_path_reachable`) climbs under MOUNT_LOCK's
locking read (`Mount::up`), then `is_subdir`. None of them takes a
reference, so nothing is dropped inside a walk. `d_path` and
`dentry_path` copy names into a PATH_MAX buffer allocated before the
walk (Linux prepend_buffer): nothing allocates under the locks or
the guard; a pass that raced starts the buffer over. `Dentry::alloc`
inserts a child under the parent's `d_lock` unless one with that name
is cached (Linux d_alloc + d_add): one dentry per name.

An inode's dentries (`ILocked.i_dentry`, Linux i_dentry and
d_u.d_alias) are an intrusive list through `Dentry.d_alias` under the
inode's `i_lock` (Linux the same), thread context only. A dentry is on its inode's list exactly while its d_lock
holds that inode: `DentryRef::new` links a positive one, `add` links
one it makes positive, `d_delete` (making it negative in place) and
`dentry_kill` unlink it, each with the inode's list lock taken first
and the dentry's d_lock (and in `add` and `d_delete` the parent's)
inside it, as Linux takes i_lock before d_lock. `d_delete` therefore
finds the child (`d_lookup`) and its inode before any lock and checks
under the locks that it is still that child with that inode (the
caller's `i_rwsem` keeps it so). The lookups (`d_find_alias`,
`d_find_any_alias`, `d_find_alias_by`: Linux d_find_alias,
d_find_any_alias, find_acceptable_alias's walk) read each entry's
d_lock under the list lock and take references with
`DentryRef::try_get`: the list lock keeps an entry's memory, since a
dying dentry leaves the list in `dentry_kill` before its free is
queued. No reference is dropped under the list lock (a last put would
take it again), and nothing else is taken under it.

A cached child, positive or negative, is revalidated by its
filesystem's dentry operation (`DentryOps::d_revalidate` through
`Dentry::revalidate`, Linux d_revalidate(dir, name, dentry, flags):
the directory's inode and the lookup's `LookupBits`) after its d_lock is
released, inside whatever i_rwsem the walk holds: procfs's takes the
task's task_lock and its fd table lock. A negative dentry a filesystem
keeps (`InodeOps::lookup_neg`, Linux ->lookup's d_splice_alias(NULL))
is stamped (`Dentry.d_time`, a plain atomic) before it is hashed with
what its d_revalidate compares, read under the lock the lookup holds:
vfat's directory version (`Inode.i_version`, Linux i_version: bumped
by an entry's add or removal under the directory's i_rwsem held for
writing; the lookup holds it shared); kernfs's directory revision
(`KNode.rev`, Linux dir.rev: bumped as a child is linked or unlinked
under KERNFS_RWSEM write and the directory's `children` lock held for
writing; the lookup reads it with the find under that lock held for
reading); cgroupfs's (`Cgroup.rev`: bumped under the `children` or
`subsys` lock held for writing as a child or a controller's files come
or go; the lookup reads it, Acquire, before it looks, so a change after
the read leaves the stamp stale). A positive cgroupfs dentry is
checked in ref mode only (kernfs_dop_revalidate's active, parent and
name checks: `still_there`): the cgroup's `dead` flag, the parent's
`children` and the cgroup's `subsys` each taken for reading, alone. Asked by an RCU walk (`LookupBits::RCU`,
Linux LOOKUP_RCU; and a permission check's MAY_NOT_BLOCK) the dentry,
directory and inode are borrowed under the guard with no reference and may be
torn down already: the answer may read only fields with no drop glue
and take nothing that sleeps, else it is ECHILD; kernfs, cgroupfs and
vfat (Linux kernfs_dop_revalidate, vfat_revalidate_ci) always are. procfs
answers from `ProcRcu` (`Inode::private_rcu`, Linux proc_inode's pid
put by ->free_inode: set before the inode is visible, dropped by
`i_callback` a grace period after the teardown): the task through its
`Pid` under a nested guard (pid_task), its owner taken over with
`task_dump_owner` (credentials under RCU, the mm under task_lock, a
spin leaf), hidepid and fd/ checks with the superblock's options and
`ptrace::may_access_task` (TASKLIST read, task_lock: spin, no sleep);
ECHILD where Linux is (PDE entries, fd/<n>, /proc/sys). A stale answer invalidates that dentry (`dentry::d_invalidate`,
Linux d_invalidate: the parent's d_lock, then its own, as every
unhook, the parent read again if a rename moved it meanwhile; then
each mountpoint at or below it, found by a walk of child lists under
d_lock (`find_submount`, restarted if RENAME_LOCK's sequence moved),
has its mounts detached (`mount::detach_mounts`, Linux
__detach_mounts: NAMESPACE_SEM write, then MOUNT_LOCK write, the
mountpoint pinned; in that one section the dentry is dropped
(`dentry::d_drop`: its parent borrowed under an RCU read guard, the
parent's d_lock, then its own; the tree's references put with
`DentryRef::put_held`, never the last: the caller's and the
mountpoint's outlive them, so no dentry is put or killed under
MOUNT_LOCK, as Linux d_drop takes and puts none); then each mount on its `m_list` goes with
`umount_tree` and UMOUNT_COVER, every submount leaving a cover at its
unmounted parent, and the covers left on the dentry itself go,
`drop_cover`), so it sleeps, inside the walk's i_rwsem as Linux's
lookup under i_rwsem does; then `d_drop_tree` below it), never
whatever holds the name by then; an
error is the lookup's and invalidates nothing (Linux lookup_fast,
lookup_dcache, __lookup_slow). `sb_permission` reads `Inode.sb` for a write only. `proc::proc_flush_pid` runs after a task leaves TASKLIST: it
clones the task's and its leader's `Pid` under TASKLIST's read lock
(dropped after it), then walks the procfs superblocks
(`iterate_supers_type_active`: an active reference each, no
s_umount) and invalidates dentries (`d_invalidate`: d_lock, then
NAMESPACE_SEM and MOUNT_LOCK for what is mounted there, Linux
proc_invalidate_siblings_dcache), each named as that superblock's pid
namespace numbers the task; it sleeps.

A procfs superblock's pid namespace (`ProcOpts.pid_ns`, Linux
proc_fs_info.pid_ns: the mounter's) is fixed at mount and read with no
lock; inode data holds the task's `Pid` (`ProcPid`, an `Arc`, Linux
proc_inode->pid; its last reference may go wherever the inode does,
PIDMAP_LOCK being a leaf), copied out of the inode data and, once per
access, turned into a reference to the task (`Pid.task` under RCU,
never under the inode data's lock: Linux get_pid_task) that every
helper then works on, never its number (a
helper needing the task's locked fields finds it again under TASKLIST
only if it is still that task, `GlobalTaskTable::view`; its resources under its
alloc_lock); lookup, readdir and the per-task files
translate through the pid helpers (3.1.1 Pid namespaces): the hash
and the task link under RCU
(readdir and /proc/<pid>/task gather under it with no allocation,
`collect_tasks`/`collect_threads`); status and stat number every pid
under that read lock from the `Pid`s it keeps listed (lock-free).

An open procfs file's `ProcOpen.seq` (sync::Mutex, Linux seq_file
m->lock) is held across generating its content (which takes
TASKLIST, mmap_lock, network and mount locks) and the copy to the
caller (may fault: -> mmap_lock); under f_pos_lock for read().

The dcache shrinker (`dentry::shrink_dcache`: drop_caches 2, direct
reclaim) walks the superblocks with `superblock::iterate_supers_trylock`
(`SB_LOCK` to step, s_umount by trylock-read: a superblock whose
s_umount is busy is skipped, Linux super_cache_scan, since reclaim may
run under one), then per dentry the parent's d_lock (write)
and the child's (read): spin locks only, allocating nothing. Direct
reclaim never runs in atomic context (`may_direct_reclaim`), so an
allocation under a d_lock cannot re-enter it.

**Superblock lists** (`fs/superblock.rs`; Linux fs/super.c,
fs/filesystems.c): `SB_LOCK` (spin Mutex, thread context; Linux
sb_lock; under it only what `sget`'s test and set take, below, and
the SB_DEAD wakeup's `var_waitqueue` lock) guards `super_blocks`
(`SuperBlock.s_list`) and each type's `FileSystemType.fs_supers`
(`SuperBlock.s_instances`, a `LockedBy` cell of the lock's data). Both
are `util::list::WeakList`s: a `Weak` per superblock, linked by `sget`
and unlinked by its last passive put (`Drop for SuperBlock`, Linux
put_super), so the lists allocate nothing under the lock (only a new
superblock's anonymous device number may, GFP_ATOMIC, below). A
filesystem's data (`SuperBlock.s_fs_info`, Linux s_fs_info, an
`RcuOnceArc`) is set once by its fill or sget's set and released, as
Linux, by its ->put_super (tmpfs; vfat by `kill_fs_info_rcu`, unless an
inode is busy: every other inode evicted) or
->kill_sb (procfs, sysfs, cgroup2, tracefs after kill_anon_super, every
inode evicted; ramfs before it, its inodes live, as Linux
ramfs_kill_sb: it sets none) or a fill that fails after setting it, in
thread context (`kill_fs_info`: out of the cell, a grace period
(synchronize_rcu), then the reference dropped there; Linux frees it
by kfree_rcu / call_rcu, but here the data's drop may sleep: an
inode's put, a pid namespace's), never with the superblock's memory,
whose drop may come in any context (only a superblock never listed,
sget's set having failed, still holds it then, dropped in sget's
thread context, or one whose shutdown left a busy, poisoned inode,
whose data put_super kept: vfat, whose data's drop does not
sleep). Readers borrow it under an RCU guard (`fs_info_rcu`:
sget's tests, short reads) or take a reference (`fs_info`), dropped
in thread context; once released it reads as None. A superblock has two counts, as in
Linux: active references (`SbActive`, `SuperBlock.s_active`, Linux
s_active; never raised from zero) and passive ones (the `Arc`, Linux
s_passive; every inode holds one, `Inode.sb`, dropped at its teardown
in thread context). What is freed by an RCU callback (`rcuc/N`,
preemption off) names its superblock by a `Weak` instead, memory only
(`Dentry.sb`, d_free; a vfat metadata list's, i_callback): a last
passive put there would run `Drop for SuperBlock`, whose block
device's last put puts its inode (sleeps). Its life's flags in `s_flags` (Linux SB_BORN: set when its
mount returns, `vfs_get_tree`; SB_DYING: set by the shutdown under
s_umount; SB_DEAD: set under `SB_LOCK` after kill_sb) are waited for on
`sync::waitqueue::var_waitqueue` (Linux wait_var_event); SB_DEAD's
wakeup is taken under `SB_LOCK`. A walker (`iterate_supers`,
`iterate_supers_type`; Linux __iterate_supers) skips a dying
superblock and takes the next one's passive reference under the lock,
releases it, waits for SB_BORN or SB_DYING and takes s_umount for
reading unless it is dying (Linux super_lock_shared), runs its
callback (which may sleep), and drops the previous reference with the
lock released. `sget` (Linux sget_fc) runs its test under it, on
superblocks not yet dead (sysfs, cgroup2: `SuperBlock.s_fs_info`
borrowed under an RCU guard), and a new superblock's `set`, which
stores its identity: `s_fs_info` set (an atomic exchange; its
wrapper allocated before), and
an anonymous device number taken
from `UNNAMED_DEV_IDA` (Linux get_anon_bdev under sb_lock: the
`util::ida::Ida` IrqSpinlock leaf, its bitmap grown GFP_ATOMIC; freed
by kill_anon_super after SB_DEAD, any context) — the only other locks
taken under `SB_LOCK`), takes a match's passive reference and, unlocked, trades it
for an active one with s_umount held for writing (Linux grab_super:
once born; a dying match is waited for until SB_DEAD and the search
repeated); else it allocates a superblock unlocked with its s_umount
already held for writing (Linux alloc_super), and under the lock sets
and lists it. Either way the superblock comes back with s_umount held
(`SbLocked`): the filesystem fills a new one under it (Linux
fill_super, from get_tree_nodev / get_tree_single / get_tree_bdev /
kernfs_get_tree), `vfs_get_tree` sets SB_BORN, and the mounter
releases it before making the mount (Linux do_new_mount_fc, fc_mount);
an error path drops it as deactivate_locked_super. `FILE_SYSTEMS` (spin RwLock leaf, thread context; Linux
file_systems_lock) guards the registered types, a singly linked list
through `FileSystemType.next` in registration order.
`dentry::d_drop_tree` (a removed directory's cache, inside the
victim's i_rwsem: Linux vfs_rmdir's shrink_dcache_parent; an unhashed
dentry's cached subtree, a dying superblock's tree) takes the same
parent-then-child d_locks one leaf at a time, with no RENAME_LOCK held
(d_move drops it first); each leaf it unhooks is still held by the
walk, so its last reference goes after the locks.
`Dentry::d_delete` (unlink, rmdir) only makes the dentry negative or
unhashes it under the parent's and child's d_locks; the inode it took
is released (`inotify::d_iput`, which queues allocated events; Linux
dentry_unlink_inode's fsnotify_inoderemove and iput) after both are
dropped. No dentry's last reference is dropped under a d_lock.

#### libfs / tracefs (fs/libfs.rs, fs/tracefs.rs; Linux fs/libfs.c, fs/tracefs)

tracefs's entries are its dentries (Linux simple_lookup, d_make_persistent):
`libfs::simple_create` makes one under the parent's `i_rwsem` (lookup,
dentry allocation, inode, instantiation: Linux simple_start_creating ..
simple_done_creating), `libfs::simple_recursive_removal` takes a subtree
away holding one directory's `i_rwsem` at a time going down, and going
up the victim's parent's, taken after the victim's is released, across
`d_invalidate` (-> NAMESPACE_SEM for a mountpoint) and its callback
(Linux __simple_recursive_removal). `libfs::dcache_readdir` keeps an
open directory's place with a cursor dentry (Linux d_alloc_cursor,
DCACHE_DENTRY_CURSOR) on the directory's children list: found and
stepped past under the directory's d_lock held for reading
(`Dentry::scan_positives`, Linux scan_positives), moved under it held
for writing (`Dentry::cursor_move`, Linux hlist_del_init /
hlist_add_behind), under the getdents (or lseek) shared `i_rwsem`; a
cursor is never hashed or positive and every walk of a children list
steps over it (Linux d_walk); its list reference is put after the
d_lock is released. `PinnedFs` (a filesystem's kernel mount
and hold count; Linux pin_fs_lock) is a spin leaf, thread context only
(never taken in IRQ context, so no IRQ class): the check, the
install and the count are one hold; the mount is made and put with it
released.
tracefs's mount options (`FsInfo`, Linux tracefs_fs_info) are a spin
leaf, thread context only (never taken in IRQ context, so no IRQ
class), replaced by a mount or remount and read by show_options; the
owner an inode takes from the root (Linux set_tracefs_inode_owner) is
written with no lock, by permission (an RCU walk's too) and getattr,
from the root's ids and the inode's PERM_SET flags (atomics, as Linux
writes i_uid there), the root's inode borrowed with no reference under
`SuperBlock.root` (a spin RwLock leaf: written only by the fill's
`set_root` and the shutdown's take) and an RCU guard (Linux
ti->private, a plain pointer: no inode holds another, so none is put
from an inode's RCU-freed data); a uid=/gid= remount walks the superblock's inodes
(`for_each_sb_inode`, Linux the tracefs_inodes RCU list) setting them.

#### kernfs / sysfs (fs/kernfs/, fs/kernfs/sysfs.rs; Linux fs/kernfs)

| Lock | Type | Order / rule |
|------|------|--------------|
| `kernfs::KERNFS_RWSEM` | sync::RwSem (Linux kernfs_rwsem) | write: add, remove, rename a node; read: symlink target paths. Taken by subsystems registering objects (in thread context, under their own locks such as RTNL), never under a VFS lock, never across show()/store() |
| `KNode.children` | sync::RwSem (Linux keeps a directory's rbtree under kernfs_rwsem) | inside KERNFS_RWSEM: alone (lookup, readdir under the walk's i_rwsem; getattr's link count) or under KERNFS_RWSEM for changes; thread context, never under a spin lock |
| `KNode.parent` | spin RwLock, leaf | set when the node is linked, cleared when unlinked (KERNFS_RWSEM write); `KNode.name` never changes (no rename) and has no lock |
| `KNode.iattr` | spin Mutex, leaf (Linux kernfs_iattr_rwsem) | written by chmod/chown/utimes under the inode's i_rwsem; read (copied out) when lookup builds an inode, under the parent's i_rwsem |
| `AttrNode.ops`, `BinNode.ops` | spin RwLock, leaf | read (clone) under an active reference by show()/store(); cleared by `KNode::remove` after the drain, with no lock held, the operations dropped after it is released (a removed node kept by a dentry or open file pins nothing) |
| `OpenAttr.buf` | sync::Mutex (Linux kernfs_open_file.mutex), per open file | held across show()/store(), which take subsystem locks, and across a read's copy to the caller (may fault: -> mmap_lock; no active reference held then, Linux seq_read_iter under m->lock); a write copies its data in before taking it; under f_pos_lock for read/write |
| `SB_LOCK` (sget) | spin Mutex (under it only `SuperBlock.s_fs_info` read by a test (RCU guard) or set by a set (an atomic exchange), `UNNAMED_DEV_IDA` (IrqSpinlock leaf, its bitmap grown GFP_ATOMIC), and the SB_DEAD wakeup's `var_waitqueue` lock) | a network namespace's sysfs superblock, and the default cgroup hierarchy's cgroup2 one (cgroupfs `CgSuper`, shared by every cgroup2 mount), is found in its type's `fs_supers` by `sget` (Linux kernfs_get_tree: kernfs_test_super on the kernfs root and namespace), its test reading `SuperBlock.s_fs_info` under the lock; the match is then taken by `grab_super` with the lock released |

Device model (base/): `Device.lock` (sync::Mutex, Linux device_lock)
guards the device's "dead" flag, set first by `del` (a dead device is
never bound again), and is held across a driver's probe and the
release of its binding; `del` takes the device off its bus's list
before unbinding it, so no new probe finds it. `core::GLUE`
(sync::Mutex, Linux gdp_mutex) serializes finding or making a class
glue directory with making the device's directory in it, and the
emptied-glue removal: Device.lock -> GLUE -> KERNFS_RWSEM. `Device.added`
(spin Mutex, leaf) records what registration completed. A
probe may register child devices (their sysfs entries, uevents and
probes), so a parent's lock is taken before its children's, never the
reverse. `Device.driver` (spin RwLock) and `Device.bound` (spin Mutex)
are leaves read without the device lock. `BusType.devices` is a klist
(`util::klist`, Linux klist_devices): the device embeds its node
(`Device.knode_bus`), a walk (`bus.devices()`, Linux bus_for_each_dev)
takes the klist's spin leaf only to step and holds the device it
stands on, so a probe sleeps between devices; a device removed while a
walker stands on it is marked dead, skipped, and unlinked when the walker
moves on. `BusType.drivers` (Linux klist_drivers) is an intrusive list
of the 'static drivers, never unregistered, stepped under its spin
leaf. `core::DEVICES_LIST` (Linux devices_kset list) is an intrusive
list through `Device.kset_link`, a spin leaf. Nothing allocates under
these locks. `device_shutdown` (reboot(2)) takes the devices off the
list's end one at a time, as Linux, and runs each bound driver's
shutdown callback with the lock dropped, so callbacks (which may poll
hardware or wait on driver commands, such as an xHCI's) never run under
it. `PciDev.driver_override` is a sleeping
`sync::Mutex` leaf (Linux device_lock).
I/O port resources (base/resource.rs): `IOPORT` (spin RwLock, Linux
resource_lock), the /proc/ioports tree: thread context only, a leaf;
a claimed range is allocated before it is taken and a released one
freed after, so the tree is only relinked under it; /proc/ioports
copies it out into room reserved before and formats unlocked. Taken by a
driver's probe and remove (`Device.lock` → IOPORT) and by a serial
port's move (`Tty.port` → IOPORT, 3.9).
Net devices: `NetNamespace::register_device` links the device on the
namespace's `devices` RCU list (its leaf writer lock released) before
creating the device's sysfs entries (under RTNL for driver
registrations: RTNL -> KERNFS_RWSEM); a namespace's
devices leave sysfs when it is dropped, in thread context. A NIC
driver's probe and remove run under its device's lock and take RTNL
(`register_netdev` / `unregister_netdev`): `Device.lock` -> RTNL ->
KERNFS_RWSEM; no net device attribute's show() takes RTNL, so the
removal's drain cannot wait on itself. `unregister_netdev` then waits
for the device's references with RTNL released and `Device.lock`
held (Linux the same, in netdev_run_todo): no holder of a net device
reference takes a device's lock (its attributes hold it weakly).
Block devices: a disk's partitions are registered and removed (their
sysfs entries, devtmpfs nodes, uevents) under the disk's `open_mutex`:
`Disk.open_mutex` -> KERNFS_RWSEM -> devtmpfs root i_rwsem. Their
attributes read the block device without it.

uevents (base/uevent.rs) broadcast under `ns::net::NET_NAMESPACE_LIST`
(sleeping `sync::RwSem`, Linux net_namespace_list under net_rwsem: read
by `for_each_net` and the sysfs setup's snapshot, which registers
devices and so sends uevents after releasing it; written at namespace
creation and by `cleanup_net` (from the `netns` workqueue, before it
takes RTNL); thread context, a uevent is sent from a sleepable context as
Linux's kobject_uevent), then each namespace's uevent multicast list (a snapshot: the clones are GFP_KERNEL) -> `NlSock.rxq`;
`ksysfs::UEVENT_HELPER` (a fixed array, Linux uevent_helper) is a spin
leaf: show copies it out and emits after releasing it.

show()/store() run under an active reference (`KNode::get_active`),
not a lock. `KNode::remove` deactivates the subtree and sleeps until
active references drain (Linux kernfs_drain), with no lock held: a
caller must not hold a lock that a show()/store() of the removed nodes
takes (Linux lockdep's kernfs active "lock").

#### Mount Namespace & Mount Objects

**Location:** `fs/mount.rs`

A `MountRef` (`fs/mntput.rs`) counts one reference in the mount's
per-CPU parts `Mount.mnt_pcp` (Linux mnt_pcp): paths, namespace roots,
open files, the entries of a parent's `mnt_mounts`. A clone adds to
its CPU's part, lock-free. While the mount is in a namespace
(`Mount.mnt_ns` set; a kernel mount carries `MNT_NS_INTERNAL`, Linux
kern_mount) the tree holds a reference to it, so a put takes from its
CPU's part under an RCU read guard (Linux mntput_no_expire's fast
path). Taking mounts out of their namespace clears `mnt_ns` under
NAMESPACE_SEM write and MOUNT_LOCK write; releasing NAMESPACE_SEM
(`NsWrite`'s drop, Linux namespace_unlock) waits out a grace period
(`rcu::synchronize`) and puts the tree's references in the releasing
task: umount (its task's teardown, if the last, runs before the
syscall returns) and a namespace's last reference (`put_mnt_ns`),
both through `umount_tree`, which, as Linux, runs whole in one
MOUNT_LOCK write section its caller holds (do_umount: NAMESPACE_SEM,
MOUNT_LOCK, the checks, propagate_mount_busy, umount_tree; unlock in
reverse): every mount of the tree is marked MNT_UMOUNT and taken off
its parent's list, propagation adds what it takes along
(`propagate_umount`: candidates, MNT_LOCKED cleared, `umount_one`,
`reparent`'s mnt_change_mountpoint), all leave propagation, then
each leaves its namespace, is marked MNT_SYNC_UMOUNT for a
synchronous umount, leaves its cover (`leave_cover`, preallocated)
and comes off its parent, hash and mountpoint. Nothing under it
allocates, sleeps or puts a reference that could be the last: the
set's references and the candidates' are list entries
(`Mount.mnt_list`); the extra ones (a parent list's entry once the
set holds the mount, a candidate that stays, reparent's) go with
`MountRef::put_held` (Linux holds none; never the last, lock-free);
each unmounted mount's reference moves to `NsTree.unmounted` (Linux
unmounted) and a mountpoint whose last mount left to
`NsTree.ex_mountpoints` (Linux ex_mountpoints), both owned by
NAMESPACE_SEM and released by namespace_unlock after it lets go: the
mountpoints (their dentries put), then, after the grace period, the
references. Dropping a parent link's `Weak` there is at most a free
(Linux kfree under mount_lock; the heap is IRQ-safe). A mount
moved (MS_MOVE, pivot_root) keeps its namespace and its parent's
reference moves with it. A put of a mount out of its namespace is
exact: under MOUNT_LOCK write it takes from its part and sums them;
the one reaching zero sets `Mount.doomed` (Linux MNT_DOOMED). Links
that must not keep a mount are `Weak` (`Mount.mnt_parent`, `s_mounts`) and take a reference with `MountRef::try_get` (Linux
legitimize_mnt: an add while in a namespace, else under MOUNT_LOCK's
locking read, refused once doomed). A mount an RCU walk reached
borrowed (`lookup_mnt`, `choose_mountpoint`) gets its reference from
`MountRef::legitimize` (Linux __legitimize_mnt). No put of a mount out
of its namespace under MOUNT_LOCK.

| Field | Type | Purpose |
|-------|------|---------|
| `MntNamespace.root` (`ns/mod.rs`) | `RwLock<Option<MountRef>>` | Root of the namespace's mount tree (one per mount namespace) |
| `Mount.mnt_parent` | `AtomicPtr<Mount>` (a `Weak::into_raw`) | Parent mount (Linux mnt_parent; no reference: `get_parent` takes one with `try_get_mnt`): no lock of its own, written under NAMESPACE_SEM write and `MOUNT_LOCK` write (`attach_mnt`'s mnt_set_mountpoint, `detach_mnt`, `put_mnt_ns`, a teardown's `unhang_children`), read under either (`parent_in`, `get_parent`, `up`), or under an RCU read guard checked by MOUNT_LOCK's sequence (`up_rcu`, `__lookup_mnt`) |
| `Mount.mnt_mountpoint` | `AtomicPtr<Dentry>` | Where it is mounted (Linux mnt_mountpoint): no reference, the dentry pinned by its `Mountpoint` (m_dentry) while set; set and cleared with `mnt_parent` in one MOUNT_LOCK write section (a teardown's `unhang_children` too, its last mountpoints to `NsTree.ex_mountpoints`), or for a mount torn down off its parent cleared under MOUNT_LOCK's locking read just before its mountpoint is put (`put_mountpoint`); `get_mountpoint` takes a reference under an RCU read guard (`DentryRef::try_get`) |
| `Mount.mnt_mp` | `AtomicPtr<Mountpoint>` | Its mountpoint (Linux mnt_mp), which counts it: set and cleared with `mnt_mountpoint` (`set_mountpoint`, `take_mountpoint`), read under NAMESPACE_SEM or MOUNT_LOCK while the mount has a parent (`mp_in`: copy_tree attaches a copy on its source's, pivot_root pins the old root's) |
| `Mount.mnt_mp_list` | `list::Link` | On its mountpoint's `m_list` (Linux mnt_mp_list) while `mnt_mp` is set: linked and unlinked with it under MOUNT_LOCK, in the same section as `mnt_parent`, so the list holds hung mounts only; `detach_mounts` takes the head off in each pass under MOUNT_LOCK write (umount_tree, or umount_mnt for one already unmounted) |
| `Mount.overmount` | `AtomicPtr<Mount>` | The mount hung on its root (Linux overmount), no reference: set by `make_visible`, cleared when that mount leaves (`take_parent`, `mnt_change_mountpoint`), all under NAMESPACE_SEM write and `MOUNT_LOCK` write; read under either (`topmost_overmount`: graft's tucking, `where_to_mount` under MOUNT_LOCK's locking read) |
| `Mount.mnt_mounts` | `LockedByEither<OwnedList>` (no lock of its own) | Submounts, each entry a reference to the submount (`MountRef::into_entry`; Linux mnt_mounts, linked through `Mount.mnt_child`): changed only under NAMESPACE_SEM write and `MOUNT_LOCK` both (`attach_mnt`, `detach_mnt`: `&mut NsTree` and `&mut MntHash`), read under either (`Stable`: `&NsTree` from a NAMESPACE_SEM guard, `&MntHash` from `MOUNT_LOCK.read_excl`). Walks step with `next_mnt` (Linux next_mnt: first submount, else the next sibling of the nearest mount up to the walk's root that has one), so no list is copied and no stack is kept |
| `Mount.mnt_pcp` | `util::percpu_alloc::PcpSlot` (a word per CPU, in that CPU's chunks) | `MountRef` count (Linux mnt_pcp's mnt_count), summed under `MOUNT_LOCK` write once out of its namespace |
| `Mount.doomed` | `AtomicBool` | Last reference gone (Linux MNT_DOOMED), set under `MOUNT_LOCK` write by that put |
| `Mount.mnt_flags` | `AtomicU32` | MNT_NOSUID/NODEV/NOEXEC/READONLY/LOCK_*/LOCKED/SYNC_UMOUNT/UMOUNT; every write under `MOUNT_LOCK` (remount, reconfigure, pivot_root's MNT_LOCKED, lock_mnt_tree's locks, umount_tree's MNT_UMOUNT and MNT_SYNC_UMOUNT), read lock-free (open, exec, statfs, can_change_locked_flags: a lock is never cleared), and by `legitimize`'s locking read |
| `Mount.mnt_list` | `util::list::Link` (no lock) | On an umount's list (Linux mnt_list: `umount_tree`'s set, `propagate_umount`'s candidates and committed mounts, `NsTree.unmounted`), each entry a reference: the first three local to `umount_tree` under NAMESPACE_SEM write and MOUNT_LOCK write, the unmounted owned by NAMESPACE_SEM and put by namespace_unlock a grace period after it lets go |
| `MntHash.event`, `NsTree.touched`, `MntEvents` | MOUNT_LOCK write (the numbers); NAMESPACE_SEM (`touched`); `WaitQueue` | A mount namespace's change number and pollers (Linux mnt_ns->event, ->poll, touch_mnt_namespace), an `Arc<MntEvents>` the namespace and its `ns::tree` entry share. The last change's number of any namespace is a plain field of MOUNT_LOCK's data (`MntHash.event`, Linux `event` under mount_lock held for writing); a change (`commit_tree`, `change_type`, pivot_root, a remount) takes a new one and stores it in the namespace's `MntEvents` under MOUNT_LOCK write (`tree::mnt_set_event`: under `NS_TREE`, no reference taken, inactive namespaces too); `do_umount` takes one before `umount_tree`, which stores the current number in each namespace it takes mounts from (Linux __touch_mnt_namespace). Pollers load the number lock-free (Linux READ_ONCE). Under NAMESPACE_SEM the id is also recorded in `NsTree.touched` (a fixed array: umount_tree runs under MOUNT_LOCK; past four, every mount namespace's pollers are woken); `namespace_unlock` wakes them with NAMESPACE_SEM dropped, holding only cloned `MntEvents` (a last put is a free). A remount (no NAMESPACE_SEM) wakes the caller's namespace after MOUNT_LOCK (`mount::touch_mnt_ns`, check_mnt). A mounts file keeps the namespace and root of its open and the number it last reported (`ProcOpen.mnt`, swapped by poll: POLLERR|POLLPRI when they differ) |
| `Mount.mnt_cover`, `Mount.mnt_covers`, `Mountpoint.m_covers` | `LockedBy<Option<Arc<MntCover>>, MntHash>`, `RcuHList<CoverA, MntHash>`, `LockedBy<List<CoverPinA>, MntHash>` | A mount's preallocated cover and the covers its unmounted submounts left (Linux mnt_cover, mnt_covers, mp->m_covers): umount_tree's `leave_cover` takes the cover of a mount unmounted with its parent (a locked one; any with UMOUNT_COVER, `detach_mounts`) and links it on its unmounted parent's list and its mountpoint's `m_covers` (no reference; Linux the pin) under `MOUNT_LOCK` write, the cover counting the mountpoint (`m_count`) and naming its parent (`MntCover.parent`, live while the cover is linked); `detach_mounts` takes the covers on its dentry off both lists (`drop_cover`, Linux the same) under MOUNT_LOCK write; `__lookup_mnt` walks the list under an RCU read guard (the caller checks MOUNT_LOCK's sequence, or holds its locking read) and reads the dentry's inode (`d_lock`, under MOUNT_LOCK as attach's DCACHE_MOUNTED) to pick the stand-in; the parent's teardown takes them all off in one `MOUNT_LOCK` write section, off their mountpoints' `m_covers` too (Linux mntput_no_expire's drop_cover), frees each a grace period later (`kfree_rcu`) and drops a last mountpoint after the unlock |
| `MOUNT_LOCK` | `SeqLock` (spin writer + sequence) | Linux mount_lock (lock_mount_hash): serializes `mnt_flags` writers and `s_mounts` changes, and is held around every change of the tree's links (`attach_mnt`, `detach_mnt`, and `umount_tree` whole, its caller holding it across, as Linux do_umount, put_mnt_ns; with NAMESPACE_SEM write it owns `mnt_mounts`); under NAMESPACE_SEM and s_umount; under it only `SuperBlock.s_mounts`, `pnode::GROUP_IDA` (bulk_make_private), `ns::tree` `NS_TREE` (umount_tree's `tree::mnt_bump`), RENAME_LOCK (a raced d_path pass, path_is_under's is_subdir) and in attach/detach/umount the mountpoint dentry's `d_lock` (DCACHE_MOUNTED, a cover's inode), in `detach_mounts` its parent's then its own and its hash bucket (`d_drop`); with NAMESPACE_SEM write it owns each mount's `mnt_parent`/`mnt_mountpoint`; it owns the mount and mountpoint hashes (below); `MountRef::legitimize`'s locking read takes nothing under it. Helpers that need it take its `&mut MntHash` (`umount_tree`, `propagate_umount`, `propagate_mount_busy`, `propagate_mount_unlock`, `hide_mnt`, `change_mountpoint`, `umount_mnt`, `Mount::mark_in`), so a caller that does not hold it does not compile. No mount, mountpoint or dentry is dropped under it, and no reference put that could be the last (`MountRef::put_held`, `DentryRef::put_held` only) (`prepare_remount_ro` releases its references, `detach_mnt` the parent's reference to the mount, its parent link's `Weak`, the mountpoint and its dentry after the unlock; `umount_tree` leaves its references and mountpoints to namespace_unlock, `NsTree.unmounted` and `NsTree.ex_mountpoints`, and drops parent links' `Weak`s, at most a free; the mount hash's reference goes through `put_rcu`). The sequence is read lock-free by `lookup_mnt`, `choose_mountpoint`, `d_path` and scoped walks (3.3 Path Traversal) |
| `ns::tree` `NS_TREE` (3.4) | `IrqSpinlock` leaf | Mount namespaces by id are its mount tree (Linux mnt_ns_tree): a mount namespace leaves it first thing in its drop; `mnt_ns_same_owner` compares two namespaces' owner ids under it with no reference taken, from graft under NAMESPACE_SEM write, before MOUNT_LOCK; `mnt_ns_adjoined` (NS_MNT_GET_NEXT/PREV) is `tree::adjoined_any` (inactive ones too, Linux ns_ref_get); a mount change stores the entry's `MntEvents` number under it (`mnt_set_event`, under MOUNT_LOCK write) and `mnt_events` clones the `MntEvents` out |
| `Mount.t_flags` | `AtomicU32` | T_UNBINDABLE (Linux mnt_t_flags): written only under NAMESPACE_SEM write (change_propagation), read lock-free |
| `Mount.mnt_ns` | `AtomicU64` | Id of the mount's namespace (`MntNamespace.id`, never reused), 0 for none, `MNT_NS_INTERNAL` for a kernel mount (Linux mnt_ns, MNT_NS_INTERNAL): written only under NAMESPACE_SEM write (commit_tree when a tree is grafted or propagated, the namespace root, a namespace copy; umount and `put_mnt_ns` clear it, a grace period before the tree's references are put), or once before a kernel mount is shared; read lock-free by a put's fast path under an RCU read guard, read by `check_mnt` under NAMESPACE_SEM; can_umount and remount read it first without, as Linux (umount repeats it under the lock) |
| `SuperBlock.s_flags` | `AtomicU32` | SB_RDONLY; set by mount/remount, read lock-free by permission checks. SB_BORN, SB_DYING (under s_umount write), SB_DEAD (under `SB_LOCK`): set once each, release, read acquire (Linux super_wake / super_flags) |
| `SuperBlock.s_active` | `AtomicU32` | active references (`SbActive`, Linux s_active): a clone adds; a put that leaves others subtracts lock-free (atomic_add_unless); the last one is taken under s_umount write (deactivate_locked_super); `grab_super` adds only if nonzero, under s_umount write |
| `SuperBlock.s_bdev_file` | spin Mutex leaf | the block device held open (Linux s_bdev_file): set at mount, taken by the shutdown's kill_sb after s_umount is released; the handle is released (Disk.open_mutex) with the lock dropped |
| `Mount.mnt_writers` + `MNT_WRITE_HOLD` in `Mount.mnt_flags` | `util::percpu_alloc::PcpSlot` (a word per CPU) and a flag bit | Write-access holders through the mount (Linux mnt_pcp's mnt_writers, MNT_WRITE_HOLD): a writer (`want_write`, Linux mnt_get_write_access) adds to any CPU's part, then (SeqCst fence, Linux smp_mb) spins while MNT_WRITE_HOLD is set, then (Acquire, smp_rmb) checks read-only state (EROFS, taking its add back); a put takes from any CPU's part, the sum adds up. A holder (`hold_writers`, Linux mnt_hold_writers) sets the flag under `MOUNT_LOCK`, fences (smp_mb), sums the parts: nonzero is EBUSY with nothing changed; else the read-only state is set before `unhold_writers` clears the flag (Release, smp_wmb). Making a mount read-only (`set_flags`, Linux mnt_make_readonly) or the file system (`prepare_remount_ro`, Linux sb_prepare_remount_readonly: every writable mount in `s_mounts`, and `s_writers`) holds this way, setting `SuperBlock.s_readonly_remount` (Linux s_readonly_remount, SeqCst) rather than SB_RDONLY: writers check it with the read-only state (Linux mnt_is_readonly) until `reconfigure_super` has run ->reconfigure (vfat's writeback, under s_umount write) and set SB_RDONLY, then clears it. `Mount::flags` never shows the flag. The writer's spin is invisible to lockdep; holders never wait for writers |
| `SuperBlock.s_writers` | `AtomicU64` (count + WRITE_HOLD bit 63) | Write-access holders for mountless internal objects, the same protocol on one word (`superblock::get_write`, `hold_writers`), held by `prepare_remount_ro` under `MOUNT_LOCK` |
| `SuperBlock.s_mounts` | spin Mutex leaf | the superblock's mounts (Linux s_mounts: a `WeakList` through `Mount.mnt_instance`): a new mount is added under `MOUNT_LOCK` (`Mount::alloc`, Linux clone_mnt under lock_mount_hash), so a read-only remount's walk (`prepare_remount_ro`, under `MOUNT_LOCK` and this lock across both passes, taking no reference) misses no mount a writer could use; a mount leaves it first thing in its teardown, under this lock alone, before its superblock is released |

**Last reference:** as for files (`fput`), the last `MountRef`'s drop
never tears the mount down itself (Linux mntput_no_expire): it marks
the mount doomed and queues the teardown (`Mount::cleanup`,
Linux cleanup_mnt: off `s_mounts`, its submounts unhung under
NAMESPACE_SEM write and MOUNT_LOCK and their references dropped, its
mountpoint and id released, then its root dentry and its active
superblock reference, whose last put shuts the filesystem down under
s_umount and sleeps) on the current task's task_work
(`Twa::Resume`: an umount(2) is complete when it returns), or, from
interrupt context, a kernel thread or a task past `exit_task_work`,
on `DELAYED_MNTPUT` (IrqSpinlock leaf, the mounts' embedded callback
heads) drained by delayed work on `SYSTEM_WQ`. So a `MountRef` may be
dropped under any lock. The `sb` and `root` fields (`MntOwned`) are
released by the teardown while the mount's memory may live on in a
`try_get`'s brief `Arc` (a refused one never reads them). The
teardown hands its `Arc` to `kfree_rcu` (Linux cleanup_mnt's call_rcu
of delayed_free_vfsmnt, through `Mount.mnt_rcu`), so a mount an RCU
walk reached stays readable for the walk's guard; the drop then runs
in `rcuc/N` (1.4.2) and only releases memory and the mount's
`PcpSlot` number (an IrqSpinlock leaf).

**Busy:** as Linux do_umount (propagate_mount_busy, do_refcount_check),
umount sums the count under NAMESPACE_SEM write and MOUNT_LOCK write,
held on into umount_tree (MNT_EXPIRE's check: MOUNT_LOCK write alone,
before NAMESPACE_SEM, as Linux): a
mount with submounts or more than its caller's and the tree's
references (two), or a mount the propagation would take along with
more than its tree's one (`propagate_mount_busy`'s chain_busy, Linux
7.4), is EBUSY, unless MNT_DETACH; MNT_EXPIRE needs no submount and
exactly two. An
open file, a task's root or cwd, any held path counts. /proc mount
lists hold their references only under NAMESPACE_SEM read (Linux
m_start), which umount excludes. A put clears an MNT_EXPIRE mark
(`Path`'s drop, a file's release; Linux mntput) but umount's own
(`Path::into_mnt_noexpire`, Linux mntput_no_expire).

**Lock Order for Mount Operations:**
```
1. the mountpoint's Inode.i_rwsem (attach: a dead directory is refused)
2. mount::NAMESPACE_SEM (write: attach, umount, namespace copy)
3. SuperBlock.s_umount (write: remount; the last deactivate, with
   nothing above held)
4. mount::MOUNT_LOCK (attach_mnt / detach_mnt / umount_tree; Mount::alloc)
5. MntNamespace.root (read/write)
6. Dentry.d_lock (d_flags: DCACHE_MOUNTED, with the mountpoint)
```
Every mount, bind, MS_MOVE and pivot_root locks its target with
`lock_mount` (Linux do_lock_mount): where to mount (`where_to_mount`:
the root of the topmost mount stacked on the path, under MOUNT_LOCK's
locking read), then that dentry's i_rwsem, then NAMESPACE_SEM, then
`where_to_mount` again, all released and repeated if it changed; pivot_root's chroot_fs_refs runs after both are
released (TASKLIST read to collect the tasks, then each FsStruct.seq's
write side, `replace_refs`).
umount writes the filesystem back after releasing NAMESPACE_SEM
(writeback takes inode locks; Linux syncs in deactivate_super after
namespace_unlock). Mount ids come from `MNT_IDS` (`util::ida::Ida`,
Linux mnt_id_ida: its IrqSpinlock leaf, the bitmap grown outside it;
a mount's teardown frees its id) and
`MNT_ID_UNIQUE` (atomic).

**Mount and mountpoint hashes** (Linux mount_hashtable,
mountpoint_hashtable; `mount::MountTables`, sized from RAM at boot by
`mnt_hash_init`, Linux mnt_init): an attached mount is in the chain of
(parent, mountpoint) (`Mount.mnt_hash`, a `util::rcuhlist` chain whose
writers pass MOUNT_LOCK's `MntHash`: `attach_mnt` adds it, and
`detach_mnt`, `put_mnt_ns` and a teardown's `unhang_children` take it
out, all under MOUNT_LOCK write, before its `parent` or `mountpoint`
changes; the chain's `Arc` is released a grace period later through
`Mount.mnt_puts`). A dentry with mounts on it has one `Mountpoint`
(Linux struct mountpoint: a reference to the dentry, `m_count`, the
mounts attached there, its covers and the pins on it, `m_covers`,
the covers alone, and `m_list`, the mounts alone, linked through `Mount.mnt_mp_list` by
`set_mountpoint` and unlinked by `take_mountpoint`, both under
MOUNT_LOCK) in a bucket under MOUNT_LOCK (`LockedBy` its `MntHash`, a locking read or
the write side); each mount on it points at it (`Mount.mnt_mp`), a
pin (`MpPin`, Linux pinned_mountpoint) keeps it across an attach;
while it exists the dentry is marked mounted (`DentryFlags.mounted`,
Linux DCACHE_MOUNTED, written under its d_lock inside MOUNT_LOCK).
`get_mountpoint` allocates a new one outside MOUNT_LOCK and repeats
its lookup (Linux get_mountpoint: one may come, or go with an unhung
mount's put, meanwhile); one left out of the hash, and one whose
count reaches zero, is dropped with its dentry after the unlock
(Linux ex_mountpoints; umount_tree's on `NsTree.ex_mountpoints`,
dropped by namespace_unlock after NAMESPACE_SEM).
A tree grafted (`graft`, Linux attach_recursive_mnt) and its
propagated copies are first hung on their mountpoints with no list or
hash entry (`set_mountpoint`, under MOUNT_LOCK; reachable only by the
grafting task), then each joins its namespace and is made visible in
turn under MOUNT_LOCK write; a mount found already at a copy's place
moves onto the root of the copy's topmost overmount in the same
section (`mnt_change_mountpoint`, Linux's tucking).
Propagation (`fs/pnode.rs`) runs entirely under NAMESPACE_SEM (write),
as Linux: each mount's `Mount.prop` (`pnode::PropLinks`, `LockedBy`
NAMESPACE_SEM's `NsTree`, no lock of its own: Linux mnt_group_id, the
mnt_share peer ring, mnt_slave_list / mnt_slave, mnt_master, T_MARKED,
T_UMOUNT_CANDIDATE)
is written under the write side and read under either (mountinfo's
shared:/master:/propagate_from: under the read side). The links are
raw pointers: a linked mount is in a namespace or held by the caller,
umount and a namespace's end make every mount private before it
leaves, and a teardown unlinks one still linked (NAMESPACE_SEM read to
look, write to unlink; never the case today). An umount computes
what propagation takes (`propagate_umount`) and makes the set private
at once (`bulk_make_private`) under NAMESPACE_SEM write and, inside
umount_tree, MOUNT_LOCK write (Linux: mount_lock held across
propagate_umount, which marks, unlists and moves mounts). Peer group ids come from
`pnode::GROUP_IDA` (`util::ida::Ida`, Linux mnt_group_ida: its
IrqSpinlock leaf), allocated under NAMESPACE_SEM write and freed when
a group's last member leaves.

**Lock Order for Path Traversal (follow_mount, lookup_mnt):**
```
1. RCU read guard, MOUNT_LOCK's sequence sampled (lookup_mnt; the
   RCU walk's at the lookup's start; a legitimize that saw it move
   takes the locking read)
2. child.mnt_parent, child.mnt_mountpoint (loads, comparing addresses)
```
The walk carries a Path{mnt, dentry}: a dentry marked mounted is
crossed with `lookup_mnt` (Linux lookup_mnt, __lookup_mnt: the mount
hash chain of (mnt, dentry) walked under the guard, the entry found
legitimized as below, repeated if a mount change raced); ".." at a mount root
climbs with `choose_mountpoint` (Linux follow_dotdot): `Mount.mnt_parent`
and `Mount.mnt_mountpoint` read under an RCU read guard (`up_rcu`) with
MOUNT_LOCK's sequence sampled, then a reference to the mount found
(`MountRef::legitimize`, Linux __legitimize_mnt: an add, then the
sequence; if it moved, MOUNT_LOCK's locking read decides whether the
add came too late for a doomed mount) and to the mountpoint
(`DentryRef::try_get`); a raced climb puts what it took after
releasing the guard and repeats. The parent ".." lands on must still
be under the mount's root (`mount::path_connected`, Linux
path_connected: a bind mount's root only, `is_subdir` under
RENAME_LOCK's sequence or locking read, nothing else held), else
ENOENT: a rename may have taken the directory out of the subtree.

**RCU path walk** (`fs/namei/rcu.rs`; Linux LOOKUP_RCU,
link_path_walk, lookup_fast, step_into, try_to_unlazy): every lookup
(`path_lookupat`, `filename_parentat`, an open's `open_target`: each
the one place its RCU-to-ref retry happens, every walk under it one
try in the mode given) first walks under one RCU read guard, which disables preemption: nothing in
it sleeps, takes a sleeping lock, allocates or drops a reference, and
it stores to no shared dentry, inode or lock word. Its place
(`RcuPath`: mount, dentry, inode, `d_seq` value, no references) moves
by `__d_lookup_rcu` (each hit's `d_seq` sampled), the parent's `d_seq`
checked after the lookup, the child's inode read with `d_inode_rcu`
and checked against the child's sample before the walk stands on it
(Linux nd->seq / nd->next_seq). The search permission is asked with
MAY_NOT_BLOCK on the borrowed inode, a revalidation with LOOKUP_RCU
(above: ECHILD where the answer needs more than RCU-readable fields).
A dentry marked mounted is crossed in RCU mode (`follow_mount_rcu`,
Linux __follow_mount_rcu): `__lookup_mnt` under the guard, the mount's
root borrowed (`Mount::root_rcu`: the hash chain's reference keeps the
mount's teardown, which puts its root, after the guard began) with its
`d_seq` sampled, MOUNT_LOCK's sequence checked after each step; a
no-xdev walk or a raced mount change leaves RCU mode there. ".."
climbs in RCU mode too (`follow_dotdot_rcu`, Linux follow_dotdot_rcu):
at a mount's root to its mountpoint (`choose_mountpoint_rcu`, the
links read with `up_rcu`, the root compared by address), then the
parent through `d_parent` (`Dentry::parent_rcu`) with its `d_seq`
sampled before the child's is checked, MOUNT_LOCK's sequence checked
after a climb or at the root, and `path_connected` (`is_subdir`, under
RENAME_LOCK's sequence) for a bind mount; the root, beneath, a no-xdev
climb or a disconnected parent is ECHILD, and the ref walk gives the
answer. A symlink is followed in RCU mode (Linux pick_link under
LOOKUP_RCU): its body is the inode's `i_link`, or what ->get_link
gives when asked with `rcu` (Linux get_link(NULL dentry): nothing that
sleeps; ECHILD otherwise), pushed on the walk's own stack (two levels
in place, more allocated GFP_ATOMIC; Linux nd->stack), an absolute
one moving the walk to the root it read at its start; an atime to
update, an ECHILD body or a failed stack allocation leaves RCU mode
there with the link held (legitimize_path, as legitimize_links). Each
stack level keeps its link (mount, dentry, `d_seq` sample) borrowed;
leaving RCU mode with levels on the stack takes a reference to each
link (`legitimize_links`, Linux the same: ECHILD if one moved, what was
taken put after the guard; the levels past the embedded ones go in
room reserved, GFP_ATOMIC, with the stack's), so an `i_link` body stays
valid in ref mode through its held link: the ref walk goes on from the
same stack (Linux's one link_path_walk loop: `Held`, nothing copied),
each link held until its body is walked and put as its level pops
(put_link, sleeping allowed: no guard then): in either mode a level
pops once its last component is looked up, before that component is
stepped into (Linux walk_component's put_link unless WALK_MORE), so a
chain of links holds one. A walk that starts in
ref mode pushes its links on such a stack too (two levels in place,
more allocated GFP_KERNEL on first need: ENOMEM, Linux
nd_alloc_stack), the link held, its inode too for an `i_link` body.
Where it must leave RCU mode (a miss; for an O_CREAT open's last
name a negative entry or O_EXCL too, lookup_open then taking the
parent's i_rwsem (Linux open_last_lookups); a
revalidation or permission check that said ECHILD) it
takes references to where it stands (`try_to_unlazy`,
`try_to_unlazy_next` for a child too, `legitimize_path`:
`MountRef::legitimize` against MOUNT_LOCK's sequence sampled at the
lookup's start, `DentryRef::try_get`, then the `d_seq` check again)
and goes on in ref mode from there. The walk starts with no reference
either (Linux path_init under LOOKUP_RCU): the root and the cwd are
read from the caller's fs_struct (borrowed lock-free, the task's own)
under `FsStruct.seq`'s sequence (`root_rcu`, `pwd_rcu`: the paths'
addresses, kept in atomics stored in the write section beside the
owned paths, and their `d_seq` sampled in the same read; the old
paths are put after the write section and freed a grace period
later), a dirfd's path borrowed from its file (`fdget_raw`: no lock,
and no reference from a table no other task uses), a
held start (a parent) borrowed, and file_open_root's root borrowed as
the walk's root too (Linux ND_ROOT_PRESET: absolute names and bodies
and ".." stop there; never legitimized, the caller holds it). The root is
legitimized at the first unlazy that needs it (`legitimize_root`,
Linux nd->root_seq: against its `d_seq` and MOUNT_LOCK's sequence,
the reference kept in `Nd.root` for the ref walks, a scoped lookup's
held start cloned); complete_walk leaves it untaken unless scoped,
and a later ref walk of the lookup takes it then (set_root:
`FsStruct.seq`'s locking read). The credentials are the current
task's, borrowed (`Task::subj_cred_ref`, Linux current_cred), not
copied. If a legitimize fails, or a
sequence moved, the walk is ECHILD and the lookup is done again in
ref mode from its start (a new `Nd`: path_init's sequences sampled
again). What a failed legitimize took is put after the guard
(`Puts`, Linux terminate_walk; the links legitimize_links took stay
on the link stack, which the walk's caller keeps, `Nd::walk`, and
drops after the guard): a put may be the last. Its slots are
fixed by role, as terminate_walk's set (the walk's place, the symlink
being picked, the root, a mount taken without its dentry,
try_to_unlazy_next's child), each filled at most once since every fill ends the walk; a
second fill panics in every build rather than drop under the guard. A
RESOLVE_CACHED walk (Linux LOOKUP_CACHED) may not leave RCU mode but
at its end (complete_walk), so it is EAGAIN where Linux's is: the
retry's `Nd::new` refuses LOOKUP_CACHED without LOOKUP_RCU. No lock
is taken or added; the sequences are read (`read_begin` spins out a
writer, which holds spin locks only).

A scoped walk (openat2 RESOLVE_BENEATH / RESOLVE_IN_ROOT, `namei::Nd`;
Linux nd->m_seq, nd->r_seq) uses `MOUNT_LOCK`'s and `RENAME_LOCK`'s
sequences sampled at its start (every lookup samples them), holding no
lock, and after each ".." gives up
with EAGAIN if either moved: a rename or a mount change may have taken
it above its root. Its result must then still be under the root
(`mount::is_path_reachable`, Linux complete_walk's path_is_under:
`Mount.mnt_parent`/`Mount.mnt_mountpoint` borrowed under MOUNT_LOCK's locking
read, then `is_subdir`), else EXDEV.

`is_local_mountpoint` (rmdir, unlink, rename: EBUSY) walks the
caller's namespace with `next_mnt` under NAMESPACE_SEM read (Linux
__is_local_mountpoint under namespace_sem), each mount's
`mnt_mountpoint` compared, inside the inode locks those syscalls
hold (sleeping, outer): the parents' and the
victim's (rmdir/unlink) or the renamed and replaced inodes' (a
directory being replaced included, like Linux vfs_rename). `attach`
takes the mountpoint directory's i_rwsem (Linux lock_mount) around
linking the new mount in and refuses a directory marked dead
(`Inode::set_dead`, set by rmdir or a rename replacing it under that
same lock), so a mount and a removal of its mountpoint serialize:
i_rwsem -> NAMESPACE_SEM -> MntNamespace.root.

#### VFS Locking Notes

**Single Dentry Lock:** Following Linux's `d_lock` pattern, each dentry uses a
single RwLock (`d_lock`) protecting all mutable state. This matches the proven
Linux design and simplifies lock ordering.

#### Directory Operation Locking (Linux i_rwsem Pattern)

**Location:** `fs/inode.rs`, `fs/syscall.rs`

Following Linux's `i_rwsem` pattern, directory operations are serialized at the
VFS layer by `Inode::lock()` on the parent directory's inode, which returns
a guard that releases the lock when dropped (Linux inode_lock /
inode_unlock). This ensures no concurrent modifications to a directory's
contents.

**Operations requiring the lock:**
- `create` (open with O_CREAT)
- `mkdir` / `mkdirat`
- `rmdir`
- `unlink` / `unlinkat`
- `link` / `linkat`
- `symlink` / `symlinkat`
- `mknod` / `mknodat`
- `rename` (uses `lock_rename()` for two-directory locking)

**API (RAII guards: every return path releases, no unsafe unlock):**
```rust
impl Inode {
    /// i_rwsem for writing (Linux inode_lock)
    pub fn lock(&self) -> InodeLock<'_>;
    /// The same, the guard owning an `Arc` of the inode
    pub fn lock_arc(self: &Arc<Self>) -> InodeLockArc;
    /// i_rwsem shared (Linux inode_lock_shared): lookup, readdir
    pub fn lock_shared(&self) -> InodeLockShared<'_>;
}
```

**VFS syscall pattern:**
```rust
fn sys_mkdir(...) {
    let parent_inode = parent_dentry.get_inode()?;
    let _lock = parent_inode.lock();
    // Filesystem operation (no concurrent access possible); `?` and
    // early returns release the lock with the guard
    parent_inode.i_op.mkdir(...)
}
```

**Lookup and permission under the lock (Linux lookup_open /
filename_create):** `namei::Nd::lookup_open` (O_CREAT, when the walk's
lookup_fast found no positive entry or O_EXCL skipped it; an existing name
found by lookup_fast, in RCU mode or not, takes no i_rwsem),
`namei.rs::create_entry` (mkdir, mknod, symlink, link) and
`namei.rs::delete_entry` (unlink, rmdir) take the parent's `Inode::lock()`
first and, while holding it, look the name up (`lookup_one`,
`lookup_dcache`: dentry `d_lock`, then the file system's `lookup`), decide
EEXIST / "created by this call", run the DAC checks (`dac::may_create`,
`dac::may_delete`; these read the inode's atomic mode/uid/gid and, for the
new mode, the task's umask under `FsStruct.seq`'s locking read) and perform the
operation. So the existence check, the permission decision and the change
are atomic with respect to other directory operations on that parent.
Order: parent `i_rwsem` -> `FsStruct.seq` (umask read, leaf) and parent
`i_rwsem` -> dentry `d_lock` -> fs-internal locks. Rename does the same
lookups and checks (`link.rs::rename_locked`) inside `lock_rename()`.

**The inode whose link count changes (Linux vfs_link / vfs_unlink /
vfs_rmdir / vfs_rename):** inside the parent's lock, link takes the
source inode's `i_rwsem` exclusive around its `i_nlink == 0` check
(ENOENT) and the file system's `link`; unlink and rmdir take the
victim's around `unlink`/`rmdir`; rename takes the non-directory source
and target (`fs::lock_two_nondirs`, lower address first, one lock if
they are the same inode) around the file system's `rename`. So a link
never brings back an inode whose last link an unlink in another
directory is dropping. Order: parent directory `i_rwsem`(s) -> that
inode's `i_rwsem` -> dentry `d_lock` -> fs-internal locks. Once the
file system removed the name, still under the victim's lock (a
rename's replaced target: under its own), its dentry is marked so
nothing mounts on it again (`Dentry::dont_mount`, Linux dont_mount:
DCACHE_CANT_MOUNT under its `d_lock`; `lock_mount` refuses it with
ENOENT under the target's `i_rwsem`, which the removal holds) and what
other mount namespaces mounted on it is detached (`detach_mounts`,
Linux vfs_rmdir, vfs_unlink, vfs_rename: NAMESPACE_SEM write and
MOUNT_LOCK under the inodes' `i_rwsem`, as the order above has it). The victim
is never an ancestor of the locked parents (a link source is never a
directory; rename skips directories, which have no hard links), so this
nests strictly below the directory order.

**Filesystem implications:**
Filesystems can trust that VFS has serialized directory operations. Complex
internal locking (like lock ordering for cross-directory operations) is
unnecessary. Filesystems may still use internal locks for `Sync` requirements,
but these become simple acquisitions without ordering concerns.

#### Rename Locking (Linux lock_rename Pattern)

**Location:** `fs/mod.rs`, `fs/dentry.rs`

The rename operation requires special locking to prevent deadlocks and directory
cycles. The implementation follows Linux's `lock_rename()` pattern from `fs/namei.c`.

**Lock Ordering Rules:**

1. **Same directory:** Single lock only
2. **Ancestor relationship:** Lock ancestor first (parent before child)
3. **No ancestor relationship:** Lock by address order (lower address first)

This ordering prevents deadlocks because:
- The ancestor-first rule ensures a consistent hierarchy-based order
- The address-based fallback provides a total order for unrelated directories
- No two concurrent renames can acquire locks in opposite order

**Directory locks:** `lock_rename()` locks each directory's inode
`i_rwsem` (`Inode::lock_arc()` of each parent dentry's inode), the same
lock create/mkdir/unlink/rmdir/link/symlink/mknod take on the parent, so a
rename excludes every other operation on both directories, as in Linux
(lock_rename -> inode_lock_nested). Order: `SuperBlock.s_vfs_rename_mutex`
(cross-directory only) -> directory `i_rwsem`s (ancestor first, else by
address) -> dentry `d_lock` -> fs-internal locks.

**API:**

```rust
/// Lock two directories for rename; the guard releases them in reverse,
/// then s_vfs_rename_mutex (Linux unlock_rename); `trap()` is the parent
/// that is an ancestor of the other, if one is
pub fn lock_rename(p1: &Arc<Dentry>, p2: &Arc<Dentry>) -> RenameLock;

/// The non-directory source/target of a rename, by address; a guard
pub fn lock_two_nondirs(a: Option<&InodeRef>, b: Option<&InodeRef>) -> NondirsLock;

/// Check if child is a subdirectory of ancestor
pub fn is_subdir(child: &Arc<Dentry>, ancestor: &Arc<Dentry>) -> bool;
```

**Cycle Prevention:**

Before performing a rename of a directory, `is_subdir()` checks that the new
parent is not a descendant of the source directory. This prevents:
- `mv /a /a/b/c/a` (moving directory into itself)
- Creating unreachable loops in the directory tree

```rust
// In rename_locked, under the RenameLock:
if source_inode.mode().is_dir() && is_subdir(&new_parent_dentry, &source_dentry) {
    return Err(EINVAL); // would create a cycle; the guard unlocks
}
```

**Two-Level Locking:**

The VFS layer locks both directories' `i_rwsem` via `lock_rename()`, which
excludes renames and all other directory operations on them. Filesystems may
still use internal locks for their data structures (e.g., ramfs children
BTreeMap).

**Error Conditions:**
- `EINVAL`: new_parent is subdirectory of source (cycle)
- `ENOTEMPTY`: target directory not empty
- `EXDEV`: cross-filesystem rename

#### Cross-Directory Rename Serialization (Linux s_vfs_rename_mutex)

**Location:** `fs/superblock.rs`, `fs/mod.rs`

Cross-directory renames require additional serialization beyond per-dentry locks
to prevent races during ancestor relationship checks. This follows Linux's
`s_vfs_rename_mutex` pattern from `fs/namei.c`.

**Why needed:**

Without a per-superblock lock, this race is possible:
1. Thread A: `rename(a/x, b/y)` - checks `is_subdir()`, finds no relationship
2. Thread B: `rename(b, a/b)` - moves `b` under `a`
3. Thread A: locks directories based on stale relationship info
4. Result: potential deadlock or incorrect cycle detection

**SuperBlock Field:**

| Field | Type | Purpose |
|-------|------|---------|
| `s_vfs_rename_mutex` | `sync::Mutex<()>` | Serializes cross-directory renames |

**Lock Ordering for Cross-Directory Rename:**

```
1. SuperBlock.s_vfs_rename_mutex (cross-directory only)
   ↓
2. Parent directories via lock_rename() (ancestor-first or address order)
   ↓
3. Source/target inodes if needed
```

**Same-Directory Rename:**

Does not acquire `s_vfs_rename_mutex` - only the directory's `i_rwsem`.

#### Directory Iteration (getdents64)

Linux holds the directory's `i_rwsem` shared across `iterate_shared` and
`filldir64` copies each record straight to user memory. hk file systems
emit entries while holding locks (ramfs `RamfsInodeData.children`
read lock, a sleeping RwSem; procfs and cgroupfs emit unlocked), so
user memory must
not be touched from the emit callback (a fault could sleep under a
spinlock). `sys_getdents64` holds the directory's `i_rwsem` shared
across `readdir` (Linux iterate_dir) and gathers records into a
kernel buffer bounded by `GETDENTS_CHUNK` (32 KiB, independent of the
user `count`), and copies it to user space after `readdir` returned and
every lock is dropped; a call may return fewer bytes than fit (callers
loop until 0). Positions are stable cookies (ramfs per-directory
position counter, vfat slot index, procfs pid/fd based), so nothing has
to stay locked between calls. The call holds the file's `f_pos_lock`
(below), like Linux `fdget_pos`.

#### File Writes and Positions (Linux i_rwsem / f_pos_lock)

**Location:** `fs/file.rs` (`File::write_iter`, `File::pos_lock`),
`fs/io.rs` (`file_readv`, `file_writev`, `sys_lseek`), `fs/fd.rs`
(`do_truncate`)

- `File.f_pos_lock` (`sync::Mutex<()>`, Linux `f_pos_lock` with
  FMODE_ATOMIC_POS): taken by read/readv/write/writev/lseek/getdents64
  on regular files and directories for the whole call (not by
  pread/pwrite, which do not use the position), so processes sharing an
  open file (fork, dup, SCM_RIGHTS) never read or write at the same
  position. Pipes, sockets and devices are not position-based and skip
  it, as in Linux.
- `Inode.i_rwsem` is held across every write to a regular file
  (`File::write_iter`, i.e. write/writev/pwrite/pwritev*/io_uring/splice
  users of `File::write`/`pwrite`): with O_APPEND (or RWF_APPEND) the
  position is set to `i_size` under the lock, so appends from separate
  open files never overlap, and the data copy, the size update,
  RLIMIT_FSIZE check and set-id stripping are atomic with respect to
  other writers. `truncate`/`ftruncate`/O_TRUNC take it too (Linux
  do_truncate). Reads do not take it (Linux generic_file_read_iter),
  except a vfat O_DIRECT read, which holds it exclusive from its
  end-of-file check until its last bio is submitted (3.10, Linux
  DIO_LOCKING).
- Data moves between user memory and the file through an iov_iter
  (`fs/iov_iter.rs`). Page-cache files (ramfs, vfat, block devices:
  `filemap::read_iter`/`write_iter`) copy straight between the
  caller's memory and the cache pages; file types not converted yet go
  through a kernel buffer of at most 64 KiB (`file::WRITE_CHUNK`) per
  step, so one call never pins more kernel memory than that. As in
  Linux, the user copies (and their page faults) happen under
  `f_pos_lock` and, for writes, `i_rwsem` (held across the whole
  write, which keeps a large O_APPEND write contiguous); the fault
  path takes neither lock, and both are sleeping locks, so a fault may
  sleep. Order `i_rwsem` -> mmap_lock: the fault path never takes
  `i_rwsem`. A read copies each page out holding only a reference to
  it, no page lock (Linux filemap_read), so a fault on the destination
  (even a mapping of the same page) can lock it. A write faults each
  page's source bytes in first (`IovSource::fault_in`, with `i_rwsem`
  but no page lock held), then copies under the page lock with page
  faults disabled and nothing faulted in (`copy_from_nofault`, Linux
  generic_perform_write + copy_folio_from_iter_atomic): a fault there
  could need that very page's lock (a source mapping the file) or
  another page's (ABBA). A copy that comes up short is retried after
  the page is unlocked.
- Character devices copy to the reader with no spin lock held: N_TTY
  takes input out of `Tty.ldata` into a 64-byte kernel buffer and
  copies it after dropping the lock (Linux tty_read); /dev/kmsg formats
  its record under `KmsgUser.cur` and `LOG` and copies it after.
- Order: `f_pos_lock` -> file `i_rwsem` -> page cache / page locks ->
  fs-internal locks. A file's `i_rwsem` is taken under a directory's
  only by link, unlink and rename (above), never the reverse: no
  directory lock is taken while a file's `i_rwsem` is held (O_CREAT
  drops the parent's lock before O_TRUNC).
- Both are sleeping locks (`sync`): the vfat write path may wait
  for page locks and block I/O while holding `i_rwsem`, which a spinlock
  would forbid.
- Path walk (`namei.rs::lookup_slow`) takes a directory's `i_rwsem`
  shared on a dcache miss (Linux lookup_slow), as an open's last name
  without O_CREAT does (`Nd::lookup_open`, Linux lookup_open's
  inode_lock_shared, after mnt_want_write for O_TRUNC or a write
  mode, its result dropped); callers already holding
  that directory exclusively (create, unlink, rename) use `lookup_one`
  directly.

#### Inode Timestamp Locking (Linux i_rwsem Pattern)

**Location:** `fs/inode.rs` (`InodeTime`), `fs/perm.rs` (utimes)

Each timestamp (`atime`, `mtime`, `ctime`) is a pair of atomics (seconds,
nanoseconds), like Linux's `i_*time_sec` / `i_*time_nsec` fields:

- **Reads** (getattr/stat) are lock-free (Linux `inode_get_mtime` in
  `generic_fillattr`). A read racing a write may pair the new seconds with
  the old nanoseconds, as on Linux.
- **Writes** hold `i_rwsem` exclusive (Linux `notify_change` under
  `inode_lock`): utimensat/utimes/utime take it after `want_write`, then
  check permission (owner, CAP_FOWNER or write access; Linux
  setattr_prepare inside notify_change) and set atime, mtime and ctime
  in the same hold.
- **Mode, uid and gid** follow the same rule: chmod and chown take
  `i_rwsem` after `want_write` and keep it across the permission checks,
  the set-id kill computed from the current mode, the stores and ctime
  (Linux chmod_common/chown_common); a write or truncate kills set-id bits
  under it (`remove_privs`). Readers (permission checks, stat, exec) load
  them lock-free, as Linux reads i_mode with READ_ONCE.

#### Timers (time/timer.rs; Linux kernel/time/timer.c)

A `TimerList` is embedded in its pinned owner and armed in jiffies
(`mod_timer`) or not before a CLOCK_MONOTONIC instant (`mod_timer_ns`,
tick granularity, never early). Each CPU has a HARD and a SOFT base
(`TimerBase`: `wheel`, an IrqSpinlock over the 64-slot wheel and the
running callback, and a wait queue); a timer stays on the base of the
CPU that first armed it. Under its base's wheel lock (Linux
base->lock): the timer's expiry, `not_before` bound and slot
(`TimerList.pos`, a `sync::LockedCell` read and written only through
that lock's data, checked against the timer's `base`; one arm sets
expiry and bound together), its pending flag (changed there, read
without it by `pending`, Linux timer_pending), and `Wheel.running` /
`runner` (Linux running_timer). `deadline_ns` (/proc/net/tcp) takes
the lock to read the bound.

- **HARD** callbacks run in the CPU's tick with interrupts off and only
  wake tasks (`schedule_timeout`'s on-stack timer, Linux
  process_timeout). **SOFT** callbacks run in `ktimers/N`, process
  context (`Alarm`s run the network protocol timers); the tick only
  wakes the thread.
- `run` sets `running` under the base lock, drops it for the callback
  and clears `running` once it holds it again (Linux __run_timers).
  `del_timer_sync` detaches and checks `running` under the lock (Linux
  try_to_del_timer_sync), and waits with it dropped for a running
  callback, then retries (spinning
  for HARD, whose callback runs with interrupts off on another CPU;
  sleeping on the base's wait queue for SOFT, whose callback may
  sleep), so the owner may go once it returns; dropping a `TimerList`
  does that. From the timer's own callback it only detaches (the base
  records the running task, `Wheel.runner`, and never touches the
  timer after the callback returns), so a callback may drop the
  timer's owner; elsewhere (SOFT) never where sleeping is not allowed.
- `ArcTimer<T>` (Linux sk_reset_timer/sk_stop_timer): a SOFT timer in
  an `Arc`-owned object; a pending arm holds one reference to the
  owner (taken when `reset` finds it idle, `mod_timer` returning the
  old pending state), which the callback receives and drops, or
  `stop` drops when it disarms. The owner's last reference may thus
  go in its own callback, and while the timer can fire the owner is
  alive. Its drop only disarms, never waits (Linux neigh_destroy,
  sk_free): the arm's reference covers the callback until the base no
  longer touches the timer, so no other drop can be the last while a
  callback runs, and the owner may go in any context (`rcuc/N` after
  `kfree_rcu` or `RcuUnlinked::defer`).
- Order: `Alarm.st` -> `TimerBase.wheel` (leaf).

#### High-resolution timers (time/hrtimer.rs; Linux kernel/time/hrtimer.c)

An `HrTimer` is embedded in its pinned owner and fires at an absolute
CLOCK_MONOTONIC or CLOCK_REALTIME ns time. Each CPU has a HARD and a
SOFT `HrBase`: `q`, an IrqSpinlock over one sorted intrusive list per
clock and `running` (Linux hrtimer_cpu_base->running). Each timer's
expiry and clock (`HrTimer.node`, a `sync::LockedCell`: Linux
node.expires / _softexpires and its clock base) are read and written
only under the lock of the base it names; `pending` changes there and
is also read without it. `run` sets `running` under `q`, drops it for
the callback and clears it once it holds it again (Linux
__run_hrtimer). The CPU's clock event device runs one-shot,
programmed for the earliest expiry of both bases; the scheduler tick is
a HARD hrtimer re-armed every TICK_NS.

- HARD callbacks run in the timer interrupt (the tick, sleep
  deadlines, timerfd, which only takes its IrqSpinlock and wakes
  readers); SOFT ones in `ktimers/N`, like the wheel's: POSIX timers
  and itimers send signals. Both cancel with
  `cancel_sync` before taking their `inner` lock (their callback takes
  it) and re-arm under it, so owner locks (`PosixTimer.inner`,
  `Timerfd.inner`) -> `HrBase.q`.
- `clock_settime` (thread context, timekeeper lock dropped) runs
  `timerfd::clock_was_set`: it walks the cancel-on-set timerfds on the
  RCU list `CANCEL_LIST` under `rcu::read_lock` and locks each one's
  `inner` in turn (no allocation, no list lock). Absolute realtime hrtimers see the new
  time at the next clock event (at most a tick away).
- `start` queues and reprograms with interrupts off (no migration or
  timer interrupt in between), on the starting CPU's base: it moves the
  timer there unless its callback is running on the old one (Linux
  switch_hrtimer_base). `HrTimer.base` changes only under the old base's
  lock, and every locker rechecks it after locking (`lock_base`, Linux
  lock_hrtimer_base). `cancel_sync` detaches and checks `running`
  under the base lock (Linux hrtimer_try_to_cancel), then waits out a
  running callback with it dropped and retries (spinning for HARD,
  sleeping on the `ktimers/N` wait queue for SOFT); dropping an
  `HrTimer` does that.
- `HrBase.q` is a leaf: callbacks run with it dropped, and
  `reprogram` takes the two bases' locks one at a time.

#### Wait Queues (sync/waitqueue.rs)

Linux-style wait queues (`include/linux/wait.h`, `kernel/sched/wait.c`).

```rust
pub struct WaitQueue { head: IrqSpinlock<List<WaitEntry>> } // -> pi_lock -> rq lock

// Sleeper side (process context, no spinlocks held)
wq.wait_event(|| cond);                                  // uninterruptible
wq.wait_event_exclusive(|| cond);                        // woken one at a time
wq.wait_event_interruptible(|| cond)?;                   // Err(RestartSys) on signal
wq.wait_event_killable(|| cond)?;                        // Err(Interrupted) on SIGKILL
wq.wait_event_timeout(|| cond, ticks) -> u64;            // 0 = timed out
wq.wait_event_interruptible_timeout(|| cond, ticks)?;    // Ok(left) / Err
// open-coded: let w = pin!(WaitEntry::new());
//   prepare_to_wait(w.as_ref(), state); check; schedule(); finish_wait(w.as_ref())
// poll/epoll: add_wait_queue/remove_wait_queue (entries with a wake function)

// Waker side (any context, including IRQ handlers)
wq.wake_one(); wq.wake_all();
wq.wake_poll(POLLIN | POLLRDNORM);                       // Linux wake_up_poll
```

- **Entries are intrusive** (Linux wait_queue_entry): a `WaitEntry` is
  pinned on the waiter's stack (a poll table pins its entries on the
  heap), links into the queue's list, and records the queue it is on
  (`wq`, written under the head lock). Dropping an entry unlinks it
  under that lock, so every way out of a wait (signal, error, panic)
  leaves nothing behind; the queue outlives its entries. A waker that
  removes an entry clears its `wq` last (Release); `finish_wait` sees
  it clear (Acquire) and skips the lock, and the waker no longer
  touches the entry (Linux list_del_init_careful).
- **Wakeup** (Linux __wake_up_common): `wake_one` wakes every
  non-exclusive entry and the first exclusive one whose wake succeeds
  (`wake_up`); `wake_all` wakes all. An entry's wake function (poll's
  `pollwake`, flagging its table) replaces the default task wakeup and
  runs under the head lock; autoremove entries are unlinked once woken.
  `sync::Mutex` and `Completion` wait exclusively. `wake_poll` passes
  the events that happened as the key (Linux wake_up_poll): tasks and
  poll/select entries wake as for `wake_all`, an epoll item waiting for
  none of them does not (ep_poll_callback), so an edge-triggered item
  is reported once per matching event. Wakers key what Linux keys
  (sockets, pipes, eventfd, timerfd, n_tty input, pidfd, io_uring,
  epoll's own pollers) and leave the rest unkeyed.

- **IRQ class:** the head lock is an `IrqSpinlock`; like Linux
  `__wake_up_common`, tasks are woken under it (`try_to_wake_up`: the
  task's pi_lock, then this CPU's rq lock or the target CPU's lock-free
  wake list), so the order is head -> pi_lock -> rq lock and nothing
  else nests inside it. Wakers never take `TASKLIST` and never allocate
  (no waiter list is collected; run queues are intrusive), so `wake_*`
  is safe from IRQ handlers. An entry names its task by pointer: the
  sleeper unregisters before it can go away. Registration
  (`prepare_to_wait`) links under the head lock in thread context only.
- **No lost wakeups:** the sleeper registers and sets its state before
  re-checking the condition (see 3.1 Sleep / Wakeup Protocol). Wakers must
  make the condition true before calling `wake_*`.
- **Autoremove:** a woken entry is removed by the waker; `finish_wait`
  (or the entry's drop) removes it otherwise. Poll entries stay until
  the poll ends.
- `wait_event_*_deadline` take an absolute deadline on CLOCK_MONOTONIC
  or CLOCK_REALTIME and sleep on an on-stack HARD hrtimer
  (`hrtimer::schedule_hrtimeout`): ns-precise, never early.
  Wakers of queues shared by waiters with different conditions (SysV
  sem/msg, mqueue, sockets) use `wake_all` or `wake_poll` (which wakes
  all as well): a `wake_one` could pick a waiter whose condition is
  still false.
- `cond` closures run with the task state set, so they must not sleep:
  they read atomics or take spin locks (eventfd, inotify, timer wheel)
  but never a sleeping lock (`sync::Mutex`, `RwSem`), whose contended
  path would sleep and reset the task state. Objects guarded by a
  sleeping lock publish what their waiters test: a pipe's ring indices
  (one `head_tail` word), its usable slot count (`max_usage`, changed by
  F_SETPIPE_SZ) and its reader/writer counts are atomics written under
  `Pipe.inner` and read without it (Linux pipe_readable /
  pipe_writable).

**Page Locking (Linux folio_wait_table Pattern):**

`PAGE_WAIT_TABLE: [WaitQueue; 256]` is hashed by page frame. `CachedPage::lock`
sleeps with `wait_event(|| !locked)` and retries its CAS; `unlock` and end of
writeback use `wake_all` (the bucket is shared by unrelated pages, so a
single wakeup could be consumed by the wrong waiter). **Early Boot
Fallback:** if scheduling is not yet enabled, page locking spins.

### 3.4 Namespaces

**Location:** `ns/mod.rs`, `ns/uts.rs`, `ns/common.rs`, `ns/tree.rs`, `ns/setns.rs`,
`ns/listns.rs`, `fs/pseudo/nsfs.rs`

The namespace subsystem follows Linux's `nsproxy` pattern, where each task has
a reference to an `NsProxy` that holds pointers to its namespaces. Multiple
tasks can share the same `NsProxy` (e.g., threads created without CLONE_NEW* flags).

#### Namespace Locks

| Variable | Type | Purpose |
|----------|------|---------|
| `Task.nsproxy` | `Option<Arc<NsProxy>>` under `Task.alloc_lock` | The task's namespaces |
| `UtsNamespace.name` | `RwLock<NewUtsname>` | Per-namespace UTS data |
| `MntNamespace.root` | `RwLock<Option<Arc<Mount>>>` | Mount tree root (3.3) |
| `UserNamespace.uid_map.extents` | `RwLock<Vec<UidGidExtent>>` | UID mapping extents |
| `UserNamespace.gid_map.extents` | `RwLock<Vec<UidGidExtent>>` | GID mapping extents |
| `PidNamespace.alloc` | `AtomicU32` changed under PIDMAP_LOCK | Pid count, NS_ADDING, NS_INIT (3.1.1, "A pid namespace's init") |
| `PidNamespace.reaper`, `reboot` | `TableCell` (TASKLIST) | Child reaper, reboot(2) status (3.1.1) |
| `ns::tree` `NS_TREE` | `IrqSpinlock<Trees>` leaf, global | Every namespace of every type by `ns_id` (Linux ns_tree_lock, a seqlock, and ns_unified_root, the per-type roots, each user namespace's ns_owner_root, here one tree keyed by (owner id, id)): each entry a `Weak` (a network namespace's passive) and its owner's id. Global as Linux's: a lookup by id must see every namespace. `tree::add` lists a namespace once made whole, its three nodes allocated before it is made (`tree::Nodes`: creation fails with ENOMEM, the insert cannot); `tree::remove` takes it out where its last reference goes (`NsCommon`'s drop; a network namespace's `cleanup_net` under NET_NAMESPACE_LIST write, a mount namespace's drop before its unmount), so in any context, hence IRQ-safe; the nodes are freed after the unlock. Lookups and walks (`lookup`, `lookup_at`, `adjoined`, `adjoined_any`, `walk`) upgrade a `Weak` under it (an atomic) and check the namespace (`Strong::get`: in active use, Linux ns_get_unless_inactive, and a network namespace's counted reference, `get_net`) or drop the reference only after the unlock. Under it nothing is allocated, freed or dropped and no lock taken: innermost, below any lock a namespace's last put may run under |
| `NsCommon.linked` | `AtomicBool` under `NS_TREE` | The namespace is in the tree (Linux !RB_EMPTY_NODE(ns_tree_node)): set by `tree::add`, cleared by `tree::remove`, both under `NS_TREE`; `NsCommon`'s drop reads it with exclusive access and takes the lock only if set |
| `NsCommon.active` | `AtomicU32` (no lock) | Active references (Linux __ns_ref_active, an atomic_t), changed lock-free in any context, TASKLIST and PIDMAP_LOCK-free paths included (`Namespace::active_get`/`active_put`): a first one takes one on the owning user namespace and a last puts it, walking up the owners (each kept in memory by its child's `Arc`); 1 and never changed for an initial namespace. Held by an installed nsproxy for each namespace but the user one (`NsProxy.active`), by a listed task for its credentials' user namespace (`TaskInner.user_ns`), by a `Pid` for its namespace (alloc to `release_numbers`) and by an nsfs inode (`NsInode`, made to dropped). `tree`'s hand-out reads it after the unlock, racily, as Linux |
| `NsProxy.active` | `bool` (no lock) | It holds its namespaces' active references (Linux deactivate_nsproxy vs nsproxy_free): set once by `activate` at install (`init_task_ns`) while the `Arc` is still unique, read by its drop |
| `TaskInner.user_ns` | `TableCell` (TASKLIST) | The user namespace whose active reference the task holds while listed (Linux real_cred->user_ns: get_cred_namespaces, exit_cred_namespaces): taken in `GlobalTaskTable::insert`, put in `remove_task`, moved by `switch_cred_namespaces` (the task itself, TASKLIST write; the old `Arc` dropped after) |
| `NsCommon.stashed` | `AtomicPtr<Dentry>` (no lock) | The namespace's nsfs dentry while one lives, no reference (Linux ns->stashed): set by a compare-exchange from null (`ns_get_path`; the loser drops its own dentry and retries), cleared by a compare-exchange from that dentry in its kill (`DentryOps.d_prune`, Linux ns_prune_dentry) before its memory's grace period starts; a reader loads it and takes a reference under an RCU read guard (`DentryRef::try_get`, Linux lockref_get_not_dead) |

`CgroupNamespace`, and a `PidNamespace`'s level, parent and number
bitmap, are immutable after creation (no lock).

#### Locking Rules

1. **The NsProxy is a Task field** - `get_task_ns(&Task)` clones the
   `Arc<NsProxy>` out under its alloc_lock (the task itself reads
   `current().nsproxy()` lock-free);
   `init_task_ns` / `exit_task_ns` swap it under the alloc_lock (the
   task itself, or a fork child before it runs) and drop the old one
   after unlocking (a network namespace's teardown takes RTNL; nothing
   is released under the lock).

2. **Per-namespace data uses RwLock** - UTS name data is read-heavy (uname is
   called frequently) but rarely written (sethostname/setdomainname are rare).
   It is taken with no task lock held (after the clone out).

3. **clone/unshare** - `copy_namespaces()` reads the parent's, then
   installs the child's under the child's alloc_lock, never with a
   namespace lock held; it runs in `copy_process()` after copy_mm, as
   in Linux (can fail on OOM).

4. **Namespace files** - an nsfs inode holds a reference to its
   namespace (Linux i_private), dropped with the inode at its dentry's
   kill: the last reference to a mount or network namespace may go
   there, and a mount namespace's end sleeps (NAMESPACE_SEM), so an
   nsfs dentry is put only where sleeping is allowed (a file's
   deferred release, a mount's teardown, a path put in a syscall), as
   Linux dput. setns (`ns/setns.rs`) builds the new set aside with no
   lock held (TASKLIST read briefly for the thread check, as Linux
   thread_group_empty), then switches to it under the alloc_lock.

5. **listns(2)** (`ns/listns.rs`) - no lock held across its walk:
   each step takes `NS_TREE` once (`tree::walk`), the namespace it
   hands out is checked (type, the caller's own or may see all) and
   its id copied out with nothing held; a reference it held last may
   be dropped there, in syscall context.

#### Lock Order for Namespace Operations

```
Task.alloc_lock (clone the Arc<NsProxy> out, release; none for the
    task itself) then, with nothing held: UtsNamespace.name / MntNamespace.root /
    UidGidMap.extents (leaves)
Any lock (a namespace's last put, NET_NAMESPACE_LIST write in
    cleanup_net, NAMESPACE_SEM in graft) → ns::tree NS_TREE
    (IrqSpinlock, innermost leaf)
```

#### Syscall Patterns

**uname(2):** Read path - acquires `UtsNamespace.name` read lock briefly:
```rust
let uts_ns = current_uts_ns();  // cloned out lock-free (current)
let tmp: NewUtsname = *uts_ns.name.read();  // RwLock read
// Copy to userspace
```

**sethostname(2)/setdomainname(2):** Write path - acquires exclusive lock:
```rust
let uts_ns = current_uts_ns();  // cloned out lock-free (current)
{
    let mut guard = uts_ns.name.write();  // RwLock write
    guard.nodename = new_name;
}
```

#### Reference Counting

`NsProxy` and individual namespaces use `Arc` for reference counting:
- Tasks share `Arc<NsProxy>` through `Task.nsproxy`
- Clone without CLONE_NEW* flags: child shares parent's `Arc<NsProxy>`
- Clone with CLONE_NEW* flags: new `NsProxy` created with new namespace(s)
- Exit: `exit_task_ns` takes it out of the Task; the Arc drops after
  the task's alloc_lock is released

### 3.5 Timekeeping

**Location:** `time/mod.rs`

The timekeeper uses a **seqlock** pattern for lock-free reads with consistent
snapshots. Writers (`update` from the CPU 0 timer tick, `set_realtime` from
clock_settime/settimeofday, `init`) hold `TimeKeeper.lock`, an IrqSpinlock
leaf, across the whole odd-`seq` window (Linux `timekeeper_lock`,
`raw_spin_lock_irqsave` around `write_seqcount_begin/end`). IRQs off there is
required: a tick on the writer's CPU reads the clock (timer expiry) and
would spin forever on the odd `seq` of the write it interrupted. The lock also
keeps two writers from interleaving their `seq` bumps (which would let
readers accept a torn snapshot). Nothing is taken under it.

```rust
pub struct TimeKeeper {
    lock: IrqSpinlock<Ntp>,      // Serializes writers, IRQs off (leaf); the adjtimex NTP state
    seq: AtomicU32,              // Sequence counter (odd = write in progress)
    cycle_base: AtomicU64,
    mono_base_ns: AtomicU64,
    realtime_offset_ns: AtomicI64,
    tai_offset: AtomicI32,       // TAI - UTC, seconds; seqlock-protected (CLOCK_TAI reads it in the same pass)
    mult: AtomicU64,
    shift: AtomicU32,
    tsc_freq_hz: AtomicU64,
    initialized: AtomicU32,
    read_cycles_fn: spin::Once<fn() -> u64>,
}
```

#### Seqlock Read Pattern

```rust
loop {
    let seq1 = self.seq.load(Ordering::Acquire);
    if seq1 & 1 != 0 { continue; }  // Writer active, retry

    // Read all values...
    let cycle_base = self.cycle_base.load(Ordering::Relaxed);
    // ...

    fence(Ordering::Acquire);         // smp_rmb (read_seqcount_retry)
    let seq2 = self.seq.load(Ordering::Relaxed);
    if seq1 != seq2 { continue; }  // Data changed, retry

    return computed_time;
}
```

Writers (`write_begin`/`write_end`, under `TimeKeeper.lock`): `seq += 1`
then `fence(Release)` (smp_wmb) before the field stores, and
`fence(Release)` then `seq += 1` after them (Linux write_seqcount_*).

#### CPU time (task/cputime.rs; Linux kernel/sched/cputime.c)

Tick-based, as Linux CONFIG_TICK_CPU_ACCOUNTING: nothing is done at
syscall entry or exit. The arch's interrupt entry records in its
`PerCpu.irq_user` whether the interrupted frame was user mode (x86: the
frame's CS RPL; arm64: the EL0 vector), saved and restored around the
handler (Linux set_irq_regs); only that CPU writes it, interrupts off.
Each tick (`scheduler_tick`, interrupt context) then calls
`account_process_tick`: `TICK_NS` of utime if `irq_user`, else of stime
unless it interrupted only the idle task, added to the running task
(load and store: the tick of its CPU is the only writer) and, while
its group keeps CPU timer totals, to `GroupCputimer`'s sums (RMWs:
every thread's CPU adds). Runtime is exact (`se.sum_exec_runtime`,
3.1). Readers: SCHED clocks read the runtime (`task_sched_runtime`
under the task's rq lock); PROF/VIRT clocks, CPU timers, itimers and
RLIMIT_CPU the raw samples; times, getrusage, wait's rusage and
/proc/<pid>/stat scale the samples to the runtime (`cputime_adjust`,
under `prev_cputime`, an IrqSpinlock leaf); SIGCHLD's times are the
raw samples (Linux do_notify_parent).

### 3.6 Kernel Logging (printk)

**Location:** `printk.rs`, `console.rs`

The printk subsystem uses IRQ-safe locks to ensure SMP-safe message output
while avoiding deadlocks in interrupt context:

```rust
/// Serializes console/serial writes across CPUs (IRQ-safe)
static OUTPUT_LOCK: IrqSpinlock<()> = IrqSpinlock::new(());

/// Protects the ring buffer state (IRQ-safe)
static PRINTK: IrqSpinlock<PrintkState> = IrqSpinlock::new(PrintkState::new());

/// Console driver registry (IRQ-safe)
static CONSOLE_REGISTRY: IrqSpinlock<ConsoleRegistry> = IrqSpinlock::new(...);
```

**Locking Hierarchy:**
```
1. OUTPUT_LOCK (held for entire message, including newline) - IrqSpinlock
   ↓
2. PRINTK (held briefly for ring buffer write) - IrqSpinlock
   ↓
3. CONSOLE_REGISTRY (console_write's snapshot of the enabled consoles) - IrqSpinlock
```

**The record log** (`kmsg.rs`): `LOG` (IrqSpinlock) holds the
records that /dev/kmsg and syslog(2) read. printk adds each complete
line under OUTPUT_LOCK (try_lock while panicking); a /dev/kmsg write
adds its record under `LOG` alone, then writes the console under
OUTPUT_LOCK. Nothing allocates under `LOG`: readers size their
buffers before taking it, and syslog reads copy the ring out (one
memcpy) and format after releasing it. printk may run with run-queue locks held,
so it never wakes readers itself: it sets `WAKE_PENDING`, and the
scheduler tick (no locks held) wakes them (Linux defers the klogd
wakeup through irq_work).

**Rate limits** (`util/ratelimit.rs`, Linux lib/ratelimit.c): a
`RatelimitState` (a caller's static: `buffer_io_error`,
`__find_get_block_slow`'s report) keeps its interval's start under an
`IrqSpinlock` leaf, any context (bio completions call it in hardirq),
only tried: a caller that finds it held decides from the burst left
(an atomic, as Linux's rs_n_left) without it. The suppressed-count
report is printed after the lock is dropped (Linux printk_deferred
under it), so OUTPUT_LOCK never nests under it.

**Why IRQ-Safe:**

All three locks use `IrqSpinlock` because printk can be called from:
- Normal process context
- Timer interrupt handlers (e.g., debug output)
- Exception handlers (e.g., page fault diagnostics)

Using `IrqSpinlock` (like Linux's `raw_spin_lock_irqsave()`) ensures:
1. Interrupts disabled while holding the lock
2. No deadlock if printk is called from interrupt context
3. No deadlock if a timer interrupt fires while another CPU holds the lock

**Lock Separation:**

The three-lock design serves different purposes:
- `OUTPUT_LOCK`: Ensures entire formatted messages are written atomically
- `PRINTK`: Protects the ring buffer data structure
- `CONSOLE_REGISTRY`: Protects the list of registered consoles

This separation allows:
1. Buffering to proceed while another CPU writes to console
2. Console code to potentially log (though not currently needed)

**PrintkWriter Pattern:**

The `PrintkWriter` struct holds `OUTPUT_LOCK` for the duration of
formatting (`output_lock`, which records the owning CPU in
`OUTPUT_OWNER`). A printk nested on the CPU that holds it (console code,
or a lockdep report from an allocation made under it), or one during an
oops while another CPU holds it, gets no guard and writes the serial
port directly (Linux printk_safe's recursion context) instead of
spinning on its own lock.

This ensures that `write!` macro invocations (which may call `write_str` multiple
times during formatting) produce atomic output.

**printkln! Atomicity:**

The `printkln!` macro uses a single `PrintkWriter` for both the message
and newline. Its arguments are evaluated (a `match` on `format_args!`,
whose temporaries live to the end of the match) before `OUTPUT_LOCK` is
taken, as a Linux printk caller's are, so an argument that allocates
does not allocate under it:

```rust
macro_rules! printkln {
    ($($arg:tt)*) => {{
        match format_args!($($arg)*) {
            args => {
                let mut writer = PrintkWriter::new();
                let _ = writer.write_fmt(args);
                let _ = writer.write_str("\n");
                // OUTPUT_LOCK released when writer drops
            }
        }
    }};
}
```

**SMP Safety:**

Before the OUTPUT_LOCK fix, multiple CPUs could interleave output character-by-character:
```
Timer: stTimearted with Timer: started...  (corrupted)
```

After the fix, each message is atomic:
```
Timer: started with 10ms interval
Timer: started with 10ms interval
```

**Panic-Safe Output:**

During panic, the normal locking path can deadlock if the panicking CPU already
holds `OUTPUT_LOCK`. The printk subsystem handles this with:

1. **`OOPS_IN_PROGRESS` flag** - Atomic bool set at panic entry via `set_oops_in_progress()`
2. **`try_lock()` fallback** - Non-blocking lock attempt in panic mode
3. **Direct serial output** - If lock unavailable, bypass console subsystem

```rust
// In PrintkWriter::write_str() during panic:
if self._guard.is_some() {
    printk_write_locked(s.as_bytes());  // Normal path
} else {
    direct_serial_write(s.as_bytes());  // Panic fallback
}
```

**Console Integration:**

`console::console_write()` takes `CONSOLE_REGISTRY` only for a snapshot
of the enabled consoles (or, with none registered, the early UART
write), then writes each with the lock dropped; the tty console's write
waits until the transmitter is empty before it returns (Linux
serial8250_console_write, pl011_console_write), so nothing else needs
to flush a console: the idle loop never touches one.

A console whose output a thread sends (the USB serial console, 3.10)
only queues it in its write: printk runs in any context, run-queue
locks included, so the write cannot wake the thread. It calls
`console_defer_kick` (sets `KICK_PENDING`, an atomic) and the
scheduler tick (`console::tick`, no locks held) snapshots the enabled
consoles under `CONSOLE_REGISTRY` and calls each one's `kick` with it
released, which queues work (Linux defers printk's wakeups through
irq_work, defer_console_output).

```rust
pub fn console_write(data: &[u8]) {
    let snapshot = {
        let registry = CONSOLE_REGISTRY.lock();  // IrqSpinlock
        // ...early UART if none registered...
        registry.enabled_consoles_snapshot()
    };
    for console in snapshot.into_iter().flatten() {
        console.write(data);  // outside the lock
    }
}
```

The lock order (OUTPUT_LOCK → PRINTK → CONSOLE_REGISTRY) is maintained throughout.

**Console Flags (Linux CON_* Pattern):**

Console drivers are registered with flags that control behavior:

```rust
bitflags! {
    pub struct ConsoleFlags: u16 {
        const ENABLED = 1 << 0;       // Console can receive output
        const BOOT = 1 << 1;          // Early boot console
        const PRINTBUFFER = 1 << 2;   // Replay log buffer on registration
        const CONSDEV = 1 << 3;       // Primary console (/dev/console target)
    }
}
```

- `BOOT` consoles (e.g., serial) are the first output during early boot
- `CONSDEV` consoles (e.g., graphics) are the primary interactive console
- `ENABLED` is automatically set on registration; only enabled consoles receive output

**Trace ring (`trace.rs`; Linux kernel/trace ring_buffer):** trace
events (`trace::emit`, e.g. xHCI's, system `xhci-hcd`) never reach
printk: an enabled event (its flag an atomic, read lock-free) is
formatted on the stack and appended to this CPU's ring, an
`IrqSpinlock` leaf (any context, hardirq included; nothing allocated
under it; the oldest records are overwritten). `EVENT_MUTEX` (sleeping
`sync::Mutex`, Linux event_mutex, thread only) holds the registered
systems and serializes enabling: the `events/.../enable` stores and
`trace_event=` (applied as each system registers) set the flags under
it, allocating the rings first (once, a `Once` per CPU; Linux
tracing_update_buffers); registration makes the system's tracefs
directories under it (order: `EVENT_MUTEX` -> the tracefs directory's
`i_rwsem`, `fs::libfs` 3.3; an enable file's write, under that file's
`i_rwsem` like every regular file's, takes `EVENT_MUTEX`; no tracefs
entry is ever removed). tracefs's `trace` file (`fs::tracefs`,
/sys/kernel/tracing) copies each ring out under its lock into a buffer
allocated before taking it, one CPU at a time, and formats with no lock
held; an O_TRUNC open for writing (Linux tracing_open) empties each
ring under its lock, one CPU at a time, from the file's open (no other
lock).

### 3.7 Signal Infrastructure

**Location:** `signal/mod.rs`, `signal/pending.rs`, `signal/syscall.rs`

The signal subsystem manages signal handlers (SigHand) and per-task signal state
(blocked masks, pending signals). It follows Linux's `sighand_struct` and signal
state patterns.

#### Signal Locks

| Variable | Type | Purpose |
|----------|------|---------|
| `Task.sighand` | `RcuLockedArc<SigHand, GlobalTaskTable>` | The task's handler table (Linux task->sighand, `__rcu`): set by fork in the TASKLIST write section that lists the child (`install_fork_signal`, Linux copy_process: visible with its sighand); replaced (exec's unshare_sighand) or cleared at release (`unhash`, Linux __exit_signal from release_task: a zombie keeps its handlers) under TASKLIST's write lock and the old table's `siglock`, the old reference dropped a grace period later (`put_rcu` on `SigHand.puts`); read under TASKLIST (the views' `sighand`) or an RCU read guard (`get_task_sighand`) |
| `SigHand.siglock` | `spin::Mutex<Box<[SigAction]>>` (its data the action table), thread context only (not IRQ-safe), one lockdep class (`new_siglock`); held through a `SigGuard` (`sync::InstanceGuard`), the proof siglock-owned cells check against their owner table | Linux sighand->siglock: held with TASKLIST's write lock while a task stops naming the table (`SigHand::leave`: exec, release) and while a thread list of a group whose threads name it changes (`SignalStruct.threads`); held across a send, from its prepare to its last wakeup (`send_task_in`, `send_timer_sigqueue`; Linux send_signal_locked), across do_signal_stop's thread walk, and around a group kill's (`zap_group`: exit_group, de_thread). Never two at once (one lockdep class): a stop notice to a parent is sent after the stopping thread's is dropped. Not IRQ-safe as in Linux PREEMPT_RT: hk sends no signal from an interrupt handler (rule 1, `check_send_context`); a hardirq sender would make it an IrqSpinlock (Linux irqsave). Owns `Task.sig` (each task's, of the tasks naming the table). Owns `SignalStruct.jobctl` and `shared` of the group whose threads name it. Its data is the action table. Order: TASKLIST → `siglock`. |
| `SignalStruct.threads` | `sync::LockedByBoth<OwnedList<ThreadNode>, GlobalTaskTable, SigHand>` | The group's threads (Linux signal->thread_head): changed under TASKLIST's write lock and the siglock of the table every thread names (the cell's owner, checked at run time: set when the group gets its first task, moved by exec's unshare under the old siglock), walked under either: `GlobalTaskTable::threads` (TASKLIST), `SignalStruct::threads` (a `SigGuard`: complete_signal's thread choice, `zap_threads`, `stop::prepare`, do_signal_stop). A task joins in the section that gives it its group (`install_fork_signal`, `init_task_signal`) and leaves at release (`unhash`, with its sighand clear, under one siglock hold). CLONE_THREAD requires CLONE_SIGHAND (EINVAL), so a group's threads share one table |
| `SigHand.users` | `TableCell<u32>` (TASKLIST) | Tasks whose `Task.sighand` it is, changed with that field (Linux sighand->count): exec copies a table with more than one (unshare_sighand) |
| `Task.sig` | `sync::InstanceCell<TaskSignalState, SigHand>` (per task), owned by the siglock of the table `Task.sighand` names | Blocked mask, private pending set, altstack; a ptrace stop: `jobctl` (TRACED, PTRACE_FROZEN, LISTENING), `ptrace_code`, `last_siginfo` (3.1.3) (Linux task->blocked, ->pending, ->jobctl, ->exit_code, ->last_siginfo: no lock of their own, under the siglock of the table the task names). Borrowed (`signal::sig_of`) under a `SigGuard` of that table, checked at run time: `lock_task_sighand` (RCU, retry) or, under TASKLIST, `lock_sighand_in`. The owner is set where the task first names a table (`install_fork_signal`, `init_task_signal`: the state was built unseen) and moves with `Task.sighand` (exec's unshare, TASKLIST write + the old siglock: Linux unshare_sighand), so a holder of the old table that found the task through it never shares the state with a holder of the new one; after release (no table) it is unreachable, as Linux's (lock_task_sighand fails). A kernel thread has no table: its state is never reached |
| `Task.thread_flags` TIF_SIGPENDING | atomic, recomputed under siglock | Pending-signal flag |
| `SignalStruct.jobctl` | `sync::InstanceCell<stop::GroupStop, SigHand>`, owned by the siglock of the table the group's threads name (moved with the thread list: `SignalStruct::set_owner`); reached through the group's `SignalStruct` (a task's `cpu_group`, Linux task->signal, fixed for its life) | Job-control state (Linux signal->flags' SIGNAL_STOP_*/SIGNAL_CLD_*, group_stop_count, group_exit_code as the stop's signal: under siglock). A thread's stop bits (`jobctl` STOP_PENDING, STOP_CONSUME, STOPPED, TRAP_STOP, TRAP_NOTIFY, TRAPPING) change in the same hold. Borrowed by: a stop signal's or SIGCONT's send, across its prepare, queue, thread choice and wakeups (Linux prepare_signal/complete_signal); do_signal_stop; a ptrace trap's entry (`ptrace_stop_why`) and do_jobctl_trap; PTRACE_INTERRUPT; `zap_threads`; `exit_participate`; `notify_cld`; the tracer's attach and unlink; a clone's insert (`join_group_stop`); wait (`take_stopped`, `take_continued`, under `lock_sighand_in`); a stop notice's code. A group exit starts under the siglock (`SignalStruct::start_exit`: do_group_exit with its zap, a fatal signal's `group_kill`, the last thread's exit; Linux SIGNAL_GROUP_EXIT under siglock), so a stop signal's or SIGCONT's send, which checks for one before its prepare, is dropped by an exit begun before it and seen by one begun after. The siglock is dropped before any parent is notified (a SIGCHLD send takes the parent's); wakeups under it are allowed. Entries a stop signal or SIGCONT flushes go to the caller's `SigPending`, dropped with no signal lock held (a timer's entry goes back to its timer) |
| `SignalStruct.shared` | `sync::InstanceCell<GroupPending, SigHand>`, owned as `jobctl` (`SignalStruct::shared`, `signal::group_pending`, Linux t->signal->shared_pending) | Thread-group pending set and curr_target (Linux signal->shared_pending, curr_target), and the forks in progress (`GroupPending.multiprocess`, Linux signal->multiprocess): a fork links its boxed `ForkDelay` node under its siglock at its start (`fork_signals_begin`, with its ERESTARTNOINTR check of the caller's pending signals in the same hold), a send of a `PidType::Pgid` signal records it in every node in the hold that queues it, and the child's attach (`install_fork_signal`, TASKLIST write) unlinks the node under the parent's siglock (Linux copy_process) and, after dropping it, ORs its set into the new group's set under the child's table's siglock; a failed fork unlinks it under its siglock as it returns |
| `SignalStruct.ignored_timers` | `sync::InstanceCell<OwnedList<IgnoredAdapter>, SigHand>`, owned as `jobctl` | Interval timers whose signal was ignored or flushed, one reference each (Linux signal->ignored_posix_timers under siglock): listed by `posix_timer::sig_ignore` (a timer send that finds the signal ignored, `send_timer_sigqueue`; a flush under siglock: `flush_ignored` in a send's prepare and in sigaction's flush; Linux posixtimer_sig_ignore, sigqueue_free_ignored), each entry put back in its timer's `sigq` in that hold; taken off by sigaction's requeue (`sig_unignore`, the entry queued under the same siglock, Linux posixtimer_sig_unignore) and by the timer's delete, always by a thread of its process (`signal::cleanup_ignored` under that thread's siglock, Linux posix_timer_cleanup_ignored under current->sighand->siglock); entries left on a SignalStruct that goes (its last exit raced) are put by its Drop through exclusive access, no siglock (`posix_timer::drop_timers`, Linux exit_itimers' mop-up). Under the siglock a timer's `inner` (its periodic flag and sequence) and `sigq` are taken as leaves: no path takes the siglock under either (a timer's signal is sent after `inner` is dropped); a timer reference dropped there goes through `put_rcu` |
| `SigPending` list | `Option<Box<SigQueue>>` under the set's lock | Queued siginfo (Linux sigpending.list of struct sigqueue) |
| `SigHand.siglock` data | `Box<[SigAction]>` (64 entries, `Signal::idx`) inside the siglock (`SigGuard` derefs to it, `signal::action`) | Signal handler table (Linux sighand->action under siglock): read and written under the siglock; a send reads it in its hold (`sig_ignored`, `fatal`); `SigHand::get_action`, `set_action`, `ign_cgt`, `flush_handlers`, `deep_clone` take the siglock themselves (callers hold none); exec's unshare copies it into the new table under the old siglock (Linux unshare_sighand) |
| `SignalStruct.rlim` | `IrqSpinlock<[RLimit; N]>` | Resource limits (leaf; nothing allocates under it: a fork allocates its SignalStruct, then copies the limits under the parent's, as Linux copy_signal under task_lock) |
| `SignalStruct.subreaper` | `TableCell<bool>` (TASKLIST) | PR_SET_CHILD_SUBREAPER (Linux signal->is_child_subreaper): set by any thread under the write lock, read under the read lock by prctl and by the reparenting it decides (`find_reaper`, in `forget_original_parent`'s write section) |
| `SignalStruct.unkillable` | `AtomicBool`, no lock | A pid namespace's init (Linux SIGNAL_UNKILLABLE): set before the group is visible (fork of a process numbered 1 in its namespace, the global init at boot), cleared once when the kernel forces a SIG_DFL signal on it; read by a send (`Target::protects`), CLONE_PARENT and delivery. A monotonic flag no other state is ordered with |

#### Locking Rules

1. **Per-task signal state is under its table's siglock** (Linux: the
   task's fields under sighand->siglock) - `with_task_signal_state`
   locks the task's table (`lock_task_sighand`: RCU, retry; None once
   released) and runs its closure on the borrowed state (no sleeping,
   no user memory, no TASKLIST, nothing released in it), then
   recomputes TIF_SIGPENDING and hands newly blocked group signals on
   in the same hold (`with_sig`, `retarget`: the thread list walked
   under siglock). Deviation: Linux siglock is IRQ-safe; hk's is thread
   context only. Audit (T0): no interrupt handler
   sends a signal (the tty receive path is not driven from the UART
   IRQ, SIGIO comes from `kill_fasync` in thread context, spin locks
   possibly held, no SIGURG generation, POSIX timer/itimer expiry runs in
   `ktimers/N`, no tick-based SIGXCPU/SIGPROF, fault signals are sent by
   the faulting task with interrupts on). `send_signal` reports
   `SIGNAL:FAIL` if called with a nonzero interrupt depth (arm64 IRQ
   entry now counts the depth too).

2. **The action table is siglock data** (Linux sighand->action) - a
   fault's signal reads it in thread context with interrupts on, like
   every sender (rule 1); dequeueing reads it after the state's hold.

4. **Never hold IrqSpinlock while acquiring Mutex** - Would violate lock ordering.

5. **Queue entries are made under siglock, GFP_ATOMIC, and freed
   outside it** (Linux __send_signal_locked's __sigqueue_alloc): once
   the locked section has decided the signal is queued (not ignored,
   not a non-RT one already pending: Linux prepare_signal,
   legacy_queue), it makes the `SigQueue` with `with_gfp(ATOMIC)` and
   charges the receiver's user (an atomic on its `Ucounts`, whose
   reference the entry keeps, 3.1.1), as Linux under siglock; a failed
   one leaves a non-RT signal pending without info and refuses an RT
   one (EAGAIN). TASKLIST may be held around it (a child's notice,
   Linux do_notify_parent under tasklist_lock). A dequeue unlinks its
   entry under the lock and the caller frees it (`Dequeued::info`)
   after; an exiting task's private set is taken under siglock with
   PF_EXITING set (`exit_participate`, Linux exit_signals:
   sigqueue_dequeue_pending) and freed after, and an exiting task
   (PF_EXITING, read under siglock) gets no private entries, so none
   outlives that flush. A zombie keeps its blocked mask and the rest of
   its state (`Task.sig`); the group's set stays in its `SignalStruct` until the
   struct goes with the last task naming it.
   Senders run in thread context, never from hardirq; every step of a
   send takes only spin locks and allocates GFP_ATOMIC, so a sender may
   hold spin locks (SIGIO from a socket wakeup under its locks, as in
   Linux): its held locks order above TASKLIST and the signal locks.

6. **A send runs under the receiver's siglock** (Linux
   do_send_sig_info, send_signal_locked, complete_signal): it reaches
   the receiver's table through `lock_task_sighand` (RCU: the table
   the task names, its siglock taken, rechecked; ESRCH once released)
   and holds it from its prepare to its last wakeup (`send_task_in`).
   No TASKLIST: a caller already holding it, read or write, sends in
   place (a process-group walk, kill(-1), a child's notice,
   exit_ptrace's EXITKILL, send_sigio, as Linux send_signal_locked
   under tasklist_lock), the siglock taken inside it. What the send
   reads of the receiver comes from its siglock, RCU (credentials,
   sender numbering: `Task::pid_nr_ns`) or a racy load (`Task.ptrace`,
   as Linux under siglock). After the signal is
   queued under the receiver's siglock, the group's thread list is
   walked under siglock (`signal::choose`), each candidate's
   state borrowed alone to test wants_signal, and whether it ends the
   group decided there, never for an init its protection covers
   (`Target::protects`). Then a decided group kill is done
   (`group_kill`, `zap_threads`: each thread's state in turn,
   nothing allocated) and the chosen thread's TIF_SIGPENDING is
   recomputed and it is woken under its siglock (Linux
   signal_wake_up under siglock), all in the same hold (a wakeup takes
   only pi_lock and run-queue locks, allowed under siglock). A send changes
   no blocked mask, so it never
   retargets (`with_sig_send`), which would take TASKLIST again. A
   thread that blocks a group signal or starts exiting hands it on
   the same way after dropping its own lock, each receiver marked and
   woken under siglock (retarget_shared_pending).
   A thread that changes its mask between the test and the wakeup
   sees the signal when it recomputes TIF_SIGPENDING.

#### Lock Order for Signal Operations

```
1. TASKLIST (read lock to find a task)
   ↓
1a. SigHand.siglock (spin Mutex; a send, the thread list; with TASKLIST
    written, Task.sighand and the thread list change; owns Task.sig,
    SignalStruct.jobctl and SignalStruct.shared: no locks of their own)
```

#### Clone Integration (CLONE_SIGHAND)

The signal subsystem integrates with `clone(2)` via `clone_task_signal()`:

**Without CLONE_SIGHAND:**
```rust
// Fork: deep clone signal handlers
let new_sighand = parent_sighand.deep_clone();  // New Arc<SigHand>
child gets independent handler table
```

**With CLONE_SIGHAND:**
```rust
// Thread: share signal handlers
child_sighand = parent_sighand.clone();  // Same Arc<SigHand>
// Both tasks share the same handler table
```

**With CLONE_THREAD:**
```rust
// Also share pending signals (thread group): both reach the group's
// pending set through the same Arc<SignalStruct> (Task.cpu_group)
child.set_cpu_group(&signal);
```

#### Syscall Patterns

**rt_sigaction(2):** Get/set signal handlers:
```rust
let mut g = lock_task_sighand(&me, &rcu)?;      // siglock (do_sigaction)
let old = replace(&mut g[sig.idx()], new);      // its action table
if new.ignores(sig) { flush_group_signal(&g, ..) } // group + each thread
else if old.is_ignore() { sig_unignore(&g, ..) }   // ignored timers requeued
drop(g);                                        // flushed entries freed,
                                                // then oact is written
```
As Linux do_sigaction, the install and its flush or requeue are one
siglock hold: no other sigaction, send or dequeue on the table runs
between them. Flushed timer entries go back to their timers in that
hold, an interval timer's listed on `SignalStruct.ignored_timers`.

**rt_sigprocmask(2):** Modify blocked mask:
```rust
with_task_signal_state(&current(), |state| {  // siglock, no TASKLIST
    state.blocked = new_mask;
});                                     // TIF_SIGPENDING recomputed
```

**kill(2)/tgkill(2):** Send signal to task (`send_sig_info(&t, ..)`,
process context only). The syscall finds and checks the target under
RCU (the struct pid's task, its credentials and session; a
`TaskRef`); the send works on that task under its siglock (Linux
kill_pid_info_type, do_send_sig_info):
```rust
let rcu = rcu::read_lock();
let g = lock_task_sighand(t, &rcu)?;      // ESRCH once released
let tg = target(t, &rcu);                 // handlers, group, limits
prepare_signal(&g, ..);                   // stop/SIGCONT effects
let sent = with_sig_send(&g, t, |t, state| {  // its Task.sig, under g
    if sig_ignored(..) { return Dropped } // SIG_IGN / default-ignore
    state.pending.add(sig);
    Queued(wants)
});                                       // TIF_SIGPENDING recomputed
complete_signal(&g, ..);                  // thread choice, wakeup
```
`with_task_signal_state` recomputes the task's TIF_SIGPENDING after every
access (the one record of it: no copy in `TaskSignalState`), so it means
"a signal is deliverable under the current mask"; interruptible sleeps
test it via `waitqueue::signal_pending()` and return `-ERESTARTSYS`/
`-ERESTARTNOHAND`.

**Syscall exit** (`entry::syscall_exit_to_user_mode`, Linux
syscall_exit_to_user_mode): it enters `do_signal(regs)` only if
TIF_SIGPENDING or TIF_RESTORE_SIGMASK is set or the result is an
-ERESTART* code (rewound even with no signal, like Linux
arch_do_signal_or_restart); otherwise it reads only the thread flags and
the result register and takes no lock. `do_signal` delivers the signal
and restarts or fails the syscall per SA_RESTART. A syscall with a
temporary mask (rt_sigsuspend, ppoll, pselect6, epoll_pwait;
`set_temp_sigmask`) saves the old one in `TaskSignalState.saved_sigmask`
under siglock and sets TIF_RESTORE_SIGMASK (current task only, an atomic
bit: no lock); a handler frame takes the saved mask and clears the bit,
otherwise `restore_saved_sigmask` puts it back under siglock on the way
out (Linux set_restore_sigmask / restore_saved_sigmask_unless).

#### Thread-Group Exit (Linux do_group_exit, zap_other_threads, de_thread)

No new lock. `SignalStruct.group_exit` (an `AtomicU64`, changed only by
compare-and-swap) holds the group's state: running, exiting with a wait
status (Linux SIGNAL_GROUP_EXIT + group_exit_code), or a thread's exec
ending the others (group_exec_task). The first exit_group or fatal
signal wins the swap; a fatal signal also overrides an exec's
de_thread, exit_group does not.

- `zap_threads` walks the group's thread list under its siglock (a
  send's, or exit_group's and de_thread's own, `zap_group`; nothing
  allocated: Linux zap_other_threads under siglock), queuing SIGKILL in
  the private pending set of each thread not yet exiting (PF_EXITING)
  under its siglock, setting its
  TIF_SIGPENDING and ending a ptrace stop there (`sigkill_task`), and
  waking it in that hold (`WakeMode::Fatal`: interruptible and
  killable sleeps; Linux signal_wake_up(t, 1) under siglock; a wakeup
  takes only pi_lock and run-queue locks).
- A thread cloned into a group whose state is set gets SIGKILL after
  `install_fork_signal` set up its signal state (`zap_new_thread`): the
  state is set before a zap takes TASKLIST and the siglock, so either
  the zap saw the new thread on the list or the clone sees the state.
- Every task keeps its `SignalStruct` (`cpu_group`, Linux task->signal)
  for its life; a zombie leader's gives the group's status to the
  reaper. A task gives its CPU time to it in the TASKLIST write section
  that takes it off its thread list (`unhash`, Linux __exit_signal).
- A leader is reported to its parent once (Linux exit_notify /
  release_task under tasklist_lock): the leader decides in the TASKLIST
  write section that makes it a zombie (`exit_notify`), each untraced
  thread in the one that ends it, which also takes it out of the task
  list (`exit_notify`, Linux autoreaps it); a thread still listed counts
  as left to report it (`group_pending`, also for a reparent), so
  exactly the last section finds the group empty, and no wait reaps the
  leader before that section.
- A traced zombie thread is released by its tracer: by its wait
  (`wait_zombie`, Linux wait_task_zombie) or at its exit, after the
  live tracees are detached, one TASKLIST write section per thread
  (`detach_zombies`, Linux exit_ptrace). The section that takes it out
  of the list also queues its zombie leader's notice if it was the last
  thread (`unhash_thread`, Linux release_task), with an entry made
  before the lock as below; the Task is released after it.
- A traced zombie leader whose tracer is outside its real parent's
  process is its tracer's alone (the parent's wait skips it) until the
  tracer reaps it (`wait_zombie`) or exits (`detach_zombies`): the
  TASKLIST write section that does so unlinks it and queues the real
  parent's notice (`Zombie::Detached`, Linux wait_task_zombie
  EXIT_TRACE, __ptrace_detach), autoreaping it if that parent does not
  wait. One write section covers both, so hk has no EXIT_TRACE state.
- A zombie's notice (Linux do_notify_parent) is queued in the TASKLIST
  write section that makes it reapable: the one that makes it a zombie
  (`exit_notify`), removes its group's last thread (`exit_notify` of
  that thread) or moves it to a parent in another process (`reparent_children`,
  Linux reparent_leader). So no wait reaps it before its signal is
  pending, and a parent the signal wakes finds it. Its pidfd pollers are woken
  in the same section, before the signal (`notify_pidfd`, Linux
  do_notify_pidfd from do_notify_parent; also for an untraced thread's
  exit), and again when a task leaves the list (`remove_task`, Linux
  __unhash_process). Under the write
  lock: the receiver and signal, the autoreap decision (the parent
  process's SIGCHLD action, in the `SigHand` of the thread the signal
  goes to) and the whole send (`signal::send_task_in`: TASKLIST →
  the receiver's siglock, the order above;
  its `SigQueue` entry made under the receiver's siglock,
  GFP_ATOMIC, rule 5); an autoreaped zombie leaves the task list there
  too (Linux EXIT_DEAD). The thread that takes the signal is chosen,
  a decided group kill done, and signalfd readers and that thread
  woken in the same section (Linux __group_send_sig_info,
  complete_signal under siglock inside tasklist_lock). After the
  lock: the autoreaped Task released.
- de_thread (exec) holds cred_guard (sleeping, outermost) while it
  sleeps killable until every other thread is released and the leader
  is a zombie (`exec_waits`, Linux notify_count: a traced zombie thread
  waits for its tracer's reap); each thread's release and each exit in
  the group wakes it directly (`exit::wake_exec` after TASKLIST, a
  read hold to find it: Linux wake_up_process(group_exec_task)); it
  holds no spinlock. A thread blocked on that cred_guard (its own exec, or an
  attach to the group) sleeps interruptibly, so the SIGKILL de_thread
  sends ends it. The old leader and exited threads are removed under
  TASKLIST and released after it.

#### Reference Counting

`SigHand` uses `Arc` for reference counting:
- Tasks share `Arc<SigHand>` through `Task.sighand`
- Clone with CLONE_SIGHAND: child shares parent's `Arc<SigHand>`
- Clone without CLONE_SIGHAND: new `Arc<SigHand>` with deep-cloned handlers
- Release: the task stops naming it (`unhash`), its reference dropped through `put_rcu`

### 3.8 Futex Subsystem

**Location:** `task/futex.rs`

The futex (fast userspace mutex) subsystem provides efficient userspace synchronization
primitives. It uses a hash bucket design similar to Linux's `futex_queues`.

#### Futex Locks

| Variable | Type | Purpose |
|----------|------|---------|
| `FUTEX_HASH_TABLE` | `[FutexHashBucket; 256]` | Hash buckets for waiters |
| `FutexHashBucket.waiters` | `sync::spin::Mutex<List<FutexQ>>` | Per-bucket waiter list (intrusive; entries pinned on the waiters' stacks) |
| `FutexHashBucket.waiter_count` | `AtomicU32` | Fast-path check for waiters |
| `Task.robust_list` | `u64` under TASKLIST | Per-task robust list head |

#### Why a Plain Spin Lock for Bucket Waiters

Futex operations run in thread context only (syscalls, task exit); the
bucket lock is a `sync::spin::Mutex` (Linux hb->lock, a spinlock_t):
no interrupt handler takes it, and wakeups are issued after it is
dropped (WakeQ). It is a leaf but for a requeue, which nests two
buckets in address order.

#### Memory Barrier Pattern (Linux-style)

The futex implementation follows Linux's memory barrier pattern from
`kernel/futex/waitwake.c` lines 63-108 to prevent lost wakeups:

```
Waiter (CPU 0)              Waker (CPU 1)
--------------              --------------
waiter_count++              *futex = new_value
smp_mb()                    smp_mb()
lock(bucket)                if (waiter_count > 0)
val = *futex                  lock(bucket)
if val == expected            find & wake waiters
  enqueue                     unlock(bucket)
unlock(bucket)
sleep
```

The `fence(Ordering::SeqCst)` calls ensure that either:
- Waiter sees new futex value → doesn't sleep
- Waker sees waiter_count > 0 → wakes waiter

Neither thread can miss the other's update.

#### Lock Ordering

```
FutexHashBucket.waiters (spin Mutex): leaf (two in address order for a
requeue). Wakers dequeue FutexQ entries under it into a WakeQ (a
reference to each task, Linux wake_q_add), drop it, then wake them
(`task::wake_q::WakeQ::wake` -> try_to_wake_up; no TASKLIST).
```

Keys (`make_key`, Linux get_futex_key) are made before any bucket
lock: a private futex is (mm, address), with no lock; a shared one
takes the mmap_lock for reading to find its VMA (and, under it, the
file's dentry `d_lock` for its inode) and drops it before locking a
bucket: mmap_lock and bucket locks are never nested. A shared key in a
shared mapping is the backing inode (shared anonymous memory and SysV
shm included: tmpfs files), named by its `KeySeq`
(Linux i_sequence: unique for the boot, assigned on first use from a
global atomic counter, no lock), and its byte offset; in private
memory it is (mm, address), apart from the private key. The exit path
(robust list, CLEARTID) wakes with shared keys, before `exit_mm`.

A `FutexQ` (Linux futex_q) is pinned on the waiter's stack and linked
into its bucket. Its `lock_ptr` names the bucket it is on: set under
that bucket's lock, moved by a requeue under both buckets' locks,
cleared by the waker that dequeues it as its last touch of the entry
(Release). The waiter sleeps (Sleep / Wakeup Protocol, 3.1) until it
sees `lock_ptr` clear (Acquire), a signal or its deadline; then
`unqueue` (Linux futex_unqueue) locks the bucket `lock_ptr` names,
re-checks it under that lock (a requeue may have moved the entry:
retry) and unlinks the entry; finding it clear means a waker dequeued
it (the wait succeeded). The entry's drop unqueues it too. So a
requeued waiter keeps sleeping on the new futex, and no bucket ever
holds an entry whose waiter returned.

For `futex_requeue()` with two different buckets:
- Lock buckets in address order (lower pointer address first)
- This prevents deadlock when two threads requeue in opposite directions

#### Robust Futex Cleanup

Robust futexes are cleaned up during task exit via `exit_robust_list()`:
1. Called from task exit path in `task/exit.rs`
2. Walks the userspace robust list with a 2048 entry limit
3. For each entry the task owns, sets `FUTEX_OWNER_DIED` by a user
   cmpxchg against the value read (`uaccess::cmpxchg_user_u32`, Linux
   futex_atomic_cmpxchg_inatomic), retried when the word changed, so a
   waiter's `FUTEX_WAITERS` is never lost; then wakes one waiter. No
   lock is held: faults are resolved in place.
4. Uses shared bucket lock only briefly per entry

#### Key Rules

1. **Bucket lock is a plain spin lock** - thread context only (a leaf)
2. **Memory barriers before userspace access** - Prevents lost wakeups
3. **Bucket lock is a leaf** - wakeups are issued after dropping it
4. **Multi-bucket operations use address ordering** - Prevents deadlock
5. **Robust cleanup has entry limit** - Prevents infinite loop from corrupted list
6. **No sleeping user access under a bucket lock** - the futex word is
   faulted in first (`get_user`, may sleep), then read under the bucket
   lock with page faults disabled (`uaccess::pagefault_disable`, Linux
   futex_get_value_locked): a page that went away meanwhile fails at
   once and the call returns EAGAIN (userspace re-checks, as after a
   value change) where Linux retries internally. Nothing else reads user
   memory under a futex or TASKLIST lock (`get_robust_list` copies
   out after unlocking).

### 3.9 TTY and Console Subsystem

**Location:** `tty/`, `hw/gfx/console.rs`, `console.rs`, `printk.rs`

The TTY and console subsystem handles terminal I/O and kernel message output.
Console framework locks are IRQ-safe (IrqSpinlock) to support printk from interrupt
context. Per-TTY locks use Mutex and are accessed from process context only.

#### Console Framework Locks

| Variable | Location | Type | Purpose |
|----------|----------|------|---------|
| `OUTPUT_LOCK` | `printk.rs` | `IrqSpinlock<()>` | Serializes all console writes across CPUs |
| `PRINTK` | `printk.rs` | `IrqSpinlock<PrintkState>` | Protects ring buffer state |
| `CONSOLE_REGISTRY` | `console.rs` | `IrqSpinlock<ConsoleRegistry>` | Protects console driver list |
| `UartPort.cfg` (8250 `SerialTty`, PL011) | `tty/serial_core.rs` | spin `Mutex<UartCfg>`, thread context | What TIOCSSERIAL changes of a port (Linux uart_port's irq, flags, uartclk, custom_divisor, fifosize under port->mutex): taken under the tty's `port` mutex by TIOC[GS]SERIAL, alone by probe (the interrupt number). A leaf |
| `UartPort.xmit` (8250 `SerialTty`, PL011) | `tty/serial_core.rs` | `IrqSpinlock<Xmit>` | A UART's port lock (Linux uart_port.lock) and its transmit buffer (4 KiB, Linux xmit_fifo). A tty write (under the tty's `write_lock`, or N_TTY echo from the flip thread) copies into it and starts the transmitter under it (Linux uart_write); the TX interrupt (8250 THRE, PL011 TXIS) or, for a port without one, its HARD poll timer refills the transmitter under it (Linux serial8250_tx_chars, pl011_tx_chars, serial8250_timeout); the driver's interrupt-enable shadow (8250 IER, PL011 IMSC), the stopped flag (Linux tty->flow.stopped as uart_tx_stopped reads it; uart_stop, uart_start) and the pending flow control character (Linux x_char, uart_send_xchar) change under it. A console write holds it for the whole message (under `OUTPUT_LOCK`, any context; only tried during an oops, as Linux), so console output never interleaves with a tty write's bytes. Order: -> the timer wheel lock (arming the poll timer); nothing else. Writers are woken (`Tty.write_wait`) after it is released: a wakeup takes run-queue locks, and printk, so the console write, may run under one; the interrupt handler reads input (the flip buffer) before taking it |

All three use `IrqSpinlock` for IRQ safety - see Section 3.6 for details.

#### Per-TTY Locks

Each `Tty` struct contains:

| Lock | Type | Purpose |
|------|------|---------|
| `termios` | `Mutex<KTermios>` | Terminal I/O settings with the speeds (Linux `tty->termios`, a ktermios, under `termios_rwsem`): TCSETS*, TCSETS*2 and TCSETA* read it, build the new settings unlocked, then store them under `ldata` → `termios` (Linux set_termios: tty_set_termios) |
| `ldata` | `sync::Mutex<NTtyData>` (sleeping) | N_TTY read ring, edited line and echo ring (Linux `n_tty_data` under `termios_rwsem`): input processing, reads' copies out, flushes and termios changes; held across the echo's driver writes and ISIG signals |
| `avail` | atomics (`n_tty::Avail`) | `ldata`'s commit, line and read heads and ICANON, stored (Release) under `ldata` as each holder releases it, loaded (Acquire) with no lock by poll and a reader's wait condition (Linux `input_available_p` on `commit_head`/`canon_head`/`read_tail`): a poll may run under a spin lock (an epoll's), a wait condition with the task state set. A hint only: the input itself is copied under `ldata` |
| `ctrl` | `Mutex<TtyCtrl>` | Session, foreground group, window size (Linux `ctrl.lock` + `winsize_mutex`) |
| `flip` | `IrqSpinlock<Flip>` | Bytes from the UART interrupt handler (Linux `tty_bufhead`) |
| `buf_lock` | `sync::Mutex<()>` (sleeping) | Feeding `flip` to N_TTY vs input flushes (Linux `tty_bufhead.lock`); outside `ldata` |
| `read_lock` | `sync::Mutex<()>` (sleeping) | One N_TTY reader at a time, held across the whole read and its sleeps (Linux `atomic_read_lock`): a canonical line copied out in pieces goes to one reader; outermost tty lock, taken before `ldata` |
| `write_lock` | `sync::Mutex<()>` (sleeping) | One writer at a time, held across the whole write(2) (Linux `atomic_write_lock`, tty_write_lock): another writer's bytes never land inside it; outermost on the write side, taken before the TOSTOP check (`termios`, TASKLIST → `ctrl`, SIGTTOU) and the driver writes; O_NONBLOCK try-locks (EAGAIN), else interruptible. Thread context only: printk's console write and N_TTY echo do not take it (as Linux). Not nested with `read_lock` or `buf_lock` |
| `port` | `sync::Mutex<TtyPort>` (sleeping) | The port's close_delay, closing_wait and initialized flag (Linux `tty_port` under `port->mutex`). TIOCSSERIAL sets them under `files` → `ldata` → `port` → `UartPort.cfg`, and moves the port under it (shutdown, `IOPORT`, startup); an open brings a port that is down up under `files` → `port`, a hangup or the last close takes it down there; TIOCGSERIAL reads it |
| `UartPort.detached` | `AtomicBool` | The port's device is gone (Linux `state->uart_port` NULL): set by the removal, cleared by the probe, under `port`; read by an open's activation and TIOC[GS]SERIAL under `port` |
| `io_error` | `AtomicBool` | TTY_IO_ERROR: set and cleared under `port` (an open, a shutdown, TIOCSSERIAL) and, cleared, by the tty's last release under `files`; read with no lock by read, write and ioctl |
| `exclusive` | `AtomicBool` | TTY_EXCLUSIVE: set and cleared by TIOCEXCL and TIOCNXCL with no lock (Linux set_bit and clear_bit, no tty_lock), read by TIOCGEXCL; an open tests it under `files` (Linux tty_reopen under tty_lock: EBUSY without CAP_SYS_ADMIN); the tty's last release clears it under `files` (Linux frees the tty_struct). A flag, not state another field depends on: an ioctl racing an open may land on either side of it, as in Linux |
| `output_lock` | `sync::Mutex<()>` (sleeping) | N_TTY output against its echo (Linux `n_tty_data.output_lock`): a write checks the driver's room and writes a block, or a CR NL pair (ONLCR) whole, under it (Linux process_output_block, process_output -> do_output_char), and writes non-OPOST output under it; echo is written to the driver under it (`ldata` → `output_lock`, Linux process_echoes), so no echo lands between a room check and its write. Order: `write_lock` → `ldata` → `output_lock` → `UartPort.xmit`; never held across a sleep for room |
| `files` | `sync::Mutex<TtyFiles>` (sleeping) | Open files (Linux `tty->count` and `tty_files` under `tty_lock`: every open of the tty, /dev/tty and /dev/console included, each its `Redirect`), the port's opens (Linux `port->count`: a hangup takes the hung files' away) and TTY_HUPPED. Held across an open's listing and controlling-tty setup (→ CTTY_LOCK, Linux tty_open under tty_lock), across a release and across a hangup. The port's last open's release, under it, drops TCOOFF-stopped output (`flow`, the port lock), waits on `write_wait` for output to drain (up to closing_wait, interruptible; Linux tty_port_close_start under tty_lock), flushes input (`buf_lock` → `ldata`) and shuts the port down (the port lock); the tty's last file's clears the session (CTTY_LOCK → `ctrl`) and resets `flow`. A hangup (Linux __tty_hangup under tty_lock) marks the files hung (each `Redirect.hung`, atomic, read lock-free by the file's operations and by readers' and writers' wait conditions; `Tty.hupping` likewise), takes them off `fasync` (`fasync_helper`: File.f_lock → FASYNC_LOCK; the file's address, recorded by its fasync call, is valid while its `Redirect` is listed, since its release unlists it under `files`), takes the session (CTTY_LOCK → `ctrl`), signals the session leader and foreground group (TASKLIST, signal locks), flushes input and output and resets `ldata` and `throttle`. Outermost tty lock: taken with no tty lock held, never under `read_lock` or `write_lock` |
| `read_wait` | `WaitQueue` | Readers and pollers waiting for input |
| `write_wait` | `WaitQueue` | Writers (under `write_lock`), pollers and tcdrain waiting for the driver's room or an empty queue (Linux write_wait); the driver wakes it with no lock held (`Tty::write_wakeup`) |
| `flow` | `Mutex<Flow>` (spin, thread context) | Output flow control (Linux `tty->flow` under `flow.lock`): stopped, and stopped by TCOOFF. TCXONC stops and restarts output under it, calling the driver's stop/start (→ `UartPort.xmit`); writers are woken after it is released (Linux `__start_tty`'s tty_wakeup runs under flow.lock) |
| `throttle` | `sync::Mutex<bool>` (sleeping) | The driver is throttled (Linux `TTY_THROTTLED` under `throttle_mutex`): N_TTY throttles it under `ldata` when the read ring nearly fills and unthrottles it under `ldata` when a read has emptied it (Linux n_tty_check_throttle, n_tty_check_unthrottle; both run under `ldata`, so Linux's flow_change protocol for concurrent producer and reader is not needed); the driver's throttle (a UART: STOP under IXOFF) runs under it → `termios`, the port lock |
| `closing` | `AtomicBool` | A last close is draining output (Linux `tty->closing`): input does only flow control meanwhile |
| `fasync` | `FasyncList` (RCU, 3.11) | O_ASYNC files (Linux `tty->fasync`): N_TTY input sends their SIGIO under `ldata` (Linux: under termios_rwsem), at each canonical line end, or after non-canonical input, then wakes `read_wait`. A write stopped short with files listening sets `do_write_wakeup` (atomic, Linux TTY_DO_WRITE_WAKEUP); the next `write_wakeup` clears it and sends SIGIO POLL_OUT (Linux n_tty_write_wakeup) with no lock held, or under `ldata` from the echo's driver write. Deviation: Linux sends it from the TX interrupt (uart_write_wakeup -> tty_wakeup); hk's signal locks are thread context only (3.7), so a wakeup in an interrupt handler sets `wakeup_due` and the flip thread sends it |

`termios` and `ctrl` are spin locks taken in thread context only,
briefly, never across a signal, a sleep or a driver write: the SIGWINCH
of TIOCSWINSZ and the SIGHUP/SIGCONT of giving up a controlling tty are
sent after `ctrl` is dropped. `ldata` (sleeping, thread context: the
flip thread, readers, TIOCINQ, input flushes and termios changes from
ioctl) is taken with no spin lock held and orders above `termios`
(input processing reads termios and set_termios swaps it under `ldata`,
so an ICANON change is applied atomically, as Linux's `termios_rwsem`).
Under `ldata` N_TTY queues echo in its ring and writes it to the driver
(`driver_write`: the UART's polled MMIO/port writes, no lock) once
`ECHO_COMMIT_WATERMARK` bytes are pending and at the end of the input
(Linux commit_echoes, flush_echoes), and sends an ISIG signal to the
foreground group (Linux __isig: `ctrl` for the group, then TASKLIST and
the signal locks). No driver write and no signal path takes `ldata`.
Order: `read_lock` → `ldata`; `buf_lock` → `ldata` → `termios`, `ctrl`,
TASKLIST and the signal locks.

Input (`tty/flip.rs`, Linux tty_buffer.c): the UART handler (IRQ
context, under its line's `IrqDesc.lock`) drains its FIFO into `Tty.flip` (leaf), sets
`flip::PENDING` and wakes `flip::FLIP_WAIT`; the `ttyflip` kernel thread
takes the bytes out (`flip`, released before the line discipline runs)
and feeds them to N_TTY, which wakes `read_wait` under `ldata`. It is the only
consumer, so input stays in order. Order: `IrqDesc.lock` → `Tty.flip`;
`IrqDesc.lock` → wait queue head (the wakeup).

A process's controlling tty and old foreground group
(`SignalStruct.ctty`, spin leaf, thread context; Linux signal->tty and
signal->tty_old_pgrp under siglock) are set and cleared under it alone,
under TASKLIST (read) when sessions are walked (session_clear_tty, a
hangup's tty_signal_session_leader), never nested with `Tty.ctrl`; pid
references taken out of it are dropped after the locks.

`tty::jobctrl::CTTY_LOCK` (spin `Mutex`, thread context; Linux tty_lock
+ siglock in `__proc_set_tty`/`session_clear_tty`) serializes giving and
taking controlling ttys (open without O_NOCTTY, TIOCSCTTY, TIOCNOTTY, a
session leader's exit), so a session never gets two. `Tty.ctrl` holds
the session and foreground group as `Arc<pid::Pid>` references (Linux
get_pid), read from the caller's task under TASKLIST. Order (Linux
tty_lock → tasklist_lock → ctrl.lock): `CTTY_LOCK` → TASKLIST (read) →
`Tty.ctrl`. TIOCSPGRP checks that the group is in the caller's session
and stores it with TASKLIST read-held across both, so the group cannot
change in between; the pid lookup (under RCU) comes before TASKLIST.

#### Graphics Console Lock

| Lock | Type | Purpose |
|------|------|---------|
| `GfxConsole.state` | `IrqSpinlock<GfxConsoleState>` | Framebuffer surface + cursor position |

The graphics console uses a **single lock** protecting both cursor position and
framebuffer surface, held across a whole console write (any context,
under `OUTPUT_LOCK`). The write only tries it: held (a printk nested in
the write, a concurrent oops), the output is dropped (Linux
vt_console_print's printing_lock trylock under console_lock). A leaf.

#### Lock Ordering

```
OUTPUT_LOCK (IrqSpinlock, held for entire formatted message)
    ↓
PRINTK (IrqSpinlock, ring buffer, brief hold during write)
    ↓
CONSOLE_REGISTRY (IrqSpinlock, console dispatch to drivers)
    ↓
Per-TTY spin locks (termios, ctrl) - independent between TTYs
    ↓
GfxConsole.state (IrqSpinlock, try_lock; if graphics console receives output)
```

The console writes run after `CONSOLE_REGISTRY` is released, under
`OUTPUT_LOCK` alone: the USB serial console's `PORT` (IrqSpinlock,
3.10) is a leaf there.

#### Panic-Safe Console Output

During panic, the normal locking path can deadlock if the panicking CPU already
holds `OUTPUT_LOCK`. The printk subsystem handles this with:

1. **`OOPS_IN_PROGRESS` flag** - Atomic bool set at panic entry via `set_oops_in_progress()`
2. **`try_lock()` fallback** - Non-blocking lock attempt in panic mode
3. **Direct serial output** - If lock unavailable, bypass console subsystem

```rust
// In PrintkWriter::write_str() during panic:
if self._guard.is_some() {
    printk_write_locked(s.as_bytes());  // Normal path with lock
} else {
    direct_serial_write(s.as_bytes());  // Panic fallback, no lock
}
```

#### Key Rules

1. **All console framework locks are IRQ-safe** - printk works from interrupt context
2. **OUTPUT_LOCK ensures atomic messages** - Multi-CPU printk won't interleave
3. **Per-TTY locks are independent** - No ordering constraints between TTYs
4. **GfxConsole uses single lock** - Cursor and surface always atomic
5. **Panic bypasses locks** - Direct serial for guaranteed panic output
6. **ConsoleFlags control console behavior** - ENABLED, BOOT, CONSDEV flags

### 3.10 Device Drivers

Device drivers use thread-context locks (Mutex, RwLock) for their state.
ISRs only ack the device, set atomics and use IRQ-safe deferral
(`napi_schedule`, `WaitQueue::wake_*`), deferring work to thread context.

#### Device IRQ Registration (irq.rs)

| Lock | Type | IRQ class | Order |
|------|------|-----------|-------|
| `IrqDesc.lock` (`irq.rs`; one per line of the static `IRQ_TABLE`, Linux desc->lock) | `IrqSpinlock` | taken in IRQ (`handle_irq`) and process context (`request_irq`, a registration's drop) | leaf, except that the interrupt controller's line mask/unmask (`arch::IrqChipOps`) and the line's handlers run under it. Lines never nest: no code holds two descriptors' locks |
| `MATRIX` (`arch/x86_64/irq.rs`, Linux vector_lock over the irq_matrix) | spin `Mutex` | thread only (`msi_alloc`, `msi_free`: a driver's probe and remove) | leaf: hands out MSI lines and per-CPU device vectors and writes each CPU's `VECTOR_IRQ` table (atomics, read lock-free with acquire by the interrupt entry on that CPU, Linux per-CPU vector_irq) |
| `I8259A_LOCK` (`arch/x86_64/pic.rs`), `IRQ_CONTROLLER_LOCK` (`arch/aarch64/gic.rs`) | `IrqSpinlock<()>` | any context | leaf, under `IrqDesc.lock`: the chip state lines share (the PIC mask registers; GICD_ICFGR, 16 SPIs per register) changes under it (Linux i8259A_lock, irq-gic-common.c irq_controller_lock) |

Generic interface (`crate::irq`): `request_irq(irq, Arc<T: IrqHandler>)
-> IrqRegistration<T>` (shareable; the handler's address is its Linux
dev_id, the same handler twice on a line is EBUSY; `IrqFn` wraps a
stateless fn). The registration points at its line's descriptor; dropping
it removes the handler. Nothing allocates or frees under `IrqDesc.lock`:
the handler's list node (Linux irqaction, in an intrusive `BoxList`) is
allocated before the lock, and a removed or refused one is freed after
it. Drivers stop their device interrupting before dropping it (INTx
stays enabled at the device, as Linux free_irq leaves it). Lockdep does
not track `IrqSpinlock` classes, so the per-line locks are covered by the
rule that no code nests two of them. `pci_intx_irq(bus, dev, fn, pin,
line)` routes PCI INTx; `PciDevice::request_irq` uses both. The first
handler of a line unmasks it, the last one's removal masks it, both under
the line's `IrqDesc.lock` (Linux irq_startup/irq_shutdown under desc->lock). Every
handler of a shared line is called; an interrupt on a line without
handlers masks it, and a line nobody claims more than 99,900 times in a
100,000-interrupt window is masked (stuck level INTx), reported after the
lock is dropped; a handler added to such a line unmasks it again (Linux
__setup_irq clearing IRQS_SPURIOUS_DISABLED).

- aarch64: SPIs are configured on unmask by `gic::enable_spi` (level/edge
  in ICFGR, priority 0x80, Group 1, IROUTER -> CPU 0, ISENABLER); PCI INTx
  comes from the host bridge DT `interrupt-map`/`interrupt-map-mask` parsed
  at boot (`arch/aarch64/pci_irq.rs`, matching in `hw/pci/intx.rs`), else
  the QEMU virt swizzle INTID 35 + (slot + pin - 1) % 4.
- x86-64: legacy 8259 PIC with the firmware-assigned config-space Interrupt
  Line (QEMU `pc`). Real hardware in APIC mode (Dell OptiPlex 3020 target)
  needs IOAPIC + ACPI `_PRT` routing (not implemented). MSI lines (16 and
  up) are one LAPIC vector of one CPU each (`msi_alloc`, an `MsiIrq` freed
  on drop); the chip's mask/unmask leave them alone, the device's MSI-X
  entry is their mask (`hw/pci/msix.rs`: unmasked after `request`,
  masked before the handler is dropped, under no lock). The entry acks
  the LAPIC, then runs `handle_irq` (edge).
- aarch64 has no MSI (no GICv3 ITS driver): `msi_alloc` is None.
- Handlers run in IRQ context with their line's lock held: they must only ack
  the device, touch atomics/IrqSpinlocks and wake threads; they must not
  request or free IRQs. Once a registration's drop returns its handler is
  not running (Linux free_irq's synchronize_irq).

#### DMA API (hw/dma.rs)

The backend (`DMA_OPS`) is set once at boot (`spin::Once`) and read
without a lock, so the streaming calls (`dma_map_single`/`unmap`, sync)
are IRQ-safe: blk-mq dispatch and completion run them in hardirq
context. `dma_alloc_coherent` allocates frames (thread context only).

#### USB Subsystem

**Location:** `hw/usb/` (`urb.rs`, `hcd.rs`, `message.rs`: Linux
drivers/usb/core urb.c, hcd.c, message.c; `xhci.rs`, `xhci_ring.rs`:
Linux drivers/usb/host/xhci.c, xhci-ring.c)

Linux model: a driver submits an URB (`usb_submit_urb`), the host
controller queues its TD on the endpoint ring under its IRQ-safe lock,
its interrupt handler consumes the event ring and gives finished URBs
back (`usb_hcd_giveback_urb`), and their completion handlers run from
the giveback bottom half (Linux HCD_BH on system_bh_wq; here the
`usb_bh` workqueue's thread, `USB_BH_WQ`, as hk has no softirqs; the
handlers keep the bottom-half rule and never sleep, so one worker
serves every controller). Synchronous requests (`usb_control_msg`,
`usb_bulk_msg`: Linux usb_start_wait_urb) sleep on a `Completion` the
handler completes. Commands (Enable Slot, Address Device, Configure
Endpoint, Reset Endpoint, Set TR Dequeue Pointer, ...) are queued on
the command ring the same way; their completion events are matched to
the oldest outstanding command by TRB address, and a waiter sleeps on
its command's `Completion`. The command timer (`Xhci.cmd_timer`, a
`DelayedWork` on `SYSTEM_WQ`, Linux xhci->cmd_timer) aborts the
command ring when the controller sits on a command for 5 s, so no
waiter sleeps forever. There is one `Arc<Xhci>` per bound controller;
the USB devices below it reach it as their `Hcd` (`UsbDevice.bus`).

Cancellation (Linux usb_unlink_urb, usb_kill_urb, xhci_urb_dequeue):
`usb_unlink_urb` (any context) marks the URB unlinked under `Urb.st`
and its TD cancelled under `Xhci.lock`, and queues a Stop Endpoint
nobody waits for (allocated GFP_ATOMIC, as Linux); its completion, in
the interrupt handler, turns the cancelled TDs into No-ops, queues a
Set TR Dequeue Pointer past one the endpoint sat on and gives back
the others; that command's completion gives back the rest and
restarts the endpoint. `usb_kill_urb` (thread, may sleep) also raises
the URB's `reject` and sleeps on `USB_KILL_URB_QUEUE` until its
`use_count` drops, which the giveback does after the completion
handler; the atomics' fences pair as Linux's (`reject` before
`use_count` in the kill, the reverse in submit and giveback). A
synchronous request that times out kills its URB before returning, so
the caller's buffer and the URB's are never the device's after it.

| Lock | Type | IRQ class | Order |
|------|------|-----------|-------|
| `Xhci.lock` (`xhci.rs`; Linux xhci->lock) | `IrqSpinlock<XhciState>` | any context: the interrupt handler (under its line's `IrqDesc.lock`), URB submission, command queueing and the command timeout work (thread) | `IrqDesc.lock` -> `Xhci.lock` -> {`Urb.st`, `GivebackBh.list`, the `usb_bh` and system workqueues' locks (`queue_work`, `mod_delayed_work`, `cancel_delayed_work`), a command's `Completion` (`done` -> wait queue -> run queue), the slab (the commands the interrupt handler queues for a halted endpoint are allocated GFP_ATOMIC, as Linux), the trace ring, printk on error paths}. Holds the command and event rings, the command list, each device's contexts, endpoint rings, TD lists and endpoint state. Never sleeps or waits: the command abort releases it for its handshake (Linux xhci_abort_cmd_ring); halt and reset poll the controller under it, as Linux xhci_stop. Queueing never allocates: TD and command lists have their room reserved with the ring. No URB is freed under it (a finished TD's URB reference moves to the bottom half's list) |
| `Xhci.mutex` (`xhci.rs`; Linux xhci->mutex) | sleeping `sync::Mutex<()>` | thread only | serializes slot and context commands, held across their waits: Enable Slot with Address Device, Evaluate Context, Configure Endpoint, Disable Slot; -> `Xhci.lock` |
| `Urb.st` (`urb.rs`; Linux urb->status, actual_length, unlinked, hcpriv) | `IrqSpinlock` | any context | leaf: under `Xhci.lock` (the length measured from an event) or alone (submit, giveback, the buffer copies, which only happen while the URB is not queued) |
| `GivebackBh.list` (`hcd.rs`; Linux giveback_urb_bh.lock) | `IrqSpinlock<ArcList<Urb>>` | any context | leaf, under `Xhci.lock`: given-back URBs; the `usb_bh` work takes the whole list out under it and runs the completion handlers with nothing held. A work queued while running runs again (WORK_RERUN), as Linux's re-queues itself |
| `PORT` (hw/usb/serial.rs; Linux usb_serial_port.lock) | `IrqSpinlock<Port>` | any context | The USB serial console's device (slot, bulk OUT endpoint; none while no FTDI port is the console), its write FIFO (4 KiB, Linux write_fifo), its write URB and busy flag (Linux write_urbs[0], USB_SERIAL_WRITE_BUSY). Leaf: the console write (under `OUTPUT_LOCK`, interrupt handlers included) queues into the FIFO under it, dropping what does not fit (Linux kfifo_in_locked), and asks the tick to kick the console (`console_defer_kick`, 3.6); the tick's kick checks it and queues the write work after releasing it; the write start (the write work on `SYSTEM_WQ`, or the URB's completion handler in the giveback bottom half) takes a chunk out and marks the URB busy under it (Linux kfifo_out_locked), then fills and submits the URB with it released (`Urb.st`, `Xhci.lock`); the completion handler clears busy under it. Probe and remove take it alone (remove after `unregister_console` released `CONSOLE_REGISTRY`), remove taking the URB out and poisoning it (`usb_poison_urb`, Linux usb_serial_port_poison_urbs: waits for its giveback, refuses resubmission) with it released. Nothing on the transfer path prints: xHCI tracing goes to the trace ring (`trace.rs`), and a failed transfer is reported once (`ERR_ONCE`, Linux dev_err_console), so the console never queues its own transfers' messages forever |
| `PORT_DEV` (hw/usb/serial.rs; Linux port->serial->dev) | sleeping `sync::Mutex`, thread only | leaf: the console port's device and bulk IN endpoint, set by probe and cleared by remove, cloned out for the boot self-test |

Transfer buffers are coherent DMA memory allocated with each URB
(Linux usb_alloc_coherent with URB_NO_TRANSFER_DMA_MAP), aligned so
no TRB buffer crosses a 64 KiB boundary unsplit; the synchronous
requests copy the caller's data in and out, so callers may pass any
buffer, the stack included.

Enumeration (descriptor reads, Evaluate Context, Configure Endpoint,
SET_CONFIGURATION) runs in the xHCI probe, after its interrupt handler
is registered and the controller started, with `Xhci.mutex` around the
slot and context commands. The devices are then registered under the
PCI device's lock: the root hub `usb1`, its generic driver's probe
adding the interfaces under `usb1`'s device lock, then each port's
device the same way, so device locks nest PCI function -> usb_device ->
interface (parent before child, as Linux); interface drivers' probes
(usb-storage's SCSI scan) submit URBs under them.

Unbinding the xHCI runs the same nesting top-down (Linux
usb_remove_hcd): under the PCI device's lock each USB device is
deleted, the root hub last; its generic driver's release, under its
lock, deletes the interfaces, whose drivers' removes run under the
interface's lock (usb-storage: the disk's `open_mutex` for
del_gendisk, then `UsbMscDevice.state`; ftdi_sio: `CONSOLE_REGISTRY`,
then `PORT`, then the write URB's poisoning, then `PORT_DEV`). The controller is then stopped: each
slot disabled (`Xhci.mutex`, a Disable Slot command, its TDs given
back with Shutdown), then halted and reset under `Xhci.lock`, which
marks it dying (later submissions fail with Shutdown) and gives back
what is still queued, the command timer cancelled, the IRQ handler
unregistered (`IrqDesc.lock`, which waits out a running handler), bus
mastering turned off. The register mapping and the controller's
memory go with the last `Arc<Xhci>`, which URBs a driver still holds
keep: no access ever reaches an unmapped register.

#### Block Device Subsystem

**Location:** `block/` (`blkdev.rs`, `blk_mq.rs`, `dio.rs`, `genhd.rs`,
`part/`), `hw/virtio/blk.rs`, `fs/pageio/blkdev_ops.rs`, `fs/ramfs/devtmpfs.rs`,
`sync/completion.rs`

Linux model (block/bio.c, blk-mq.c, genhd.c): a bio is submitted from
thread context, the driver completes it from its interrupt handler and
`bio_endio` runs `end_io` there (hardirq). `submit_bio_wait` sleeps on a
`Completion` that `end_io` completes.

| Lock | Type | IRQ class | Order |
|------|------|-----------|-------|
| `Disk.open_mutex` | `sync::Mutex<OpenState>` (sleeping; Linux disk->open_mutex) | thread only | outermost block lock; holds the count of open partitions (Linux open_partitions, plain) and the disk's `part_tbl` (its block devices by partition number, one slot per minor, each a reference; Linux disk->part_tbl), and each `BlockDevice.openers` (an atomic on the device, as Linux bd_openers) changes only under it, as does the soft block size's initial value at the first open (Linux set_init_blocksize; BLKBSZSET changes it under the bdev inode's `i_rwsem`, Rules): block device open/release (files, and the kernel opens of a mount (`SuperBlock.s_bdev_file`) and of active swap: `BdevHandle`), partition scans (and rescans, BLKRRPART), disk removal (`del_gendisk` drops its devices under it); I/O, `INODE_HASH_LOCK` (`bdev_add` hashes a device's inode, `bdev_del` unhashes it), `MAJORS` and the devtmpfs root's `i_rwsem` are taken under it |
| `MAJORS` | sleeping `sync::Mutex` (block majors, register_blkdev; Linux major_names_lock) | thread only | leaf |
| `BDEV_LOCK` (`block/claim.rs`; Linux bdev_lock) | sleeping `sync::Mutex<BdevLock>` | thread only | leaf: every disk's exclusive claims (`Disk.claims`: each device's holder and count, Linux bd_holder, bd_holders; the claim in progress, Linux whole->bd_claiming). A claim is prepared under it alone, before `open_mutex` (`claim::prepare`: EBUSY if another holder has the device; a claim in progress on the disk is waited for on its `var_waitqueue`, queued under it, slept with it dropped), then finished or ended under `open_mutex` (`claim::finish` at open, `claim::end` at release: open_mutex -> it) or abandoned alone (`claim::abort`). Holders: a mounted superblock (`get_tree_bdev`), a file opened O_EXCL, active swap, BLKBSZSET's and BLKRRPART's claims for the call |
| blk-mq software queue (`BlkMq.ctxs[cpu]`) | `IrqSpinlock<BioList>`, one per CPU | thread (submit) and hardirq (a FUA write's post-flush, sent from the write's completion after the hardware queue lock is dropped) | leaf: never taken with the hardware queue lock held; in the ISR it nests under the line's `IrqDesc.lock` (IrqDesc.lock -> ctx lock; nothing allocates under it: the flush is preallocated with its post-flush queue, and the completions free bios and the `FlushSeq` to the heap under `IrqDesc.lock` only, outside every queue lock); its pending bit in the hardware queue's `ctx_map` (Linux) is set and cleared under it, and a run visits only set bits (one that misses a bit being set is followed by the submitter's own run) |
| Post-flush queue (`RequestQueue.fqs[h]`, `block/blkdev.rs`, one per hardware queue; Linux blk_flush_queue->mq_flush_lock) | `IrqSpinlock` | thread (a FUA write's submission) and hardirq (its data's and the shared flush's completions) | leaf: writes waiting for a flush, the writes the flush in flight serves, the FUA data in flight and the preallocated flush; the flush is sent and the writes are ended after it is dropped |
| blk-mq requests taken (`BlkMq.rqs[h]`, Linux tags in use) | `AtomicUsize` per hardware queue, lock-free (as Linux's sbitmap) | thread (`get_rq` at submission or plug time) and hardirq (completion, failed dispatch) | counts requests from `get_rq` to their end, wherever they are (software queue, parked for kblockd, dispatch list, driver); a NOWAIT bio takes one only below the driver's depth (compare-and-swap), else ends with EAGAIN; the dispatch itself stays under the hardware queue lock. With `BlkMq.dying` (set once by `start_drain`) the end that brings a count to 0 wakes `drained` (Linux q_usage_counter) |
| Block plug (`Task.plug` -> a `BlkPlug` in a `blk_plug` frame, `block/plug.rs`; Linux current->plug) | none: task-private | thread, the owning task only (submission, and `schedule()` on the way to sleep: Linux sched_submit_work) | holds bios and merges into the last held request; going out takes the software then hardware queue locks as a submission does, never under a spin lock (`schedule` checks `might_sleep` first); from `schedule()` (the sleep state set) it takes only the software queue locks, then each reached hardware queue's `HctxRun.hold` and a kblockd queue (intrusive: no allocation), waking that kblockd: nothing is dispatched or ended there; flushes and FUA writes bypass it |
| `HctxRun.hold` (per hardware queue: a hold on its `BlkMq` while its kblockd run is queued; Linux hctx->run_work) | spin `Mutex` | thread only (`schedule()` on the way to sleep, the kblockd worker) | leaf: set and the run queued (after unlocking) on the kblockd of the hardware queue's first CPU, always the same, by `run_async`; the work takes the hold, runs the queue and drops the hold unlocked, so the `BlkMq` outlives every queued run. `KBLOCKD` is per CPU (Linux kblockd: per-CPU, highpri pool), one worker each at nice -20; the only global is the static array of those per-CPU workqueues |
| blk-mq hardware queue (`BlkMq.hctxs[i]`) | `IrqSpinlock` over the dispatch list, the driver queue (virtio-blk: one virtqueue and its tags; Linux virtio_blk_vq.lock), the in-flight count and the dying flag | thread (dispatch, drain, release) and hardirq (completion, restart) | leaf: `queue_rq`/`complete` only touch the ring, MMIO and the lock-free DMA API (`DMA_OPS` is a `Once`), never allocate or sleep (virtio-blk's descriptor tables are allocated with the queue: a small one per tag and a bounded set of full-size ones; a request that finds no full-size one free stays on the dispatch list until a completion puts one back); taken under its line's `IrqDesc.lock` in the ISR |
| `BlkMq.drained` | `WaitQueue` (Linux mq_freeze_wq) | woken from any context (the request end that empties a dying queue's count, after the queue locks are dropped); waited in thread context (`del_gendisk`, no lock held) | its head lock -> run-queue lock; the condition reads the counts only |
| `Completion.done` | `IrqSpinlock<u32>` | any context | -> its wait queue head -> run-queue lock (the wakeup is issued under it, Linux complete()) |
| `VdDisk.vdev` (`hw/virtio/blk.rs`) | sleeping `sync::Mutex<Option<Arc<VirtioDevice>>>` (Linux vblk->vdev_mutex) | thread only | HDIO_GETGEO (`getgeo`) reads the device config under it, lock-free (the config generation loop), nothing else taken; remove, after `del_gendisk`, clears it and resets the device, frees its IRQ and takes its queues and rings back under it, so no config read follows the reset |
| `BlockDevice.read_only`, `Disk.part0_ro`, `BlockDevice.ro_warned` | `AtomicBool`, lock-free (Linux BD_READ_ONLY, BD_RO_WARNED in the atomic bd_flags) | any (stored by BLKROSET, read by writes, writeback's bios and mmap) | lone flags: a write checks them as it starts, as Linux bdev_read_only; one in flight when BLKROSET lands completes, as in Linux |
| `RamDisk.pages` | spin `Mutex<XArray>` (Linux brd_pages xa_lock) | thread only (bio-based driver) | leaf; a page's frame is allocated before it, index nodes with it dropped (`xarray::store_nomem`), a frame that lost a race freed |

Rules:

- **Finding block devices (Linux block/bdev.c):** each block device's
  inode (`bd_inode`) lives on the bdev pseudo superblock
  (`fs::pseudo::BDEV`, Linux blockdev_superblock, made after the mount
  tree as Linux's bdev_cache_init), on its `s_inodes` from creation
  (`BlockDevice::new`, Linux bdev_alloc). `bdev_add` puts the device
  in its disk's `part_tbl` and hashes the inode by device number;
  `get_blkdev` (Linux blkdev_get_no_open) is an `ilookup5` of that
  number (`INODE_HASH_LOCK`, the inode's `rdev` compared under it), the
  device then reached from the inode's `BdevOwner`; `bdev_del` takes it
  out of `part_tbl` and the hash, so lookups miss a removed device that
  open files still hold. sync(2) (`sync_bdevs`), meminfo's Buffers
  (`nr_blockdev_pages`), reclaim and /proc/partitions walk the bdev
  superblock's `s_inodes` (`for_each_sb_inode`: one inode per
  hold of its lock, the work done with no lock);
  /proc/partitions gathers references that way and sorts and formats
  them with no lock held. No global map of devices.
- **Disk removal (`del_gendisk`, Linux):** under `open_mutex` every
  hardware queue is marked dying (nothing reaches `queue_rq` after,
  every request not yet started, on a software queue or the dispatch
  list, ends with EIO) and the block devices are dropped; then, with no
  lock held, it sleeps on `BlkMq.drained` until every request taken
  has ended. The driver's remove then frees the IRQ, takes its
  queues back (`BlkMq::release`) and resets the device before freeing
  the rings (`VirtioDevice::del_vqs`).
- **end_io runs in hardirq context** (virtio-blk) or in the submitter's
  thread (bio-based drivers: ramdisk, USB sd). It may only complete a
  `Completion`, touch atomics and wake; the bios are ended after the
  hardware queue lock is dropped, so `end_io` can resubmit.
  A FUA write on a queue with a volatile cache but no FUA (every
  queue now; Linux blk_insert_flush, REQ_FSEQ_POSTFLUSH) carries a
  `FlushSeq`, allocated at submission with its flush bio: the write's
  completion sends the flush from its own context (blk-mq: the
  software and hardware queue locks, IRQ-safe leaves, taken in
  hardirq), the flush's completion runs the owner's `end_io`. The
  sequence is owned by the one bio in flight at a time; no lock.
  `submit_bio_wait`'s `end_io` hands the bio back and completes last:
  once `Completion::wait` returns the waker no longer touches the
  waiter's stack.
- **Direct I/O (`block/dio.rs`, Linux __blkdev_direct_IO):** the bios
  of one I/O count down a `DioWait` on the submitter's stack: `left`
  (atomic, bios in flight plus one the submitter holds while it
  submits), `err` (atomic, the first error's errno, compare-exchange
  from 0) and a `Completion`. Each bio's `end_io` (hardirq) stores its
  error, frees the bio, then decrements `left` (AcqRel); the one that
  reaches 0 completes, last. The submitter drops its own count after
  the last submit and waits only if a bio is still out, so once it
  returns no `end_io` touches the frame (`Completion`'s rule). It then
  dirties a read's pages and unpins them in thread context (page
  lock; 3.2 Page pins). No lock is held across the I/O, and no
  i_rwsem: block devices are not regular files (Linux
  blkdev_read_iter/blkdev_write_iter take none for direct I/O). The
  cache over the range is written back first (page lock -> i_pages,
  the writeback's own order) and, for a write, dropped before and
  after (`filemap::invalidate_pages2`: page lock -> i_mmap read -> PTE
  lock to unmap, then i_pages; Linux invalidate_inode_pages2_range).
- **vfat direct I/O (`fs/vfat/direct.rs`, Linux fat_direct_IO over
  __blockdev_direct_IO with DIO_LOCKING):** the same bios and
  `DioWait` (`dio::direct_io_map`, through the disk extents
  fat_get_block maps, Linux get_more_blocks),
  under the file's `i_rwsem` held exclusive. A write runs under the
  one `File::write_iter` holds for the whole call (invalidation, bios,
  wait, size update, the buffered rest), as Linux
  generic_file_write_iter. A read takes it itself after writing the
  cache back unlocked (Linux kiocb_write_and_wait), and holds it over
  the end-of-file check, a second write-back, the mapping
  (fat_get_block: `VfatInode.cache`, FAT reads) and the pinning and
  submission of every bio
  (plugged), dropping it after the plug is flushed and before the
  wait (`direct_io_map`'s `unlock`); a buffered rest is read unlocked.
  Order: `i_rwsem` -> page lock -> i_pages (write-back,
  invalidation), `i_rwsem` -> mmap_lock (pinning faults the caller's
  pages in; the fault path takes no `i_rwsem`).
  An asynchronous write (AIO, io_uring) whose file has pages cached
  when its last bio ends hands itself and its result to a work item
  made at submission (`PostWrite.job`, an IrqSpinlock leaf, any
  context; the queueing on `SYSTEM_WQ` follows the unlock), which
  drops the written range from the cache in thread context (page lock
  -> i_pages, no `i_rwsem`) before the count is lowered and the result
  passed on (Linux dio_bio_end_aio -> dio_aio_complete_work).
- **Direct I/O in flight (`Inode.i_dio_count`, Linux i_dio_count):**
  an atomic counter, raised under `i_rwsem` before an I/O's first bio
  (`inode_dio_begin`, or `dio_guard`) and lowered once its last bio
  is done (`inode_dio_end`; any context, including a completion: the
  last one wakes the variable's queue in `VAR_WAIT_TABLE`
  (`sync/waitqueue.rs`, Linux bit_wait_table / wake_up_var), whose
  lock is an IrqSpinlock taking only run-queue locks). The decrement
  is AcqRel and the waiter re-checks the count (Acquire) after
  queueing (`wait_event`), so no wakeup is lost. `inode_dio_wait`
  sleeps until it is 0 with `i_rwsem` held exclusive, which keeps new
  direct I/O out: vfat truncate (Linux fat_setattr) and a failed
  write's trim wait before any cluster is freed, so a read that
  dropped `i_rwsem` before its wait never reads a cluster another file
  got. A shared queue may hold other variables' waiters; each
  re-checks its own condition.
- **Boot I/O sleeps:** the scheduler runs and interrupts are on before
  driver probe (main.rs: the boot context is pid 1 by then, Linux
  kernel_init), so the boot partition scan's `submit_bio_wait` sleeps on
  its completion like any other.
- **devtmpfs nodes under `open_mutex`:** Linux hands node updates to
  devtmpfsd; hk creates/removes them in the caller (probe, rescan), under
  the devtmpfs root's `i_rwsem`. No path holding a directory `i_rwsem`
  takes `open_mutex` (a block device is opened after the path walk), so
  `open_mutex -> i_rwsem` cannot invert.
  The devtmpfs superblock is a tmpfs one (its limits: 3.11 tmpfs
  accounting); a remount reconfigures it under its `s_umount` held
  for writing, like any tmpfs.
- **Block device page cache (`BlockDevice.bd_inode`, Linux
  bd_mapping):** device-file I/O and vfat metadata go through it, in
  buffer heads (3.2 Per-inode page cache, Buffer heads); pages are
  read and written synchronously under their page lock, never under a
  spinlock. The last opener's release writes it back and drops it
  under `open_mutex` (Linux blkdev_flush_mapping: sync_blockdev,
  kill_bdev, which empties the per-CPU buffer LRUs first): open_mutex
  -> page lock -> buffer lock, i_private_lock -> i_pages.
- **Soft block size (the bdev inode's `Inode.i_blkbits`, Linux
  i_blkbits; BLKBSZGET):** set at the first open under `open_mutex`
  (Linux set_init_blocksize) and changed by `set_blocksize` only for a
  caller holding the device's exclusive claim (BLKBSZSET: an O_EXCL
  file's or one taken for the call; a device filesystem's mount through
  `sb_set_blocksize`, its superblock's: under its `s_umount`), so no
  mounted filesystem's buffers change size under it, under the bdev inode's `i_rwsem` held for writing, across
  the cache's write-back and drop (sync_blockdev, kill_bdev), with the
  mapping's `invalidate_lock` held for writing inside it (a fault or
  read filling a page waits): `s_umount` -> bdev `i_rwsem` ->
  invalidate_lock -> page lock. Buffered reads and writes of the
  device file hold that `i_rwsem` shared (Linux blkdev_read_iter,
  blkdev_write_iter), across their user copies: bdev `i_rwsem` ->
  mmap_lock; direct I/O and filesystem metadata take none. Read
  lock-free elsewhere (READ_ONCE).

#### Network Subsystem

**Location:** `net/`, `net/core/dev.rs`, `ns/net.rs`

**Execution model (NAPI-like, no softirqs).** No protocol code runs in
interrupt context. A NIC ISR only reads/acks its interrupt cause, masks the
device's interrupts and calls `napi_schedule()`. Per-CPU `softnet/N`
kthreads (one per CPU with a scheduler, `kthread_run` bound to CPU N) poll
the scheduled NAPI contexts (weight 64, 300 packets per round, then
`yield_now()` if work remains), the CPU's `netif_rx` backlog among them
as its own NAPI (Linux sd->backlog, polled by `process_backlog`), calling
`netif_receive_skb()` -> EtherType handler (`ip_rcv`, `arp_rcv`) -> TCP/UDP/
ICMP. `lo` transmits with `netif_rx()` into the sending CPU's backlog; the
transmit path therefore never re-enters the receive path. A sending socket
syscall then runs `netif_rx_flush_local()` at a point where it holds no
locks (Linux runs pending softirqs at `local_bh_enable()` after
`dev_queue_xmit`), so loopback data is normally queued at the peer before
`sendto()` returns. As Linux's do_softirq_own_stack it runs the backlog
on the CPU's IRQ stack (`irq_stack::run_softirq`: interrupts on, nesting
there; preemption off), allocating GFP_ATOMIC: atomic, it never sleeps,
and a deep task path (an exit closing TCP sockets over lo) does not
carry the receive path's depth on its own stack. A received packet's namespace is its device's
(`skb.net()`), never `current_net_ns()`; a socket's is `Sock.net`.

Today all device IRQs are routed to CPU 0 (PIC / GIC IROUTER), so
received traffic for eth0 runs on `softnet/0`; `lo` traffic goes to the
backlog of the sending task's CPU, whichever that is. The locks below do
not rely on either.

| Lock | Type | IRQ class | Notes |
|------|------|-----------|-------|
| `Softnet.poll_list` (per CPU) | `IrqSpinlock<ArcList<NapiLink>>` (Linux sd->poll_list) | taken in IRQ (`napi_schedule`) and by `softnet/N` | leaf; a scheduled NAPI is linked through its own `Napi.poll_list` with a reference (only the setter of SCHED in `Napi.state` links it, so never twice): the ISR never allocates. Whoever takes a NAPI off it polls it: softnet/N, or an inline `netif_rx_flush_local` taking the backlog's NAPI (one being polled is not on it, so it is left to its poller) |
| `Softnet.wq` (per CPU) | `WaitQueue` | woken from IRQ | leaf (see Wait Queues) |
| `Softnet.backlog` (per CPU) | `SkbQueue<Box<SkBuff>>` (its spin `Mutex`, Linux input_pkt_queue.lock; one lockdep class for every CPU's) | thread only (`netif_rx`, `softnet/N`, inline flush) | leaf; max 1000 packets, then drop + `rx_dropped`. The skbs are linked through their own `SkBuff.list` (Linux skb->next/prev): queueing allocates nothing, so `lo`'s transmit under socket locks queues no memory |
| `Napi.state` | `AtomicU32` (Linux napi->state) | IRQ + thread | one word of SCHED, MISSED and DISABLE, changed by compare-and-swap with Linux's transitions. `napi_schedule` (napi_schedule_prep) sets SCHED and queues it, or sets MISSED if already scheduled; none while DISABLE. `napi_complete_done` (a SeqCst compare-and-swap: a full barrier before the driver re-checks its pending causes) clears SCHED and MISSED, but keeps SCHED if MISSED was set and returns false: the poll loop that holds the NAPI puts it back on the list (`Softnet.requeue`, this CPU's poller alone) and the driver keeps its interrupts masked. `napi_disable` (driver `stop`, RTNL held, sleeps) sets DISABLE, so softnet completes an over-budget poll instead of requeueing it, takes SCHED once free and holds it until `napi_enable` (driver `open`). The backlog's NAPI changes SCHED only under `Softnet.backlog`'s lock: set by the `netif_rx` that finds it clear (and queues it), cleared by the `process_backlog` that empties the queue (Linux enqueue_to_backlog, process_backlog) |
| `NetDevice.running` | `AtomicBool` | thread (RTNL writers; NAPI poll readers) | Linux __LINK_STATE_START (`netif_running`): set before the driver's `open`, cleared before its `stop`; polls re-enable device interrupts only while set, checked under the driver's `rx` lock that `stop` takes to mask, so open/close never strand a device masked or leave a stopped one unmasked |
| `PTYPE_BASE` | `RcuList` of `&'static PacketType` (Linux ptype_base; its `ends` spin leaf) | readers under RCU (receive path); written at boot (`dev_add_pack`) | the handler is copied out of the walk and called after the guard drops (handlers take socket locks and allocate) |
| `PTYPE_ALL` | `spin::RwLock` (fixed array of taps) | thread only | leaf; taps copied out, called after unlock. Taps (AF_PACKET) run from `netif_receive_skb` and from `dev_queue_xmit` (PACKET_OUTGOING), i.e. possibly under a caller's socket or neighbour-free transmit path: they take only the AF_PACKET leaves below |
| `Softnet.thread` (per CPU) | `spin::Once<Arc<KThread>>` | thread only | set once by `softnet_init` |
| `Sock` (`net/sock.rs`, in every protocol socket) | atomics + `Sock.wq` (`WaitQueue`) | any (wakeups) | error, shutdown, buffer sizes, timeouts, SOL_SOCKET flags, SO_LINGER (switch and time in one word); one wait queue per socket for readers, writers, connect/accept and pollers (`sk_data_ready`/`sk_write_space`/`sk_error_report` = `wake_poll` keyed with their events, `sk_state_change` = `wake_all`), woken after the socket's own protocol locks are dropped; another path may wake it under its own locks (an AF_PACKET tap queueing to a packet socket under a transmitting TCP socket's `cb`): `Sock.wq` is an IrqSpinlock taking only run-queue locks, so that never inverts |
| sockfs inode `private` | `spin::RwLock` (VFS, `Inode.private`) | thread only | read per socket file operation (`sock_of`) to reach the protocol socket; leaf |
| `TcpSock.lock` owner (`net/tcp/mod.rs`; `net::sock_lock::SockLock<Inner>`, `net/core/sock_lock.rs`) | sleeping owner (an `owned` bit under `slock`, waiters on `SockLock.wq`, exclusive and uninterruptible) | thread only (socket calls: connect, bind, listen, shutdown, setsockopt/getsockopt incl. TCP_INFO, SIOCINQ, release, disconnect, sendmsg, recvmsg) | Linux `lock_sock`: guards the `tcp_sock` state (`Inner`: the whole I/O-free `TcpCb` with its queues, options, timers and the connect-in-progress flag `Inner.connecting` (Linux SS_CONNECTING); tuple, port ownership, listener link, timer slot) for socket calls across user copies (recvmsg copies from the receive queue, sendmsg into the send queue: owner -> mmap_lock through the faults) and is released only around sleeps (`Relock::unlocked`, Linux sk_wait_event: waits for data, room, memory, the handshake). Above every network spin lock: everything the old socket spin lock was above (tables, `Inet.addr`, `TcpSock.queue`, the timer bases, the transmit path) may be taken under it. A step's `Out` is applied as the owner (segments transmitted, error/shutdown bits and the `Snap` published, so one connection's segments are never reordered across CPUs); wakeups, SIGIO included, run within the step, owned (Linux: before release_sock). Release (Linux release_sock) feeds the backlog to `backlog_rcv` owned with `slock` dropped until it is empty (input still sees the socket owned and backlogs), then under `slock` runs `release_cb` (deferred timers, MTU reduction, soft error; it also publishes the `Snap`; its wakeups, SIGIO included, run there, Linux tcp_release_cb), clears `owned` and wakes one waiter. Never taken under a spin lock or another TCP socket's owner. A closed or disconnected listener's unaccepted children are aborted as the listener's owner (`listen_stop`, after its accept queue is taken: Linux inet_csk_listen_stop under lock_sock), each under its own `slock` (never owned, Linux bh_lock_sock(child)); its SYN_RECEIVED children are left to drop themselves under their own `slock`, as Linux request socks. A listener reference a child takes under its `slock` (its listener check, its queueing, the listener's wakeup) is put a grace period later (`put_listener`, `rcu::put_rcu`), never dropped there |
| `TcpSock.lock` slock | `spin::Mutex` (lockdep class: `SockLock::new` in `TcpSock::new`, one for every TCP socket) | thread only (softnet input, the socket's timers on `ktimers/N`, ICMP errors, owners' lock/release) | Linux `bh_lock_sock`: the `owned` bit, the backlog (`SkbHead<Box<SkBuff>>`: skbs linked through their own `list`, queueing allocates nothing; its truesize count, Linux sk_backlog.len, zeroed only when a release found it empty) and the deferred flags (Linux sk_tsq_flags TCP_*_DEFERRED). The connection's queues are skbs linked through their own `list` or `rb` node (receive queue `SkbHead`, out-of-order and retransmit queues `SkbTree`, write queue `SkbHead`; Linux sk_receive_queue, out_of_order_queue, tcp_rtx_queue, sk_write_queue): input queues the received skb itself and allocates nothing; what it and the timers transmit under the slock are copies or header-only skbs allocated GFP_ATOMIC (Linux tcp_write_xmit, tcp_send_ack, tcp_retransmit_skb, tcp_fragment); the sender fills its skbs as the owner (Linux sk_allocation). Input (`TcpSock::rcv`, Linux tcp_v4_rcv) runs tcp_v4_do_rcv under it when unowned (state changes, transmit, `Snap`, the error and shutdown bits as above, then the wakeups: wait queues, epoll, SIGIO), else queues to the backlog (Linux tcp_add_backlog: over rcvbuf*2 + sndbuf/2 + 64 KiB with the receive queue it drops); a timer that finds the socket owned sets TIMER (Linux tcp_write_timer), an ICMP error MTU or ERR (Linux tcp_v4_err: `mtu_info`, `err_soft`); a handshake's ICMP error is queued for IP_RECVERR under it, owned or not (Linux ip_icmp_error). Input re-checks under it (or in `backlog_rcv`) that the socket still has the tuple it was found by. Never nested with another socket's: a listener's segments take no socket lock (Linux tcp_v4_rcv's TCP_LISTEN case: the SYN path reads the listener's published state, options and queue leaf); a new child is allocated GFP_ATOMIC before any lock (Linux inet_reqsk_alloc, sk_clone_lock) and set up, hashed and its SYN-ACK sent under its own slock (new, never owned); a child never takes its listener's, it queues itself under the listener's `queue` leaf and the listener is woken under the child's slock (Linux tcp_child_process). A TIME_WAIT entry is allocated GFP_ATOMIC under it (Linux inet_twsk_alloc); tables, `Inet.addr`, `TcpSock.queue`, the timer bases and the transmit path below it. An owner's release runs `release_cb` (the deferred work, its transmit and wakeups) under it, as an unowned timer runs under it (Linux release_sock). The `SockLock.wq` IrqSpinlock is a leaf under it (release wakes a locker there, Linux release_sock) |
| `TcpSock.snap` (`Snap`: state, receive and send queue bytes, writable, snd_una, snd_max), `TcpSock.live` (`cb::Live`), `TcpSock.mtu_info`, `TcpSock.err_soft` | atomics (`Live`: `sync::SoleCell`s) | written by the one context holding the socket (owner, or slock unowned); read lock-free | Linux's READ_ONCE fields: `Snap` is stored (Release) at the end of every locked step (`apply`, `release_cb`) and read (Acquire) by poll (tcp_poll), `TcpSock::state`, SIOCOUTQ/`inq`, the sleepers' conditions (sk_wait_event: data, room, handshake, close) and tcp_v4_err's sequence check on an owned socket; the owner re-checks under the lock after waking. `Live` holds the control block's own fields that /proc/net/tcp reads (Linux get_tcp4_sock: icsk_pending/icsk_timeout and the keepalive timer as `tmr`, `keep_at`, `wait_at`; icsk_backoff, icsk_probes_out, icsk_rto, icsk_ack ato/quick/pingpong, snd_cwnd, snd_ssthresh, mss_cache, fastopenq.max_qlen), not copies: an `Arc` shared by the socket, its `TcpCb` and the block's `Cong`, apart from the lock's data so a reader never aliases the holder's `&mut`. Each is stored (Relaxed, WRITE_ONCE) where it changes by the same one context and read (Relaxed, READ_ONCE) by TCP's own code under the lock; a new block (connect, a listener's child) resets them all but `fastopen` (the socket's, Linux's accept queue). A timer and its deadline are packed in one word, so a reader sees a matching pair. /proc/net/tcp takes no socket lock and never waits for an owner (`info::sock_line`): under RCU it reads `Snap` (state, queue bytes) and `Live` field by field, as Linux reads racily; a listener's accept count is `TcpSock.ack_backlog`. `mtu_info` / `err_soft` (Linux tp->mtu_info, sk_err_soft) are stored under slock by an ICMP error that found the socket owned before its deferred flag is set, and read by the owner's `release_cb` after the flag (both ordered by slock). Relaxed for those two |
| `TcpSock.queue` | `spin::Mutex<Option<Accept>>` | thread only | leaf: a listener's SYN_RECEIVED children and accept queue, intrusive lists through each child's `accept_link` (Linux rskq_accept_head; queueing allocates nothing); taken by the lockless SYN path, under a child's slock (queued, moved, dropped; a child completing after its listener stopped listening is aborted under its own slock, Linux inet_child_forget), under the listener's owner (listen, close, accept, disconnect). `TcpSock.ack_backlog` (atomic, Linux sk_ack_backlog) is stored under it as the accept queue changes (sk_acceptq_added / removed; 0 when the queues are taken) and read lock-free by poll, accept's wait and /proc/net/tcp (READ_ONCE: inet_csk_listen_poll, reqsk_queue_empty) |
| `TcpSock.listen_opts` | `spin::Mutex<cb::Opts>` | thread only | leaf: a listener's options copied at the end of each locked step in LISTEN, read by the lockless SYN path (Linux reads the listener's tcp_sock fields with no lock) |
| `TimeWait.inner` (`net/tcp/timewait.rs`) | `spin::Mutex` | thread only | a TIME_WAIT entry's `TwCb` (Linux tcp_timewait_sock's fields, which Linux reads and writes with READ_ONCE/WRITE_ONCE and no lock) + its timer's armed deadline; same position as the `TcpSock.lock` slock (taken instead of it, never with it). A segment (`TimeWait::rcv`, Linux tcp_timewait_state_process) and the 2MSL timer (Linux tw_timer_handler) work on the `TwCb` under it and allocate nothing; under it only its timer's base (`TimeWait::sync`). The ACK is built under it and transmitted after it is dropped (Linux tcp_v4_timewait_ack: an skb of its own, GFP_ATOMIC); an entry that ends (RST, timer, takeover SYN, namespace teardown) leaves the tables after it is dropped |
| TCP socket timers `TcpSock.timers`, `TimeWait.timer` (`net/tcp/`) | `time::timer::ArcTimer` (SOFT `TimerList`s) | callbacks in `ktimers/N` (thread) | Linux icsk_retransmit_timer, icsk_delack_timer, sk_timer, tw_timer: embedded, armed by `sync_timers` / `TimeWait::sync` under the socket lock (owner or slock) / `TimeWait.inner` for the control block's deadlines, a pending one holding a reference to its socket (Linux sk_reset_timer); the callback takes the slock (an owned socket gets the TIMER deferred flag, run at its release) or `TimeWait.inner`, and drops the reference after unlocking, possibly the socket's last (an `ArcTimer`'s drop only disarms, never waits). Order: socket lock -> timer base (IrqSpinlock leaf) |
| TCP tables (`net/tcp/table.rs`, Linux tcp_hashinfo: one set for every namespace, entries matched in their own, net_eq) | ehash and lhash: `util::hlist_nulls` RCU chains, each bucket its own spin lock (Linux inet_ehash_lockp, ilb2->lock); an ehash bucket has one chain of `Eh` entries (Linux sock_common heads), each a connection's or a TIME_WAIT entry's, made before any table lock (a child's and a TIME_WAIT entry's GFP_ATOMIC with it, connect()'s as the owner) and held by its owner (`Inner.eh` under the socket lock, the TIME_WAIT entry's own leaf) to unhash it; a socket entering TIME_WAIT is replaced under the bucket's one lock; bhash: a spin `Mutex<ArcList<BindBucket>>` per bucket, each bucket's owners under its own spin leaf | thread only | lookups (segment input, ICMP errors, listener lookup, /proc/net/tcp) walk ehash/lhash under `rcu::read_lock` with no lock and take a reference, re-checking the key after (Linux __inet_lookup_established); a chain's reference to an entry taken off is dropped a grace period later (`rcu::put_rcu`; Linux: the hash's sock_hold with SLAB_TYPESAFE_BY_RCU), so lockless readers never see a freed socket, and an entry may be rehashed at once (a reader that followed it ends at another nulls value and looks again). Order: bhash chain -> bind bucket owners (leaf) -> ehash bucket (one lockdep class for every nulls bucket, never two held); `Inet.addr` of candidates read under the bhash locks and under RCU; a bind bucket is allocated GFP_ATOMIC under its chain lock (Linux inet_bind_bucket_create), freed with its last owner; connect picks a port and inserts its four-tuple under the port's chain lock (Linux __inet_hash_connect). Never a socket lock under a table lock |
| `Sock.errq` (`net/sock.rs`) | `SkbQueue<Box<SkBuff>>` (its spin `Mutex`, Linux sk_error_queue.lock) | thread only (softnet ICMP error delivery, sendmsg's local errors, recvmsg MSG_ERRQUEUE, poll) | leaf: IP_RECVERR queue of skbs (quoted payload, `SkbCb::Exterr`) built GFP_ATOMIC before it (Linux ip_icmp_error's skb_clone, ip_local_error's alloc_skb), bounded by SO_RCVBUF (own charge); a purge splices it out and frees after; the wakeup follows the unlock |
| `IcmpRate.peers` (`net/icmp.rs`, per netns) | `spin::Mutex<RbTree>` (Linux inet_peer_base.lock) | thread only | leaf: the per-destination limiters (Linux inet_peer), a new one's node allocated GFP_ATOMIC under it (as Linux inet_getpeer); peers the lookup passed past their time to live (inet_peer_gc: 120..600 s by load, against 1% of memory in entries) are unlinked under it and freed after. The global credit is two atomics, refilled lock-free (Linux icmp_global_allow) |
| `UdpSock.op`, `PingSock.op` | sleeping `sync::Mutex<()>` (Linux lock_sock) | thread only (socket calls) | datagram socket lock (bind/connect/disconnect/autobind; connect autobinds within the same hold, and routes under it); taken before the protocol's port/identifier table, never under a spin lock |
| `RxQueue.q` (`net/dgram.rs`: UDP, ping, raw receive queues) | `SkbQueue` (its spin `Mutex`, Linux sk_receive_queue.lock; one lockdep class) | thread only (softnet enqueue, recvmsg) | leaf; the received skbs themselves, each wrapped in an `Arc` (Linux skb->users) GFP_ATOMIC before the lock and linked through `SkBuff.list`, so queueing allocates nothing; broadcast, raw and ping copies are cloned GFP_ATOMIC before it (Linux skb_clone); MSG_PEEK takes a reference under it and copies after; bounded by SO_RCVBUF (`rmem` atomic, skb truesize: charged before the push, uncharged after the pop; a purge splices the queue out and uncharges exactly what it took); skbs are dropped after it |
| `RAW_TABLE.lock` (`net/raw.rs`, one for every namespace, entries matched in their own, net_eq) | `spin::Mutex<RawLocked>` (Linux raw_v4_hashinfo.lock; its `UniqueOwner` proves writers of the 256 `RcuHList` chains) | thread only | leaf except `Inet.addr`: raw sockets hashed by protocol and namespace (Linux raw_hashfunc); taken by create and release only. Delivery and ICMP-error fan-out walk a chain under `rcu::read_lock` (Linux raw_v4_input, raw_icmp_error), read each candidate's `Inet.addr` and queue GFP_ATOMIC clones under the guard. A removed socket's table reference is released a grace period later (`RcuHRef::defer_put`, Linux SOCK_RCU_FREE), possibly in `rcuc/N`; `RawSock.filter` is an atomic |
| `PacketTable.sklist` (`net/packet/`, per netns; `util::rculist`, its writers' spin leaf) | `RcuList` | thread only (taps in softnet or a transmitting task, socket create/close) | Linux net->packet.sklist: create and release write it (O(n) unlink by address); the device tap, NETDEV_DOWN and /proc/net/packet walk it under `rcu::read_lock` (Linux sk_for_each_rcu) and queue GFP_ATOMIC copies under the guard; NETDEV_UNREGISTER, which sleeps per socket (`mclist`, device promiscuity), walks a `snapshot` taken before. A released socket's list reference goes a grace period later (`RcuUnlinked::defer`), possibly in `rcuc/N`; a global atomic count skips all work when no packet socket exists |
| `PacketSock.rxq` (`PktQueue.q`), `PacketSock.filter` | `SkbQueue` (spin `Mutex`) / `spin::RwLock` | thread only | leaves; the queue holds each frame's copy as an skb (`SkbCb::Pkt`) made GFP_ATOMIC and wrapped in its `Arc` before the lock (Linux packet_rcv's skb_clone; MSG_PEEK takes a reference under it), bounded by SO_RCVBUF (`rmem` atomic, checked before the copy, drops counted); a purge frees after the lock; the filter `Arc` is cloned out and the read guard dropped before it runs (a separate statement: an `if let` scrutinee's guard would live across the run); the binding (protocol, ifindex) and flags are atomics |
| `PacketSock.mclist` | sleeping `sync::Mutex<Vec<Mreq>>` (Linux: under RTNL) | thread only | PACKET_ADD/DROP_MEMBERSHIP list, changed only under RTNL (Linux packet_mc_add takes rtnl_lock); RTNL -> `mclist`, dropped before the device's promiscuity changes (`NetDevice.set_promiscuity`, RTNL held, may call the driver) |
| `PacketSock.bind` | `AtomicU64` (protocol << 32 \| ifindex) | thread only (bind, device unregister; read by receive, send, getname) | the binding (Linux po->num/ifindex under po->bind_lock): changed only by compare-exchange from the value the change was decided on, so bind and unregister never undo each other. bind looks the device up again after storing: unregister unlists a device before visiting its sockets, so either that visit sees the new binding or the lookup misses the device and bind moves the socket to ifindex -1 (Linux "unlisted") |
| `PING_TABLE.lock` (`net/ping.rs`, one for every namespace, entries matched in their own, net_eq) | `spin::Mutex<PingLocked>` (Linux ping_table.lock; its `UniqueOwner` proves writers of the 64 `RcuHList` chains) | thread only | ping sockets by echo identifier and namespace in 64 RCU hash chains (`util::rcuhlist`, Linux hlist_*_rcu): an identifier search and its insert are one hold of `lock` (the new socket's identifier is set under it; the rover is per namespace), removals take it too; candidates' `Inet.addr` is read under it (order table -> Inet.addr). Receive/error lookups walk a chain under `rcu::read_lock`, take a reference to the match under the guard (sock_hold) and queue after dropping it. A removed socket's table reference is released a grace period later (`RcuHRef::defer_put`, Linux SOCK_RCU_FREE), possibly in `rcuc/N` |
| `Inet.addr` (`net/af_inet.rs`) | `spin::Mutex` | thread only | leaf: addresses/ports of a TCP or UDP socket; read under the UDP/TCP port tables during lookups, so bind sets the addresses before publishing the port in a table (reset on failure; Linux inet_bind) |
| `RTNL` (`net/rtnl.rs`) | `sync::Mutex<()>` (sleeping, Linux rtnl_mutex) | thread only (syscalls, kernel config; never softnet) | OUTERMOST network lock: serializes all configuration changes (link up/down + MTU, addresses, routes, neighbour entries, device naming + registration via `alloc_netdev`/`register_netdev`) from netlink, SIOCS* ioctls and the kernel. Functions needing it take `&RtnlGuard`. Never taken while any spinlock is held (a socket's last close, which may take it for AF_PACKET memberships, runs only after the fd table lock is dropped). Holders may sleep (user copies such as SIOCADDRT's `rt_dev` name, like Linux rtentry_to_fib_config; driver open/stop waiting for NAPI) but never take a socket lock (`sk_lock`) and never wait for packets. Releasing it (`RtnlGuard` drop, Linux rtnl_unlock -> netdev_run_todo) takes the todo list under it, unlocks, then waits for the devices unregistered under that hold (sleeps, RCU barriers; Unregistration below): the guard's drop sleeps when the hold unregistered a device, so it is never dropped under a spinlock |
| `rtnl::NET_TODO` (`net/rtnl.rs`, Linux net_todo_list) | `spin::Mutex<ArcList<TodoList>>` | thread only | leaf, taken only under RTNL: `unregister_netdevice` links the device (`NetDevice.todo_list`, a reference held), the RTNL release takes the whole list; nothing is dropped under it |
| `NetNamespace.devices` | `RcuList` (Linux dev_base_head) | readers under RCU, any context; writers thread only | registration and unlisting run under RTNL (or before the namespace is listed) and take the list's leaf writer lock; lookups (`get_device`, `dev_get_by_index`) walk it under RCU and take a reference, no lock, no copy; `/proc/net/dev` formats under the guard into a `SeqBuf` (fs/proc/seq.rs, Linux seq_file: a fixed buffer, the walk rerun into a doubled one on overflow), allocating nothing inside; `devices()` references every device for work done per device; unlisting returns after a grace period (Linux synchronize_net), so no reader still walks over the device |
| `NetNamespace.loopback` | `spin::RwLock` | thread only | reached only via methods returning owned values / `Arc` (no guard escapes) |
| UDP hash slot locks (`net/udp.rs` `UDP_TABLE`, one table for every namespace, sized at boot) | `spin::Mutex<()>` per slot (`util::hlist_nulls` buckets; Linux udp_hslot.lock) | thread only | one held at a time: a bind's conflict check, its insert and the port it sets are one hold of its port's slot (ephemeral search locks each candidate's slot in turn), and so is an unhash with its reuseport detach; candidates' `Inet.addr` is read under it (order slot -> `REUSEPORT_LOCK` -> Inet.addr). Receive, multicast, ICMP-error lookups and /proc/net/udp walk a slot under `rcu::read_lock` (Linux __udp4_lib_lookup, __udp4_lib_mcast_deliver) and queue GFP_ATOMIC clones under the guard. A removed socket's table reference is released a grace period later (`NullsUnlinked::defer`, Linux SOCK_RCU_FREE), possibly in `rcuc/N` |
| `REUSEPORT_LOCK` (`net/core/sock_reuseport.rs`, one for every group) | `spin::Mutex<ReuseLocked>` (Linux reuseport_lock; its `UniqueOwner` proves writers of each group's member array and each socket's `ReuseCb`) | thread only | inside a UDP slot lock: joins (a full member array replaced by one twice its size, allocated GFP_ATOMIC under it as Linux reuseport_grow), leaves (the last member moved into the slot; no allocation), has_conns on connect. Lookups pick a member under `rcu::read_lock` (Linux reuseport_select_sock); replaced arrays, member references and left groups are released a grace period later (`put_rcu`) |
| `Fib.tables`, `FibTable.entries` (`net/inet/fib.rs`, per netns; Linux fib_table_hash, a table's aliases) | `RcuList`s (their `ends` spin leaves) | readers under RCU, any context; writers thread only | changed only under RTNL (Linux fib_table_insert/delete): a route goes in at its sorted place (`insert_before`/`insert_after`) or takes an old one's (`replace`, NLM_F_REPLACE); one removed or replaced is freed after a grace period (`RcuUnlinked::defer`, Linux alias_free_mem_rcu). Routes losing their device or preferred source are first marked dead (`FibEntry.fib_flags`/`pfsrc_removed`, atomics written under RTNL and read by lookups without a lock: Linux fi->fib_flags), then unlinked in one walk per table under its `ends` (`RcuList::remove_all`, Linux fib_table_flush), the walk only deferring entries or moving them into room reserved beforehand; the pfsrc ones are announced after it. Input/output routing (softnet, socket syscalls, possibly under `sk_lock`) walks them under `rcu::read_lock` and takes a reference to the route it returns; route dumps fill an `NlBuf` and /proc/net/route a `SeqBuf` under the guard; notifications are built outside it. Tables are never removed while the namespace lives |
| `InDevice.ifa_list` (`NetDevice.ip_ptr`, Linux in_device ifa_list; IPv6 later), `ifaddr::INET_ADDR_LST` (Linux inet_addr_lst: 256 chains by namespace and local address) | `RcuList`s (their `ends` spin leaves) | readers under RCU, any context; writers thread only | changed only under RTNL (`inet::ifaddr`): an address is inserted at its place (a primary after the last primary of its scope, a secondary last: `insert_after`) and on its hash chain, and unlinked from both and freed after a grace period with one callback (`RcuUnlinked::defer_with`, Linux inet_free_ifa); NLM_F_REPLACE changes its `flags`/`rt_priority`/`proto` atomics in place. Readers (source selection on transmit, possibly under a socket lock; `ip_dev_find`; address dumps filling an `NlBuf`) walk under `rcu::read_lock`, no lock, no copy |
| `NeighTable.lock` (`net/core/neigh.rs`; `arp::arp_tbl`, one table for every namespace, IPv6 ND later; Linux tbl->lock) | `spin::Mutex<TblLocked>` | thread only (softnet, socket output, `ktimers/N` neighbour timers, the system workqueue's periodic GC, RTNL-held configuration) | writers of the RCU hash (`NeighHash`: `RcuHList` chains published through an `RcuArc`; lookups, dumps and /proc/net/arp walk them under `rcu::read_lock`, no lock, no copy), the gc list and every device's list (`NetDevice.neighbours`, a `LockedBy` it owns). An entry is allocated with `Gfp::ATOMIC` before it is taken (Linux neigh_alloc); the hash doubles under it with `Gfp::ATOMIC` (neigh_hash_grow: entries move between chains with no grace period, the old table is freed after one; on failure it stays); unhashed entries are released after a grace period (`RcuHRef::defer`). Order: -> `Neighbour.inner` (GC, flush, delete, gc-list moves); the forced GC runs from `create` before it is taken; periodic GC drops it between chains and re-queues itself under it (-> the workqueue's IrqSpinlock, Linux queue_delayed_work under tbl->lock) |
| `Neighbour.inner` (Linux neigh->lock) | `spin::Mutex` | thread only | NUD state, the entry's timer and its unresolved queue (`arp_queue`: an intrusive `SkbHead`, bounded by truesize at unres_qlen_bytes). The timer (`ArcTimer`, a pending arm holds a reference, Linux neigh_add_timer's neigh_hold) is armed and deleted under it (-> the timer base's IrqSpinlock). Never held while transmitting, soliciting or reporting errors: state changes return actions run after the unlock |
| `timer::Alarm.st` (IP reassembly) | `spin::Mutex` | thread only | held across arming its SOFT `TimerList` (-> the timer base's IrqSpinlock); otherwise leaf |
| `NetMib` (`net/mib.rs`, per netns `NetNamespace.mib`; Linux net->mib) | none: per-CPU `AtomicU64` words (IcmpMsg: one atomic per entry, Linux DEFINE_SNMP_STAT_ATOMIC) | any (receive, transmit under socket and queue locks, timers, syscalls) | lock-free counters: an update is one relaxed RMW on the calling CPU's word (Linux this_cpu_inc: safe from IRQs and preemption; a task moved between picking the word and the RMW still counts exactly, on the other CPU's word); /proc/net/snmp and /proc/net/netstat sum every CPU's words (snmp_fold_field), not a snapshot. Its `inuse` gauges (/proc/net/sockstat's sockets, TCP/UDP/RAW hashed and TIME_WAIT counts; Linux prot_inuse) also go down by one: a part may wrap, the sum (read clamped at 0, sock_prot_inuse_get) does not; each socket moves them once each way, guarded by its own flag (`Sock.inuse`: in by compare-exchange, out for good by swap; `TcpSock.inuse` swapped). Takes no lock, so it has no order position |
| IPv4 reassembly (`net/inet/frag.rs`): `FRAG_TABLE` bucket locks, `FragQueue.st` | `util::hlist_nulls` bucket `spin::Mutex` (Linux the fqdir rhashtable's); `spin::Mutex<Frags>` per queue (Linux q->lock) | thread only (softnet, a queue's timer on ktimers/N) | queues of every namespace (sized at boot, the namespace's random mix in the hash) looked up under `rcu::read_lock`, made GFP_ATOMIC with no lock held and inserted under the bucket lock (a racing one kept). `st` holds the fragments (the received skbs in an rbtree) and lengths; killing a queue (completion, overlap, expiry; Linux inet_frag_kill) unhashes it under `st` (order `FragQueue.st` -> bucket lock) and stops its `ArcTimer`. The completed datagram is assembled (GFP_ATOMIC) and an expiry's ICMP error sent after `st` is dropped, from the dead queue's fragments. The namespace's memory (each fragment's skb truesize) and queue counts are atomics; at namespace exit `frag::net_exit` stops new queues and kills its queues one at a time (found under the bucket lock, which is dropped before the queue's `st`; Linux fqdir_exit). A queue's table reference goes a grace period after it is unhashed, possibly in `rcuc/N` |
| `route::FNHE_LOCK` (`net/inet/route.rs`, global; Linux fnhe_lock) | `spin::Mutex<FnheLock>` (its `UniqueOwner` proves writers of every nexthop's `RcuHList` exception chains) | thread only (softnet ICMP frag-needed input, `route::output` deleting an expired exception, possibly under a socket lock) | leaf: a route's chains are allocated at its first exception and each exception is created under it with `Gfp::ATOMIC` (Linux kzalloc GFP_ATOMIC under fnhe_lock), dropped without memory; past a chain depth of 5 to 9 (randomized, Linux FNHE_RECLAIM_DEPTH) the oldest is removed first; removed ones are freed after a grace period. Readers (`route::output`) walk the chain under RCU; pmtu, expiry and generation are atomics updated in place. One of an older generation than `NetNamespace.fnhe_genid` (a lock-free counter bumped by a net.ipv4.route.flush write, Linux fnhe_genid) is reset under it when found (Linux rt_bind_exception). The chains go with their route (a replaced route's with it) |
| `NL_TABLE.lock` (`net/netlink`, one for every namespace) | `spin::Mutex<NlLocked>` (Linux nl_table's hash locks and netlink_table_grab; its `UniqueOwner` proves writers of the port id `RcuHList` chains, sized at boot) | thread only | a bind/autobind checks the socket's `bound`, searches the chain and publishes its portid in one hold (Linux netlink_insert), so concurrent binds of one socket cannot both insert; release unhashes under it; a first subscription adds the socket to its namespace's multicast list of its protocol (`NlNet.mc`, `RcuHList` chains it also owns), which it leaves when its last group goes or at release (Linux netlink_update_subscriptions). Unicast lookups walk a chain under `rcu::read_lock` and take a reference under the guard (Linux netlink_lookup); broadcasts walk a multicast list under RCU, or a snapshot taken before when the clones may sleep (Linux netlink_lock_table + do_one_broadcast's caller GFP). Released sockets' references go a grace period later (`defer_put`, `defer_put`), possibly in `rcuc/N` |
| `NlSock.dump` | sleeping `sync::Mutex<Option<Dump>>` (Linux nlk->cb_mutex) | thread only (sender's `sendmsg`, reader's `recvmsg`, release) | running dump cursor; held while it snapshots devices/FIB/ARP and while its part is queued to `rxq` (keeps parts ordered); readers are woken after it is dropped; never with RTNL. `NlSock.running` (atomic, Linux cb_running) says a dump is set: written under it, read lock-free by poll (`readable`, possibly under an epoll IrqSpinlock) |
| `NlSock.rxq`, `NlSock.dst` | `SkbQueue` (spin `Mutex`) / `spin::Mutex` | thread only | leaves; replies, dump parts and notifications are skbs (`SkBuff::from_vec`, `SkbCb::Nl`) wrapped in their `Arc` before the queue lock and pushed under it (each charged to rcvbuf first; a broadcast clones each extra receiver's copy with no lock held, under the caller's GFP, Linux netlink_broadcast's allocation), MSG_PEEK takes a reference under it and copies after, a release purges it and frees after; `Sock.wq` is woken (`data_ready`) after it is dropped; a dequeue wakes `NlSock.wait` (Linux nlk->wait: user senders waiting for room) after it is dropped |
| `NlSock` portid/groups/flags/err/rmem/congested/dead, autobind `ROVER` | atomics | thread only | `dead` (Linux SOCK_DEAD) is set at release, which then purges `rxq` and wakes `NlSock.wait`: a user sender waiting there for room fails ECONNREFUSED |
| `UnixSock.bindlock` (`net/unix`) | `sync::Mutex<()>` (sleeping) | thread only | Linux u->bindlock: bind/autobind; taken with no spinlock held, before the `UnixTable`/`BSD` buckets. A path bind runs the VFS mknod (parent `i_rwsem`) first and takes `bindlock` after it returns (Linux nests i_rwsem -> bindlock; hk does not need to); if the socket got bound meanwhile it drops `bindlock` before unlinking the node, so `i_rwsem` is never taken under `bindlock` |
| `UnixSock.iolock` | `sync::Mutex<()>` (sleeping) | thread only (recvmsg) | Linux u->iolock: one reader across dequeue -> user copy -> consume; dropped before waiting for data; above `st`/`rq` |
| `UnixSock.st` | `spin::Mutex<Option<Arc<UnixSock>>>` | thread only | Linux unix_state_lock: the peer; `state`, shutdown bits and `dead` change under it. At most two published sockets at once: listener -> connecting socket (stream connect; a socket that is not CLOSE fails before taking its own, so listeners never nest), then the new server-side socket (not yet reachable by anyone; Linux unix_state_lock_nested(newsk)) as a third; or two in ascending address order (`lock2`, Linux unix_state_double_lock: dgram connect, socketpair). Senders queue under the receiver's `st`, so nothing is queued to a released socket |
| `UnixSock.rq` | `SkbOwnedQueue` (spin `Mutex`, skbs carry its owner mark) | thread only | receive queue (Linux sk_receive_queue.lock), under `st`; a listener's queue holds embryo connections. Messages are skbs (`SkbCb::Unix`: the sender's charge, credentials, files, consumed count) whose `Arc` is made before any lock; readers (holding `iolock`) take a reference under it and copy after (Linux unix_stream_read_generic), step to the next one (skb_peek_next) and unlink a fully read one (skb_unlink) by its mark, a no-op if a purge took it; taken skbs are freed after it. `UnixSock.inq_len` (atomic) changes under it |
| `UnixCb.fp` (a queued message's files) | `spin::Mutex` | thread only | leaf (`queue` charges the files in flight under the receiver's `st` and `fp`: an atomic of the sender's ucounts, Linux user->unix_inflight); changed only by the `iolock` holder: the reader takes the files, a peek takes them out, copies them unlocked (Linux unix_peek_fds) and puts them back |
| `UnixTable.buckets` (per netns, 2 x 256), `unix::BSD` (global, 256, by inode number) | `spin::Mutex` per bucket (Linux unx.table.locks, bsd_socket_locks; one lockdep class each) | thread only | sockets linked through `UnixSock.node` / `bind_node` and held weakly (WeakList: a socket leaves at release, or first thing in its drop): unbound and path-bound ones in the lower half, abstract names (hashed with the type) in the upper; after `bindlock`; a bind makes its address before any lock, then takes the old and new buckets in index order (Linux unix_table_double_lock) and publishes `UnixSock.addr` under them (bucket -> `addr`), then the `BSD` bucket alone; lookups upgrade under the bucket and drop the `Arc` after it; /proc/net/unix formats each bucket under its lock into a `SeqBuf`. Nothing is allocated under them, no socket lock is taken under them |
| `UnixSock.addr`, `UnixSock.peercred` | `spin::RwLock` / `spin::Mutex` | thread only | leaves (Linux u->addr, sk_peer_lock) |
| `UnixSock.path` | `spin::Mutex` | thread only | leaf (Linux u->path: the bound socket inode's dentry with its mount, so umount of a filesystem with a bound socket is EBUSY, as Linux): set by a path bind after `bindlock`'s check, before the `BSD` insert; read under a `BSD` bucket (`find_bsd` compares its inode); copied to an accepted socket under `UnixSock.st` (the listener's copied out first: never two `path` locks nested); taken by the release under `UnixSock.st` after `unhash_bsd` (Linux unix_release_sock: under unix_state_lock, with sock_orphan) and put with nothing held, last (path_put) |
| `UnixSock.relay` | `spin::Mutex<()>` | thread only | Linux peer_wait.lock's part in peer_wake: a datagram sender (poll, or a non-blocking send) whose peer's queue is full links its own embedded `peer_wake` entry on the peer's `peer_wait` under it, holding its own `st` so the peer stays its peer while linked (Linux unix_dgram_poll under unix_state_lock); order `st` -> `relay` -> `peer_wait` head; the sender's `peer_wake_to` atomic is set under it. Nothing is allocated |
| `UnixSock` `state`/`dead`/`wmem`/`backlog`/`peer_wake` | atomics | thread only | |
| `NetDevice.ops` | `spin::RwLock<Option<Arc<dyn NetDeviceOps>>>` | thread only | the driver while registered (Linux reg_state + netdev_ops); written once, under RTNL, by `rtnl::unregister_netdevice` (`detach_ops`: None = unregistered). Read-held across the driver's `xmit` (after the lock-free IFF_UP check, so a closed device's senders do not take it), so the write waits for transmits in flight (Linux synchronize_net after dev_deactivate); RTNL-side callbacks (open, stop, set_promisc) clone the `Arc` out, since they may sleep, and RTNL orders them with the detach. Under it: the driver's TX lock, `Softnet.backlog` (lo). Also read under `NeighTable.lock` (`is_gone`: no neighbour is created for an unregistered device after its flush) |
| `NetDevice.net` | `spin::RwLock<Weak<NetNamespace>>` | thread only | read per received packet; written at registration (RTNL held), before the device is linked on the namespace's list |
| driver `netdev` / `Napi.poller` (`spin::Once<Weak<..>>`) | set once at probe, before the IRQ is registered and the NAPI added | read lock-free by polls (thread) | ISRs never read them (they use the driver struct passed as IRQ data) |
| `icmp::ICMP_ECHO_REPLY_WQ` | `WaitQueue` | woken by ICMP input (softnet) | kernel self-test waiter only (`selftest.rs`), woken after the reply is recorded |
| `UnixSock.peer_wait` | `WaitQueue` | thread only | Linux peer_wait: dgram senders blocked on a full peer wait here (no lock held); woken (POLLOUT) by the peer's reads and release; a linked `peer_wake` entry's callback (Linux unix_dgram_peer_wake_relay), under this head, is unlinked by the waker (`add_wait_queue_once`), clears `peer_wake_to` and wakes its socket's `Sock.wq`: `peer_wait` head -> `Sock.wq` head, never the reverse |
| `NetNamespace.sysctl`, `port_range` (`/proc/sys/net`, `sysctl.rs`) | atomics | thread only | no locks; a multi-value sysctl (ping_group_range, ip_local_port_range) is one packed atomic word, so readers never see half an update; the boot port/ISN secret is a `spin::Once`. A /proc/sys/net inode is bound to the namespace it was looked up in (`sysctl::Entry`, `proc_sysctl::NetDir`: a `Weak`, the id and the namespace's `SysctlSet`, Linux the inode's ctl_table_header of net->sysctls); each open, read and write takes an active reference for its duration (`maybe_get`, Linux sysctl_head_grab / use_table), ENOENT once the set is unregistering or there is none, never under the inode data's lock (the drop may be the last). `SysctlSet.unregistering` (Linux header->unregistering) is set once, Release, by `cleanup_net` before the namespace's devices go (Linux the sysctl pernet exits' start_unregistering); ref-mode revalidate and procfs's d_delete read it Acquire under the inode data's read lock, taking no reference (proc_sys_revalidate, proc_sys_delete), so a dput never drops a namespace's reference; procfs's `d_compare` (`proc_sysctl::compare`, Linux proc_sys_compare) reads the candidate's `ProcRcu.net` id and the caller's own nsproxy, no lock |
| `NetDevice.stats`, `flags`, `mtu`, `ifindex`, `carrier`, `promiscuity`, `allmulti` | atomics | any (`promiscuity`/`allmulti` written only under RTNL) | `flags` holds administrative state only; IFF_RUNNING/IFF_LOWER_UP/operstate are derived on read |
| e1000 `rx` ring | `spin::Mutex<Option<..>>` | thread only (NAPI poll, open, stop, remove) | leaf; frames are allocated under it with `Gfp::ATOMIC` (Linux napi_alloc_skb; dropped and counted without memory), linked on an `SkbHead` through their own `list` and delivered after it is dropped; also holds `napi_off` (NAPI disabled by `stop`), read by remove after `unregister_netdev` to disable a NAPI that never was; taken out (rings freed) by remove after the chip reset and IRQ free |
| e1000 `tx` ring | `spin::Mutex<Option<..>>` | thread only (xmit, poll reclaim, remove) | leaf; ring full -> drop, `tx_dropped`, ENOBUFS; empty once removed |
| e1000 `pending_icr`, irq counters | atomics | IRQ + thread | ISR ORs ICR causes in; poll swaps them out |
| virtio-net `rx` queue (`hw/net/virtio_net.rs`) | `spin::Mutex<Option<..>>` | thread only (NAPI poll, open, stop, remove) | leaf: virtqueue + bounce buffers + `napi_off` (as e1000); frames are allocated and linked as e1000's and delivered after it is dropped; taken out by remove, whose `del_vqs` resets the device before the rings and buffers are freed |
| virtio-net `tx` queue | `spin::Mutex<Option<..>>` | thread only (xmit, poll reclaim, remove) | leaf; one descriptor per frame; ring full -> drop, `tx_dropped`, ENOBUFS; empty once removed |
| virtio-net `config_pending`; `VringCb` (RX avail NO_INTERRUPT flag) | atomics / lock-free MMIO-style store | IRQ + thread | the ISR suppresses RX interrupts and flags config changes; the poll re-enables under `rx` only while `netif_running`, and `stop` suppresses under `rx`. With the event index the device ignores the flag: suppressing also sets `used_event` to 0 (Linux virtqueue_disable_cb_split), which `get` leaves alone while the flag is set, so a suppressed ring interrupts only when its used index wraps past 0; `enable_cb` (under `rx`) moves it back to the next entry. A suppression racing a `get` that just saw the flag clear may leave one more interrupt (a hint, as in Linux) |
| virtio-PCI transport (`hw/virtio/pci.rs`) | none | probe and remove (under the virtio device's or the PCI function's `Device.lock`), then IRQ (ISR byte) | common config (status, features, queues, reset) written only under those device locks; device config reads are generation-checked and lock-free; queue notify writes happen under the caller's queue lock |
| Drivers' IRQ registrations: `VirtioDevice.irq` (MSI-X vectors, then their per-vector handlers or the INTx handler, owning the virtio driver's callbacks), the e1000 binding's `irq`, `SerialTty.irq` (8250), `Pl011Port.irq` | spin `Mutex<Option<IrqRegistration<..>>>` (virtio: `Mutex<IrqSlot>`) | thread only (probe sets it, remove takes it; the 8250's: its port's startup and shutdown, under `Tty.port`, each port's handler holding the port and its tty; virtio: `alloc_vectors` enables MSI-X unlocked and stores the vectors, `setup_vq` writes a queue's vector under it, `request_irq` claims the slot, registers unlocked, then stores it or frees the claim; `free_irq` takes it) | leaf: vectors are enabled, registrations made and dropped (`IrqDesc.lock`, `MATRIX`) unlocked; the ISR never takes it (the handler holds its device state) |
| PCI and USB `DYNIDS` (hw/pci/driver.rs, hw/usb/usbcore.rs; Linux dynids.lock) | spin Mutex | thread only | leaf over an intrusive list of boxed ids (Linux pci_dynid/usb_dynid): new_id allocates its entry before taking it, remove_id frees after releasing it; each match takes it alone; the probing after new_id runs with it dropped |
| `ScsiDisk.state` (block/sd.rs, Linux sdev_state + state_mutex) | spin `Mutex<ScsiDeviceState>` | thread only | leaf: transitions (Linux's legal table) and each command's state check take it alone, never across I/O |
| `util::ida::Ida` allocators: virtio, virtio-blk and sd indexes (Linux virtio_index_ida, vd_index_ida, sd_index_ida), namespace inode numbers (`ns::inum`, Linux proc_inum_ida), mount ids (`fs::mount` MNT_IDS, Linux mnt_id_ida) | `IrqSpinlock` | alloc thread only; free any context | leaf; nothing allocates under it (alloc grows the bitmap with it dropped, fallibly for `try_alloc`); a disk index is freed when the disk's last reference drops, a namespace's number when the namespace goes, a mount id when the mount drops |
| `SYSTEM_TRANSITION` (`power.rs`) | sleeping `sync::Mutex<()>` | thread only (reboot(2)) | Linux system_transition_mutex: held from after the permission and magic checks through `device_shutdown` and the arch power-off/restart/halt, which do not return; outermost: taken before `core::DEVICES_LIST` and every driver lock the shutdown callbacks take |
| `power::CAD_PID` (`power.rs`) | `spin::Mutex<Option<Arc<Pid>>>` | thread only (init's start, kernel.cad_pid) | leaf: the process Ctrl-Alt-Del signals (Linux cad_pid, xchg'd there); a replaced reference is dropped after it. `power::C_A_D` is an atomic flag (Linux C_A_D), written by reboot(2) CAD_ON/CAD_OFF under SYSTEM_TRANSITION or by kernel.ctrl-alt-del, read lock-free |
| x86 `power::POWER` (`arch/x86_64/power.rs`) | `spin::Once` | thread only (boot set; power-off/reboot read) | set once from the FADT before `reboot(2)` can run, read lock-free after; the ACPI register sequences (`hw/acpi/hw.rs`) take no locks |

**Lock order (outermost first):**

```
RTNL (sleeping; configuration)   TcpSock.lock owner (sleeping; -> mmap_lock) -> its slock
  |                                 (one socket's at a time: the SYN path takes no
  |                                 listener lock) /
  |                                 TimeWait.inner / UdpSock.op, PingSock.op (sleeping)
  |                                 -> TCP bhash -> owners -> ehash, lhash / UDP slot -> REUSEPORT_LOCK /
  |                                    PING_TABLE.lock -> Inet.addr
  |                                 -> TcpSock.queue / RxQueue.q
  |                                 -> TCP socket timers (timer base); Alarm.st -> timer base
  v                                 |
NetNamespace tables (RwLocks; lookups drop the guard before returning);
  address lists, FIB tables (RCU readers; writers under RTNL take the
  lists' leaf `ends`)
  -> NeighTable.lock -> Neighbour.inner -> timer base (dropped before any
     transmit)
  (RAW_TABLE.lock -> Inet.addr; FragQueue.st -> frag bucket, FNHE_LOCK, IcmpRate.peers,
   Sock.errq, RxQueue.q: leaves, never held while transmitting)
  -> NL_TABLE.lock -> NlSock.rxq (netlink replies/notifications;
     lookups and broadcasts under RCU take no table lock)
  (AF_UNIX: UnixSock.bindlock (sleeping) -> UnixTable buckets / BSD bucket
   -> UnixSock.addr / path; UnixSock.iolock (sleeping) -> UnixSock.st (listener
   before connector, else by address) -> UnixSock.rq / peercred / addr /
   path / UnixCb.fp; UnixSock.st -> peer's UnixSock.relay ->
   peer_wait head -> Sock.wq head)
  (NlSock.dump -> RCU walks of devices, addresses, FIB, neighbours
   -> NlSock.rxq: dump parts)
  (AF_PACKET taps, from any receive or transmit path: under RCU,
   PacketSock.filter / PacketSock.rxq, each a leaf;
   RTNL -> PacketSock.mclist)
  -> NetDevice.ops (read across a transmit; NeighTable.lock -> it)
  -> device TX lock (e1000 tx, virtio-net tx)
  -> Softnet.backlog (lo xmit)           Softnet.poll_list; WaitQueue -> pi_lock
                                          -> rq (IrqSpinlocks, innermost)
```

**AF_UNIX** (`net/unix/`, Linux af_unix.c order). Sockets talk
directly: a sender queues a message on the receiver's `rq` while
holding the receiver's `st`, after copying the data in with no lock
held; readers copy out under `iolock` only, and take an end (error,
shutdown) seen with the queue empty only if `rq` is still empty after
it (a peer queues before it shuts down; Linux tests both under
`unix_state_lock`). Messages (and the files
they carry) are dropped only with no spinlock held: dropping a file
can release a socket, which takes its own and its peer's `st`.
Each file's release is deferred (`fput`, 3.3 Descriptor Tables), so a
chain of sockets in flight releases one file at a time from the task's
task_work loop (or the delayed list), never by recursion. Waits (`sock::wait_on`
on our `Sock.wq` or a peer's `peer_wait`) hold no lock; wakeups follow
the unlock.

RTNL and `sk_lock` are never held together. No network lock is held
while taking a socket lock (lookups return `Arc` handles), and no lock is
held across `netif_rx_flush_local()` (it delivers, taking socket locks):
socket calls run it at their end, after every step. It flushes the
backlog the task's last `lo` transmit went to (`Task.rx_cpu`, written
by `netif_rx`), which is another CPU's if the task moved during the
call (a user copy that slept); earlier packets on yet another CPU, and
any flush that is missed, only wait for that CPU's softnet thread. Netlink requests are processed in
the sender's `sendmsg` with no lock held on entry; mutating handlers take
RTNL; handlers that change a device look it up under RTNL (Linux
locked doits), so they never act on an unregistered one. Carrier
changes (`netif_carrier_on/off`, from a driver's NAPI poll
or `open()`) send RTM_NEWLINK without RTNL (a multicast list -> NlSock.rxq
only). Open/close follow Linux __dev_open/__dev_close: `running` is set
before the driver's open (which `napi_enable`s, then unmasks) and cleared
before its stop (which `napi_disable`s, waiting for a running poll, then
masks under `rx`). A poll re-enables interrupts only while `running`,
under `rx`: a poll racing with open re-enables them, one racing with
close leaves the device masked; `netif_receive_skb` drops frames of a
down device.

**Unregistration** (`rtnl::unregister_netdevice`, Linux
unregister_netdevice_many_notify; from a driver's remove via
`net::unregister_netdev`): under RTNL the device is closed (as above),
unlisted from its namespace (lookups stop finding it; its ifindex is
never reused), and its driver detached (`NetDevice.ops` write: waits
for a transmit in flight; from then on no driver callback runs), then
its addresses, routes and neighbours go and packet sockets lose it
(NETDEV_UNREGISTER), RTM_DELLINK is sent and its sysfs device removed.
The driver then disables a NAPI that is still enabled (`napi_disable`
waits for a running poll), quiesces the hardware, frees its IRQ (no
ISR runs after its `IrqRegistration` is dropped, which takes the
line's `IrqDesc.lock` every dispatch of the line holds), `netif_napi_del`s and frees its DMA
memory. Before that, releasing RTNL waits for the device (Linux
netdev_run_todo, `rtnl::NET_TODO`): with RTNL dropped and an
`rcu_barrier` (routes and neighbours unlinked under RTNL are freed by
RCU callbacks), until its `Arc` count shows only its owner (the
driver's binding, or its namespace's loopback slot) and the todo
list's (Linux netdev_refcnt_read == 1). Holders let go on
NETDEV_UNREGISTER (`netdev_unregister_notify`: addresses, routes,
neighbours and their queued packets; packet sockets keep only the
index); skbs keep no device reference once queued to a socket or a
reassembly queue (Linux skb->dev = NULL there), the rest (in-flight
packets, a route or a `dev_get_by_*` reference of a running call) go
when the call ends, none of them waiting for RTNL or a lock the
waiter holds (`Device.lock` in a driver's remove). The waiter checks
after an RCU barrier and a sleep of 1 ms doubling to 250, sends
NETDEV_UNREGISTER again every second under RTNL (released without
running the list: Linux __rtnl_unlock), and every 10 s prints
"unregister_netdevice: waiting for <dev> to become free. Usage count
= <n>" for each device still held (Linux netdev_wait_allrefs_any).
A namespace has active references (`NetRef`, Linux net->ns.count:
tasks' nsproxies and user sockets) and passive ones (its `Arc`, Linux
net->passive: the memory; TIME_WAIT entries, devices' back pointers,
walkers; /proc/sys/net inodes hold only a `Weak` and its `SysctlSet`). Dropping the last active reference, in any context (a
socket's table reference released in `rcuc/N`), pushes the namespace
on a lock-free list (`CLEANUP_LIST`, Linux cleanup_list) and queues one
static work item on the `netns` workqueue, allocating nothing (Linux
__put_net). `cleanup_net` there unlists the namespaces from
`NET_NAMESPACE_LIST` (write), unregisters each device under RTNL
through `rtnl::unregister_netdevice`, loopback last (Linux
default_device_exit_batch: its addresses, routes, neighbours and
sysfs device go; the RTNL release waits for them, its own device
references dropped first, the loopback slot the owner's), clears
its loopback (loopback_net_exit), ends
the batch's TIME_WAIT entries in one walk (`TimeWait::kill`, Linux
tcp_twsk_purge: timer stopped for good under the entry's lock,
unhashed), waits for queued RCU
callbacks (`rcu_barrier`) and drops the passive references the list
held. Walkers that reach a namespace through a passive reference take
an active one only if it has one (`maybe_get`, Linux
maybe_get_net).

**Driver ISR rules (e1000 pattern):** read ICR (read-to-clear; 0 => not
ours on a shared line, return false), write IMC (mask all), record causes
in an atomic, `napi_schedule`. The poll handles link changes (LSC ->
`netif_carrier_on/off`), reclaims TX, receives up to `budget` frames by
copying them out of coherent bounce buffers, and when it did less than its
budget calls `napi_complete_done` and (while running, under `rx`)
rewrites IMS (a cause latched while masked fires then). If its own ISR
consumed causes during the poll (shared line), it masks and reschedules
itself; `napi_complete_done`'s full barrier orders the ISR's
`pending_icr` update before this re-check.

**virtio-net** follows the same shape over the virtio transport: the
transport ISR reads the ISR status byte (read-to-clear; 0 => not ours),
and calls the driver's lock-free callbacks: a queue interrupt sets the RX
avail ring's NO_INTERRUPT flag (Linux virtqueue_disable_cb from
vring_interrupt) and `napi_schedule`s; a config interrupt sets
`config_pending` and schedules. The poll handles the link, reclaims TX,
receives and reposts RX buffers, and under budget calls
`napi_complete_done`, then (only while the interface is open) clears
NO_INTERRUPT under `rx` and re-checks the used ring and `config_pending`:
work that arrived meanwhile makes it suppress again and reschedule
(Linux virtqueue_napi_complete). The ISR's flag store and the poll's
clear can race; either order leaves NAPI scheduled or the flag clear.

Sockets block only in `Sock::wait` (`wait_event_interruptible_timeout`
on `Sock.wq`) with no lock held (TCP releases its owner lock around
it), or for the TCP owner lock (`SockLock.wq`); receive paths make the condition true
under their leaf lock, drop it, then wake (TCP wakes within its locked
step, as Linux). A socket leaves every table at
last close (`ProtoOps::release`); a TCP connection leaves ehash when it
reaches CLOSED (an orphan when its close handshake or timers end) or is
replaced by a TIME_WAIT entry, which leaves after 2MSL.

**TCP and Linux lock_sock.** Two levels, as Linux
(`net::sock_lock::SockLock`, Linux socket_lock_t): the owner
(`lock_sock`, sleeping) and `slock` (`bh_lock_sock`, spin) over the
owned bit, the backlog and the deferred flags. Socket calls own the
socket across user copies (recvmsg copies straight from the receive
queue to user memory, consuming only what reached it; sendmsg copies
straight into the send queue) and release it only while asleep
(`Relock::unlocked` around `Sock::wait`/`wait_data`, Linux
sk_wait_event), re-checking under the lock after waking. Input, timers
and ICMP errors take `slock`: unowned, they run at once (Linux
tcp_v4_do_rcv, the timer handlers, tcp_v4_err); owned, input waits in
the backlog and timers and errors set deferred flags, which the owner's
release runs before clearing `owned`, as Linux release_sock: the
backlog with `slock` dropped (`backlog_rcv`, Linux __release_sock;
input meanwhile still sees the socket owned and backlogs, re-checked
until empty), then `release_cb` (Linux tcp_release_cb), the owned bit
and the locker's wakeup under `slock`. Lock-free readers (poll, the sleepers'
conditions, SIOCOUTQ) read the `Snap` atomics every locked step
publishes, as Linux reads sk_state and the queue edges with READ_ONCE.
Segments are transmitted and errors/shutdown bits published within the
locked step (`TcpSock::apply`), and the wakeups follow within it: as
the owner, or under `slock` (Linux wakes from tcp_v4_do_rcv, the timer
handlers and tcp_v4_err under bh_lock_sock).
Transmitting under either level is safe because the output path only
takes FIB/neighbour/device-TX leaves and `lo` queues to the receive
backlog instead of delivering inline; the loopback flush
(`netif_rx_flush_local`) runs only with no lock held (at the end of
socket calls, and before a sleep with the socket released). A
TIME_WAIT entry transmits with no lock held.

#### Key Device Driver Rules

1. **Driver locks are thread-context only** - ISR-shared state is atomics or
   core IrqSpinlocks (`napi_schedule`, wait queues)
2. **ISRs ack and defer** - never take a driver Mutex, defer to thread context
3. **Atomics for hot paths** - Use atomics for frequently-accessed state
4. **Completion callbacks are IRQ-safe** - bio `end_io` runs in hardirq: only
   atomics, `Completion::complete` and wakeups; skb completion takes no lock

### 3.11 Other Subsystem Locks

Thread context only unless the class says IRQ; each is a leaf (nothing
else is taken under it) unless an order is given. "spin" is the
`sync::spin` Mutex/RwLock (not IRQ-safe).

| Lock | Location | Class | Protects / order |
|------|----------|-------|------------------|
| `Task.vfork_done` | task/mod.rs | atomic pointer | the vforking parent's on-stack `Completion` (Linux vfork_done): set before the child runs, taken once by the child at exec/exit, which completes it; the parent waits uninterruptibly so the completion outlives that use |
| `Task.wake_q` | task/mod.rs, task/wake_q.rs | atomic pointer | next task on the `WakeQ` it is queued on (Linux task->wake_q): claimed null -> tail by a compare-exchange after a full fence, so a task is on one queue at a time; only that queue's owner links and walks it; the waker clears it before `try_to_wake_up`, which may then queue it again |
| `SignalStruct.posix_timers` | signal/mod.rs, time/posix_timer.rs | spin Mutex | the thread group's timer_create timers (Linux signal->posix_timers and their posix_timers_hashtable entries): an `RbTree` id -> timer whose nodes are reserved before the lock and freed after it, so nothing allocates or frees under it. timer_create (Linux do_timer_create) takes an id with a placeholder (None, skipped by every lookup) in one hold, makes the timer and copies the id out with the lock dropped, then publishes the timer in a second hold or removes the placeholder on an error; clock_nanosleep's hidden CPU timer is made with its node before the lock and inserted in one hold. Thread context, never under TASKLIST; cpu_timer holds it around arming the group's CPU-timer state and its whole expiry pass (`PosixTimer.inner` of the registry's timers and of the CPU itimers, and `SignalStruct.rlim`, inside); deleted at exec and at the group's last exit (`exec_timers`, `exit_itimers`: timers stopped after the lock) or with the SignalStruct (`drop_timers`, from its Drop: exclusive access, no lock or siglock) |
| `SignalStruct.itimers` | signal/mod.rs, time/posix_timer.rs | embedded `PosixTimer`s (their `inner` IrqSpinlocks) | ITIMER_REAL, ITIMER_VIRTUAL and ITIMER_PROF (Linux signal->real_timer, signal->it[]), made with the SignalStruct (fork fails ENOMEM there, setitimer cannot fail); no registry lock: each is reached through the SignalStruct and its state is under its own `inner`. ITIMER_REAL's SOFT hrtimer callback (`it_real_fn`, `ktimers/N`) reaches the SignalStruct by address, so it is cancelled at the group's last exit (`exit_itimers`) and waited out by the SignalStruct's Drop; it takes `inner`, drops it, then takes a reference to `leader_pid` under RCU and sends SIGALRM with nothing held. The CPU itimers are checked by cpu_timer's expiry pass under `posix_timers`, after the registry's timers |
| `SignalStruct.leader_pid` | signal/mod.rs | `RcuLockedArc` owned by TASKLIST | the group leader's struct pid (Linux signal->pids[PIDTYPE_TGID]), ITIMER_REAL's target and a parent's number for getppid and /proc (`Task::tgid_nr_ns`): set under the write lock when the group's first task is attached (`install_fork_signal`, `init_task_signal`), cleared there when its leader is released (`detach_group_pids`, Linux __unhash_process detach_pid(PIDTYPE_TGID)), the old reference dropped a grace period later (`put_rcu`); an exec by another thread keeps it (that thread takes the leader's struct pid, exchange_tids); read under RCU (`it_real_fn` takes a reference in its read section and sends after it) |
| `SignalStruct.wait_chldexit` | signal/mod.rs, signal/notify.rs, task/proc.rs | `WaitQueue` (IrqSpinlock head) | the process's threads in wait4/waitid and a dying namespace init's reap (Linux signal->wait_chldexit): they sleep on it with no lock held, rechecking under TASKLIST's read lock; a child's or tracee's exit, stop or continue notice wakes the receiver's (`notify::wake_up_parent`, Linux __wake_up_parent) inside the TASKLIST hold that made it reportable (`notify` under the write lock, `notify_parent_cldstop` under the read lock), as do de_thread's release of an old leader (its tracer or parent's) and, after TASKLIST, an autoreaped child's release (its parent's: the child stays listed until then); the head is a leaf under TASKLIST |
| `PosixTimer.inner` | time/posix_timer.rs | IrqSpinlock | one timer's state; -> its hrtimer's base (re-armed under it); cancelled with `cancel_sync` before it is taken (settime) or with it dropped (delete). A CPU-time timer's clock value is read before it, at settime and at signal delivery (`deliver_locked`): a sample may take TASKLIST and the target's rq lock (task_sched_runtime) |
| `PosixTimer.sigq` | time/posix_timer.rs | spin Mutex | a timer_create timer's preallocated signal entry while it is not queued (Linux SIGQUEUE_PREALLOC); leaf, never in hardirq, never with `inner`; taken under a siglock (`posix_timer::sig_ignore`, `sig_unignore`). The entry is taken out to be queued by `signal::send_timer_sigqueue` with no lock held, put back under the receiver's siglock when its signal is ignored, and put back when its signal is dequeued (`posix_timer::deliver`, which rearms an interval timer under `inner`), flushed or refused (`reclaim`). A flushed set is dropped wherever its send ran: kill_fasync's F_SETSIG stop signal or SIGCONT drops it under `Fasync.fa` / `FOwner.st` (interrupts off), RCU and the caller's spin locks, so `reclaim` takes `sigq` there as a leaf and puts the timer reference it upgraded through `put_rcu` (Linux posixtimer_putref: kfree_rcu): a timer deleted meanwhile is torn down in `rcuc/N`, its hrtimer idle, never under those locks |
| CPU-timer state (`time/cpu_timer.rs`): `SignalStruct.cputimer`, `Task.cpu_next` | time/cpu_timer.rs | atomics | the group's running CPU totals (utime, stime, sum_exec_runtime: Linux cputime_atomic, RMWs from every thread's CPU) and expiry hints per PROF/VIRT/SCHED sample, a thread's hints; written by the tick's samples and runtime charges (rq lock, interrupts off) and by `run` in task context. The group totals start (arming a process timer, `arm_group`) and stop (`run` finding nothing armed) only under `posix_timers`; sampling never starts them (Linux cpu_clock_sample_group with start=false for gettime). `run` (TIF_NOTIFY_RESUME on the way to user mode) takes `posix_timers` -> `PosixTimer.inner`, then `SignalStruct.rlim`, and sends signals after dropping them: expired timers go on a local firing list through their embedded `PosixTimer.elist` (Linux collect_timerqueue, no allocation), marked `collected` and `firing` under `inner`; after the lock each is unlinked, `collected` cleared under `inner`, and fired if `firing` is still set (settime and delete clear it). A timer still `collected` is skipped by another thread's pass, so it is never linked twice. The itimers' and RLIMIT_CPU's process signals are kept in locals (one each) |
| timerfd `CANCEL_LIST` | time/timerfd.rs | `RcuList` (its `ends` spin leaf), thread only | the timerfds that armed TFD_TIMER_CANCEL_ON_SET (Linux cancel_list), linked through `Timerfd.clist`: `clock_was_set` walks it under `rcu::read_lock` and takes each one's `inner` (IrqSpinlock) in turn, skipping one whose `might_cancel` is off; `setup_cancel` decides under `inner` (`might_cancel`, `listed`), drops it, and the first arming links the timerfd; it stays linked until its release, which clears `listed` under `inner` and unlinks it with no lock held; the list's reference goes with `RcuUnlinked::defer` (Linux kfree_rcu: `Timerfd.rcu`), dropped by `rcuc/N` after a grace period, its timer already cancelled (a HARD hrtimer's drop only spins on a running callback, and none runs). Never nested with `inner` |
| `TimerBase.wheel` (per CPU, HARD and SOFT) | time/timer.rs | IrqSpinlock leaf | a 64-slot wheel of `TimerList`s (their links, `expires`, `pending`); callbacks run with it dropped (`running` set); taken in the tick, by `ktimers/N` and by arming/deleting code in any context |
| `HrBase.q` (per CPU, HARD and SOFT) | time/hrtimer.rs | IrqSpinlock leaf | sorted lists of `HrTimer`s per clock (their links, `expires`, `pending`); callbacks run with it dropped (`running` set); taken in the clock event interrupt, by `ktimers/N` and by start/cancel in any context. `SOFT_ACTIVATED` (per-CPU atomic, Linux softirq_activated): set by the clock interrupt when it hands due SOFT timers to `ktimers/N`, cleared by it after its pass (interrupts off, then reprogram); while set the clock event counts only HARD timers |
| `EPNESTED` (sleeping) → `Eventpoll.mtx` (sleeping) → `EpItem.regs` (spin) → file wait queue heads → `Eventpoll.lock` (IrqSpinlock); `File.f_ep` (spin leaf) | io/epoll.rs | see column 1 | epoll (Linux epnested_mutex, ep->mtx, ep->lock, file->f_lock): `EPNESTED` serializes an epoll target's loop check and insert. `Eventpoll.mtx` (Linux ep->mtx) holds the item map (Linux ep->rbr) and, as Linux, is held across each epoll_ctl operation (an add polls the target with it held, registering), each scan of the ready list (epoll_wait's `send_events`, Linux ep_send_events, with its items' polls and copies to user; the epoll file's own poll, Linux __ep_eventpoll_poll) and each item's removal (EPOLL_CTL_DEL, and a watched file's release: `eventpoll_release` takes each watching epoll's `mtx` in turn), so one scan at a time looks at the ready list. An epoll watched by another is polled with the outer one's `mtx` held and takes its own inside (Linux mutex_lock_nested by depth; hk lockdep does not check nesting within a class): the loop check under `EPNESTED` keeps the nesting acyclic and at most EP_MAX_NESTS deep. A file's last `FileRef` dropped under it only queues the release (`fput`), whose `eventpoll_release` takes it later. An item keeps its file's address only (Linux epi->ffd.file). To poll an item's file, epoll takes a reference with `FileRef::try_get` (`EpItem::fget`, Linux epi_fget), always under `mtx`: an item a holder sees is still in the map, so its file's release has not passed this epoll's `eventpoll_release` and the file is not freed. An epoll's drop (no `mtx` is needed: nothing else reaches it) takes each item off its file's `f_ep` under an RCU read guard (`f_ep_off`): a linked item's file has not finished its release, so its memory stays a file object for the guard (type-stable file cache), and a count taken there (or none: the release unlinks the item) lets it lock `f_ep`. `Eventpoll.file` (Linux ep->file) is set before the epoll is reachable and cleared by the epoll file's release under `EPNESTED`, which the loop check holds while it reads it. `EpItem.regs` holds an item's callback entries: an add polls the file (a poll method may sleep) into a local list and swaps it into `regs` after; unregistering takes the watched file's queue locks under it, before the item leaves the map and ready list, so no callback can queue it again. `Eventpoll.lock` (Linux ep->lock) holds the ready list (`EpItem.rdlink`): `ep_poll_callback` runs under a woken queue's lock (possibly in an interrupt), queues the item under it, then wakes the epoll's own queues after releasing it (a nested epoll's callback in turn: bounded by EP_MAX_NESTS, no cycles). A scan takes the items queued when it starts off the front one at a time (Linux ep_start_scan) and polls each with the lock released; an event meanwhile queues one again at the end (Linux's ovflist), a level-triggered one reported goes back at the end, one whose copy-out failed back in front, and waiters are woken after if any is ready (ep_done_scan). Nothing sleeps, allocates, polls, copies to user or drops a last `Arc<EpItem>` under `Eventpoll.lock`. `File.f_ep` (Linux file->f_ep under file->f_lock) lists the items watching the file through `EpItem.fllink`, holding a reference each (no allocation): an add links the item, EPOLL_CTL_DEL and an epoll's drop unlink it if still linked (an item's link is only ever on its own file's list), the file's release takes them off one at a time under it; the loop check counts an epoll file's watchers under it, sizes its vector with it released and fills it under it (no add meanwhile: `EPNESTED`). |
| `Inotify.fasync` | io/inotify.rs | `FasyncList` (RCU, see `Fasync.fa`) | the group's O_ASYNC files (Linux fsnotify group fsn_fa); queueing an event sends their SIGIO after `Inotify.inner` is dropped |
| `Inotify.mark_mutex`; `Inode.fsnotify` (`Marks.list`) | io/inotify.rs | sleeping `sync::Mutex`; spin leaf | `mark_mutex` (Linux group->mark_mutex) serializes a group's adds and is taken before every other inotify lock. `Marks.list` holds the watches on an inode (Linux i_fsnotify_marks: group and wd); it grows with the lock released (`push_if`, `kmem::grow_locked`: nothing allocates under it). The superblock's shutdown finds its watched inodes by walking `s_inodes` (`for_each_sb_inode`, Linux fsnotify_unmount_inodes' s_inodes walk): a watch holds its inode, so every watched one is live and listed. An add holds the watched path (mount and dentry) throughout, so neither the superblock's shutdown nor the dentry's release of the inode can run meanwhile: it puts the mark on the inode, then under `Inotify.inner` (order `Inotify.inner` -> `Marks.list`, the only nesting) inserts the watch only if the mark is still there; a failure undoes the charge before anything is published. rm_watch and a group's drop remove the watch under `Inotify.inner`, then the mark. Removal of an inode's watches (Linux fsnotify_inoderemove: a dentry letting go of an inode with no name left, in `d_delete` after its locks or in a dentry's final drop, never under a d_lock (Linux dentry_unlink_inode); fsnotify_sb_delete: the superblock's shutdown under s_umount, the
list taken whole under its lock) takes the marks out under `Marks.list`, releases it, then per group takes `Inotify.inner` and checks the wd still names that inode before queueing IN_DELETE_SELF/IN_UNMOUNT and IN_IGNORED; only the remover that finds the watch uncharges it. A watch's inode reference is counted on its superblock (`WatchedInode`, `SuperBlock.s_fsnotify_watched`, Linux fsnotify_get_inode_ref / fsnotify_put_inode_ref): the put comes first, then the count's decrement, the last waking its `var_waitqueue`; the shutdown, after its walk, sleeps there (under s_umount for writing, nothing else held) until the count is zero (Linux fsnotify_sb_delete's wait_var_event), so a watch rm_watch or a group's drop took out before the walk puts its inode before the dentry tree goes, never during or after the shutdown. The group's watch table (wd -> watch, Linux's idr under idr_lock) stays under `Inotify.inner`, a sorted vector: an add makes room for one more under `mark_mutex` before taking `Inotify.inner` (`kmem::grow_locked`, Linux idr_preload; only adds insert, so the room stays), and removals free nothing under it. Nothing there sleeps: each event is allocated before `Inotify.inner` is taken (Linux allocates in inotify_handle_inode_event, then fsnotify_insert_event takes notification_lock; no memory: IN_Q_OVERFLOW takes its place, a queue position that allocates nothing, Linux's preallocated overflow_event), an unqueued or read event is freed after the lock, the wakeup is allowed under any lock and SIGIO is sent with `kill_fasync` once `Inotify.inner` is dropped (Linux fsnotify_insert_event). A watch never counts toward a mount being busy |
| `USER_WATCHES` | io/inotify.rs | spin leaf | each user's inotify watches against fs.inotify.max_user_watches (Linux UCOUNT_INOTIFY_WATCHES ucounts), a vector of (uid, count) that grows with the lock released (`push_if`; Linux alloc_ucounts allocates before ucounts_lock): a new watch is charged before `Inotify.inner` is taken and a removed one returned after it is released (never nested in it; returning frees nothing); the limit itself (`MAX_USER_WATCHES`) is a sysctl atomic read lock-free |
| `Fanotify.mark_mutex` → `Fanotify.inner` | io/fanotify.rs | sleeping `sync::Mutex`; IrqSpinlock leaf | a fanotify group's marks (Linux group->mark_mutex): fanotify_mark adds, removes and flushes them under it (allocating there); never nested with `Fanotify.inner`, the event queue (Linux notification_lock): an event is allocated before it is taken (Linux fanotify_alloc_event, then fsnotify_insert_event; no memory or a full queue: FAN_Q_OVERFLOW, a queue position that allocates nothing) and freed after it is released |
| `Eventfd.inner`, `Inotify.inner`, `Fanotify.inner`, `Signalfd.inner`, `Timerfd.inner` | io/eventfd.rs, io/inotify.rs, io/fanotify.rs, io/signalfd.rs, time/timerfd.rs | IrqSpinlock | per-object state of the anon-inode files (inotify: watch table and event queue; fanotify: event queue; both queues are `io/fsnotify.rs` `NotifQueue`, Linux fs/notify/notification.c: insert, remove_first, the overflow event as a queue position, max_events); their wait queues are woken after unlocking. An inotify watch holds its inode (`InodeRef`, matched by identity, Linux's mark pinning the inode); a removed watch's inode is released after `Inotify.inner` is dropped. eventfd, inotify and fanotify readers wait with it held (`wait_event_interruptible_locked`: inner -> wait queue head while queueing, released while asleep) |
| `IoRing.submit` → `Files`, `IoRing.cq` | io/io_uring/ | `submit` sleeping `sync::Mutex` (Linux uring_lock); `cq` spin Mutex (Linux completion_lock), thread context | `submit`: the kernel's SQ head (Linux cached_sq_head), the registered files and buffers, the pending poll/timeout list; held across a whole io_uring_enter submission, so the operations run (and may sleep, fault on user memory, take any lock a syscall takes) under it, and across io_uring_register; an io-wq worker takes it to install an open's file in the registered table (`IoRing::fixed_install`, Linux io_ring_submit_lock), after the open and with no other lock held, while a chain run in io_uring_enter, which holds it, installs through the held `Submit` (never taking it again) (which reads the fd table under it: -> `Files`; replaced files are released after both). `cq`: the kernel's CQ tail (Linux cached_cq_tail) and the overflow list (Linux cq_overflow_list), a leaf but for growing that list, GFP_NOWAIT named (Linux io_cqe_overflow_locked allocates the overflow CQE under completion_lock, GFP_NOWAIT); posting writes the CQE into the shared ring and publishes the tail (Release) under it, wakeups follow the unlock (`IoRing.cq_wait`, GETEVENTS sleepers, which check the tail after queueing themselves, and the poll queue). `IoRing.poll_files` (sleeping `sync::Mutex`, Linux polls under uring_lock; IOPOLL rings: the files with polled requests issued; thread context) is held while GETEVENTS and the exit/exec polls poll them (-> the disk's poll queues and the bio ends they run: `Tctx.reqs`, `TaskWorks.q`, wakeups); emptied once nothing is in flight, the files released after it. `IoRing.overflowed` (atomic) is set and cleared under `cq` and read lock-free by poll and GETEVENTS; `IoRing.dropped` (atomic, a CQE was lost) is set under `cq` and cleared by the io_uring_enter that returns EBADR. The overflow list holds at most `cq_entries` CQEs (Linux charges them to the memory cgroup). The ring memory (`mm::shared::SharedRegion`) is written by user space at any time: the kernel only uses atomics and volatile copies on it |
| `Mm.ioctx` (`IoctxTable.slots`); `AIO_NR` | io/aio/mod.rs | spin Mutex leaves, thread context | `Mm.ioctx`: an address space's AIO contexts by id (Linux mm->ioctx_table under ioctx_lock): io_setup adds (the table grows by a buffer allocated before the lock, `kmem::spare`/`adopt`), io_destroy and exit_aio remove, every AIO syscall looks a context up under it, cloning its `Arc`; mremap of a ring, under the mmap_lock for writing, finds its context in it and moves the context id (atomics); nothing is taken under it. `AIO_NR` (Linux aio_nr_lock): the events every context asked for, against aio-max-nr (an atomic, read lock-free) |
| `Kioctx.ring_lock` (sleeping) → mmap_lock; `Kioctx.comp`, `Kioctx.reap`; `PollIocb.reg` (sleeping) → `Kioctx.active` → file wait queue head → `PollIocb.st` → `Workqueue.inner` | io/aio/ctx.rs, io/aio/poll.rs | `ring_lock`, `reg` sleeping `sync::Mutex`; `comp`, `reap`, `active`, `st` IrqSpinlock | An AIO context (Linux struct kioctx). `ring_lock` (Linux ring_lock): one io_getevents copies events to user space (it may fault: -> mmap_lock) and moves the ring's head. `comp` (Linux completion_lock): the kernel's tail and the count of posted events whose slots are not free yet; a request's end writes its event into the shared ring and publishes the tail (Release) under it, in any context (a bio's end_io in hardirq), then signals its eventfd (`Eventfd.inner`) and wakes io_getevents sleepers (`Kioctx.wait`, keyed by the events in the ring) after the unlock; a leaf. `Kioctx.avail` (atomic, Linux reqs_available) counts free event slots, refilled under `comp` from the head user space stored. `reap`: requests whose event is posted, waiting for release in thread context (their pins are dirtied under page locks, their file dropped: Linux bio_dirty_work, delayed_fput), pushed in any context with a delayed work item on `SYSTEM_WQ` (queued from the interrupt handler: `Workqueue.inner`), drained by that work, io_submit, io_getevents and the context's end; a leaf. `active` (Linux ctx_lock): the cancellable requests (IOCB_CMD_POLL), taken by io_cancel, the end's cancel, and a poll's submission and work, which take their wait entry off the file's queue under it (-> the queue head). `PollIocb.reg` (a poll request's wait entry and the owners of its queue) is held by the submission across the file's poll (which may sleep) and its decision under `active`, and by the poll work around its own, so the work waits for a submission still registering. A poll's wakeup runs under the file's wait queue head and takes only `PollIocb.st` (its work's queued/again/cancelled flags), then queues its work (`Workqueue.inner`, the worker's wait queue head): head -> head nesting, as epoll's callback. `Kioctx.users` and `reqs` (atomics, Linux percpu_ref users and reqs) count the syscalls using a context and its requests alive; io_destroy and exit_aio set `dead` (SeqCst against a lookup's increment, and against the last put's read of `dead` after its decrement: store buffering, all four accesses SeqCst), wait for `users` to drain, cancel, then wait for `reqs` (`Kioctx.idle`), releasing reaped requests meanwhile |
| `TaskWorks.q` (per task) | task/task_work.rs | IrqSpinlock leaf | a task's queued callbacks (Linux task->task_works, here a lock and an intrusive list of embedded callback heads that never allocates): `task_work_add` from any context, hardirq included, links a head, drops the lock, then flags the task: `Twa::Resume` sets TIF_NOTIFY_RESUME (a file's release, run on the return to user mode), `Twa::Signal` sets TIF_NOTIFY_SIGNAL and wakes the task from an interruptible sleep (pi_lock, run-queue lock: after the lock; io_uring's `WorkHead`s, linked once). The task pops one at a time and runs it with nothing held, at the return to user mode, in io_uring and io-wq waits and in sleeps that run work and go on (`signal_pending_run_work`); `exit_task_work` (after exit dropped its files, fs context, namespaces and mm) closes the list: later adds fail, and a file goes to `fs::file`'s delayed list instead |
| `percpu_alloc::GROW` → `Ida` | util/percpu_alloc.rs | sleeping `sync::Mutex`; under NAMESPACE_SEM (a tree copy's mounts) or nothing | Linux pcpu_alloc_mutex: makes a page-sized chunk of counter slots on every CPU the first time one of its slots is handed out, publishing each pointer once (Release; readers Acquire, lock-free); chunks are never freed. Slot numbers come from an `Ida` (IrqSpinlock leaf), freed in any context; a slot is zeroed on every CPU when handed out |
| `DELAYED_MNTPUT` → (after) `Workqueue.inner` | fs/mntput.rs | IrqSpinlock leaf | Linux delayed_mntput_list / delayed_mntput_work: mounts whose last reference went in interrupt context, a kernel thread or an exited task, linked through their embedded callback head (no allocation), each holding its `Arc`; the first add queues the delayed work (one tick) after the lock is released. The work takes the whole list under the lock and tears each mount down with it dropped (taking NAMESPACE_SEM, MOUNT_LOCK, `s_mounts` and, for a last active superblock reference, s_umount and whatever the shutdown takes, with nothing else held); mounts those teardowns drop queue again |
| `DELAYED_FPUT` → (after) `Workqueue.inner`; `DELAYED_FPUT_RUN` (sleeping) | fs/file.rs | IrqSpinlock leaf; sleeping `sync::Mutex`, outermost | Linux delayed_fput_list / delayed_fput_work: files whose last reference went in interrupt context, a kernel thread or an exited task, linked through their embedded callback head (no allocation), each holding its `Arc`; the first add queues the delayed work (one tick) after the lock is released. The work (and `flush_delayed_fput`) takes the whole list under the lock and releases each file with it dropped, under `DELAYED_FPUT_RUN`, which a flush takes to wait out a drain under way (Linux flush_delayed_work); files those releases drop queue again |
| `Tctx.reqs` (per task) → `TaskWorks.q`; `IoWq` `Acct.q`, `IoWq.workers`, `Tctx.io_wq`, `IoRing.defer` | io/io_uring/tctx.rs, io/io_uring/iowq.rs, io/io_uring/mod.rs | `Tctx.reqs` IrqSpinlock; the others spin Mutex leaves, thread context | `Tctx.reqs`: a task's ended io_uring requests (Linux tctx->task_list), pushed by `AsyncIo::complete` in any context (a bio's end_io in hardirq); the push queues the task's callback under it, while the pushed request (which holds the task) is still the pusher's, so no task reference is dropped in an interrupt handler. The task pops them in its context and finishes them (CQE under `IoRing.cq`, pins released: page locks) with nothing held. `Acct.q`: one io-wq pool's queue (an intrusive list of boxed work: nothing allocates under it) and worker counts; `IoWq.workers`: the running workers, for cancel, an intrusive list (Linux wq->all_list) each worker links itself on, its node allocated when it was started (Linux create_io_worker); `Tctx.io_wq`: the task's io-wq and whether its cancel began (Linux tctx->in_cancel): exit and exec leave it in place while they cancel, so work queued meanwhile ends ECANCELED, and take it after; none is made again after exit (after exec, a new one); `IoRing.defer`: the requests a drain holds back, each boxed before the lock and linked through its own node (Linux io_defer_entry), popped under it and queued after. `Tctx.polled` (sleeping `sync::Mutex`, thread context: submit notes a ring, exit and exec's cancel walk it in place, polling each ring: -> `IoRing.poll_files`): the task's IOPOLL rings. Workers are io threads of the submitter's process, started (only by the owner, else through its task_work callback) and woken after the locks are released. `Tctx.inflight`, `IoRing.inflight` (atomics) count requests from their issue or queueing to their drop (in the submitter's context or a worker's); exit and exec wait for zero after cancelling the io-wq, polling IOPOLL rings and running their own ended requests meanwhile; the drop that takes `IoRing.inflight` to zero lets the held-back requests go |
| `Pid.wait_pidfd` | task/pid.rs, task/pidfd.rs | WaitQueue | pidfd pollers of the task the `Pid` names (Linux wait_pidfd); woken under TASKLIST's write lock (a wait queue head is a leaf under it) when the task becomes a zombie and is reported (`notify_pidfd` from `notify`, Linux do_notify_pidfd) or, an untraced thread, exits, and when it leaves the task list (`remove_task`, Linux __unhash_process). A poll reads the task's state under TASKLIST's read lock (`pidfd_exited`, Linux pidfd_poll under RCU): readable once it is a zombie and, a leader, no other thread of its group is listed; hung up once it is gone. Poll methods run with no spin lock held, so taking TASKLIST there is in order |
| `SigHand.signalfd_wq` | signal/mod.rs | WaitQueue (its own IrqSpinlock) | signalfd readers and pollers of the tasks sharing a handler table (Linux sighand->signalfd_wqh); woken by send_signal after the target's signal state is unlocked; readers take `Signalfd.inner` and the caller's signal state only in its condition, after the queue's lock is dropped |
| `Workqueue.inner` | task/workqueue.rs | IrqSpinlock | pending and delayed work lists (`SYSTEM_WQ`, `BDI_WORKQUEUE`, `KBLOCKD`), intrusive (Linux work_struct.entry): each item links to the next through its own `next`/`dnext`, a reference the list owns while queued, so queueing never allocates; a work item's state is plain fields under its own `IrqSpinlock` (pending/running bits, the links; a delayed item's `wake_tick`, nonzero exactly while it is on the delayed list, a `seq` that voids its promoted entry, and whether that entry is on the pending list). `queue_work` takes the item lock and drops it before this lock; linking and the delayed-work calls (queue, mod, cancel, promote) take one item lock at a time under it, so list membership and `wake_tick` change together (order: `Workqueue.inner` → item, a leaf; nobody waits for `inner` holding an item lock). An item is non-reentrant across workqueues (Linux find_worker_executing_work): a worker that pops one running elsewhere marks it to run again (WORK_RERUN, under the item lock) and the running worker runs it once more. Queueing and the delayed-work calls are allowed in any context, hardirq included (Linux queue_work: pool->lock with interrupts off): they allocate nothing, drop no last reference and wake the worker through its wait queue; work functions run in the worker only |
| `BdiWriteback.dwork` | mm/writeback.rs | IrqSpinlock (`DelayedWork`) | a disk's periodic writeback work, reaching its `BdiWriteback` through a `Weak` (no registry); a leaf, writeback runs with it released |
| `Task.cgroup`, `CgroupRoot.root_cgrp`, `Cgroup.tasks`, `Cgroup.{children, subsys}`, `CgroupSubsysState.private`, `CpuState.bw`, `IoState.devices` | cgroup/ | spin (RwLock; `Task.cgroup`, `CpuState.bw` (weight, quota, period together), `IoState.devices` (each device's io.max limits together: an `RbTree` whose node a new device's write reserves with the lock dropped, then looks up again, Linux blkg_conf_prep; a removed device's node is freed after it; io.max's read sizes its copy before taking it and retries if the tree grew) Mutex leaves; nothing allocates under them), but `Cgroup.{children, subsys}`: sleeping `sync::RwSem`, thread context. A cgroup's `tasks` is an intrusive list through `Task.cg_node` (Linux css_set->tasks, cg_list): joining allocates nothing, a task leaves it at exit (or, never exited, when freed), and cgroup.procs sizes its buffer before taking the lock. A cgroup's `parent` and `ancestors` are fixed at creation (Linux cgrp->ancestors[]) and the controllers are a static table (Linux cgroup_subsys[]): no lock | cgroup hierarchy and membership (`Task.cgroup`: the task's cgroup, a leaf reached through the task the caller holds: current, a fork child, or a `TaskRef` cloned out of TASKLIST; Linux task->cgroups); parent before child; never under TASKLIST. `CGROUP_MUTEX` (sleeping, Linux cgroup_mutex; section 2) serializes mkdir, rmdir, cgroup.procs/subtree_control/freeze writes and a CLONE_INTO_CGROUP fork from admission to post_fork, so rmdir's emptiness check and its `dead` mark cannot interleave with an attach. `Cgroup.children` and `Cgroup.subsys` (Linux kernfs_rwsem, and cgrp->subsys[] written under cgroup_mutex) are written only under `CGROUP_MUTEX`; their readers (cgroupfs lookup/readdir/reads, fork's `can_fork` and `ForkCg`, exit's `detach_task`, migration) never hold a spin lock: a migration reads both cgroups' controllers before taking `Task.cgroup` (Linux cgroup_mutex -> css_set_lock), which the held `CGROUP_MUTEX` and `CGROUP_THREADGROUP_RWSEM` keep valid; `is_empty` reads `children` before `tasks`. A cgroupfs inode's private data is fixed at creation and read without a lock (Linux kernfs_node->priv). `CGROUP_THREADGROUP_RWSEM` (sleeping, under `CGROUP_MUTEX`) keeps forks out while cgroup.procs moves a whole thread group. The pids counters are atomics charged add-then-check (Linux pids_try_charge): at fork, before the child exists, on the target cgroup (`cgroup::can_fork`, undone by `ForkCg` on failure); the root is never charged. memory.max is one atomic word (Linux page_counter max); a cgroup's frozen flag is written under `CGROUP_MUTEX`. |
| `IpcIds.inner`, `KernIpcPerm.lock`, `MsgQueue.q`, `SemArray.global`, `SemSlot.lock`, `SemUndoList.list_proc`, `MQ_ACCT`, `MqQueue.{messages, flags, notify}`; `MQ_REGISTRY` | ipc/ | spin; `MQ_REGISTRY` sleeping (`RwSem`) | SysV and POSIX IPC objects; `MQ_REGISTRY` (the POSIX queues by name, Linux the mqueue root's i_rwsem) is taken by mq_open and mq_unlink in thread context under no other lock, and a create charges and allocates the queue under it; `MQ_ACCT` (the POSIX queue count, Linux mq_lock over mq_queues_count) is a leaf, taken under `MQ_REGISTRY` by a create and by a queue's Drop (which may run under it at unlink); under it a create charges the queue's bytes against RLIMIT_MSGQUEUE to its creator's ucounts (an atomic, UCOUNT_RLIMIT_MSGQUEUE, 3.1.1 Per-user counts; the queue keeps the reference) and a Drop returns them, as Linux mqueue_get_inode and mqueue_evict_inode; nothing allocates under it; `MqQueue.messages` (a spin leaf, Linux info->lock) holds the message tree (Linux msg_tree: an `RbTree` by priority of per-priority intrusive FIFOs, with mq_curmsgs and qsize): a message is allocated before it is taken, and so is a spare tree node when the cache looks empty (`MqQueue.cache_empty`, an atomic hint read unlocked as Linux reads info->node_cache), stashed under it (Linux node_cache); a new priority finding no cached node allocates one there with GFP_ATOMIC named (Linux msg_insert's fallback; ENOMEM fails the send); a receive that empties a priority puts its node in the cache or frees it after the lock; `IpcIds.rwsem` (sleeping, section 2) -> `IpcIds.inner` -> the object's lock; `IpcIds.inner` holds the index and key trees (`RbTree`): an insert reserves both nodes under `IpcIds.rwsem` before taking it (Linux ipc_addid: idr_preload(GFP_KERNEL), then idr_alloc_cyclic(GFP_NOWAIT) under the lock), so nothing allocates under it, and a removal frees its nodes after it; the namespace totals (`used_sems`, `shm_tot`) grow only under `IpcIds.rwsem`, after the insert, and shrink lock-free at destroy; a removed, still attached shm segment's key (`KernIpcPerm.key`, an atomic) becomes IPC_PRIVATE under `IpcIds.inner` (Linux ipc_set_key_private). Semaphores use Linux sem_lock's two levels: a single-operation semop takes only that semaphore's `SemSlot.lock` (its value, sempid, otime, its single-operation waiter lists and every undo structure's adjustment of it, reached through the `SemLock` guard); multi-operation semops, semctl, exit and removal take `SemArray.global` (the array's waiter lists, `complex_count`, ctime, the undo structures of the array: `list_id`) in complex mode: `use_global_lock` (written under `global`, read lock-free) is set and every slot lock taken and dropped once, which waits out the single-operation holders; the fast path rechecks the flag with Acquire after its slot lock and falls back to `global` while it is set; it is cleared with Release after `USE_GLOBAL_LOCK_HYSTERESIS` global holds with no multi-operation waiter. Order `SemArray.global` -> `SemSlot.lock`. Waiters are on-stack `SemQueue`s on intrusive lists (Linux sem_queue on pending_alter/pending_const, per semaphore and per array; merge_queues/unmerge_queues splice them, nothing allocates): a waker unlinks one under the locks, puts its sleeper on a `WakeQ` (woken after the unlock) and then stores its status (Release) as its last touch, since the sleeper may return as soon as it reads it (Acquire, Linux q->status); a sleeper that gives up (timeout, signal, removal) takes the locks, rereads the status and otherwise unlinks itself before returning. A SEM_UNDO structure (`SemUndo`, Linux sem_undo: one array's adjustments, one per semaphore) is on its undo list (`SemUndoList.list_proc`, a spin leaf, Linux ulp->lock) and on its array's `list_id`; both links change together under both locks, order `SemArray.global` -> `SemUndoList.list_proc`: find_alloc_undo allocates it with no lock, then looks it up again under both before linking it; freeary and exit_sem unlink it under both (exit_sem reads its list alone, then takes the array's lock and looks the entry up again). A task's undo list is allocated before `TASKLIST` is taken and installed after a recheck (Linux get_undo_list). `MsgQueue.q` holds the queue's messages (an intrusive list of messages each allocated before it is taken, Linux load_msg before ipc_lock_object; a removed queue's are freed after it, freeque), counters, qbytes, times and last pids (Linux: the msq lock): msgsnd's limit and removal check, the enqueue and the sender's pid and time are one critical section, likewise msgrcv's dequeue, and IPC_STAT copies a snapshot under it; IPC_SET takes `KernIpcPerm.lock` (a leaf) under it. The namespace's message statistics are atomics changed under it |
| `KEYRING_LINK` (sleeping) → `Key.keyring_keys`; `USER_KEYRINGS`, `Key.payload` → `KEY_DATABASE` → `KEY_USERS`; `Task.keyrings` | keys/ | `Key.payload`, `Key.keyring_keys`: sleeping `sync::RwSem` (Linux key->sem); `USER_KEYRINGS`: sleeping `sync::Mutex` (Linux key_user_keyring_mutex); `KEY_DATABASE`, `KEY_USERS`: spin RwLock leaves; `Task.keyrings`: spin Mutex leaf | a task's thread/process/session keyrings (`Task.keyrings`, reached through the current task or a fork child: a missing keyring is created with it unlocked and installed if the slot is still empty, Linux keyring_alloc then commit_creds; a replaced or spare key is dropped after it), the per-user keyrings (created under `USER_KEYRINGS`), `KEY_USERS` (Linux key_user_tree: a `util::rbtree` whose node is allocated before the lock and dropped if another made the entry, Linux key_user_lookup), the key registry and keyrings. Links and keyring slots own keys (`Arc<Key>`); `KEY_DATABASE` (Linux key_serial_tree under key_serial_lock) is a `util::rbtree` of weak entries (lookups upgrade after releasing it); a key's node is allocated with the key before the lock (`alloc_key`), so nothing allocates under it, and only that key removes its entry (invalidate, or its `Drop`); invalidation's keyring walk takes it once per key visited. A key's `Drop` (its last reference) takes `KEY_DATABASE`, then `KEY_USERS` (the per-user quota, a leaf), so no `Arc<Key>` is dropped under either; `Key.keyring_keys` is a leaf: unlinked keys are dropped after it is released, and replaced slots after `Task.keyrings`. `KEYRING_LINK` (Linux keyring_serialise_link_lock) is held by a keyring's link from its cycle check to the link, taken with no spin lock held. `Key.payload` also plays key->sem: instantiate (only from uninstantiated), update, revoke and invalidate change `Key.state` under its write lock, so a revoked key is never revived (the state is read lock-free); and KEYCTL_CHOWN / KEYCTL_SETPERM decide (owner, group, CAP_SYS_ADMIN) and store `Key.uid`/`gid`/`perm` in one write hold, as Linux keyctl_chown_key / keyctl_setperm_key under key->sem; those atomics are read lock-free by the permission checks and describe (Linux reads key->uid unlocked) |
| `FileLockCtx.flc_lock` (per inode), `locks::BLOCKED` | fs/locks.rs | spin Mutex | an inode's flock and POSIX locks (Linux i_flctx flc_lock; a POSIX owner is a descriptor table's id; nothing allocates for a POSIX change under it: room for the two locks one change can add is reserved before it is taken, Linux posix_lock_inode's new_fl/new_fl2, and splits, inserts and merges are done in place; a flock change likewise reserves room for one more shared holder, Linux flock_lock_inode's new_fl),  leaf but for BLOCKED (flc_lock -> BLOCKED, Linux blocked_lock_lock: each waiting POSIX owner and the owner it waits on, for EDEADLK). A blocked locker sleeps on the inode's wait queue with neither held, interruptibly, until the change count moves; `locks::BLOCKED` (Linux blocked_hash) is an rbtree whose node the waiter allocates before taking it and frees after it |
| `cmdline::SAVED` | cmdline.rs | `spin::Once` | the saved kernel command line (Linux saved_command_line): set once while parsing, before SMP; read lock-free (init's arguments, /proc/cmdline) |
| `FILE_SYSTEMS`, `SB_LOCK` | fs/superblock.rs | spin RwLock, spin Mutex | the registered filesystem types (Linux file_systems_lock) and the superblock lists (Linux sb_lock); 3.3 Superblock lists |
| `SuperBlock.s_inodes` | fs/inode.rs, fs/superblock.rs | spin Mutex (per superblock) | the superblock's inodes (Linux s_inodes under s_inode_list_lock); 3.3 Superblock inode lists |
| `INODE_HASH_LOCK` | fs/icache.rs | spin Mutex | the inode cache's buckets (Linux inode_hash_lock); 3.3 Inode cache: under it `Inode.private` -> `VfatInode.d` (vfat's `test`) |
| `CHARDEV_REGISTRY` | fs/chardev.rs | sleeping `sync::RwSem` (Linux chrdevs_lock, cdev_map->lock: mutexes) | character device registry: registered at probe, looked up at open and mmap (under mmap_lock); never under a spin lock |
| `File.f_lock` | fs/file.rs | spin Mutex | file status flags (Linux f_lock); a leaf but for `FASYNC_LOCK` under it (O_ASYNC is set or cleared only with the file's fasync entry, Linux fasync_insert_entry). `File.f_iocb` (the flags' I/O part, Linux f_iocb_flags: O_APPEND, O_DIRECT, O_DSYNC, __O_SYNC) is an atomic written only under it with the flags (F_SETFL), read lock-free by each read and write: an I/O racing an F_SETFL sees the old or the new word, as Linux's unlocked read of f_iocb_flags. `File.f_wb_err` / `f_sb_err` (Linux f_wb_err, f_sb_err: the writeback errors of the file's mapping and filesystem it has seen) are atomics sampled at open and advanced only under it (`errseq` check-and-advance, Linux file_check_and_advance_wb_err), read lock-free first. `AddressSpace.wb_err`, `SuperBlock.s_wb_err` (`util::errseq::ErrSeq`, Linux errseq_t) are lock-free words set by a failed writeback and a stale page cache after a direct write |
| `File.f_lock` → `FASYNC_LOCK` → `Fasync.fa`; `Fasync.fa` → `FOwner.st` → TASKLIST | io/fasync.rs | `FASYNC_LOCK`: spin Mutex, thread context; `fa`, `FOwner.st`: `IrqRwLock` | SIGIO (Linux fasync_lock, fasync_struct's fa_lock, fown->lock, RCU readers): a `FasyncList` (a pipe's readers and writers, a socket's, a tty's, an inotify group's) is an `RcuList` of `Fasync` entries, each a file's `FOwner` reference and armed fd in `fa`. `fasync_helper` (from `->fasync`; a pipe's under `Pipe.inner`, Linux pipe_fasync) allocates the entry first, then under `File.f_lock` and `FASYNC_LOCK` finds the owner's entry (a new fd under its `fa` write) or links the new one, and sets O_ASYNC with it; a removal clears `fa` (Linux fa_file = NULL), unlinks the entry and frees it a grace period later (`RcuUnlinked::defer`), the owner reference dropped after the locks. `kill_fasync` walks under RCU with `with_gfp(ATOMIC)`, any context but hardirq, any spin locks held: per entry `fa` read, then the owner's `st` read held across `send_sigio` (the owner's pid borrowed, no reference); the owner's thread, process or process group is found and sent to under one TASKLIST read hold, a group walked and each process sent to in place (Linux send_sigio: do_each_pid_task under tasklist_lock), nothing allocated but each signal's queue entry (GFP_ATOMIC, 3.7 rule 5). `FasyncList.armed` (atomic, written under `FASYNC_LOCK`, read lock-free: Linux kill_fasync's unlocked list test) lets a wakeup with no armed file skip the walk. A file's last close takes it off its lists (`->fasync(-1, off)`) before `->release` |
| `SuperBlock.{root, private}`, `DentryCache.root` | fs/superblock.rs, fs/dentry.rs | spin RwLock | superblock root and private data, the dcache root |
| `RamfsInodeData.xattrs` | fs/ramfs/mod.rs | spin | tmpfs xattrs (under VFS locks); nothing allocates under it: the name and value are copied before it is taken (Linux simple_xattr_alloc), the list grows with it released (`kmem::spare`), and a replaced or removed attribute is freed after. Only tmpfs has them (ramfs: EOPNOTSUPP, as Linux). Their space is the inode space under `tmpfs::Acct.stat` (Linux free_ispace under stat_lock), never nested with this lock: a set takes its space before the lock (ENOSPC) and returns what it did not use after; the inode's share (`RamfsInodeData.xattr_bytes`) goes back when it is freed |
| tmpfs accounting (`tmpfs::Acct`: `stat`, `max_blocks`, `used_blocks`) | fs/ramfs/tmpfs.rs | `stat` IrqSpinlock leaf; `used_blocks` a `PercpuCounter` | as Linux shmem_sb_info: `stat` (Linux stat_lock) holds the inode limit, the inode space (Linux free_ispace: each inode, extra hard link and user.* xattr takes from it; returned at unlink of an extra link, at `evict_inode` in any context, and when the xattr goes) and the inode64/noswap options; `max_blocks` (an atomic written under `stat`, read without it as Linux does) is the block limit; file pages are charged to `used_blocks` as they enter the cache (`filemap::add`, under the page lock, before `i_pages`) by a limited add that is exact near the limit, and returned as they leave (`remove`, eviction). A remount (under `s_umount` held for writing) checks every new limit against the use and changes them all under `stat`, or nothing. Uncounted while unlimited; an unlimited mount cannot be limited again (Linux "Cannot retroactively limit size") |
| `PercpuCounter.lock` | util/percpu_counter.rs | IrqSpinlock leaf | a per-CPU counter's folded count (Linux percpu_counter.lock): parts (atomics, one cache line each) fold into it at the batch size; an exact sum or a limited add near its limit takes it; the folded count is read without it for estimates. A caller's choice of its CPU's part, the read, the check and the add run with interrupts off (Linux local_irq_save), so nothing on that CPU slips an add in between and a part never passes the batch (the bound a limited add's fast path relies on) |
| membarrier `GLOBAL_MUTEX` → `IPI_MUTEX` | task/membarrier.rs | sleeping (`sync::Mutex`; `IPI_MUTEX` is Linux membarrier_ipi_mutex) | `IPI_MUTEX` serializes the membarrier commands that interrupt other CPUs, so callers cannot multiply the IPIs; held only across `smp_call_function_many` (waited); nothing is taken under it. `GLOBAL_MUTEX` (killable) paces MEMBARRIER_CMD_GLOBAL to one call per tick: held across its IPIs and its one-tick sleep, so GLOBAL callers never delay the expedited ones. The targets are chosen from each CPU's `PerCpuScheduler.curr_mm` / `membarrier_state` (atomics written at every switch in `make_current`: `curr_mm` SeqCst, then a full fence, then the registrations read, so a registration either sees the CPU in its mm and refreshes it by IPI or is seen by the switch; Linux rq->curr->mm and rq->membarrier_state), compared, never dereferenced |
| `Inode.i_pipe` | fs/inode.rs, io/pipe.rs (FIFOs, pipefs) | spin Mutex (Linux inode->i_lock around i_pipe) | a FIFO's or pipefs inode's pipe and its open-file count: attached by the first open (pipe(2): at creation, with both ends counted; a FIFO's pipe is allocated with the lock dropped and installed if the slot is still empty, Linux fifo_open, the losing one freed after the unlock), dropped by the last release (a pipe end's release as a FIFO's); only the slot and its file count (Linux pipe->files) change under it: an open counts its file under it, then changes the pipe's counts under `Pipe.inner` with it dropped; a release changes the counts under `Pipe.inner`, then drops its file under this (Linux fifo_open, pipe_release, put_pipe_info). Never held across a wait or with `Pipe.inner` |
| `Pipe.inner` | io/pipe.rs | sleeping (`sync::Mutex`, Linux pipe->mutex) | the pipe's buffer ring; held across page allocation and across read/write's copy to or from the caller's memory (may fault: -> mmap_lock, as Linux pipe->mutex), never under a spin lock; two pipes (splice, tee) in address order (Linux pipe_double_lock); -> frame allocator; -> `FASYNC_LOCK` (pipe_fasync changes both lists under it, Linux too); -> the output file's write path (i_rwsem, page cache, socket locks) for a pipe-to-file splice, which consumes only what the write took (Linux iter_file_splice_write under pipe_lock); -> the input file's read path for a file-to-pipe splice, which reads only once the pipe has room (Linux splice_file_to_pipe: wait_for_space, then do_splice_read under pipe_lock). A splice, tee or vmsplice waits for data or room with it dropped (`lock_data`, `lock_room`; Linux pipe_wait_readable/writable) and decides EOF, EPIPE or progress under it. Read and write send SIGIO after dropping it, as Linux pipe_read / pipe_write; a pipe-to-file splice wakes the writers under it (Linux splice_from_pipe_end), publishing the ring indices first (`PipeGuard::publish`). `Pipe.head_tail` (one word, Linux pipe->head_tail) is stored under it as the guard unlocks (and before a wakeup made under it), `max_usage` where F_SETPIPE_SZ changes it, and both are read locklessly by wait conditions and poll (poll runs under `Eventpoll.inner`, an IrqSpinlock) with one load each; other wakeups follow the unlock, as Linux's. The reader/writer counts and a FIFO's open counters change under it (a pipe end's dup and release, fifo_open, pipe_release: a FIFO release's SIGIO to both sides when that left readers or writers but not both is sent under it, -> `kill_fasync`), so a blocking FIFO open decides, and samples the counter it waits on, before unlocking, and a write decides EPIPE under it (Linux pipe_write, wait_for_space). A read decides EOF (no writers) under it, after seeing the ring empty (Linux pipe_read under pipe->mutex): a writer's last write unlocks before its release drops the count, so its data is never read as EOF |
| `VgaCon.state` | arch/x86_64/vgacon.rs | IrqSpinlock | VGA text console state, under `CONSOLE_REGISTRY` (3.9) |
| `SimpleGfxDevice.state` | hw/gfx/ | sleeping `sync::Mutex` (Linux DRM modeset locks) | framebuffer device state, DRM ioctls only |
| `GFX_DEVICES`, `NEXT_MINOR` | gfx/ | spin | framebuffer device registry |
| `UsbMscDevice.state` | hw/usb/msc.rs | sleeping `sync::Mutex` (Linux us->dev_mutex), thread only | a mass-storage interface's CBW tag, disconnected flag and learnt CSW signature and residue quirk, held across each BOT transaction (CBW, data, CSW: synchronous bulk requests, sleeping on their URBs' completions, under it) and its recovery (clear-halt control requests, each an xHCI endpoint reset waiting on Stop and Configure Endpoint commands; a Bulk-Only reset's up to 6 s wait on `UsbMscDevice.dying`, Linux delay_wait). The transaction runs under PF_MEMALLOC_NOIO (Linux GFP_NOIO), so reclaim from inside it never writes back through the device. Its unbind completes `dying` before taking the lock (ending a reset's wait, Linux US_FLIDX_DISCONNECTING), then sets the flag under it, after the disk is gone and the command in progress is done |
| `INTX_MAP` | arch/aarch64/pci_irq.rs | spin Mutex | PCI INTx routing from the device tree (boot) |
| `PCI_LOCK` | arch/x86_64/pci_conf.rs (port I/O config access) | IrqSpinlock | Linux pci_lock: the CF8 address write and the CFC data access of one config read/write; leaf (port I/O only). ECAM accesses are single MMIO operations and take no lock |
| PCI fixups (`hw/pci/quirks.rs`) | none | thread only (boot) | run by bus enumeration (single-threaded) on each function before driver probe |
| `CMDLINE_CONSOLE` | cmdline.rs | spin Mutex | console= choice |
| `CPU_CRNG` (per CPU) -> `BASE` | random.rs | IrqSpinlock | ChaCha20 CRNG: this CPU's key, then the base key when the CPU key is refreshed or the base reseeded; both leaves otherwise (callers include softirq net code). `GENERATION`/`BIRTH_NS` are atomics read unlocked, rechecked under `BASE` |
| `Inode.i_flags` | fs/inode.rs | atomic word (fetch_or / fetch_and: bits of different writers share it, Linux inode_set_flags' cmpxchg) | S_DEAD (set by rmdir or a replacing rename under the directory's `i_rwsem`), S_SWAPFILE (set and cleared by swapon/swapoff), I_LINKABLE (an O_TMPFILE file not opened O_EXCL may get its first name, Linux i_state under i_lock: set before the file is reachable, tested and cleared by linkat under the inode's `i_rwsem`, `link_locked`); read lock-free |
| `Inode.i_writecount`, `Inode.i_flags` S_SWAPFILE | fs/inode.rs | atomics | writers (> 0) or executions denying them (< 0), Linux i_writecount, changed by CAS (`get_write_access` / `deny_write` through a file's `DenyWrite`, ETXTBSY on the wrong sign); an active swap area (S_SWAPFILE: tested, set and cleared by swapon/swapoff
under its i_rwsem, i_rwsem -> `SWAP_INFO`, and checked under it by
writes and truncates). The address space holds the executable's denial (`MmStruct.exe_deny`, cloned at fork) |
| `BdiWriteback.pass` | mm/writeback.rs, fs/pageio/fs_writeback.rs | sleeping `sync::Mutex` | serializes writeback passes over one disk's lists (`wb_writeback`: sync and syncfs (under the superblock's s_umount read, Linux iterate_supers / syncfs's down_read), a superblock's shutdown and vfat's remount (under its s_umount write), the periodic writeback; Linux runs them one at a time from the wb's work list), held across their I/O: pass -> page lock -> i_mmap -> PTE lock, and `list_lock` taken and released under it per step; an inode's metadata is written under it after its pages (`__writeback_single_inode` -> ->write_inode: pass -> the device's page cache (vfat's entry block, bread) -> vfat `VfatSbData.ipos` (spin); a sync(2)/syncfs pass is for_sync, so no ->sync_inode_metadata under it), a data-integrity pass sleeps under it on an inode another writer has (I_SYNC: that writer takes no `pass`), and an inode's last reference may go under it (eviction, which may write that inode back first). fsync and the write-back before an eviction write an inode without it (`writeback_single_inode`), under I_SYNC |
| `BdiWriteback.list_lock` | mm/writeback.rs, fs/pageio/fs_writeback.rs | spin Mutex, a leaf but for an inode's `i_lock` (Linux wb->list_lock -> i_lock) | Linux wb->list_lock: the disk's dirty inodes, `b_dirty` (oldest first), `b_io` (the running pass's) and `b_more_io` (left for the next pass), `InodeList`s through `Inode.i_io_list` holding no reference (Linux), `Inode.i_io_on` (which list it is on) and `Inode.dirtied_when` (Linux dirtied_when: written under it and the inode's `i_lock` as it is queued or requeued, read under it by a pass's expiry test). An inode's dirty state is its `i_state` bits (Linux I_DIRTY_SYNC, I_DIRTY_DATASYNC, I_DIRTY_PAGES; I_SYNC, I_SYNC_QUEUED; I_METADATA_WRITEBACK, set by ->write_inode and cleared by a WB_SYNC_ALL write, not for sync, before it calls ->sync_inode_metadata with no lock held), written under `i_lock` only. `__mark_inode_dirty` (every page dirtying through the mapping's `host`, `filemap::dirty_page`, Linux __folio_mark_dirty; the filesystems' metadata) tests the bits lock-free after a full fence (Linux smp_mb, paired with the one `__writeback_single_inode` puts between clearing them and testing the cache's DIRTY mark: either side sees the other), sets them under `i_lock` and, for an inode going from clean to dirty, drops `i_lock`, takes `list_lock` then `i_lock` (Linux locked_inode_to_wb_and_lock_list) and queues it at `b_dirty`'s tail unless a pass has it (I_SYNC_QUEUED) or it is I_FREEING, then arms the periodic work after unlocking if the lists were empty; under a page lock at most. A pass moves the expired inodes (of one superblock for a sync) to `b_io` in one hold, marking each I_SYNC_QUEUED under its `i_lock` (Linux queue_io), then superblock by superblock: a pass for one superblock runs under its caller's s_umount; the periodic pass takes the front inode's superblock's s_umount for reading with trylock under `list_lock` (Linux __writeback_inodes_wb: super_trylock_shared, failing too for one not born or dying) and sends that inode back to `b_dirty` if it fails, else writes that superblock's inodes until another's comes first and releases it; per inode, under `list_lock` and its `i_lock`: one of another superblock (in a pass for one) or being freed back to `b_dirty` (Linux redirty_tail_locked; I_FREEING off the lists), one another writer has (I_SYNC) to `b_more_io` or, for a data-integrity pass, slept on with `i_lock` only (the eviction, which takes the inode off `b_io` under `list_lock` then `i_lock`, waits for it, so the inode stays live); else it sets I_SYNC and takes a reference (`Inode::__iget`: not I_FREEING/I_WILL_FREE under `i_lock`, so the count is above zero), unlocks, writes it, then under both locks requeues it by its state (Linux requeue_inode) and clears I_SYNC, waking its waiters under `i_lock` (Linux inode_sync_complete), and drops it with no lock held (its last reference may evict it). `writeback_single_inode` (fsync, sync_inode_metadata, the write-back before an eviction) sets I_SYNC under `i_lock` (waiting for a writer already at it, for WB_SYNC_ALL), writes, then under both locks takes a clean inode off the lists or puts a dirty one back on `b_dirty` unless a pass has it. An inode's eviction takes it off its list under the lock and its `i_lock` (`inode_io_list_del`, Linux evict), before any field goes, so a linked entry is a live value. The mapping's `host` is the inode whose `i_data` it is (Linux mapping->host, a plain pointer): page dirtying borrows it with no reference under the page's lock (Linux __folio_mark_dirty; eviction truncates every page under its lock before the inode goes, and the I_FREEING test keeps one being freed off the lists); a buffer's dirtying outside the page lock grabs it (`Inode::igrab`, failing once its last reference went) |
| `LAST_INO` (per CPU) | fs/anon_inodes.rs | IrqSpinlock leaf | this CPU's batch of pseudo-filesystem inode numbers (Linux get_next_ino, preempt-off per-CPU counter); refilled from the atomic `SHARED_LAST_INO` under it |
| `NUMA_TOPOLOGY` | mm/numa.rs | IrqSpinlock leaf | NUMA node table: written by the boot parsers and by each CPU at bring-up (`numa::cpu_up`, end of arch per-CPU init), read by getcpu, the mempolicy syscalls (mbind copies the node spans before taking mmap_lock; get_mempolicy's page node with no lock held) and futex_waitv (FUTEX2_NUMA node checks, after `futex_mpol` drops mmap_lock) |
| `BpfHashMap.data`, `BpfArrayMap.data` | bpf/map.rs | IrqSpinlock | BPF map contents; nothing allocates under them: hash elements are preallocated at create on a free list (Linux htab prealloc), lookups and get_next_key copy into a buffer the caller allocated before the lock (Linux bpf_map_copy_value) |

---

## 4. Deadlock Prevention

The kernel employs several strategies to prevent deadlocks:

### 4.1 IRQ Disable During IrqSpinlock Hold

The `IrqSpinlock` disables interrupts while held, preventing:
- Timer interrupt deadlock (interrupt tries to acquire lock already held)
- Same-CPU deadlock scenarios

### 4.2 Preemption Disable During IrqSpinlock Hold

The `IrqSpinlock` increments `preempt_count` while held, preventing:
- Context switch while holding the lock
- Preemption-related deadlocks

### 4.3 Hierarchical Lock Ordering

All code follows the global lock ordering defined in Section 2. This prevents
circular wait conditions.

### 4.4 Per-CPU Data Structures

Per-CPU variables (`percpu!`, `cpu::PerCpu`, Linux DEFINE_PER_CPU) live
in per-CPU areas: the `.data..percpu` template is the pristine image,
each possible CPU's area a copy of it (the boot CPU's in .bss, made
first thing at boot; the others' by `cpu::setup_areas` as soon as the
firmware's CPU list is parsed, before anything sizes per-CPU data by
the possible count: its enabled CPUs, plus the boot CPU if it is not
listed), reached at `per_cpu_offset(cpu)` from the template (Linux
per_cpu_ptr). One CPU's variables sit together, so two CPUs never share
a cache line through them. The offsets are set once before the CPUs
that read them exist (Release on the possible count). State that names
its CPU is set in a new area before it is published (`cpu::prepare_cpu`,
Linux's CPU prepare states: `HrBase.cpu`); nothing derives a CPU from a
copy's address.

The scheduler uses per-CPU run queues: a CPU's own scheduling takes only
its own lock; a wakeup takes the target's (3.1).

### 4.5 Lock-Free Reads (Seqlock)

The timekeeper uses seqlocks so readers never block writers, and writers
never block readers. Readers simply retry if they detect a concurrent write.

### 4.6 Short Critical Sections

Locks are held for the minimum time necessary. Nothing that sleeps (I/O,
sleeping locks, user copies that may fault) runs under any spinlock.
Allocations under an IrqSpinlock are allowed in thread context (the heap
and frame allocator locks are IrqSpinlocks themselves), never in
interrupt context (7.2).

### 4.7 No Non-IRQ-Safe Locks in Interrupt Context

**CRITICAL:** The kernel ensures that `Mutex` and `RwLock` (which don't disable
interrupts) are NEVER acquired from interrupt handlers. This prevents the
classic deadlock scenario:

```
Thread context:     Mutex.lock() → interrupted while holding
Timer ISR:          tries Mutex.lock() → spins forever → DEADLOCK
```

---

## 5. Lock-Free Patterns

Several kernel subsystems use lock-free programming for performance:

### 5.1 Atomic Counters

Used for reference counting, tick counts, and other simple counters:

```rust
// Reference count increment
refcount.fetch_add(1, Ordering::Relaxed);

// Tick count
TICK_COUNT.fetch_add(1, Ordering::Relaxed);
```

The preempt count and interrupt depth are this CPU's alone: one
unlocked `add gs:[field]` on x86 (Linux raw_cpu_add_4 on
`__preempt_count`), a plain load and store on arm64 (Linux
`__preempt_count_add`), with a compiler barrier on the inside of the
section. No lock prefix is needed: only the CPU writes them, and an
interrupt that changes them restores them before returning.

### 5.2 File Position

`File.pos` is an atomic only so it can be read and written from shared
references: `advance_pos` and `set_pos` are a plain load and store
(Linux `f_pos`), made under `f_pos_lock` for regular files and
directories (`pos_lock`, Linux FMODE_ATOMIC_POS) and racy for the rest,
as Linux's.

### 5.3 Seqlock for Time

As described in Section 3.5, time reads are lock-free using the seqlock pattern.

### 5.4 Atomic Types vs Struct-Level Locks

When designing data structures, choose between atomics and locks carefully:

#### When to Use Atomics

1. **Reference counting** - Single counter, increment/decrement operations
2. **Independent flags** - Bool/state that doesn't need to update with other fields
3. **Statistics counters** - Counters where slight inconsistency is acceptable
4. **Seqlock sequences** - Sequence number for seqlock readers
5. **Lock-free algorithms** - Data structures designed for lock-free access

#### When to Use Struct-Level Locks

1. **Related fields that must update together** - Use Mutex/RwLock
2. **Invariants across multiple fields** - Lock ensures invariant holds
3. **Complex state transitions** - Lock serializes state machine

#### Common Mistake to Avoid

Using multiple atomics in a struct and updating them separately does NOT provide
multi-field atomicity. If fields A and B must be consistent:

**Wrong:**
```rust
struct Foo {
    a: AtomicU32,
    b: AtomicU32,
}
// Two separate stores - can be seen inconsistently
foo.a.store(1, Ordering::Release);
foo.b.store(2, Ordering::Release);
```

**Right:**
```rust
struct Foo {
    inner: Mutex<FooInner>,
}
struct FooInner {
    a: u32,
    b: u32,
}
// Single lock - guaranteed consistent
let mut guard = foo.inner.lock();
guard.a = 1;
guard.b = 2;
```

#### Rules (phase L)

1. **Lock first, atomics second.** An object with a lock keeps its fields
   as plain data inside that lock. An atomic is justified only by a named
   lockless reader (cite it in a comment, as Linux's READ_ONCE comments
   do); writers still take the lock.
2. **No check-then-act on atomics.** A `load` followed by a `store` or
   `fetch_*` on a decision path is one RMW (`fetch_update`/CAS). Limits use
   Linux's add-then-rollback (`page_counter_try_charge`,
   `pids_try_charge`). Anything spanning two fields needs a lock.
3. **No `Mutex<()>` guarding sibling atomics.** The protected state goes
   inside the Mutex.
4. **Publication is Release/Acquire.** A value whose observation implies
   other data is visible (i_size, ready flags, pointers) is
   Release/Acquire. Relaxed is for counters and statistics, with a
   comment.
5. **Set-once is `Once`, a constructor argument or a boot initcall**, not a
   lazy flag on a hot path. Boot globals written only before SMP may stay
   Relaxed atomics, documented as `__ro_after_init` equivalents.
6. **Recursion and ownership guards are per holder** (owner CPU/task in the
   lock, or `try_lock`), never a global bool.
7. **Every shared atomic is documented here**: writer context and lock,
   reader context, ordering, Linux equivalent.
8. **IDs exposed to user space use an IDA when Linux does** (device
   indexes), not a monotonic counter.
9. **Counters hit on every packet or op on every CPU are per-CPU with
   batching.**
10. **An atomic read-modify-write needs two concurrent writers.** State
    one CPU or one task writes is a Relaxed load and store (a lock's
    own fields, the owner's counters); a per-CPU word only its CPU
    writes is `cpu::LocalWord::local_add` (Linux this_cpu_add: no lock
    prefix on x86), the preempt count an unlocked per-CPU add (5.1).
11. **Per-CPU data lives in the per-CPU areas** (`percpu!`, 4.4): never
    an inline `[T; NR_CPUS]`, whose neighbouring CPUs share cache
    lines.
12. **No published copies.** A lockless reader reads the real field,
    stored once where it changes (Linux READ_ONCE of the field), not a
    second set of atomics refreshed from locked state.

#### hk Pattern Examples

Correct uses of atomics in hk:

| Subsystem | Atomic Fields | Why Correct |
|-----------|---------------|-------------|
| `TimeKeeper` | seq, cycle_base, mono_base_ns, etc. | Seqlock pattern - all read together with seq validation |
| `File` | pos | Under `f_pos_lock` for writers; atomic for lockless readers |
| `Inode` | mode, uid, gid | Written under i_rwsem (chmod, chown, set-id kill on write/truncate); read lock-free |
| `Inode` | size | Linux i_size_write/read: Release under i_rwsem, Acquire lock-free, so the bytes below it are visible first |
| `Sock` | flags, error, buffer sizes | Independent values; protocol data under the socket lock |
| `Sock` | shutdown | Written under the protocol socket lock (TCP `lock`: owner or slock, unix `st`); read lock-free by poll |
| TCP `TcpSock.snap` | state, queue bytes, writable, snd_una/snd_max | Linux READ_ONCE of sk_state and the queue edges: stored (Release) at the end of every locked step by the one context holding the socket, read (Acquire) by poll, the waits and tcp_v4_err; the owner re-checks under the lock |
| TCP `TcpSock.live` (`cb::Live`) | timers, RTO and backoff, probes, delayed ACK mode, cwnd/ssthresh, MSS, fastopen | Linux WRITE_ONCE/READ_ONCE of the icsk/tcp_sock fields get_tcp4_sock reads: the control block's own fields (no published copy, rule 12), `SoleCell`s stored where they change by the one context holding the socket, read lock-free by /proc/net/tcp. Relaxed: each field independent |
| `NetMib` (per-CPU words) | SNMP / TcpExt counters | Linux SNMP_INC_STATS (this_cpu_inc): each counter is independent, one relaxed RMW on this CPU's word; readers sum all words with no ordering against other counters. Relaxed |
| TCP `mem::FW_ALLOC` (per-CPU) | quanta not yet in `ALLOCATED` | Linux tcp_memory_per_cpu_fw_alloc (rule 9): every charge and uncharge, under the connection's socket lock, is an RMW on this CPU's slot (correct after a migration, as this_cpu ops); past ±`PCPU_RSV` the slot is swapped to 0 and added to `ALLOCATED`. Relaxed: a count |
| TCP `mem::ALLOCATED` | quanta all connections hold, less the CPUs' reserves | Linux tcp_memory_allocated: read lock-free by every charge to check the limits (add-then-check: the charge is added before the check, subtracted on failure); lags by up to the reserve per CPU, as Linux. Relaxed |
| TCP `mem::LIMITS[3]`, `mem::PCPU_RSV` | tcp_mem, net.core.mem_pcpu_rsv | sysctl words (initial netns only), each independent, read lock-free per charge (Linux sysctl_tcp_mem, mem_pcpu_rsv with READ_ONCE). Relaxed |
| TCP `mem::PRESSURE` | memory pressure mode: when it began (ms), 0 when off | Linux tcp_memory_pressure: set past tcp_mem[1] (compare-exchange from 0: the one winner counts TCPMemoryPressures), cleared under tcp_mem[0] (swap: the one that ends it counts TCPMemoryPressuresChrono), by any charge. Relaxed |
| TCP `mem::ORPHANS` (per-CPU `AtomicIsize`) | orphaned TCP connections, every namespace's | Linux tcp_orphan_count: a `mem::Orphan` guard held in the socket's `Inner` increments this CPU's part when the connection is orphaned and decrements the part of the CPU it drops on (destroy, TIME_WAIT hand-over, or the socket's drop); /proc/net/sockstat sums the parts, clamped at 0. Relaxed |
| TCP `mem::SOCKETS` | live TCP control blocks | Linux tcp_sockets_allocated: incremented and decremented at control-block creation and drop, read for the fair-share test under pressure. Relaxed. Global, not per-CPU: socket churn, not per packet |
| `CachedPage` | refcount, dirty, writeback, locked | Linux page cache pattern - flags + refcount |
| `cpu::NR_CPU_IDS` | CPU count | Linux nr_cpu_ids: stored once (Release) by `smp::init` on the boot CPU, after the others are up but before they schedule; read Acquire |
| kthread `NEXT_CPU` | round-robin cursor | one `fetch_add` per pick, so racing creators get different CPUs; Relaxed (a hint, publishes nothing) |

---

## 6. Preemption Control

The kernel tracks preemption state per-CPU to know when context switches are safe.

### 6.1 preempt_count

Each CPU maintains a `preempt_count` in its per-CPU data:

```rust
pub preempt_count: AtomicU32,
```

**When preempt_count > 0:**
- Context switches are not allowed
- The scheduler will not preempt this CPU
- `IrqSpinlock` contributes to this count

### 6.2 Preemption Control API

**Location:** `arch/x86_64/percpu.rs`

```rust
/// Disable preemption (increment preempt_count)
pub fn preempt_disable();

/// Enable preemption (decrement preempt_count)
pub fn preempt_enable();

/// Get current preempt_count (debugging)
pub fn preempt_count() -> u32;
```

### 6.3 Automatic Preemption Tracking

Every spin lock manages preempt_count (Linux spin_lock): `IrqSpinlock`
and the `sync::spin` `Mutex`/`RwLock` wrappers alike.

```rust
// On lock():
percpu::preempt_disable();  // preempt_count++ (IrqSpinlock: after cli)

// On unlock/drop():
percpu::preempt_enable();   // preempt_count-- (after the release)
```

So `sync::in_atomic()` (preempt count nonzero, interrupts off, or an
interrupt handler running) is exact: such a context must not sleep
(`might_sleep` reports `MIGHT_SLEEP:FAIL`). A task switches out
holding only its run-queue lock (preempt count exactly 1; anything else
is `SCHED:FAIL scheduling while atomic`).

---

## 7. Interrupt Context Rules

### 7.1 What Can Run in Interrupt Context

- Timer tick updates (atomic only)
- Wake sleepers (IrqSpinlock only, per-CPU only)
- `WaitQueue::wake_one/wake_all` and `try_to_wake_up` (IrqSpinlocks
  only, no allocation: wakes run under the head lock; the priority
  lists and remote wake lists are intrusive)
- `hrtimer::interrupt()` (every CPU's clock event): runs the due HARD
  hrtimers (the tick among them), wakes `ktimers/N` for due SOFT ones,
  programs the next event (`HrBase.q` leaves only)
- `timer::run_local()` (every CPU's tick): runs the CPU's due HARD timer
  callbacks (they only wake tasks) and wakes `ktimers/N` when a SOFT one
  is due; SOFT callbacks run there, in process context (they may send
  signals, take Mutexes, allocate)
- `napi_schedule()` (NIC ISRs): `Softnet.poll_list` IrqSpinlock push
  (pre-reserved, no allocation) and a wake of `softnet/N` (allocation-free
  as above); a no-op while the NAPI is scheduled or disabled
- `Workqueue::queue_work` and the delayed-work calls (Linux queue_work
  from an interrupt handler): `Workqueue.inner` and the item's lock
  (IrqSpinlocks) and a wake of the worker; the worker promotes expired
  delayed work itself, sleeping with a timeout until the next deadline,
  and runs every work function in thread context
- Block completion (virtio-blk ISR: per queue on MSI-X, every queue on
  INTx): the blk-mq hardware queue lock
  (`IrqSpinlock`, leaf) to reap the virtqueue and restart dispatch, then
  `bio_endio` with no lock held; `end_io` completes a `Completion`
  (`IrqSpinlock` -> wait queue wakeup); the lock-free DMA API unmaps
- Buffer head completion (`fs/pageio/buffer.rs` bh_end_*): the buffer's bits,
  the ring's `b_uptodate_lock` (IrqSpinlock leaf), the page's flags,
  the buffer's and the page's wait queues, and on a write error, under
  an RCU read guard, the mapping's `wb_err` and its superblock's
  `s_wb_err` (atomic errseqs; the superblock reached through the
  inode's `Weak`, no reference taken: `superblock::sb_wb_err_set`)
- AIO completion (a bio's end of an AIO request): `Kioctx.comp`
  (IrqSpinlock) to post the event into the shared ring, then the
  request's eventfd (`Eventfd.inner`), the io_getevents wakeup and the
  push onto `Kioctx.reap` with its delayed work queued; the request's
  release (pins dirtied, file dropped) runs later in thread context
- Set reschedule flags (atomic)
- Read per-CPU data (via GS segment)

### 7.2 What CANNOT Run in Interrupt Context

- **Memory allocation** (the frame allocator and the heap are IRQ-safe,
  but IRQ paths must not depend on allocating)
- **TASKLIST access** (uses Mutex)
- **VFS operations** (use RwLock)
- **Sleeping on anything** (printk is safe: its locks are IrqSpinlocks, 3.6)
- **Any Mutex or RwLock acquisition**

### 7.3 Deferring Work

If interrupt context needs to trigger something that requires non-IRQ-safe locks:

1. Record the event (atomic, or an IrqSpinlock-protected queue)
2. Wake a kernel thread (`WaitQueue::wake_*` / `try_to_wake_up`, IRQ-safe)
3. The actual work is done in thread context (`ktimers/N`, workqueue
   workers, `softnet/N` threads for network receive)

Example: a CPU's tick notices an expired SOFT timer and wakes
`ktimers/N`, which runs the callback (posix timers send signals there). The
tick's TIF_NEED_RESCHED is only acted on when the task returns to user
mode (3.1).

### 7.4 Locks Never Acquired from Interrupt Context

The following locks are NEVER acquired from interrupt handlers (timer ISR,
exceptions, etc.). With the locks of 3.11 (all thread context only) and
every `spin::Mutex`/`RwLock` and sleeping lock elsewhere in this document,
this is the interrupt-safety invariant:

| Lock | Location | Type | Reason |
|------|----------|------|--------|
| `TASKLIST` | task/tasklist.rs | `RwLock` | every task (Linux tasklist_lock) |
| `SigHand.siglock` | signal/mod.rs | `Mutex` | Linux sighand->siglock: `Task.sighand` and thread list changes, a send, thread walks (after TASKLIST, before SignalStruct.jobctl; 3.7) |
| `Task.alloc_lock` | task/mod.rs | `Mutex` | A task's mm, files, fs, nsproxy, comm, mempolicy, io_context (Linux task_lock; under TASKLIST, over SigHand.siglock) |
| `FsStruct.seq` | fs/fsstruct.rs | `SeqLock` | Root, cwd, umask (leaf; Linux fs->seq): writers and reference-taking readers lock, RCU walks read root/pwd under its sequence |
| `MEMBLOCK` | mm/memblock.rs | `Mutex` | Boot memory map (boot CPU, before SMP) |
| `PidNamespace.bacct` | task/acct.rs | `Mutex` | A pid namespace's process accounting file (Linux pid_namespace->bacct; leaf, thread context: cloned out, the record written and an old file released with no lock held; an exit walks its namespace and each parent, one lock at a time; taken out at the namespace's zap, after its other tasks are gone) |
| All VFS locks | fs/*.rs | `RwLock` | Inodes, dentries, mounts |
| Descriptor tables (`Files`) | task/fdtable.rs | `Mutex` | Per-task fd tables |
| `RTNL` and every network `spin::Mutex`/`RwLock` | net/ | `sync::Mutex` / `Mutex` / `RwLock` | Configuration, sockets, tables, queues (3.10) |
| Driver queue locks (e1000 / virtio-net `rx`, `tx`) | hw/net/ | `Mutex` | Rings: NAPI poll, xmit, open/stop |
| `Softnet.backlog` | net/core/dev.rs | `Mutex` | `netif_rx` (lo), softnet |
| `MAJORS`, `RamDisk.pages` | block/ | sleeping `Mutex` / spin `Mutex` | Block majors, RAM disk pages (3.10) |
| `Disk.open_mutex` | block/blkdev.rs | sleeping `sync::Mutex` | Block device open/release, partition scans |
| Sleeping locks (`sync::Mutex`, `RwSem`) | sync/ | sleeping | Never in IRQ or atomic context (`might_sleep`) |

With `make check LOCKDEP=1` (1.5) every tracked spin lock taken in an
interrupt handler is reported (`LOCKDEP:FAIL ... in interrupt context`).

Note: `OUTPUT_LOCK`, `PRINTK`, and `CONSOLE_REGISTRY` are now `IrqSpinlock` and
CAN be safely acquired from interrupt context. See Section 3.6.

**Invariant**: Code running with interrupts enabled that acquires any of these
locks will never be interrupted by an ISR that also tries to acquire the same lock.

**Why this is safe**: ISRs in hk only perform the operations of 7.1:
atomics, and IrqSpinlocks (run queues and pi locks, wait queue heads,
`IrqDesc.lock`, the blk-mq hardware queue, `Completion.done`,
`Softnet.poll_list`, the cross-CPU call queues, printk)

ISRs NEVER perform:
- Memory allocation (`alloc`, `Box`, `Vec` growth): wakeups and run-queue
  enqueues are intrusive, NAPI scheduling uses reserved capacity (7.1)
- Task table operations - would acquire TASKLIST Mutex
- VFS operations - would acquire RwLock
- Any `spin::Mutex`/`RwLock` or sleeping lock (printk's are IrqSpinlocks)

### 7.5 Syscalls and Faults Run With Interrupts On

The syscall entry (x86 `syscall_entry` after saving the user state;
arm64 `handle_el0_sync` for SVC), user-mode faults and kernel faults on
user addresses from a context with interrupts on (x86 after reading
CR2, arm64 after FAR; Linux do_user_addr_fault / el0_da / el1_abort)
run with interrupts enabled, as in Linux; the entry/exit code
around them (building and restoring pt_regs, x86 `swapgs` and the
switch to the per-CPU top_of_stack, ELR/SPSR_EL1, a fork child's first
return: `clone_child_entry` enables them for the child-TID write and
disables them again) keeps them off. Every x86 IDT vector is an
interrupt gate, so no interrupt lands between an entry from user mode
and its `swapgs` (NMI, #DF and #MC use paranoid entry: they read
MSR_GS_BASE).
The kernel stays cooperative: an interrupt never switches tasks in
kernel mode (the handlers only set flags, wake, and run cross-CPU
calls; an interrupt from user mode may switch on its way back, with
nothing held), so code between explicit schedule points still runs
uninterrupted by other tasks. What this changes, and why it holds:

- Per-CPU data and the current task: a task stays on its CPU between
  scheduling points (no preemption), so per-CPU reads stay valid until
  the next sleep, yield or return to user mode, after which it may run
  on another CPU (a slot is not kept across one: re-read it); state an
  interrupt handler also touches is atomic or taken with interrupts
  off (`IrqSpinlock`, `local_irq_save`: per-CPU page lists, slab arrays,
  TLB state, cross-CPU queues); `curr` is written only by thread
  context.
- Preempt-free sections: unchanged (no preemption); `IrqSpinlock`
  still raises the preempt count and masks interrupts.
- `spin::Mutex`/`RwLock` holders now take interrupts: such a lock must
  never be taken in an interrupt handler (7.4; `LOCKDEP=1` reports one),
  exactly as for kernel threads, which always ran with interrupts on.
- Sleeping with interrupts off is now a bug: `might_sleep` reports it
  under `LOCKDEP=1` (1.5).
- Interrupt handlers run on their CPU's IRQ stack (`irq_stack`, Linux
  hardirq_stack/irq_stack: x86 for an interrupt from kernel mode, arm64
  for any), not the interrupted task's; the return-to-user work after
  them runs on the task stack. Nothing nests on the IRQ stack but
  exceptions (handlers keep interrupts off).
- IRQ toggles (`cli`/`sti`, `msr daifset/daifclr`, `local_irq_*`) are
  compiler barriers (no `nomem`), so no memory access moves across
  them.
- Cross-CPU calls: a CPU in a long syscall answers IPIs at once, and
  spinning waiters (page-table locks) have interrupts on.

---

## 8. API Quick Reference

### Lock Acquisition

| Lock Type | Acquire | Release |
|-----------|---------|---------|
| `IrqSpinlock<T>` | `let guard = lock.lock();` | Automatic on drop |
| `Mutex<T>` | `let guard = lock.lock();` | Automatic on drop |
| `RwLock<T>` (read) | `let guard = lock.read();` | Automatic on drop |
| `RwLock<T>` (write) | `let guard = lock.write();` | Automatic on drop |

### Preemption Control

| Operation | Code |
|-----------|------|
| Disable preemption | `percpu::preempt_disable()` |
| Enable preemption | `percpu::preempt_enable()` |
| Get count | `percpu::preempt_count()` |

### Atomic Operations

| Operation | Code |
|-----------|------|
| Load | `val.load(Ordering::Relaxed)` |
| Store | `val.store(new, Ordering::Relaxed)` |
| Fetch-add | `val.fetch_add(n, Ordering::Relaxed)` |
| Compare-exchange | `val.compare_exchange(old, new, success, failure)` |
| Swap | `val.swap(new, Ordering::AcqRel)` |

### Scheduler Context Switch

```rust
let mut rq = sched.lock.lock();  // IRQs disabled, preemption disabled

// Safe to acquire TASKLIST (interrupts are disabled)
let table = TASKLIST.lock();
// ... get task info ...
drop(table);

// ... select next task ...
unsafe { context_switch(curr, next, kstack); }
// Lock released when guard drops
```

---

## 9. Gaps vs Linux Kernel

Features present in Linux but not yet implemented in hk:

| Feature | Linux | hk | Impact |
|---------|-------|-----|--------|
| `spin_lock_bh()` | Disables softirqs | N/A | No softirqs in hk |
| Softirqs/Tasklets | Deferred interrupt work | Not implemented | ISRs must be minimal |
| NAPI | Network interrupt mitigation | NAPI-like: per-CPU `softnet/N` kthreads poll drivers | Receive processing in thread context |
| Threaded IRQs | IRQ handlers in thread context | Not implemented | All IRQs run in interrupt context |
| lockdep | Runtime deadlock detection | Lockdep-lite (1.5): spin-lock order and sleep-in-atomic checks, `make check LOCKDEP=1` | No sleeping-lock order graph, no IRQ-state classes per lock |
| RCU | Read-Copy-Update | Not implemented | Use RwLock instead |
| Lazy TLB, PCID, global pages | kernel threads keep the last user mm; PCID tags; PGE | Kernel threads load the kernel table; every CR3 write flushes all | More flushes on context switch (x86) |
| PTE locks | `spinlock_t` in the page-table page (ptdesc) | A lock word in the table's struct page (lockdep-tracked as one class) | No owner or fairness (test-and-set) |

### Implications

1. **No softirqs**: Device drivers cannot defer work to bottom-half context. All
   deferred work must use workqueues or be handled synchronously.

2. **NAPI without softirqs**: driver ISRs only ack/mask and `napi_schedule`
   a per-CPU `softnet/N` kthread that polls the device; protocol processing
   never runs in interrupt context (see 3.10 Network Subsystem).

3. **Lockdep-lite only**: spin-lock order inversions and sleeping in
   atomic context are reported at run time (1.5); sleeping-lock order is
   still verified by review.

4. **No RCU**: Read-heavy data structures use RwLock, which has higher overhead
   than RCU for read-mostly workloads.

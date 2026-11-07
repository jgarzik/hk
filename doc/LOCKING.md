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

**Location:** `arch/x86_64/spinlock.rs`, `arch/aarch64/spinlock.rs`

An IRQ-safe spinlock that disables interrupts and preemption while held. This is
the primary lock for code paths that may be entered from both interrupt and
process context.

**Cross-Architecture Consistency:** Both x86_64 and aarch64 implementations MUST:
1. Disable interrupts while held
2. Increment `preempt_count` (via `percpu::preempt_disable()`)
3. Decrement `preempt_count` on release (via `percpu::preempt_enable()`)

**Properties:**
- Disables interrupts on lock acquisition (via `cli`)
- Increments `preempt_count` (prevents context switch)
- Saves and restores interrupt state on unlock
- Uses `AtomicBool` with compare-exchange for lock state
- Non-blocking spin loop while waiting

**Semantics (Linux equivalent: `spin_lock_irqsave`):**
```rust
// On lock():
1. pushfq; cli              // Save flags, disable interrupts
2. preempt_count++          // Disable preemption
3. atomic compare-exchange  // Acquire lock

// On drop()/unlock():
1. atomic store(false)      // Release lock
2. preempt_count--          // Re-enable preemption
3. sti (if was enabled)     // Restore interrupt state
```

**Use cases:**
- Per-CPU run queues (scheduler)
- Any data structure accessed from timer interrupt handlers
- Critical sections that must not be interrupted

**Methods:**
```rust
fn lock(&self) -> IrqSpinlockGuard<'_, T>
unsafe fn force_unlock(&self)  // For context switch only
```

**Example:**
```rust
let sched = get_percpu_sched(cpu_id);
let mut rq = sched.lock.lock();  // IRQs disabled, preemption disabled
// ... critical section ...
// IRQs and preemption restored automatically on drop
```

### 1.2 Mutex<T> (spin crate, via `sync::spin`)

A standard spinning mutex from the `spin` crate (taken through
`crate::sync::spin`, tracked by lockdep-lite in `LOCKDEP=1` builds, 1.5). Used for data structures that
are **NOT** accessed from interrupt context.

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

### 1.3 RwLock<T> (spin crate, via `sync::spin`)

A read-write lock from the `spin` crate. Allows multiple concurrent readers
or one exclusive writer.

**Properties:**
- Multiple readers OR single writer
- Does NOT disable interrupts
- Raises `preempt_count` while held, like `Mutex` (1.2)
- Reader-writer fairness depends on implementation

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

### 1.4 Sleeping locks: sync::Mutex<T>, sync::RwSem (sync/)

Linux `struct mutex` and `struct rw_semaphore`: a contended lock sleeps
on the lock's `WaitQueue` instead of spinning (only a tid-0 caller, the
boot context before pid 1 exists or an idle task, spins: neither ever
meets contention), so the holder may sleep (page locks, block I/O,
user page faults, blocking pipe/socket I/O).

- `Mutex<T>`: owner tid recorded (debug builds catch recursive locking
  and foreign unlocks); `unlock` wakes one waiter, which retries.
  `lock_interruptible`/`lock_killable` (Linux mutex_lock_interruptible/
  _killable) give up with EINTR on a signal (any, or SIGKILL) pending
  while they wait; `try_lock` (mutex_trylock) never sleeps.
- `RwSem<T>` (typed; `RwSem<()>` guards what its owner says):
  `read`/`write` guards, `read_killable`/`write_killable` (Linux
  down_*_killable: a `Killable` sleep, woken by wakeups and SIGKILL
  only, that gives up with EINTR once SIGKILL is pending),
  `read_interruptible`/`write_interruptible` (Linux
  down_*_interruptible: any pending signal gives up with EINTR; no
  caller yet), `try_read`/`try_write`, and the raw `down_read`/`up_read`, `down_write`/
  `up_write` pairs; writer preference: once a writer waits, new readers
  wait behind it (a killable writer that gives up wakes them). Its
  count word is a short `spin::Mutex` leaf never held across a sleep;
  release wakes all waiters (mixed conditions).
- Rules: thread context only; never taken in IRQ context or while any
  spinlock is held (`might_sleep` asserts a zero preempt count in debug
  builds; `IrqSpinlock` raises it). Sleeping locks order ABOVE every
  spinlock: a spinlock may be taken under them, never the reverse.

**Used for:** `RwSem`: `Inode.i_rwsem`, `SignalStruct.exec_update`,
the mmap_lock (`Mm.map`), `AnonVma.chain`; `Mutex`:
`SuperBlock.s_vfs_rename_mutex`, `File.f_pos_lock`,
`SignalStruct.cred_guard`, RTNL (Linux rtnl_mutex), `TcpSock.rd`,
`UnixSock.bindlock`, `UnixSock.iolock`, `Disk.open_mutex`, `SWAPON` and
`Pipe.inner` (Linux pipe->mutex).

### 1.4.1 SeqLock (sync/seqlock.rs)

Linux seqlock_t: `write()` takes a spin lock and keeps the sequence odd
while held (Release fences around the writer's stores); lockless
readers use `read_begin`/`read_retry` and repeat a read that raced a
writer. Thread context only. Used for `MOUNT_LOCK`.

### 1.5 Lockdep-lite (`sync::lockdep`, feature `lockdep`)

Kernel code takes `crate::sync::spin::{Mutex, RwLock}` (never the `spin`
crate's types directly; `printk` and lockdep itself are the exceptions).
These wrap `spin`'s types and raise the preempt count while held (1.2).
Every build checks `might_sleep` against the preempt count, interrupt
state and interrupt depth, and reports the first violation as
`MIGHT_SLEEP:FAIL`; a context switch with any lock held besides the
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
  (`#[track_caller]`, like Linux's static lock_class_key: all `TcpSock.cb`
  share one class). Taking B while holding A records A -> B; taking B
  under A after A was taken under B reports both acquisitions. Only
  direct inversions (no transitive cycles); nesting within one class is
  not checked (listener -> child `cb`, `lock2` of two unix sockets).
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

The held-lock stacks are per CPU (the kernel is not preemptive and a task
never sleeps holding a spin lock, which is itself checked), the edge
table is a fixed array: nothing allocates. Power-off prints a
`lockdep: N reports, M order edges` summary. `IrqSpinlock` acquisitions
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
SignalStruct.cred_guard (sync::Mutex; Linux cred_guard_mutex; exec,
                         ptrace attach; outermost)
    ↓
SignalStruct.exec_update (sync::RwSem; Linux exec_update_lock; write:
                          exec installing the new mm; read: mm_access;
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
                   lists)
        ↓
    SuperBlock.s_umount (sync::RwSem; write for remount, read for a
                   bind remount)
        ↓
    mount::MOUNT_LOCK (SeqLock writer, spin; every mnt_flags write)
        → SuperBlock.s_mounts (spin leaf: a new mount, a read-only
                   remount's snapshot)
        ↓
    dentry::RENAME_LOCK (spin RwLock, Linux rename_lock: write in
                   d_move/d_exchange, read in is_subdir/d_path)
        ↓
    MntNamespace.root, Mount.{children, parent, mountpoint} (spin;
                   d_path reads parent/mountpoint under RENAME_LOCK)
        ↓
    Dentry.d_lock (single d_lock like Linux; short, never held across
                   i_rwsem; parent before child)
        ↓
    Inode.private
        ↓
Filesystem-internal locks (ramfs children/data; procfs data, a leaf:
    held only to copy out what a lookup, readdir, readlink or read
    acts on, which then runs unlocked; kernfs
    `KNode.{children,name,parent,iattr}` spin leaves, 3.3 kernfs)
    ↓
Leaves taken with no task lock held (their Arc is cloned out of the
Task first, under its alloc_lock or lock-free by the task itself):
UtsNamespace.name (RwLock), FsStruct.inner (Mutex),
FutexHashBucket.waiters (spin Mutex; wakeups through a WakeQ after
unlocking)
    ↓
Global subsystem locks (TASKLIST, fd table `Files`)  ← NOT IRQ-safe;
    no file is released under `Files` (3.3, Descriptor Tables); order
    `Files` -> TASKLIST -> Task.alloc_lock (descriptor allocation
    reads RLIMIT_NOFILE under the table lock; kcmp takes a table out
    under the task's alloc_lock and locks it after dropping that); no
    user memory is accessed under any of them. A task's signal
    handlers and signal state, robust-list head and TLS base are
    fields of its `Task` read or changed under TASKLIST; its mm, fd
    table, fs context, namespaces, name, memory policy and I/O context
    under its alloc_lock (3.1.1); under them only leaves:
    SignalStruct.shared (Mutex) → SigHand.action
    (IrqSpinlock); SignalStruct.rlim (IrqSpinlock leaf, also under
    `Files`; setrlimit/prlimit64 read the old limit, decide (with the
    lock-free capable()) and store in one hold, as Linux do_prlimit
    under task_lock); UCOUNTS;
    wait queue heads
    ↓
Address space: mmap_lock (sleeping RwSem; under i_rwsem: a write's user
    copy may fault) → page lock (PG_locked, sleeping; Linux folio_lock)
    [→ AddressSpace.i_pages (spin leaf, Linux xa_lock; 3.2)]
    → AddressSpace.i_mmap (sleeping RwSem, Linux i_mmap_rwsem)
    → AnonVma.chain (sleeping RwSem, Linux anon_vma->rwsem)
    → page_table_lock → PTE lock (spin)
    → SwapInfo.map (spin, Linux si->lock) | swap cache (IrqSpinlock,
      Linux i_pages; never nested with SwapInfo.map) | LRU add batch
      (IrqSpinlock, per CPU) | Lruvec.lock (IrqSpinlock, Linux lru_lock;
      never nested with the others)
    ← never nested with TASKLIST (3.2)
    ↓
Memory allocator locks (Linux: ... → slab → pcp → zone->lock):
    slab per-CPU array (IRQs off) → KmemCache.list_lock (IrqSpinlock)
    → per-CPU page list lock (IrqSpinlock, one at a time) → Zone.lock
    (IrqSpinlock leaf);
    3.2 Heap Allocator, Frame Allocator

Kernel mappings (3.2 Kernel Page Tables): vmalloc FLUSH (sleeping;
    held across the allocation area's TLB flush) → vmalloc AREA (spin
    leaf; no mapping or flush under it); vmstack FLUSH (sleeping,
    thread context; held across the stack area's TLB flush) → IOREMAP,
    vmstack SLOTS (spin leaves; no mapping or flush under them); KTABLES
    (spin, thread context) → frame allocator

Pipes (3.11): Pipe.inner (sleeping; two in address order) → frame
    allocator, and the mmap_lock of a faulting user copy (read and
    write copy between pipe pages and the caller's memory under it,
    Linux pipe_read/pipe_write), and `FasyncList.list` (pipe_fasync);
    no other lock under it, none of these above it

SIGIO (3.11, io/fasync.rs; Linux fasync_lock, f_lock, fown->lock):
    FasyncList.list (sleeping, per object: a pipe's two, a socket's) → File.f_lock (fasync_helper
    sets O_ASYNC with the list change) | FOwner.st (spin leaf, copied
    and released before a send); kill_fasync sends under
    FasyncList.list → TASKLIST (read) → Task.sig → shared_pending, so
    its callers hold no spin lock (no Inode.i_pipe, no Pipe.inner)

Block locks (3.10 Block Device Subsystem):
    Disk.open_mutex (sleeping) → devtmpfs root i_rwsem → BLKDEV_REGISTRY,
    MAJORS; I/O sleeps under open_mutex only
    blk-mq software queue, hardware queue (IrqSpinlock leaves; the
    hardware queue also from the driver ISR, under IRQ_TABLE)
    Completion.done (IrqSpinlock) → wait queue head → run-queue lock

Network locks (3.10 Network Subsystem has the full order):
    RTNL (sleeping, outermost; never under any spinlock)
        ↓
    TcpSock.rd / UnixSock.bindlock / UnixSock.iolock (sleeping)
        ↓
    socket locks (TcpSock.cb, TimeWait.inner, UdpSock.op, PingSock.op,
    UnixSock.st) → protocol tables → Inet.addr → queues, timers
        ↓ (transmit under a socket lock)
    FIB / neighbour / device TX → Softnet.backlog
    Socket wakeups (`Sock::data_ready`, `write_space`,
    `error_report`, `wake_async`) send SIGIO (`Sock.fasync` ->
    FasyncList.list), so they run after every network spin lock is
    dropped (TCP posts an error under `TcpSock.cb` with `post_err` and
    signals after unlocking). `Sock.wq_flags` (NOSPACE, WAITDATA) are
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
    IRQ-safe; Linux task_lock; one task's at a time) → Task.sig (spin
    Mutex, per task) → SignalStruct.shared (spin Mutex) →
    SigHand.action (IrqSpinlock leaf); Task.keyrings, Task.cgroup,
    Task.fput_defer: per-task leaves reached through a TaskRef, never
    under TASKLIST; SignalStruct.posix_timers (never under TASKLIST)
    → PosixTimer.inner, SignalStruct.rlim (cpu_timer's expiry pass)

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
    CANCEL_LIST (spin) → Timerfd.inner

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
    (spin; never takes TASKLIST under it); Tty.ldata → Tty.termios
    (spin, thread context; termios is read under ldata by input
    processing and swapped under it by set_termios, as Linux's
    termios_rwsem spans both); Tty.read_lock (sleeping Mutex, Linux
    atomic_read_lock) → Tty.ldata, Tty.flip: held by a reader across its
    sleeps on read_wait; Tty.write_lock (sleeping Mutex, Linux
    atomic_write_lock) → Tty.termios, TASKLIST (read) → Tty.ctrl and
    the SIGTTOU send (the TOSTOP check): held by a writer across the
    whole write(2) and its driver writes; never nested with read_lock or
    buf_lock; Tty.buf_lock (sleeping Mutex, Linux
    tty_bufhead.lock) → Tty.ldata: held by the flip thread across
    feeding input (including the echo's driver write) and by
    flush_input; Tty.flip (IrqSpinlock leaf,
    also under IRQ_TABLE in the UART handler). No tty spin lock is held
    across a signal, a sleep or a driver write; Tty.buf_lock is (ISIG
    signals, and SIGIO: Tty.buf_lock → `Tty.fasync` FasyncList.list).
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
  `SignalStruct.shared` (spin Mutex) -> `SigHand.action`,
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
parameters (`class`, `policy`, `static_prio`, `rt_priority`,
`reset_on_fork`; SCHED_RR's slice), the run-list `link`, the saved
switch frame, and the WakeQ link; plus
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
(SCHED_NORMAL/BATCH/IDLE: EEVDF, `task/fair.rs`; the entity's
vruntime, deadline, lag and exec_start change under the rq lock of its
CPU, and the tick charges the running one under it), idle (never
queued). A woken task preempts a lower class, a lower rt priority, or
a fair task EEVDF would not pick at that point (not for SCHED_BATCH/IDLE).
rt bandwidth (`task/rt.rs`, Linux rt_rq->rt_time): `CpuRunQueue.rt_bw`
holds the rt time run on that CPU in the current 1 s period, under its
rq lock (charged by the tick and when an rt task switches out). Once
it reaches 950 ms, fair tasks rank above rt ones there (pick and
wakeup preemption) while any is runnable, until the period ends (the
tick of a running fair task rolls it over and reschedules).
It has no lock of its own.
`CpuRunQueue.min_vruntime` (under the rq lock) stands for the average
when no fair task is there.

Each `PerCpu` (per-CPU data) contains:
```rust
pub interrupt_depth: AtomicU32,   // Nesting depth of interrupts
pub preempt_count: AtomicU32,     // Preemption disable count
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

7. **User FP/SIMD state is saved eagerly, per task, never lazily** - no
   lock is involved; the state always lives with the task it belongs to:
   - x86-64: the kernel is soft-float and never touches x87/XMM/YMM, so a
     task's user FP state stays in the registers while it is in the kernel.
     `context_switch` XSAVEs (or FXSAVEs) it into an area on the outgoing
     task's kernel stack and XRSTORs it when that task runs again; a fork
     child gets the parent's state just below its pt_regs
     (`SchedArch::clone_child_fpu`), loaded by `ret_from_fork`.
   - aarch64: the kernel uses NEON, so every exception entry (EL0 and EL1)
     saves q0-q31/FPCR/FPSR in its trap frame and restores them on exit;
     the EL0 frame (the task's pt_regs, rule 6) holds the user FP state.
     `__switch_to_asm` preserves d8-d15.
   Signal frames, fork and execve read/write the state in these places;
   nothing may use user FP registers between a context switch's save and
   the task's next return to user mode except through them.

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
(created asleep in that CPU's rq, then woken). `KTHREADS`
(`spin::Mutex<Vec<Arc<KThread>>>`, process context only, never held across
a wakeup/sleep; order: may be taken while holding nothing else, or only
sleeping locks such as a directory's `i_rwsem`) maps tid -> control
block. `get_task_fs` takes it for a task with no fs of its own, to hand
a kernel thread the shared knullfs fs_struct (fs/fsstruct.rs
`KTHREAD_FS`; umask from create_mode runs under the directory's
`i_rwsem`). `kthread_should_stop/should_park/parkme` and
`kthread_stop/park/unpark` use atomics + `try_to_wake_up` + the block's
`ack` WaitQueue. A thread created without a CPU gets one round-robin;
every kernel thread stays on its CPU (`cpus_mask` holds only it, Linux
kthread_bind). Standing threads: `ktimers/N` (one per CPU, runs its SOFT
timer callbacks), the system workqueue worker, `softnet/N` (one per CPU,
network receive; see 3.10), `kselftest` (boot only).

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

**Location:** `task/mod.rs`, `task/percpu.rs`

A global `TASKLIST: RwLock<GlobalTaskTable>` (Linux tasklist_lock: read
for lookups and walks, write for any change) protects the task list and
the relations, ptrace, exit and other `TaskInner` fields. Per task, as in
Linux: `Task.alloc_lock` (Linux task_lock) guards the resource pointers
(mm, files, fs, nsproxy, comm, mempolicy, io_context), `Task.pi_lock`
serializes wakers (3.1), `Task.sig` holds the per-task signal state
(3.7).

#### Data Structures

| Variable | Type | Purpose |
|----------|------|---------|
| `TASKLIST` | `RwLock<GlobalTaskTable>` | Every task: an intrusive `ArcList` (Linux init_task.tasks) holding a `TaskRef` (`Arc<Task>`) each, found by tid through the pid hash (`Pid.task`, set and cleared under the write lock) |
| Per-CPU `curr` | `*const Task` in PerCpu | The running task (no lock) |
| `Task.cred` | `Arc<Cred>` (raw) | Reference-counted credentials |

**Pids** (`task/pid.rs`, Linux 4.14 pidmap): a `Pid` holds one
number per pid-namespace level. Numbers come from a lock-free bitmap
per namespace (pages allocated outside any lock, installed by
compare-and-swap; bits set and cleared atomically). `PIDMAP_LOCK`
(spin leaf, thread context only, nothing allocates under it) protects
the global hash chains of every live `Pid`'s numbers: `alloc_pid`
links them, `find_pid` walks them (taking a strong reference only
while the `Pid` lives: the hash holds weak ones), and they are
unlinked and given back when the last task leaves the `Pid`
(`release_numbers` from `GlobalTaskTable::remove`, `change_pids` and
`take_leadership`, under TASKLIST's write lock: Linux free_pid from
detach_pid), or at its last drop if no task ever left it. It is taken
under nothing but may be taken under TASKLIST.
A process's pid is its leader's tid; an exec from a non-leader takes
the leader's tid and `Pid` (`take_leadership`, Linux exchange_tids)
under TASKLIST (the run queue knows tasks by reference, not by
number). The idle tasks
are tid 0 and, like the boot task, not in TASKLIST.

**Relations** (under TASKLIST's write lock to change, read lock to
walk): `real_parent` and `ptracer` are task references (`Weak`), never
numbers, so a recycled tid cannot inherit a parent or tracer link. A
group leader is on its real parent's `children` (intrusive `ArcList`,
link `Task.sibling`, one strong reference each; Linux only lists
leaders); `link_child` at fork and exec's leader change, unlinked at
reap. An exiting task first hands its children to another live thread
of its group, else the nearest child subreaper, else init
(`forget_original_parent`, `adopt`); an exited non-leader thread
leaves the task list at once (Linux release_task), unless traced:
then when its tracer reaps it or exits (Linux wait_task_zombie,
exit_ptrace).
A group leader's `threads` (intrusive `ArcList`, link
`Task.thread_node`, the leader included; Linux signal->thread_head)
lists its group: joined at insert, left at removal, handed to the
exec'ing thread when it takes the leader's place. A process is found
by its pid as its leader's tid (`get(pid)`); its threads through
`threads(pid)`.

**Process groups and sessions** (Linux pid->tasks[PIDTYPE_PGID,
PIDTYPE_SID]): each `Pid` has a `pgrp` and a `session` list (intrusive
`List`, links `Task.pgrp_link`/`session_link`, no references), changed
under TASKLIST's write lock and walked under its read lock (through
`GlobalTaskTable::pgrp`/`pgrp_threads`). Only group leaders are on
them (`TaskInner.pids_linked`), like Linux: linked when inserted
(fork), by the new leader at exec's `take_leadership`, and after a
change; unlinked at `remove` (release or reap; a zombie leader stays,
as in Linux). Every thread holds a reference to its group's and
session's `Pid` (`TaskInner.pgrp`/`session`, Linux signal->pids), so
a `Pid` outlives its group even after its own task is gone; the
`pgid`/`sid` atomics carry the numbers for lock-free getpgid/getsid.
setpgid and setsid change every thread of the process in one write
section (`change_pids`); fork copies the creator's under the same
write lock that inserts the child. The old `Pid` references are
dropped after TASKLIST; a group's `Pid` is looked up by number
(`find_pgrp`, PIDMAP_LOCK) before TASKLIST is taken. Group 0, where
init starts, is `INIT_STRUCT_PID` (Linux init_struct_pid, never
hashed). kill(-pgrp), kill(0), tty ISIG, F_SETOWN and PRIO_PGRP /
IOPRIO_WHO_PGRP walk a group's list, never the whole task list.

A `Task` has five kinds of fields: fixed at creation (`tid`, `pid`,
`kind`, `kstack_top`); hot atomics written by the task itself (or its
creator before it first runs) or under TASKLIST, and read lock-free
by anyone (`flags` = Linux PF_*, `thread_flags` = TIF_*, `cpu`,
`start_time`, `ppid`/`pgid`/`sid`, `seccomp_mode`, `tls`, utime/stime
and the other counters; utime/stime/last_run_ns/in_kernel are written
only on the task's own CPU with interrupts off (its syscall entry and
exit, its context switches, the tick) inside the `acct_seq` sequence
count, which readers on other CPUs retry on); `cred` (below); the
alloc_lock fields; and
the rest, `TaskInner`, in a `TableCell` (`sync::LockedBy` owned by
`GlobalTaskTable`): a borrow of the locked table is the key, `&table`
reads it and `&mut table` writes it, checked by the compiler (the
table is a `UniqueOwner`: TASKLIST holds the only one). The `Pid`
process-group and session lists are owned the same way. A `TaskRef` cloned out of the table keeps the task alive but
reads only its fixed and atomic fields without the lock.

**alloc_lock fields** (Linux task_lock(p), `p->alloc_lock`): `mm`,
`files`, `fs`, `nsproxy`, `comm`, `mempolicy`, `io_context`.
`Task.alloc_lock` is a spin Mutex (thread context only, not IRQ-safe,
one lockdep class for every task; never two tasks' at once). Owner
rule (`OwnCell`): only the task itself changes them (or its creator
before it first runs: fork attaches the child's fs, files, nsproxy
and I/O context after inserting it), always under its alloc_lock; the
task reads its own lock-free (`current().mm()`, `files()`, `fs()`,
`nsproxy()`, `comm()`; Linux current->mm etc.); others read them under
the lock (`Task::task_lock()`, `percpu::with_task_lock(tid, f)`: the
pid lookup takes TASKLIST only to find the task; procfs, kcmp, acct,
ptrace access checks, `get_task_mm`/`get_task_fs`/`get_task_ns`).
`io_context` is the exception: ioprio_set installs one in another
task, so it is read under the lock only. Exec swaps the mm and comm in
one alloc_lock section (under `exec_update` and TASKLIST, which it
holds for the page table), so a reader sees the old name with the old
mm or the new with the new (Linux exec_mmap, __set_task_comm). Order:
TASKLIST (and PIDMAP_LOCK) before alloc_lock, alloc_lock before
`Task.sig`; nothing else is taken under it (no TASKLIST, no `Files`,
no sleeping lock). `cred` keeps its own scheme (Linux RCU): lock-free
for the task, TASKLIST for others.

#### Locking Rules

1. **TASKLIST is NOT IRQ-safe** - Never acquire from interrupt handlers
2. **IrqSpinlock → TASKLIST is safe** - IRQs disabled prevents ISR from running
3. **The tick reads no TASKLIST** - wakeups and timers use `Task` fields only
4. **Nothing is released under TASKLIST or an alloc_lock** - a task's
   shared resources (`files`, `fs`, `nsproxy`, `io_context`, `mm`
   under alloc_lock; `sighand`/`signal`, `seccomp_filter`, a reaped
   `Task` under TASKLIST) are `take()`n or `replace()`d under the lock
   and dropped after it: their last reference can close sockets (TCP
   release may sleep in SO_LINGER: sleeping under a spin lock) or tear
   down a network namespace (RTNL, a sleeping lock). `Arc<Cred>` is the
   exception: replacing it under the lock (commit_creds) frees only
   memory.
5. **PF_EXITING** - `exit_current` sets `pf::EXITING` in `Task.flags`
   before releasing anything; release paths read
   it lock-free via `current_exiting()` (TCP close skips its SO_LINGER
   wait, Linux inet_release).

#### Credential Handling (Linux Pattern)

Following Linux's `kernel/cred.c` pattern (see `include/linux/cred.h`):

1. **Reference-counted** - `Task.cred` holds an `Arc<Cred>` (as a raw
   pointer; the boot task points at a static root `Cred`)
2. **Copy-on-write** - modifications use prepare/commit
3. **Owner rule** - the task reads its own credentials lock-free
   (`current().cred()`, Linux current_cred); other tasks read them under
   TASKLIST; only the task itself replaces them (`commit_creds`, under
   TASKLIST), so a lock-free owner read never races a writer

**Credential APIs (like Linux):**
- `prepare_creds()` - Clone current credentials, return mutable copy
- `commit_creds(new)` - swap `Task.cred` under TASKLIST; the old
  `Arc<Cred>` is dropped after the lock (it only frees memory)
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
  access), pidfd_getfd and kcmp hold it for reading
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
`tid`, `pid`, the hot atomics (`ppid`/`pgid`/`sid`, `seccomp_mode`,
`flags`, `thread_flags`, accounting, `tls`), `cred` (others read it
under TASKLIST) and the alloc_lock fields but `io_context` (Linux
current->mm/files/fs/nsproxy/comm: only the task itself changes them,
or its creator before it first runs, under its alloc_lock; other tasks
read them under it). `get_task_fd`, `get_task_mm`, `get_task_fs`,
`get_task_ns` and `has_pending_signals` take this lock-free path for
the current task (fget, the page-fault mm lookup, path walks,
`signal_pending`).

The context switch takes no TASKLIST: `make_current` reads the next
task's kernel stack, address space and TLS from the task (it is not
running, so its owner fields are stable); /proc reads the run state
from `Task.se`.

### 3.1.2 Comparison with Linux task_struct Locking

| Linux Lock | Purpose | hk Equivalent |
|------------|---------|---------------|
| `alloc_lock` (task_lock) | mm, files, fs, nsproxy, comm, mempolicy, io_context | `Task.alloc_lock` (spin Mutex, per task) |
| `pi_lock` | Wakeups, state | `Task.pi_lock` (IrqSpinlock, per task; 3.1) |
| `sighand->siglock` | Signal state, handlers | `Task.sig`, `SignalStruct.shared` (spin Mutex), `SigHand.action` (IrqSpinlock; 3.7) |
| `tasklist_lock` | Task list, parent/child, ptrace links | `TASKLIST` (global spin RwLock) |
| RCU (`cred`) | Credentials | lock-free for the task, TASKLIST for others |

Remaining differences: the `task_struct` fields Linux leaves to the
task itself or to siglock (scheduling policy, prctl state, robust
list, seccomp filter) are `TaskInner` fields under TASKLIST, and
`cred` has no RCU (TASKLIST stands in for it).

### 3.1.3 Task State Invariants

The `TaskState` enum in `TASKLIST` is informational (and records
`Zombie(wait_status)` / `Traced`), not the scheduling source of truth:

**ptrace stops** (`task/ptrace.rs`, Linux ptrace_stop): the tracee
sets `TaskState::Traced(code)` and `ptrace_code` under the TASKLIST
write lock, drops it, wakes `CHILD_EXIT_WQ` and signals its tracer, then
sleeps `Killable` until its TASKLIST state is no longer `Traced` (read
lock, rechecked after each wakeup) or SIGKILL. The tracer's wait clears
`ptrace_code` under the write lock; resume, detach and the tracer's exit
(`exit_ptrace`) set the state and the code to deliver under it, then
`try_to_wake_up` the tracee with it dropped. SIGKILL ends the stop in
the section that queues it (`sigkill_task` from `zap_threads`, Linux
signal_wake_up(fatal) clearing JOBCTL_TRACED), so a wait after the
kill never reports the stop. A tracer's request holds the stop while it
runs (`TaskInner.ptrace_frozen`, Linux JOBCTL_PTRACE_FROZEN): set under
the write lock by `ptrace_check_attach` (in the stop, no SIGKILL
pending), cleared under it when the request's `Frozen` guard drops (if the
listed task is still the same `Task`, not one that reused its tid),
and whenever a stop begins or ends (resume, detach, the tracer's exit,
the tracee leaving `ptrace_stop`), so no stale flag outlives a stop;
while it is set, SIGKILL leaves the stop alone (`sigkill_task`, and the
tracee, woken, sleeps `Uninterruptible` once it reads frozen with
SIGKILL pending), and the guard's drop ends a stop with SIGKILL pending
and wakes the tracee after the lock (Linux ptrace_unfreeze_traced). The
arch register and
single-step helpers take the TASKLIST read lock themselves, so callers
never hold it.

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
  (`Zone.draining`, an atomic flag; Linux pcpu_drain_mutex, which
  hk takes like a trylock): a caller that finds one running never
  waits (it may hold a spinlock, or have interrupted the drainer) and
  just retries its allocation. Allocations in interrupt context never
  drain (debug builds assert they do not pass `Gfp::RECLAIM`). A CPU
  without
  per-CPU data yet (coming up, or the boot CPU early) never touches a
  per-CPU list: it allocates and frees under `Zone.lock`. A list's page
  count is an atomic beside its lock (statistics read it lock-free).
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
(`exit_mmap`), `task/percpu.rs` (`exit_current`, `exec_replace_image`,
`do_clone`)

- `Mm.users` (`AtomicUsize`, Linux mm_users) counts the tasks running in
  the address space and pinned users (`MmRef`: ptrace PEEK/POKE,
  process_vm_*, a /proc/<pid>/maps read). The last `MmRef` drop runs
  `exit_mmap`, which, under the mm lock held for writing, takes the
  VMAs (dropping the rmap chains) and tears down the user half
  (`pgtable::detach_user`, a TLB flush, `UserTables::free`), then drops
  the VMAs (file references) with no lock held. **Never drop an `MmRef`
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
  mincore, msync, populate, remote reads (ptrace PEEK,
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
- Shared anonymous memory (`mm::shmem::Shmem`, Linux shmem): its page
  index `Shmem.root` is a `spin::Mutex` taken by the fault path under
  the mm lock (mm lock -> Shmem.root) and by MADV_REMOVE after the mm
  lock is dropped; under it only `FRAME_ALLOCATOR` and the heap (index
  nodes, atomic under the spin lock) are taken. The object goes with its last VMA
  (possibly under the mm lock): its drop takes no lock but
  `FRAME_ALLOCATOR`.
- A SysV shm attachment (`ipc::shm::ShmAttach`, in its VMA) is cloned
  and dropped with the VMA, possibly under the mm lock: it only updates
  the segment's atomics (shm_nattch, times, pid), and destroying a
  removed segment at the last detach takes no lock. IPC_RMID (mark
  deleted, then read shm_nattch) and shmat (count the attachment, then
  check the mark) order with SeqCst fences, so a racing shmat backs out
  (EINVAL) or IPC_RMID sees it; destroy is idempotent, so namespace
  totals are given back exactly once.
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
  page-table and page allocation (`FRAME_ALLOCATOR`), a shared object's
  `Shmem.root`, rmap/LRU, and the reads that may sleep (a file page:
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
  (`PgTables::pte_alloc`, `pmd_alloc`), a 2MB entry mapped (`do_huge_anon`), split
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
  self-deadlock). Allocations that must not fail are made first: fork
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
  flushes the whole range once per batch of 64 frames and only then
  releases them (and, at exit, the page tables): no frame is reused
  while a CPU may still reach it through its TLB. rmap flushes in the
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

#### Swap (mm/swap.rs, swap_state.rs; Linux mm/swapfile.c, swap_state.c)

- `SwapInfo.map` (`spin::Mutex`, Linux si->lock): a device's slot
  counts (swap PTEs + SWAP_HAS_CACHE) and allocation hint; swapoff
  clears SWP_WRITEOK under it, and the allocator rechecks it there, so
  no slot is taken after swapoff's scans begin. Thread
  context only; a leaf taken under the PTE lock (fork's swap_duplicate,
  zap's free_swap_and_cache, swap-in's swap_free), never with a swap
  cache lock held.
- `SwapInfo.cache` (`IrqSpinlock<XArray>`, Linux i_pages xa_lock_irq):
  the swap cache of a device, page by slot. A leaf: under it only the
  allocators (a page, a heap index node; atomic, never sleeping). A lookup takes its page
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
- `SWAP_INFO` (spin `RwLock`, read mostly): the devices; `SWAPON`
  (sleeping `Mutex`, Linux swapon_mutex) serializes swapon/swapoff.
  swapoff (`try_to_unuse`) clears SWP_WRITEOK, then walks every address
  space (collected under `TASKLIST` and each task's alloc_lock, which
  are dropped before any mm lock) with its mmap_lock held for reading, faulting the device's swap
  PTEs in.

#### LRU (mm/lru.rs; Linux mm/swap.c lruvec)

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

#### Reclaim (mm/vmscan.rs; Linux mm/vmscan.c)

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
- arm64 ASIDs (`mm/asid.rs`, `arch/aarch64/tlb.rs`, Linux
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

**Location:** `arch/x86_64/kmap.rs`, `arch/x86_64/ioremap.rs`,
`arch/aarch64/kmap.rs`, `arch/aarch64/ioremap.rs`;
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
  tables under `KTABLES` (`spin::Mutex` leaf, thread context, one per
  arch in ioremap.rs; `FRAME_ALLOCATOR` is taken under it for table
  frames). Linux: `vmap_area_lock` + `init_mm.page_table_lock`. A PTE
  of a range one owns is set or cleared without a lock: only the
  holder of the range's `vmalloc::VmArea` (Linux vm_struct; a vmalloc
  block, a kernel stack) or of an ioremap mapping changes it, and these
  kernel tables are never freed.
- TLB: iounmap clears the entries and flushes every CPU
  (`flush_tlb_kernel_range`, with `IOREMAP` not held) before the range
  is freed; arm64 broadcasts, x86 sends IPIs.
- Kernel stacks (`mm::vmstack`, Linux VMAP_STACK): 16KB of single
  pages at the start of a 64KB slot, the rest unmapped (the guard gap
  the next stack's overflow faults in). `free` (from `DeadTask::drop`,
  possibly with interrupts off) unmaps and frees the pages with a
  local flush and marks the slot dirty under `SLOTS`; `alloc` (thread
  context) flushes the whole area on every CPU once 64 slots are dirty,
  with `SLOTS` not held, before any of them is reused (Linux lazy
  vmap purge). Flushers are serialized by `FLUSH` (sleeping
  `sync::Mutex`), so one cleaning a slot set from its snapshot cannot
  clean a slot freed again after another's flush. `SLOTS` is never
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
- All IRQ-safe (an allocation in interrupt context cannot deadlock),
  but the policy is still **no allocation in IRQ context**; IRQ paths
  reserve capacity up front (e.g. `netif_napi_add`)
- kmalloc above 8KB (or aligned above 4KB) takes pages directly from
  the page allocator. The heap has no GFP argument, so its pages take
  one from the context (`slab::heap_gfp`): GFP_KERNEL (to the min
  watermark; reclaiming only where the caller may sleep, else a drain),
  GFP_ATOMIC only in an interrupt handler or within reclaim
  (PF_MEMALLOC). A cache grows with interrupts as the caller had
  them (the per-CPU array is used with them off, the new slab is made
  after restoring them, Linux cache_grow_begin). User data stops at
  low, leaving low - min to kernel objects (a failed heap
  allocation is fatal in Rust): user allocations stop at low until the
  OOM killer (P6), even after reclaim; then Linux's min.
- Direct reclaim runs for a `Gfp::RECLAIM` allocation (GFP_KERNEL,
  GFP_USER, GFP_HIGHUSER_MOVABLE) only when the caller really may sleep
  (`page_alloc::may_direct_reclaim`): no spin lock held, interrupts on,
  a task (not tid 0), not reclaim itself (PF_MEMALLOC) and I/O allowed
  (no PF_MEMALLOC_NOIO). Otherwise it drains the per-CPU lists and
  retries once. Reclaim runs with PF_MEMALLOC set
  (`mm::memalloc_scope`, Linux memalloc_noreclaim_save), so its own
  allocations take GFP_ATOMIC and never reclaim again; swap writeback
  runs with PF_MEMALLOC_NOIO (Linux memalloc_noio_save). The reverse map
  only tries the AnonVma chain lock under PF_MEMALLOC (Linux rmap_walk
  with try_lock): an allocating task may hold it for writing. Direct
  reclaim swaps only to block-device areas (`swap::get_swap_page`
  skips swap files under PF_MEMALLOC), since a file's swap_rw may
  need filesystem locks the allocating task holds. A fault
  whose page table cannot be allocated (under the page_table_lock)
  reclaims after dropping it and retries.

#### Per-inode page cache (Linux i_pages)

**Location:** `mm/filemap.rs` (`AddressSpace`, the inode's
`i_data`); users: ramfs, vfat files, block devices
(`BlockDevice.bd_inode`). vfat writes its FAT and directory blocks
into the device cache marking only the 512-byte sectors it changes
(`bdev_write_meta`: bits in `Page.private`, set under the page lock;
Linux dirty buffer heads), and the device's writepage writes only
those: a device-cache page may also hold file-data clusters, which
the file's own cache writes. (A write-back widened to the device's logical
block stays inside one FAT sector: vfat refuses a FAT sector smaller
than that block. A newly allocated cluster's device-cache pages are
dropped before and after it is zeroed on the disk.)

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
- Dirty, cached and unevictable pages are counted per CPU
  (`NR_DIRTY`, `NR_FILE`, `NR_UNEVICT`: atomics, Linux vmstat), summed
  lock-free for the dirty limits and /proc/meminfo.
- Reclaim and drop_caches (`shrink_cache`, `drop_pagecache`) walk
  the cached inodes in place, allocating nothing: one inode reference
  at a time is taken under its inode-cache bucket lock (or the block
  device registry lock), then its clean pages are dropped with no lock
  held but each page's, taken with trylock (reclaim never waits for
  one); an unevictable mapping (ramfs) is never touched.
- Eviction (`Drop for AddressSpace`, the inode's last reference)
  empties `i_pages` without page locks: nothing else can reach the
  mapping any more.

### 3.3 Virtual File System (VFS)

**Location:** `fs/`

The VFS uses fine-grained locking with `RwLock` for concurrent read access.
**All VFS locks are NOT IRQ-safe** and must only be accessed from thread context.

#### Global Structures

| Variable | Type | Purpose |
|----------|------|---------|
| `DCACHE` | `DentryCache` (contains `RwLock`) | Dentry cache root |

#### Descriptor Tables (Linux files_struct)

**Location:** `task/fdtable.rs`, `task/mod.rs` (`FdTable`)

The last `Arc<Files>` closes every descriptor, whoever drops it (a
/proc reader too; Linux put_files_struct): its drop flushes and may
sleep, so a `Files` reference is never dropped under a spin lock
(the task's is swapped out under alloc_lock and dropped after it).
`Files.users` counts the tasks using the table (Linux
files_struct.count) and decides sharing for exec and unshare.

`Files` (one per task, shared by CLONE_FILES) wraps the table's
`spin::Mutex` (Linux `files->file_lock`), thread context only, a leaf
apart from the heap. Releasing a file can sleep (a TCP socket with
SO_LINGER waits for its close handshake; socket release paths take
sleeping locks), so **no file is ever released under it**: close,
dup2/dup3 over an open descriptor and installs the table refuses
(EMFILE) park the detached `Arc<File>`s in the table, and
`FilesGuard::drop` releases them after unlocking (Linux
`file_close_fd_locked` under the lock, `filp_close`/`fput` after
`spin_unlock`). Files looked up with `get` are clones taken while the
table holds its own reference, so dropping them under the lock is never
the last reference.

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
(by directory-entry position) are hashed so each on-disk object has one
`Inode`. One `IrqSpinlock` per bucket (a RAM-sized table), a leaf:
under it only the bucket vector, `Weak` counts and the filesystem's
`test` (which may take `Inode.private`, a spin RwLock, then vfat's
`VfatInode` data, a spin Mutex leaf held only to copy the data in or
out; never taken from an interrupt). IRQ-safe
because a last reference could go anywhere. The hash holds `Weak`s;
an inode upgraded under a bucket lock is never dropped there (its last
reference's eviction takes the same lock): lookups keep them in a
vector dropped after unlocking. Eviction (`Drop for Inode` ->
`icache::evict`, Linux iput_final -> evict) runs where the last `Arc`
goes, possibly under spin locks: it takes the bucket lock (if hashed)
and calls `->evict_inode`, which must not sleep; vfat queues the
cluster freeing of an unlinked file on `SYSTEM_WQ`
(`Workqueue.inner`, IrqSpinlock leaf). Deviation from Linux: no
unused-inode LRU or I_NEW state (an inode is complete before it is
hashed; the losing builder's inode is dropped unhashed).

**Dentry** (`fs/dentry.rs`):

Following Linux's `d_lock` pattern, each dentry has a single RwLock protecting
all mutable state, its name and parent included:

```rust
pub struct Dentry {
    pub sb: Weak<SuperBlock>,   // Immutable after creation
    d_lock: RwLock<DentryInner>, // Single lock (like Linux d_lock)
}

struct DentryInner {
    name: FileName,             // Changed by d_move/d_exchange
    inode: Option<Arc<Inode>>,
    parent: Option<Arc<Dentry>>, // Pinned by the child (Linux d_parent)
    children: BTreeMap<FileName, Arc<Dentry>>,
    flags: DentryFlags,
}
```

A rename moves the dentry itself (`d_move`, `d_exchange`) under the
global `RENAME_LOCK` (write; Linux rename_lock), with both parents'
`i_rwsem` held by the caller; each step takes one `d_lock` at a time
(parent, then the moved or replaced child). `is_subdir` and `d_path`
read parents and names under `RENAME_LOCK` (read), so they see one
consistent tree. `d_path` also climbs mounts (`Mount.parent`, then
`Mount.mountpoint`, each read and released) inside it: RENAME_LOCK ->
Mount fields -> d_lock; nothing takes RENAME_LOCK under a Mount lock. `Dentry::alloc` inserts a child under the parent's
`d_lock` unless one with that name is cached (Linux d_alloc + d_add):
one dentry per name. Deviation: Linux readers retry a seqlock instead of
taking a lock.

A cached child is revalidated (`InodeOps::revalidate`, Linux
d_revalidate) after its d_lock is released, inside whatever i_rwsem the
walk holds: procfs's takes TASKLIST (read) and the task's fd table
lock. `proc::proc_flush_pid` runs after a task leaves TASKLIST: it
collects the procfs superblocks under `PROC_SBS` (spin Mutex, leaf),
releases it, then drops dentries (d_lock).

An open procfs file's `ProcOpen.seq` (sync::Mutex, Linux seq_file
m->lock) is held across generating its content (which takes
TASKLIST, mmap_lock, network and mount locks) and the copy to the
caller (may fault: -> mmap_lock); under f_pos_lock for read().

The dcache shrinker (`dentry::shrink_dcache`: drop_caches 2, direct
reclaim) takes `superblock::ALL_SBS` (spin Mutex, leaf) only to pick the
next superblock, then per dentry the parent's d_lock (write) and the
child's (read): spin locks only, allocating nothing. Direct reclaim
never runs in atomic context (`may_direct_reclaim`), so an allocation
under a d_lock or ALL_SBS cannot re-enter it.
`dentry::d_drop_tree` (an unhashed dentry's cached subtree, a dying
superblock's tree) takes the same parent-then-child d_locks one leaf
at a time, with no RENAME_LOCK held (d_move drops it first).

#### kernfs / sysfs (fs/kernfs/, fs/sysfs.rs; Linux fs/kernfs)

| Lock | Type | Order / rule |
|------|------|--------------|
| `kernfs::KERNFS_RWSEM` | sync::RwSem (Linux kernfs_rwsem) | write: add, remove, rename a node; read: symlink target paths. Taken by subsystems registering objects (in thread context, under their own locks such as RTNL), never under a VFS lock, never across show()/store() |
| `KNode.children`, `.name`, `.parent` | spin RwLock, leaves | alone (lookup, readdir under the walk's i_rwsem) or under KERNFS_RWSEM |
| `KNode.iattr` | spin Mutex, leaf (Linux kernfs_iattr_rwsem) | written by chmod/chown/utimes under the inode's i_rwsem; read (copied out) when lookup builds an inode, under the parent's i_rwsem |
| `AttrNode.ops`, `BinNode.ops` | spin RwLock, leaf | read (clone) under an active reference by show()/store(); cleared by `KNode::remove` after the drain, with no lock held, the operations dropped after it is released (a removed node kept by a dentry or open file pins nothing) |
| `OpenAttr.buf` | sync::Mutex (Linux kernfs_open_file.mutex), per open file | held across show()/store(), which take subsystem locks, and across a read's copy to the caller (may fault: -> mmap_lock; no active reference held then, Linux seq_read_iter under m->lock); a write copies its data in before taking it; under f_pos_lock for read/write |
| `sysfs::SBS` | spin Mutex, leaf | per-network-namespace superblocks, taken only in mount |

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
are leaves read without the device lock. `Class.devices`,
`BusType.{devices,drivers}` (Linux klist_devices/klist_drivers) and
`core::DEVICES_LIST` (Linux devices_kset list) are spin leaves taken
alone; lists are snapshotted before probing walks them.
`device_shutdown` (reboot(2)) takes the list out under its lock and runs
each bound driver's shutdown callback after dropping it, so callbacks
(which may poll hardware or take driver locks such as `USB_CONTROLLER`)
never run under it. `PciDev.driver_override` is a spin leaf.
Net devices: `NetNamespace::register_device` drops the namespace's
`devices` spin lock before creating the device's sysfs entries (under
RTNL for driver registrations: RTNL -> KERNFS_RWSEM); a namespace's
devices leave sysfs when it is dropped, in thread context. A NIC
driver's probe and remove run under its device's lock and take RTNL
(`register_netdev` / `unregister_netdev`): `Device.lock` -> RTNL ->
KERNFS_RWSEM; no net device attribute's show() takes RTNL, so the
removal's drain cannot wait on itself.
Block devices: a disk's partitions are registered and removed (their
sysfs entries, devtmpfs nodes, uevents) under the disk's `open_mutex`:
`Disk.open_mutex` -> KERNFS_RWSEM -> devtmpfs root i_rwsem. Their
attributes read the block device without it.

uevents (base/uevent.rs) broadcast with `ns::net::NET_NAMESPACE_LIST`
(spin Mutex, leaf; Linux net_namespace_list) taken only to snapshot
the namespaces, then each namespace's `NlTable.socks` -> `NlSock.rxq`;
`ksysfs::UEVENT_HELPER` is a spin leaf.

show()/store() run under an active reference (`KNode::get_active`),
not a lock. `KNode::remove` deactivates the subtree and sleeps until
active references drain (Linux kernfs_drain), with no lock held: a
caller must not hold a lock that a show()/store() of the removed nodes
takes (Linux lockdep's kernfs active "lock").

#### Mount Namespace & Mount Objects

**Location:** `fs/mount.rs`

The mount namespace uses reference counting for busy detection, following the
Linux `vfsmount.mnt_count` pattern:

| Field | Type | Purpose |
|-------|------|---------|
| `MntNamespace.root` (`ns/mod.rs`) | `RwLock<Option<Arc<Mount>>>` | Root of the namespace's mount tree (one per mount namespace) |
| `Mount.mountpoint` | `RwLock<Option<Arc<Dentry>>>` | Where this fs is mounted |
| `Mount.parent` | `RwLock<Option<Weak<Mount>>>` | Parent mount reference |
| `Mount.children` | `RwLock<Vec<Arc<Mount>>>` | Child mounts |
| `Mount.mnt_count` | `AtomicU64` | Open file reference count |
| `Mount.mnt_flags` | `AtomicU32` | MNT_NOSUID/NODEV/NOEXEC/READONLY/LOCKED; every write under `MOUNT_LOCK` (remount, reconfigure, pivot_root's MNT_LOCKED), read lock-free (open, exec, statfs) |
| `MOUNT_LOCK` | `SeqLock` (spin writer + sequence) | Linux mount_lock (lock_mount_hash): serializes `mnt_flags` writers and `s_mounts` changes; under NAMESPACE_SEM and s_umount; only `SuperBlock.s_mounts` is taken under it (no mount is dropped under it: `make_rdonly` releases its references after the unlock); the sequence is there for lockless readers |
| `Mount.t_flags` | `AtomicU32` | T_UNBINDABLE (Linux mnt_t_flags): written only under NAMESPACE_SEM write (change_propagation), read lock-free |
| `Mount.mnt_ns` | `AtomicU64` | Id of the mount's namespace (`MntNamespace.id`, never reused), 0 for none (Linux mnt_ns): written only under NAMESPACE_SEM write (commit_tree when a tree is grafted or propagated, the namespace root, a namespace copy; umount clears it), read by `check_mnt` under NAMESPACE_SEM; can_umount and remount read it first without, as Linux (umount repeats it under the lock) |
| `SuperBlock.s_flags` | `AtomicU32` | SB_RDONLY; set by mount/remount, read lock-free by permission checks |
| `Mount.writers`, `SuperBlock.s_writers` | `AtomicU64` (count + WRITE_HOLD bit 63) | Write-access holders (Linux mnt_writers + WRITE_HOLD): through a mount on the mount, for mountless internal objects on the superblock. A writer adds itself, spins while WRITE_HOLD is set, then checks read-only state (EROFS, backing out). Making a mount read-only (`set_flags`, Linux mnt_make_readonly) or the file system (`make_rdonly`, Linux sb_prepare_remount_readonly: every writable mount in `s_mounts` and `s_writers`) sets WRITE_HOLD under `MOUNT_LOCK`, is EBUSY with nothing changed if any count is nonzero, else sets the read-only flag before clearing the hold (Release). The writer's spin is invisible to lockdep; holders never wait for writers |
| `SuperBlock.s_mounts` | spin Mutex leaf | the superblock's mounts (Weak; Linux s_mounts), always under `MOUNT_LOCK`: a new mount is added there (`Mount::new`, Linux clone_mnt under lock_mount_hash), so a read-only remount's snapshot misses no mount a writer could use |

**Reference Counting (mntget/mntput):**

Each open `File` holds a reference to its mount via the `mnt` field:
- `File::new()` → `mntget()` increments `mnt_count`
- `File::drop()` → `mntput()` decrements `mnt_count`
- `is_mount_busy()` returns true if `mnt_get_count() > 0`
- Unmount fails with `EBUSY` if mount is busy (unless `MNT_FORCE`/`MNT_DETACH`)

**Lock Order for Mount Operations:**
```
1. the mountpoint's Inode.i_rwsem (attach: a dead directory is refused)
2. mount::NAMESPACE_SEM (write: attach, umount, namespace copy)
3. SuperBlock.s_umount (write: remount)
4. MntNamespace.root (read/write)
5. parent Mount.children (write for add/remove child)
6. Mount.parent (write for set/clear)
7. Mount.mountpoint (write for set/clear)
8. Dentry.d_lock (DentryInner.flags: write for the mount count)
```
MS_MOVE and pivot_root take the target's (put_old's) i_rwsem, then
NAMESPACE_SEM; pivot_root's chroot_fs_refs runs after both are
released (TASKLIST read to collect the tids, then each FsStruct.inner).
umount writes the filesystem back after releasing NAMESPACE_SEM
(writeback takes inode locks; Linux syncs in deactivate_super after
namespace_unlock). Mount ids come from `MNT_IDS` (spin Mutex leaf,
Linux mnt_id_ida) and `MNT_ID_UNIQUE` (atomic). Deviation: no global
(parent, mountpoint) hash; crossing scans the current mount's children.
Propagation (`fs/pnode.rs`) runs entirely under NAMESPACE_SEM (write):
peer groups live in `pnode::GROUPS` (spin Mutex, leaf: never held
across a call into the mount tree or a d_lock).

**Lock Order for Path Traversal (follow_mount, lookup_mnt):**
```
1. Mount.children (read) of the walk's current mount
2. child.mountpoint (read)
3. Dentry.d_lock (DentryInner.inode: read)
```
The walk carries a Path{mnt, dentry}: crossing looks only at the
current mount's children (Linux lookup_mnt); ".." at a mount root
reads `Mount.parent` and `Mount.mountpoint` (follow_dotdot).

`is_local_mountpoint` (rmdir, unlink, rename: EBUSY) takes the same
locks in the same order, one mount's `children` at a time, inside the
inode locks those syscalls hold (sleeping, outer): the parents' and the
victim's (rmdir/unlink) or the renamed and replaced inodes' (a
directory being replaced included, like Linux vfs_rename). `attach`
takes the mountpoint directory's i_rwsem (Linux lock_mount) around
linking the new mount in and refuses a directory marked dead
(`Inode::set_dead`, set by rmdir or a rename replacing it under that
same lock), so a mount and a removal of its mountpoint serialize:
i_rwsem -> MntNamespace.root -> Mount.children -> Mount.mountpoint.

#### VFS Locking Notes

**No RCU (future optimization):** The current implementation uses `RwLock` for all
VFS read paths. Linux uses RCU for lockless path lookup. This is acceptable for MVP
but may be a scalability bottleneck under heavy path lookup load.

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
filename_create):** `open.rs::create_in` (O_CREAT), `namei.rs::create_entry`
(mkdir, mknod, symlink, link) and `namei.rs::delete_entry` (unlink, rmdir)
take the parent's `Inode::lock()` first and, while holding it, look the name
up (`lookup_one`: dentry `d_lock`, then the file system's `lookup`), decide
EEXIST / "created by this call", run the DAC checks (`dac::may_create`,
`dac::may_delete`; these read the inode's atomic mode/uid/gid and, for the
new mode, the task's umask under `FsStruct.inner`) and perform the
operation. So the existence check, the permission decision and the change
are atomic with respect to other directory operations on that parent.
Order: parent `i_rwsem` -> `FsStruct.inner` (umask read, leaf) and parent
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
inode's `i_rwsem` -> dentry `d_lock` -> fs-internal locks. The victim
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
pub fn lock_two_nondirs(a: Option<&Arc<Inode>>, b: Option<&Arc<Inode>>) -> NondirsLock;

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
emit entries while holding spinlocks (ramfs `RamfsInodeData.children`
read lock, cgroupfs inode-data read locks; procfs emits unlocked), so
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
  do_truncate). Reads do not take it (Linux generic_file_read_iter).
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
  shared on a dcache miss (Linux lookup_slow); callers already holding
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
(`TimerBase`: an IrqSpinlock-protected 64-slot wheel, `running`, a wait
queue); a timer stays on the base of the CPU that first armed it. A
timer's expiry, `not_before` bound, slot and pending flag change only
under its base's wheel lock (one arm sets expiry and bound together),
where `run` reads them.

- **HARD** callbacks run in the CPU's tick with interrupts off and only
  wake tasks (`schedule_timeout`'s on-stack timer, Linux
  process_timeout). **SOFT** callbacks run in `ktimers/N`, process
  context (`Alarm`s run the network protocol timers); the tick only
  wakes the thread.
- Callbacks run with the base lock dropped and `running` set.
  `del_timer_sync` detaches and waits for a running callback (spinning
  for HARD, whose callback runs with interrupts off on another CPU;
  sleeping on the base's wait queue for SOFT, whose callback may
  sleep), so the owner may go once it returns; dropping a `TimerList`
  does that. Never call it from the timer's own callback, nor (SOFT)
  where sleeping is not allowed.
- Order: `Alarm.st` -> `TimerBase.wheel` (leaf).

#### High-resolution timers (time/hrtimer.rs; Linux kernel/time/hrtimer.c)

An `HrTimer` is embedded in its pinned owner and fires at an absolute
CLOCK_MONOTONIC or CLOCK_REALTIME ns time. Each CPU has a HARD and a
SOFT `HrBase`: `q`, an IrqSpinlock over one sorted intrusive list per
clock, and `running`. The CPU's clock event device runs one-shot,
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
  `timerfd::clock_was_set`: it snapshots the cancel-on-set timerfds
  under `CANCEL_LIST` (a spin leaf except for `setup_cancel`, which
  takes `CANCEL_LIST` -> `Timerfd.inner`), then locks each one's
  `inner` with the list dropped. Absolute realtime hrtimers see the new
  time at the next clock event (at most a tick away).
- `start` queues and reprograms with interrupts off (no migration or
  timer interrupt in between), on the starting CPU's base: it moves the
  timer there unless its callback is running on the old one (Linux
  switch_hrtimer_base). `HrTimer.base` changes only under the old base's
  lock, and every locker rechecks it after locking (`lock_base`, Linux
  lock_hrtimer_base). `cancel_sync` waits out a running
  callback (spinning for HARD, sleeping on the `ktimers/N` wait queue
  for SOFT); dropping an `HrTimer` does that.
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
  are atomics read without `Pipe.inner` (Linux pipe_readable /
  pipe_writable).

**Page Locking (Linux folio_wait_table Pattern):**

`PAGE_WAIT_TABLE: [WaitQueue; 256]` is hashed by page frame. `CachedPage::lock`
sleeps with `wait_event(|| !locked)` and retries its CAS; `unlock` and end of
writeback use `wake_all` (the bucket is shared by unrelated pages, so a
single wakeup could be consumed by the wrong waiter). **Early Boot
Fallback:** if scheduling is not yet enabled, page locking spins.

### 3.4 Namespaces

**Location:** `ns/mod.rs`, `ns/uts.rs`

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

`PidNamespace` and `CgroupNamespace` are immutable after creation (no
lock).

#### Locking Rules

1. **The NsProxy is a Task field** - `get_task_ns` clones the `Arc<NsProxy>`
   out (lock-free for the task itself, else under its alloc_lock);
   `init_task_ns` / `exit_task_ns` swap it under the alloc_lock (the
   task itself, or a fork child before it runs) and drop the old one
   after unlocking (a network namespace's teardown takes RTNL; nothing
   is released under the lock).

2. **Per-namespace data uses RwLock** - UTS name data is read-heavy (uname is
   called frequently) but rarely written (sethostname/setdomainname are rare).
   It is taken with no task lock held (after the clone out).

3. **clone/unshare** - `copy_namespaces()` reads the parent's, then
   installs the child's under the child's alloc_lock, never with a
   namespace lock held; it runs early in `do_clone()` (can fail on OOM).

#### Lock Order for Namespace Operations

```
Task.alloc_lock (clone the Arc<NsProxy> out, release; none for the
    task itself) then, with nothing held: UtsNamespace.name / MntNamespace.root /
    UidGidMap.extents (leaves)
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
3. CONSOLE_REGISTRY (held during console_write) - IrqSpinlock
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

The `PrintkWriter` struct holds `OUTPUT_LOCK` for the duration of formatting:

```rust
pub struct PrintkWriter {
    _guard: Option<IrqSpinlockGuard<'static, ()>>,
}

impl PrintkWriter {
    pub fn new() -> Self {
        if OOPS_IN_PROGRESS.load(Ordering::Acquire) {
            Self { _guard: OUTPUT_LOCK.try_lock() }
        } else {
            Self { _guard: Some(OUTPUT_LOCK.lock()) }
        }
    }
}
```

This ensures that `write!` macro invocations (which may call `write_str` multiple
times during formatting) produce atomic output.

**printkln! Atomicity:**

The `printkln!` macro uses a single `PrintkWriter` for both the message and newline:

```rust
macro_rules! printkln {
    ($($arg:tt)*) => {{
        let mut writer = PrintkWriter::new();
        let _ = write!(writer, $($arg)*);
        let _ = writer.write_str("\n");
        // OUTPUT_LOCK released when writer drops
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

`console::console_write()` holds `CONSOLE_REGISTRY` lock during `write_all()`:

```rust
pub fn console_write(data: &[u8]) {
    let registry = CONSOLE_REGISTRY.lock();  // IrqSpinlock
    if registry.has_console() {
        registry.write_all(data);
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

### 3.7 Signal Infrastructure

**Location:** `signal/mod.rs`, `signal/pending.rs`, `signal/syscall.rs`

The signal subsystem manages signal handlers (SigHand) and per-task signal state
(blocked masks, pending signals). It follows Linux's `sighand_struct` and signal
state patterns.

#### Signal Locks

| Variable | Type | Purpose |
|----------|------|---------|
| `Task.sighand` | `Option<Arc<SigHand>>` under TASKLIST | The task's handler table |
| `SigHand.users` | `TableCell<u32>` (TASKLIST) | Tasks whose `Task.sighand` it is, changed with that field (Linux sighand->count): exec copies a table with more than one (unshare_sighand) |
| `Task.sig` | `spin::Mutex<TaskSignalState>` (per task) | Blocked mask, private pending set, altstack (Linux siglock's per-task part) |
| `Task.thread_flags` TIF_SIGPENDING | atomic, recomputed under `Task.sig` | Pending-signal flag |
| `SignalStruct.shared` | `spin::Mutex<GroupPending>`, reached through `TaskSignalState.shared_pending` (the task's `Arc<SignalStruct>`); a flush on SIG_IGN (`flush_group_signal`) takes it alone, through the group's `SignalStruct` | Thread-group pending set and curr_target (Linux signal->shared_pending, curr_target) |
| `SigPending` list | `Option<Box<SigQueue>>` under the set's lock | Queued siginfo (Linux sigpending.list of struct sigqueue) |
| `SigHand.action` | `IrqSpinlock<Box<[SigAction]>>` (65 entries) | Signal handler table |
| `SignalStruct.rlim` | `IrqSpinlock<[RLimit; N]>` | Resource limits (leaf) |

#### Why SigHand.action Uses IrqSpinlock

Signal handlers may be queried from interrupt context:
- **SIGSEGV**: From page fault handler when accessing invalid memory
- **SIGFPE**: From divide-by-zero or floating point exception handler
- **SIGBUS**: From alignment fault handler
- **SIGTRAP**: From debug exception handler

Because these exceptions can occur at any time (including while holding other locks),
the signal handler table must use an IRQ-safe lock. The `IrqSpinlock` ensures that:
1. Interrupts are disabled during access
2. No deadlock can occur if a page fault happens while setting a handler

#### Locking Rules

1. **Per-task signal state has its own lock** - `get_task_sighand`
   clones the `Arc<SigHand>` out under TASKLIST; `with_task_signal_state`
   finds the task (the current one without TASKLIST, another under
   TASKLIST's read lock) and runs its closure under `Task.sig` (no
   sleeping, no user memory, no TASKLIST, nothing released in it).
   Deviation: Linux siglock is IRQ-safe and per thread group; hk's is
   per task, thread context only. Audit (T0): no interrupt handler
   sends a signal (the tty receive path is not driven from the UART
   IRQ, SIGIO comes from `kill_fasync` in thread context with no spin
   lock held, no SIGURG generation, POSIX timer/itimer expiry runs in
   `ktimers/N`, no tick-based SIGXCPU/SIGPROF, fault signals are sent by
   the faulting task with interrupts on). `send_signal` reports
   `SIGNAL:FAIL` if called with a nonzero interrupt depth (arm64 IRQ
   entry now counts the depth too).

2. **SigHand.action uses IrqSpinlock** - Can be safely accessed from synchronous
   exception handlers (page faults, etc.) and process context; a leaf.

3. **The group set before action** - `SigHand.action` may be read
   under `Task.sig` and `SignalStruct.shared` (a send's `sig_ignored`);
   dequeueing reads the action after both are dropped.

4. **Never hold IrqSpinlock while acquiring Mutex** - Would violate lock ordering.

5. **Queue entries are made and freed outside the locks** (Linux
   allocates its sigqueue GFP_ATOMIC under siglock; hk allocates under
   no spin lock): a sender allocates its `SigQueue` and charges the
   receiver's user (`UCOUNTS`) before taking `Task.sig`, the locked
   section only links it in, and an unused one is dropped after the
   lock is released. A dequeue unlinks its entry under the lock and the
   caller frees it (`Dequeued::info`) after; an exiting task's sets are
   swapped out under TASKLIST and `Task.sig` and freed after both, and
   an exiting task (PF_EXITING, read under `Task.sig`) gets no entries,
   so none outlives that flush. Senders run in thread context with no
   spin lock held (mqueue drops its notify lock before sending). A
   send first decides under `Task.sig` (then `SignalStruct.shared` and
   `SigHand.action`, the usual order) whether the signal is dropped
   (ignored, or non-RT and already pending: Linux prepare_signal,
   legacy_queue) and makes no entry then; the locked section decides
   again. The charge comes before the lock, not under it as in Linux,
   so while an entry that turns out unused (the state changed between
   the two decisions) is alive its user's count is one high: a racing
   send for the same user at its RLIMIT_SIGPENDING can see EAGAIN.
   Charging under `Task.sig` would put `UCOUNTS`, whose map allocates
   a node for a new user, under it; the window is one locked section
   and matters only at the limit.

6. **A group signal's thread is chosen with no lock held** (Linux
   complete_signal under siglock): after the signal is queued on the
   group set under the receiver's `Task.sig`, the threads are listed
   under TASKLIST (read) and dropped, then each candidate's `Task.sig`
   is taken alone to test wants_signal, and the chosen one's
   TIF_SIGPENDING is recomputed under it before the wakeup. A thread
   that blocks a group signal or starts exiting hands it on the same
   way after dropping its own lock (retarget_shared_pending). A thread
   that changes its mask between the test and the wakeup sees the
   signal when it recomputes TIF_SIGPENDING.

#### Lock Order for Signal Operations

```
1. TASKLIST (Task.sighand; read lock to find a task)
   ↓
2. Task.sig (spin Mutex, per task)
   ↓
3. SignalStruct.shared (spin Mutex, thread-group pending)
   ↓
4. SigHand.action (IrqSpinlock, handler table; leaf)
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
// Also share pending signals (thread group)
// Both reach the group's pending set through the same Arc<SignalStruct>
child.shared_pending = SharedPending(Some(signal.clone()));
```

#### Syscall Patterns

**rt_sigaction(2):** Get/set signal handlers:
```rust
let sighand = get_task_sighand(tid)?;  // cloned out under TASKLIST
let actions = sighand.action.lock();    // IrqSpinlock
let old = actions[sig].clone();
actions[sig] = new_action;
```

**rt_sigprocmask(2):** Modify blocked mask:
```rust
with_task_signal_state(tid, |state| {   // Task.sig (current: no TASKLIST)
    state.blocked = new_mask;
});                                     // TIF_SIGPENDING recomputed
```

**kill(2)/tgkill(2):** Send signal to task (`send_signal`, process context
only):
```rust
let deliverable = with_task_signal_state(tid, |state| {  // TASKLIST read
    if sig_ignored(..) { return false }   // to find tid, then Task.sig;
    state.pending.add(sig);               // SIG_IGN / default-ignore: dropped
    !state.blocked.contains(sig)
});                                       // TIF_SIGPENDING recomputed
// both released, then:
signal_wake_up(tid, WakeMode::Interruptible) // try_to_wake_up(&Task) or
                                             // kick_process
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
under Task.sig and sets TIF_RESTORE_SIGMASK (current task only, an atomic
bit: no lock); a handler frame takes the saved mask and clears the bit,
otherwise `restore_saved_sigmask` puts it back under Task.sig on the way
out (Linux set_restore_sigmask / restore_saved_sigmask_unless).

#### Thread-Group Exit (Linux do_group_exit, zap_other_threads, de_thread)

No new lock. `SignalStruct.group_exit` (an `AtomicU64`, changed only by
compare-and-swap) holds the group's state: running, exiting with a wait
status (Linux SIGNAL_GROUP_EXIT + group_exit_code), or a thread's exec
ending the others (group_exec_task). The first exit_group or fatal
signal wins the swap; a fatal signal also overrides an exec's
de_thread, exit_group does not.

- `zap_threads` queues SIGKILL in each live thread's private pending
  set and sets its TIF_SIGPENDING under TASKLIST, collects the tids,
  drops TASKLIST, then wakes each (`WakeMode::Fatal`: interruptible
  and killable sleeps), as `send_signal` does (TASKLIST is never held
  across a wakeup where it can be dropped first).
- A thread cloned into a group whose state is set gets SIGKILL after
  `clone_task_signal` set up its signal state (`zap_new_thread`): the
  state is set before a zap takes TASKLIST, so either the zap saw the
  new thread or the clone sees the state.
- The zombie leader keeps its `SignalStruct` until reaped (the group's
  status); the reaper reads it under TASKLIST and releases the Task
  after dropping it.
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
  pending, and a parent the signal wakes finds it. The process's
  pidfds see its exit in the section of its last thread's exit, before
  any notice (`mark_pidfd`). Under the write
  lock: the receiver and signal, the autoreap decision (the parent
  process's SIGCHLD action, in the `SigHand` of the thread the signal
  goes to) and the queueing (`signal::send_held`: TASKLIST →
  Task.sig → SignalStruct.shared → SigHand.action, the order above);
  an autoreaped zombie leaves the task list there too (Linux
  EXIT_DEAD). Its `SigQueue` entry is made and charged before the lock
  (`notify::Entry`, for the receiver's user found under the read lock;
  none when no signal is sent: a parent that ignores SIGCHLD);
  if the receiver's user or the signal changed by the time the write
  lock is held (`Entry::fits`), the lock is dropped and a new entry made
  before anything changes. After the lock: the unused entry is freed,
  signalfd readers and the receiving thread are woken
  (`Posted::finish`: complete_signal takes TASKLIST itself), the
  autoreaped Task released.
- de_thread (exec) holds cred_guard (sleeping, outermost) while it waits
  on CHILD_EXIT_WQ (killable) until every other thread is released and
  the leader is a zombie (`exec_waits`, Linux notify_count: a traced
  zombie thread waits for its tracer's reap, whose release wakes the
  queue); it holds no spinlock. A thread blocked on that cred_guard (its own exec, or an
  attach to the group) sleeps interruptibly, so the SIGKILL de_thread
  sends ends it. The old leader and exited threads are removed under
  TASKLIST and released after it.

#### Reference Counting

`SigHand` uses `Arc` for reference counting:
- Tasks share `Arc<SigHand>` through `Task.sighand`
- Clone with CLONE_SIGHAND: child shares parent's `Arc<SigHand>`
- Clone without CLONE_SIGHAND: new `Arc<SigHand>` with deep-cloned handlers
- Exit: the Arc drops with the task's entry

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
(`WakeQ::wake_up` -> try_to_wake_up; no TASKLIST).
```

Keys (`make_key`, Linux get_futex_key) are made before any bucket
lock: a private futex is (mm, address), with no lock; a shared one
takes the mmap_lock for reading to find its VMA (and, under it, the
file's dentry `d_lock` for its inode) and drops it before locking a
bucket: mmap_lock and bucket locks are never nested. A shared key in a
shared mapping is the backing `Shmem` or inode, named by its `KeySeq`
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
1. Called from task exit path in `task/percpu.rs`
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

All three use `IrqSpinlock` for IRQ safety - see Section 3.6 for details.

#### Per-TTY Locks

Each `Tty` struct contains:

| Lock | Type | Purpose |
|------|------|---------|
| `termios` | `Mutex<Termios>` | Terminal I/O settings (baud, echo, etc.) |
| `ldata` | `Mutex<NTtyData>` | N_TTY read ring and edited line (Linux `n_tty_data`) |
| `ctrl` | `Mutex<TtyCtrl>` | Session, foreground group, window size (Linux `ctrl.lock` + `winsize_mutex`) |
| `flip` | `IrqSpinlock<Flip>` | Bytes from the UART interrupt handler (Linux `tty_bufhead`) |
| `buf_lock` | `sync::Mutex<()>` (sleeping) | Feeding `flip` to N_TTY vs input flushes (Linux `tty_bufhead.lock`); outside `ldata` |
| `read_lock` | `sync::Mutex<()>` (sleeping) | One N_TTY reader at a time, held across the whole read and its sleeps (Linux `atomic_read_lock`): a canonical line copied out in pieces goes to one reader; outermost tty lock, taken before `ldata` |
| `write_lock` | `sync::Mutex<()>` (sleeping) | One writer at a time, held across the whole write(2) (Linux `atomic_write_lock`, tty_write_lock): another writer's bytes never land inside it; outermost on the write side, taken before the TOSTOP check (`termios`, TASKLIST → `ctrl`, SIGTTOU) and the driver writes; O_NONBLOCK try-locks (EAGAIN), else interruptible. Thread context only: printk's console write and N_TTY echo do not take it (as Linux). Not nested with `read_lock` or `buf_lock` |
| `read_wait` | `WaitQueue` | Readers and pollers waiting for input |
| `fasync` | `FasyncList` (sleeping, 3.11) | O_ASYNC files (Linux `tty->fasync`): N_TTY input sends their SIGIO after dropping `ldata`, under `buf_lock` |

The `Mutex`es are spin locks taken in thread context only, briefly, one
at a time except `ldata` → `termios` (input processing reads termios and
set_termios swaps it under `ldata`, so an ICANON change is applied
atomically, as Linux's `termios_rwsem`), and never across a signal, a
sleep or a driver write: N_TTY collects echo and ISIG signals under
`ldata` and writes/sends them after dropping it; the SIGWINCH of
TIOCSWINSZ and the SIGHUP/SIGCONT of giving up a controlling tty are sent
after `ctrl` is dropped. A reader's wait condition takes `ldata`.

Input (`tty/flip.rs`, Linux tty_buffer.c): the UART handler (IRQ
context, under `IRQ_TABLE`) drains its FIFO into `Tty.flip` (leaf), sets
`flip::PENDING` and wakes `flip::FLIP_WAIT`; the `ttyflip` kernel thread
takes the bytes out (`flip`, released before the line discipline runs)
and feeds them to N_TTY (`ldata`), then wakes `read_wait`. It is the only
consumer, so input stays in order. Order: `IRQ_TABLE` → `Tty.flip`;
`IRQ_TABLE` → wait queue head (the wakeup).

`tty::jobctrl::CTTY_LOCK` (spin `Mutex`, thread context; Linux tty_lock
+ siglock in `__proc_set_tty`/`session_clear_tty`) serializes giving and
taking controlling ttys (open without O_NOCTTY, TIOCSCTTY, TIOCNOTTY, a
session leader's exit), so a session never gets two. `Tty.ctrl` holds
the session and foreground group as `Arc<pid::Pid>` references (Linux
get_pid), read from the caller's task under TASKLIST. Order (Linux
tty_lock → tasklist_lock → ctrl.lock): `CTTY_LOCK` → TASKLIST (read) →
`Tty.ctrl`. TIOCSPGRP checks that the group is in the caller's session
and stores it with TASKLIST read-held across both, so the group cannot
change in between; the pid lookup (PIDMAP_LOCK) comes before TASKLIST.

#### Graphics Console Lock

| Lock | Type | Purpose |
|------|------|---------|
| `GfxConsole.state` | `Mutex<GfxConsoleState>` | Framebuffer surface + cursor position |

The graphics console uses a **single lock** protecting both cursor position and
framebuffer surface. This ensures atomic character rendering and cursor updates.

#### Lock Ordering

```
OUTPUT_LOCK (IrqSpinlock, held for entire formatted message)
    ↓
PRINTK (IrqSpinlock, ring buffer, brief hold during write)
    ↓
CONSOLE_REGISTRY (IrqSpinlock, console dispatch to drivers)
    ↓
Per-TTY locks (Mutex: termios, ldata, ctrl) - independent between TTYs
    ↓
GfxConsole.state (Mutex, if graphics console receives output)
```

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

#### Device IRQ Registration (arch/{x86_64,aarch64}/irq.rs)

| Lock | Type | IRQ class | Order |
|------|------|-----------|-------|
| `IRQ_TABLE` (per arch) | `IrqSpinlock` | taken in IRQ (`dispatch_irq`) and process context (register/unregister) | leaf except for the interrupt-controller MMIO it programs; handlers run under it |

Generic interface (`crate::arch::irq`): `register_irq_handler(irq,
Arc<dyn crate::irq::IrqHandler>, id)` (shareable; first handler unmasks
the line, last one masks it; the table holds the handler's device state
while registered, `IrqFn` wraps a stateless fn), `unregister_irq_handler`
(hands the reference back, dropped by the caller after the table lock),
`pci_intx_irq(bus, dev, fn, pin, line)`. `PciDevice::register_irq_handler`
uses these on both arches. Every handler of a shared line is called; a line
nobody claims 100000 times in a row is masked (stuck level INTx).

- aarch64: SPIs are configured by `gic::enable_spi` (level/edge in ICFGR,
  priority 0x80, Group 1, IROUTER -> CPU 0, ISENABLER); PCI INTx comes from
  the host bridge DT `interrupt-map`/`interrupt-map-mask` parsed at boot
  (`arch/aarch64/pci_irq.rs`, matching in `hw/pci/intx.rs`), else the QEMU
  virt swizzle INTID 35 + (slot + pin - 1) % 4.
- x86-64: legacy 8259 PIC with the firmware-assigned config-space Interrupt
  Line (QEMU `pc`). Real hardware in APIC mode (Dell OptiPlex 3020 target)
  needs IOAPIC + ACPI `_PRT` routing (not implemented).
- Handlers run in IRQ context with the table lock held: they must only ack
  the device, touch atomics/IrqSpinlocks and wake threads; they must not
  register/unregister IRQs.

#### DMA API (hw/dma.rs)

The backend (`DMA_OPS`) is set once at boot (`spin::Once`) and read
without a lock, so the streaming calls (`dma_map_single`/`unmap`, sync)
are IRQ-safe: blk-mq dispatch and completion run them in hardirq
context. `dma_alloc_coherent` allocates frames (thread context only).

#### USB Subsystem

**Location:** `hw/usb/`

| Lock | Type | Purpose |
|------|------|---------|
| `USB_CONTROLLER` | `Mutex<Option<XhciController>>` | Global xHCI controller access; the USB console's transfer only `try_lock`s it (busy, by this CPU's printk or another's: the output is dropped), so a printk under it never deadlocks |
| `XHCI_IRQ_STATE.*` | `AtomicU64`, `AtomicBool` | ISR state (lock-free) |
| `PORT` (hw/usb/serial.rs) | spin `Mutex<Port>` | The USB serial console's device (slot, bulk OUT endpoint; none while no FTDI port is the console) and DMA buffer: the console write `try_lock`s it (busy: the output is dropped) and holds it across the bulk transfer, so it orders before `USB_CONTROLLER`; probe and remove take it alone (remove after `unregister_console` released `CONSOLE_REGISTRY`), and remove's clearing waits out a write in progress |

DMA buffers never live on a kernel stack (stacks are not in the linear
map, `mm::vmstack`; `DirectDmaOps` panics on one): the mass-storage
CBW/CSW and the INQUIRY/READ CAPACITY data are heap buffers, the
console's output goes through `PORT`'s buffer; control transfers
bounce through a coherent buffer of their own.

Enumeration (descriptor reads, Evaluate Context, Configure Endpoint,
SET_CONFIGURATION) runs in the xHCI probe on the controller it owns,
before it is published in `USB_CONTROLLER`: no lock. The devices are
then registered under the PCI device's lock: the root hub `usb1`, its
generic driver's probe adding the interfaces under `usb1`'s device
lock, then each port's device the same way, so device locks nest PCI
function -> usb_device -> interface (parent before child, as Linux);
interface drivers' probes (usb-storage's SCSI scan) take
`USB_CONTROLLER` per transfer under them.

Unbinding the xHCI runs the same nesting top-down (Linux
usb_remove_hcd): under the PCI device's lock each USB device is
deleted, the root hub last; its generic driver's release, under its
lock, deletes the interfaces, whose drivers' removes run under the
interface's lock (usb-storage: the disk's `open_mutex` for
del_gendisk, then `UsbMscDevice.state`; ftdi_sio: `CONSOLE_REGISTRY`,
then `PORT`). The controller is then taken out of `USB_CONTROLLER`
(drivers' transfers fail with no device from there on) and stopped
with no lock held: slots disabled, halted, reset, the IRQ handler
unregistered (`IRQ_TABLE`, which waits out a running handler), memory
freed.

**ISR Pattern:** The xHCI ISR sets `interrupt_pending` atomic but does NOT acquire
`USB_CONTROLLER` mutex. This avoids IRQ-context deadlock since the mutex is not
IRQ-safe.

#### Block Device Subsystem

**Location:** `block/` (`blkdev.rs`, `blk_mq.rs`, `genhd.rs`,
`part/`), `hw/virtio/blk.rs`, `fs/{blkdev_ops,devtmpfs}.rs`,
`sync/completion.rs`

Linux model (block/bio.c, blk-mq.c, genhd.c): a bio is submitted from
thread context, the driver completes it from its interrupt handler and
`bio_endio` runs `end_io` there (hardirq). `submit_bio_wait` sleeps on a
`Completion` that `end_io` completes.

| Lock | Type | IRQ class | Order |
|------|------|-----------|-------|
| `Disk.open_mutex` | `sync::Mutex<OpenState>` (sleeping; Linux disk->open_mutex) | thread only | outermost block lock; holds the count of open partitions (Linux open_partitions, plain), and each `BlockDevice.openers` (an atomic on the device, as Linux bd_openers) and soft block size (BLKBSZSET) change only under it: block device open/release (files, and the kernel opens of a mount (`SuperBlock.s_bdev`) and of active swap: `BdevHandle`), partition scans (and rescans, BLKRRPART), disk removal (`del_gendisk` drops its devices under it); I/O, `BLKDEV_REGISTRY`, `MAJORS` and the devtmpfs root's `i_rwsem` are taken under it |
| `BLKDEV_REGISTRY` | spin `RwLock` (dev_t -> block device; global like Linux's bdev map) | thread only | leaf |
| `MAJORS` | spin `Mutex` (block majors, register_blkdev) | thread only | leaf |
| blk-mq software queue (`BlkMq.ctxs[cpu]`) | `IrqSpinlock<BioList>`, one per CPU | thread (submit) | leaf: never taken with the hardware queue lock held; its pending bit in the hardware queue's `ctx_map` (Linux) is set and cleared under it, and a run visits only set bits (one that misses a bit being set is followed by the submitter's own run) |
| blk-mq hardware queue (`BlkMq.hctxs[i]`) | `IrqSpinlock` over the dispatch list, the driver queue (virtio-blk: one virtqueue and its tags; Linux virtio_blk_vq.lock), the in-flight count and the dying flag | thread (dispatch, drain, release) and hardirq (completion, restart) | leaf: `queue_rq`/`complete` only touch the ring, MMIO and the lock-free DMA API (`DMA_OPS` is a `Once`), never allocate or sleep; taken under `IRQ_TABLE` in the ISR |
| `BlkMq.drained` | `WaitQueue` (Linux mq_freeze_wq) | woken from hardirq (the completion that empties a dying queue, after its lock is dropped); waited in thread context (`del_gendisk`, no lock held) | its head lock -> run-queue lock; the condition takes each hardware queue lock alone |
| `Completion.done` | `IrqSpinlock<u32>` | any context | -> its wait queue head -> run-queue lock (the wakeup is issued under it, Linux complete()) |
| `RamDisk.pages` | spin `Mutex` | thread only (bio-based driver) | leaf |

Rules:

- **Disk removal (`del_gendisk`, Linux):** under `open_mutex` every
  hardware queue is marked dying (nothing reaches `queue_rq` after,
  pending bios end with EIO) and the block devices are dropped; then,
  with no lock held, it sleeps on `BlkMq.drained` until the started
  requests complete. The driver's remove then frees the IRQ, takes its
  queues back (`BlkMq::release`) and resets the device before freeing
  the rings (`VirtioDevice::del_vqs`).
- **end_io runs in hardirq context** (virtio-blk) or in the submitter's
  thread (bio-based drivers: ramdisk, USB sd). It may only complete a
  `Completion`, touch atomics and wake; the bios are ended after the
  hardware queue lock is dropped, so `end_io` can resubmit.
  `submit_bio_wait`'s `end_io` hands the bio back and completes last:
  once `Completion::wait` returns the waker no longer touches the
  waiter's stack.
- **Boot I/O sleeps:** the scheduler runs and interrupts are on before
  driver probe (main.rs: the boot context is pid 1 by then, Linux
  kernel_init), so the boot partition scan's `submit_bio_wait` sleeps on
  its completion like any other.
- **devtmpfs nodes under `open_mutex`:** Linux hands node updates to
  devtmpfsd; hk creates/removes them in the caller (probe, rescan), under
  the devtmpfs root's `i_rwsem`. No path holding a directory `i_rwsem`
  takes `open_mutex` (a block device is opened after the path walk), so
  `open_mutex -> i_rwsem` cannot invert.
- **Block device page cache (`BlockDevice.bd_inode`, Linux
  bd_mapping):** device-file I/O and vfat metadata go through it (3.2
  Per-inode page cache); pages are read and written synchronously
  under their page lock, never under a spinlock. The last opener's
  release writes it back and drops it under `open_mutex` (Linux
  blkdev_flush_mapping): open_mutex -> page lock -> i_pages.

#### Network Subsystem

**Location:** `net/`, `net/core/dev.rs`, `ns/net.rs`

**Execution model (NAPI-like, no softirqs).** No protocol code runs in
interrupt context. A NIC ISR only reads/acks its interrupt cause, masks the
device's interrupts and calls `napi_schedule()`. Per-CPU `softnet/N`
kthreads (one per CPU with a scheduler, `kthread_run` bound to CPU N) poll
the scheduled NAPI contexts (weight 64, 300 packets per round, then
`yield_now()` if work remains) and the CPU's `netif_rx` backlog, calling
`netif_receive_skb()` -> EtherType handler (`ip_rcv`, `arp_rcv`) -> TCP/UDP/
ICMP. `lo` transmits with `netif_rx()` into the sending CPU's backlog; the
transmit path therefore never re-enters the receive path. A sending socket
syscall then runs `netif_rx_flush_local()` at a point where it holds no
locks (Linux runs pending softirqs at `local_bh_enable()` after
`dev_queue_xmit`), so loopback data is normally queued at the peer before
`sendto()` returns. A received packet's namespace is its device's
(`skb.net()`), never `current_net_ns()`; a socket's is `Sock.net`.

Today all device IRQs are routed to CPU 0 (PIC / GIC IROUTER), so
received traffic for eth0 runs on `softnet/0`; `lo` traffic goes to the
backlog of the sending task's CPU, whichever that is. The locks below do
not rely on either.

| Lock | Type | IRQ class | Notes |
|------|------|-----------|-------|
| `Softnet.poll_list` (per CPU) | `IrqSpinlock<VecDeque<Arc<Napi>>>` | taken in IRQ (`napi_schedule`) and by `softnet/N` | leaf; capacity reserved by `netif_napi_add`, so the ISR never allocates |
| `Softnet.wq` (per CPU) | `WaitQueue` | woken from IRQ | leaf (see Wait Queues) |
| `Softnet.backlog` (per CPU) | `spin::Mutex<VecDeque<Box<SkBuff>>>` | thread only (`netif_rx`, `softnet/N`, inline flush) | leaf; max 1000 packets, then drop + `rx_dropped` |
| `Softnet.busy` (per CPU) | `AtomicBool` | thread only | one task processes a CPU's backlog at a time (softnet/N or an inline `netif_rx_flush_local`); a flush that finds it set leaves the packets to the running one. softnet/N does not count a backlog held by a flush as work (it would spin until the flush ends, e.g. while the flusher sleeps on a socket lock); the flusher clears it (Release) before its last backlog check and wakes softnet/N if packets remain, and softnet/N rechecks it (Acquire) after queueing on `Softnet.wq`, so no wakeup is lost |
| `dev::TIMER_DUE` | `AtomicBool` | thread (an Alarm callback on `ktimers/N` sets, softnet/0 clears) | protocol timers are due: softnet/0 runs `tcp::timer::run` with no lock held |
| `Napi.sched`, `Napi.disable` | `AtomicBool` | IRQ + thread | `sched` set by `napi_schedule` (only the setter queues it), cleared by `napi_complete_done` (a SeqCst RMW: a full barrier before the driver re-checks its pending causes, Linux cmpxchg), held by `napi_disable` (driver `stop`, RTNL held, sleeps until a running poll completes) until `napi_enable` (driver `open`); `disable` makes softnet complete an over-budget poll instead of requeueing it |
| `NetDevice.running` | `AtomicBool` | thread (RTNL writers; NAPI poll readers) | Linux __LINK_STATE_START (`netif_running`): set before the driver's `open`, cleared before its `stop`; polls re-enable device interrupts only while set, checked under the driver's `rx` lock that `stop` takes to mask, so open/close never strand a device masked or leave a stopped one unmasked |
| `PTYPE_BASE`, `PTYPE_ALL` | `spin::RwLock` (`Vec<..>` / fixed array of taps) | thread only | leaf; handlers copied out, called after unlock. Taps (AF_PACKET) run from `netif_receive_skb` and from `dev_queue_xmit` (PACKET_OUTGOING), i.e. possibly under a caller's socket or neighbour-free transmit path: they take only the AF_PACKET leaves below |
| `NAPI_LIST`, `SOFTNET_THREADS` | `spin::Mutex<Vec<..>>` | thread only | leaf; registration (`netif_napi_add`/`netif_napi_del`, the latter only for a disabled NAPI) |
| `Sock` (`net/sock.rs`, in every protocol socket) | atomics + `Sock.wq` (`WaitQueue`) | any (wakeups) | error, shutdown, buffer sizes, timeouts, SOL_SOCKET flags, SO_LINGER (switch and time in one word); one wait queue per socket for readers, writers, connect/accept and pollers (`sk_data_ready`/`sk_write_space`/`sk_error_report` = `wake_poll` keyed with their events, `sk_state_change` = `wake_all`), woken after the socket's own protocol locks are dropped; another path may wake it under its own locks (an AF_PACKET tap queueing to a packet socket under a transmitting TCP socket's `cb`): `Sock.wq` is an IrqSpinlock taking only run-queue locks, so that never inverts |
| sockfs inode `private` | `spin::RwLock` (VFS, `Inode.private`) | thread only | read per socket file operation (`sock_of`) to reach the protocol socket; leaf |
| `TcpSock.cb` (`net/tcp/mod.rs`) | `spin::Mutex<Inner>` | thread only (softnet input, softnet/0 timers, socket calls) | the TCP socket lock: Linux `bh_lock_sock` plus the `tcp_sock` state it guards (the whole I/O-free `TcpCb`: state, sequence space, send/receive/out-of-order queues, RFC 7323 option state, delayed-ACK state, RTO, all timers, the connect-in-progress flag (`Inner.connecting`, Linux SS_CONNECTING: connect decides EALREADY/EISCONN/EINPROGRESS under it), the shutdown bits (set by shutdown and cleared by disconnect under it, as inet_shutdown/tcp_disconnect under lock_sock; `Sock.shutdown` is read locklessly by poll), the IPPROTO_TCP options (`TcpCb.opts`; the separate `TcpSock.opts` leaf is gone); tuple, port ownership, listener link). Held for one bounded step: never across a sleep or a user copy. The step's `Out` is applied before the unlock (Linux transmits under the socket lock): error and shutdown bits are published and segments transmitted under it (cb -> FIB / neighbour / device TX, which never re-enter a socket lock), so one connection's segments are never reordered across CPUs; only wakeups follow the unlock. Segment input re-checks under it that the socket still has the tuple it was found by. A listener's is taken before its new child's (creating it, and sending its SYN-ACK); a child never takes its listener's `cb` (it queues itself under the listener's `queue` leaf and the listener is woken after the child's unlock) |
| `TcpSock.rd` | `sync::Mutex<()>` (sleeping) | thread only (recvmsg) | serializes readers across peek -> user copy -> consume, so a faulting copy leaves the data queued (reader half of Linux `lock_sock`); a MSG_TRUNC reader that only discards takes it too; held only for that step, never across a wait; above `cb` |
| `TcpSock.queue` | `spin::Mutex<Option<Accept>>` | thread only | leaf: a listener's SYN_RECEIVED children and accept queue; taken under the listener's or a child's `cb` |
| `TimeWait.inner` (`net/tcp/timewait.rs`) | `spin::Mutex` | thread only | a TIME_WAIT entry's queue-less control block + timer slot; same position as `TcpSock.cb` (taken instead of it, never with it): its ACKs/RSTs are transmitted under it, then TCP `TIMERS` / `Alarm.st` as for `cb` |
| TCP `TIMERS` (`net/tcp/timer.rs`) | `spin::Mutex<BTreeMap>` | thread only | leaf under `cb`/`TimeWait.inner`: (deadline, id) -> weak owner. `rearm` drops it before arming the `timer::Alarm` (so `cb` -> `Alarm.st` -> timer base, never `TIMERS` -> `Alarm.st`); the Alarm only wakes softnet/0 (`dev::raise_timer`), which takes due entries out and runs each under its owner's lock with `TIMERS` dropped |
| TCP tables `TcpTables.{bhash, ehash, lhash}` (`net/tcp/table.rs`, per netns) | `spin::RwLock` | thread only | `bhash` -> `ehash` (connect picks a port and inserts its four-tuple atomically); `lhash` -> `Inet.addr` (listener lookup scores candidates' bound address and device); candidates' `Inet.addr` and `Sock` flags are read under `bhash`; never a socket `cb` under a table lock (/proc/net/tcp copies the entries out, drops the table locks, then takes each `cb` / `TimeWait.inner` in turn) |
| `Sock.errq` (`net/sock.rs`) | `spin::Mutex` | thread only (softnet ICMP error delivery, recvmsg MSG_ERRQUEUE, poll) | leaf: IP_RECVERR queue, bounded by SO_RCVBUF (own charge); the wakeup follows the unlock |
| `IcmpRate.st` (`net/icmp.rs`, per netns) | `spin::Mutex` | thread only | leaf: global + per-destination (bounded, 256) ICMP error token buckets |
| `UdpSock.op`, `PingSock.op` | `spin::Mutex<()>` | thread only | datagram socket lock (bind/connect/disconnect/autobind; connect autobinds within the same hold); never across a sleep or a transmit; taken before the protocol's port/identifier table |
| `RxQueue.q` (`net/dgram.rs`: UDP, ping, raw receive queues) | `spin::Mutex` | thread only (softnet enqueue, recvmsg) | leaf; bounded by SO_RCVBUF (`rmem` atomic: charged before the push, uncharged after the pop; a purge uncharges exactly what it took) |
| `RawTable.socks` (`net/raw.rs`, per netns) | `spin::RwLock` | thread only | raw sockets by protocol; delivery and ICMP-error fan-out clone the matching `Arc`s (reading their `Inet.addr`) and queue after dropping it; `RawSock.filter` is an atomic |
| `PacketTable.socks` (`net/packet/`, per netns) | `spin::RwLock<Vec<Arc<PacketSock>>>` | thread only (taps in softnet or a transmitting task, socket create/close) | leaf; the tap clones the matching `Arc`s and queues after dropping it (a global atomic count skips all work when no packet socket exists) |
| `PacketSock.rxq` (`PktQueue.q`), `PacketSock.filter` | `spin::Mutex` / `spin::RwLock` | thread only | leaves; the queue is bounded by SO_RCVBUF (`rmem` atomic, drops counted); the filter `Arc` is cloned out and the read guard dropped before it runs (a separate statement: an `if let` scrutinee's guard would live across the run); the binding (protocol, ifindex) and flags are atomics |
| `PacketSock.mclist` | `spin::Mutex<Vec<Mreq>>` | thread only | PACKET_ADD/DROP_MEMBERSHIP list, changed only under RTNL (Linux packet_mc_add takes rtnl_lock); RTNL -> `mclist`, dropped before the device's promiscuity changes (`NetDevice.set_promiscuity`, RTNL held, may call the driver) |
| `PacketSock.bind` | `AtomicU64` (protocol << 32 \| ifindex) | thread only (bind, device unregister; read by receive, send, getname) | the binding (Linux po->num/ifindex under po->bind_lock): changed only by compare-exchange from the value the change was decided on, so bind and unregister never undo each other. bind looks the device up again after storing: unregister unlists a device before visiting its sockets, so either that visit sees the new binding or the lookup misses the device and bind moves the socket to ifindex -1 (Linux "unlisted") |
| `PingTable.socks` (`net/ping.rs`, per netns) | `spin::RwLock` | thread only | ping sockets by echo identifier; receive/error lookups clone the `Arc` and queue after dropping it; reads candidates' `Inet.addr` under it (order table -> Inet.addr) |
| `Inet.addr` (`net/af_inet.rs`) | `spin::Mutex` | thread only | leaf: addresses/ports of a TCP or UDP socket; read under the UDP/TCP port tables during lookups, so bind sets the addresses before publishing the port in a table (reset on failure; Linux inet_bind) |
| `RTNL` (`net/rtnl.rs`) | `sync::Mutex<()>` (sleeping, Linux rtnl_mutex) | thread only (syscalls, kernel config; never softnet) | OUTERMOST network lock: serializes all configuration changes (link up/down + MTU, addresses, routes, neighbour entries, device naming + registration via `alloc_netdev`/`register_netdev`) from netlink, SIOCS* ioctls and the kernel. Functions needing it take `&RtnlGuard`. Never taken while any spinlock is held (a socket's last close, which may take it for AF_PACKET memberships, runs only after the fd table lock is dropped). Holders may sleep (user copies such as SIOCADDRT's `rt_dev` name, like Linux rtentry_to_fib_config; driver open/stop waiting for NAPI) but never take a socket lock (`sk_lock`) and never wait for packets |
| `NetNamespace` tables (`devices`, `loopback`), `UdpTable.socks` | `spin::RwLock` | thread only | reached only via lookup/insert methods returning owned values / `Arc` (no guard escapes: RCU-ready); the UDP port table reads each candidate's `Inet.addr` under its lock |
| `Fib.tables` (`net/inet/fib.rs`, per netns) | `spin::RwLock` | thread only | leaf; written only under RTNL; read by input/output routing (softnet, socket syscalls, possibly under `sk_lock`) and dumps; returns `Arc<FibEntry>` clones; notifications are sent after the guard is dropped |
| `NetDevice.addrs` (IPv4 list; IPv6 later) | `spin::RwLock` | thread only | leaf; written only under RTNL (`inet::ifaddr`), read via snapshots (`inet_addrs()`) |
| `NeighTable.hash` (`net/core/neigh.rs`; `NetNamespace.arp`, IPv6 ND later) | `spin::RwLock` | thread only (softnet, socket output, ktimers/N) | (ifindex, address) -> `Arc<Neighbour>`; lookups drop the guard; GC/flush take each entry's `inner` under the write lock (order hash -> inner) |
| `Neighbour.inner` | `spin::Mutex` | thread only | leaf: NUD state + bounded unresolved queue (unres_qlen_bytes). Never held while transmitting, soliciting, reporting errors or arming the neighbour `Alarm` (the next deadline is read under it, armed after): state changes return actions run after the unlock |
| neighbour `TABLES` | `spin::Mutex` | thread only | leaf (snapshot of registered tables). One `timer::Alarm` runs all tables' due entries and GC on `ktimers/N`, armed with no table lock held |
| `timer::Alarm.st` (neighbour, IP reassembly, TCP) | `spin::Mutex` | thread only | held across arming its SOFT `TimerList` (-> the timer base's IrqSpinlock); otherwise leaf |
| `FragTable.st` (`net/inet/frag.rs`, per netns) | `spin::Mutex` | thread only (softnet, reassembly timer on ktimers/N) | leaf: reassembly queues + memory charge; completed datagrams are delivered and expiry ICMP errors sent after it is dropped. Reassembly `TABLES` (registered namespaces) is a leaf `spin::Mutex` |
| `PmtuCache.m` (`net/inet/route.rs`, per netns) | `spin::Mutex` | thread only | leaf: learned path MTUs, read by `route::output` (possibly under a socket lock), written by ICMP frag-needed handling |
| `NlTable.socks` (`net/netlink`, per netns) | `spin::RwLock` | thread only | leaf; bound netlink sockets by (protocol, portid); lookups return `Arc` clones. A bind/autobind checks the socket's `bound` and publishes its portid under the write lock (Linux netlink_insert), so concurrent binds of one socket cannot both insert |
| `NlSock.dump` | `spin::Mutex<Option<Dump>>` | thread only (sender's `sendmsg`, reader's `recvmsg`) | running dump cursor; held while it snapshots devices/FIB/ARP and while its part is queued to `rxq` (keeps parts ordered); readers are woken after it is dropped; never with RTNL |
| `NlSock.rxq`, `NlSock.dst` | `spin::Mutex` | thread only | leaf; replies, dump parts and notifications are pushed under it (each charged to rcvbuf first), `Sock.wq` is woken (`data_ready`) after it is dropped; a dequeue wakes `NlSock.wait` (Linux nlk->wait: user senders waiting for room) after it is dropped |
| `NlSock` portid/groups/flags/err/rmem/congested/dead, autobind `ROVER` | atomics | thread only | `dead` (Linux SOCK_DEAD) is set at release, which then purges `rxq` and wakes `NlSock.wait`: a user sender waiting there for room fails ECONNREFUSED |
| `UnixSock.bindlock` (`net/unix`) | `sync::Mutex<()>` (sleeping) | thread only | Linux u->bindlock: bind/autobind; taken with no spinlock held, before `UnixTable.st`/`BSD`. A path bind runs the VFS mknod (parent `i_rwsem`) first and takes `bindlock` after it returns (Linux nests i_rwsem -> bindlock; hk does not need to); if the socket got bound meanwhile it drops `bindlock` before unlinking the node, so `i_rwsem` is never taken under `bindlock` |
| `UnixSock.iolock` | `sync::Mutex<()>` (sleeping) | thread only (recvmsg) | Linux u->iolock: one reader across dequeue -> user copy -> consume; dropped before waiting for data; above `st`/`rq` |
| `UnixSock.st` | `spin::Mutex<Option<Arc<UnixSock>>>` | thread only | Linux unix_state_lock: the peer; `state`, shutdown bits and `dead` change under it. At most two published sockets at once: listener -> connecting socket (stream connect; a socket that is not CLOSE fails before taking its own, so listeners never nest), then the new server-side socket (not yet reachable by anyone; Linux unix_state_lock_nested(newsk)) as a third; or two in ascending address order (`lock2`, Linux unix_state_double_lock: dgram connect, socketpair). Senders queue under the receiver's `st`, so nothing is queued to a released socket |
| `UnixSock.rq` | `spin::Mutex<RxQueue>` | thread only | receive queue (Linux sk_receive_queue.lock), under `st`; a listener's queue holds embryo connections |
| `UnixTable.st` (per netns), `unix::BSD` (global, by inode) | `spin::RwLock` | thread only | all sockets + abstract names (per type) / filesystem bindings; after `bindlock`, before `UnixSock.addr` (published under them); lookups return `Arc`s, no socket lock under them |
| `UnixSock.addr`, `UnixSock.peercred`, `UnixSock.relay` | `spin::RwLock` / `spin::Mutex` | thread only | leaves (Linux u->addr, sk_peer_lock, peer_wait.lock for peer_wake relays); `relay` also guards the registered sockets' `peer_wake` atomics |
| `unix::scm::INFLIGHT`, `Task.fput_defer` | `spin::Mutex` | thread only | leaves: per-user in-flight file counts (charged under the receiver's `st`); the current task's files awaiting `defer_fput` (each task drains its own, like Linux task_work fput; `Some` marks the task draining, so nested releases queue instead of recursing; only the task itself takes it) |
| `UnixSock` `state`/`dead`/`wmem`/`backlog`/`peer_wake` | atomics | thread only | |
| `NetDevice.ops` | `spin::RwLock<Option<Arc<dyn NetDeviceOps>>>` | thread only | the driver while registered (Linux reg_state + netdev_ops); written once, under RTNL, by `rtnl::unregister_netdevice` (`detach_ops`: None = unregistered). Read-held across the driver's `xmit` (after the lock-free IFF_UP check, so a closed device's senders do not take it), so the write waits for transmits in flight (Linux synchronize_net after dev_deactivate); RTNL-side callbacks (open, stop, set_promisc) clone the `Arc` out, since they may sleep, and RTNL orders them with the detach. Under it: the driver's TX lock, `Softnet.backlog` (lo). Also read under `NeighTable.hash` (`is_gone`: no neighbour is created for an unregistered device after its flush) |
| `NetDevice.net` | `spin::RwLock<Weak<NetNamespace>>` | thread only | read per received packet; written at registration under the namespace's `devices` write lock (order `devices` -> `NetDevice.net`) |
| driver `netdev` / `Napi.poller` (`spin::Once<Weak<..>>`) | set once at probe, before the IRQ is registered and the NAPI added | read lock-free by polls (thread) | ISRs never read them (they use the driver struct passed as IRQ data) |
| `icmp::ICMP_ECHO_REPLY_WQ` | `WaitQueue` | woken by ICMP input (softnet) | kernel self-test waiter only (`selftest.rs`), woken after the reply is recorded |
| `UnixSock.peer_wait` | `WaitQueue` | thread only | Linux peer_wait: dgram senders blocked on a full peer wait here (no lock held); woken by the peer's reads and release, relays to pollers via `UnixSock.relay` |
| `NetNamespace.sysctl`, `port_range` (`/proc/sys/net`, `sysctl.rs`) | atomics | thread only | no locks; a multi-value sysctl (ping_group_range, ip_local_port_range) is one packed atomic word, so readers never see half an update; the boot port/ISN secret is a `spin::Once` |
| `NetDevice.stats`, `flags`, `mtu`, `ifindex`, `carrier`, `promiscuity`, `allmulti` | atomics | any (`promiscuity`/`allmulti` written only under RTNL) | `flags` holds administrative state only; IFF_RUNNING/IFF_LOWER_UP/operstate are derived on read |
| e1000 `rx` ring | `spin::Mutex<Option<..>>` | thread only (NAPI poll, open, stop, remove) | leaf; frames are delivered after it is dropped; also holds `napi_off` (NAPI disabled by `stop`), read by remove after `unregister_netdev` to disable a NAPI that never was; taken out (rings freed) by remove after the chip reset and IRQ free |
| e1000 `tx` ring | `spin::Mutex<Option<..>>` | thread only (xmit, poll reclaim, remove) | leaf; ring full -> drop, `tx_dropped`, ENOBUFS; empty once removed |
| e1000 `pending_icr`, irq counters | atomics | IRQ + thread | ISR ORs ICR causes in; poll swaps them out |
| virtio-net `rx` queue (`hw/net/virtio_net.rs`) | `spin::Mutex<Option<..>>` | thread only (NAPI poll, open, stop, remove) | leaf: virtqueue + bounce buffers + `napi_off` (as e1000); frames are delivered after it is dropped; taken out by remove, whose `del_vqs` resets the device before the rings and buffers are freed |
| virtio-net `tx` queue | `spin::Mutex<Option<..>>` | thread only (xmit, poll reclaim, remove) | leaf; one descriptor per frame; ring full -> drop, `tx_dropped`, ENOBUFS; empty once removed |
| virtio-net `config_pending`; `VringCb` (RX avail NO_INTERRUPT flag) | atomics / lock-free MMIO-style store | IRQ + thread | the ISR suppresses RX interrupts and flags config changes; the poll re-enables under `rx` only while `netif_running`, and `stop` suppresses under `rx` |
| virtio-PCI transport (`hw/virtio/pci.rs`) | none | probe and remove (under the virtio device's or the PCI function's `Device.lock`), then IRQ (ISR byte) | common config (status, features, queues, reset) written only under those device locks; device config reads are generation-checked and lock-free; queue notify writes happen under the caller's queue lock |
| `VirtioDevice.irq` (driver interrupt callbacks) | `IrqSpinlock<Option<Arc<dyn VirtioIrq>>>` | thread (`request_irq`, `free_irq`) and hardirq (`vp_interrupt`, under `IRQ_TABLE`) | leaf: the ISR clones the callbacks out and calls them after unlocking; `free_irq` unregisters the handler (`IRQ_TABLE`) before clearing it, so the ISR never drops the last reference |
| PCI and USB `DYNIDS` (hw/pci/driver.rs, hw/usb/usbcore.rs; Linux dynids.lock) | spin Mutex | thread only | leaf: new_id/remove_id and each match take it alone; the probing after new_id runs with it dropped |
| `ScsiDisk.state` (block/sd.rs, Linux sdev_state + state_mutex) | spin `Mutex<ScsiDeviceState>` | thread only | leaf: transitions (Linux's legal table) and each command's state check take it alone, never across I/O |
| `util::ida::Ida` allocators: virtio, virtio-blk and sd indexes (Linux virtio_index_ida, vd_index_ida, sd_index_ida) | `IrqSpinlock` | alloc thread only; free any context | leaf; nothing allocates under it (alloc grows the bitmap with it dropped); a disk index is freed when the disk's last reference drops |
| `SYSTEM_TRANSITION` (`power.rs`) | sleeping `sync::Mutex<()>` | thread only (reboot(2)) | Linux system_transition_mutex: held from after the permission and magic checks through `device_shutdown` and the arch power-off/restart/halt, which do not return; outermost: taken before `core::DEVICES_LIST` and every driver lock the shutdown callbacks take |
| x86 `power::POWER` (`arch/x86_64/power.rs`) | `spin::Once` | thread only (boot set; power-off/reboot read) | set once from the FADT before `reboot(2)` can run, read lock-free after; the ACPI register sequences (`hw/acpi/hw.rs`) take no locks |

**Lock order (outermost first):**

```
RTNL (sleeping; configuration)   TcpSock.rd (sleeping) -> TcpSock.cb (listener before its new child;
  |                                 a child never takes its listener's cb) /
  |                                 TimeWait.inner / UdpSock.op / PingSock.op
  |                                 -> TCP bhash -> ehash, lhash / UdpTable.socks /
  |                                    PingTable.socks -> Inet.addr
  |                                 -> TcpSock.queue / RxQueue.q
  |                                 -> TCP TIMERS (leaf); Alarm.st -> timer base
  v                                 |
NetDevice.addrs, NetNamespace tables, Fib.tables (RwLocks; lookups drop
  the guard before returning)
  -> NeighTable.hash -> Neighbour.inner (dropped before any transmit)
  (RawTable.socks -> Inet.addr; FragTable.st, PmtuCache.m, IcmpRate.st,
   Sock.errq, RxQueue.q: leaves, never held while transmitting)
  -> NlTable.socks -> NlSock.rxq (netlink replies/notifications)
  (AF_UNIX: UnixSock.bindlock (sleeping) -> UnixTable.st / BSD
   -> UnixSock.addr; UnixSock.iolock (sleeping) -> UnixSock.st (listener
   before connector, else by address) -> UnixSock.rq / peercred / addr /
   INFLIGHT; UnixSock.relay leaf)
  (NlSock.dump -> devices/FIB/ARP snapshots -> NlSock.rxq: dump parts)
  (AF_PACKET taps, from any receive or transmit path: PacketTable.socks,
   then PacketSock.filter / PacketSock.rxq, each a leaf;
   RTNL -> PacketSock.mclist)
  -> NetDevice.ops (read across a transmit; NeighTable.hash -> it)
  -> device TX lock (e1000 tx, virtio-net tx)
  -> Softnet.backlog (lo xmit)           Softnet.poll_list; WaitQueue -> pi_lock
                                          -> rq (IrqSpinlocks, innermost)
```

**AF_UNIX** (`net/unix/`, Linux af_unix.c order). Sockets talk
directly: a sender queues a message on the receiver's `rq` while
holding the receiver's `st`, after copying the data in with no lock
held; readers copy out under `iolock` only. Messages (and the files
they carry) are dropped only with no spinlock held: dropping a file
can release a socket, which takes its own and its peer's `st`.
`scm::defer_fput` drops files from one loop, so a chain of sockets in
flight releases iteratively, never by recursion. Waits (`sock::wait_on`
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
or `open()`) send RTM_NEWLINK without RTNL (NlTable.socks -> NlSock.rxq
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
ISR runs after `unregister_irq_handler`, which takes the IRQ table
lock every dispatch holds), `netif_napi_del`s and frees its DMA
memory. A `NetDevice` still referenced (queued skbs) stays down and
driverless; hk cannot wait for those references (Linux
netdev_wait_allrefs) because skbs in socket queues hold them.

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
on `Sock.wq`) with no lock held; receive paths make the condition true
under their leaf lock, drop it, then wake. A socket leaves every table at
last close (`ProtoOps::release`); a TCP connection leaves ehash when it
reaches CLOSED (an orphan when its close handshake or timers end) or is
replaced by a TIME_WAIT entry, which leaves after 2MSL.

**TCP and Linux lock_sock.** Linux has two levels: `lock_sock` (an
owner lock process context holds across user copies and sleeps, with
a backlog where softirq input waits) and the `bh_lock_sock` spinlock.
hk input already runs in thread context, so `TcpSock.cb` alone plays
both parts, with a release-before-sleep discipline: socket calls copy
user data through a bounded (64 KiB) kernel buffer outside the lock and
re-check the state at every step, and sleep in `Sock::wait` with no lock
held. Consequences (deviations): input never waits for a sleeping user
(no backlog), and concurrent senders on one socket interleave at
64 KiB steps rather than at sndbuf-wait points. Like Linux, segments
are transmitted and errors/shutdown bits published under the lock
(`TcpSock::emit`, at the end of `TcpSock::step`); wakeups follow the
unlock. Transmitting under `cb` is safe because the output path only
takes FIB/neighbour/device-TX leaves and `lo` queues to the receive
backlog instead of delivering inline; the loopback flush
(`netif_rx_flush_local`) runs only at the end of socket calls, with no
lock held. A TIME_WAIT entry transmits under its `inner` the same way.

**Known gaps (later phases):** RCU for the read-mostly tables (FIB,
device list, address lists: COW snapshots are the intended next step;
see plan 3a).

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
| `SignalStruct.posix_timers` | signal/mod.rs, time/posix_timer.rs | spin Mutex | the thread group's POSIX timers and itimers (Linux signal->posix_timers); thread context, never under TASKLIST; cpu_timer holds it around arming the group's CPU-timer state and its whole expiry pass (`PosixTimer.inner` and `SignalStruct.rlim` inside); deleted at the group's last exit (`exit_itimers`, timers stopped after the lock) or with the SignalStruct |
| `PosixTimer.inner` | time/posix_timer.rs | IrqSpinlock | one timer's state; -> its hrtimer's base (re-armed under it); cancelled with `cancel_sync` before it is taken (settime) or with it dropped (delete). A CPU-time timer's clock value is read before it (that may take TASKLIST) |
| `PosixTimer.sigq` | time/posix_timer.rs | spin Mutex | a timer_create timer's preallocated signal entry while it is not queued (Linux SIGQUEUE_PREALLOC); leaf, thread context: taken alone, never with `inner` or a signal lock. The entry is taken out to be queued by `signal::send_timer_sigqueue` with no lock held, and put back when its signal is dequeued (`posix_timer::deliver`, which rearms an interval timer under `inner`), flushed or refused (`reclaim`) |
| CPU-timer state (`time/cpu_timer.rs`): `SignalStruct.cputimer`, `Task.cpu_next` | time/cpu_timer.rs | atomics | the group's running CPU totals and expiry hints, a thread's hints; written by the tick and accounting (interrupts off) and by `run` in task context. The group totals start (arming a process timer, `arm_group`) and stop (`run` finding nothing armed) only under `posix_timers`; sampling never starts them (Linux cpu_clock_sample_group with start=false for gettime). `run` (TIF_NOTIFY_RESUME on the way to user mode) takes `posix_timers` -> `PosixTimer.inner`, then `SignalStruct.rlim`, and sends signals after dropping them |
| timerfd `CANCEL_LIST` | time/timerfd.rs | spin::Mutex | thread only: weak refs to TFD_TIMER_CANCEL_ON_SET timerfds; -> `Timerfd.inner` (setup_cancel); `clock_was_set` copies it out and drops it first |
| `TimerBase.wheel` (per CPU, HARD and SOFT) | time/timer.rs | IrqSpinlock leaf | a 64-slot wheel of `TimerList`s (their links, `expires`, `pending`); callbacks run with it dropped (`running` set); taken in the tick, by `ktimers/N` and by arming/deleting code in any context |
| `HrBase.q` (per CPU, HARD and SOFT) | time/hrtimer.rs | IrqSpinlock leaf | sorted lists of `HrTimer`s per clock (their links, `expires`, `pending`); callbacks run with it dropped (`running` set); taken in the clock event interrupt, by `ktimers/N` and by start/cancel in any context. `SOFT_ACTIVATED` (per-CPU atomic, Linux softirq_activated): set by the clock interrupt when it hands due SOFT timers to `ktimers/N`, cleared by it after its pass (interrupts off, then reprogram); while set the clock event counts only HARD timers |
| `EPNESTED` (sleeping) → `EpItem.regs` (spin) → file wait queue heads → `Eventpoll.lock` (IrqSpinlock); `File.f_ep` (spin leaf) | io/epoll.rs | see column 1 | epoll (Linux epnested_mutex, ep->lock, file->f_lock): `EPNESTED` serializes an epoll target's loop check and insert. `EpItem.regs` holds an item's callback entries: an add polls the file with no lock held (a poll method may sleep) and moves the entries it made under `regs` after; unregistering takes the watched file's queue locks under it, before the item leaves the map and ready list, so no callback can queue it again. `ep_poll_callback` runs under a woken queue's lock (possibly in an interrupt) and takes `Eventpoll.lock` (map and ready list), then wakes the epoll's own queues after releasing it (a nested epoll's callback in turn: bounded by EP_MAX_NESTS, no cycles). Nothing polls, copies to user or drops an `EpItem` or a last `Arc<File>` under `Eventpoll.lock`. A file's last close (`eventpoll_release`) unregisters its items under `EpItem.regs` before its queues go. |
| `Inotify.fasync` | io/inotify.rs | `FasyncList` (sleeping, see `FasyncList.list`) | the group's O_ASYNC files (Linux fsnotify group fsn_fa); queueing an event sends their SIGIO after `Inotify.inner` is dropped |
| `Eventfd.inner`, `Inotify.inner`, `Fanotify.inner`, `IoUring.inner`, `Signalfd.inner`, `Timerfd.inner` | io/eventfd.rs, io/epoll.rs, io/inotify.rs, io/fanotify.rs, io/io_uring.rs, io/signalfd.rs, time/timerfd.rs | IrqSpinlock | per-object state of the anon-inode files; their wait queues are woken after unlocking. eventfd, inotify and fanotify readers wait with it held (`wait_event_interruptible_locked`: inner -> wait queue head while queueing, released while asleep) |
| `Pid.exit`, `Pid.wait_pidfd` | task/pid.rs | atomic; WaitQueue | a pidfd's process (its leader's `Pid`, the file's only state): its exit status, stored in the TASKLIST write section of its last thread's exit before the exit's notice is queued (Linux do_notify_pidfd from do_notify_parent), so a parent its signal wakes polls the pidfd readable; the pollers are woken after TASKLIST, before the signal's wakeups |
| `SigHand.signalfd_wq` | signal/mod.rs | WaitQueue (its own IrqSpinlock) | signalfd readers and pollers of the tasks sharing a handler table (Linux sighand->signalfd_wqh); woken by send_signal after the target's signal state is unlocked; readers take `Signalfd.inner` and the caller's signal state only in its condition, after the queue's lock is dropped |
| `Workqueue.inner` | task/workqueue.rs | IrqSpinlock | pending and delayed work lists (`SYSTEM_WQ`, `BDI_WORKQUEUE`); a work item's state is plain fields under its own `spin::Mutex` (pending/running bits; a delayed item's `wake_tick`, nonzero exactly while it is on the delayed list, and a `seq` that voids a promoted copy). `queue_work` takes the item lock and drops it before this lock; the delayed-work calls (queue, mod, cancel, promote) take the item lock under it, so list membership and `wake_tick` change together (order: `Workqueue.inner` → item, a leaf). Never from IRQ context |
| `BDI_REGISTRY`, `BdiWriteback.dirty`, `BdiWriteback.dwork` | mm/writeback.rs | spin | per-disk writeback state: the devices with dirty data, the periodic work; leaves, writeback runs with none held |
| `Task.cgroup`, `CSS_SET_CACHE`, `CgroupRoot.{root_cgrp, controllers}`, `Cgroup.{parent, children, ancestors, subsys, tasks}`, `CssSet.subsys`, `CgroupSubsysState.private`, `CpuState.bw`, `IoState.devices` | cgroup/ | spin (RwLock; `CSS_SET_CACHE`, `Task.cgroup`, `CpuState.bw` (weight, quota, period together), `IoState.devices` (each device's limits together) Mutex leaves) | cgroup hierarchy and membership (`Task.cgroup`: the task's cgroup, a leaf reached through a `TaskRef` cloned out of TASKLIST, Linux task->cgroups); parent before child; never under TASKLIST. `CGROUP_MUTEX` (sleeping, Linux cgroup_mutex; section 2) serializes mkdir, rmdir, cgroup.procs/subtree_control/freeze writes and a CLONE_INTO_CGROUP fork from admission to post_fork, so rmdir's emptiness check and its `dead` mark cannot interleave with an attach; it is taken before the cgroupfs inode's spin lock. `CGROUP_THREADGROUP_RWSEM` (sleeping, under `CGROUP_MUTEX`) keeps forks out while cgroup.procs moves a whole thread group. The pids counters are atomics charged add-then-check (Linux pids_try_charge): at fork, before the child exists, on the target cgroup (`cgroup::can_fork`, undone by `ForkCg` on failure); the root is never charged. memory.max is one atomic word (Linux page_counter max); a cgroup's frozen flag is written under `CGROUP_MUTEX`. |
| `IpcIds.inner`, `KernIpcPerm.lock`, `MsgQueue.q`, `SemArray.global`, `SemSlot.lock`, `SemUndoList.arrays`, `MQ_REGISTRY`, `MqQueue.{messages, flags, notify}` | ipc/ | spin | SysV and POSIX IPC objects; `IpcIds.rwsem` (sleeping, section 2) -> `IpcIds.inner` -> the object's lock; the namespace totals (`used_sems`, `shm_tot`) grow only under `IpcIds.rwsem`, after the insert, and shrink lock-free at destroy. Semaphores use Linux sem_lock's two levels: a single-operation semop takes only that semaphore's `SemSlot.lock` (its value, sempid, otime, single-operation waiters and SEM_UNDO adjustments, reached through the `SemLock` guard); multi-operation semops, semctl, exit and removal take `SemArray.global` (multi-operation waiters, `complex_count`, ctime) in complex mode: `use_global_lock` (written under `global`, read lock-free) is set and every slot lock taken and dropped once, which waits out the single-operation holders; the fast path rechecks the flag with Acquire after its slot lock and falls back to `global` while it is set; it is cleared with Release after `USE_GLOBAL_LOCK_HYSTERESIS` global holds with no multi-operation waiter. Order `SemArray.global` -> `SemSlot.lock`. A waiter's status is set by its waker under the locks (Release) and read by the sleeper without them (Acquire, Linux q->status); wakeups happen after the unlock. SEM_UNDO adjustments live in each semaphore (`PerSem.undo`, by undo-list id); `SemUndoList.arrays` (a leaf, never held with the array's locks) names the arrays a list has adjusted and is filled before the array lock is taken (Linux find_alloc_undo). `MsgQueue.q` holds the queue's messages, counters, qbytes, times and last pids (Linux: the msq lock): msgsnd's limit and removal check, the enqueue and the sender's pid and time are one critical section, likewise msgrcv's dequeue, and IPC_STAT copies a snapshot under it; IPC_SET takes `KernIpcPerm.lock` (a leaf) under it. The namespace's message statistics are atomics changed under it |
| `KEYRING_LINK` (sleeping) → `Key.keyring_keys`; `Task.keyrings`, `USER_KEYRINGS`, `Key.payload` → `KEY_DATABASE` → `KEY_USERS` | keys/ | spin (RwLock; `Task.keyrings` Mutex) | a task's thread/process/session keyrings (`Task.keyrings`, reached through a `TaskRef` cloned out of TASKLIST; creating a keyring registers it under it), the per-user keyrings, the key registry and keyrings. Links and keyring slots own keys (`Arc<Key>`); `KEY_DATABASE` holds weak entries (lookups upgrade after releasing it). A key's `Drop` (its last reference) takes `KEY_DATABASE`, then `KEY_USERS` (the per-user quota, a leaf), so no `Arc<Key>` is dropped under either; `Key.keyring_keys` is a leaf: unlinked keys are dropped after it is released, and replaced slots after `Task.keyrings`. `KEYRING_LINK` (Linux keyring_serialise_link_lock) is held by a keyring's link from its cycle check to the link, taken with no spin lock held. `Key.payload` also plays key->sem: instantiate (only from uninstantiated), update, revoke and invalidate change `Key.state` under its write lock, so a revoked key is never revived (the state is read lock-free); and KEYCTL_CHOWN / KEYCTL_SETPERM decide (owner, group, CAP_SYS_ADMIN) and store `Key.uid`/`gid`/`perm` in one write hold, as Linux keyctl_chown_key / keyctl_setperm_key under key->sem; those atomics are read lock-free by the permission checks and describe (Linux reads key->uid unlocked) |
| `FileLockCtx.flc_lock` (per inode), `locks::BLOCKED` | fs/locks.rs | spin Mutex | an inode's flock and POSIX locks (Linux i_flctx flc_lock; a POSIX owner is a descriptor table's id), leaf but for BLOCKED (flc_lock -> BLOCKED, Linux blocked_lock_lock: each waiting POSIX owner and the owner it waits on, for EDEADLK). A blocked locker sleeps on the inode's wait queue with neither held, interruptibly, until the change count moves |
| `cmdline::SAVED` | cmdline.rs | spin Mutex | the saved kernel command line (Linux saved_command_line): written once while parsing, before SMP; read in thread context (init's arguments); a leaf |
| `signal::NO_SHARED` | signal/mod.rs | spin Mutex | the empty group set a task with no SignalStruct (kernel thread, exited task) reads; nothing is queued on it; locked where `SignalStruct.shared` would be, same position (Task.sig -> shared) |
| `FS_TYPES`, `CHARDEV_REGISTRY` | fs/superblock.rs, fs/chardev.rs | spin | filesystem types, character device registry |
| `File.f_lock` | fs/file.rs | spin Mutex | file status flags (Linux f_lock); a leaf, also under `FasyncList.list` (O_ASYNC is set or cleared only with the file's fasync entry) |
| `FasyncList.list` → `File.f_lock`, `FOwner.st` | io/fasync.rs | sleeping `sync::Mutex` (per object: a pipe's readers and writers, a socket's, a tty's, an inotify group's); `FOwner.st` spin leaf | SIGIO (Linux fasync_lock and RCU readers, fown->lock): `FasyncList.armed` (atomic, written under the lock, read lock-free: Linux kill_fasync's unlocked list test) lets a wakeup with no armed file skip the lock; a list's entries (a file's `FOwner` reference and the armed fd), changed by `fasync_helper` (from `->fasync`; a pipe's under `Pipe.inner`, Linux pipe_fasync) and walked by `kill_fasync`, which sends each entry's signal under it: thread context, no spin lock held (3.7 rule 1). `FOwner.st` (a file's owner pid, type, setter uids and F_SETSIG signal; allocated once per file) is copied under it and released before the send. A file's last close takes it off its lists (`->fasync(-1, off)`) before `->release` |
| `SuperBlock.{root, private}`, `DentryCache.root` | fs/superblock.rs, fs/dentry.rs | spin RwLock | superblock root and private data, the dcache root |
| `RamfsInodeData.xattrs`, `RamfsSbData.sb` | fs/ramfs.rs | spin | ramfs xattrs and superblock back-pointer (under VFS locks) |
| membarrier `GLOBAL_MUTEX` → `IPI_MUTEX` | task/membarrier.rs | sleeping (`sync::Mutex`; `IPI_MUTEX` is Linux membarrier_ipi_mutex) | `IPI_MUTEX` serializes the membarrier commands that interrupt other CPUs, so callers cannot multiply the IPIs; held only across `smp_call_function_many` (waited); nothing is taken under it. `GLOBAL_MUTEX` (killable) paces MEMBARRIER_CMD_GLOBAL to one call per tick: held across its IPIs and its one-tick sleep, so GLOBAL callers never delay the expedited ones. The targets are chosen from each CPU's `PerCpuScheduler.curr_mm` / `membarrier_state` (atomics written at every switch in `make_current`: `curr_mm` SeqCst, then a full fence, then the registrations read, so a registration either sees the CPU in its mm and refreshes it by IPI or is seen by the switch; Linux rq->curr->mm and rq->membarrier_state), compared, never dereferenced |
| `Inode.i_pipe` | fs/inode.rs, io/pipe.rs (FIFOs) | spin Mutex leaf (Linux inode->i_lock around i_pipe) | a FIFO's pipe and its open-file count: attached by the first open, dropped by the last release; every change of the pipe's reader/writer counts and open counters happens under it (so a blocking open decides, and samples the counter it waits on, before unlocking; the release wakes the other side under it: -> `Pipe.wait_queue`); never held across a wait (a blocking open waits on `Pipe.wait_queue` after unlocking) or under `Pipe.inner` |
| `Pipe.inner` | io/pipe.rs | sleeping (`sync::Mutex`, Linux pipe->mutex) | the pipe's buffer ring; held across page allocation and across read/write's copy to or from the caller's memory (may fault: -> mmap_lock, as Linux pipe->mutex), never under a spin lock; two pipes (splice, tee) in address order (Linux pipe_double_lock); -> frame allocator; -> `FasyncList.list` (pipe_fasync changes both lists under it, Linux too). SIGIO is sent after it is dropped (Linux sends under pipe->mutex) and after `Inode.i_pipe`. `Pipe.head`/`tail` (atomics) are published as the guard unlocks and read locklessly by wait conditions and poll (poll runs under `Eventpoll.inner`, an IrqSpinlock); wakeups follow the unlock |
| `NTtyLdisc.data` | tty/n_tty.rs | spin Mutex | line discipline buffer (input is polled, not IRQ-fed) |
| `VgaCon.state` | arch/x86_64/vgacon.rs | IrqSpinlock | VGA text console state, under `CONSOLE_REGISTRY` (3.9) |
| `SimpleGfxDevice.state`, `GFX_DEVICES`, `NEXT_MINOR` | gfx/ | spin | framebuffer device state and registry |
| `UsbMscDevice.state` | hw/usb/msc.rs | sleeping `sync::Mutex` (Linux us->dev_mutex), thread only | a mass-storage interface's CBW tag and disconnected flag, held across each BOT transaction (CBW, data, CSW: the transfers take `USB_CONTROLLER` under it); its unbind sets the flag under it, after the disk is gone and the command in progress is done |
| `INTX_MAP` | arch/aarch64/pci_irq.rs | spin Mutex | PCI INTx routing from the device tree (boot) |
| `PCI_LOCK` | arch/x86_64/pci_conf.rs (port I/O config access) | IrqSpinlock | Linux pci_lock: the CF8 address write and the CFC data access of one config read/write; leaf (port I/O only). ECAM accesses are single MMIO operations and take no lock |
| PCI fixups (`hw/pci/quirks.rs`) | none | thread only (boot) | run by bus enumeration (single-threaded) on each function before driver probe |
| `CMDLINE_CONSOLE` | cmdline.rs | spin Mutex | console= choice |
| `CPU_CRNG` (per CPU) -> `BASE` | random.rs | IrqSpinlock | ChaCha20 CRNG: this CPU's key, then the base key when the CPU key is refreshed or the base reseeded; both leaves otherwise (callers include softirq net code). `GENERATION`/`BIRTH_NS` are atomics read unlocked, rechecked under `BASE` |
| `Inode.i_writecount`, `Inode.i_swapfile` | fs/inode.rs | atomics | writers (> 0) or executions denying them (< 0), Linux i_writecount, changed by CAS (`get_write_access` / `deny_write_access`, ETXTBSY on the wrong sign); an active swap area (S_SWAPFILE: set and cleared by swapon/swapoff
under its i_rwsem, `SWAPON` -> i_rwsem, and checked under it by
writes and truncates). The address space holds the executable's denial (`MmStruct.exe_deny`, cloned at fork) |
| `SuperBlock.s_wb_lock` | fs/superblock.rs | sleeping `sync::Mutex` | serializes whole-filesystem writeback passes (`writeback_sb`: sync, syncfs, umount, the periodic writeback), held across their I/O: s_wb_lock -> page lock -> i_mmap -> PTE lock. fsync writes its inode without it; a page another pass is writing carries the WRITEBACK mark and its writer holds its page lock, so fsync waits on that lock |
| `SuperBlock.s_dirty`, `SUPER_BLOCKS` | fs/superblock.rs, fs/fs_writeback.rs | spin Mutex leaves | inodes with dirty pages, each held (an `Arc`) until written back (Linux wb->b_dirty), and the device filesystems for sync(2) (Linux super_blocks). `mark_inode_dirty` takes `s_dirty` under a page lock at most (the fault path), then the BDI's spin locks to arm its periodic writeback; writeback takes the list and writes with no spin lock held |
| `LAST_INO` (per CPU) | fs/anon_inodes.rs | IrqSpinlock leaf | this CPU's batch of pseudo-filesystem inode numbers (Linux get_next_ino, preempt-off per-CPU counter); refilled from the atomic `SHARED_LAST_INO` under it |
| `NUMA_TOPOLOGY` | mm/numa.rs | IrqSpinlock leaf | NUMA node table: written by the boot parsers and by each CPU at bring-up (`numa::cpu_up`, end of arch per-CPU init), read by getcpu and the mempolicy syscalls |
| `BpfHashMap.data`, `BpfArrayMap.data` | bpf/map.rs | IrqSpinlock | BPF map contents |

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

// Preempt count
preempt_count.fetch_add(1, Ordering::Relaxed);
```

### 5.2 Atomic File Position

File position updates use lock-free atomics:

```rust
pub fn advance_pos(&self, n: u64) -> u64 {
    self.pos.fetch_add(n, Ordering::Relaxed)
}
```

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

#### Rules (phase L, from the 2026-11-03 atomics audit)

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

#### hk Pattern Examples

Correct uses of atomics in hk:

| Subsystem | Atomic Fields | Why Correct |
|-----------|---------------|-------------|
| `TimeKeeper` | seq, cycle_base, mono_base_ns, etc. | Seqlock pattern - all read together with seq validation |
| `File` | pos | Under `f_pos_lock` for writers; atomic for lockless readers |
| `Inode` | mode, uid, gid | Written under i_rwsem (chmod, chown, set-id kill on write/truncate); read lock-free |
| `Inode` | size | Linux i_size_write/read: Release under i_rwsem, Acquire lock-free, so the bytes below it are visible first |
| `Sock` | flags, error, buffer sizes | Independent values; protocol data under the socket lock |
| `Sock` | shutdown | Written under the protocol socket lock (TCP `cb`, unix `st`); read lock-free by poll |
| TCP `mem::FW_ALLOC` (per-CPU) | quanta not yet in `ALLOCATED` | Linux tcp_memory_per_cpu_fw_alloc (rule 9): every charge and uncharge, under the connection's `cb`, is an RMW on this CPU's slot (correct after a migration, as this_cpu ops); past ±`PCPU_RSV` the slot is swapped to 0 and added to `ALLOCATED`. Relaxed: a count |
| TCP `mem::ALLOCATED` | quanta all connections hold, less the CPUs' reserves | Linux tcp_memory_allocated: read lock-free by every charge to check the limits (add-then-check: the charge is added before the check, subtracted on failure); lags by up to the reserve per CPU, as Linux. Relaxed |
| TCP `mem::LIMITS[3]`, `mem::PCPU_RSV` | tcp_mem, net.core.mem_pcpu_rsv | sysctl words (initial netns only), each independent, read lock-free per charge (Linux sysctl_tcp_mem, mem_pcpu_rsv with READ_ONCE). Relaxed |
| TCP `mem::PRESSURE` | memory pressure mode | Linux tcp_memory_pressure: set past tcp_mem[1], cleared under tcp_mem[0], by any charge; a mode, so racing writers store the same value. Relaxed |
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

/// Check if preemption is disabled
pub fn preempt_disabled() -> bool;

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
- Workqueues have no IRQ-side work: the worker thread promotes expired
  delayed work itself, sleeping with a timeout until the next deadline
- Block completion (virtio-blk ISR): the blk-mq hardware queue lock
  (`IrqSpinlock`, leaf) to reap the virtqueue and restart dispatch, then
  `bio_endio` with no lock held; `end_io` completes a `Completion`
  (`IrqSpinlock` -> wait queue wakeup); the lock-free DMA API unmaps
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
| `TASKLIST` | task/percpu.rs | `RwLock` | every task (Linux tasklist_lock) |
| `SignalStruct.shared` | signal/mod.rs | `Mutex` | Thread-group pending signals and curr_target (under Task.sig) |
| `Task.alloc_lock` | task/mod.rs | `Mutex` | A task's mm, files, fs, nsproxy, comm, mempolicy, io_context (Linux task_lock; under TASKLIST, over `Task.sig`) |
| `FsStruct.inner` | fs/fsstruct.rs | `Mutex` | Root, cwd, umask (leaf) |
| `UCOUNTS` | task/mod.rs | `Mutex` | Per-real-uid counts: RLIMIT_NPROC tasks, RLIMIT_SIGPENDING queued signals (leaf: may be taken under TASKLIST, takes no lock) |
| `MEMBLOCK` | mm/memblock.rs | `Mutex` | Boot memory map (boot CPU, before SMP) |
| `ACCT_FILE` | task/acct.rs | `Mutex` | Process accounting file (leaf: cloned out, the record written and an old file released with no lock held) |
| All VFS locks | fs/*.rs | `RwLock` | Inodes, dentries, mounts |
| Descriptor tables (`Files`) | task/fdtable.rs | `Mutex` | Per-task fd tables |
| `RTNL` and every network `spin::Mutex`/`RwLock` | net/ | `sync::Mutex` / `Mutex` / `RwLock` | Configuration, sockets, tables, queues (3.10) |
| Driver queue locks (e1000 / virtio-net `rx`, `tx`) | hw/net/ | `Mutex` | Rings: NAPI poll, xmit, open/stop |
| `Softnet.backlog` | net/core/dev.rs | `Mutex` | `netif_rx` (lo), softnet |
| `BLKDEV_REGISTRY`, `MAJORS`, `RamDisk.pages` | block/ | `RwLock` / `Mutex` | Block device lookup, majors, RAM disk pages (3.10) |
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
`IRQ_TABLE`, the blk-mq hardware queue, `Completion.done`,
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
- Interrupt handlers nest on the interrupted task's kernel stack (no
  separate IRQ stacks, unlike Linux): handlers stay shallow.
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
| Check if disabled | `percpu::preempt_disabled()` |
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
| Per-CPU variables | `DEFINE_PER_CPU` | Manual per-CPU arrays | Less convenient API |
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

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

### 1.4 Sleeping locks: sync::Mutex<T>, sync::RwSem (kernel/sync/)

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
  only, that gives up with EINTR once SIGKILL is pending), `try_read`/
  `try_write`, and the raw `down_read`/`up_read`, `down_write`/
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
  run with them on, 7.5). Without the feature it is the old debug-build
  preempt-count assertion.
- **Lock order:** a lock's class is the source location of its `new()`
  (`#[track_caller]`, like Linux's static lock_class_key: all `TcpSock.cb`
  share one class). Taking B while holding A records A -> B; taking B
  under A after A was taken under B reports both acquisitions. Only
  direct inversions (no transitive cycles); nesting within one class is
  not checked (listener -> child `cb`, `lock2` of two unix sockets).
- **IRQ safety:** a tracked lock taken in an interrupt handler (the timer
  tick and device IRQ dispatch call `lockdep::irq_enter/exit`).

The held-lock stacks are per CPU (the kernel is not preemptive and a task
never sleeps holding a spin lock, which is itself checked), the edge
table is a fixed array: nothing allocates. Power-off prints a
`lockdep: N reports, M order edges` summary. `IrqSpinlock` acquisitions
are not tracked for order (they are leaves or near-leaves); they count
through the preempt count.

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
VFS locks (detailed order):
    File.f_pos_lock (sync::Mutex; read/write/lseek/getdents by position)
        ↓
    MntNamespace.root
        ↓
    Mount.{children, parent, mountpoint}
        ↓
    SuperBlock.s_vfs_rename_mutex (cross-directory rename only)
        ↓
    Inode.i_rwsem (sync::RwSem; exclusive: directory operations,
                   lock_rename, regular file write and truncate; shared:
                   path-walk lookup on a dcache miss, readdir;
                   parent directory -> the link/unlink/rename victim or
                   link source, two non-directories by address)
        ↓
    Dentry.d_lock (single d_lock like Linux; short, never held across i_rwsem)
        ↓
    Inode.private
        ↓
Filesystem-internal locks (ramfs children/data, procfs data)
    ↓
Leaves taken with no task lock held (their Arc is cloned out of the
Task first, under its alloc_lock or lock-free by the task itself):
UtsNamespace.name (RwLock), FsStruct.inner (Mutex),
FutexHashBucket.waiters (spin Mutex; wakeups through a WakeQ after
unlocking)
    ↓
Global subsystem locks (TASKLIST, PAGE_CACHE, fd table `Files`)  ← NOT IRQ-safe;
    no file is released under `Files` (3.3, Descriptor Tables); order
    `Files` -> TASKLIST -> Task.alloc_lock (descriptor allocation
    reads RLIMIT_NOFILE under the table lock; kcmp takes a table out
    under the task's alloc_lock and locks it after dropping that); no
    user memory is accessed under any of them. A task's signal
    handlers and signal state, robust-list head and TLS base are
    fields of its `Task` read or changed under TASKLIST; its mm, fd
    table, fs context, namespaces, name, memory policy and I/O context
    under its alloc_lock (3.1.1); under them only leaves:
    TaskSignalState.shared_pending (Mutex) → SigHand.action
    (IrqSpinlock); SignalStruct.rlim (IrqSpinlock leaf, also under
    `Files`); NPROC; wait queue heads
    ↓
Address space: mmap_lock (sleeping RwSem; under i_rwsem: a write's user
    copy may fault) → page lock (PG_locked, sleeping; Linux folio_lock)
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

Kernel mappings (3.2 Kernel Page Tables): vmstack FLUSH (sleeping,
    thread context; held across the stack area's TLB flush) → IOREMAP,
    vmstack SLOTS (spin leaves; no mapping or flush under them); KTABLES
    (spin, thread context) → frame allocator

Pipes (3.11): Pipe.inner (sleeping; two in address order) → frame
    allocator; no other lock under it, none of these above it

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
    Mutex, per task) → TaskSignalState.shared_pending (spin Mutex) →
    SigHand.action (IrqSpinlock leaf); Task.keyrings, Task.cgroup,
    Task.fput_defer, SignalStruct.posix_timers: per-task leaves reached
    through a TaskRef, never under TASKLIST

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
    PRINTK (IrqSpinlock, ring buffer)
        ↓
    CONSOLE_REGISTRY (IrqSpinlock, console dispatch)
```

### Key Rules

1. **IrqSpinlock is innermost for IRQ-safe locks** - When you need to hold both
   an IRQ-safe lock and a non-IRQ-safe lock, acquire the IrqSpinlock first.

2. **Never acquire non-IRQ-safe locks from interrupt context** - This is the
   fundamental rule. TASKLIST, PAGE_CACHE, fd tables, and allocator locks must
   NEVER be acquired from timer ISR or any interrupt handler.

3. **Parent before child** - When locking multiple inodes in a directory
   hierarchy, lock parents before children.

4. **For multiple directories** - When an operation spans multiple directories
   at the same level, lock in increasing inode number order.

5. **Release in reverse order** - Always unlock in the opposite order of acquisition.

6. **VFS locks are outer locks** - Filesystem-internal locks must always be
   acquired while holding VFS locks, never the reverse.

### Why IrqSpinlock → TASKLIST is Safe

Some IrqSpinlock holders may take `TASKLIST` (the scheduler no longer
does: the run queue keeps everything a switch or wakeup needs in the
`Task`, 3.1):

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
  `TaskSignalState.shared_pending` (spin Mutex) -> `SigHand.action`,
  `SignalStruct.rlim`): they take nothing that leads back to it
- TASKLIST is NEVER acquired from interrupt context (see Section 7.4)
- Nothing is released under TASKLIST (3.1.1 rule 4): a release could
  sleep, and no task sleeps holding a spin lock

---

## 3. Per-Subsystem Locking

### 3.1 Scheduler

**Location:** `kernel/task/percpu.rs`

Each CPU has its own run queue and lock (Linux struct rq); a wakeup
takes the lock of the run queue it queues on, whichever CPU that is.

#### Global State

| Variable | Type | Purpose |
|----------|------|---------|
| `PERCPU_SCHEDS` | `PerCpu<PerCpuScheduler>` | Per-CPU scheduler array |
| `TASKLIST` | `RwLock<GlobalTaskTable>` | Every task (Linux tasklist_lock + task list) |
| `TICK_COUNT` | `AtomicU64` | Global tick counter (jiffies, TICK_MS = 10 ms); advanced only by CPU 0's tick; every CPU's tick runs its own timers (`timer::run_local`; Timers, 3.3) |

#### Per-CPU State

Each `PerCpuScheduler` contains:
```rust
pub struct PerCpuScheduler {
    pub lock: IrqSpinlock<CpuRunQueue>,  // curr, idle, prev, 256 priority lists, dead
    pub initialized: AtomicBool,          // Init flag
    pub nr_switches: AtomicU64,           // context switches (QSBR hook)
    pub curr_mm: AtomicUsize,             // running task's Mm address (membarrier)
    pub membarrier_state: AtomicU32,      // its membarrier registrations
}
```

Each `Task` carries its scheduling entity (`Task.se`, Linux
sched_entity + `__state`/`on_rq`): `state` (`SleepState` as an
atomic), `on_rq` (queued or running), `on_cpu` (running, or its CPU
still switching away from it), `prio`, the priority-list `link`, the
saved switch frame, and the WakeQ link; plus
`Task.pi_lock` (IrqSpinlock, Linux pi_lock). The run queue owns one
reference to each task of its CPU, from its first wakeup (or creation
asleep) until its final switch away (`DeadTask`; Linux: the task's own
usage count put in finish_task_switch); its lists and `curr` hold none
of their own. `prio` is written under TASKLIST (setpriority,
sched_setscheduler) and read lock-free; a queued task moves at its
next enqueue.

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
   priority and affinity changes) or found it on that list.

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
preemption point added later can honor it. A signal for a task running
on another CPU kicks it (`kick_process`: the reschedule IPI), so its
return to user mode delivers the signal.

**RCU hook:** `PerCpuScheduler.nr_switches` counts context switches per CPU;
since kernel code cannot be preempted, a change in a CPU's counter (or the
CPU being idle) is a quiescent state for a future QSBR RCU.

#### Kernel Threads (kernel/task/kthread.rs)

`kthread_run(name, fn, arg, cpu)` creates a pid-0 task bound to one CPU
(created asleep in that CPU's rq, then woken). `KTHREADS`
(`spin::Mutex<Vec<Arc<KThread>>>`, process context only, never held across
a wakeup/sleep; order: may be taken while holding nothing else) maps tid ->
control block. `kthread_should_stop/should_park/parkme` and
`kthread_stop/park/unpark` use atomics + `try_to_wake_up` + the block's
`ack` WaitQueue. A thread created without a CPU gets one round-robin;
every kernel thread stays on its CPU (`cpus_mask` holds only it, Linux
kthread_bind). Standing threads: `ktimers/N` (one per CPU, runs its SOFT
timer callbacks), the system workqueue worker, `softnet/N` (one per CPU,
network receive; see 3.10), `kselftest` (boot only).

**Stoppers (kernel/task/stop_machine.rs, Linux stop_machine.c):**
`migration/N`, one per CPU at the highest priority, runs calls queued
with `stop_one_cpu` (thread context; the caller sleeps until done). Per
CPU: `Stopper.lock` (sleeping `sync::Mutex`, one caller at a time, held
until the call completes) → `Stopper.work` (IrqSpinlock leaf, the
slot). `migration_cpu_stop` takes the task's pi_lock → this CPU's rq
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
Linux rq->nr_running. On x86-64 each CPU has its own TSS (RSP0) and
syscall entry stack top, set at each switch to a user task.

### 3.1.1 Task Struct and Credentials

**Location:** `kernel/task/mod.rs`, `kernel/task/percpu.rs`

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

**Pids** (`kernel/task/pid.rs`, Linux 4.14 pidmap): a `Pid` holds one
number per pid-namespace level. Numbers come from a lock-free bitmap
per namespace (pages allocated outside any lock, installed by
compare-and-swap; bits set and cleared atomically). `PIDMAP_LOCK`
(spin leaf, thread context only, nothing allocates under it) protects
the global hash chains of every live `Pid`'s numbers: `alloc_pid`
links them, `find_pid` walks them (taking a strong reference only
while the `Pid` lives: the hash holds weak ones), and the last drop of
a `Pid` unlinks them. It is taken under nothing but may be taken
under TASKLIST (a reaped task's `Pid` is dropped after TASKLIST).
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
(`forget_original_parent`, `reparent`); an exited non-leader thread
leaves the task list at once (Linux release_task), unless traced.
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
and the other counters); `cred` (below); the alloc_lock fields; and
the rest, `TaskInner`, in a `TableCell` that only the locked
table's views reach (`GlobalTaskTable::get`/`iter` read it,
`get_mut`/`iter_mut` write it with the table borrowed mutably; Linux
LockedBy). A `TaskRef` cloned out of the table keeps the task alive but
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
  attach.
- `exec_update` (`sync::RwSem`): `exec_replace_image` holds it for
  writing, inside `cred_guard`, while it installs the new mm, name and
  dumpability under TASKLIST and the task's alloc_lock; process_vm_readv/writev (`access_mm`),
  the /proc mm_access paths (maps, environ; the stat fields gated by
  access) hold it for reading (`signal::ExecUpdateRead`) around the
  access decision and taking the mm.

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
| `sighand->siglock` | Signal state, handlers | `Task.sig`, `TaskSignalState.shared_pending` (spin Mutex), `SigHand.action` (IrqSpinlock; 3.7) |
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
`try_to_wake_up` the tracee with it dropped. The arch register and
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

**Location:** `kernel/mm/page_alloc.rs` (Linux mm/page_alloc.c), API in
`kernel/frame_alloc.rs`

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
- Watermarks (min/low/high, from min_free_kbytes) are set once at boot
  and checked lock-free against the zone's free count (an atomic
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

**Location:** `kernel/mm/memblock.rs`

- `MEMBLOCK` (`spin::Mutex`, leaf): RAM and reserved ranges, used only
  on the boot CPU before SMP, in thread context (the arch fills it,
  early allocations take from it, the free ranges go to the frame
  allocator). `FRAME_ALLOCATOR` may be taken under it (handing the
  free ranges over); nothing else is.

#### struct page (vmemmap)

**Location:** `kernel/mm/page.rs`

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

**Location:** `kernel/mm/mod.rs` (`Mm`, `MmRef`), `kernel/mm/memory.rs`
(`exit_mmap`), `kernel/task/percpu.rs` (`exit_current`, `exec_replace_image`,
`do_clone`)

- `Mm.users` (`AtomicUsize`, Linux mm_users) counts the tasks running in
  the address space and pinned users (`MmRef`: ptrace PEEK/POKE,
  process_vm_*, a /proc/<pid>/maps read). The last `MmRef` drop runs
  `exit_mmap`, which takes the VMAs under the mm lock, drops the rmap
  chains, then tears down the user half (`paging::detach_user`, a
  TLB flush, `UserTables::free`) and drops
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
- The mmap_lock (`Mm.map`, a sleeping `RwSem<MmStruct>`, Linux
  mm->mmap_lock; "the mm lock" below) guards the VMA tree and VM
  counters. Taken through `Mm::mmap_read` / `mmap_write` and their
  `_killable` forms (the syscalls that change mappings and the /proc
  readers give up with EINTR on SIGKILL, as in Linux). Thread context
  only, never under a spinlock (sleeping locks order above all of
  them). Readers: /proc (maps, cmdline, environ, status figures),
  mincore, msync, populate, remote reads (ptrace PEEK,
  process_vm_readv), `segv_code`; every other user, the fault path
  included, takes it for writing. `dup_mm` holds the parent's mm lock while
  it copies VMAs and page tables (`memory::copy_page_range`: it
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
  lock is dropped; under it only `FRAME_ALLOCATOR` is taken (index
  nodes are frames, no heap). The object goes with its last VMA
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
- The page-fault path (`kernel/mm/fault.rs`, `handle_mm_fault`, shared by
  both arches) holds the mm lock for reading from the VMA lookup through
  the PTE update (Linux lock_mm_and_find_vma: a stack that must grow
  first takes it for writing, grows, and the fault starts over), so a
  fault cannot race fork's copy, munmap, mprotect or mremap of its
  range, which hold it for writing. Faults, MADV_DONTNEED/FREE/REMOVE
  and remote access (ptrace PEEK/POKE, process_vm_*) hold it for
  reading and may run at once: they change entries under the
  page-table locks (Page-table locks below). Under the mm lock:
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
- Page-table locks (`kernel/mm/ptl.rs`; Linux page_table_lock and split
  PTE locks): `Mm.page_table_lock` (`spin::Mutex<()>`, not IRQ-safe)
  covers table-structure changes: a missing table installed
  (`ptl::pte_alloc`), a 2MB entry mapped (`do_huge_anon`), split
  (`split_huge_pmd`) or cleared (`take_huge_pmd`). The PTE lock of each
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
  are freed while the address space is live only with the mm lock held
  for writing (munmap, mremap: `memory::free_pgtables`, Linux
  free_pgtables), after the VMAs of their range left the reverse-map
  chains, and only once empty and outside every remaining VMA's span:
  an entry pointer stays valid under any mm lock hold, or under the
  AnonVma.chain lock of a VMA it lies in (the reverse map). Order: mm lock -> page_table_lock -> PTE lock ->
  `FRAME_ALLOCATOR` (pages and tables are allocated, and the TLB is
  flushed, under them); never in interrupt context; no sleeping under
  them. A holder may flush other CPUs' TLBs: their waiters spin with
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
  table (`paging::detach_user`) into a full-mm `Gather`, which flushes
  the whole address space with its paging-structure caches
  (`flush_tlb_mm`), then frees pages and tables (`UserTables::free`). A CPU that last ran the address space
  (another thread still in `exit_current`) has it loaded until it
  switches away, so the flush reaches it (arm64 broadcast; x86 see TLB
  Flushing).

#### Swap (kernel/mm/swap.rs, swap_state.rs; Linux mm/swapfile.c, swap_state.c)

- `SwapInfo.map` (`spin::Mutex`, Linux si->lock): a device's slot
  counts (swap PTEs + SWAP_HAS_CACHE) and allocation hint; swapoff
  clears SWP_WRITEOK under it, and the allocator rechecks it there, so
  no slot is taken after swapoff's scans begin. Thread
  context only; a leaf taken under the PTE lock (fork's swap_duplicate,
  zap's free_swap_and_cache, swap-in's swap_free), never with a swap
  cache lock held.
- `SwapInfo.cache` (`IrqSpinlock<XArray>`, Linux i_pages xa_lock_irq):
  the swap cache of a device, page by slot. A leaf: under it only the
  allocator (index nodes, never sleeping). A lookup takes its page
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

#### LRU (kernel/mm/lru.rs; Linux mm/swap.c lruvec)

- `Lruvec.lock` (`IrqSpinlock`, Linux lruvec->lru_lock): the LRU lists,
  linked through struct page (`next`/`prev`, owned by the list while
  PG_LRU is set). IRQ-safe because a page leaves its list when it is
  freed (`lru::page_freed`, from the allocator's release with no
  allocator lock held), and pages are freed in any context. A leaf:
  nothing is taken under it but page reference atomics; no reference is
  dropped under it (a drop may free the page and take it again).
- Per-CPU add batches (`IrqSpinlock`, one per CPU; Linux cpu_fbatches):
  a batch holds a reference on each page; a full batch is taken out
  under its lock, then added under `Lruvec.lock` (never both held), then
  its references dropped. `lru_add_drain_all` drains every CPU's batch
  from the caller under each batch's lock (Linux asks each CPU through
  a work item).
- Isolation (reclaim) takes a page off a list under `Lruvec.lock` only
  if it can take a reference (get_page_unless_zero): a page whose count
  reached 0 is left for `page_freed`, which takes the lock and unlinks
  it. Reclaim never takes an mmap_lock while holding it.

#### Reclaim (kernel/mm/vmscan.rs; Linux mm/vmscan.c)

- `shrink_folio_list` works on pages it isolated (each with a
  reference) and holds no lock between pages. Per page: page lock by
  trylock (never waits), then swap cache add (cache lock, then slot
  counts), the reverse map (AnonVma.chain for reading -> PTE lock ->
  slot counts, TLB flush), the swap write with only the page lock
  held (block I/O sleeps), and the delete with its count frozen under
  the cache lock. It never takes an mmap_lock (callers may hold one for
  reading: MADV_PAGEOUT, a fault's direct reclaim), and holds no
  spinlock across I/O or a sleeping lock.

#### TLB Flushing (kernel/mm/tlb.rs; arch/{x86_64,aarch64}/tlb.rs)

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

#### Cross-CPU Calls (kernel/smp.rs; arch/{x86_64,aarch64}/ipi.rs)

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
  flush may have skipped it). Global: every sender needs every CPU's
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

**Location:** `kernel/arch/x86_64/kmap.rs`, `kernel/arch/x86_64/ioremap.rs`,
`kernel/arch/aarch64/kmap.rs`, `kernel/arch/aarch64/ioremap.rs`;
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
  of a range one owns is set or cleared without a lock.
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
- User half: per address space, changed by its tasks under the mm lock
  (the fault path, see Address Spaces);
  never contains a kernel mapping.

#### Heap Allocator (boot arena, slab)

**Location:** `kernel/heap.rs` (global allocator, boot arena),
`kernel/mm/slab.rs` (Linux mm/slab.c array caches, SLUB-style lists)

- Before the page allocator is up, allocations come from a static boot
  arena (first-fit list under an `IrqSpinlock` leaf); afterwards from
  kmalloc caches. A block goes back to whichever gave it.
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
  skips swap files under PF_MEMALLOC), since a file's writepage may
  need filesystem locks the allocating task holds. A fault
  whose page table cannot be allocated (under the page_table_lock)
  reclaims after dropping it and retries.

#### Page Cache

**Location:** `kernel/mm/page_cache.rs`, `kernel/main.rs` (`PAGE_CACHE`)

```rust
static PAGE_CACHE: Mutex<PageCache> = Mutex::new(PageCache::new(1024));
```

The page cache uses a hierarchical locking model similar to Linux:

**Locking Hierarchy:**
```
1. PAGE_CACHE (global Mutex) - find/create AddressSpace
   ↓
2. AddressSpace.inner (per-file RwLock) - page operations within a file
   ↓
3. AddressSpace.invalidate_lock (RwLock) - truncate/fault serialization
   ↓
4. CachedPage.lock() - page contents access (spin-wait)
```

**Per-Page Locks (CachedPage):**
- `locked: AtomicBool` - Per-page lock for I/O synchronization
- `lock()`, `unlock()`, `trylock()` methods
- Similar to Linux's `PG_locked` / `folio_lock()`

**Per-File Locks (AddressSpace):**
- `inner: RwLock<AddressSpaceInner>` - Protects page map
- `invalidate_lock: RwLock<()>` - Like Linux's `mapping->invalidate_lock`
  - Read path (fault, read): hold shared
  - Truncate/invalidate path: hold exclusive

**Reference Counting:**
- `refcount: AtomicU32` with proper memory ordering
- Uses `Ordering::AcqRel` for increments, `Ordering::Release` for decrements
- `try_claim_for_eviction()` uses CAS to prevent race during eviction

**Key APIs:**
- `find_or_create_page()` - Atomic find-or-create (fixes TOCTOU race)
- `find_get_page()` - Lookup with refcount increment

**No writeback under PAGE_CACHE:** eviction (`evict_one`, PAGE_CACHE
held) skips dirty pages; while every evictable page is dirty the cache
may exceed its limit by an eighth, then allocation fails (ENOMEM). Dirty pages are written by the flusher, fsync and sync, which
call `writepage` with no spinlock held (it does block I/O and sleeps).

**Mapped ramfs pages (Linux filemap_fault):** a MAP_SHARED fault on a
ramfs file (`InodeOps::map_page`) takes PAGE_CACHE with no spinlock
held (the mmap_lock held for reading: mmap_lock -> PAGE_CACHE) and,
still under it, a frame reference for the PTE
(PAGE_CACHE -> FRAME_ALLOCATOR), so truncate or inode eviction, which
drop only the cache's own reference (`FrameAlloc::put_frame`), cannot
free a frame a mapping still uses.

**Freeing ramfs pages (Linux evict_inode):** dropping a ramfs inode's
`RamfsInodeData` (no directory entry, open file, mapping or dentry left)
takes PAGE_CACHE -> FRAME_ALLOCATOR (its `Pcp.lock` -> `Zone.lock`
IrqSpinlocks) to free its
pages. The page cache never holds inode references, so the last inode
reference is never dropped with PAGE_CACHE held. Unevictable (ramfs)
pages are kept off the eviction FIFO and are refused at the low
watermark (`FrameAlloc::reserve_low`: the zone's free count, an atomic
read while PAGE_CACHE is held).

### 3.3 Virtual File System (VFS)

**Location:** `kernel/fs/`

The VFS uses fine-grained locking with `RwLock` for concurrent read access.
**All VFS locks are NOT IRQ-safe** and must only be accessed from thread context.

#### Global Structures

| Variable | Type | Purpose |
|----------|------|---------|
| `DCACHE` | `DentryCache` (contains `RwLock`) | Dentry cache root |

#### Descriptor Tables (Linux files_struct)

**Location:** `task/fdtable.rs`, `task/mod.rs` (`FdTable`)

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
    pub size: AtomicU64,                           // Lock-free size updates
    i_rwsem: RwSem,                                // Dir ops, file write/truncate
    pub private: RwLock<Option<Arc<dyn InodeData>>>, // FS-specific data
}
```

**Dentry** (`fs/dentry.rs`):

Following Linux's `d_lock` pattern, each dentry has a single RwLock protecting
all mutable state:

```rust
pub struct Dentry {
    pub name: String,           // Immutable after creation
    pub sb: Weak<SuperBlock>,   // Immutable after creation
    d_lock: RwLock<DentryInner>, // Single lock (like Linux d_lock)
}

struct DentryInner {
    inode: Option<Arc<Inode>>,
    parent: Option<Weak<Dentry>>,
    children: BTreeMap<String, Arc<Dentry>>,
    flags: DentryFlags,
}
```

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
| `Mount.mnt_flags` | `AtomicU32` | MNT_NOSUID/NODEV/NOEXEC; set by mount/remount, read lock-free (open, exec, statfs) |
| `SuperBlock.s_flags` | `AtomicU32` | SB_RDONLY; set by mount/remount, read lock-free by permission checks |
| `SuperBlock.s_writers` | `AtomicU64` | Write-access holders (`want_write` guard, Linux mnt_want_write). Lock-free protocol against `make_rdonly`: the writer increments `s_writers` then reads `s_flags`; the remount sets SB_RDONLY then reads `s_writers` (all SeqCst), backing out (EROFS / EBUSY) if it sees the other side, so a writer and a read-only remount never both succeed |

**Reference Counting (mntget/mntput):**

Each open `File` holds a reference to its mount via the `mnt` field:
- `File::new()` → `mntget()` increments `mnt_count`
- `File::drop()` → `mntput()` decrements `mnt_count`
- `is_mount_busy()` returns true if `mnt_get_count() > 0`
- Unmount fails with `EBUSY` if mount is busy (unless `MNT_FORCE`/`MNT_DETACH`)

**Lock Order for Mount Operations:**
```
1. MntNamespace.root (read/write)
2. parent Mount.children (write for add/remove child)
3. Mount.parent (write for set/clear)
4. Mount.mountpoint (write for set/clear)
5. Dentry.d_lock (DentryInner.flags: write for the mounted flag)
```

**Lock Order for Path Traversal (follow_mount):**
```
1. MntNamespace.root (read)
2. Mount.children (read)
3. child.mountpoint (read)
4. Dentry.d_lock (DentryInner.inode: read)
```

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
VFS layer via `inode_lock()`/`inode_unlock()` on the parent directory's inode.
This ensures no concurrent modifications to a directory's contents.

**Operations requiring inode_lock:**
- `create` (open with O_CREAT)
- `mkdir` / `mkdirat`
- `rmdir`
- `unlink` / `unlinkat`
- `link` / `linkat`
- `symlink` / `symlinkat`
- `mknod` / `mknodat`
- `rename` (uses `lock_rename()` for two-directory locking)

**API:**
```rust
impl Inode {
    /// Acquire exclusive lock for directory operations
    pub fn inode_lock(&self);

    /// Release exclusive lock
    pub unsafe fn inode_unlock(&self);
}
```

**VFS syscall pattern:**
```rust
fn sys_mkdir(...) {
    let parent_inode = parent_dentry.get_inode()?;

    // Acquire directory lock
    parent_inode.inode_lock();

    // Filesystem operation (no concurrent access possible)
    let result = parent_inode.i_op.mkdir(...);

    // Release lock
    unsafe { parent_inode.inode_unlock() };

    result
}
```

**Lookup and permission under the lock (Linux lookup_open /
filename_create):** `open.rs::create_in` (O_CREAT), `path.rs::create_entry`
(mkdir, mknod, symlink, link) and `path.rs::delete_entry` (unlink, rmdir)
take the parent's `inode_lock()` first and, while holding it, look the name
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
`i_rwsem` (via `Dentry::rename_lock()` -> `Inode::inode_lock()`), the same
lock create/mkdir/unlink/rmdir/link/symlink/mknod take on the parent, so a
rename excludes every other operation on both directories, as in Linux
(lock_rename -> inode_lock_nested). Order: `SuperBlock.s_vfs_rename_mutex`
(cross-directory only) -> directory `i_rwsem`s (ancestor first, else by
address) -> dentry `d_lock` -> fs-internal locks.

**API:**

```rust
/// Lock two directories for rename (returns "trap" if ancestor relationship)
pub fn lock_rename(p1: &Arc<Dentry>, p2: &Arc<Dentry>) -> Option<Arc<Dentry>>;

/// Unlock directories after rename
pub fn unlock_rename(p1: &Arc<Dentry>, p2: &Arc<Dentry>);

/// Check if child is a subdirectory of ancestor
pub fn is_subdir(child: &Arc<Dentry>, ancestor: &Arc<Dentry>) -> bool;
```

**Cycle Prevention:**

Before performing a rename of a directory, `is_subdir()` checks that the new
parent is not a descendant of the source directory. This prevents:
- `mv /a /a/b/c/a` (moving directory into itself)
- Creating unreachable loops in the directory tree

```rust
// In sys_renameat2:
if source_inode.mode().is_dir() {
    if is_subdir(&new_parent_dentry, &source_dentry) {
        unlock_rename(...);
        return EINVAL;  // Would create cycle
    }
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
read lock, procfs/cgroupfs inode-data read locks), so user memory must
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

**Location:** `fs/file.rs` (`File::write_from`, `File::pos_lock`),
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
  (`File::write_from`, i.e. write/writev/pwrite/pwritev*/io_uring/splice
  users of `File::write`/`pwrite`): with O_APPEND (or RWF_APPEND) the
  position is set to `i_size` under the lock, so appends from separate
  open files never overlap, and the data copy, the size update,
  RLIMIT_FSIZE check and set-id stripping are atomic with respect to
  other writers. `truncate`/`ftruncate`/O_TRUNC take it too (Linux
  do_truncate). Reads do not take it (Linux generic_file_read_iter).
- Data moves between user memory and the file through a kernel buffer
  of at most 64 KiB (`file::WRITE_CHUNK`) per step, so one call never
  pins more kernel memory than that (a full-size buffer per blocked
  reader exhausted the heap). As in Linux, the user copies (and their
  page faults) happen under `f_pos_lock` and, for writes, `i_rwsem`
  (held across all chunks, which keeps a large O_APPEND write
  contiguous); the fault path takes neither lock, and both are sleeping
  locks, so a fault may sleep. Order `i_rwsem` -> mmap_lock: the fault
  path never takes `i_rwsem`. The write's user copy runs with page
  faults disabled (`uaccess::copy_from_user_atomic`, Linux
  generic_perform_write): a missing page is faulted in first
  (`fault_in_readable`, with `i_rwsem` but no spinlock or page lock
  held) and the copy retried, so the copy itself never nests a fault
  (and the mmap_lock) under the locks taken for it (later the page
  lock).
- Order: `f_pos_lock` -> file `i_rwsem` -> page cache / page locks ->
  fs-internal locks. A file's `i_rwsem` is taken under a directory's
  only by link, unlink and rename (above), never the reverse: no
  directory lock is taken while a file's `i_rwsem` is held (O_CREAT
  drops the parent's lock before O_TRUNC).
- Both are sleeping locks (`kernel/sync`): the vfat write path may wait
  for page locks and block I/O while holding `i_rwsem`, which a spinlock
  would forbid.
- Path walk (`path.rs::lookup_slow`) takes a directory's `i_rwsem`
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
  `inode_lock`): utimensat/utimes/utime take it after `want_write` and the
  permission check, then set atime, mtime and ctime.

#### Timers (kernel/timer.rs; Linux kernel/time/timer.c)

A `TimerList` is embedded in its pinned owner and armed in jiffies
(`mod_timer`) or not before a CLOCK_MONOTONIC instant (`mod_timer_ns`,
tick granularity, never early). Each CPU has a HARD and a SOFT base
(`TimerBase`: an IrqSpinlock-protected 64-slot wheel, `running`, a wait
queue); a timer stays on the base of the CPU that first armed it.

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

#### High-resolution timers (kernel/hrtimer.rs; Linux kernel/time/hrtimer.c)

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

#### Wait Queues (kernel/waitqueue.rs)

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
  `sync::Mutex` and `Completion` wait exclusively.

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
  sem/msg, mqueue, sockets) use `wake_all`: a `wake_one` could pick a
  waiter whose condition is still false.
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

**Location:** `kernel/ns/mod.rs`, `kernel/ns/uts.rs`

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

**Location:** `kernel/time.rs`

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
    lock: IrqSpinlock<()>,       // Serializes writers, IRQs off (leaf)
    seq: AtomicU32,              // Sequence counter (odd = write in progress)
    cycle_base: AtomicU64,
    mono_base_ns: AtomicU64,
    realtime_offset_ns: AtomicI64,
    mult: AtomicU64,
    shift: AtomicU32,
    tsc_freq_hz: AtomicU64,
    initialized: AtomicU32,
    read_cycles_fn: AtomicPtr<()>,
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

**Location:** `kernel/printk.rs`, `kernel/console.rs`

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

**Location:** `kernel/signal/mod.rs`, `kernel/signal/syscall.rs`

The signal subsystem manages signal handlers (SigHand) and per-task signal state
(blocked masks, pending signals). It follows Linux's `sighand_struct` and signal
state patterns.

#### Signal Locks

| Variable | Type | Purpose |
|----------|------|---------|
| `Task.sighand` | `Option<Arc<SigHand>>` under TASKLIST | The task's handler table |
| `Task.sig` | `spin::Mutex<TaskSignalState>` (per task) | Blocked mask, private pending set, altstack (Linux siglock's per-task part) |
| `Task.thread_flags` TIF_SIGPENDING | atomic, recomputed under `Task.sig` | Pending-signal flag |
| `TaskSignalState.shared_pending` | `SharedPending` (`Arc<spin::Mutex<SigPending>>`) | Thread-group pending set |
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
   IRQ, no SIGIO/SIGURG generation, POSIX timer/itimer expiry runs in
   `ktimers/N`, no tick-based SIGXCPU/SIGPROF, fault signals are sent by
   the faulting task with interrupts on). `send_signal` reports
   `SIGNAL:FAIL` if called with a nonzero interrupt depth (arm64 IRQ
   entry now counts the depth too).

2. **SigHand.action uses IrqSpinlock** - Can be safely accessed from synchronous
   exception handlers (page faults, etc.) and process context; a leaf.

3. **shared_pending before action** - Dequeueing takes
   `shared_pending` and then reads the action (`get_action`) under it.

4. **Never hold IrqSpinlock while acquiring Mutex** - Would violate lock ordering.

#### Lock Order for Signal Operations

```
1. TASKLIST (Task.sighand; read lock to find a task)
   ↓
2. Task.sig (spin Mutex, per task)
   ↓
3. TaskSignalState.shared_pending (spin Mutex, thread-group pending)
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
child.shared_pending = parent.shared_pending.clone();  // Same Arc<Mutex<SigPending>>
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
- de_thread (exec) holds cred_guard (sleeping, outermost) while it waits
  for the other threads on CHILD_EXIT_WQ (killable); it holds no
  spinlock. The old leader and exited threads are removed under
  TASKLIST and released after it.

#### Reference Counting

`SigHand` uses `Arc` for reference counting:
- Tasks share `Arc<SigHand>` through `Task.sighand`
- Clone with CLONE_SIGHAND: child shares parent's `Arc<SigHand>`
- Clone without CLONE_SIGHAND: new `Arc<SigHand>` with deep-cloned handlers
- Exit: the Arc drops with the task's entry

### 3.8 Futex Subsystem

**Location:** `kernel/futex.rs`

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
1. Called from task exit path in `kernel/task/percpu.rs`
2. Walks the userspace robust list with a 2048 entry limit
3. For each entry, sets `FUTEX_OWNER_DIED` bit and wakes one waiter
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

**Location:** `kernel/tty/`, `kernel/gfx/console.rs`, `kernel/console.rs`, `kernel/printk.rs`

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
| `input` | `Mutex<InputBuffer>` | Hardware input ring buffer |
| `state` | `Mutex<TtyState>` | Session ID, foreground group |

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
Per-TTY locks (Mutex: termios, input, state) - independent between TTYs
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

#### Device IRQ Registration (kernel/arch/{x86_64,aarch64}/irq.rs)

| Lock | Type | IRQ class | Order |
|------|------|-----------|-------|
| `IRQ_TABLE` (per arch) | `IrqSpinlock` | taken in IRQ (`dispatch_irq`) and process context (register/unregister) | leaf except for the interrupt-controller MMIO it programs; handlers run under it |

Generic interface (`crate::arch::irq`): `IrqHandler = fn(u32, *mut ()) ->
bool`, `register_irq_handler(irq, handler, data, id)` (shareable; first
handler unmasks the line, last one masks it), `unregister_irq_handler`,
`pci_intx_irq(bus, dev, fn, pin, line)`. `PciDevice::register_irq_handler`
uses these on both arches. Every handler of a shared line is called; a line
nobody claims 100000 times in a row is masked (stuck level INTx).

- aarch64: SPIs are configured by `gic::enable_spi` (level/edge in ICFGR,
  priority 0x80, Group 1, IROUTER -> CPU 0, ISENABLER); PCI INTx comes from
  the host bridge DT `interrupt-map`/`interrupt-map-mask` parsed at boot
  (`arch/aarch64/pci_irq.rs`, matching in `bus/pci_intx.rs`), else the QEMU
  virt swizzle INTID 35 + (slot + pin - 1) % 4.
- x86-64: legacy 8259 PIC with the firmware-assigned config-space Interrupt
  Line (QEMU `pc`). Real hardware in APIC mode (Dell OptiPlex 3020 target)
  needs IOAPIC + ACPI `_PRT` routing (not implemented).
- Handlers run in IRQ context with the table lock held: they must only ack
  the device, touch atomics/IrqSpinlocks and wake threads; they must not
  register/unregister IRQs.

#### DMA API (kernel/dma.rs)

The backend (`DMA_OPS`) is set once at boot (`spin::Once`) and read
without a lock, so the streaming calls (`dma_map_single`/`unmap`, sync)
are IRQ-safe: blk-mq dispatch and completion run them in hardirq
context. `dma_alloc_coherent` allocates frames (thread context only).

#### USB Subsystem

**Location:** `kernel/usb/`

| Lock | Type | Purpose |
|------|------|---------|
| `USB_CONTROLLER` | `Mutex<Option<XhciController>>` | Global xHCI controller access |
| `XHCI_IRQ_STATE.*` | `AtomicU64`, `AtomicBool` | ISR state (lock-free) |
| `USB_OUTPUT_ACTIVE` | `AtomicBool` | Console recursion guard |
| `BOUNCE` (usb/serial.rs) | `Mutex<[u8; 256]>` | USB serial console DMA buffer: `try_lock` only (a busy buffer drops the output), held across the bulk transfer, so it orders before `USB_CONTROLLER` |

DMA buffers never live on a kernel stack (stacks are not in the linear
map, `mm::vmstack`; `DirectDmaOps` panics on one): the mass-storage
CBW/CSW and the INQUIRY/READ CAPACITY data are heap buffers, the
console's output goes through `BOUNCE`.

**ISR Pattern:** The xHCI ISR sets `interrupt_pending` atomic but does NOT acquire
`USB_CONTROLLER` mutex. This avoids IRQ-context deadlock since the mutex is not
IRQ-safe.

#### Block Device Subsystem

**Location:** `kernel/storage/` (`blkdev.rs`, `blk_mq.rs`, `genhd.rs`,
`part/`), `kernel/virtio/blk.rs`, `kernel/fs/{blkdev_ops,devtmpfs}.rs`,
`kernel/completion.rs`

Linux model (block/bio.c, blk-mq.c, genhd.c): a bio is submitted from
thread context, the driver completes it from its interrupt handler and
`bio_endio` runs `end_io` there (hardirq). `submit_bio_wait` sleeps on a
`Completion` that `end_io` completes.

| Lock | Type | IRQ class | Order |
|------|------|-----------|-------|
| `Disk.open_mutex` | `sync::Mutex` (sleeping; Linux disk->open_mutex) | thread only | outermost block lock: block device open/release, partition scans (and rescans, BLKRRPART); I/O, `BLKDEV_REGISTRY`, `MAJORS` and the devtmpfs root's `i_rwsem` are taken under it |
| `BLKDEV_REGISTRY` | spin `RwLock` (dev_t -> block device; global like Linux's bdev map) | thread only | leaf |
| `MAJORS` | spin `Mutex` (block majors, register_blkdev) | thread only | leaf |
| blk-mq software queue (`BlkMq.ctxs[cpu]`) | `IrqSpinlock<BioList>`, one per CPU | thread (submit) | leaf: never taken with the hardware queue lock held |
| blk-mq hardware queue (`BlkMq.hctxs[i]`) | `IrqSpinlock` over the dispatch list and the driver queue (virtio-blk: one virtqueue and its tags; Linux virtio_blk_vq.lock) | thread (dispatch) and hardirq (completion, restart) | leaf: `queue_rq`/`complete` only touch the ring, MMIO and the lock-free DMA API (`DMA_OPS` is a `Once`), never allocate or sleep; taken under `IRQ_TABLE` in the ISR |
| `Completion.done` | `IrqSpinlock<u32>` | any context | -> its wait queue head -> run-queue lock (the wakeup is issued under it, Linux complete()) |
| `RamDisk.pages` | spin `Mutex` | thread only (bio-based driver) | leaf |
| devtmpfs `PENDING` | spin `Mutex` (nodes queued before VFS init) | thread only | leaf (holds the devtmpfs root read under it) |

Rules:

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
- **No page cache in front of block devices yet:** device file I/O is
  synchronous bios through bounce frames, never under a spinlock. The
  page cache never writes a page back under `PAGE_CACHE` (3.2 Page
  Cache): writepage sleeps on block I/O.

#### Network Subsystem

**Location:** `kernel/net/`, `kernel/net/core/dev.rs`, `kernel/ns/net.rs`

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
| `Softnet.busy` (per CPU) | `AtomicBool` | thread only | one task processes a CPU's backlog at a time (softnet/N or an inline `netif_rx_flush_local`); a flush that finds it set leaves the packets to the running one |
| `dev::TIMER_DUE` | `AtomicBool` | thread (an Alarm callback on `ktimers/N` sets, softnet/0 clears) | protocol timers are due: softnet/0 runs `tcp::timer::run` with no lock held |
| `Napi.sched`, `Napi.disable` | `AtomicBool` | IRQ + thread | `sched` set by `napi_schedule` (only the setter queues it), cleared by `napi_complete_done` (a SeqCst RMW: a full barrier before the driver re-checks its pending causes, Linux cmpxchg), held by `napi_disable` (driver `stop`, RTNL held, sleeps until a running poll completes) until `napi_enable` (driver `open`); `disable` makes softnet complete an over-budget poll instead of requeueing it |
| `NetDevice.running` | `AtomicBool` | thread (RTNL writers; NAPI poll readers) | Linux __LINK_STATE_START (`netif_running`): set before the driver's `open`, cleared before its `stop`; polls re-enable device interrupts only while set, checked under the driver's `rx` lock that `stop` takes to mask, so open/close never strand a device masked or leave a stopped one unmasked |
| `PTYPE_BASE`, `PTYPE_ALL` | `spin::RwLock` (`Vec<..>` / fixed array of taps) | thread only | leaf; handlers copied out, called after unlock. Taps (AF_PACKET) run from `netif_receive_skb` and from `dev_queue_xmit` (PACKET_OUTGOING), i.e. possibly under a caller's socket or neighbour-free transmit path: they take only the AF_PACKET leaves below |
| `NAPI_LIST`, `SOFTNET_THREADS` | `spin::Mutex<Vec<..>>` | thread only | leaf; registration |
| `Sock` (`net/sock.rs`, in every protocol socket) | atomics + `Sock.wq` (`WaitQueue`) | any (wakeups) | error, shutdown, buffer sizes, timeouts, SOL_SOCKET flags, SO_LINGER (switch and time in one word); one wait queue per socket for readers, writers, connect/accept and pollers (`sk_data_ready`/`sk_write_space`/`sk_state_change` = `wake_all`), woken after the socket's own protocol locks are dropped; another path may wake it under its own locks (an AF_PACKET tap queueing to a packet socket under a transmitting TCP socket's `cb`): `Sock.wq` is an IrqSpinlock taking only run-queue locks, so that never inverts |
| sockfs inode `private` | `spin::RwLock` (VFS, `Inode.private`) | thread only | read per socket file operation (`sock_of`) to reach the protocol socket; leaf |
| `TcpSock.cb` (`net/tcp/mod.rs`) | `spin::Mutex<Inner>` | thread only (softnet input, softnet/0 timers, socket calls) | the TCP socket lock: Linux `bh_lock_sock` plus the `tcp_sock` state it guards (the whole I/O-free `TcpCb`: state, sequence space, send/receive/out-of-order queues, RFC 7323 option state, delayed-ACK state, RTO, all timers, the IPPROTO_TCP options (`TcpCb.opts`; the separate `TcpSock.opts` leaf is gone); tuple, port ownership, listener link). Held for one bounded step: never across a sleep or a user copy. The step's `Out` is applied before the unlock (Linux transmits under the socket lock): error and shutdown bits are published and segments transmitted under it (cb -> FIB / neighbour / device TX, which never re-enter a socket lock), so one connection's segments are never reordered across CPUs; only wakeups follow the unlock. Segment input re-checks under it that the socket still has the tuple it was found by. A listener's is taken before its new child's (creating it, and sending its SYN-ACK); a child never takes its listener's `cb` (it queues itself under the listener's `queue` leaf and the listener is woken after the child's unlock) |
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
| `NlSock.rxq`, `NlSock.dst` | `spin::Mutex` | thread only | leaf; replies, dump parts and notifications are pushed under it (each charged to rcvbuf first), `wq` is woken after it is dropped |
| `NlSock` portid/groups/flags/err/rmem/congested/dead, autobind `ROVER` | atomics | thread only | `dead` (Linux SOCK_DEAD) is set at release, which then purges `rxq` and wakes `Sock.wq`: a user sender waiting there for room fails ECONNREFUSED |
| `UnixSock.bindlock` (`net/unix`) | `sync::Mutex<()>` (sleeping) | thread only | Linux u->bindlock: bind/autobind; taken with no spinlock held, before `UnixTable.st`/`BSD`. A path bind runs the VFS mknod (parent `i_rwsem`) first and takes `bindlock` after it returns (Linux nests i_rwsem -> bindlock; hk does not need to); if the socket got bound meanwhile it drops `bindlock` before unlinking the node, so `i_rwsem` is never taken under `bindlock` |
| `UnixSock.iolock` | `sync::Mutex<()>` (sleeping) | thread only (recvmsg) | Linux u->iolock: one reader across dequeue -> user copy -> consume; dropped before waiting for data; above `st`/`rq` |
| `UnixSock.st` | `spin::Mutex<Option<Arc<UnixSock>>>` | thread only | Linux unix_state_lock: the peer; `state`, shutdown bits and `dead` change under it. At most two published sockets at once: listener -> connecting socket (stream connect; a socket that is not CLOSE fails before taking its own, so listeners never nest), then the new server-side socket (not yet reachable by anyone; Linux unix_state_lock_nested(newsk)) as a third; or two in ascending address order (`lock2`, Linux unix_state_double_lock: dgram connect, socketpair). Senders queue under the receiver's `st`, so nothing is queued to a released socket |
| `UnixSock.rq` | `spin::Mutex<RxQueue>` | thread only | receive queue (Linux sk_receive_queue.lock), under `st`; a listener's queue holds embryo connections |
| `UnixTable.st` (per netns), `unix::BSD` (global, by inode) | `spin::RwLock` | thread only | all sockets + abstract names (per type) / filesystem bindings; after `bindlock`, before `UnixSock.addr` (published under them); lookups return `Arc`s, no socket lock under them |
| `UnixSock.addr`, `UnixSock.peercred`, `UnixSock.relay` | `spin::RwLock` / `spin::Mutex` | thread only | leaves (Linux u->addr, sk_peer_lock, peer_wait.lock for peer_wake relays); `relay` also guards the registered sockets' `peer_wake` atomics |
| `unix::scm::INFLIGHT`, `Task.fput_defer` | `spin::Mutex` | thread only | leaves: per-user in-flight file counts (charged under the receiver's `st`); the current task's files awaiting `defer_fput` (each task drains its own, like Linux task_work fput; `Some` marks the task draining, so nested releases queue instead of recursing; only the task itself takes it) |
| `UnixSock` `state`/`dead`/`wmem`/`backlog`/`peer_wake` | atomics | thread only | |
| `NetDevice.net` | `spin::RwLock<Weak<NetNamespace>>` | thread only | read per received packet; written at registration under the namespace's `devices` write lock (order `devices` -> `NetDevice.net`) |
| driver `netdev` / `Napi.poller` (`spin::Once<Weak<..>>`) | set once at probe, before the IRQ is registered and the NAPI added | read lock-free by polls (thread) | ISRs never read them (they use the driver struct passed as IRQ data) |
| `icmp::ICMP_ECHO_REPLY_WQ` | `WaitQueue` | woken by ICMP input (softnet) | kernel self-test waiter only (`selftest.rs`), woken after the reply is recorded |
| `UnixSock.peer_wait` | `WaitQueue` | thread only | Linux peer_wait: dgram senders blocked on a full peer wait here (no lock held); woken by the peer's reads and release, relays to pollers via `UnixSock.relay` |
| `NetNamespace.sysctl`, `port_range` (`/proc/sys/net`, `kernel/sysctl.rs`) | atomics | thread only | no locks; a multi-value sysctl (ping_group_range, ip_local_port_range) is one packed atomic word, so readers never see half an update; the boot port/ISN secret is a `spin::Once` |
| `NetDevice.stats`, `flags`, `mtu`, `ifindex`, `carrier`, `promiscuity`, `allmulti` | atomics | any (`promiscuity`/`allmulti` written only under RTNL) | `flags` holds administrative state only; IFF_RUNNING/IFF_LOWER_UP/operstate are derived on read |
| e1000 `rx` ring | `spin::Mutex` | thread only (NAPI poll) | leaf; frames are delivered after it is dropped |
| e1000 `tx` ring | `spin::Mutex` | thread only (xmit, poll reclaim) | leaf; ring full -> drop, `tx_dropped`, ENOBUFS |
| e1000 `pending_icr`, irq counters | atomics | IRQ + thread | ISR ORs ICR causes in; poll swaps them out |
| virtio-net `rx` queue (`net/driver/virtio_net.rs`) | `spin::Mutex` | thread only (NAPI poll, open) | leaf: virtqueue + bounce buffers; frames are delivered after it is dropped |
| virtio-net `tx` queue | `spin::Mutex` | thread only (xmit, poll reclaim) | leaf; one descriptor per frame; ring full -> drop, `tx_dropped`, ENOBUFS |
| virtio-net `config_pending`; `VringCb` (RX avail NO_INTERRUPT flag) | atomics / lock-free MMIO-style store | IRQ + thread | the ISR suppresses RX interrupts and flags config changes; the poll re-enables under `rx` only while `netif_running`, and `stop` suppresses under `rx` |
| virtio-PCI transport (`virtio/pci.rs`) | none | probe (single-threaded enumeration), then IRQ (ISR byte) | common config written only during probe; device config reads are generation-checked and lock-free; queue notify writes happen under the caller's queue lock |
| `virtio::DRIVERS` | `spin::Mutex<Vec>` | thread only (boot) | leaf; registered before bus enumeration, read by the PCI match/probe |

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
RTNL. Carrier changes (`netif_carrier_on/off`, from a driver's NAPI poll
or `open()`) send RTM_NEWLINK without RTNL (NlTable.socks -> NlSock.rxq
only). Open/close follow Linux __dev_open/__dev_close: `running` is set
before the driver's open (which `napi_enable`s, then unmasks) and cleared
before its stop (which `napi_disable`s, waiting for a running poll, then
masks under `rx`). A poll re-enables interrupts only while `running`,
under `rx`: a poll racing with open re-enables them, one racing with
close leaves the device masked; `netif_receive_skb` drops frames of a
down device.

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
| `SignalStruct.posix_timers` | signal/mod.rs, posix_timer.rs | spin Mutex | the thread group's POSIX timers and ITIMER_REAL (Linux signal->posix_timers); leaf, thread context; deleted at the group's last exit (`exit_itimers`, timers stopped after the lock) or with the SignalStruct |
| `PosixTimer.inner` | posix_timer.rs | IrqSpinlock | one timer's state; -> its hrtimer's base (re-armed under it); cancelled with `cancel_sync` before it is taken (settime) or with it dropped (delete) |
| timerfd `CANCEL_LIST` | timerfd.rs | spin::Mutex | thread only: weak refs to TFD_TIMER_CANCEL_ON_SET timerfds; -> `Timerfd.inner` (setup_cancel); `clock_was_set` copies it out and drops it first |
| `TimerBase.wheel` (per CPU, HARD and SOFT) | timer.rs | IrqSpinlock leaf | a 64-slot wheel of `TimerList`s (their links, `expires`, `pending`); callbacks run with it dropped (`running` set); taken in the tick, by `ktimers/N` and by arming/deleting code in any context |
| `HrBase.q` (per CPU, HARD and SOFT) | hrtimer.rs | IrqSpinlock leaf | sorted lists of `HrTimer`s per clock (their links, `expires`, `pending`); callbacks run with it dropped (`running` set); taken in the clock event interrupt, by `ktimers/N` and by start/cancel in any context |
| `Eventfd.inner`, `Eventpoll.inner`, `Inotify.inner`, `Fanotify.inner`, `IoUring.inner`, `Pidfd.inner`, `Signalfd.inner`, `Timerfd.inner` | eventfd.rs, epoll.rs, inotify.rs, fanotify.rs, io_uring.rs, pidfd.rs, signalfd.rs, timerfd.rs | IrqSpinlock | per-object state of the anon-inode files; their wait queues are woken after unlocking (pidfd: under it -> wait queue head) |
| `SIGNALFD_REGISTRY`, `PIDFD_REGISTRY` | signalfd.rs, pidfd.rs | IrqSpinlock | live instances for signal and exit notification; registry -> the instance's `inner` |
| `Workqueue.inner` | workqueue.rs | IrqSpinlock | pending and delayed work lists (`SYSTEM_WQ`, `BDI_WORKQUEUE`); a work item's own `spin::Mutex<Work>` is taken and dropped before it |
| `BDI_REGISTRY`, `BdiWriteback.dirty_inodes`, `BdiWriteback.dwork` | mm/writeback.rs | spin | per-device writeback state |
| `DIRTY_ADDRESS_SPACES` | mm/page_cache.rs | spin Mutex | files with dirty pages (sync) |
| `Task.cgroup`, `CSS_SET_CACHE`, `CgroupRoot.{root_cgrp, controllers}`, `Cgroup.{parent, children, ancestors, subsys, tasks}`, `CssSet.subsys`, `CgroupSubsysState.private`, `IoState.devices` | cgroup/ | spin (RwLock; `CSS_SET_CACHE`, `Task.cgroup` Mutex) | cgroup hierarchy and membership (`Task.cgroup`: the task's cgroup, a leaf reached through a `TaskRef` cloned out of TASKLIST, Linux task->cgroups); parent before child; never under TASKLIST |
| `IpcIds.inner`, `KernIpcPerm.lock`, `MsgQueue.{messages, receivers, senders}`, `MsgReceiver.result`, `SemArray.pending`, `SemUndoList.undos`, `MQ_REGISTRY`, `MqQueue.{messages, flags, notify}` | ipc/ | spin | SysV and POSIX IPC objects; `IpcIds.inner` -> the object's lock |
| `Task.keyrings` → `KEY_DATABASE`, `USER_KEYRINGS`, `Key.payload`, `Key.keyring_keys` | keys/ | spin (RwLock; `Task.keyrings` Mutex) | a task's thread/process/session keyring references (`Task.keyrings`, reached through a `TaskRef` cloned out of TASKLIST; creating a keyring registers it under it), key registry and keyrings (lookups clone the `Arc<Key>` out) |
| `FILE_LOCKS` (flock), `POSIX_LOCKS` | fs/flock.rs, fs/posix_lock.rs | spin Mutex | file lock tables; waiters sleep with them dropped |
| `FS_TYPES`, `CHARDEV_REGISTRY` | fs/superblock.rs, chardev.rs | spin | filesystem types, character device registry |
| `File.f_lock` | fs/file.rs | spin Mutex | file status flags (Linux f_lock) |
| `SuperBlock.{root, private}`, `DentryCache.root` | fs/superblock.rs, fs/dentry.rs | spin RwLock | superblock root and private data, the dcache root |
| `RamfsInodeData.xattrs`, `RamfsSbData.sb` | fs/ramfs.rs | spin | ramfs xattrs and superblock back-pointer (under VFS locks) |
| membarrier `GLOBAL_MUTEX` → `IPI_MUTEX` | membarrier.rs | sleeping (`sync::Mutex`; `IPI_MUTEX` is Linux membarrier_ipi_mutex) | `IPI_MUTEX` serializes the membarrier commands that interrupt other CPUs, so callers cannot multiply the IPIs; held only across `smp_call_function_many` (waited); nothing is taken under it. `GLOBAL_MUTEX` (killable) paces MEMBARRIER_CMD_GLOBAL to one call per tick: held across its IPIs and its one-tick sleep, so GLOBAL callers never delay the expedited ones. The targets are chosen from each CPU's `PerCpuScheduler.curr_mm` / `membarrier_state` (atomics written at every switch in `make_current`, SeqCst for `curr_mm`; Linux rq->curr->mm and rq->membarrier_state), compared, never dereferenced |
| `Pipe.inner` | pipe.rs | sleeping (`sync::Mutex`, Linux pipe->mutex) | the pipe's buffer ring; held across page allocation, never under a spin lock; two pipes (splice, tee) in address order (Linux pipe_double_lock); -> frame allocator. `Pipe.head`/`tail` (atomics) are published as the guard unlocks and read locklessly by wait conditions and poll (poll runs under `Eventpoll.inner`, an IrqSpinlock); wakeups follow the unlock |
| `NTtyLdisc.data` | tty/n_tty.rs | spin Mutex | line discipline buffer (input is polled, not IRQ-fed) |
| `VgaCon.state` | arch/x86_64/vgacon.rs | IrqSpinlock | VGA text console state, under `CONSOLE_REGISTRY` (3.9) |
| `SimpleGfxDevice.state`, `GFX_DEVICES`, `NEXT_MINOR` | gfx/ | spin | framebuffer device state and registry |
| `UsbMscDevice.state` | usb/msc.rs | spin | USB mass-storage device state |
| `INTX_MAP` | arch/aarch64/pci_irq.rs | spin Mutex | PCI INTx routing from the device tree (boot) |
| `CMDLINE_CONSOLE`, `CRNG` | cmdline.rs, random.rs | spin Mutex | console= choice, CRNG state |
| `NUMA_TOPOLOGY` | numa.rs | IrqSpinlock | NUMA node table |
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

#### hk Pattern Examples

The following patterns are CORRECT uses of atomics in hk:

| Subsystem | Atomic Fields | Why Correct |
|-----------|---------------|-------------|
| `TimeKeeper` | seq, cycle_base, mono_base_ns, etc. | Seqlock pattern - all read together with seq validation |
| `Inode` | mode, uid, gid, size, nlink | Each field updated independently by different operations |
| `File` | pos | File position modified independently (concurrent reads OK) |
| `Sock` | flags, error, shutdown, buffer sizes | Independent flags; protocol data under the socket lock |
| `CachedPage` | refcount, dirty, writeback, locked | Linux page cache pattern - flags + refcount |
| `MsgQueue` | stime, rtime, cbytes, qnum, etc. | Different syscalls update different subsets |

All hk structs that update multiple related fields atomically use locks:
- `MsgQueue.messages: Mutex<VecDeque<MsgMsg>>` - protects message list
- `SemArray.pending: Mutex<VecDeque<...>>` - serializes pending ops
- `PageCache inner locks` - protect page maps

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
| `TASKLIST` | kernel/task/percpu.rs | `RwLock` | every task (Linux tasklist_lock) |
| `TaskSignalState.shared_pending` | kernel/signal/mod.rs | `Mutex` | Thread-group pending signals (under TASKLIST) |
| `Task.alloc_lock` | kernel/task/mod.rs | `Mutex` | A task's mm, files, fs, nsproxy, comm, mempolicy, io_context (Linux task_lock; under TASKLIST, over `Task.sig`) |
| `FsStruct.inner` | kernel/fs/fsstruct.rs | `Mutex` | Root, cwd, umask (leaf) |
| `NPROC` | kernel/task/mod.rs | `Mutex` | RLIMIT_NPROC tasks per real uid (leaf: may be taken under TASKLIST, takes no lock) |
| `MEMBLOCK` | kernel/mm/memblock.rs | `Mutex` | Boot memory map (boot CPU, before SMP) |
| `ACCT_FILE` | kernel/acct.rs | `Mutex` | Process accounting file (leaf: cloned out, the record written and an old file released with no lock held) |
| `PAGE_CACHE` | kernel/mm/page_cache.rs (static in kernel/main.rs) | `Mutex` | Page cache lookup |
| All VFS locks | kernel/fs/*.rs | `RwLock` | Inodes, dentries, mounts |
| Descriptor tables (`Files`) | kernel/task/fdtable.rs | `Mutex` | Per-task fd tables |
| `RTNL` and every network `spin::Mutex`/`RwLock` | kernel/net/ | `sync::Mutex` / `Mutex` / `RwLock` | Configuration, sockets, tables, queues (3.10) |
| Driver queue locks (e1000 / virtio-net `rx`, `tx`) | kernel/net/driver/ | `Mutex` | Rings: NAPI poll, xmit, open/stop |
| `Softnet.backlog` | kernel/net/core/dev.rs | `Mutex` | `netif_rx` (lo), softnet |
| `BLKDEV_REGISTRY`, `MAJORS`, `RamDisk.pages`, devtmpfs `PENDING` | kernel/storage/, kernel/fs/devtmpfs.rs | `RwLock` / `Mutex` | Block device lookup, majors, RAM disk pages, early device nodes (3.10) |
| `Disk.open_mutex` | kernel/storage/blkdev.rs | sleeping `sync::Mutex` | Block device open/release, partition scans |
| Sleeping locks (`sync::Mutex`, `RwSem`) | kernel/sync/ | sleeping | Never in IRQ or atomic context (`might_sleep`) |

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

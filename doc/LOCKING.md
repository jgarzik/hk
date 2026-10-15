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

### 1.2 Mutex<T> (spin crate)

A standard spinning mutex from the `spin` crate. Used for data structures that
are **NOT** accessed from interrupt context.

**Properties:**
- Blocking (spins until lock acquired)
- Does NOT disable interrupts
- Does NOT track preempt_count
- Suitable for longer critical sections in thread context

**Use cases:**
- Global task table (TASK_TABLE)
- Page cache
- File descriptor tables
- Frame allocator (thread context only)
- Heap allocator (thread context only)

**CRITICAL CONSTRAINT:** Never acquire a `Mutex` from interrupt context. If you
need to access the data from an interrupt handler, use `IrqSpinlock` instead or
defer the work.

### 1.3 RwLock<T> (spin crate)

A read-write lock from the `spin` crate. Allows multiple concurrent readers
or one exclusive writer.

**Properties:**
- Multiple readers OR single writer
- Does NOT disable interrupts
- Reader-writer fairness depends on implementation

**Use cases:**
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
on the lock's `WaitQueue` instead of spinning (it spins only before
scheduling is enabled), so the holder may sleep (page locks, block I/O,
user page faults, blocking pipe/socket I/O).

- `Mutex<T>`: owner tid recorded (debug builds catch recursive locking
  and foreign unlocks); `unlock` wakes one waiter, which retries.
- `RwSem`: `down_read`/`up_read` (shared), `down_write`/`up_write`
  (exclusive); writer preference: once a writer waits, new readers wait
  behind it. Its count word is a short `spin::Mutex` leaf never held
  across a sleep; release wakes all waiters (mixed conditions).
- Rules: thread context only; never taken in IRQ context or while any
  spinlock is held (`might_sleep` asserts a zero preempt count in debug
  builds; `IrqSpinlock` raises it). Sleeping locks order ABOVE every
  spinlock: a spinlock may be taken under them, never the reverse.

**Used for:** `Inode.i_rwsem` (`RwSem`), `SuperBlock.s_vfs_rename_mutex`
and `File.f_pos_lock` (`Mutex`).

### 1.5 Atomic Types

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
VFS locks (detailed order):
    File.f_pos_lock (sync::Mutex; read/write/lseek/getdents by position)
        ↓
    MOUNT_NS.root
        ↓
    Mount.{children, parent, mountpoint}
        ↓
    SuperBlock.s_vfs_rename_mutex (cross-directory rename only)
        ↓
    Inode.i_rwsem (sync::RwSem; exclusive: directory operations,
                   lock_rename, regular file write and truncate; shared:
                   path-walk lookup on a dcache miss, readdir)
        ↓
    Dentry.d_lock (single d_lock like Linux; short, never held across i_rwsem)
        ↓
    Inode.{lock, private}
        ↓
Filesystem-internal locks (ramfs children/data, procfs data)
    ↓
Namespace locks:
    TASK_NS (Mutex)  ← Global TID→NsProxy mapping
        ↓
    UtsNamespace.name (RwLock)  ← Per-namespace UTS data
    ↓
Signal locks:
    TASK_SIGHAND (Mutex)  ← Global TID→SigHand mapping
        ↓
    TASK_SIGNAL_STATE (Mutex)  ← Per-task blocked/pending
        ↓
    SigHand.action (IrqSpinlock)  ← Signal handler table
    ↓
Futex locks:
    TASK_ROBUST_LIST (Mutex)  ← Per-task robust list heads
        ↓
    FutexHashBucket.waiters (IrqSpinlock)  ← Per-bucket waiter list
    ↓
Filesystem context locks (TASK_FS)
    ↓
Per-CPU scheduler locks (IrqSpinlock)  ← IRQ-safe, can hold while acquiring below
    ↓
Global subsystem locks (TASK_TABLE, PAGE_CACHE, fd table `Files`)  ← NOT IRQ-safe;
    no file is released under `Files` (3.3, Descriptor Tables)
    ↓
Address space: Mm lock (mmap_lock) → AnonVma, LRU  ← never nested with TASK_TABLE (3.2)
    ↓
Memory allocator locks (FRAME_ALLOCATOR, heap)  ← NOT IRQ-safe

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
   fundamental rule. TASK_TABLE, PAGE_CACHE, fd tables, and allocator locks must
   NEVER be acquired from timer ISR or any interrupt handler.

3. **Parent before child** - When locking multiple inodes in a directory
   hierarchy, lock parents before children.

4. **For multiple directories** - When an operation spans multiple directories
   at the same level, lock in increasing inode number order.

5. **Release in reverse order** - Always unlock in the opposite order of acquisition.

6. **VFS locks are outer locks** - Filesystem-internal locks must always be
   acquired while holding VFS locks, never the reverse.

### Why IrqSpinlock → TASK_TABLE is Safe

The scheduler acquires `IrqSpinlock` then `TASK_TABLE` because:

1. `IrqSpinlock` disables interrupts on the local CPU
2. While interrupts are disabled, no ISR can run on this CPU
3. Therefore, no deadlock can occur from the timer ISR trying to acquire TASK_TABLE
4. This ordering is safe because TASK_TABLE is NEVER acquired from interrupt context

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
- No nested interrupt can try to acquire TASK_TABLE
- Deadlock is impossible from the local CPU

Other CPUs cannot cause deadlock because:
- They follow the same ordering (IrqSpinlock → TASK_TABLE)
- No CPU ever acquires TASK_TABLE then IrqSpinlock
- TASK_TABLE is NEVER acquired from interrupt context (see Section 7.4)

---

## 3. Per-Subsystem Locking

### 3.1 Scheduler

**Location:** `kernel/task/percpu.rs`

The scheduler uses a per-CPU locking model to minimize contention.

#### Global State

| Variable | Type | Purpose |
|----------|------|---------|
| `PERCPU_SCHEDS` | `[PerCpuScheduler; MAX_CPUS]` | Per-CPU scheduler array |
| `TASK_TABLE` | `Mutex<GlobalTaskTable>` | Global task registry |
| `SCHEDULING_ENABLED` | `AtomicBool` | Global scheduling enable flag |
| `TICK_COUNT` | `AtomicU64` | Global tick counter (jiffies, TICK_MS = 10 ms); advanced only by CPU 0's tick, which also runs `check_timers()`; every CPU's tick runs its own `wake_sleepers()` |

#### Per-CPU State

Each `PerCpuScheduler` contains:
```rust
pub struct PerCpuScheduler {
    pub lock: IrqSpinlock<CpuRunQueue>,  // Protects run queue
    pub initialized: AtomicBool,          // Init flag
}
```

Each `PerCpu` (per-CPU data) contains:
```rust
pub interrupt_depth: AtomicU32,   // Nesting depth of interrupts
pub preempt_count: AtomicU32,     // Preemption disable count
pub needs_reschedule: AtomicBool, // Reschedule request flag
```

#### Locking Rules

1. **Each CPU only locks its own run queue** - no CPU ever takes another
   CPU's `PerCpuScheduler.lock`. A wakeup for a task owned by another CPU is
   posted to that CPU's `wake_list` (an `IrqSpinlock<Vec<(Tid, WakeMode)>>`,
   a leaf lock) and applied by the owner, under its rq lock, at its next
   `schedule()`/`yield_now()`/tick (Linux ttwu_queue). Tasks never migrate:
   `Task.cpu` names the owning run queue.

2. **Run queue lock is IRQ-safe** - Timer interrupts cannot cause deadlocks.
   Lock order: rq lock → `wake_list` (drain) and rq lock → `TASK_TABLE`
   (switch info, priority refresh). Never take an rq lock while holding
   `TASK_TABLE`, and never call a wakeup (`wake_up_task`, `WaitQueue::wake*`)
   while holding this CPU's rq lock (it is not recursive).

3. **Context switch happens with lock held** - The lock is released by the
   task switched to (its guard drop, or `finish_context_switch` for a new
   task).

4. **`context_switch_first()`** - An exiting task (`exit_current`) keeps
   the lock held across its final switch like any other switch (the guard
   is forgotten; the next task releases it), so nothing runs on this CPU
   between leaving the dead task and the next task taking over. Only the
   boot-time first switch (`try_schedule`) drops it before switching.

5. **Timer ISR only touches local CPU** - `wake_sleepers()` drains the local
   `wake_list` and wakes expired sleepers of the local sleep queue only.

6. **Per-CPU syscall user state belongs to the current task** - the
   `syscall_user_*` block in per-CPU data is saved on the outgoing task's
   kernel stack across every `context_switch` and restored when it runs
   again, so a task that slept inside a syscall returns (and builds signal
   frames) with its own registers. A user fault that delivers a signal
   (`force_sig_fault`) loads the block from the fault's trap frame and
   copies it back afterwards; the task is not inside a syscall then.

7. **User FP/SIMD state is saved eagerly, per task, never lazily** - no
   lock is involved; the state always lives with the task it belongs to:
   - x86-64: the kernel is soft-float and never touches x87/XMM/YMM, so a
     task's user FP state stays in the registers while it is in the kernel.
     `context_switch` XSAVEs (or FXSAVEs) it into an area on the outgoing
     task's kernel stack and XRSTORs it when that task runs again; a fork
     child gets the parent's state in a reserve above its trap frame
     (`SchedArch::CLONE_FPU_RESERVE`), loaded by `clone_child_entry`.
   - aarch64: the kernel uses NEON, so every exception entry (EL0 and EL1)
     saves q0-q31/FPCR/FPSR in its trap frame and restores them on exit;
     the EL0 frame (per-CPU `user_frame`, saved with the syscall block of
     rule 6) holds the user FP state. `__switch_to_asm` preserves d8-d15.
   Signal frames, fork and execve read/write the state in these places;
   nothing may use user FP registers between a context switch's save and
   the task's next return to user mode except through them.

8. **Dead tasks are freed by the next task (Linux finish_task_switch)** -
   `exit_current` cannot free the kernel stack it runs on, nor the
   top-level page table still loaded in CR3/TTBR0. It pushes them as a
   `DeadTask` (stack, mm_count reference) on its rq's `dead` list, under
   the rq lock held across the switch. The task switched to takes the list
   under the rq lock and frees it after releasing the lock (in
   `context_switch_locked`, or `finish_context_switch` for a new task):
   frame frees and the last `Arc<Mm>` drop (top-level table, heap) never
   happen under the rq lock.

#### Sleep / Wakeup Protocol (Linux set_current_state / try_to_wake_up)

Each run-queue entry (`KernelThreadContext`) carries the scheduling truth:
`state: SleepState {Running, Interruptible, Uninterruptible}` and `queued`
(present in the priority queue; prevents double enqueue).

```text
sleeper                                   waker (any CPU, any context)
-------                                   -----
register on wait queue                    make condition true
set_current_state(Interruptible)          wake_up_task(tid, cpu, mode):
if condition: done                          own CPU:  lock rq, try_wake
if signal_pending(): -ERESTARTSYS           remote:   push to wake_list
schedule()  // returns at once if a       try_wake: state != Running →
            // wakeup already set Running   Running, enqueue unless current
```

`WakeMode::Interruptible` (signals) wakes only `Interruptible` sleepers;
`WakeMode::Any` (wait queues, timeouts) wakes both. `schedule_timeout(t)`
adds a sleep-queue entry; whichever of wakeup and timeout comes first ends
the sleep and the entry is removed afterwards. Spurious wakeups are allowed:
every sleeper re-checks its condition.

**Preemption model:** hk is non-preemptive (cooperative). The timer tick
never switches tasks, in kernel or user mode; switches happen only in
`schedule()`, `yield_now()`, `exit_current()` and AP startup. Therefore a
`spin::Mutex`/`RwLock` holder is never involuntarily preempted, and the only
same-CPU hazard is an IRQ handler taking a lock the interrupted code holds
(hence the IRQ rules). A `PreemptSpinlock` is not needed today; if
preemption is ever added it must honor `preempt_count`, and `spin::Mutex`
would then need a preempt-disabling wrapper.

**RCU hook:** `PerCpuScheduler.nr_switches` counts context switches per CPU;
since kernel code cannot be preempted, a change in a CPU's counter (or the
CPU being idle) is a quiescent state for a future QSBR RCU.

#### Kernel Threads (kernel/task/kthread.rs)

`kthread_run(name, fn, arg, cpu)` creates a pid-0 task bound to one CPU
(created asleep in that CPU's rq, then woken). `KTHREADS`
(`spin::Mutex<Vec<Arc<KThread>>>`, process context only, never held across
a wakeup/sleep; order: may be taken while holding nothing else) maps tid ->
control block. `kthread_should_stop/should_park/parkme` and
`kthread_stop/park/unpark` use atomics + `wake_up_task` + the block's
`ack` WaitQueue. Unbound threads go round-robin to APs (CPU 0 runs the
cooperative user tasks). Standing threads: `ktimerd` (CPU 0, runs software
timer callbacks), the system workqueue worker, `softnet/N` (one per CPU,
network receive; see 3.10), `kselftest` (boot only).

Every online AP gets an idle task (`init_ap_schedulers`) and enters the
scheduler from its boot idle loop. User tasks still run only on CPU 0. On
x86-64 the TSS (RSP0) and the syscall entry stack are global: kernel
threads switch with kernel stack 0, which leaves them untouched, so an AP
switch cannot clobber CPU 0's user-entry stack. Per-CPU TSS is required
before user tasks run on APs.

### 3.1.1 Task Struct and Credentials

**Location:** `kernel/task/mod.rs`, `kernel/task/percpu.rs`

The kernel uses a single global `TASK_TABLE: Mutex<GlobalTaskTable>` protecting
all task structs. This is simpler than Linux's per-task locks (`alloc_lock`,
`pi_lock`, `sighand->siglock`) but sufficient for hk's current design.

#### Data Structures

| Variable | Type | Purpose |
|----------|------|---------|
| `TASK_TABLE` | `Mutex<GlobalTaskTable>` | All tasks in system |
| Per-CPU `CurrentTask` | Copy struct in PerCpu | Cached task info (no lock) |
| `Task.cred` | `Arc<Cred>` | Reference-counted credentials |

#### Locking Rules

1. **TASK_TABLE is NOT IRQ-safe** - Never acquire from interrupt handlers
2. **IrqSpinlock → TASK_TABLE is safe** - IRQs disabled prevents ISR from running
3. **wake_sleepers() caches priority** - `SleepEntry.priority` avoids TASK_TABLE in ISR

#### Credential Handling (Linux Pattern)

Following Linux's `kernel/cred.c` pattern (see `include/linux/cred.h`):

1. **Reference-counted** - `Task.cred: Arc<Cred>` provides reference counting
2. **Copy-on-write** - Credential modifications use prepare/commit pattern
3. **Dual storage** - `Task.cred` in TASK_TABLE for persistence,
   `CurrentTask.cred` copied into per-CPU struct for fast syscall access

**Credential APIs (like Linux):**
- `prepare_creds()` - Clone current credentials, return mutable copy
- `commit_creds(new)` - Update Task.cred in TASK_TABLE AND CurrentTask.cred
- `copy_creds(flags, parent)` - For fork/clone: share Arc (CLONE_THREAD) or deep copy

**Credential Flow:**
1. Syscall calls `prepare_creds()` to get mutable copy of current credentials
2. Syscall modifies the credentials (e.g., `new.euid = target_uid`)
3. Syscall calls `commit_creds(Arc::new(modified))` to persist changes
4. `commit_creds()` updates both per-CPU cache (immediate visibility) and
   TASK_TABLE (persistence across context switch)
5. On context switch, scheduler loads `Task.cred` from TASK_TABLE into
   the new task's per-CPU `CurrentTask.cred`

**Why dual storage?**
- Per-CPU `CurrentTask.cred` provides fast syscall access (no lock needed)
- `Task.cred` in TASK_TABLE ensures credentials persist across context switches
- Without TASK_TABLE persistence, credentials would be lost when switching away

#### Deferred State Updates

`wake_sleepers()` does not update `Task.state: Sleeping → Ready` because:
- Run queue membership is the source of truth for runnability
- Updating would require TASK_TABLE lock (unsafe in ISR)
- `TaskState` is only checked for zombie detection in `waitpid()`

#### Future Consideration

When ptrace is implemented, hk may need per-task locks like Linux's `alloc_lock`
to serialize remote credential/mm access. The current global `TASK_TABLE` lock
is sufficient while all task modifications are by the current task itself.

#### Per-CPU Current Task Access (Lock-Free)

Each CPU maintains its own `PerCpu` structure accessed via the GS segment register
(x86-64) or SP_EL0 (aarch64). This provides lock-free access to the current task:

**x86-64 Pattern:**
```rust
// kernel/arch/x86_64/percpu.rs
pub fn current_tid() -> Tid {
    // Read GS:offset directly - no lock needed
    try_current_cpu()
        .map(|percpu| percpu.current_tid.load(Ordering::Relaxed))
        .unwrap_or(0)
}
```

**Why no lock is needed:**
1. Each CPU only accesses its own PerCpu structure
2. GS base is set once during CPU init and never changes
3. `current_tid` is only modified during context switch (with IrqSpinlock held)
4. Reads are always consistent (atomic load)

**CurrentTask is a COPY, not a reference:**

The `PerCpu.current_task` field contains a COPY of task metadata (tid, pid, cred),
not a pointer to the Task in TASK_TABLE. This provides:
- Fast syscall access without locking TASK_TABLE
- Consistent snapshot during syscall execution
- Updates happen at controlled points (context switch, commit_creds)

**Update Points:**
1. Context switch: Scheduler copies from Task in TASK_TABLE to PerCpu
2. `commit_creds()`: Updates both PerCpu cache AND Task in TASK_TABLE
3. `setpgid()`/`setsid()`: Updates both locations

**Linux Comparison:**
Linux uses a `current_task` per-CPU variable pointing directly to `task_struct`.
hk uses a copied snapshot for simpler lifetime management in Rust (no raw pointers
to task_struct across CPU boundaries).

### 3.1.2 Comparison with Linux task_struct Locking

Linux uses multiple per-task locks; hk uses a simpler global lock model:

| Linux Lock | Purpose | hk Equivalent |
|------------|---------|---------------|
| `alloc_lock` | Protect mm, files, fs, comm | `TASK_TABLE` (global) |
| `pi_lock` | Priority inheritance, state | `TASK_TABLE` (global) |
| `sighand->siglock` | Signal handlers | `SigHand.action` (IrqSpinlock) |
| `tasklist_lock` | Task list, parent/child | `TASK_TABLE` (global) |

**Why hk's approach works:**
1. Single lock simplifies lock ordering (no per-task lock hierarchy)
2. All task modifications go through TASK_TABLE
3. Current task reads use per-CPU cache (no lock needed)
4. Acceptable for MVP; can add per-task locks for ptrace later

**When hk would need per-task locks:**
- ptrace (remote task state modification)
- /proc filesystem (concurrent access to task state)
- RT priority inheritance (`pi_lock` equivalent)

For now, all task field modifications are by the task itself (through syscalls),
so the global TASK_TABLE lock is sufficient.

### 3.1.3 Task State Invariants

The `TaskState` enum in `TASK_TABLE` is informational (and records
`Zombie(wait_status)` / `Traced`), not the scheduling source of truth:

**Source of Truth for Scheduling** (owner CPU's rq, IrqSpinlock):
1. **Runnable**: entry `queued` (in `CpuRunQueue.queue`)
2. **Current**: `CpuRunQueue.current`
3. **Sleeping**: entry `state != Running`, not queued, not current; reachable
   from a wait queue, futex bucket, the sleep queue, or a signal
4. **Zombie**: `TaskState::Zombie(status)` set AND the entry removed from the
   rq (`exit_current`)

Wakers (possibly in IRQ context) never touch `TASK_TABLE`; code must NOT rely
on `TaskState` for scheduling decisions. `Zombie(status)` holds the Linux
wait status word (`code << 8` or the killing signal).

### 3.2 Memory Management

#### Frame Allocator

**Location:** `kernel/frame_alloc.rs`

```rust
pub struct BitmapFrameAllocator {
    inner: IrqSpinlock<BitmapFrameAllocatorInner>,
}
```

- Single `IrqSpinlock` protects the bitmap, refcounts and allocation
  state (page-fault paths allocate with interrupts enabled; a leaf lock,
  takes no other lock)
- Policy: no frame allocation in interrupt context
- Thread-safe via `&self` methods (`alloc()`, `free()`)

#### Address Spaces (Mm: mm_users / mm_count, mmap_lock)

**Location:** `kernel/mm/mod.rs` (`Mm`, `MmRef`), `kernel/mm/memory.rs`
(`exit_mmap`), `kernel/task/percpu.rs` (`exit_current`, `exec_replace_image`,
`do_clone`)

- `Mm.users` (`AtomicUsize`, Linux mm_users) counts the tasks running in
  the address space and pinned users (`MmRef`: ptrace PEEK/POKE,
  process_vm_*, a /proc/<pid>/maps read). The last `MmRef` drop runs
  `exit_mmap`, which takes the VMAs under the mm lock, drops the rmap
  chains, then tears down the user half (`paging::free_user`) and drops
  the VMAs (file references) with no lock held. **Never drop an `MmRef`
  under a spinlock** (TASK_TABLE included): take it out (`Option::take`,
  `replace`) and drop it after unlocking. `mmget_not_zero` refuses an
  address space already being torn down.
- `Arc<Mm>` (Linux mm_count) keeps the struct and its top-level table,
  freed on the last drop (`Mm::drop`, __mmdrop). Holders: every `MmRef`,
  `get_task_mm` callers (the task's own user reference keeps the mappings),
  an open /proc/<pid>/maps (Linux proc_mem_open: mmgrab only), and an
  exited task's `DeadTask` until its CPU has switched away (scheduler
  rule 8).
- `Task.mm` is set and taken under `TASK_TABLE`: at clone (`dup_mm` or a
  shared `MmRef`), at exec (`exec_replace_image` loads the new table, then
  drops the old user reference: a vfork parent or other CLONE_VM threads
  keep it alive), at exit (`exit_task_mm`, after the robust list and
  CLEARTID writes that still need the mappings, Linux mm_release before
  exit_mm). A task becomes a zombie only after that, so a reaping parent
  never drops a task that still uses its mm.
- The mm lock (`Mm::lock`, a `spin::Mutex`) is hk's mmap_lock: it guards
  the VMA tree and VM counters. `dup_mm` holds the parent's mm lock while
  it copies VMAs and page tables. munmap / MAP_FIXED / brk shrink / shmdt
  zap pages under it (`munmap_locked`). Order: mm lock → AnonVma lock,
  `LRU`, page descriptors, swap slots → `FRAME_ALLOCATOR`; nothing taken
  under those leaf locks takes an mm lock (the swap rmap walk uses the
  roots recorded in AnonVma chains, not the task table or mm locks).
  `TASK_TABLE` is never held while taking an mm lock.
- The page-fault paths find the VMA under the mm lock but drop it before
  allocating and installing the PTE (they may sleep reading a file), so a
  fault can race munmap of the same range in another thread (gap vs Linux,
  which holds mmap_lock for read across the fault and the page table lock
  around the PTE update; section 9).
- Teardown TLB: `free_user` detaches the user half from the top-level
  table, flushes (arm64: `tlbi vmalle1is`, all CPUs; x86: this CPU, if
  the table is loaded here), then frees pages and tables. A CPU that last
  ran the address space (another thread still in `exit_current`) is only
  covered on arm64; on x86 it may keep stale user TLB entries until its
  next CR3 load, but it no longer touches user memory (section 9).

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
- The ioremap window's lower tables are shared by every address space
  and changed only under `IOREMAP` (`spin::Mutex`, not IRQ-safe, never
  taken in IRQ context). Under it `FRAME_ALLOCATOR` is taken for new
  table frames; `IOREMAP` is a leaf otherwise (Linux: `vmap_area_lock`
  + `init_mm.page_table_lock`).
- TLB: ioremap/iounmap flush with `invlpg` (local) on x86 and
  `tlbi vae1is` (broadcast) on arm64; x86 has no kernel TLB shootdown yet, so after
  iounmap another CPU may still cache the old translation of a range
  that is handed out again (gap vs Linux `flush_tlb_kernel_range`,
  section 9; drivers do not iounmap in practice).
- User half: per address space, changed by its tasks under the mm lock
  (the fault paths install PTEs after dropping it, see Address Spaces);
  never contains a kernel mapping.

#### Heap Allocator

**Location:** `kernel/heap.rs`

```rust
pub struct HeapAllocator {
    inner: IrqSpinlock<HeapAllocatorInner>,
}
```

- Single `IrqSpinlock` protects the free list (fixed-size heap, never
  grows, so it takes no other lock): an allocation in interrupt context
  cannot deadlock against an interrupted allocator
- Policy is still **no allocation in IRQ context** (failure handling and
  latency); IRQ paths reserve capacity up front (e.g. `netif_napi_add`)
- Implements `GlobalAlloc` trait
- Used by Rust's `alloc` crate for `Box`, `Vec`, `String`, etc.

#### Page Cache

**Location:** `core/page_cache.rs`, `kernel/main.rs`

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

**Freeing ramfs pages (Linux evict_inode):** dropping a ramfs inode's
`RamfsInodeData` (no directory entry, open file, mapping or dentry left)
takes PAGE_CACHE -> FRAME_ALLOCATOR (`IrqSpinlock`, leaf) to free its
pages. The page cache never holds inode references, so the last inode
reference is never dropped with PAGE_CACHE held. Unevictable (ramfs)
pages are kept off the eviction FIFO and are refused below the memory
reserve (`FrameAlloc::reserve_low`: the frame allocator's exact free
count and the heap's free-byte count, both read under their own leaf
locks while PAGE_CACHE is held).

### 3.3 Virtual File System (VFS)

**Location:** `fs/` crate

The VFS uses fine-grained locking with `RwLock` for concurrent read access.
**All VFS locks are NOT IRQ-safe** and must only be accessed from thread context.

#### Global Structures

| Variable | Type | Purpose |
|----------|------|---------|
| `DCACHE` | `DentryCache` (contains `RwLock`) | Dentry cache root |
| `MOUNT_NS` | `MountNamespace` (contains `RwLock`) | Mount namespace root |

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
    pub lock: RwLock<()>,                          // Metadata protection
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
| `MOUNT_NS.root` | `RwLock<Option<Arc<Mount>>>` | Global mount tree root |
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
1. MOUNT_NS.root (read/write)
2. parent Mount.children (write for add/remove child)
3. Mount.parent (write for set/clear)
4. Mount.mountpoint (write for set/clear)
5. Dentry.flags (write for mounted flag)
```

**Lock Order for Path Traversal (follow_mount):**
```
1. MOUNT_NS.root (read)
2. Mount.children (read)
3. child.mountpoint (read)
4. Dentry.inode (read)
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
  locks, so a fault may sleep.
- Order: `f_pos_lock` -> file `i_rwsem` -> page cache / page locks ->
  fs-internal locks. A directory `i_rwsem` is never held while a file's
  `i_rwsem` is taken (O_CREAT drops the parent's lock before O_TRUNC).
- Both are sleeping locks (`kernel/sync`): the vfat write path may wait
  for page locks and block I/O while holding `i_rwsem`, which a spinlock
  would forbid.
- Path walk (`path.rs::lookup_slow`) takes a directory's `i_rwsem`
  shared on a dcache miss (Linux lookup_slow); callers already holding
  that directory exclusively (create, unlink, rename) use `lookup_one`
  directly.

#### Inode Timestamp Locking (Linux i_rwsem Pattern)

**Location:** `fs/inode.rs`, `fs/syscall.rs`

Inode timestamps (`atime`, `mtime`, `ctime`) use `Cell<Timespec>` internally. Since
`Cell` is not thread-safe, callers **must hold `inode.lock`** before accessing
timestamps. This follows Linux's pattern where callers provide serialization via
`i_rwsem`.

**Locking Requirements:**
- **Reads** (stat/getattr): Hold `inode.lock` in read mode
- **Writes** (utimensat, utimes, utime): Hold `inode.lock` in write mode

**Implementation Pattern:**
```rust
// Reading timestamps (e.g., in getattr):
let _guard = inode.lock.read();
let atime = inode.atime();
let mtime = inode.mtime();
let ctime = inode.ctime();

// Writing timestamps (e.g., in sys_utimensat):
{
    let _guard = inode.lock.write();
    inode.set_atime(new_atime);
    inode.set_mtime(new_mtime);
    inode.set_ctime(now);
}
```

**Why not atomics?** Timespec is a struct with two fields (sec, nsec). Converting
to atomics would complicate the API and still require paired loads/stores for
consistency. The struct-level locking pattern matches Linux's approach.

#### Wait Queues (kernel/waitqueue.rs)

Linux-style wait queues (`include/linux/wait.h`, `kernel/sched/wait.c`).

```rust
pub struct WaitQueue { head: IrqSpinlock<Vec<WaitQueueEntry>> } // leaf lock

// Sleeper side (process context, no spinlocks held)
wq.wait_event(|| cond);                                  // uninterruptible
wq.wait_event_interruptible(|| cond)?;                   // Err(RestartSys) on signal
wq.wait_event_timeout(|| cond, ticks) -> u64;            // 0 = timed out
wq.wait_event_interruptible_timeout(|| cond, ticks)?;    // Ok(left) / Err
// open-coded: prepare_to_wait(&mut WaitEntry, state); check; schedule(); finish_wait
// poll/select: add_poll_entry/remove_entry (non-autoremove registrations)

// Waker side (any context, including IRQ handlers)
wq.wake_one(); wq.wake_all();
```

- **IRQ class:** the head lock is an `IrqSpinlock` and a leaf: entries are
  collected under it, the lock is dropped, then tasks are woken
  (`wake_up_task`: own rq lock or the target's `wake_list`). Wakers never
  take `TASK_TABLE`, so `wake_*` is safe from IRQ handlers.
- **No lost wakeups:** the sleeper registers and sets its state before
  re-checking the condition (see 3.1 Sleep / Wakeup Protocol). Wakers must
  make the condition true before calling `wake_*`.
- **Autoremove:** a woken entry is removed by the waker; `finish_wait`
  removes it otherwise. Poll entries stay until the poll ends.
- `wait_event_interruptible_deadline` takes a CLOCK_MONOTONIC deadline.
  Wakers of queues shared by waiters with different conditions (SysV
  sem/msg, mqueue, sockets) use `wake_all`: a `wake_one` could pick a
  waiter whose condition is still false.
- `cond` closures run with the task state set; they may take sleeping-context
  locks (Mutex) but must not sleep themselves.

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
| `TASK_NS` | `Mutex<BTreeMap<Tid, Arc<NsProxy>>>` | Global TID→NsProxy mapping |
| `UtsNamespace.name` | `RwLock<NewUtsname>` | Per-namespace UTS data |
| `PidNamespace.next_pid` | `Mutex<u32>` | PID allocation within namespace |
| `PidNamespace.pid_map` | `RwLock<BTreeMap<u32, Tid>>` | PID→TID mapping |
| `PidNamespace.tid_map` | `RwLock<BTreeMap<Tid, u32>>` | TID→PID mapping |
| `UserNamespace.uid_map.extents` | `RwLock<Vec<UidGidExtent>>` | UID mapping extents |
| `UserNamespace.gid_map.extents` | `RwLock<Vec<UidGidExtent>>` | GID mapping extents |

#### Locking Rules

1. **TASK_NS is a global Mutex** - Protects the task→namespace mapping, similar
   to `TASK_FS` for filesystem context.

2. **Per-namespace data uses RwLock** - UTS name data is read-heavy (uname is
   called frequently) but rarely written (sethostname/setdomainname are rare).

3. **Acquire TASK_NS before TASK_TABLE** - This prevents deadlock with the
   scheduler. `copy_namespaces()` is called in `do_clone()` before acquiring
   any scheduler locks.

4. **Namespace operations happen before page table copy** - In clone/fork,
   namespace setup happens early for clean error handling (can fail on OOM).

#### Lock Order for Namespace Operations

```
1. TASK_NS (acquire for lookup/insert)
   ↓
2. UtsNamespace.name (acquire for read/write of hostname)
   ↓
3. TASK_FS (if also accessing filesystem context)
   ↓
4. Per-CPU scheduler (IrqSpinlock)
   ↓
5. TASK_TABLE (for task state updates)
```

#### Syscall Patterns

**uname(2):** Read path - acquires `UtsNamespace.name` read lock briefly:
```rust
let uts_ns = current_uts_ns();  // TASK_NS lookup
let tmp: NewUtsname = *uts_ns.name.read();  // RwLock read
// Copy to userspace
```

**sethostname(2)/setdomainname(2):** Write path - acquires exclusive lock:
```rust
let uts_ns = current_uts_ns();  // TASK_NS lookup
{
    let mut guard = uts_ns.name.write();  // RwLock write
    guard.nodename = new_name;
}
```

#### Reference Counting

`NsProxy` and individual namespaces use `Arc` for reference counting:
- Tasks share `Arc<NsProxy>` via the `TASK_NS` table
- Clone without CLONE_NEW* flags: child shares parent's `Arc<NsProxy>`
- Clone with CLONE_NEW* flags: new `NsProxy` created with new namespace(s)
- Exit: removes entry from `TASK_NS`, Arc refcount drops

### 3.5 Timekeeping

**Location:** `core/time.rs`

The timekeeper uses a **seqlock** pattern for lock-free reads with consistent
snapshots.

```rust
pub struct TimeKeeper {
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

    let seq2 = self.seq.load(Ordering::Acquire);
    if seq1 != seq2 { continue; }  // Data changed, retry

    return computed_time;
}
```

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
| `TASK_SIGHAND` | `Mutex<BTreeMap<Tid, Arc<SigHand>>>` | Global TID→SigHand mapping |
| `TASK_SIGNAL_STATE` | `Mutex<BTreeMap<Tid, TaskSignalState>>` | Per-task blocked/pending |
| `TASK_TIF_SIGPENDING` | `Mutex<BTreeMap<Tid, bool>>` | Per-task pending flag |
| `SigHand.action` | `IrqSpinlock<[SigAction; 65]>` | Signal handler table |
| `TaskSignalState.shared_pending` | `Arc<Mutex<SigPending>>` | Thread group pending |

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

1. **TASK_SIGHAND/TASK_SIGNAL_STATE are global Mutexes** - Protects task→signal
   mappings, similar to `TASK_FS` for filesystem context. Only accessed from
   syscall (process) context.

2. **SigHand.action uses IrqSpinlock** - Can be safely accessed from synchronous
   exception handlers (page faults, etc.) and process context.

3. **Acquire TASK_SIGHAND before SigHand.action** - Look up the signal handler
   struct first, then acquire its internal lock.

4. **Never hold IrqSpinlock while acquiring Mutex** - Would violate lock ordering.

#### Lock Order for Signal Operations

```
1. TASK_SIGHAND (acquire for lookup/insert)
   ↓
2. TASK_SIGNAL_STATE (acquire for blocked mask/pending)
   ↓
3. SigHand.action (IrqSpinlock, for handler table)
   ↓
4. TaskSignalState.shared_pending (Mutex, for thread group pending)
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
let sighand = get_task_sighand(tid)?;  // TASK_SIGHAND lookup
let actions = sighand.action.lock();    // IrqSpinlock
let old = actions[sig].clone();
actions[sig] = new_action;
```

**rt_sigprocmask(2):** Modify blocked mask:
```rust
with_task_signal_state(tid, |state| {   // TASK_SIGNAL_STATE lookup
    state.blocked = new_mask;
    state.recalc_sigpending();
});
```

**kill(2)/tgkill(2):** Send signal to task (`send_signal`, process context
only):
```rust
let deliverable = with_task_signal_state(tid, |state| {  // TASK_TABLE
    if sig_ignored(..) { return false }   // SIG_IGN / default-ignore: dropped
    state.pending.add(sig);
    !state.blocked.contains(sig)
});                                       // tif_sigpending recomputed
// TASK_TABLE released, then:
wake_up_tid(tid, WakeMode::Interruptible) // signal_wake_up
```
`with_task_signal_state` recomputes `tif_sigpending` after every access, so it
means "a signal is deliverable under the current mask"; interruptible sleeps
test it via `waitqueue::signal_pending()` and return `-ERESTARTSYS`/
`-ERESTARTNOHAND`. `syscall_exit_signal_work` (arch syscall exit) delivers
the signal and restarts or fails the syscall per SA_RESTART.

#### Reference Counting

`SigHand` uses `Arc` for reference counting:
- Tasks share `Arc<SigHand>` via the `TASK_SIGHAND` table
- Clone with CLONE_SIGHAND: child shares parent's `Arc<SigHand>`
- Clone without CLONE_SIGHAND: new `Arc<SigHand>` with deep-cloned handlers
- Exit: removes entry from `TASK_SIGHAND`, Arc refcount drops

### 3.8 Futex Subsystem

**Location:** `kernel/futex.rs`

The futex (fast userspace mutex) subsystem provides efficient userspace synchronization
primitives. It uses a hash bucket design similar to Linux's `futex_queues`.

#### Futex Locks

| Variable | Type | Purpose |
|----------|------|---------|
| `FUTEX_HASH_TABLE` | `[FutexHashBucket; 256]` | Hash buckets for waiters |
| `FutexHashBucket.waiters` | `IrqSpinlock<Vec<FutexQ>>` | Per-bucket waiter list |
| `FutexHashBucket.waiter_count` | `AtomicU32` | Fast-path check for waiters |
| `TASK_ROBUST_LIST` | `Mutex<BTreeMap<Tid, u64>>` | Per-task robust list heads |

#### Why IrqSpinlock for Bucket Waiters

Futex operations may be called from signal context (e.g., during signal delivery
or cleanup). Using `IrqSpinlock` ensures:
1. Interrupts are disabled during bucket access
2. No deadlock if signal handler tries to access same bucket
3. Memory barrier semantics for race prevention with userspace

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
FutexHashBucket.waiters (IrqSpinlock): leaf. Wakers dequeue FutexQ entries
under it, drop it, then wake_up_task(tid, cpu) (no TASK_TABLE).
```

Waiters sleep with the Sleep / Wakeup Protocol (section 3.1): state set to
Interruptible, then "still queued?" re-checked under the bucket lock, then
`schedule_timeout`. A waker that dequeued the entry is the wake; signal or
timeout dequeue the entry themselves.

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

1. **Bucket lock is IRQ-safe** - Safe from signal handlers
2. **Memory barriers before userspace access** - Prevents lost wakeups
3. **Bucket lock is a leaf** - wakeups are issued after dropping it
4. **Multi-bucket operations use address ordering** - Prevents deadlock
5. **Robust cleanup has entry limit** - Prevents infinite loop from corrupted list

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

#### USB Subsystem

**Location:** `kernel/usb/`

| Lock | Type | Purpose |
|------|------|---------|
| `USB_CONTROLLER` | `Mutex<Option<XhciController>>` | Global xHCI controller access |
| `XHCI_IRQ_STATE.*` | `AtomicU64`, `AtomicBool` | ISR state (lock-free) |
| `USB_OUTPUT_ACTIVE` | `AtomicBool` | Console recursion guard |

**ISR Pattern:** The xHCI ISR sets `interrupt_pending` atomic but does NOT acquire
`USB_CONTROLLER` mutex. This avoids IRQ-context deadlock since the mutex is not
IRQ-safe.

#### Block Device Subsystem

**Location:** `kernel/storage/`

| Lock | Type | Purpose |
|------|------|---------|
| `BLKDEV_REGISTRY` | `RwLock<BlockDeviceRegistry>` | Device registration |
| `RequestQueue.sched` | `Mutex<Box<dyn IoScheduler>>` | Per-queue scheduler |
| `RequestQueue.disk` | `RwLock<Option<Arc<Disk>>>` | Back-reference |
| `Disk.capacity_sectors` | `AtomicU64` | Lock-free capacity |
| `BlockDevice.open_count` | `AtomicUsize` | Lock-free open count |

**I/O Completion:** Bio completion callbacks are synchronous and must not acquire
locks to avoid deadlock with the request queue.

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
(`skb.net()`), never `current_net_ns()`; a socket's is `Socket.net`.

Today all device IRQs are routed to CPU 0 (PIC / GIC IROUTER) and user
tasks run only on CPU 0, so in practice protocol work for eth0 and lo runs
on CPU 0 (`softnet/0` or a CPU-0 task); kernel threads on other CPUs (e.g.
the ICMP self-test on CPU 1) use their own CPU's softnet. The locks below
do not rely on that.

| Lock | Type | IRQ class | Notes |
|------|------|-----------|-------|
| `Softnet.poll_list` (per CPU) | `IrqSpinlock<VecDeque<Arc<Napi>>>` | taken in IRQ (`napi_schedule`) and by `softnet/N` | leaf; capacity reserved by `netif_napi_add`, so the ISR never allocates |
| `Softnet.wq` (per CPU) | `WaitQueue` | woken from IRQ | leaf (see Wait Queues) |
| `Softnet.backlog` (per CPU) | `spin::Mutex<VecDeque<Box<SkBuff>>>` | thread only (`netif_rx`, `softnet/N`, inline flush) | leaf; max 1000 packets, then drop + `rx_dropped` |
| `dev::TIMER_DUE` | `AtomicBool` | thread (ktimerd sets, softnet/0 clears) | protocol timers are due: softnet/0 runs `tcp::timer::run` with no lock held |
| `Napi.sched` | `AtomicBool` | IRQ + thread | set by `napi_schedule` (only the setter queues it), cleared by `napi_complete_done` |
| `PTYPE_BASE`, `PTYPE_ALL` | `spin::RwLock` (`Vec<..>` / fixed array of taps) | thread only | leaf; handlers copied out, called after unlock. Taps (AF_PACKET) run from `netif_receive_skb` and from `dev_queue_xmit` (PACKET_OUTGOING), i.e. possibly under a caller's socket or neighbour-free transmit path: they take only the AF_PACKET leaves below |
| `NAPI_LIST`, `SOFTNET_THREADS` | `spin::Mutex<Vec<..>>` | thread only | leaf; registration |
| `Sock` (`net/sock.rs`, in every protocol socket) | atomics + `Sock.wq` (`WaitQueue`) | any (wakeups) | error, shutdown, buffer sizes, timeouts, SOL_SOCKET flags; one wait queue per socket for readers, writers, connect/accept and pollers (`sk_data_ready`/`sk_write_space`/`sk_state_change` = `wake_all`), always woken after protocol locks are dropped |
| sockfs inode `private` | `spin::RwLock` (VFS, `Inode.private`) | thread only | read per socket file operation (`sock_of`) to reach the protocol socket; leaf |
| `TcpSock.cb` (`net/tcp/mod.rs`) | `spin::Mutex<Inner>` | thread only (softnet input, softnet/0 timers, socket calls) | the TCP socket lock: Linux `bh_lock_sock` plus the `tcp_sock` state it guards (the whole I/O-free `TcpCb`: state, sequence space, send/receive/out-of-order queues, RFC 7323 option state, delayed-ACK state, RTO, all timers, the IPPROTO_TCP options (`TcpCb.opts`; the separate `TcpSock.opts` leaf is gone); tuple, port ownership, listener link). Held for one bounded step: never across a sleep, a user copy or a transmit (work is returned as `Out` and run after unlock). A listener's is taken before its new child's (creating it); a child never takes its listener's `cb` |
| `TcpSock.rd` | `sync::Mutex<()>` (sleeping) | thread only (recvmsg) | serializes readers across peek -> user copy -> consume, so a faulting copy leaves the data queued (reader half of Linux `lock_sock`); held only for that step, never across a wait; above `cb` |
| `TcpSock.queue` | `spin::Mutex<Option<Accept>>` | thread only | leaf: a listener's SYN_RECEIVED children and accept queue; taken under the listener's or a child's `cb` |
| `TimeWait.inner` (`net/tcp/timewait.rs`) | `spin::Mutex` | thread only | a TIME_WAIT entry's queue-less control block + timer slot; same position as `TcpSock.cb` |
| TCP `TIMERS` (`net/tcp/timer.rs`) | `spin::Mutex<BTreeMap>` | thread only | leaf under `cb`/`TimeWait.inner`: (deadline, id) -> weak owner. Its `timer::Alarm` only wakes softnet/0 (`dev::raise_timer`), which takes due entries out and runs each under its owner's lock with `TIMERS` dropped |
| TCP tables `TcpTables.{bhash, ehash, lhash}` (`net/tcp/table.rs`, per netns) | `spin::RwLock` | thread only | `bhash` -> `ehash` (connect picks a port and inserts its four-tuple atomically); `lhash` leaf; candidates' `Inet.addr` and `Sock` flags are read under `bhash`; never a socket `cb` under a table lock (/proc/net/tcp copies the entries out, drops the table locks, then takes each `cb` / `TimeWait.inner` in turn) |
| `Sock.errq` (`net/sock.rs`) | `spin::Mutex` | thread only (softnet ICMP error delivery, recvmsg MSG_ERRQUEUE, poll) | leaf: IP_RECVERR queue, bounded by SO_RCVBUF (own charge); the wakeup follows the unlock |
| `IcmpRate.st` (`net/icmp.rs`, per netns) | `spin::Mutex` | thread only | leaf: global + per-destination (bounded, 256) ICMP error token buckets |
| `UdpSock.op`, `PingSock.op` | `spin::Mutex<()>` | thread only | datagram socket lock (bind/connect/disconnect/autobind); never across a sleep or a transmit; taken before the protocol's port/identifier table |
| `RxQueue.q` (`net/dgram.rs`: UDP, ping, raw receive queues) | `spin::Mutex` | thread only (softnet enqueue, recvmsg) | leaf; bounded by SO_RCVBUF (`rmem` atomic) |
| `RawTable.socks` (`net/raw.rs`, per netns) | `spin::RwLock` | thread only | raw sockets by protocol; delivery and ICMP-error fan-out clone the matching `Arc`s (reading their `Inet.addr`) and queue after dropping it; `RawSock.filter` is an atomic |
| `PacketTable.socks` (`net/packet/`, per netns) | `spin::RwLock<Vec<Arc<PacketSock>>>` | thread only (taps in softnet or a transmitting task, socket create/close) | leaf; the tap clones the matching `Arc`s and queues after dropping it (a global atomic count skips all work when no packet socket exists) |
| `PacketSock.rxq` (`PktQueue.q`), `PacketSock.filter` | `spin::Mutex` / `spin::RwLock` | thread only | leaves; the queue is bounded by SO_RCVBUF (`rmem` atomic, drops counted); the filter `Arc` is cloned out and run with no lock held; the binding (protocol, ifindex) and flags are atomics |
| `PacketSock.mclist` | `spin::Mutex<Vec<Mreq>>` | thread only | PACKET_ADD/DROP_MEMBERSHIP list, changed only under RTNL (Linux packet_mc_add takes rtnl_lock); RTNL -> `mclist`, dropped before the device's promiscuity changes (`NetDevice.set_promiscuity`, RTNL held, may call the driver) |
| `PingTable.socks` (`net/ping.rs`, per netns) | `spin::RwLock` | thread only | ping sockets by echo identifier; receive/error lookups clone the `Arc` and queue after dropping it; reads candidates' `Inet.addr` under it (order table -> Inet.addr) |
| `Inet.addr` (`net/af_inet.rs`) | `spin::Mutex` | thread only | leaf: addresses/ports of a TCP or UDP socket; read under the UDP/TCP port tables during lookups |
| `RTNL` (`net/rtnl.rs`) | `spin::Mutex<()>` | thread only (syscalls, kernel config; never softnet) | OUTERMOST network lock: serializes all configuration changes (link up/down + MTU, addresses, routes) from netlink, SIOCS* ioctls and the kernel. Functions needing it take `&RtnlGuard`. Holders never sleep and never take a socket lock (`sk_lock`) |
| `NetNamespace` tables (`devices`, `loopback`), `UdpTable.socks` | `spin::RwLock` | thread only | reached only via lookup/insert methods returning owned values / `Arc` (no guard escapes: RCU-ready); the UDP port table reads each candidate's `Inet.addr` under its lock |
| `Fib.tables` (`net/inet/fib.rs`, per netns) | `spin::RwLock` | thread only | leaf; written only under RTNL; read by input/output routing (softnet, socket syscalls, possibly under `sk_lock`) and dumps; returns `Arc<FibEntry>` clones; notifications are sent after the guard is dropped |
| `NetDevice.addrs` (IPv4 list; IPv6 later) | `spin::RwLock` | thread only | leaf; written only under RTNL (`inet::ifaddr`), read via snapshots (`inet_addrs()`) |
| `NeighTable.hash` (`net/core/neigh.rs`; `NetNamespace.arp`, IPv6 ND later) | `spin::RwLock` | thread only (softnet, socket output, ktimerd) | (ifindex, address) -> `Arc<Neighbour>`; lookups drop the guard; GC/flush take each entry's `inner` under the write lock (order hash -> inner) |
| `Neighbour.inner` | `spin::Mutex` | thread only | leaf: NUD state + bounded unresolved queue (unres_qlen_bytes). Never held while transmitting, soliciting or reporting errors: state changes return actions run after the unlock |
| neighbour `TABLES` | `spin::Mutex` | thread only | leaf (snapshot of registered tables). One `timer::Alarm` runs all tables' due entries and GC on `ktimerd`, armed with no table lock held |
| `timer::Alarm.st` (neighbour, IP reassembly) | `spin::Mutex` | thread only | held across `timer_add/timer_del` (-> `TIMERS` IrqSpinlock); otherwise leaf |
| `FragTable.st` (`net/inet/frag.rs`, per netns) | `spin::Mutex` | thread only (softnet, reassembly timer on ktimerd) | leaf: reassembly queues + memory charge; completed datagrams are delivered and expiry ICMP errors sent after it is dropped. Reassembly `TABLES` (registered namespaces) is a leaf `spin::Mutex` |
| `PmtuCache.m` (`net/inet/route.rs`, per netns) | `spin::Mutex` | thread only | leaf: learned path MTUs, read by `route::output` (possibly under a socket lock), written by ICMP frag-needed handling |
| `NlTable.socks` (`net/netlink`, per netns) | `spin::RwLock` | thread only | leaf; bound netlink sockets by (protocol, portid); lookups return `Arc` clones |
| `NlSock.dump` | `spin::Mutex<Option<Dump>>` | thread only (sender's `sendmsg`, reader's `recvmsg`) | running dump cursor; held while it snapshots devices/FIB/ARP and while its part is pushed to `rxq` (keeps parts ordered); never with RTNL |
| `NlSock.rxq`, `NlSock.dst` | `spin::Mutex` | thread only | leaf; replies, dump parts and notifications are pushed under it (each charged to rcvbuf first), `wq` is woken after it is dropped |
| `NlSock` portid/groups/flags/err/rmem/congested, autobind `ROVER` | atomics | thread only | |
| `UnixSock.bindlock` (`net/unix`) | `sync::Mutex<()>` (sleeping) | thread only | Linux u->bindlock: bind/autobind; taken with no spinlock held, before `UnixTable.st`/`BSD`. A path bind runs the VFS mknod (parent `i_rwsem`) first and takes `bindlock` after it returns (Linux nests them; hk does not need to) |
| `UnixSock.iolock` | `sync::Mutex<()>` (sleeping) | thread only (recvmsg) | Linux u->iolock: one reader across dequeue -> user copy -> consume; dropped before waiting for data; above `st`/`rq` |
| `UnixSock.st` | `spin::Mutex<Option<Arc<UnixSock>>>` | thread only | Linux unix_state_lock: the peer; `state`, shutdown bits and `dead` change under it. Two at once only as listener -> connecting socket (stream connect; a socket that is not CLOSE fails before taking its own, so listeners never nest) or in ascending address order (`lock2`, Linux unix_state_double_lock: dgram connect, socketpair). Senders queue under the receiver's `st`, so nothing is queued to a released socket |
| `UnixSock.rq` | `spin::Mutex<RxQueue>` | thread only | receive queue (Linux sk_receive_queue.lock), under `st`; a listener's queue holds embryo connections |
| `UnixTable.st` (per netns), `unix::BSD` (global, by inode) | `spin::RwLock` | thread only | all sockets + abstract names (per type) / filesystem bindings; after `bindlock`, before `UnixSock.addr` (published under them); lookups return `Arc`s, no socket lock under them |
| `UnixSock.addr`, `UnixSock.peercred`, `UnixSock.relay` | `spin::RwLock` / `spin::Mutex` | thread only | leaves (Linux u->addr, sk_peer_lock, peer_wait.lock for peer_wake relays); `relay` also guards the registered sockets' `peer_wake` atomics |
| `unix::scm::INFLIGHT`, `unix::scm::DEFERRED` | `spin::Mutex` | thread only | leaves: per-user in-flight file counts (charged under the receiver's `st`), files awaiting `defer_fput` |
| `UnixSock` `state`/`dead`/`wmem`/`backlog`/`peer_wake`, `DRAINING` | atomics | thread only | |
| `NetDevice.net` | `spin::RwLock<Weak<NetNamespace>>` | thread only | read per received packet; written at registration |
| `NetNamespace.sysctl`, `port_range` (`/proc/sys/net`, `kernel/sysctl.rs`) | atomics | thread only | no locks; a multi-value sysctl (ping_group_range) is one packed `AtomicU64`, so readers never see half an update |
| `NetDevice.stats`, `flags`, `mtu`, `ifindex`, `carrier`, `promiscuity`, `allmulti` | atomics | any (`promiscuity`/`allmulti` written only under RTNL) | `flags` holds administrative state only; IFF_RUNNING/IFF_LOWER_UP/operstate are derived on read |
| e1000 `rx` ring | `spin::Mutex` | thread only (NAPI poll) | leaf; frames are delivered after it is dropped |
| e1000 `tx` ring | `spin::Mutex` | thread only (xmit, poll reclaim) | leaf; ring full -> drop, `tx_dropped`, ENOBUFS |
| e1000 `pending_icr`, irq counters | atomics | IRQ + thread | ISR ORs ICR causes in; poll swaps them out |
| virtio-net `rx` queue (`net/driver/virtio_net.rs`) | `spin::Mutex` | thread only (NAPI poll, open) | leaf: virtqueue + bounce buffers; frames are delivered after it is dropped |
| virtio-net `tx` queue | `spin::Mutex` | thread only (xmit, poll reclaim) | leaf; one descriptor per frame; ring full -> drop, `tx_dropped`, ENOBUFS |
| virtio-net `opened`, `config_pending`; `VringCb` (RX avail NO_INTERRUPT flag) | atomics / lock-free MMIO-style store | IRQ + thread | the ISR suppresses RX interrupts and flags config changes; the poll re-enables under `rx` |
| virtio-PCI transport (`virtio/pci.rs`) | none | probe (single-threaded enumeration), then IRQ (ISR byte) | common config written only during probe; device config reads are generation-checked and lock-free; queue notify writes happen under the caller's queue lock |
| `virtio::DRIVERS` | `spin::Mutex<Vec>` | thread only (boot) | leaf; registered before bus enumeration, read by the PCI match/probe |

**Lock order (outermost first):**

```
RTNL (configuration only)        TcpSock.rd (sleeping) -> TcpSock.cb (listener before its new child;
  |                                 a child never takes its listener's cb) /
  |                                 TimeWait.inner / UdpSock.op / PingSock.op
  |                                 -> TCP bhash -> ehash, lhash / UdpTable.socks /
  |                                    PingTable.socks -> Inet.addr
  |                                 -> TcpSock.queue / RxQueue.q
  |                                 -> TCP TIMERS -> Alarm.st -> kernel TIMERS
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
  -> Softnet.backlog (lo xmit)           Softnet.poll_list / WaitQueue / rq
                                          (IrqSpinlocks, innermost)
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
held across `netif_rx_flush_local()`. Netlink requests are processed in
the sender's `sendmsg` with no lock held on entry; mutating handlers take
RTNL. Carrier changes (`netif_carrier_on/off`, from a driver's NAPI poll
or `open()`) send RTM_NEWLINK without RTNL (NlTable.socks -> NlSock.rxq
only). A device that is closed while its NAPI poll runs stays masked: the
poll rewrites IMS only if the device is still up, and `netif_receive_skb`
drops frames of a down device.

**Driver ISR rules (e1000 pattern):** read ICR (read-to-clear; 0 => not
ours on a shared line, return false), write IMC (mask all), record causes
in an atomic, `napi_schedule`. The poll handles link changes (LSC ->
`netif_carrier_on/off`), reclaims TX, receives up to `budget` frames by
copying them out of coherent bounce buffers, and when it did less than its
budget calls `napi_complete_done` and rewrites IMS (a cause latched while
masked fires then). If its own ISR consumed causes during the poll (shared
line), it reschedules itself.

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
64 KiB steps rather than at sndbuf-wait points. Segments, wakeups and
errors decided under the lock are carried out after it is dropped
(`TcpSock::finish`), so no TCP lock is held across a transmit; the
loopback flush (`netif_rx_flush_local`) runs only at the end of socket
calls.

**Known gaps (later phases):** RCU for the read-mostly tables (FIB,
device list, address lists: COW snapshots are the intended next step;
see plan 3a).

#### Key Device Driver Rules

1. **Driver locks are thread-context only** - ISR-shared state is atomics or
   core IrqSpinlocks (`napi_schedule`, wait queues)
2. **ISRs ack and defer** - never take a driver Mutex, defer to thread context
3. **Atomics for hot paths** - Use atomics for frequently-accessed state
4. **Completion callbacks are lock-free** - Don't acquire locks in bio/skb completion

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

The scheduler uses per-CPU run queues. Each CPU only locks its own run queue,
eliminating cross-CPU lock contention for the hot path.

### 4.5 Lock-Free Reads (Seqlock)

The timekeeper uses seqlocks so readers never block writers, and writers
never block readers. Readers simply retry if they detect a concurrent write.

### 4.6 Short Critical Sections

Locks are held for the minimum time necessary. No memory allocations, I/O,
or other potentially-blocking operations are performed under IrqSpinlock.

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

As described in Section 3.4, time reads are lock-free using the seqlock pattern.

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
| `Socket` | flags, error, eof | Independent flags with Mutex-protected data buffers |
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

`IrqSpinlock` automatically manages preempt_count:

```rust
// On lock():
percpu::preempt_disable();  // preempt_count++

// On unlock/drop():
percpu::preempt_enable();   // preempt_count--
```

---

## 7. Interrupt Context Rules

### 7.1 What Can Run in Interrupt Context

- Timer tick updates (atomic only)
- Wake sleepers (IrqSpinlock only, per-CPU only)
- `WaitQueue::wake_one/wake_all` and `wake_up_task` (IrqSpinlocks only)
- `timer::check_timers()` (CPU 0 tick): peeks `TIMERS` (IrqSpinlock) and
  wakes `ktimerd`; timer callbacks themselves run in `ktimerd`, process
  context (they may send signals, take Mutexes, allocate)
- `napi_schedule()` (NIC ISRs): `Softnet.poll_list` IrqSpinlock push
  (pre-reserved, no allocation) and a wake of `softnet/N`
- Workqueues have no IRQ-side work: the worker thread promotes expired
  delayed work itself, sleeping with a timeout until the next deadline
- Set reschedule flags (atomic)
- Read per-CPU data (via GS segment)

### 7.2 What CANNOT Run in Interrupt Context

- **Memory allocation** (frame allocator is a Mutex; the heap is IRQ-safe
  but IRQ paths must not depend on allocating)
- **TASK_TABLE access** (uses Mutex)
- **VFS operations** (use RwLock)
- **printk** (uses Mutex, consider try_lock for exceptions)
- **Any Mutex or RwLock acquisition**

### 7.3 Deferring Work

If interrupt context needs to trigger something that requires non-IRQ-safe locks:

1. Record the event (atomic, or an IrqSpinlock-protected queue)
2. Wake a kernel thread (`WaitQueue::wake_*` / `wake_up_task`, IRQ-safe)
3. The actual work is done in thread context (`ktimerd`, workqueue
   workers, `softnet/N` threads for network receive)

Example: the CPU 0 tick notices an expired software timer and wakes
`ktimerd`, which runs the callback (posix timers send signals there). The
`needs_reschedule` flag set by the tick is currently unused for preemption
(hk is non-preemptive, see 3.1).

### 7.4 Complete List of Locks Never Acquired from Interrupt Context

The following locks are NEVER acquired from interrupt handlers (timer ISR,
exceptions, etc.). This table serves as the authoritative reference for the
interrupt-safety invariant:

| Lock | Location | Type | Reason |
|------|----------|------|--------|
| `TASK_TABLE` | kernel/task/percpu.rs | `Mutex` | Global task registry |
| `TASK_SIGHAND` | kernel/signal/mod.rs | `Mutex` | Signal handler mapping |
| `TASK_SIGNAL_STATE` | kernel/signal/mod.rs | `Mutex` | Per-task signal state |
| `TASK_FS` | kernel/fs/context.rs | `Mutex` | Filesystem context |
| `TASK_NS` | kernel/ns/mod.rs | `Mutex` | Namespace context |
| `TASK_TLS` | kernel/task/tls.rs | `Mutex` | TLS base addresses |
| `NPROC` | kernel/task/mod.rs | `Mutex` | RLIMIT_NPROC tasks per real uid (leaf: may be taken under TASK_TABLE, takes no lock) |
| `FRAME_ALLOCATOR` | kernel/frame_alloc.rs | `Mutex` | Physical frame allocation |
| `PAGE_CACHE` | core/page_cache.rs | `Mutex` | Page cache lookup |
| All VFS locks | kernel/fs/*.rs | `RwLock` | Inodes, dentries, mounts |

Note: `OUTPUT_LOCK`, `PRINTK`, and `CONSOLE_REGISTRY` are now `IrqSpinlock` and
CAN be safely acquired from interrupt context. See Section 3.6.

**Invariant**: Code running with interrupts enabled that acquires any of these
locks will never be interrupted by an ISR that also tries to acquire the same lock.

**Why this is safe**: ISRs in hk only perform these operations:
- Read/write atomics (tick counts, flags, `needs_reschedule`)
- Acquire `IrqSpinlock` (per-CPU scheduler run queue)
- Call `wake_sleepers()` which only touches per-CPU run queue

ISRs NEVER perform:
- Memory allocation (`alloc`, `Box`, `Vec` growth) - would acquire heap Mutex
- Task table operations - would acquire TASK_TABLE Mutex
- VFS operations - would acquire RwLock
- printk - would acquire OUTPUT_LOCK Mutex (potential deadlock)

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

// Safe to acquire TASK_TABLE (interrupts are disabled)
let table = TASK_TABLE.lock();
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
| lockdep | Runtime deadlock detection | Not implemented | Manual ordering verification |
| RCU | Read-Copy-Update | Not implemented | Use RwLock instead |
| Per-CPU variables | `DEFINE_PER_CPU` | Manual per-CPU arrays | Less convenient API |
| Kernel TLB shootdown | `flush_tlb_kernel_range` IPIs | x86: local `invlpg` only | Stale ioremap translation on other CPUs after iounmap |
| User TLB shootdown | `flush_tlb_mm_range` IPIs to `mm_cpumask` | x86: local `invlpg` / CR3 reload only (arm64 broadcasts `tlbi ...is`) | Another CPU running a thread of the same process may use a stale translation after munmap/mprotect/exit_mmap |
| mmap_lock across faults | `mmap_read_lock` + PTE lock in the fault path | Fault drops the mm lock before installing the PTE | A fault can race munmap of the same range in another thread |

### Implications

1. **No softirqs**: Device drivers cannot defer work to bottom-half context. All
   deferred work must use workqueues or be handled synchronously.

2. **NAPI without softirqs**: driver ISRs only ack/mask and `napi_schedule`
   a per-CPU `softnet/N` kthread that polls the device; protocol processing
   never runs in interrupt context (see 3.10 Network Subsystem).

3. **No lockdep**: Lock ordering must be verified manually via code review.
   Consider adding compile-time lock ordering enforcement in the future.

4. **No RCU**: Read-heavy data structures use RwLock, which has higher overhead
   than RCU for read-mostly workloads.

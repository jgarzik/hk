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
4. [Deadlock Prevention](#4-deadlock-prevention)
5. [Lock-Free Patterns](#5-lock-free-patterns)
6. [Preemption Control](#6-preemption-control)
7. [Interrupt Context Rules](#7-interrupt-context-rules)
8. [API Quick Reference](#8-api-quick-reference)

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

### 1.4 Atomic Types

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
    MOUNT_NS.root
        ↓
    Mount.{children, parent, mountpoint}
        ↓
    Dentry.{d_lock, rename_lock} (single d_lock like Linux, rename_lock for lock_rename)
        ↓
    Inode.i_rwsem (directory operation serialization, like Linux i_rwsem)
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
Global subsystem locks (TASK_TABLE, PAGE_CACHE, FD_TABLE)  ← NOT IRQ-safe
    ↓
Printk locks:
    OUTPUT_LOCK (held for entire message)
        ↓
    PRINTK (ring buffer)
        ↓
    CONSOLE_REGISTRY (console dispatch)
    ↓
Memory allocator locks (FRAME_ALLOCATOR, heap)  ← NOT IRQ-safe
```

### Key Rules

1. **IrqSpinlock is innermost for IRQ-safe locks** - When you need to hold both
   an IRQ-safe lock and a non-IRQ-safe lock, acquire the IrqSpinlock first.

2. **Never acquire non-IRQ-safe locks from interrupt context** - This is the
   fundamental rule. TASK_TABLE, PAGE_CACHE, FD_TABLE, and allocator locks must
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

---

## 3. Per-Subsystem Locking

### 3.1 Scheduler

**Location:** `kernel/percpu_sched.rs`

The scheduler uses a per-CPU locking model to minimize contention.

#### Global State

| Variable | Type | Purpose |
|----------|------|---------|
| `PERCPU_SCHEDS` | `[PerCpuScheduler; MAX_CPUS]` | Per-CPU scheduler array |
| `TASK_TABLE` | `Mutex<GlobalTaskTable>` | Global task registry |
| `SCHEDULING_ENABLED` | `AtomicBool` | Global scheduling enable flag |
| `TICK_COUNT` | `AtomicU64` | Timer tick counter |

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

1. **Each CPU only locks its own run queue** - Cross-CPU operations go through
   `TASK_TABLE` or use IPIs.

2. **Run queue lock is IRQ-safe** - Timer interrupts cannot cause deadlocks.

3. **Context switch happens with lock held** - The lock is released after
   returning from `context_switch()`.

4. **Drop lock before `context_switch_first()`** - The initial switch to a
   task never returns, so the lock must be explicitly dropped.

5. **Timer ISR only touches local CPU** - `wake_sleepers()` only processes
   the current CPU's sleep queue to maintain locality.

**Lock acquisition pattern:**
```rust
// In yield_now() or try_schedule()
let sched = get_percpu_sched(cpu_id);
let mut rq = sched.lock.lock();  // IRQs disabled, preempt_count++

// Safe to acquire TASK_TABLE while holding IrqSpinlock
// (interrupts are disabled, so no ISR can try to acquire TASK_TABLE)
let table = TASK_TABLE.lock();

// ... modify run queue, select next task ...

unsafe { context_switch(curr, next, next_kstack); }
// Lock automatically released when guard drops after context switch returns
```

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

### 3.2 Memory Management

#### Frame Allocator

**Location:** `kernel/frame_alloc.rs`

```rust
pub struct BitmapFrameAllocator {
    inner: Mutex<BitmapFrameAllocatorInner>,
}
```

- Single `Mutex` protects the bitmap and allocation state
- **NOT IRQ-safe** - must not be called from interrupt context
- Thread-safe via `&self` methods (`alloc()`, `free()`)

#### Heap Allocator

**Location:** `kernel/heap.rs`

```rust
pub struct HeapAllocator {
    inner: Mutex<HeapAllocatorInner>,
}
```

- Single `Mutex` protects the free list
- **NOT IRQ-safe** - must not be called from interrupt context
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

### 3.3 Virtual File System (VFS)

**Location:** `fs/` crate

The VFS uses fine-grained locking with `RwLock` for concurrent read access.
**All VFS locks are NOT IRQ-safe** and must only be accessed from thread context.

#### Global Structures

| Variable | Type | Purpose |
|----------|------|---------|
| `DCACHE` | `DentryCache` (contains `RwLock`) | Dentry cache root |
| `MOUNT_NS` | `MountNamespace` (contains `RwLock`) | Mount namespace root |

#### Per-Object Locks

**Inode** (`fs/inode.rs`):
```rust
pub struct Inode {
    pub size: AtomicU64,                           // Lock-free size updates
    pub lock: RwLock<()>,                          // Metadata protection
    i_rwsem: Mutex<()>,                            // Directory operation serialization
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

**Dentry Rename Lock:**

Each dentry has a dedicated `rename_lock` (Mutex) separate from `d_lock`:

```rust
pub struct Dentry {
    d_lock: RwLock<DentryInner>,  // Protects inode, parent, children, flags
    rename_lock: Mutex<()>,       // For lock_rename() coordination
}
```

The separate lock allows holding across function calls (not RAII-bound) and
avoids interfering with concurrent reads of dentry metadata.

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

The VFS layer acquires dentry rename_locks via `lock_rename()`. Filesystems may
still use internal locks for their data structures (e.g., ramfs children BTreeMap)
to protect against concurrent non-rename operations. The VFS rename_lock ensures
only one rename operates on a given directory pair at a time.

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
| `s_vfs_rename_mutex` | `Mutex<()>` | Serializes cross-directory renames |

**Lock Ordering for Cross-Directory Rename:**

```
1. SuperBlock.s_vfs_rename_mutex (cross-directory only)
   ↓
2. Parent directories via lock_rename() (ancestor-first or address order)
   ↓
3. Source/target inodes if needed
```

**Same-Directory Rename:**

Does not acquire `s_vfs_rename_mutex` - only needs the single dentry's
`rename_lock`.

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

#### Wait Queues (Linux folio_wait_table Pattern)

**Location:** `core/waitqueue.rs`

Wait queues provide event-based blocking where tasks sleep until woken by another
task. This is used for page locking and can be used for other blocking primitives.

**Key Components:**
```rust
/// A wait queue for blocking synchronization
pub struct WaitQueue {
    head: IrqSpinlock<WaitQueueHead>,
}

/// Global page wait hash table (like Linux folio_wait_table)
static PAGE_WAIT_TABLE: [WaitQueue; 256];
```

**API:**
```rust
impl WaitQueue {
    fn wait(&self);        // Sleep until woken
    fn wake_one(&self);    // Wake first waiter (fair)
    fn wake_all(&self);    // Wake all waiters
}

/// Get wait queue for a page address
fn page_wait_queue(page_addr: u64) -> &'static WaitQueue;
```

**Page Locking:**

Page cache pages use sleeping locks instead of spinning. When a page is already
locked, waiters sleep on the page's wait queue until the holder calls `unlock()`:

```rust
impl CachedPage {
    pub fn lock(&self) {
        // Fast path: try immediate acquire
        if self.locked.compare_exchange(...).is_ok() { return; }

        // Slow path: sleep on wait queue
        loop {
            if self.locked.compare_exchange(...).is_ok() { return; }
            page_wait_queue(self.frame).wait();
        }
    }

    pub fn unlock(&self) {
        self.locked.store(false, Ordering::Release);
        page_wait_queue(self.frame).wake_one();
    }
}
```

**Early Boot Fallback:** If scheduling is not yet enabled, page locking falls
back to spinning instead of sleeping.

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

**Location:** `core/printk.rs`, `core/console.rs`

The printk subsystem uses two separate locks to ensure SMP-safe message output
while avoiding deadlocks:

```rust
/// Serializes console/serial writes across CPUs
static OUTPUT_LOCK: Mutex<()> = Mutex::new(());

/// Protects the ring buffer state
static PRINTK: Mutex<PrintkState> = Mutex::new(PrintkState::new());
```

**Locking Hierarchy:**
```
1. OUTPUT_LOCK (held for entire message, including newline)
   ↓
2. PRINTK (held briefly for ring buffer write)
   ↓
3. CONSOLE_REGISTRY (held during console_write)
```

**Lock Separation:**

The two-lock design serves different purposes:
- `OUTPUT_LOCK`: Ensures entire formatted messages are written atomically
- `PRINTK`: Protects the ring buffer data structure

This separation allows:
1. Buffering to proceed while another CPU writes to console
2. Console code to potentially log (though not currently needed)

**PrintkWriter Pattern:**

The `PrintkWriter` struct holds `OUTPUT_LOCK` for the duration of formatting:

```rust
pub struct PrintkWriter {
    _guard: spin::MutexGuard<'static, ()>,
}

impl PrintkWriter {
    pub fn new() -> Self {
        Self { _guard: OUTPUT_LOCK.lock() }
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

**Interrupt Context:**

- **NOT IRQ-safe** - `Mutex` does not disable interrupts
- Printk from interrupt context will spin if another CPU holds OUTPUT_LOCK
- For panic context, interrupts are disabled first, so deadlock is avoided
- Consider `try_lock()` pattern for truly interrupt-safe logging if needed

**Console Integration:**

`console::console_write()` holds `CONSOLE_REGISTRY` lock during `write_all()`:

```rust
pub fn console_write(data: &[u8]) {
    let registry = CONSOLE_REGISTRY.lock();
    if registry.has_console() {
        registry.write_all(data);
    }
}
```

The lock order (OUTPUT_LOCK → PRINTK → CONSOLE_REGISTRY) is maintained throughout.

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

**kill(2)/tgkill(2):** Send signal to task:
```rust
with_task_signal_state(tid, |state| {   // TASK_SIGNAL_STATE lookup
    state.pending.add(sig);
});
set_tif_sigpending(tid);                // TASK_TIF_SIGPENDING update
```

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
1. FutexHashBucket.waiters (IrqSpinlock)
   ↓
2. TASK_TABLE (Mutex, for task state updates during wake)
   ↓
3. Per-CPU scheduler lock (IrqSpinlock, for run queue updates)
```

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
3. **Lock order: bucket → TASK_TABLE → scheduler** - Consistent ordering
4. **Multi-bucket operations use address ordering** - Prevents deadlock
5. **Robust cleanup has entry limit** - Prevents infinite loop from corrupted list

### 3.9 TTY and Console Subsystem

**Location:** `kernel/tty/`, `kernel/gfx/console.rs`, `kernel/console.rs`, `kernel/printk.rs`

The TTY and console subsystem handles terminal I/O and kernel message output.
All locks are non-IRQ-safe (Mutex) and must only be accessed from process context.

#### Console Framework Locks

| Variable | Location | Type | Purpose |
|----------|----------|------|---------|
| `OUTPUT_LOCK` | `printk.rs` | `Mutex<()>` | Serializes all console writes across CPUs |
| `PRINTK` | `printk.rs` | `Mutex<PrintkState>` | Protects ring buffer state |
| `CONSOLE_REGISTRY` | `console.rs` | `Mutex<ConsoleRegistry>` | Protects console driver list |

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
OUTPUT_LOCK (held for entire formatted message)
    ↓
PRINTK (ring buffer, brief hold during write)
    ↓
CONSOLE_REGISTRY (console dispatch to drivers)
    ↓
Per-TTY locks (termios, input, state) - independent between TTYs
    ↓
GfxConsole.state (if graphics console receives output)
```

#### Panic-Safe Console Output

During panic, the normal locking path can deadlock if the panicking CPU already
holds `OUTPUT_LOCK`. The printk subsystem handles this with:

1. **`OOPS_IN_PROGRESS` flag** - Atomic bool set at panic entry
2. **`try_lock()` fallback** - Non-blocking lock attempt in panic mode
3. **Direct serial output** - If lock unavailable, bypass console subsystem

```rust
// In PrintkWriter::new() during panic:
if OOPS_IN_PROGRESS.load(Ordering::Acquire) {
    match OUTPUT_LOCK.try_lock() {
        Some(guard) => /* use normal path */,
        None => /* direct serial write */,
    }
}
```

#### Key Rules

1. **OUTPUT_LOCK ensures atomic messages** - Multi-CPU printk won't interleave
2. **Per-TTY locks are independent** - No ordering constraints between TTYs
3. **GfxConsole uses single lock** - Cursor and surface always atomic
4. **Panic bypasses locks** - Direct serial for guaranteed panic output

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
- Set reschedule flags (atomic)
- Read per-CPU data (via GS segment)

### 7.2 What CANNOT Run in Interrupt Context

- **Memory allocation** (heap/frame allocator use Mutex)
- **TASK_TABLE access** (uses Mutex)
- **VFS operations** (use RwLock)
- **printk** (uses Mutex, consider try_lock for exceptions)
- **Any Mutex or RwLock acquisition**

### 7.3 Deferring Work

If interrupt context needs to trigger something that requires non-IRQ-safe locks:

1. Set a flag (atomic)
2. The flag is checked at safe points (interrupt exit, scheduler tick)
3. The actual work is done in thread context

Example: `needs_reschedule` flag is set in timer ISR, actual reschedule happens
at interrupt exit when `preempt_count == 0`.

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


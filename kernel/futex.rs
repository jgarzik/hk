//! Linux-compatible futex (Fast Userspace Mutex) implementation
//!
//! Futexes are the building blocks for userspace synchronization primitives
//! like mutexes, condition variables, and semaphores. They provide efficient
//! blocking when contention occurs.
//!
//! ## Supported Operations
//!
//! - FUTEX_WAIT / FUTEX_WAIT_BITSET: Block until woken or value changes
//! - FUTEX_WAKE / FUTEX_WAKE_BITSET: Wake waiting tasks
//! - FUTEX_REQUEUE / FUTEX_CMP_REQUEUE: Requeue waiters to another futex
//!
//! ## Robust Futexes
//!
//! Tasks can register a robust list of held futexes. On task exit, the kernel
//! walks this list and marks futexes with FUTEX_OWNER_DIED, then wakes waiters.
//!
//! ## Race Prevention
//!
//! The critical race between FUTEX_WAIT and FUTEX_WAKE is prevented using
//! memory barriers following Linux's pattern:
//!
//! ```text
//! Waiter (CPU 0)              Waker (CPU 1)
//! --------------              --------------
//! waiter_count++              *futex = new_value
//! smp_mb()                    smp_mb()
//! lock(bucket)                if (waiter_count > 0)
//! val = *futex                  lock(bucket)
//! if val == expected            find & wake waiters
//!   enqueue                     unlock(bucket)
//! unlock(bucket)
//! sleep
//! ```

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::arch::IrqSpinlock;
use crate::task::{Priority, TaskState, Tid};
use crate::uaccess::{get_user, put_user};

// Architecture-specific uaccess implementation
#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::uaccess::Aarch64Uaccess as Uaccess;
#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::uaccess::X86_64Uaccess as Uaccess;

// Error constants (as i32 for syscall returns)
const EAGAIN: i32 = 11;
const EFAULT: i32 = 14;
const EINVAL: i32 = 22;
const ENOSYS: i32 = 38;
const ESRCH: i32 = 3;
const ETIMEDOUT: i32 = 110;

// =============================================================================
// Futex Operation Constants (Linux ABI compatible)
// =============================================================================

/// Futex operation codes and flags (matches Linux uapi/linux/futex.h)
pub mod futex_op {
    /// Wait if *uaddr == val
    pub const FUTEX_WAIT: u32 = 0;
    /// Wake up to val waiters
    pub const FUTEX_WAKE: u32 = 1;
    /// Requeue waiters from uaddr to uaddr2
    pub const FUTEX_REQUEUE: u32 = 3;
    /// Requeue if *uaddr == val3
    pub const FUTEX_CMP_REQUEUE: u32 = 4;
    /// Wait with bitset matching
    pub const FUTEX_WAIT_BITSET: u32 = 9;
    /// Wake with bitset matching
    pub const FUTEX_WAKE_BITSET: u32 = 10;

    /// Private futex (no shared memory)
    pub const FUTEX_PRIVATE_FLAG: u32 = 128;
    /// Use CLOCK_REALTIME for timeout
    pub const FUTEX_CLOCK_REALTIME: u32 = 256;
    /// Mask to extract operation
    pub const FUTEX_CMD_MASK: u32 = !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);

    /// Match any bit in bitset operations
    pub const FUTEX_BITSET_MATCH_ANY: u32 = 0xffffffff;

    // Robust futex constants
    /// There are waiters on this futex
    pub const FUTEX_WAITERS: u32 = 0x80000000;
    /// Owner died without unlocking
    pub const FUTEX_OWNER_DIED: u32 = 0x40000000;
    /// Mask for TID in futex value
    pub const FUTEX_TID_MASK: u32 = 0x3fffffff;
}

/// Limit on robust list entries to prevent DoS
const ROBUST_LIST_LIMIT: usize = 2048;

// =============================================================================
// Futex Key
// =============================================================================

/// Futex key uniquely identifying a futex location
///
/// For private futexes (most common), the key is (virtual_address, pid).
/// For shared futexes, the key would use physical address (not yet implemented).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FutexKey {
    /// Virtual address of the futex
    pub ptr: u64,
    /// Process ID (0 for shared futexes)
    pub pid: u64,
}

impl FutexKey {
    /// Create a private futex key
    pub fn private(uaddr: u64, pid: u64) -> Self {
        Self { ptr: uaddr, pid }
    }

    /// Create a shared futex key (uses pid=0)
    #[allow(dead_code)]
    pub fn shared(uaddr: u64) -> Self {
        Self { ptr: uaddr, pid: 0 }
    }
}

// =============================================================================
// Futex Queue Entry
// =============================================================================

/// Entry representing a task waiting on a futex
pub struct FutexQ {
    /// Key identifying which futex this waiter is blocked on
    pub key: FutexKey,
    /// Thread ID of the waiting task
    pub tid: Tid,
    /// Task priority (for scheduler re-enqueue)
    pub priority: Priority,
    /// Bitset for selective wake (FUTEX_WAIT_BITSET/FUTEX_WAKE_BITSET)
    pub bitset: u32,
}

impl FutexQ {
    /// Create a new futex queue entry
    pub fn new(key: FutexKey, tid: Tid, priority: Priority, bitset: u32) -> Self {
        Self {
            key,
            tid,
            priority,
            bitset,
        }
    }
}

// =============================================================================
// Futex Hash Bucket
// =============================================================================

/// Hash bucket containing futex waiters
///
/// Uses IrqSpinlock for IRQ-safety (can be called from signal context).
/// The waiter_count provides a fast-path check to avoid lock acquisition
/// when there are no waiters.
pub struct FutexHashBucket {
    /// Waiters list protected by IrqSpinlock
    waiters: IrqSpinlock<Vec<FutexQ>>,
    /// Waiter count for fast-path optimization
    waiter_count: AtomicU32,
}

impl Default for FutexHashBucket {
    fn default() -> Self {
        Self::new()
    }
}

impl FutexHashBucket {
    /// Create a new empty hash bucket
    pub const fn new() -> Self {
        Self {
            waiters: IrqSpinlock::new(Vec::new()),
            waiter_count: AtomicU32::new(0),
        }
    }

    /// Increment waiter count (called before enqueueing)
    fn inc_waiters(&self) {
        self.waiter_count.fetch_add(1, Ordering::Release);
    }

    /// Decrement waiter count (called after dequeueing)
    fn dec_waiters(&self) {
        self.waiter_count.fetch_sub(1, Ordering::Release);
    }

    /// Check if any waiters pending (fast path for wake)
    fn has_waiters(&self) -> bool {
        self.waiter_count.load(Ordering::Acquire) > 0
    }
}

// =============================================================================
// Futex Hash Table
// =============================================================================

/// Number of buckets in the futex hash table
const FUTEX_HASH_SIZE: usize = 256;

/// Global futex hash table
static FUTEX_HASH_TABLE: [FutexHashBucket; FUTEX_HASH_SIZE] =
    [const { FutexHashBucket::new() }; FUTEX_HASH_SIZE];

/// Hash a futex key to a bucket index
///
/// Uses FNV-1a style hash for good distribution across buckets.
fn futex_hash(key: &FutexKey) -> usize {
    let mut hash: u64 = 0xcbf29ce484222325; // FNV offset basis
    hash ^= key.ptr;
    hash = hash.wrapping_mul(0x100000001b3); // FNV prime
    hash ^= key.pid;
    hash = hash.wrapping_mul(0x100000001b3);
    (hash as usize) % FUTEX_HASH_SIZE
}

/// Get the hash bucket for a futex key
fn futex_bucket(key: &FutexKey) -> &'static FutexHashBucket {
    &FUTEX_HASH_TABLE[futex_hash(key)]
}

// =============================================================================
// Robust Futex Support - uses Task.robust_list field via TASK_TABLE
// =============================================================================

use crate::task::percpu::TASK_TABLE;

/// Robust list head structure (matches Linux ABI)
#[repr(C)]
pub struct RobustListHead {
    /// The head of the list. Points back to itself if empty.
    pub list: u64,
    /// Relative offset from list entry to the futex field
    pub futex_offset: i64,
    /// Address of lock being acquired (for race with exit)
    pub list_op_pending: u64,
}

impl RobustListHead {
    /// Size of the robust list head structure
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

// =============================================================================
// User Memory Access Helpers
// =============================================================================

/// Read a u32 from user memory
///
/// Uses proper uaccess infrastructure which:
/// - Validates address is in user space range
/// - Handles SMAP protection on x86_64
/// - Checks alignment
fn read_user_u32(addr: u64) -> Result<u32, i32> {
    get_user::<Uaccess, u32>(addr).map_err(|_| -EFAULT)
}

/// Write a u32 to user memory
///
/// Uses proper uaccess infrastructure which:
/// - Validates address is in user space range
/// - Handles SMAP protection on x86_64
/// - Checks alignment
fn write_user_u32(addr: u64, val: u32) -> Result<(), i32> {
    put_user::<Uaccess, u32>(addr, val).map_err(|_| -EFAULT)
}

/// Read a u64 from user memory
///
/// Uses proper uaccess infrastructure which:
/// - Validates address is in user space range
/// - Handles SMAP protection on x86_64
/// - Checks alignment
fn read_user_u64(addr: u64) -> Result<u64, i32> {
    get_user::<Uaccess, u64>(addr).map_err(|_| -EFAULT)
}

/// Read a timespec from user memory and convert to nanoseconds
fn read_user_timeout(timeout_ptr: u64) -> Result<Option<u64>, i32> {
    if timeout_ptr == 0 {
        return Ok(None);
    }

    // Read tv_sec and tv_nsec
    let tv_sec = read_user_u64(timeout_ptr)?;
    let tv_nsec = read_user_u64(timeout_ptr + 8)?;

    // Validate
    if tv_nsec >= 1_000_000_000 {
        return Err(-EINVAL);
    }

    let ns = tv_sec.saturating_mul(1_000_000_000).saturating_add(tv_nsec);
    Ok(Some(ns))
}

// =============================================================================
// Current Task Info
// =============================================================================

/// Get current task's TID, PID, and priority
fn get_current_task_info() -> (Tid, u64, Priority) {
    use crate::task::percpu::{TASK_TABLE, current_pid, current_tid};

    let tid = current_tid();
    let pid = current_pid();

    let priority = {
        let table = TASK_TABLE.lock();
        table
            .tasks
            .iter()
            .find(|t| t.tid == tid)
            .map(|t| t.priority)
            .unwrap_or(128)
    };

    (tid, pid, priority)
}

// =============================================================================
// Core Futex Operations
// =============================================================================

/// Wait on a futex
///
/// Blocks the current task until woken or the timeout expires.
/// Returns immediately with -EAGAIN if the value at uaddr doesn't match expected.
///
/// # Arguments
/// * `uaddr` - User address of the futex (must be 4-byte aligned)
/// * `expected` - Expected value at uaddr
/// * `timeout_ns` - Optional timeout in nanoseconds
/// * `bitset` - Bitset for selective wake (must be non-zero)
/// * `is_private` - True if FUTEX_PRIVATE_FLAG is set
///
/// # Returns
/// * 0 on successful wake
/// * -EAGAIN if value at uaddr != expected
/// * -ETIMEDOUT if timeout expired
/// * -EINVAL if bitset is 0 or address is invalid
pub fn futex_wait(
    uaddr: u64,
    expected: u32,
    timeout_ns: Option<u64>,
    bitset: u32,
    is_private: bool,
) -> i32 {
    use crate::task::percpu::{SCHEDULING_ENABLED, TASK_TABLE, current_percpu_sched};

    // Validate bitset (0 is invalid per Linux ABI)
    if bitset == 0 {
        return -EINVAL;
    }

    // Check scheduling is enabled
    if !SCHEDULING_ENABLED.load(Ordering::Acquire) {
        return -EAGAIN;
    }

    // Get current task info
    let (tid, pid, priority) = get_current_task_info();

    // Create futex key
    let key = if is_private {
        FutexKey::private(uaddr, pid)
    } else {
        // For shared futexes, we'd need physical address lookup
        // For now, treat as private with pid=0
        FutexKey::shared(uaddr)
    };

    let bucket = futex_bucket(&key);

    // CRITICAL: Increment waiter count BEFORE checking value
    // This provides the memory barrier ordering with the waker
    bucket.inc_waiters();

    // Memory barrier: ensures waiter count visible before value read
    core::sync::atomic::fence(Ordering::SeqCst);

    // Lock bucket and check value
    let should_wait = {
        let mut waiters = bucket.waiters.lock();

        // Read futex value
        let current_val = match read_user_u32(uaddr) {
            Ok(v) => v,
            Err(e) => {
                bucket.dec_waiters();
                return e;
            }
        };

        // If value changed, don't wait
        if current_val != expected {
            bucket.dec_waiters();
            return -EAGAIN;
        }

        // Value matches - enqueue ourselves
        waiters.push(FutexQ::new(key, tid, priority, bitset));
        true
    };

    if !should_wait {
        return -EAGAIN;
    }

    // Mark task as sleeping
    {
        let mut table = TASK_TABLE.lock();
        if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
            task.state = TaskState::Sleeping;
        }
    }

    // Schedule away (with optional timeout)
    let deadline = timeout_ns.map(|ns| {
        let ts = crate::time::TIMEKEEPER.current_time();
        let now_ns = (ts.sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(ts.nsec as u64);
        now_ns.saturating_add(ns)
    });

    // Add to sleep queue if timeout specified
    if let Some(deadline_ns) = deadline
        && let Some(sched) = current_percpu_sched()
        && sched.initialized.load(Ordering::Acquire)
    {
        use crate::task::sched::SleepEntry;
        let mut rq = sched.lock.lock();
        rq.sleep_queue.push(SleepEntry {
            tid,
            wake_tick: deadline_ns,
            priority,
        });
        rq.sleep_queue.sort_by_key(|e| e.wake_tick);
    }

    // Yield to scheduler
    crate::task::syscall::sys_sched_yield();

    // We've been woken (or timed out)
    // Check if we're still in the queue (indicates timeout, not wake)
    let was_timeout = {
        let mut waiters = bucket.waiters.lock();
        if let Some(pos) = waiters.iter().position(|q| q.tid == tid && q.key == key) {
            // Still in queue - we weren't woken by futex_wake
            waiters.remove(pos);
            bucket.dec_waiters();
            true
        } else {
            // Not in queue - we were woken normally
            false
        }
    };

    if was_timeout && timeout_ns.is_some() {
        -ETIMEDOUT
    } else {
        0
    }
}

/// Wake waiters on a futex
///
/// Wakes up to num_wake tasks waiting on the futex at uaddr.
///
/// # Arguments
/// * `uaddr` - User address of the futex
/// * `num_wake` - Maximum number of waiters to wake
/// * `bitset` - Bitset for selective wake (must be non-zero)
/// * `is_private` - True if FUTEX_PRIVATE_FLAG is set
///
/// # Returns
/// Number of waiters woken (non-negative), or -EINVAL if bitset is 0
pub fn futex_wake(uaddr: u64, num_wake: i32, bitset: u32, is_private: bool) -> i32 {
    use crate::task::TaskState;
    use crate::task::percpu::{TASK_TABLE, current_percpu_sched};

    if num_wake <= 0 {
        return 0;
    }

    if bitset == 0 {
        return -EINVAL;
    }

    // Get current PID for private futex key
    let pid = crate::task::percpu::current_pid();

    let key = if is_private {
        FutexKey::private(uaddr, pid)
    } else {
        FutexKey::shared(uaddr)
    };

    let bucket = futex_bucket(&key);

    // Memory barrier paired with futex_wait's barrier
    core::sync::atomic::fence(Ordering::SeqCst);

    // Fast path: no waiters
    if !bucket.has_waiters() {
        return 0;
    }

    // Collect waiters to wake
    let mut woken = 0i32;
    let mut to_wake: Vec<(Tid, Priority)> = Vec::new();

    {
        let mut waiters = bucket.waiters.lock();

        let mut i = 0;
        while i < waiters.len() && woken < num_wake {
            if waiters[i].key == key && (waiters[i].bitset & bitset) != 0 {
                let q = waiters.remove(i);
                bucket.dec_waiters();
                to_wake.push((q.tid, q.priority));
                woken += 1;
            } else {
                i += 1;
            }
        }
    }

    // Wake tasks outside the bucket lock
    for (tid, priority) in to_wake {
        // Mark task as ready
        {
            let mut table = TASK_TABLE.lock();
            if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
                task.state = TaskState::Ready;
            }
        }

        // Add to run queue
        if let Some(sched) = current_percpu_sched()
            && sched.initialized.load(Ordering::Acquire)
        {
            let mut rq = sched.lock.lock();
            rq.queue().enqueue(tid, priority);
            rq.nr_running += 1;
        }
    }

    woken
}

/// Requeue waiters from one futex to another
///
/// Wakes up to nr_wake waiters on uaddr, then moves up to nr_requeue
/// waiters from uaddr to uaddr2.
///
/// # Arguments
/// * `uaddr` - Source futex address
/// * `uaddr2` - Destination futex address
/// * `nr_wake` - Number of waiters to wake
/// * `nr_requeue` - Number of waiters to requeue
/// * `cmpval` - Optional comparison value (for CMP_REQUEUE)
/// * `is_private` - True if FUTEX_PRIVATE_FLAG is set
///
/// # Returns
/// Total number of waiters woken + requeued, or negative error
pub fn futex_requeue(
    uaddr: u64,
    uaddr2: u64,
    nr_wake: i32,
    nr_requeue: i32,
    cmpval: Option<u32>,
    is_private: bool,
) -> i32 {
    use crate::task::TaskState;
    use crate::task::percpu::{TASK_TABLE, current_percpu_sched};

    if nr_wake < 0 || nr_requeue < 0 {
        return -EINVAL;
    }

    let pid = crate::task::percpu::current_pid();

    let key1 = if is_private {
        FutexKey::private(uaddr, pid)
    } else {
        FutexKey::shared(uaddr)
    };

    let key2 = if is_private {
        FutexKey::private(uaddr2, pid)
    } else {
        FutexKey::shared(uaddr2)
    };

    let bucket1 = futex_bucket(&key1);
    let bucket2 = futex_bucket(&key2);
    let same_bucket = core::ptr::eq(bucket1, bucket2);

    let mut to_wake: Vec<(Tid, Priority)> = Vec::new();
    let mut to_requeue: Vec<FutexQ> = Vec::new();
    let mut woken = 0i32;
    let mut requeued = 0i32;

    // Phase 1: Extract waiters to wake and requeue from bucket1
    {
        let mut waiters = bucket1.waiters.lock();

        // If CMP_REQUEUE, check expected value while holding lock
        if let Some(expected) = cmpval {
            let current = match read_user_u32(uaddr) {
                Ok(v) => v,
                Err(e) => return e,
            };
            if current != expected {
                return -EAGAIN;
            }
        }

        let mut i = 0;
        while i < waiters.len() {
            if waiters[i].key == key1 {
                if woken < nr_wake {
                    // Wake this waiter
                    let q = waiters.remove(i);
                    bucket1.dec_waiters();
                    to_wake.push((q.tid, q.priority));
                    woken += 1;
                } else if requeued < nr_requeue {
                    // Mark for requeue
                    let mut q = waiters.remove(i);
                    bucket1.dec_waiters();
                    q.key = key2;
                    to_requeue.push(q);
                    requeued += 1;
                } else {
                    break;
                }
            } else {
                i += 1;
            }
        }
    }

    // Phase 2: Add requeued waiters to bucket2
    if !to_requeue.is_empty() {
        if same_bucket {
            // Same bucket - just re-add with new key
            let mut waiters = bucket1.waiters.lock();
            for q in to_requeue {
                waiters.push(q);
                bucket1.inc_waiters();
            }
        } else {
            // Different bucket
            let mut waiters = bucket2.waiters.lock();
            for q in to_requeue {
                waiters.push(q);
                bucket2.inc_waiters();
            }
        }
    }

    // Phase 3: Wake collected tasks
    for (tid, priority) in to_wake {
        {
            let mut table = TASK_TABLE.lock();
            if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
                task.state = TaskState::Ready;
            }
        }

        if let Some(sched) = current_percpu_sched()
            && sched.initialized.load(Ordering::Acquire)
        {
            let mut rq = sched.lock.lock();
            rq.queue().enqueue(tid, priority);
            rq.nr_running += 1;
        }
    }

    woken + requeued
}

// =============================================================================
// Robust Futex Syscalls
// =============================================================================

/// Set the robust list head for the current task
///
/// # Arguments
/// * `head` - User address of robust_list_head structure
/// * `len` - Size of the structure (must match expected size)
///
/// # Returns
/// 0 on success, -EINVAL if len doesn't match
pub fn sys_set_robust_list(head: u64, len: u64) -> i32 {
    if len as usize != RobustListHead::SIZE {
        return -EINVAL;
    }

    let tid = crate::task::percpu::current_tid();

    let mut table = TASK_TABLE.lock();
    if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
        task.robust_list = head;
    }

    0
}

/// Get the robust list head for a task
///
/// # Arguments
/// * `pid` - Process ID (0 for current task)
/// * `head_ptr` - User address to store the robust list head pointer
/// * `len_ptr` - User address to store the length
///
/// # Returns
/// 0 on success, -ESRCH if task not found, -EFAULT on bad address
pub fn sys_get_robust_list(pid: i32, head_ptr: u64, len_ptr: u64) -> i32 {
    let current_tid = crate::task::percpu::current_tid();

    // Determine target TID
    let target_tid = if pid == 0 {
        current_tid
    } else {
        // For non-zero pid, we'd need to look up the task
        // For now, only support current task
        if pid as Tid != current_tid {
            return -ESRCH;
        }
        pid as Tid
    };

    let table = TASK_TABLE.lock();
    let head = table
        .tasks
        .iter()
        .find(|t| t.tid == target_tid)
        .map(|t| t.robust_list)
        .unwrap_or(0);

    // Write head pointer to user memory
    if head_ptr != 0 && put_user::<Uaccess, u64>(head_ptr, head).is_err() {
        return -EFAULT;
    }

    // Write length to user memory
    if len_ptr != 0 && put_user::<Uaccess, u64>(len_ptr, RobustListHead::SIZE as u64).is_err() {
        return -EFAULT;
    }

    0
}

/// Walk and cleanup robust futex list on task exit
///
/// Called during task exit to:
/// 1. Walk the user-space robust list
/// 2. For each held futex, set FUTEX_OWNER_DIED and wake one waiter
///
/// # Arguments
/// * `tid` - Thread ID of exiting task
/// * `pid` - Process ID of exiting task (for futex key)
pub fn exit_robust_list(tid: Tid, pid: u64) {
    // Get and remove robust list for this task
    let head_addr = {
        let mut table = TASK_TABLE.lock();
        if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
            let addr = task.robust_list;
            task.robust_list = 0;
            if addr != 0 { Some(addr) } else { None }
        } else {
            None
        }
    };

    let head_addr = match head_addr {
        Some(addr) => addr,
        None => return, // No robust list registered
    };

    // Read robust list head from user memory
    let list_ptr = match read_user_u64(head_addr) {
        Ok(v) => v,
        Err(_) => return,
    };

    let futex_offset = match read_user_u64(head_addr + 8) {
        Ok(v) => v as i64,
        Err(_) => return,
    };

    let pending_ptr = match read_user_u64(head_addr + 16) {
        Ok(v) => v,
        Err(_) => return,
    };

    // Handle pending lock (lock being acquired at exit)
    if pending_ptr != 0 {
        handle_futex_death(pending_ptr, futex_offset, tid, pid);
    }

    // Walk the list
    let mut entry = list_ptr;
    let mut count = 0;

    while entry != head_addr && count < ROBUST_LIST_LIMIT {
        // Get next pointer before potentially modifying entry
        let next = match read_user_u64(entry) {
            Ok(v) => v,
            Err(_) => break,
        };

        // Skip the pending entry (already handled)
        if entry != pending_ptr {
            handle_futex_death(entry, futex_offset, tid, pid);
        }

        entry = next;
        count += 1;
    }
}

/// Handle a single futex on task death
///
/// If the task owns the futex (TID matches), set FUTEX_OWNER_DIED
/// and wake one waiter.
fn handle_futex_death(entry: u64, futex_offset: i64, tid: Tid, pid: u64) {
    // Calculate futex address from entry + offset
    let futex_addr = if futex_offset >= 0 {
        entry.wrapping_add(futex_offset as u64)
    } else {
        entry.wrapping_sub((-futex_offset) as u64)
    };

    // Read current futex value
    let current_val = match read_user_u32(futex_addr) {
        Ok(v) => v,
        Err(_) => return,
    };

    // Check if we own this futex
    let owner_tid = current_val & futex_op::FUTEX_TID_MASK;
    if owner_tid != tid as u32 {
        return; // Not our futex
    }

    // Set FUTEX_OWNER_DIED bit
    let new_val = current_val | futex_op::FUTEX_OWNER_DIED;
    if write_user_u32(futex_addr, new_val).is_err() {
        return;
    }

    // Wake one waiter (use private=true since we have pid)
    let key = FutexKey::private(futex_addr, pid);
    let bucket = futex_bucket(&key);

    if bucket.has_waiters() {
        futex_wake(futex_addr, 1, futex_op::FUTEX_BITSET_MATCH_ANY, true);
    }
}

// =============================================================================
// Syscall Entry Point
// =============================================================================

/// Linux futex syscall entry point
///
/// # Arguments
/// * `uaddr` - User address of the futex
/// * `futex_op` - Operation code with optional flags
/// * `val` - Value (meaning depends on operation)
/// * `timeout_or_val2` - Timeout pointer or second value (for requeue)
/// * `uaddr2` - Second futex address (for requeue operations)
/// * `val3` - Third value (typically bitset)
///
/// # Returns
/// Result depends on operation:
/// - FUTEX_WAIT: 0 on wake, negative error code
/// - FUTEX_WAKE: number of waiters woken
/// - FUTEX_REQUEUE: number of waiters woken + requeued
pub fn sys_futex(
    uaddr: u64,
    futex_op: u32,
    val: u32,
    timeout_or_val2: u64,
    uaddr2: u64,
    val3: u32,
) -> i32 {
    use futex_op::*;

    let op = futex_op & FUTEX_CMD_MASK;
    let is_private = (futex_op & FUTEX_PRIVATE_FLAG) != 0;
    let _use_realtime = (futex_op & FUTEX_CLOCK_REALTIME) != 0;

    match op {
        FUTEX_WAIT => {
            let timeout = match read_user_timeout(timeout_or_val2) {
                Ok(t) => t,
                Err(e) => return e,
            };
            futex_wait(uaddr, val, timeout, FUTEX_BITSET_MATCH_ANY, is_private)
        }

        FUTEX_WAKE => futex_wake(uaddr, val as i32, FUTEX_BITSET_MATCH_ANY, is_private),

        FUTEX_WAIT_BITSET => {
            if val3 == 0 {
                return -EINVAL;
            }
            let timeout = match read_user_timeout(timeout_or_val2) {
                Ok(t) => t,
                Err(e) => return e,
            };
            futex_wait(uaddr, val, timeout, val3, is_private)
        }

        FUTEX_WAKE_BITSET => {
            if val3 == 0 {
                return -EINVAL;
            }
            futex_wake(uaddr, val as i32, val3, is_private)
        }

        FUTEX_REQUEUE => {
            let nr_requeue = timeout_or_val2 as i32;
            futex_requeue(uaddr, uaddr2, val as i32, nr_requeue, None, is_private)
        }

        FUTEX_CMP_REQUEUE => {
            let nr_requeue = timeout_or_val2 as i32;
            futex_requeue(
                uaddr,
                uaddr2,
                val as i32,
                nr_requeue,
                Some(val3),
                is_private,
            )
        }

        _ => -ENOSYS,
    }
}

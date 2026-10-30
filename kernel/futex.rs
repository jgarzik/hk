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
use core::cell::UnsafeCell;
use core::marker::PhantomPinned;
use core::pin::Pin;
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

use crate::error::KernelError;
use crate::list::{Link, List};
use crate::sync::spin::Mutex as SpinMutex;
use crate::task::Tid;
use crate::task::percpu::{KernelTask, WakeQ};
use crate::uaccess::{get_user, put_user};

// Architecture-specific uaccess implementation
#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::uaccess::Aarch64Uaccess as Uaccess;
#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::uaccess::X86_64Uaccess as Uaccess;

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

/// A task waiting on a futex (Linux futex_q), pinned on the waiter's
/// stack and linked into its key's hash bucket
///
/// `lock_ptr` names the bucket the entry is on: set under that bucket's
/// lock (a requeue moves it under both buckets' locks), cleared by the
/// waker that dequeues it, as its last touch of the entry (Release), so
/// a waiter that sees it null (Acquire) was woken and may return. A
/// waiter that gives up (signal, timeout) dequeues itself wherever a
/// requeue put it (`unqueue`, Linux futex_unqueue); dropping the entry
/// does the same.
pub struct FutexQ {
    link: Link,
    /// Key of the futex it waits on (a requeue changes it, under the
    /// bucket locks; read under the lock of the bucket it is on)
    key: UnsafeCell<FutexKey>,
    /// The waiting task (alive while the entry is queued)
    task: *const KernelTask,
    /// Bitset for selective wake (FUTEX_WAIT_BITSET/FUTEX_WAKE_BITSET)
    bitset: u32,
    /// The bucket it is on; null once dequeued
    lock_ptr: AtomicPtr<FutexHashBucket>,
    _pin: PhantomPinned,
}

// SAFETY: the fields shared with wakers are used under the bucket lock
// or through atomics (see above)
unsafe impl Sync for FutexQ {}
unsafe impl Send for FutexQ {}

crate::adapter!(QAdapter, FutexQ, link);

impl FutexQ {
    /// An entry for the current task (not queued)
    pub fn new(key: FutexKey, bitset: u32) -> Self {
        Self {
            link: Link::new(),
            key: UnsafeCell::new(key),
            task: &*crate::task::percpu::current() as *const KernelTask,
            bitset,
            lock_ptr: AtomicPtr::new(core::ptr::null_mut()),
            _pin: PhantomPinned,
        }
    }

    /// Its key (under the lock of the bucket it is on)
    fn key(&self) -> FutexKey {
        // SAFETY: changed only under that lock (requeue)
        unsafe { *self.key.get() }
    }

    /// Still on a bucket (no waker dequeued it)
    fn queued(&self) -> bool {
        !self.lock_ptr.load(Ordering::Acquire).is_null()
    }

    /// Link it on `b` (its lock held: `list`; Linux futex_queue)
    fn queue(self: Pin<&Self>, b: &FutexHashBucket, list: &mut List<QAdapter>) {
        // SAFETY: pinned until it is unlinked (unqueue or a waker,
        // and Drop)
        unsafe { list.push_back(&*self) };
        self.lock_ptr.store(
            b as *const FutexHashBucket as *mut FutexHashBucket,
            Ordering::Relaxed,
        );
    }

    /// Take it off its bucket unless a waker did (Linux futex_unqueue):
    /// true if it was still queued. A requeue may move it meanwhile:
    /// the bucket is re-read under its lock.
    fn unqueue(&self) -> bool {
        loop {
            let b = self.lock_ptr.load(Ordering::Acquire);
            // SAFETY: buckets are static
            let Some(bucket) = (unsafe { b.as_ref() }) else {
                return false;
            };
            let mut list = bucket.waiters.lock();
            if self.lock_ptr.load(Ordering::Relaxed) != b {
                continue;
            }
            // SAFETY: on this bucket (lock_ptr, under its lock)
            unsafe { list.remove(self) };
            bucket.dec_waiters();
            self.lock_ptr
                .store(core::ptr::null_mut(), Ordering::Relaxed);
            return true;
        }
    }
}

impl Drop for FutexQ {
    fn drop(&mut self) {
        self.unqueue();
    }
}

/// Dequeue `q` from `b` for a wakeup (Linux futex_wake_mark): its task
/// goes on `wq` (a reference: the waiter may return at once), then
/// `lock_ptr` is cleared, the last touch of `q`
///
/// # Safety
/// `q` is on `b`, whose lock the caller holds (`list`).
unsafe fn wake_mark(b: &FutexHashBucket, list: &mut List<QAdapter>, q: &FutexQ, wq: &mut WakeQ) {
    // SAFETY: see above
    unsafe { list.remove(q) };
    b.dec_waiters();
    // SAFETY: the waiter is alive while its entry is queued
    wq.add(unsafe { &*q.task });
    q.lock_ptr.store(core::ptr::null_mut(), Ordering::Release);
}

/// Why a futex sleep ended
enum FutexSleep {
    /// Our queue entry was removed by a waker
    Woken,
    /// A signal is pending
    Signal,
    /// The deadline passed
    Timeout,
}

/// Current time on the futex timeout clock, in ns
fn futex_clock_ns(realtime: bool) -> u64 {
    use crate::time::{ClockId, TIMEKEEPER};
    let clock = if realtime {
        ClockId::Realtime
    } else {
        ClockId::Monotonic
    };
    let ts = TIMEKEEPER.read(clock, TIMEKEEPER.get_read_cycles());
    (ts.sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.nsec as u64)
}

/// Sleep interruptibly until `queued()` turns false (a waker dequeued us),
/// a signal arrives, or `deadline_ns` (on the given clock) passes
fn futex_sleep<F: Fn() -> bool>(queued: F, deadline_ns: Option<u64>, realtime: bool) -> FutexSleep {
    use crate::hrtimer::{HrClock, schedule_hrtimeout};
    use crate::task::percpu::{SleepState, set_current_state};
    let clock = if realtime {
        HrClock::Realtime
    } else {
        HrClock::Monotonic
    };
    let result = loop {
        set_current_state(SleepState::Interruptible);
        if !queued() {
            break FutexSleep::Woken;
        }
        if crate::waitqueue::signal_pending() {
            break FutexSleep::Signal;
        }
        if deadline_ns.is_some_and(|d| clock.now() >= d) {
            break FutexSleep::Timeout;
        }
        schedule_hrtimeout(deadline_ns, clock);
    };
    set_current_state(SleepState::Running);
    result
}

// =============================================================================
// Futex Hash Bucket
// =============================================================================

/// Hash bucket containing futex waiters (Linux futex_hash_bucket)
///
/// The waiter list is under a plain spin lock (futexes are used from
/// syscalls only; Linux hb->lock); wakeups go through a WakeQ after it
/// is dropped. The waiter_count provides a fast-path check to avoid
/// lock acquisition when there are no waiters.
pub struct FutexHashBucket {
    /// Queued entries (FIFO)
    waiters: SpinMutex<List<QAdapter>>,
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
            waiters: SpinMutex::new(List::new()),
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
// Robust Futex Support - uses Task.robust_list field via TASKLIST
// =============================================================================

use crate::task::percpu::TASKLIST;

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
    get_user::<Uaccess, u32>(addr).map_err(|_| KernelError::BadAddress.to_errno_neg())
}

/// Read a futex word under a bucket lock (Linux
/// futex_get_value_locked): page faults are disabled, so a page that is
/// not present fails instead of sleeping. Callers fault the word in
/// with `read_user_u32` before locking; if it is gone again by the time
/// it is read under the lock they report EAGAIN (userspace re-checks
/// and retries, as after a value change) instead of retrying in the
/// kernel like Linux.
fn get_value_locked(addr: u64) -> Result<u32, i32> {
    crate::uaccess::pagefault_disable();
    let r = get_user::<Uaccess, u32>(addr);
    crate::uaccess::pagefault_enable();
    r.map_err(|_| KernelError::WouldBlock.to_errno_neg())
}

/// Write a u32 to user memory
///
/// Uses proper uaccess infrastructure which:
/// - Validates address is in user space range
/// - Handles SMAP protection on x86_64
/// - Checks alignment
fn write_user_u32(addr: u64, val: u32) -> Result<(), i32> {
    put_user::<Uaccess, u32>(addr, val).map_err(|_| KernelError::BadAddress.to_errno_neg())
}

/// Read a u64 from user memory
///
/// Uses proper uaccess infrastructure which:
/// - Validates address is in user space range
/// - Handles SMAP protection on x86_64
/// - Checks alignment
fn read_user_u64(addr: u64) -> Result<u64, i32> {
    get_user::<Uaccess, u64>(addr).map_err(|_| KernelError::BadAddress.to_errno_neg())
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
        return Err(KernelError::InvalidArgument.to_errno_neg());
    }

    let ns = tv_sec.saturating_mul(1_000_000_000).saturating_add(tv_nsec);
    Ok(Some(ns))
}

// =============================================================================
// Core Futex Operations
// =============================================================================

/// The futex key of `uaddr` for the current process
fn make_key(uaddr: u64, is_private: bool) -> FutexKey {
    if is_private {
        FutexKey::private(uaddr, crate::task::percpu::current_pid())
    } else {
        // For shared futexes, we'd need physical address lookup
        // For now, treat as private with pid=0
        FutexKey::shared(uaddr)
    }
}

/// Wait on a futex
///
/// Blocks the current task until woken or the timeout expires.
/// Returns immediately with -EAGAIN if the value at uaddr doesn't match expected.
/// A waiter requeued to another futex keeps sleeping there.
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
/// * KernelError::TimedOut.to_errno_neg() if timeout expired
/// * -EINVAL if bitset is 0 or address is invalid
pub fn futex_wait(
    uaddr: u64,
    expected: u32,
    deadline_ns: Option<u64>,
    realtime: bool,
    bitset: u32,
    is_private: bool,
) -> i32 {
    // Validate bitset (0 is invalid per Linux ABI)
    if bitset == 0 {
        return KernelError::InvalidArgument.to_errno_neg();
    }

    let key = make_key(uaddr, is_private);
    let bucket = futex_bucket(&key);

    // Fault the word in (a real EFAULT is reported here); it is read
    // again under the bucket lock with faults disabled
    if let Err(e) = read_user_u32(uaddr) {
        return e;
    }

    let q = core::pin::pin!(FutexQ::new(key, bitset));
    if let Err(e) = queue_if(bucket, q.as_ref(), uaddr, expected) {
        return e;
    }

    let why = futex_sleep(|| q.queued(), deadline_ns, realtime);

    // Dequeue ourselves unless a waker already did
    if !q.unqueue() {
        return 0; // woken by futex_wake (possibly racing a signal/timeout)
    }
    match why {
        FutexSleep::Woken => 0,
        FutexSleep::Timeout => KernelError::TimedOut.to_errno_neg(),
        // Linux: -ERESTARTSYS without timeout; with one it restarts via
        // restart_block, approximated here by -EINTR (callers retry)
        FutexSleep::Signal if deadline_ns.is_none() => KernelError::RestartSys.to_errno_neg(),
        FutexSleep::Signal => KernelError::Interrupted.to_errno_neg(),
    }
}

/// Queue `q` on `bucket` if the futex word still holds `expected`
/// (Linux futex_wait_setup): the waiter count is raised before the
/// word is read, pairing with the waker's barrier (no lost wakeup)
fn queue_if(
    bucket: &FutexHashBucket,
    q: Pin<&FutexQ>,
    uaddr: u64,
    expected: u32,
) -> Result<(), i32> {
    bucket.inc_waiters();
    core::sync::atomic::fence(Ordering::SeqCst);
    let mut list = bucket.waiters.lock();
    let r = match get_value_locked(uaddr) {
        Ok(v) if v == expected => Ok(()),
        Ok(_) => Err(KernelError::WouldBlock.to_errno_neg()),
        Err(e) => Err(e),
    };
    match r {
        Ok(()) => q.queue(bucket, &mut list),
        Err(_) => bucket.dec_waiters(),
    }
    r
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
    if num_wake <= 0 {
        return 0;
    }

    if bitset == 0 {
        return KernelError::InvalidArgument.to_errno_neg();
    }

    let key = make_key(uaddr, is_private);
    let bucket = futex_bucket(&key);

    // Memory barrier paired with futex_wait's barrier
    core::sync::atomic::fence(Ordering::SeqCst);

    // Fast path: no waiters
    if !bucket.has_waiters() {
        return 0;
    }

    let mut woken = 0i32;
    let mut to_wake = WakeQ::new();
    {
        let mut list = bucket.waiters.lock();
        let mut cur = list.front();
        while let Some(p) = cur
            && woken < num_wake
        {
            // SAFETY: on the list; its next is read before it may go
            cur = unsafe { list.next(p) };
            // SAFETY: queued entries are live
            let q = unsafe { &*p };
            if q.key() == key && q.bitset & bitset != 0 {
                // SAFETY: on this bucket, locked
                unsafe { wake_mark(bucket, &mut list, q, &mut to_wake) };
                woken += 1;
            }
        }
    }

    // Wake tasks outside the bucket lock
    to_wake.wake_up();

    woken
}

/// Requeue waiters from one futex to another
///
/// Wakes up to nr_wake waiters on uaddr, then moves up to nr_requeue
/// waiters from uaddr to uaddr2 (they keep sleeping, now on uaddr2).
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
    if nr_wake < 0 || nr_requeue < 0 {
        return KernelError::InvalidArgument.to_errno_neg();
    }

    let key1 = make_key(uaddr, is_private);
    let key2 = make_key(uaddr2, is_private);
    let b1 = futex_bucket(&key1);
    let b2 = futex_bucket(&key2);

    // CMP_REQUEUE: fault the word in before locking
    if cmpval.is_some()
        && let Err(e) = read_user_u32(uaddr)
    {
        return e;
    }

    // Both buckets locked, in address order (Linux double_lock_hb), so a
    // requeued entry is always on the bucket its lock_ptr names
    let mut to_wake = WakeQ::new();
    let r = if core::ptr::eq(b1, b2) {
        let mut l = b1.waiters.lock();
        let op = Requeue {
            key1,
            key2,
            nr_wake,
            nr_requeue,
            cmp: cmpval.map(|v| (uaddr, v)),
        };
        op.run(b1, &mut l, b2, None, &mut to_wake)
    } else {
        let (first, second) = if (b1 as *const FutexHashBucket) < (b2 as *const _) {
            (b1, b2)
        } else {
            (b2, b1)
        };
        let mut g1 = first.waiters.lock();
        let mut g2 = second.waiters.lock();
        let (l1, l2) = if core::ptr::eq(first, b1) {
            (&mut *g1, &mut *g2)
        } else {
            (&mut *g2, &mut *g1)
        };
        let op = Requeue {
            key1,
            key2,
            nr_wake,
            nr_requeue,
            cmp: cmpval.map(|v| (uaddr, v)),
        };
        op.run(b1, l1, b2, Some(l2), &mut to_wake)
    };

    // Wake collected tasks (bucket locks dropped)
    to_wake.wake_up();
    r
}

/// One requeue under the bucket locks (Linux futex_requeue's loop)
struct Requeue {
    key1: FutexKey,
    key2: FutexKey,
    nr_wake: i32,
    nr_requeue: i32,
    /// CMP_REQUEUE: (uaddr, expected value)
    cmp: Option<(u64, u32)>,
}

impl Requeue {
    /// `l2` is None when both keys hash to `b1`
    fn run(
        &self,
        b1: &FutexHashBucket,
        l1: &mut List<QAdapter>,
        b2: &FutexHashBucket,
        mut l2: Option<&mut List<QAdapter>>,
        wq: &mut WakeQ,
    ) -> i32 {
        if let Some((uaddr, expected)) = self.cmp {
            match get_value_locked(uaddr) {
                Ok(v) if v == expected => {}
                Ok(_) => return KernelError::WouldBlock.to_errno_neg(),
                Err(e) => return e,
            }
        }
        let (mut woken, mut requeued) = (0i32, 0i32);
        let mut cur = l1.front();
        while let Some(p) = cur {
            // SAFETY: on the list; its next is read before it may move
            cur = unsafe { l1.next(p) };
            // SAFETY: queued entries are live
            let q = unsafe { &*p };
            if q.key() != self.key1 {
                continue;
            }
            if woken < self.nr_wake {
                // SAFETY: on b1, locked
                unsafe { wake_mark(b1, l1, q, wq) };
                woken += 1;
            } else if requeued < self.nr_requeue {
                // SAFETY: both buckets are locked (Linux requeue_futex)
                unsafe { *q.key.get() = self.key2 };
                if let Some(l2) = l2.as_deref_mut() {
                    // SAFETY: on b1; moved to b2, both locked
                    unsafe {
                        l1.remove(q);
                        l2.push_back(q);
                    }
                    b1.dec_waiters();
                    b2.inc_waiters();
                    q.lock_ptr.store(
                        b2 as *const FutexHashBucket as *mut FutexHashBucket,
                        Ordering::Release,
                    );
                }
                requeued += 1;
            } else {
                break;
            }
        }
        woken + requeued
    }
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
        return KernelError::InvalidArgument.to_errno_neg();
    }

    let tid = crate::task::percpu::current_tid();

    let mut table = TASKLIST.write();
    if let Some(mut task) = table.get_mut(tid) {
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
            return KernelError::NoProcess.to_errno_neg();
        }
        pid as Tid
    };

    let head = TASKLIST
        .read()
        .get(target_tid)
        .map(|t| t.robust_list)
        .unwrap_or(0);

    // Write head pointer to user memory
    if head_ptr != 0 && put_user::<Uaccess, u64>(head_ptr, head).is_err() {
        return KernelError::BadAddress.to_errno_neg();
    }

    // Write length to user memory
    if len_ptr != 0 && put_user::<Uaccess, u64>(len_ptr, RobustListHead::SIZE as u64).is_err() {
        return KernelError::BadAddress.to_errno_neg();
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
        let mut table = TASKLIST.write();
        if let Some(mut task) = table.get_mut(tid) {
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
    let use_realtime = (futex_op & FUTEX_CLOCK_REALTIME) != 0;

    match op {
        FUTEX_WAIT => {
            // Relative timeout, always on CLOCK_MONOTONIC
            let timeout = match read_user_timeout(timeout_or_val2) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let deadline = timeout.map(|ns| futex_clock_ns(false).saturating_add(ns));
            futex_wait(
                uaddr,
                val,
                deadline,
                false,
                FUTEX_BITSET_MATCH_ANY,
                is_private,
            )
        }

        FUTEX_WAKE => futex_wake(uaddr, val as i32, FUTEX_BITSET_MATCH_ANY, is_private),

        FUTEX_WAIT_BITSET => {
            if val3 == 0 {
                return KernelError::InvalidArgument.to_errno_neg();
            }
            // Absolute timeout on CLOCK_MONOTONIC (or REALTIME if flagged)
            let deadline = match read_user_timeout(timeout_or_val2) {
                Ok(t) => t,
                Err(e) => return e,
            };
            futex_wait(uaddr, val, deadline, use_realtime, val3, is_private)
        }

        FUTEX_WAKE_BITSET => {
            if val3 == 0 {
                return KernelError::InvalidArgument.to_errno_neg();
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

        _ => KernelError::NotImplemented.to_errno_neg(),
    }
}

// =============================================================================
// Futex Waitv (Linux 5.16+)
// =============================================================================

/// Maximum number of futexes in a single futex_waitv call
const FUTEX_WAITV_MAX: usize = 128;

/// FUTEX2 size flags
mod futex2 {
    #![allow(dead_code)]
    pub const SIZE_U8: u32 = 0x00;
    pub const SIZE_U16: u32 = 0x01;
    pub const SIZE_U32: u32 = 0x02;
    pub const SIZE_U64: u32 = 0x03;
    pub const SIZE_MASK: u32 = 0x03;
    pub const NUMA: u32 = 0x04;
    pub const PRIVATE: u32 = 128;
    /// Valid mask for futex2 flags (size + private only for now)
    pub const VALID_MASK: u32 = SIZE_MASK | PRIVATE;
}

/// struct futex_waitv from userspace
#[repr(C)]
#[derive(Clone, Copy)]
struct UserFutexWaitv {
    val: u64,
    uaddr: u64,
    flags: u32,
    __reserved: u32,
}

/// Kernel-side futex_waitv entry with additional tracking state
struct FutexWaitvEntry {
    /// Expected value
    val: u32,
    /// User address
    uaddr: u64,
    /// Is this a private futex?
    is_private: bool,
}

/// Linux futex_waitv syscall entry point
///
/// Wait on multiple futexes simultaneously. Returns when any futex is woken,
/// the timeout expires, or a signal is received.
///
/// # Arguments
/// * `waiters_ptr` - Pointer to array of struct futex_waitv
/// * `nr_futexes` - Number of futexes in array (1-128)
/// * `flags` - Syscall flags (must be 0)
/// * `timeout_ptr` - Optional pointer to struct timespec (absolute timeout)
/// * `clockid` - Clock for timeout (CLOCK_MONOTONIC or CLOCK_REALTIME)
///
/// # Returns
/// * >= 0: Index of woken futex (hint - others may also be woken)
/// * -EINVAL: Invalid arguments
/// * -EFAULT: Bad memory access
/// * KernelError::TimedOut.to_errno_neg(): Timeout expired
/// * -EAGAIN/-EWOULDBLOCK: Value mismatch at setup
pub fn sys_futex_waitv(
    waiters_ptr: u64,
    nr_futexes: u32,
    flags: u32,
    timeout_ptr: u64,
    clockid: i32,
) -> i32 {
    // Syscall flags must be 0
    if flags != 0 {
        return KernelError::InvalidArgument.to_errno_neg();
    }

    // Validate nr_futexes is in range [1, 128]
    if nr_futexes == 0 || nr_futexes as usize > FUTEX_WAITV_MAX {
        return KernelError::InvalidArgument.to_errno_neg();
    }

    // Validate waiters pointer
    if waiters_ptr == 0 {
        return KernelError::InvalidArgument.to_errno_neg();
    }

    // Validate clockid
    const CLOCK_REALTIME: i32 = 0;
    const CLOCK_MONOTONIC: i32 = 1;
    if clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC {
        return KernelError::InvalidArgument.to_errno_neg();
    }
    let use_realtime = clockid == CLOCK_REALTIME;

    // Parse timeout (absolute time)
    let timeout_ns = if timeout_ptr != 0 {
        match read_user_timeout(timeout_ptr) {
            Ok(Some(ns)) => Some(ns),
            Ok(None) => None,
            Err(e) => return e,
        }
    } else {
        None
    };

    // Copy and validate waiters from userspace
    let mut entries: Vec<FutexWaitvEntry> = Vec::with_capacity(nr_futexes as usize);
    let entry_size = core::mem::size_of::<UserFutexWaitv>() as u64;

    for i in 0..nr_futexes {
        let entry_ptr = waiters_ptr + (i as u64) * entry_size;

        // Read the futex_waitv struct from userspace
        let val = match read_user_u64(entry_ptr) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let uaddr = match read_user_u64(entry_ptr + 8) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let flags_field = match read_user_u32(entry_ptr + 16) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let reserved = match read_user_u32(entry_ptr + 20) {
            Ok(v) => v,
            Err(e) => return e,
        };

        // Reserved field must be 0
        if reserved != 0 {
            return KernelError::InvalidArgument.to_errno_neg();
        }

        // Validate flags - only support SIZE_U32 and PRIVATE for now
        if (flags_field & !futex2::VALID_MASK) != 0 {
            return KernelError::InvalidArgument.to_errno_neg();
        }

        // Check size - only support 32-bit futexes
        let size = flags_field & futex2::SIZE_MASK;
        if size != futex2::SIZE_U32 {
            return KernelError::InvalidArgument.to_errno_neg();
        }

        // Check alignment (must be 4-byte aligned for u32)
        if uaddr % 4 != 0 {
            return KernelError::InvalidArgument.to_errno_neg();
        }

        let is_private = (flags_field & futex2::PRIVATE) != 0;

        entries.push(FutexWaitvEntry {
            val: val as u32,
            uaddr,
            is_private,
        });
    }

    // Call the main wait logic
    futex_wait_multiple(&entries, timeout_ns, use_realtime)
}

/// Wait on multiple futexes - returns index of woken futex or error
///
/// Linux futex_wait_multiple: queue an entry on every futex whose word
/// still holds its value, sleep until a waker dequeues one (or a signal
/// or the deadline), then dequeue the rest. The entries live in one
/// boxed slice, never moved while queued (dropping it dequeues them).
fn futex_wait_multiple(
    entries: &[FutexWaitvEntry],
    timeout_ns: Option<u64>,
    use_realtime: bool,
) -> i32 {
    // Fault every word in (a real EFAULT is reported here); they are
    // read again under the bucket locks with faults disabled
    for entry in entries {
        if let Err(e) = read_user_u32(entry.uaddr) {
            return e;
        }
    }

    loop {
        let qs: alloc::boxed::Box<[FutexQ]> = entries
            .iter()
            .map(|e| {
                FutexQ::new(
                    make_key(e.uaddr, e.is_private),
                    futex_op::FUTEX_BITSET_MATCH_ANY,
                )
            })
            .collect();
        // SAFETY: the slice is not moved until dropped (Drop dequeues)
        let pinned = |i: usize| unsafe { Pin::new_unchecked(&qs[i]) };

        // Queue on each futex in turn; a value mismatch or fault drops
        // `qs`, dequeuing those already queued
        for (i, e) in entries.iter().enumerate() {
            let bucket = futex_bucket(&qs[i].key());
            if let Err(err) = queue_if(bucket, pinned(i), e.uaddr, e.val) {
                return err;
            }
        }

        let why = futex_sleep(|| qs.iter().all(|q| q.queued()), timeout_ns, use_realtime);

        // Dequeue from the futexes nobody woke us from; the first one a
        // waker dequeued is the result
        let mut woken_index: i32 = -1;
        for (i, q) in qs.iter().enumerate() {
            if !q.unqueue() && woken_index < 0 {
                woken_index = i as i32;
            }
        }

        if woken_index >= 0 {
            return woken_index;
        }
        match why {
            FutexSleep::Timeout => return KernelError::TimedOut.to_errno_neg(),
            FutexSleep::Signal => return KernelError::RestartSys.to_errno_neg(),
            FutexSleep::Woken => {}
        }
    }
}

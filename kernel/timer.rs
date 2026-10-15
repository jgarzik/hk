//! Software timer callback infrastructure
//!
//! Provides a mechanism for scheduling callbacks to be executed after a delay.
//! This is used by timerfd and other kernel components that need timer services.
//!
//! ## Architecture
//!
//! Timers are stored in a global list sorted by expiration time. The timer
//! interrupt (CPU 0) calls `check_timers()`, which only notices that the
//! earliest timer expired and wakes the `ktimerd` kernel thread; callbacks
//! run there, in process context (they may take sleeping locks, allocate,
//! send signals). Before `ktimerd` starts, expired timers simply wait.
//!
//! Locking: `TIMERS` is an `IrqSpinlock` (leaf; IRQ-reachable). Callbacks
//! run with no timer lock held.
//!
//! ## Usage
//!
//! ```ignore
//! // Create a timer
//! let handle = timer_add(expires_ns, 0, callback_fn, 0);
//!
//! // Later, cancel it
//! timer_del(handle);
//! ```

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::arch::IrqSpinlock;
use crate::time::{ClockId, TIMEKEEPER};

/// Timer handle for referencing a registered timer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerHandle(u64);

impl TimerHandle {
    /// Invalid/null timer handle
    pub const NULL: Self = Self(0);

    /// Check if handle is valid
    pub fn is_valid(&self) -> bool {
        self.0 != 0
    }
}

/// Next timer handle ID
static NEXT_TIMER_ID: AtomicU64 = AtomicU64::new(1);

/// Timer callback function type
///
/// The callback receives the timer's data field, which can be used
/// to pass context (e.g., a pointer cast to u64).
pub type TimerCallback = fn(data: u64);

/// A registered software timer
pub struct Timer {
    /// Unique timer handle for identification
    pub handle: TimerHandle,
    /// Absolute expiration time in nanoseconds (monotonic clock)
    pub expires_ns: u64,
    /// Interval for periodic timers (0 = one-shot)
    pub interval_ns: u64,
    /// Callback function to invoke on expiration
    pub callback: TimerCallback,
    /// Opaque user data passed to callback
    pub data: u64,
}

impl Timer {
    /// Create a new timer
    pub fn new(expires_ns: u64, interval_ns: u64, callback: TimerCallback, data: u64) -> Self {
        let id = NEXT_TIMER_ID.fetch_add(1, Ordering::Relaxed);
        Self {
            handle: TimerHandle(id),
            expires_ns,
            interval_ns,
            callback,
            data,
        }
    }
}

/// Global timer list (sorted by expiration time)
static TIMERS: IrqSpinlock<Vec<Timer>> = IrqSpinlock::new(Vec::new());

/// Get current monotonic time in nanoseconds
fn now_ns() -> u64 {
    let ts = TIMEKEEPER.read(ClockId::Monotonic, TIMEKEEPER.get_read_cycles());
    ts.sec as u64 * 1_000_000_000 + ts.nsec as u64
}

/// Add a new timer
///
/// # Arguments
/// * `expires_ns` - Absolute expiration time in nanoseconds (monotonic)
/// * `interval_ns` - Repeat interval (0 for one-shot)
/// * `callback` - Function to call on expiration
/// * `data` - Opaque data passed to callback
///
/// # Returns
/// Handle that can be used to cancel the timer
pub fn timer_add(
    expires_ns: u64,
    interval_ns: u64,
    callback: TimerCallback,
    data: u64,
) -> TimerHandle {
    let timer = Timer::new(expires_ns, interval_ns, callback, data);
    let handle = timer.handle;

    let mut timers = TIMERS.lock();

    // Insert in sorted order (by expiration time)
    let pos = timers
        .iter()
        .position(|t| t.expires_ns > expires_ns)
        .unwrap_or(timers.len());
    timers.insert(pos, timer);

    handle
}

/// Add a relative timer (expires after delay_ns nanoseconds)
///
/// # Arguments
/// * `delay_ns` - Delay from now in nanoseconds
/// * `interval_ns` - Repeat interval (0 for one-shot)
/// * `callback` - Function to call on expiration
/// * `data` - Opaque data passed to callback
///
/// # Returns
/// Handle that can be used to cancel the timer
pub fn timer_add_relative(
    delay_ns: u64,
    interval_ns: u64,
    callback: TimerCallback,
    data: u64,
) -> TimerHandle {
    let expires_ns = crate::time::deadline_after(now_ns(), delay_ns);
    timer_add(expires_ns, interval_ns, callback, data)
}

/// Delete/cancel a timer
///
/// # Arguments
/// * `handle` - Timer handle from timer_add
///
/// # Returns
/// `true` if timer was found and removed, `false` otherwise
pub fn timer_del(handle: TimerHandle) -> bool {
    if !handle.is_valid() {
        return false;
    }

    let mut timers = TIMERS.lock();
    if let Some(pos) = timers.iter().position(|t| t.handle == handle) {
        timers.remove(pos);
        true
    } else {
        false
    }
}

/// Modify an existing timer's expiration time
///
/// # Arguments
/// * `handle` - Timer handle from timer_add
/// * `expires_ns` - New absolute expiration time
/// * `interval_ns` - New interval (0 for one-shot)
///
/// # Returns
/// `true` if timer was found and modified, `false` otherwise
pub fn timer_mod(handle: TimerHandle, expires_ns: u64, interval_ns: u64) -> bool {
    if !handle.is_valid() {
        return false;
    }

    let mut timers = TIMERS.lock();

    // Find and remove the timer
    let timer_opt = timers
        .iter()
        .position(|t| t.handle == handle)
        .map(|pos| timers.remove(pos));

    if let Some(mut timer) = timer_opt {
        // Update expiration and interval
        timer.expires_ns = expires_ns;
        timer.interval_ns = interval_ns;

        // Re-insert in sorted order
        let pos = timers
            .iter()
            .position(|t| t.expires_ns > expires_ns)
            .unwrap_or(timers.len());
        timers.insert(pos, timer);
        true
    } else {
        false
    }
}

/// Wait queue `ktimerd` sleeps on
static KTIMERD_WQ: crate::waitqueue::WaitQueue = crate::waitqueue::WaitQueue::new();

/// Set once `ktimerd` runs (IRQ-side wakeups are pointless before)
static KTIMERD_RUNNING: AtomicBool = AtomicBool::new(false);

/// True if the earliest timer has expired
fn earliest_expired() -> bool {
    let now = now_ns();
    TIMERS.lock().first().is_some_and(|t| t.expires_ns <= now)
}

/// Timer tick hook (IRQ context, CPU 0): wake `ktimerd` if a timer expired
pub fn check_timers() {
    if !TIMEKEEPER.is_initialized() || !KTIMERD_RUNNING.load(Ordering::Acquire) {
        return;
    }
    if earliest_expired() {
        KTIMERD_WQ.wake_one();
    }
}

/// Bound on callbacks per pass; ktimerd loops (it is still woken) if more
/// timers are due
const MAX_FIRE_PER_RUN: usize = 256;

/// Fire all expired timers (process context)
fn run_expired_timers() {
    let current_ns = now_ns();

    // Collect expired timers; periodic ones are re-armed past `current_ns`
    // (catching up missed periods) and re-inserted in order. Intervals are
    // user-controlled: a re-arm that overflows or reaches KTIME_MAX disarms
    // the timer (it would never fire again anyway), and each firing moves
    // the timer strictly past `current_ns`, so this loop always ends.
    let expired: Vec<(TimerCallback, u64)> = {
        let mut timers = TIMERS.lock();
        let mut fired = Vec::new();
        while fired.len() < MAX_FIRE_PER_RUN
            && timers.first().is_some_and(|t| t.expires_ns <= current_ns)
        {
            let mut timer = timers.remove(0);
            fired.push((timer.callback, timer.data));
            let late = current_ns - timer.expires_ns;
            let next = late
                .checked_div(timer.interval_ns)
                .and_then(|missed| (missed + 1).checked_mul(timer.interval_ns))
                .and_then(|step| timer.expires_ns.checked_add(step))
                .filter(|&next| next > current_ns && next < crate::time::KTIME_MAX);
            if let Some(next) = next {
                timer.expires_ns = next;
                let pos = timers.partition_point(|t| t.expires_ns <= next);
                timers.insert(pos, timer);
            }
        }
        fired
    };

    for (callback, data) in expired {
        callback(data);
    }
}

/// `ktimerd`: runs expired timer callbacks in process context
fn ktimerd(_arg: usize) {
    loop {
        KTIMERD_WQ.wait_event(earliest_expired);
        run_expired_timers();
    }
}

/// Start `ktimerd` on CPU 0 (where the timer tick checks timers)
pub fn start_ktimerd() {
    match crate::task::kthread::kthread_run_prio(
        "ktimerd",
        ktimerd,
        0,
        Some(0),
        crate::task::PRIORITY_HIGH,
    ) {
        Ok(_) => KTIMERD_RUNNING.store(true, Ordering::Release),
        Err(e) => crate::printkln!("timer: cannot start ktimerd: {:?}", e),
    }
}

/// Get the time until the next timer expires (in nanoseconds)
///
/// Returns `None` if no timers are pending.
pub fn time_until_next() -> Option<u64> {
    let timers = TIMERS.lock();
    if timers.is_empty() {
        return None;
    }

    let current_ns = now_ns();
    let next_expires = timers[0].expires_ns;

    if next_expires <= current_ns {
        Some(0) // Already expired
    } else {
        Some(next_expires - current_ns)
    }
}

/// Get the number of pending timers
pub fn timer_count() -> usize {
    TIMERS.lock().len()
}

/// A one-shot timer that tracks its earliest wanted deadline (for
/// subsystems that keep their own per-object deadlines and need one
/// kernel timer: neighbour tables, IP reassembly).
///
/// The callback must call [`Alarm::fired`] before it scans its state and
/// then re-arm for the earliest remaining deadline, so a deadline set
/// concurrently is never lost. Locking: `st` is a `crate::sync::spin::Mutex` taken
/// in thread context only and held across `timer_add/timer_del` (-> the
/// `TIMERS` IrqSpinlock).
pub struct Alarm {
    st: crate::sync::spin::Mutex<(TimerHandle, u64)>,
    cb: TimerCallback,
}

impl Alarm {
    pub const fn new(cb: TimerCallback) -> Self {
        Self {
            st: crate::sync::spin::Mutex::new((TimerHandle::NULL, u64::MAX)),
            cb,
        }
    }

    /// Fire no later than `at_ns` (monotonic)
    pub fn arm(&self, at_ns: u64) {
        let mut s = self.st.lock();
        if s.0.is_valid() && s.1 <= at_ns {
            return;
        }
        if s.0.is_valid() {
            timer_del(s.0);
        }
        *s = (timer_add(at_ns, 0, self.cb, 0), at_ns);
    }

    /// The timer ran (call first thing in the callback)
    pub fn fired(&self) {
        *self.st.lock() = (TimerHandle::NULL, u64::MAX);
    }
}

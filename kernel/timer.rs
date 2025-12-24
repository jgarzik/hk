//! Software timer callback infrastructure
//!
//! Provides a mechanism for scheduling callbacks to be executed after a delay.
//! This is used by timerfd and other kernel components that need timer services.
//!
//! ## Architecture
//!
//! Timers are stored in a global list sorted by expiration time. The timer
//! interrupt handler calls `check_timers()` which fires any expired callbacks.
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
use core::sync::atomic::{AtomicU64, Ordering};

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
    let expires_ns = now_ns() + delay_ns;
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

/// Check and fire expired timers
///
/// Should be called from the timer interrupt handler.
/// Fires callbacks for all expired timers.
pub fn check_timers() {
    if !TIMEKEEPER.is_initialized() {
        return;
    }

    let current_ns = now_ns();

    // Collect expired timers (can't call callbacks while holding lock)
    let expired: Vec<(TimerCallback, u64, u64, TimerHandle)> = {
        let mut timers = TIMERS.lock();

        let mut expired_list = Vec::new();
        let mut to_remove = Vec::new();
        let mut to_reschedule = Vec::new();

        for (idx, timer) in timers.iter().enumerate() {
            if timer.expires_ns <= current_ns {
                expired_list.push((timer.callback, timer.data, timer.interval_ns, timer.handle));
                if timer.interval_ns > 0 {
                    // Periodic timer - will be rescheduled
                    to_reschedule.push((idx, timer.expires_ns + timer.interval_ns));
                } else {
                    // One-shot timer - remove it
                    to_remove.push(idx);
                }
            } else {
                // List is sorted, no more expired timers
                break;
            }
        }

        // Remove one-shot timers (in reverse order to maintain indices)
        for idx in to_remove.into_iter().rev() {
            timers.remove(idx);
        }

        // Reschedule periodic timers
        for (idx, new_expires) in to_reschedule {
            if idx < timers.len() {
                timers[idx].expires_ns = new_expires;
            }
        }

        // Re-sort the list if we rescheduled any timers
        timers.sort_by_key(|t| t.expires_ns);

        expired_list
    };

    // Fire callbacks (outside of lock)
    for (callback, data, _interval, _handle) in expired {
        callback(data);
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

//! POSIX interval timer implementation
//!
//! Provides POSIX timer APIs compatible with Linux timer_create/timer_settime/etc.
//!
//! ## Architecture
//!
//! ```text
//! User Process
//!     |
//!     v
//! timer_create(clockid, sigevent, &timer_id) -> Allocates per-process timer
//!     |
//!     v
//! timer_settime(timer_id, ...) -> Arms timer via kernel/timer.rs
//!     |
//!     v
//! Timer expires -> Callback sends signal (or no-op for SIGEV_NONE)
//! ```
//!
//! ## Key Features
//!
//! - Per-process timer IDs (0, 1, 2, ...)
//! - Signal notification (SIGEV_SIGNAL, SIGEV_NONE)
//! - Overrun counting for missed expirations
//! - One-shot and periodic timers

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::IrqSpinlock;
use crate::signal::{SIGALRM, send_signal};
use crate::task::Tid;
use crate::time::{ClockId, TIMEKEEPER};
use crate::time_syscall::CLOCK_REALTIME;
use crate::timer::{TimerHandle, timer_add, timer_del};
use crate::timerfd::ITimerSpec;

/// POSIX timer notification types (matches Linux)
pub mod sigev_notify {
    /// Notify via signal (default)
    pub const SIGEV_SIGNAL: i32 = 0;
    /// No notification
    pub const SIGEV_NONE: i32 = 1;
    /// Notify via thread (not supported)
    pub const SIGEV_THREAD: i32 = 2;
    /// Signal specific thread
    pub const SIGEV_THREAD_ID: i32 = 4;
}

/// timer_settime flags
pub mod timer_flags {
    /// Use absolute time
    pub const TIMER_ABSTIME: i32 = 1;
}

/// union sigval (Linux ABI compatible)
#[repr(C)]
#[derive(Clone, Copy)]
pub union SigVal {
    /// Integer value
    pub sival_int: i32,
    /// Pointer value (as u64)
    pub sival_ptr: u64,
}

impl Default for SigVal {
    fn default() -> Self {
        Self { sival_int: 0 }
    }
}

/// struct sigevent (Linux ABI compatible)
///
/// Note: Linux sigevent is 64 bytes with padding. We use the minimal
/// fields needed for timer notification.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SigEvent {
    /// Data passed with notification
    pub sigev_value: SigVal,
    /// Signal number (for SIGEV_SIGNAL)
    pub sigev_signo: i32,
    /// Notification method (SIGEV_SIGNAL, SIGEV_NONE, etc.)
    pub sigev_notify: i32,
    /// Thread ID for SIGEV_THREAD_ID (union with sigev_notify_function/attributes)
    pub sigev_notify_thread_id: i32,
    /// Padding to match Linux sigevent size (64 bytes)
    pub _pad: [i32; 11],
}

impl Default for SigEvent {
    fn default() -> Self {
        Self {
            sigev_value: SigVal::default(),
            sigev_signo: SIGALRM as i32,
            sigev_notify: sigev_notify::SIGEV_SIGNAL,
            sigev_notify_thread_id: 0,
            _pad: [0; 11],
        }
    }
}

/// timer_t type (opaque timer ID)
pub type TimerT = i32;

/// Internal POSIX timer state
struct PosixTimerInner {
    /// Next expiration time (absolute monotonic ns, 0 if disarmed)
    expires_ns: u64,
    /// Interval for periodic timers (0 = one-shot)
    interval_ns: u64,
    /// Handle to the timer in the timer subsystem
    timer_handle: TimerHandle,
    /// Overrun count (expirations since last signal delivery)
    overrun: i32,
    /// Whether timer is currently armed
    armed: bool,
}

impl PosixTimerInner {
    fn new() -> Self {
        Self {
            expires_ns: 0,
            interval_ns: 0,
            timer_handle: TimerHandle::NULL,
            overrun: 0,
            armed: false,
        }
    }
}

/// POSIX timer structure
pub struct PosixTimer {
    /// Unique timer ID within the process
    timer_id: TimerT,
    /// Clock ID (CLOCK_REALTIME or CLOCK_MONOTONIC)
    clockid: i32,
    /// Owning task's TID (for signal delivery)
    owner_tid: Tid,
    /// Notification settings
    sigevent: SigEvent,
    /// Inner state protected by IRQ spinlock
    inner: IrqSpinlock<PosixTimerInner>,
    /// Unique global ID for callback lookup
    global_id: u64,
}

/// Global counter for POSIX timer IDs
static NEXT_POSIX_TIMER_ID: AtomicU64 = AtomicU64::new(1);

/// Global registry mapping global_id -> weak ref to timer
/// This allows the timer callback to find the timer
static POSIX_TIMER_REGISTRY: IrqSpinlock<Vec<(u64, Tid, TimerT)>> = IrqSpinlock::new(Vec::new());

impl PosixTimer {
    /// Create a new POSIX timer
    fn new(timer_id: TimerT, clockid: i32, owner_tid: Tid, sigevent: SigEvent) -> Arc<Self> {
        let global_id = NEXT_POSIX_TIMER_ID.fetch_add(1, Ordering::Relaxed);
        let timer = Arc::new(Self {
            timer_id,
            clockid,
            owner_tid,
            sigevent,
            inner: IrqSpinlock::new(PosixTimerInner::new()),
            global_id,
        });

        // Register in global registry for callback lookup
        POSIX_TIMER_REGISTRY
            .lock()
            .push((global_id, owner_tid, timer_id));

        timer
    }

    /// Get current monotonic time in nanoseconds
    fn now_ns() -> u64 {
        let ts = TIMEKEEPER.read(ClockId::Monotonic, TIMEKEEPER.get_read_cycles());
        ts.sec as u64 * 1_000_000_000 + ts.nsec as u64
    }

    /// Arm the timer
    ///
    /// # Arguments
    /// * `new_value` - New timer specification
    /// * `flags` - TIMER_ABSTIME for absolute time
    ///
    /// # Returns
    /// Previous timer value
    pub fn settime(self: &Arc<Self>, new_value: &ITimerSpec, flags: i32) -> ITimerSpec {
        let mut inner = self.inner.lock();

        // Save old value
        let old_value = self.get_current_value_locked(&inner);

        // Cancel existing timer if any
        if inner.timer_handle.is_valid() {
            timer_del(inner.timer_handle);
            inner.timer_handle = TimerHandle::NULL;
        }

        // Reset overrun count on re-arm
        inner.overrun = 0;

        // Check if disarming
        if new_value.is_disarmed() {
            inner.expires_ns = 0;
            inner.interval_ns = 0;
            inner.armed = false;
            return old_value;
        }

        // Calculate expiration time
        let value_ns = new_value.value_to_ns();
        inner.interval_ns = new_value.interval_to_ns();

        let expires_ns = if flags & timer_flags::TIMER_ABSTIME != 0 {
            // Absolute time
            if self.clockid == CLOCK_REALTIME {
                // CLOCK_REALTIME - need to convert to monotonic
                // For simplicity, we assume realtime ~= monotonic + offset
                // A proper implementation would handle clock jumps
                value_ns
            } else {
                // CLOCK_MONOTONIC - use directly
                value_ns
            }
        } else {
            // Relative time (saturates: a huge value never fires)
            crate::time::deadline_after(Self::now_ns(), value_ns)
        };

        inner.expires_ns = expires_ns;
        inner.armed = true;

        // Register timer callback using global_id for lookup
        inner.timer_handle = timer_add(
            expires_ns,
            inner.interval_ns,
            posix_timer_callback,
            self.global_id,
        );

        old_value
    }

    /// Get current timer value
    pub fn gettime(&self) -> ITimerSpec {
        let inner = self.inner.lock();
        self.get_current_value_locked(&inner)
    }

    /// Get current value while holding the lock
    fn get_current_value_locked(&self, inner: &PosixTimerInner) -> ITimerSpec {
        if !inner.armed || inner.expires_ns == 0 {
            return ITimerSpec::default();
        }

        let now = Self::now_ns();
        let remaining = inner.expires_ns.saturating_sub(now);

        ITimerSpec::from_ns(remaining, inner.interval_ns)
    }

    /// Get and reset overrun count
    pub fn getoverrun(&self) -> i32 {
        let inner = self.inner.lock();
        inner.overrun
    }

    /// Called when timer expires (from timer callback)
    fn on_expire(&self) {
        let should_signal;
        {
            let mut inner = self.inner.lock();

            // For periodic timers, the timer infrastructure handles rescheduling
            // For one-shot, mark as disarmed
            if inner.interval_ns == 0 {
                inner.armed = false;
                inner.expires_ns = 0;
            } else {
                // Update expires_ns for gettime accuracy
                inner.expires_ns = Self::now_ns() + inner.interval_ns;
            }

            // Determine notification action
            should_signal = self.sigevent.sigev_notify == sigev_notify::SIGEV_SIGNAL;

            // Increment overrun count (will be reset on getoverrun)
            // In Linux, this counts missed deliveries while signal is pending
            // For simplicity, we just track total expirations
            if inner.overrun < i32::MAX {
                inner.overrun = inner.overrun.saturating_add(1);
            }
        }

        // Send signal if configured
        if should_signal {
            let sig = self.sigevent.sigev_signo as u32;
            if sig > 0 && sig <= 64 {
                send_signal(self.owner_tid, sig);
            }
        }
    }

    /// Delete the timer (cancel and cleanup)
    fn delete(&self) {
        // Cancel timer
        {
            let mut inner = self.inner.lock();
            if inner.timer_handle.is_valid() {
                timer_del(inner.timer_handle);
                inner.timer_handle = TimerHandle::NULL;
            }
            inner.armed = false;
        }

        // Remove from global registry
        let mut registry = POSIX_TIMER_REGISTRY.lock();
        registry.retain(|(id, _, _)| *id != self.global_id);
    }
}

impl Drop for PosixTimer {
    fn drop(&mut self) {
        // Cancel timer on drop
        let inner = self.inner.lock();
        if inner.timer_handle.is_valid() {
            timer_del(inner.timer_handle);
        }
    }
}

/// Timer callback - finds the timer and calls on_expire
fn posix_timer_callback(data: u64) {
    // Look up timer by global_id in registry
    let (owner_tid, timer_id) = {
        let registry = POSIX_TIMER_REGISTRY.lock();
        registry
            .iter()
            .find(|(id, _, _)| *id == data)
            .map(|(_, tid, tmr_id)| (*tid, *tmr_id))
    }
    .unwrap_or((0, -1));

    if owner_tid == 0 {
        return;
    }

    // Get the timer from the task's registry
    if let Some(timer) = get_posix_timer(owner_tid, timer_id) {
        timer.on_expire();
    }
}

/// Per-process POSIX timer registry
pub struct PosixTimerRegistry {
    /// Mapping from timer_id -> timer
    timers: BTreeMap<TimerT, Arc<PosixTimer>>,
    /// Next timer ID to allocate
    next_id: TimerT,
}

impl PosixTimerRegistry {
    /// Create a new empty registry
    pub const fn new() -> Self {
        Self {
            timers: BTreeMap::new(),
            next_id: 0,
        }
    }

    /// Allocate a new timer ID
    fn alloc_id(&mut self) -> TimerT {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    /// Add a timer to the registry
    fn add(&mut self, timer: Arc<PosixTimer>) {
        self.timers.insert(timer.timer_id, timer);
    }

    /// Get a timer by ID
    fn get(&self, timer_id: TimerT) -> Option<Arc<PosixTimer>> {
        self.timers.get(&timer_id).cloned()
    }

    /// Remove a timer by ID
    fn remove(&mut self, timer_id: TimerT) -> Option<Arc<PosixTimer>> {
        self.timers.remove(&timer_id)
    }
}

impl Default for PosixTimerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Per-task POSIX timer storage
// =============================================================================

use crate::sync::spin::Mutex;

/// Global table mapping TID -> PosixTimerRegistry
static TASK_POSIX_TIMERS: Mutex<BTreeMap<Tid, PosixTimerRegistry>> = Mutex::new(BTreeMap::new());

/// Get or create a task's timer registry
fn get_or_create_registry(tid: Tid) -> &'static Mutex<BTreeMap<Tid, PosixTimerRegistry>> {
    // Ensure the task has a registry entry
    let mut table = TASK_POSIX_TIMERS.lock();
    table.entry(tid).or_default();
    drop(table);
    &TASK_POSIX_TIMERS
}

/// Create a new POSIX timer for a task
///
/// # Arguments
/// * `tid` - Owning task's TID
/// * `clockid` - CLOCK_REALTIME or CLOCK_MONOTONIC
/// * `sigevent` - Notification settings (or None for default)
///
/// # Returns
/// Timer ID on success, or negative errno
pub fn create_posix_timer(
    tid: Tid,
    clockid: i32,
    sigevent: Option<SigEvent>,
) -> Result<TimerT, i32> {
    // Validate clockid
    if clockid != 0 && clockid != 1 {
        return Err(-22); // EINVAL - only CLOCK_REALTIME (0) and CLOCK_MONOTONIC (1)
    }

    let sev = sigevent.unwrap_or_default();

    // Validate sigevent
    match sev.sigev_notify {
        sigev_notify::SIGEV_SIGNAL | sigev_notify::SIGEV_NONE => {}
        sigev_notify::SIGEV_THREAD => return Err(-22), // EINVAL - not supported
        sigev_notify::SIGEV_THREAD_ID => {
            // SIGEV_THREAD_ID requires a valid thread ID
            // For now, allow it but the signal goes to owner_tid
        }
        _ => return Err(-22), // EINVAL
    }

    // Allocate timer ID and create timer
    let timer_id;
    {
        let table = get_or_create_registry(tid);
        let mut table_guard = table.lock();
        let registry = table_guard.entry(tid).or_default();
        timer_id = registry.alloc_id();
        let timer = PosixTimer::new(timer_id, clockid, tid, sev);
        registry.add(timer);
    }

    Ok(timer_id)
}

/// Get a POSIX timer by ID
pub fn get_posix_timer(tid: Tid, timer_id: TimerT) -> Option<Arc<PosixTimer>> {
    let table = TASK_POSIX_TIMERS.lock();
    table.get(&tid).and_then(|reg| reg.get(timer_id))
}

/// A timer_create timer of `tid` (negative ids are internal: ITIMER_REAL)
fn user_timer(tid: Tid, timer_id: TimerT) -> Option<Arc<PosixTimer>> {
    if timer_id < 0 {
        return None;
    }
    get_posix_timer(tid, timer_id)
}

/// Delete a POSIX timer
///
/// # Returns
/// 0 on success, negative errno on error
pub fn delete_posix_timer(tid: Tid, timer_id: TimerT) -> Result<(), i32> {
    let timer = {
        let mut table = TASK_POSIX_TIMERS.lock();
        table.get_mut(&tid).and_then(|reg| reg.remove(timer_id))
    };

    match timer {
        Some(t) => {
            t.delete();
            Ok(())
        }
        None => Err(-22), // EINVAL - timer not found
    }
}

/// Clean up all POSIX timers for a task (on exit)
pub fn exit_posix_timers(tid: Tid) {
    let timers = {
        let mut table = TASK_POSIX_TIMERS.lock();
        table.remove(&tid)
    };

    if let Some(mut registry) = timers {
        // Delete all timers
        let ids: Vec<_> = registry.timers.keys().cloned().collect();
        for id in ids {
            if let Some(timer) = registry.remove(id) {
                timer.delete();
            }
        }
    }
}

// =============================================================================
// Syscall implementations
// =============================================================================

use crate::arch::Uaccess;
use crate::task::percpu::current_tid;
use crate::uaccess::{copy_val_from_user, copy_val_to_user, get_user, put_user};

/// sys_timer_create - Create a POSIX timer
///
/// # Arguments
/// * `clockid` - CLOCK_REALTIME (0) or CLOCK_MONOTONIC (1)
/// * `sevp` - Pointer to sigevent struct (NULL for default)
/// * `timerid` - Pointer to store timer ID
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_timer_create(clockid: i32, sevp: u64, timerid: u64) -> i64 {
    let tid = current_tid();

    // Read sigevent from user space if provided
    let sigevent = if sevp != 0 {
        match copy_val_from_user::<Uaccess, SigEvent>(sevp) {
            Ok(sev) => Some(sev),
            Err(_) => return -14, // EFAULT
        }
    } else {
        None
    };

    // Create the timer
    match create_posix_timer(tid, clockid, sigevent) {
        Ok(timer_id) => {
            // Write timer ID to user space
            if timerid != 0 && put_user::<Uaccess, TimerT>(timerid, timer_id).is_err() {
                // Linux releases the new timer if the ID cannot be stored
                let _ = delete_posix_timer(tid, timer_id);
                return -14; // EFAULT
            }
            0
        }
        Err(e) => e as i64,
    }
}

/// sys_timer_settime - Arm/disarm a POSIX timer
///
/// # Arguments
/// * `timerid` - Timer ID
/// * `flags` - 0 or TIMER_ABSTIME
/// * `new_value` - Pointer to new itimerspec
/// * `old_value` - Pointer to store old itimerspec (can be NULL)
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_timer_settime(timerid: TimerT, flags: i32, new_value: u64, old_value: u64) -> i64 {
    let tid = current_tid();

    // Validate flags
    if flags & !timer_flags::TIMER_ABSTIME != 0 {
        return -22; // EINVAL
    }

    // Get the timer
    let timer = match user_timer(tid, timerid) {
        Some(t) => t,
        None => return -22, // EINVAL - timer not found
    };

    // Read new value from user space
    if new_value == 0 {
        return -14; // EFAULT
    }
    let new_spec: ITimerSpec = match get_user::<Uaccess, ITimerSpec>(new_value) {
        Ok(v) => v,
        Err(_) => return -14, // EFAULT
    };
    // Linux itimerspec64_valid: negative or unnormalized values -> EINVAL
    if !new_spec.is_valid() {
        return -22;
    }

    // Set the timer
    let old_spec = timer.settime(&new_spec, flags);

    // Write old value to user space if requested
    if old_value != 0 && put_user::<Uaccess, ITimerSpec>(old_value, old_spec).is_err() {
        return -14; // EFAULT
    }

    0
}

/// sys_timer_gettime - Get remaining time on a POSIX timer
///
/// # Arguments
/// * `timerid` - Timer ID
/// * `curr_value` - Pointer to store current itimerspec
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_timer_gettime(timerid: TimerT, curr_value: u64) -> i64 {
    let tid = current_tid();

    // Get the timer
    let timer = match user_timer(tid, timerid) {
        Some(t) => t,
        None => return -22, // EINVAL - timer not found
    };

    if curr_value == 0 {
        return -14; // EFAULT
    }

    // Get current value
    let curr_spec = timer.gettime();

    // Write to user space
    if copy_val_to_user::<Uaccess, ITimerSpec>(curr_value, &curr_spec).is_err() {
        return -14; // EFAULT
    }

    0
}

/// sys_timer_getoverrun - Get overrun count for a POSIX timer
///
/// # Arguments
/// * `timerid` - Timer ID
///
/// # Returns
/// Overrun count on success, negative errno on error
pub fn sys_timer_getoverrun(timerid: TimerT) -> i64 {
    let tid = current_tid();

    // Get the timer
    let timer = match user_timer(tid, timerid) {
        Some(t) => t,
        None => return -22, // EINVAL - timer not found
    };

    timer.getoverrun() as i64
}

/// sys_timer_delete - Delete a POSIX timer
///
/// # Arguments
/// * `timerid` - Timer ID
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_timer_delete(timerid: TimerT) -> i64 {
    let tid = current_tid();

    if timerid < 0 {
        return -22; // EINVAL: not a timer_create id
    }
    match delete_posix_timer(tid, timerid) {
        Ok(()) => 0,
        Err(e) => e as i64,
    }
}

// =============================================================================
// Interval timers: setitimer/getitimer/alarm (Linux kernel/time/itimer.c)
// =============================================================================
//
// ITIMER_REAL is a CLOCK_MONOTONIC timer sending SIGALRM, kept in the
// owner's timer registry under an id user timer ids never take; alarm()
// is ITIMER_REAL in whole seconds. ITIMER_VIRTUAL and ITIMER_PROF (CPU
// time) are not implemented (BUGS.md).

/// ITIMER_REAL's slot in the owner's registry (user timer ids are >= 0)
const ITIMER_REAL_ID: TimerT = -1;

const ITIMER_REAL: i32 = 0;
const ITIMER_VIRTUAL: i32 = 1;
const ITIMER_PROF: i32 = 2;

/// struct itimerval
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ITimerVal {
    it_interval: crate::time_syscall::Timeval,
    it_value: crate::time_syscall::Timeval,
}

/// The current task's ITIMER_REAL timer, created on first use
fn itimer_real() -> Arc<PosixTimer> {
    let tid = current_tid();
    let mut table = TASK_POSIX_TIMERS.lock();
    let reg = table.entry(tid).or_default();
    if let Some(t) = reg.get(ITIMER_REAL_ID) {
        return t;
    }
    let t = PosixTimer::new(ITIMER_REAL_ID, 1, tid, SigEvent::default());
    reg.add(Arc::clone(&t));
    t
}

/// timeval -> timespec; None if invalid (negative, usec >= 1e6)
fn tv_to_ts(tv: crate::time_syscall::Timeval) -> Option<crate::time_syscall::LinuxTimespec> {
    (tv.tv_sec >= 0 && (0..1_000_000).contains(&tv.tv_usec)).then(|| {
        crate::time_syscall::LinuxTimespec {
            tv_sec: tv.tv_sec,
            tv_nsec: tv.tv_usec * 1000,
        }
    })
}

/// timespec -> timeval, rounding up a partial microsecond (Linux
/// rounds remaining time so a live timer never reads as 0)
fn ts_to_tv(ts: crate::time_syscall::LinuxTimespec) -> crate::time_syscall::Timeval {
    let mut tv = crate::time_syscall::Timeval {
        tv_sec: ts.tv_sec,
        tv_usec: (ts.tv_nsec + 999) / 1000,
    };
    if tv.tv_usec >= 1_000_000 {
        tv.tv_sec += 1;
        tv.tv_usec -= 1_000_000;
    }
    tv
}

fn to_itimerval(s: ITimerSpec) -> ITimerVal {
    ITimerVal {
        it_interval: ts_to_tv(s.it_interval),
        it_value: ts_to_tv(s.it_value),
    }
}

/// Validate the timer kind: only ITIMER_REAL exists here
fn which_ok(which: i32) -> Result<(), i64> {
    match which {
        ITIMER_REAL => Ok(()),
        ITIMER_VIRTUAL | ITIMER_PROF => Err(-22), // not implemented
        _ => Err(-22),
    }
}

/// getitimer(which, curr_value)
pub fn sys_getitimer(which: i32, curr: u64) -> i64 {
    if let Err(e) = which_ok(which) {
        return e;
    }
    let v = to_itimerval(itimer_real().gettime());
    if put_user::<Uaccess, ITimerVal>(curr, v).is_err() {
        return -14;
    }
    0
}

/// setitimer(which, new_value, old_value); a NULL new value disarms
/// (Linux accepts it for compatibility)
pub fn sys_setitimer(which: i32, new: u64, old: u64) -> i64 {
    if let Err(e) = which_ok(which) {
        return e;
    }
    let nv = if new == 0 {
        ITimerVal::default()
    } else {
        match get_user::<Uaccess, ITimerVal>(new) {
            Ok(v) => v,
            Err(_) => return -14,
        }
    };
    let (Some(interval), Some(value)) = (tv_to_ts(nv.it_interval), tv_to_ts(nv.it_value)) else {
        return -22;
    };
    let prev = itimer_real().settime(
        &ITimerSpec {
            it_interval: interval,
            it_value: value,
        },
        0,
    );
    if old != 0 && put_user::<Uaccess, ITimerVal>(old, to_itimerval(prev)).is_err() {
        return -14;
    }
    0
}

#[cfg(target_arch = "x86_64")]
/// alarm(seconds): arm ITIMER_REAL once, returning the seconds left on
/// the previous alarm, rounded to the nearest second but at least 1 if
/// one was pending (Linux alarm_setitimer)
pub fn sys_alarm(seconds: u32) -> i64 {
    let spec = ITimerSpec {
        it_interval: crate::time_syscall::LinuxTimespec::default(),
        it_value: crate::time_syscall::LinuxTimespec {
            tv_sec: seconds as i64,
            tv_nsec: 0,
        },
    };
    let prev = to_itimerval(itimer_real().settime(&spec, 0)).it_value;
    let mut secs = prev.tv_sec;
    if (secs == 0 && prev.tv_usec != 0) || prev.tv_usec >= 500_000 {
        secs += 1;
    }
    secs
}

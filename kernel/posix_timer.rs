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
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::IrqSpinlock;
use crate::hrtimer::{HrClock, HrTimer};
use crate::signal::{SIGALRM, send_signal};
use crate::task::Tid;
use crate::task::percpu::TICK_NS;
use crate::time_syscall::CLOCK_REALTIME;
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
    /// Next expiration time (absolute ns on `clock`, 0 if disarmed)
    expires_ns: u64,
    /// The clock `expires_ns` is on: CLOCK_REALTIME only for an
    /// absolute realtime timer (Linux: relative timers run on
    /// CLOCK_MONOTONIC)
    clock: HrClock,
    /// Interval for periodic timers (0 = one-shot)
    interval_ns: u64,
    /// Overrun count (expirations since last signal delivery)
    overrun: i32,
    /// Whether timer is currently armed
    armed: bool,
}

impl PosixTimerInner {
    fn new() -> Self {
        Self {
            expires_ns: 0,
            clock: HrClock::Monotonic,
            interval_ns: 0,
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
    /// Owning task's TID (for signal delivery; retargeted when a
    /// non-leader exec takes the leader's tid)
    owner_tid: AtomicU64,
    /// Notification settings
    sigevent: SigEvent,
    /// Inner state protected by IRQ spinlock
    inner: IrqSpinlock<PosixTimerInner>,
    /// Its expiry timer (SOFT: the callback sends a signal; data: this
    /// timer, which outlives it: dropping it waits out its callback).
    /// Unused by a CPU timer.
    timer: HrTimer,
    /// A CPU-time timer's clock (`cpu_timer`): its expiry is checked
    /// by the tick and run on the way back to user mode, not an hrtimer
    cpu: Option<crate::cpu_timer::CpuClock>,
    /// A clock_nanosleep's timer: its expiry wakes the sleeper on `wq`
    /// instead of signalling; never seen by timer_* syscalls
    sleeper: bool,
    wq: crate::waitqueue::WaitQueue,
}

impl PosixTimer {
    /// Create a new POSIX timer
    fn new(timer_id: TimerT, clockid: i32, owner_tid: Tid, sigevent: SigEvent) -> Arc<Self> {
        Self::with_cpu(timer_id, clockid, owner_tid, sigevent, None, false)
    }

    /// A timer on CPU clock `cpu` (if any); `sleeper`: clock_nanosleep's
    fn with_cpu(
        timer_id: TimerT,
        clockid: i32,
        owner_tid: Tid,
        sigevent: SigEvent,
        cpu: Option<crate::cpu_timer::CpuClock>,
        sleeper: bool,
    ) -> Arc<Self> {
        let timer = Arc::new(Self {
            timer_id,
            clockid,
            owner_tid: AtomicU64::new(owner_tid),
            sigevent,
            inner: IrqSpinlock::new(PosixTimerInner::new()),
            timer: HrTimer::new(posix_timer_fire, 0),
            cpu,
            sleeper,
            wq: crate::waitqueue::WaitQueue::new(),
        });
        timer.timer.set_data(Arc::as_ptr(&timer) as usize);
        timer
    }

    /// Its timer (pinned: the timer lives in an Arc)
    fn timer(&self) -> Pin<&HrTimer> {
        // SAFETY: an Arc's contents never move
        unsafe { Pin::new_unchecked(&self.timer) }
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
        if let Some(c) = self.cpu {
            return self.cpu_settime(c, new_value, flags);
        }
        // Cancel the existing timer, waiting out its callback (it takes
        // `inner`)
        self.timer.cancel_sync();
        let mut inner = self.inner.lock();

        // Save old value
        let old_value = self.get_current_value_locked(&inner);

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

        let (expires_ns, clock) = if flags & timer_flags::TIMER_ABSTIME != 0 {
            // Absolute, kept on its clock: a realtime one follows
            // clock_settime
            let clock = crate::time_syscall::PosixClock::decode(self.clockid)
                .and_then(|c| c.timer_base())
                .unwrap_or(HrClock::Monotonic);
            (value_ns, clock)
        } else {
            // Relative time (saturates: a huge value never fires)
            let now = crate::time::monotonic_ns();
            (
                crate::time::deadline_after(now, value_ns),
                HrClock::Monotonic,
            )
        };

        inner.expires_ns = expires_ns;
        inner.clock = clock;
        inner.armed = true;
        self.timer().start(expires_ns, clock);

        old_value
    }

    /// Get current timer value
    pub fn gettime(&self) -> ITimerSpec {
        if let Some(c) = self.cpu {
            let now = crate::cpu_timer::sample_now(c, crate::task::percpu::current_pid());
            let inner = self.inner.lock();
            return cpu_value(&inner, now.unwrap_or(0));
        }
        let inner = self.inner.lock();
        self.get_current_value_locked(&inner)
    }

    /// settime of a CPU-time timer: its expiry in that clock's ns
    /// (relative values from the clock's value now), then the cache the
    /// tick checks (Linux posix_cpu_timer_set)
    fn cpu_settime(
        &self,
        c: crate::cpu_timer::CpuClock,
        new_value: &ITimerSpec,
        flags: i32,
    ) -> ITimerSpec {
        // The clock's value, before `inner` (it may take TASKLIST)
        let now = crate::cpu_timer::sample_now(c, crate::task::percpu::current_pid()).unwrap_or(0);
        let mut inner = self.inner.lock();
        let old_value = cpu_value(&inner, now);
        inner.overrun = 0;
        if new_value.is_disarmed() {
            inner.expires_ns = 0;
            inner.interval_ns = 0;
            inner.armed = false;
            return old_value;
        }
        let value_ns = new_value.value_to_ns();
        inner.interval_ns = new_value.interval_to_ns();
        let at = if flags & timer_flags::TIMER_ABSTIME != 0 {
            value_ns
        } else {
            crate::time::deadline_after(now, value_ns)
        };
        inner.expires_ns = at;
        inner.armed = true;
        drop(inner);
        crate::cpu_timer::arm(c, at);
        old_value
    }

    /// A CPU-time timer's clock
    pub fn cpu_clock(&self) -> Option<crate::cpu_timer::CpuClock> {
        self.cpu
    }

    /// Armed
    pub fn armed(&self) -> bool {
        self.inner.lock().armed
    }

    /// When the armed CPU timer next expires (its clock's ns)
    pub fn cpu_expiry(&self) -> Option<u64> {
        let i = self.inner.lock();
        i.armed.then_some(i.expires_ns)
    }

    /// The CPU timer at clock value `now`: if due, rearm it a whole
    /// number of periods on (overruns counted) or disarm it, and say
    /// what it does (Linux cpu_timer_fire, bump_cpu_timer)
    pub fn cpu_expire(&self, now: u64) -> Option<crate::cpu_timer::Expired> {
        let mut i = self.inner.lock();
        if !i.armed || now < i.expires_ns {
            return None;
        }
        if let Some(late) = (now - i.expires_ns).checked_div(i.interval_ns) {
            let missed = late + 1;
            i.expires_ns = i
                .expires_ns
                .saturating_add(missed.saturating_mul(i.interval_ns));
            let extra = i32::try_from(missed - 1).unwrap_or(i32::MAX);
            i.overrun = i.overrun.saturating_add(extra);
        } else {
            i.armed = false;
            i.expires_ns = 0;
        }
        drop(i);
        if self.sleeper {
            return Some(crate::cpu_timer::Expired::Wake);
        }
        if self.sigevent.sigev_notify != sigev_notify::SIGEV_SIGNAL {
            return None;
        }
        let sig = self.sigevent.sigev_signo as u32;
        if sig == 0 || sig > 64 {
            return None;
        }
        // ITIMER_VIRTUAL/PROF signal the process; timer_create timers
        // their owner, like the other clocks' here
        let thread = (self.timer_id >= 0).then(|| self.owner_tid.load(Ordering::Relaxed));
        Some(crate::cpu_timer::Expired::Signal { sig, thread })
    }

    /// clock_nanosleep's timer expired: wake its sleeper
    pub fn wake_sleeper(&self) {
        self.wq.wake_all();
    }

    /// Get current value while holding the lock
    fn get_current_value_locked(&self, inner: &PosixTimerInner) -> ITimerSpec {
        if !inner.armed || inner.expires_ns == 0 {
            return ITimerSpec::default();
        }

        let remaining = inner.expires_ns.saturating_sub(inner.clock.now());

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

            if !inner.armed {
                return;
            }
            // A one-shot timer is done; a periodic one re-arms for the
            // first period end after now (Linux hrtimer_forward)
            if inner.interval_ns == 0 {
                inner.armed = false;
                inner.expires_ns = 0;
            } else {
                let now = inner.clock.now();
                let (missed, next) =
                    crate::timer::forward(inner.expires_ns, inner.interval_ns, now);
                // Periods missed beyond the one this expiry delivers
                // (Linux: hrtimer_forward's count, into it_overrun)
                let extra = i32::try_from(missed - 1).unwrap_or(i32::MAX);
                inner.overrun = inner.overrun.saturating_add(extra);
                match next {
                    Some(n) => {
                        // The expiry stays on the period grid, so the
                        // next forward counts every missed period; a
                        // period under a tick fires a tick away at the
                        // soonest, or it would keep ktimers/N busy (Linux
                        // re-arms when the signal is dequeued instead)
                        inner.expires_ns = n;
                        let fire = match inner.interval_ns < TICK_NS {
                            true => n.max(now.saturating_add(TICK_NS)),
                            false => n,
                        };
                        self.timer().start(fire, inner.clock);
                    }
                    None => {
                        inner.armed = false;
                        inner.expires_ns = 0;
                    }
                }
            }

            // Determine notification action
            should_signal = self.sigevent.sigev_notify == sigev_notify::SIGEV_SIGNAL;
        }

        // Send signal if configured
        if should_signal {
            let sig = self.sigevent.sigev_signo as u32;
            if sig > 0 && sig <= 64 {
                send_signal(self.owner_tid.load(Ordering::Relaxed), sig);
            }
        }
    }

    /// Delete the timer (cancel, waiting out its callback; thread
    /// context)
    fn delete(&self) {
        self.inner.lock().armed = false;
        self.timer.cancel_sync();
        self.wq.wake_all();
    }
}

/// A CPU timer's remaining time and interval at clock value `now`
fn cpu_value(inner: &PosixTimerInner, now: u64) -> ITimerSpec {
    if !inner.armed {
        return ITimerSpec::default();
    }
    // A due timer not yet run reads as 1 ns left (Linux: never 0)
    ITimerSpec::from_ns(
        inner.expires_ns.saturating_sub(now).max(1),
        inner.interval_ns,
    )
}

/// A POSIX timer expired (`ktimers/N`)
fn posix_timer_fire(t: &HrTimer) {
    // SAFETY: `data` is the PosixTimer owning `t` (see `PosixTimer::timer`)
    unsafe { &*(t.data() as *const PosixTimer) }.on_expire();
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

    /// Every timer, borrowed under the registry lock (cpu_timer's
    /// expiry pass)
    pub fn iter(&self) -> impl Iterator<Item = &Arc<PosixTimer>> {
        self.timers.values()
    }
}

/// A group's timers that were not deleted at its last exit (two last
/// threads raced) stop with its SignalStruct
impl Drop for PosixTimerRegistry {
    fn drop(&mut self) {
        for (_, t) in core::mem::take(&mut self.timers) {
            t.delete();
        }
    }
}

impl Default for PosixTimerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Per-process POSIX timer storage (Linux signal->posix_timers)
// =============================================================================

/// The timers of task `tid`'s thread group (its SignalStruct's)
fn with_timers<R>(tid: Tid, f: impl FnOnce(&mut PosixTimerRegistry) -> R) -> Option<R> {
    let sig = crate::signal::get_task_signal_struct(tid)?;
    let r = f(&mut sig.posix_timers.lock());
    Some(r)
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
    // Realtime, monotonic, boottime and TAI; the alarm clocks need
    // CAP_WAKE_ALARM (EPERM); CPU clocks of the caller's own process or
    // its threads (Linux also takes other processes': BUGS.md)
    use crate::time_syscall::{
        CLOCK_BOOTTIME, CLOCK_BOOTTIME_ALARM, CLOCK_MONOTONIC, CLOCK_REALTIME_ALARM, CLOCK_TAI,
    };
    let mut cpu = None;
    match clockid {
        CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_BOOTTIME | CLOCK_TAI => {}
        CLOCK_REALTIME_ALARM | CLOCK_BOOTTIME_ALARM => {
            if !crate::task::capable(crate::task::CAP_WAKE_ALARM) {
                return Err(-1); // EPERM
            }
        }
        _ => cpu = Some(own_cpu_clock(clockid).ok_or(-22)?), // EINVAL
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
        timer_id = with_timers(tid, |registry| {
            let id = registry.alloc_id();
            registry.add(PosixTimer::with_cpu(id, clockid, tid, sev, cpu, false));
            id
        })
        .ok_or(-11)?; // EAGAIN: no thread group
    }

    Ok(timer_id)
}

/// CPU clock `clockid` if it is the caller's own process or one of its
/// threads (pid 0, its own pid or tid; a thread clock any thread of its
/// group)
fn own_cpu_clock(clockid: i32) -> Option<crate::cpu_timer::CpuClock> {
    use crate::task::percpu::{current_pid, current_tid};
    let crate::time_syscall::PosixClock::Cpu { pid, thread, which } =
        crate::time_syscall::PosixClock::decode(clockid)?
    else {
        return None;
    };
    let sample = crate::cpu_timer::Sample::of(which);
    if thread {
        let tid = if pid == 0 { current_tid() } else { pid };
        let same = crate::task::percpu::TASKLIST
            .read()
            .get(tid)
            .is_some_and(|t| t.task.pid == current_pid());
        return same.then_some(crate::cpu_timer::CpuClock {
            thread: Some(tid),
            sample,
        });
    }
    (pid == 0 || pid == current_pid() || pid == current_tid()).then_some(
        crate::cpu_timer::CpuClock {
            thread: None,
            sample,
        },
    )
}

/// clock_nanosleep on the caller's process CPU clock `clockid` (Linux
/// posix_cpu_nsleep): a hidden CPU timer wakes it; until `value_ns` of
/// that clock (TIMER_ABSTIME) or that much more. On a signal, the time
/// left is returned with the error (a relative sleep reports it).
pub fn cpu_nanosleep(clockid: i32, abs: bool, value_ns: u64) -> Result<(), (KernelErrorT, u64)> {
    use crate::task::percpu::{current_pid, current_tid};
    let Some(c) = own_cpu_clock(clockid).filter(|c| c.thread.is_none()) else {
        return Err((crate::error::KernelError::InvalidArgument, 0));
    };
    let tid = current_tid();
    let sev = SigEvent {
        sigev_notify: sigev_notify::SIGEV_NONE,
        ..SigEvent::default()
    };
    let Some(t) = with_timers(tid, |reg| {
        let id = reg.alloc_id();
        let t = PosixTimer::with_cpu(id, clockid, tid, sev, Some(c), true);
        reg.add(t.clone());
        t
    }) else {
        return Err((crate::error::KernelError::InvalidArgument, 0));
    };
    let spec = ITimerSpec::from_ns(value_ns, 0);
    let r = if value_ns == 0 && !abs {
        Ok(())
    } else {
        t.settime(&spec, if abs { timer_flags::TIMER_ABSTIME } else { 0 });
        t.wq.wait_event_interruptible(|| !t.armed())
    };
    let left = match crate::cpu_timer::sample_now(c, current_pid()) {
        Some(now) => t.cpu_expiry().map_or(0, |at| at.saturating_sub(now)),
        None => 0,
    };
    let _ = with_timers(tid, |reg| reg.remove(t.timer_id));
    t.delete();
    r.map_err(|e| (e, left))
}

type KernelErrorT = crate::error::KernelError;

/// Get a POSIX timer by ID
pub fn get_posix_timer(tid: Tid, timer_id: TimerT) -> Option<Arc<PosixTimer>> {
    with_timers(tid, |reg| reg.get(timer_id)).flatten()
}

/// A timer_create timer of `tid` (negative ids are internal: ITIMER_REAL)
fn user_timer(tid: Tid, timer_id: TimerT) -> Option<Arc<PosixTimer>> {
    if timer_id < 0 {
        return None;
    }
    get_posix_timer(tid, timer_id).filter(|t| !t.sleeper)
}

/// Delete a POSIX timer
///
/// # Returns
/// 0 on success, negative errno on error
pub fn delete_posix_timer(tid: Tid, timer_id: TimerT) -> Result<(), i32> {
    let timer = with_timers(tid, |reg| reg.remove(timer_id)).flatten();

    match timer {
        Some(t) => {
            t.delete();
            Ok(())
        }
        None => Err(-22), // EINVAL - timer not found
    }
}

/// A non-leader exec took tid `new` from `old` (exchange_tids): the
/// group's timers owned by `old` now signal `new`
pub fn retarget(sig: &crate::signal::SignalStruct, old: Tid, new: Tid) {
    for t in sig.posix_timers.lock().timers.values() {
        let _ = t
            .owner_tid
            .compare_exchange(old, new, Ordering::Relaxed, Ordering::Relaxed);
    }
}

/// Delete every timer of the thread group (Linux exit_itimers: its last
/// thread is exiting)
pub fn exit_itimers(sig: &crate::signal::SignalStruct) {
    let timers = core::mem::take(&mut sig.posix_timers.lock().timers);
    // Deleted after the lock (cancel_sync waits out a running callback)
    for (_, t) in timers {
        t.delete();
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
// is ITIMER_REAL in whole seconds. ITIMER_VIRTUAL and ITIMER_PROF are
// process CPU timers (user time, user + system) sending SIGVTALRM and
// SIGPROF to the process (`cpu_timer`).

/// ITIMER_REAL's slot in the owner's registry (user timer ids are >= 0)
const ITIMER_REAL_ID: TimerT = -1;
/// ITIMER_VIRTUAL's and ITIMER_PROF's
const ITIMER_VIRTUAL_ID: TimerT = -2;
const ITIMER_PROF_ID: TimerT = -3;

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
    with_timers(tid, |reg| {
        if let Some(t) = reg.get(ITIMER_REAL_ID) {
            return t;
        }
        let t = PosixTimer::new(ITIMER_REAL_ID, 1, tid, SigEvent::default());
        reg.add(Arc::clone(&t));
        t
    })
    .unwrap_or_else(|| PosixTimer::new(ITIMER_REAL_ID, 1, tid, SigEvent::default()))
}

/// The current process's itimer `which`, created on first use
fn itimer(which: i32) -> Arc<PosixTimer> {
    use crate::cpu_timer::{CpuClock, Sample};
    let (id, sample, sig) = match which {
        ITIMER_VIRTUAL => (ITIMER_VIRTUAL_ID, Sample::Virt, crate::signal::SIGVTALRM),
        ITIMER_PROF => (ITIMER_PROF_ID, Sample::Prof, crate::signal::SIGPROF),
        _ => return itimer_real(),
    };
    let tid = current_tid();
    let make = || {
        let sev = SigEvent {
            sigev_signo: sig as i32,
            sigev_notify: sigev_notify::SIGEV_SIGNAL,
            ..SigEvent::default()
        };
        let clock = CpuClock {
            thread: None,
            sample,
        };
        // CLOCK_PROCESS_CPUTIME_ID
        PosixTimer::with_cpu(id, 2, tid, sev, Some(clock), false)
    };
    with_timers(tid, |reg| {
        if let Some(t) = reg.get(id) {
            return t;
        }
        let t = make();
        reg.add(Arc::clone(&t));
        t
    })
    .unwrap_or_else(make)
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

/// Validate the timer kind
fn which_ok(which: i32) -> Result<(), i64> {
    match which {
        ITIMER_REAL | ITIMER_VIRTUAL | ITIMER_PROF => Ok(()),
        _ => Err(-22),
    }
}

/// getitimer(which, curr_value)
pub fn sys_getitimer(which: i32, curr: u64) -> i64 {
    if let Err(e) = which_ok(which) {
        return e;
    }
    let v = to_itimerval(itimer(which).gettime());
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
    let prev = itimer(which).settime(
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

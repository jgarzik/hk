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
//! timer_settime(timer_id, ...) -> Arms timer via time/timer.rs
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

use crate::util::error::KernelError;
use crate::util::kalloc::{arc_nofail, try_arc};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::pin::Pin;

use crate::arch::IrqSpinlock;
use crate::signal::{PidType, SIGALRM, SigQueue};
use crate::sync::spin::Mutex;
use crate::task::Tid;
use crate::time::hrtimer::{HrClock, HrTimer};
use crate::time::time_syscall::CLOCK_REALTIME;
use crate::time::timerfd::ITimerSpec;
use alloc::boxed::Box;

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

/// struct sigevent (Linux ABI compatible)
///
/// Note: Linux sigevent is 64 bytes with padding. We use the minimal
/// fields needed for timer notification.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SigEvent {
    /// Data passed with notification (union sigval: an int or a
    /// pointer, its 8 bytes)
    pub sigev_value: u64,
    /// Signal number (for SIGEV_SIGNAL)
    pub sigev_signo: i32,
    /// Notification method (SIGEV_SIGNAL, SIGEV_NONE, etc.)
    pub sigev_notify: i32,
    /// Thread ID for SIGEV_THREAD_ID (union with sigev_notify_function/attributes)
    pub sigev_notify_thread_id: i32,
    /// Padding to match Linux sigevent size (64 bytes)
    pub _pad: [i32; 11],
}
crate::pod!(SigEvent {
    sigev_value,
    sigev_signo,
    sigev_notify,
    sigev_notify_thread_id,
    _pad
});

impl Default for SigEvent {
    fn default() -> Self {
        Self {
            sigev_value: 0,
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
    /// Periods missed while the signal waited, counted at its rearm
    /// (Linux it_overrun; -1 until the first)
    overrun: i64,
    /// What the last delivered signal's si_overrun said (Linux
    /// it_overrun_last: timer_getoverrun)
    overrun_last: i64,
    /// Expiry pending (Linux POSIX_TIMER_ARMED)
    armed: bool,
    /// An interval timer that fired and rearms when its signal is
    /// dequeued (Linux POSIX_TIMER_REQUEUE_PENDING)
    requeue: bool,
    /// Bumped by settime and delete; a queued signal from before is
    /// dropped at dequeue (Linux it_signal_seq, it_sigqueue_seq)
    signal_seq: u64,
    sigqueue_seq: u64,
    /// The signal was sent as an interval timer's (Linux it_sig_periodic)
    sig_periodic: bool,
    /// Its signal was ignored on expiry: queued once the action stops
    /// ignoring it (Linux ignored_posix_timers)
    ignored: bool,
}

impl PosixTimerInner {
    fn new() -> Self {
        Self {
            expires_ns: 0,
            clock: HrClock::Monotonic,
            interval_ns: 0,
            overrun: -1,
            overrun_last: 0,
            armed: false,
            requeue: false,
            signal_seq: 0,
            sigqueue_seq: 0,
            sig_periodic: false,
            ignored: false,
        }
    }
}

/// POSIX timer structure
pub struct PosixTimer {
    /// Unique timer ID within the process
    timer_id: TimerT,
    /// Clock ID (CLOCK_REALTIME or CLOCK_MONOTONIC)
    clockid: i32,
    /// Whom it signals (Linux it_pid, a counted struct pid): the
    /// thread for SIGEV_THREAD_ID, else its process's leader; a struct
    /// pid, never a number, so a reaped target's reused number never
    /// gets it, and an exec that takes the leader's pid keeps it
    target: Option<Arc<crate::task::pid::Pid>>,
    /// Its signal is for the thread (SIGEV_THREAD_ID) or the process
    /// (Linux it_pid_type)
    pid_type: PidType,
    /// Its preallocated signal entry while not queued (Linux sigq,
    /// SIGQUEUE_PREALLOC): spin leaf, thread context
    sigq: Mutex<Option<Box<SigQueue>>>,
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
    cpu: Option<crate::time::cpu_timer::CpuClock>,
    /// A clock_nanosleep's timer: its expiry wakes the sleeper on `wq`
    /// instead of signalling; never seen by timer_* syscalls
    sleeper: bool,
    wq: crate::sync::waitqueue::WaitQueue,
}

impl PosixTimer {
    /// An itimer, made on first use (Linux keeps them in signal_struct:
    /// getitimer, setitimer and alarm cannot fail)
    fn itimer(
        timer_id: TimerT,
        clockid: i32,
        owner_tid: Tid,
        sigevent: SigEvent,
        cpu: Option<crate::time::cpu_timer::CpuClock>,
    ) -> Arc<Self> {
        Self::own_data(arc_nofail(Self::fresh(
            timer_id, clockid, owner_tid, sigevent, cpu, false,
        )))
    }

    /// A timer on CPU clock `cpu` (if any); `sleeper`: clock_nanosleep's.
    /// ENOMEM
    fn with_cpu(
        timer_id: TimerT,
        clockid: i32,
        owner_tid: Tid,
        sigevent: SigEvent,
        cpu: Option<crate::time::cpu_timer::CpuClock>,
        sleeper: bool,
    ) -> Result<Arc<Self>, KernelError> {
        Ok(Self::own_data(try_arc(Self::fresh(
            timer_id, clockid, owner_tid, sigevent, cpu, sleeper,
        ))?))
    }

    /// Its state, before it is in its Arc
    fn fresh(
        timer_id: TimerT,
        clockid: i32,
        owner_tid: Tid,
        sigevent: SigEvent,
        cpu: Option<crate::time::cpu_timer::CpuClock>,
        sleeper: bool,
    ) -> Self {
        let pid_type = if sigevent.sigev_notify == sigev_notify::SIGEV_THREAD_ID {
            PidType::Pid
        } else {
            PidType::Tgid
        };
        let nr = match pid_type {
            PidType::Pid => owner_tid,
            PidType::Tgid => crate::task::percpu::current_pid(),
        };
        let target = u32::try_from(nr)
            .ok()
            .and_then(|n| crate::task::pid::find_pid(&crate::ns::INIT_PID_NS, n));
        Self {
            timer_id,
            clockid,
            target,
            pid_type,
            sigq: Mutex::new(None),
            sigevent,
            inner: IrqSpinlock::new(PosixTimerInner::new()),
            timer: HrTimer::new(posix_timer_fire, 0),
            cpu,
            sleeper,
            wq: crate::sync::waitqueue::WaitQueue::new(),
        }
    }

    /// Point its timer at it, in its Arc
    fn own_data(timer: Arc<Self>) -> Arc<Self> {
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
        let old_value = self.get_current_value_locked(&mut inner);

        // A queued signal from before is dropped; overruns start over
        // (Linux do_timer_settime, posix_timer_set_common)
        reset_signal(&mut inner);

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
            // clock_settime. A TAI deadline is the realtime one TAI - UTC
            // earlier (as clock_nanosleep's)
            let pclock = crate::time::time_syscall::PosixClock::decode(self.clockid);
            let clock = pclock
                .and_then(|c| c.timer_base())
                .unwrap_or(HrClock::Monotonic);
            let value_ns = if pclock == Some(crate::time::time_syscall::PosixClock::Tai) {
                (i128::from(value_ns) - crate::time::time_syscall::tai_offset_ns()).max(0) as u64
            } else {
                value_ns
            };
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
            let now = crate::time::cpu_timer::sample_now(c, crate::task::percpu::current_pid());
            let mut inner = self.inner.lock();
            return cpu_value(&mut inner, now.unwrap_or(0));
        }
        let mut inner = self.inner.lock();
        self.get_current_value_locked(&mut inner)
    }

    /// settime of a CPU-time timer: its expiry in that clock's ns
    /// (relative values from the clock's value now), then the cache the
    /// tick checks (Linux posix_cpu_timer_set)
    fn cpu_settime(
        &self,
        c: crate::time::cpu_timer::CpuClock,
        new_value: &ITimerSpec,
        flags: i32,
    ) -> ITimerSpec {
        // The clock's value, before `inner` (it may take TASKLIST)
        let now =
            crate::time::cpu_timer::sample_now(c, crate::task::percpu::current_pid()).unwrap_or(0);
        let mut inner = self.inner.lock();
        let old_value = cpu_value(&mut inner, now);
        reset_signal(&mut inner);
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
        crate::time::cpu_timer::arm(c, at);
        old_value
    }

    /// A CPU-time timer's clock
    pub fn cpu_clock(&self) -> Option<crate::time::cpu_timer::CpuClock> {
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

    /// The CPU timer at clock value `now`: if due, what it does (Linux
    /// cpu_timer_fire). A timer_create timer's signal is queued and an
    /// interval one rearmed when it is dequeued; an itimer
    /// (ITIMER_VIRTUAL/PROF) rearms a whole number of periods on at once
    /// and signals its process (Linux check_cpu_itimer).
    pub fn cpu_expire(&self, now: u64) -> Option<crate::time::cpu_timer::Expired> {
        use crate::time::cpu_timer::Expired;
        let mut i = self.inner.lock();
        if !i.armed || now < i.expires_ns {
            return None;
        }
        let itimer = self.timer_id < 0 && !self.sleeper;
        match (now - i.expires_ns).checked_div(i.interval_ns) {
            Some(late) if itimer => {
                i.expires_ns = i
                    .expires_ns
                    .saturating_add((late + 1).saturating_mul(i.interval_ns));
            }
            interval => {
                i.armed = false;
                i.requeue = interval.is_some();
            }
        }
        drop(i);
        if self.sleeper {
            return Some(Expired::Wake);
        }
        if !self.signals() {
            return None;
        }
        Some(if itimer {
            Expired::Signal(self.sigevent.sigev_signo as u32)
        } else {
            Expired::Queue
        })
    }

    /// Its target is a thread of the caller's process (Linux
    /// good_sigevent: same_thread_group)
    fn target_in_group(&self) -> bool {
        let table = crate::task::percpu::TASKLIST.read();
        self.target
            .as_ref()
            .and_then(|p| table.pid_tid(p))
            .and_then(|t| table.get(t))
            .is_some_and(|v| v.task.pid == crate::task::percpu::current_pid())
    }

    /// Its expiry sends a signal
    fn signals(&self) -> bool {
        let n = self.sigevent.sigev_notify;
        n != sigev_notify::SIGEV_NONE && !self.sleeper
    }

    /// Queue its signal entry (Linux posix_timer_queue_signal ->
    /// posixtimer_send_sigqueue): nothing while it is still queued; an
    /// ignored interval timer's waits to be unignored. No lock held.
    pub fn queue_signal(&self) {
        let Some(q) = self.sigq.lock().take() else {
            return;
        };
        let periodic = {
            let mut i = self.inner.lock();
            i.sigqueue_seq = i.signal_seq;
            i.sig_periodic = i.requeue;
            i.sig_periodic
        };
        let Some(target) = &self.target else {
            *self.sigq.lock() = Some(q);
            return;
        };
        let ignored = match crate::signal::send_timer_sigqueue(target, self.pid_type, q) {
            Ok(()) => false,
            Err((q, ignored)) => {
                *self.sigq.lock() = Some(q);
                ignored && periodic
            }
        };
        self.inner.lock().ignored = ignored;
    }

    /// Its signal was dequeued, the info in `info` (Linux
    /// __posixtimer_deliver_signal): false if settime or delete came
    /// since it was queued; an interval timer rearms here, its missed
    /// periods into si_overrun
    fn deliver_locked(&self, info: &mut crate::signal::SigInfo) -> bool {
        let (rearm, value) = {
            let mut i = self.inner.lock();
            if i.signal_seq != i.sigqueue_seq {
                return false;
            }
            if i.interval_ns == 0 || !i.requeue {
                return true;
            }
            let now = match self.cpu {
                Some(c) => {
                    crate::time::cpu_timer::sample_now(c, crate::task::percpu::current_pid())
                        .unwrap_or(i.expires_ns)
                }
                None => i.clock.now(),
            };
            let (missed, next) = forward_now(i.expires_ns, i.interval_ns, now);
            i.overrun = i.overrun.saturating_add(missed as i64);
            i.overrun_last = i.overrun;
            i.overrun = -1;
            i.signal_seq += 1;
            i.requeue = false;
            if let Some(n) = next {
                i.expires_ns = n;
                i.armed = true;
                if self.cpu.is_none() {
                    self.timer().start(n, i.clock);
                }
            }
            (
                next.filter(|_| self.cpu.is_some()),
                overrun_int(i.overrun_last),
            )
        };
        if let (Some(at), Some(c)) = (rearm, self.cpu) {
            crate::time::cpu_timer::arm(c, at);
        }
        let mut f = info.fields();
        if let crate::signal::SigFields::Timer { overrun, .. } = &mut f {
            *overrun = value;
        }
        *info = crate::signal::SigInfo::new(info.sig(), info.code, f);
        true
    }

    /// clock_nanosleep's timer expired: wake its sleeper
    pub fn wake_sleeper(&self) {
        self.wq.wake_all();
    }

    /// Get current value while holding the lock: an interval timer
    /// waiting for its signal's dequeue, or a SIGEV_NONE one, is moved
    /// forward past now, its periods counted (Linux common_timer_get)
    fn get_current_value_locked(&self, inner: &mut PosixTimerInner) -> ITimerSpec {
        let now = inner.clock.now();
        forward_waiting(inner, now);
        if !inner.armed && !inner.requeue {
            return ITimerSpec::default();
        }
        let remaining = inner.expires_ns.saturating_sub(now).max(1);
        ITimerSpec::from_ns(remaining, inner.interval_ns)
    }

    /// The last delivered signal's overrun count (Linux
    /// timer_getoverrun: it_overrun_last)
    pub fn getoverrun(&self) -> i32 {
        overrun_int(self.inner.lock().overrun_last)
    }

    /// Called when timer expires (from timer callback): its signal is
    /// queued; an interval timer is rearmed when that is dequeued
    /// (Linux posix_timer_fn), ITIMER_REAL's when its SIGALRM is
    fn on_expire(&self) {
        {
            let mut inner = self.inner.lock();
            if !inner.armed {
                return;
            }
            inner.armed = false;
            inner.requeue = inner.interval_ns != 0;
        }
        if self.timer_id == ITIMER_REAL_ID {
            // Linux it_real_fn: SEND_SIG_PRIV to the process
            let info = crate::signal::SendInfo::Kernel;
            if let Some(pid) = &self.target {
                crate::signal::kill_pid_info(pid, SIGALRM, info, |_| 0);
            }
        } else if self.signals() {
            self.queue_signal();
        }
    }

    /// Delete the timer (cancel, waiting out its callback; thread
    /// context): a queued signal of it is dropped at dequeue
    fn delete(&self) {
        {
            let mut i = self.inner.lock();
            i.armed = false;
            i.requeue = false;
            i.signal_seq += 1;
        }
        self.timer.cancel_sync();
        self.wq.wake_all();
    }
}

/// A settime: a queued signal from before is dropped, overruns start
/// over (Linux it_signal_seq++, posix_timer_set_common)
fn reset_signal(i: &mut PosixTimerInner) {
    i.signal_seq += 1;
    i.requeue = false;
    i.overrun = -1;
    i.overrun_last = 0;
}

/// An interval timer not armed (waiting for its signal's dequeue, or
/// SIGEV_NONE) moved past `now`, its periods counted (Linux
/// common_timer_get: timer_forward)
fn forward_waiting(i: &mut PosixTimerInner, now: u64) {
    if i.interval_ns == 0 || i.armed || !i.requeue || i.expires_ns > now {
        return;
    }
    let (missed, next) = crate::time::timer::forward(i.expires_ns, i.interval_ns, now);
    i.overrun = i.overrun.saturating_add(missed as i64);
    if let Some(n) = next {
        i.expires_ns = n;
    }
}

/// `expires` moved whole `interval`s past `now`, and how many (Linux
/// hrtimer_forward: none if it is still ahead)
fn forward_now(expires: u64, interval: u64, now: u64) -> (u64, Option<u64>) {
    if expires > now {
        return (0, Some(expires));
    }
    crate::time::timer::forward(expires, interval, now)
}

/// si_overrun and timer_getoverrun are int: clamped (Linux
/// timer_overrun_to_int)
fn overrun_int(v: i64) -> i32 {
    i32::try_from(v.max(0)).unwrap_or(i32::MAX)
}

/// Timer `q`'s signal was dequeued (Linux posixtimer_deliver_signal):
/// its info, or None if the timer no longer wants it delivered (deleted,
/// or set again since); the entry goes back to a live timer
pub fn deliver(q: Box<SigQueue>) -> Option<crate::signal::SigInfo> {
    let t = q.timer()?.upgrade()?;
    let mut info = *q.info();
    let ok = t.deliver_locked(&mut info);
    *t.sigq.lock() = Some(q);
    ok.then_some(info)
}

/// Timer `q`'s entry was flushed or not queued: back to its timer; an
/// interval timer's signal discarded as ignored waits to be unignored
/// (Linux posixtimer_sig_ignore)
pub fn reclaim(q: Box<SigQueue>) {
    let Some(t) = q.timer().and_then(alloc::sync::Weak::upgrade) else {
        return;
    };
    {
        let mut i = t.inner.lock();
        if i.sig_periodic && i.signal_seq == i.sigqueue_seq {
            i.ignored = true;
        }
    }
    *t.sigq.lock() = Some(q);
}

/// `sig`'s action no longer ignores it: the current process's interval
/// timers whose signal it ignored queue it now (Linux
/// posixtimer_sig_unignore)
pub fn sig_unignore(sig: u32) {
    let tid = current_tid();
    let waiting: alloc::vec::Vec<Arc<PosixTimer>> = with_timers(tid, |reg| {
        reg.iter()
            .filter(|t| t.sigevent.sigev_signo as u32 == sig && t.inner.lock().ignored)
            .cloned()
            .collect()
    })
    .unwrap_or_default();
    for t in waiting {
        t.inner.lock().ignored = false;
        t.queue_signal();
    }
}

/// A SIGALRM of the current process was dequeued: an interval
/// ITIMER_REAL that is not running rearms a whole number of periods
/// on (Linux posixtimer_rearm_itimer)
pub fn rearm_itimer_real() {
    let tid = current_tid();
    let Some(t) = with_timers(tid, |reg| reg.get(ITIMER_REAL_ID)).flatten() else {
        return;
    };
    let mut i = t.inner.lock();
    if i.interval_ns == 0 || i.armed {
        return;
    }
    let now = i.clock.now();
    let (_, next) = forward_now(i.expires_ns, i.interval_ns, now);
    i.requeue = false;
    if let Some(n) = next {
        i.expires_ns = n;
        i.armed = true;
        t.timer().start(n, i.clock);
    }
}

/// A CPU timer's remaining time and interval at clock value `now`
fn cpu_value(inner: &mut PosixTimerInner, now: u64) -> ITimerSpec {
    forward_waiting(inner, now);
    if !inner.armed && !inner.requeue {
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
    use crate::time::time_syscall::{
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

    // Linux good_sigevent: SIGEV_THREAD_ID names a thread of the
    // caller's group; a signalling timer a valid signal (SIGEV_THREAD
    // signals like SIGEV_SIGNAL: glibc runs its threads itself)
    use sigev_notify::{SIGEV_NONE, SIGEV_SIGNAL, SIGEV_THREAD, SIGEV_THREAD_ID};
    let mut sev = sigevent.unwrap_or(SigEvent {
        sigev_signo: SIGALRM as i32,
        ..SigEvent::default()
    });
    let default_value = sigevent.is_none();
    match sev.sigev_notify {
        // Checked on its struct pid once the timer holds it
        SIGEV_THREAD_ID => {}
        SIGEV_SIGNAL | SIGEV_THREAD => sev.sigev_notify = SIGEV_SIGNAL,
        SIGEV_NONE => {}
        _ => return Err(-22), // EINVAL
    }
    if sev.sigev_notify != SIGEV_NONE && !(1..=64).contains(&sev.sigev_signo) {
        return Err(-22);
    }
    let owner = match sev.sigev_notify {
        SIGEV_THREAD_ID => sev.sigev_notify_thread_id as Tid,
        _ => tid,
    };

    // The id, then the timer and its signal entry outside the registry
    // lock (Linux posixtimer_init_sigqueue: EAGAIN past
    // RLIMIT_SIGPENDING), then the timer in the registry
    let id = with_timers(tid, |reg| reg.alloc_id()).ok_or(-11)?;
    if default_value {
        // Linux: sival_int = the timer id
        sev.sigev_value = u64::from(id as u32);
    }
    let t =
        PosixTimer::with_cpu(id, clockid, owner, sev, cpu, false).map_err(|e| e.to_errno_neg())?;
    if sev.sigev_notify == SIGEV_THREAD_ID && !t.target_in_group() {
        return Err(-22);
    }
    if sev.sigev_notify != SIGEV_NONE {
        let fields = crate::signal::SigFields::Timer {
            tid: id,
            overrun: 0,
            value: sev.sigev_value,
        };
        let info = crate::signal::SigInfo::new(
            sev.sigev_signo as u32,
            crate::signal::si_code::SI_TIMER,
            fields,
        );
        let q = SigQueue::alloc_timer(info, Arc::downgrade(&t)).ok_or(-11)?;
        *t.sigq.lock() = Some(q);
    }
    with_timers(tid, |reg| reg.add(t)).ok_or(-11)?;
    Ok(id)
}

/// CPU clock `clockid` if it is the caller's own process or one of its
/// threads (pid 0, its own pid or tid; a thread clock any thread of its
/// group)
fn own_cpu_clock(clockid: i32) -> Option<crate::time::cpu_timer::CpuClock> {
    use crate::task::percpu::{current_pid, current_tid};
    let crate::time::time_syscall::PosixClock::Cpu { pid, thread, which } =
        crate::time::time_syscall::PosixClock::decode(clockid)?
    else {
        return None;
    };
    let sample = crate::time::cpu_timer::Sample::of(which);
    if thread {
        let tid = if pid == 0 { current_tid() } else { pid };
        let same = crate::task::percpu::TASKLIST
            .read()
            .get(tid)
            .is_some_and(|t| t.task.pid == current_pid());
        return same.then_some(crate::time::cpu_timer::CpuClock {
            thread: Some(tid),
            sample,
        });
    }
    (pid == 0 || pid == current_pid() || pid == current_tid()).then_some(
        crate::time::cpu_timer::CpuClock {
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
        return Err((crate::util::error::KernelError::InvalidArgument, 0));
    };
    let tid = current_tid();
    let sev = SigEvent {
        sigev_notify: sigev_notify::SIGEV_NONE,
        ..SigEvent::default()
    };
    let t = match with_timers(tid, |reg| {
        let id = reg.alloc_id();
        let t = PosixTimer::with_cpu(id, clockid, tid, sev, Some(c), true)?;
        reg.add(t.clone());
        Ok(t)
    }) {
        Some(Ok(t)) => t,
        Some(Err(e)) => return Err((e, 0)),
        None => return Err((crate::util::error::KernelError::InvalidArgument, 0)),
    };
    let spec = ITimerSpec::from_ns(value_ns, 0);
    let r = if value_ns == 0 && !abs {
        Ok(())
    } else {
        t.settime(&spec, if abs { timer_flags::TIMER_ABSTIME } else { 0 });
        t.wq.wait_event_interruptible(|| !t.armed())
    };
    let left = match crate::time::cpu_timer::sample_now(c, current_pid()) {
        Some(now) => t.cpu_expiry().map_or(0, |at| at.saturating_sub(now)),
        None => 0,
    };
    let _ = with_timers(tid, |reg| reg.remove(t.timer_id));
    t.delete();
    r.map_err(|e| (e, left))
}

type KernelErrorT = crate::util::error::KernelError;

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

/// Delete every timer of the thread group (Linux exit_itimers: its last
/// thread is exiting)
pub fn exit_itimers(sig: &crate::signal::SignalStruct) {
    let timers = core::mem::take(&mut sig.posix_timers.lock().timers);
    // Deleted after the lock (cancel_sync waits out a running callback)
    for (_, t) in timers {
        t.delete();
    }
}

/// An exec deletes the process's timer_create timers; its itimers stay
/// (Linux posixtimer_exec: exit_itimers keeps signal->it, whose
/// ITIMER_REAL survives exec as POSIX wants). The registry is taken out
/// and the itimers' rebuilt outside its lock (nothing allocates or is
/// released under it); the caller is the process's only thread.
pub fn exec_timers(sig: &crate::signal::SignalStruct) {
    let all = core::mem::take(&mut sig.posix_timers.lock().timers);
    let mut keep = BTreeMap::new();
    let mut gone = alloc::vec::Vec::new();
    for (id, t) in all {
        if id < 0 {
            keep.insert(id, t);
        } else {
            gone.push(t);
        }
    }
    core::mem::swap(&mut sig.posix_timers.lock().timers, &mut keep);
    // Anything made meanwhile goes too (none: the caller is alone)
    gone.extend(core::mem::take(&mut keep).into_values());
    for t in gone {
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
        Err(e) => i64::from(e),
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

    // A thread CPU clock whose thread is gone: ESRCH (Linux
    // posix_cpu_timer_set finds no task)
    if let Some(crate::time::cpu_timer::CpuClock {
        thread: Some(t), ..
    }) = timer.cpu
        && crate::time::cpu_timer::thread_sample(t).is_none()
    {
        return -3;
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

    i64::from(timer.getoverrun())
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
        Err(e) => i64::from(e),
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
    it_interval: crate::time::time_syscall::Timeval,
    it_value: crate::time::time_syscall::Timeval,
}
crate::pod!(ITimerVal {
    it_interval,
    it_value
});

/// The current task's ITIMER_REAL timer, created on first use
fn itimer_real() -> Arc<PosixTimer> {
    let tid = current_tid();
    with_timers(tid, |reg| {
        if let Some(t) = reg.get(ITIMER_REAL_ID) {
            return t;
        }
        let t = PosixTimer::itimer(ITIMER_REAL_ID, 1, tid, SigEvent::default(), None);
        reg.add(Arc::clone(&t));
        t
    })
    .unwrap_or_else(|| PosixTimer::itimer(ITIMER_REAL_ID, 1, tid, SigEvent::default(), None))
}

/// The current process's itimer `which`, created on first use
fn itimer(which: i32) -> Arc<PosixTimer> {
    use crate::time::cpu_timer::{CpuClock, Sample};
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
        PosixTimer::itimer(id, 2, tid, sev, Some(clock))
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
fn tv_to_ts(
    tv: crate::time::time_syscall::Timeval,
) -> Option<crate::time::time_syscall::LinuxTimespec> {
    (tv.tv_sec >= 0 && (0..1_000_000).contains(&tv.tv_usec)).then(|| {
        crate::time::time_syscall::LinuxTimespec {
            tv_sec: tv.tv_sec,
            tv_nsec: tv.tv_usec * 1000,
        }
    })
}

/// timespec -> timeval, rounding up a partial microsecond (Linux
/// rounds remaining time so a live timer never reads as 0)
fn ts_to_tv(ts: crate::time::time_syscall::LinuxTimespec) -> crate::time::time_syscall::Timeval {
    let mut tv = crate::time::time_syscall::Timeval {
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
        it_interval: crate::time::time_syscall::LinuxTimespec::default(),
        it_value: crate::time::time_syscall::LinuxTimespec {
            tv_sec: i64::from(seconds),
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

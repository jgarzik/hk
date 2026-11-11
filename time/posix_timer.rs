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
use crate::util::kalloc::try_arc;
use crate::util::pod::FromBytes;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::pin::Pin;

use crate::signal::{PidType, SIGALRM, SigQueue, Signal};
use crate::sync::IrqSpinlock;
use crate::sync::spin::Mutex;
use crate::task::{Task, Tid};
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

impl SigEvent {
    /// Its signal: None for 0 or a number no signal has (a SIGEV_NONE
    /// timer's, unchecked by timer_create)
    pub fn signal(&self) -> Option<Signal> {
        Signal::from_int(self.sigev_signo)
    }
}

impl Default for SigEvent {
    fn default() -> Self {
        Self {
            sigev_signo: i32::from(SIGALRM),
            sigev_notify: sigev_notify::SIGEV_SIGNAL,
            ..FromBytes::zeroed()
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
    /// An itimer, embedded in its SignalStruct (Linux signal->real_timer,
    /// signal->it[]): no target of its own (ITIMER_REAL signals the
    /// group's leader pid, `it_real_fn`; the CPU ones the process whose
    /// thread runs them); `fire`: its hrtimer's callback
    fn itimer(
        timer_id: TimerT,
        clockid: i32,
        sigevent: SigEvent,
        cpu: Option<crate::time::cpu_timer::CpuClock>,
        fire: fn(&HrTimer),
    ) -> Self {
        Self {
            timer_id,
            clockid,
            target: None,
            pid_type: PidType::Tgid,
            sigq: Mutex::new(None),
            sigevent,
            inner: IrqSpinlock::new(PosixTimerInner::new()),
            timer: HrTimer::new(fire, 0),
            cpu,
            sleeper: false,
            wq: crate::sync::waitqueue::WaitQueue::new(),
        }
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

    /// Its timer (pinned: the timer lives in an Arc, its own or, an
    /// itimer, its SignalStruct's)
    fn timer(&self) -> Pin<&HrTimer> {
        // SAFETY: an Arc's contents never move, and every PosixTimer is
        // in one (`with_cpu`, `ITimers` in `SignalStruct::alloc`)
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
    pub fn settime(&self, new_value: &ITimerSpec, flags: i32) -> ITimerSpec {
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
            Expired::Signal(self.sigevent.signal()?)
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
        {
            let mut i = self.inner.lock();
            i.sigqueue_seq = i.signal_seq;
            i.sig_periodic = i.requeue;
        }
        self.send_sigq(q);
    }

    /// Send its entry `q` as stamped when it was first queued (Linux
    /// posixtimer_queue_sigqueue): ignored, an interval timer's waits
    /// to be unignored
    fn send_sigq(&self, q: Box<SigQueue>) {
        let periodic = self.inner.lock().sig_periodic;
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
        *info = info.with_fields(f);
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

    /// The hrtimer expired: false if it was disarmed meanwhile; an
    /// interval timer rearms when its signal is dequeued
    fn expire(&self) -> bool {
        let mut inner = self.inner.lock();
        if !inner.armed {
            return false;
        }
        inner.armed = false;
        inner.requeue = inner.interval_ns != 0;
        true
    }

    /// Called when timer expires (from timer callback): its signal is
    /// queued; an interval timer is rearmed when that is dequeued
    /// (Linux posix_timer_fn)
    fn on_expire(&self) {
        if self.expire() && self.signals() {
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
pub fn sig_unignore(sig: Signal) {
    let me = current();
    let ignored = |t: &&Arc<PosixTimer>| t.sigevent.signal() == Some(sig) && t.inner.lock().ignored;
    // Sized under one hold, filled under another: nothing allocates
    // under posix_timers
    let n = with_timers(&me, |reg| reg.iter().filter(ignored).count()).unwrap_or(0);
    let mut waiting = alloc::vec::Vec::with_capacity(n);
    with_timers(&me, |reg| {
        for t in reg.iter().filter(ignored).take(n) {
            waiting.push(t.clone());
        }
    });
    // Queued as first stamped: a settime or delete since then drops it
    // at dequeue (Linux posixtimer_sig_unignore leaves it_sigqueue_seq)
    for t in waiting {
        t.inner.lock().ignored = false;
        let q = t.sigq.lock().take();
        if let Some(q) = q {
            t.send_sigq(q);
        }
    }
}

/// A SIGALRM of the current process was dequeued: an interval
/// ITIMER_REAL that is not running rearms a whole number of periods
/// on (Linux posixtimer_rearm_itimer)
pub fn rearm_itimer_real() {
    let Some(sig) = crate::signal::get_task_signal_struct(&current()) else {
        return;
    };
    let t = &sig.itimers.real;
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

    /// A free timer id, or None (EAGAIN) (Linux posix_timer_add)
    fn alloc_id(&mut self) -> Option<TimerT> {
        let timers = &self.timers;
        next_free(&mut self.next_id, |id| timers.contains_key(&id))
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

/// The next id from counter `next` that is not `taken`, clamped to
/// 0..=INT_MAX (negative ids are the itimers'); None once every id was
/// tried (Linux posix_timer_add: next_posix_timer_id & INT_MAX, skipping
/// hashed ids)
fn next_free(next: &mut TimerT, taken: impl Fn(TimerT) -> bool) -> Option<TimerT> {
    for _ in 0..=TimerT::MAX as u32 {
        let id = *next & TimerT::MAX;
        *next = next.wrapping_add(1);
        if !taken(id) {
            return Some(id);
        }
    }
    None
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

// =============================================================================
// Per-process POSIX timer storage (Linux signal->posix_timers)
// =============================================================================

/// The timers of task `t`'s thread group (its SignalStruct's)
fn with_timers<R>(t: &Task, f: impl FnOnce(&mut PosixTimerRegistry) -> R) -> Option<R> {
    let sig = crate::signal::get_task_signal_struct(t)?;
    let r = f(&mut sig.posix_timers.lock());
    Some(r)
}

/// Create a new POSIX timer for a task
///
/// # Arguments
/// * `me` - Owning task
/// * `clockid` - CLOCK_REALTIME or CLOCK_MONOTONIC
/// * `sigevent` - Notification settings (or None for default)
///
pub fn create_posix_timer(
    me: &Task,
    clockid: i32,
    sigevent: Option<SigEvent>,
) -> Result<TimerT, KernelError> {
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
                return Err(KernelError::NotPermitted);
            }
        }
        _ => cpu = Some(own_cpu_clock(clockid).ok_or(KernelError::InvalidArgument)?),
    }

    // Linux good_sigevent: SIGEV_THREAD_ID names a thread of the
    // caller's group; a signalling timer a valid signal (SIGEV_THREAD
    // signals like SIGEV_SIGNAL: glibc runs its threads itself)
    use sigev_notify::{SIGEV_NONE, SIGEV_SIGNAL, SIGEV_THREAD, SIGEV_THREAD_ID};
    let mut sev = sigevent.unwrap_or(SigEvent {
        sigev_signo: i32::from(SIGALRM),
        ..SigEvent::default()
    });
    let default_value = sigevent.is_none();
    match sev.sigev_notify {
        // Checked on its struct pid once the timer holds it
        SIGEV_THREAD_ID => {}
        SIGEV_SIGNAL | SIGEV_THREAD => sev.sigev_notify = SIGEV_SIGNAL,
        SIGEV_NONE => {}
        _ => return Err(KernelError::InvalidArgument),
    }
    // A signalling timer's signal, parsed once (not 0, not past NSIG)
    let sig = (sev.sigev_notify != SIGEV_NONE)
        .then(|| sev.signal().ok_or(KernelError::InvalidArgument))
        .transpose()?;
    let owner = match sev.sigev_notify {
        // The caller's number (Linux good_sigevent: find_task_by_vpid);
        // one it does not see names no task (0), so EINVAL below
        SIGEV_THREAD_ID => {
            crate::task::pid::from_vnr(sev.sigev_notify_thread_id as Tid).unwrap_or(0)
        }
        _ => me.tid(),
    };

    // The id, then the timer and its signal entry outside the registry
    // lock (Linux posixtimer_init_sigqueue: EAGAIN past
    // RLIMIT_SIGPENDING), then the timer in the registry
    let id = with_timers(me, |reg| reg.alloc_id())
        .flatten()
        .ok_or(KernelError::WouldBlock)?;
    if default_value {
        // Linux: sival_int = the timer id
        sev.sigev_value = u64::from(id as u32);
    }
    let t = PosixTimer::with_cpu(id, clockid, owner, sev, cpu, false)?;
    if sev.sigev_notify == SIGEV_THREAD_ID && !t.target_in_group() {
        return Err(KernelError::InvalidArgument);
    }
    if let Some(sig) = sig {
        let fields = crate::signal::SigFields::Timer {
            tid: id,
            overrun: 0,
            value: sev.sigev_value,
        };
        let info = crate::signal::SigInfo::new(sig, crate::signal::si_code::SI_TIMER, fields);
        let q = SigQueue::alloc_timer(sig, info, Arc::downgrade(&t));
        let q = q.ok_or(KernelError::WouldBlock)?;
        *t.sigq.lock() = Some(q);
    }
    with_timers(me, |reg| reg.add(t)).ok_or(KernelError::WouldBlock)?;
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
    let pid = crate::time::time_syscall::clock_pid(pid)?;
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
    use crate::task::percpu::current_pid;
    let Some(c) = own_cpu_clock(clockid).filter(|c| c.thread.is_none()) else {
        return Err((crate::util::error::KernelError::InvalidArgument, 0));
    };
    let me = crate::task::percpu::current();
    let tid = me.tid();
    let sev = SigEvent {
        sigev_notify: sigev_notify::SIGEV_NONE,
        ..SigEvent::default()
    };
    let t = match with_timers(&me, |reg| {
        let id = reg.alloc_id().ok_or(KernelError::WouldBlock)?;
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
    let _ = with_timers(&me, |reg| reg.remove(t.timer_id));
    t.delete();
    r.map_err(|e| (e, left))
}

type KernelErrorT = crate::util::error::KernelError;

/// Task `t`'s POSIX timer `timer_id`
pub fn get_posix_timer(t: &Task, timer_id: TimerT) -> Option<Arc<PosixTimer>> {
    with_timers(t, |reg| reg.get(timer_id)).flatten()
}

/// A timer_create timer of `t` (negative ids are internal: ITIMER_REAL)
fn user_timer(t: &Task, timer_id: TimerT) -> Option<Arc<PosixTimer>> {
    if timer_id < 0 {
        return None;
    }
    get_posix_timer(t, timer_id).filter(|t| !t.sleeper)
}

/// Delete task `t`'s POSIX timer: EINVAL if there is none
pub fn delete_posix_timer(t: &Task, timer_id: TimerT) -> Result<(), KernelError> {
    let timer = with_timers(t, |reg| reg.remove(timer_id)).flatten();
    timer.ok_or(KernelError::InvalidArgument)?.delete();
    Ok(())
}

/// The thread group's last thread is exiting: its timer_create timers
/// are deleted and ITIMER_REAL stopped (Linux do_exit with group_dead:
/// hrtimer_cancel(&sig->real_timer), exit_itimers). The CPU itimers run
/// only in the group's own threads: none is left to run them.
pub fn exit_itimers(sig: &crate::signal::SignalStruct) {
    exec_timers(sig);
    sig.itimers.real.delete();
}

/// An exec deletes the process's timer_create timers; its itimers stay
/// (Linux posixtimer_exec -> exit_itimers, which leaves signal->it and
/// real_timer: ITIMER_REAL survives exec as POSIX wants). The registry
/// is taken out under its lock, the timers deleted after it
/// (cancel_sync waits out a running callback).
pub fn exec_timers(sig: &crate::signal::SignalStruct) {
    let timers = core::mem::take(&mut sig.posix_timers.lock().timers);
    for (_, t) in timers {
        t.delete();
    }
}

// =============================================================================
// Syscall implementations
// =============================================================================

use crate::task::percpu::current;
use crate::uaccess::UserPtr;
use crate::util::error::KernelResult;

/// timer_create(clockid, sevp, timerid): `sevp` NULL is the default
/// sigevent
pub fn sys_timer_create(
    clockid: i32,
    sevp: UserPtr<SigEvent>,
    timerid: UserPtr<TimerT>,
) -> KernelResult<()> {
    let me = current();
    let sigevent = if sevp.is_null() {
        None
    } else {
        Some(sevp.read()?)
    };
    let timer_id = create_posix_timer(&me, clockid, sigevent)?;
    if !timerid.is_null() && timerid.write(&timer_id).is_err() {
        // Linux releases the new timer if the ID cannot be stored
        let _ = delete_posix_timer(&me, timer_id);
        return Err(KernelError::BadAddress);
    }
    Ok(())
}

/// timer_settime(timerid, flags, new_value, old_value)
pub fn sys_timer_settime(
    timerid: TimerT,
    flags: i32,
    new_value: UserPtr<ITimerSpec>,
    old_value: UserPtr<ITimerSpec>,
) -> KernelResult<()> {
    if flags & !timer_flags::TIMER_ABSTIME != 0 {
        return Err(KernelError::InvalidArgument);
    }
    let timer = user_timer(&current(), timerid).ok_or(KernelError::InvalidArgument)?;
    let new_spec = new_value.read()?;
    // Linux itimerspec64_valid: negative or unnormalized values -> EINVAL
    if !new_spec.is_valid() {
        return Err(KernelError::InvalidArgument);
    }

    // A thread CPU clock whose thread is gone: ESRCH (Linux
    // posix_cpu_timer_set finds no task)
    if let Some(crate::time::cpu_timer::CpuClock {
        thread: Some(t), ..
    }) = timer.cpu
        && crate::time::cpu_timer::thread_sample(t).is_none()
    {
        return Err(KernelError::NoProcess);
    }

    let old_spec = timer.settime(&new_spec, flags);
    if !old_value.is_null() {
        old_value.write(&old_spec)?;
    }
    Ok(())
}

/// timer_gettime(timerid, curr_value)
pub fn sys_timer_gettime(timerid: TimerT, curr_value: UserPtr<ITimerSpec>) -> KernelResult<()> {
    let timer = user_timer(&current(), timerid).ok_or(KernelError::InvalidArgument)?;
    Ok(curr_value.write(&timer.gettime())?)
}

/// timer_getoverrun(timerid): the overrun count
pub fn sys_timer_getoverrun(timerid: TimerT) -> KernelResult<i32> {
    let timer = user_timer(&current(), timerid).ok_or(KernelError::InvalidArgument)?;
    Ok(timer.getoverrun())
}

/// timer_delete(timerid)
pub fn sys_timer_delete(timerid: TimerT) -> KernelResult<()> {
    if timerid < 0 {
        return Err(KernelError::InvalidArgument); // not a timer_create id
    }
    delete_posix_timer(&current(), timerid)
}

// =============================================================================
// Interval timers: setitimer/getitimer/alarm (Linux kernel/time/itimer.c)
// =============================================================================
//
// The itimers live in the SignalStruct, made with it (Linux
// signal->real_timer and signal->it[2]): getitimer, setitimer and alarm
// cannot fail. ITIMER_REAL is a CLOCK_MONOTONIC timer sending SIGALRM to
// the group's leader pid; alarm() is ITIMER_REAL in whole seconds.
// ITIMER_VIRTUAL and ITIMER_PROF are process CPU timers (user time,
// user + system) sending SIGVTALRM and SIGPROF to the process
// (`cpu_timer::run`, after the registry's timers).

/// The itimers' ids (user timer ids are >= 0): they mark a timer as one
const ITIMER_REAL_ID: TimerT = -1;
const ITIMER_VIRTUAL_ID: TimerT = -2;
const ITIMER_PROF_ID: TimerT = -3;

/// setitimer(2) `which`: real time (SIGALRM)
pub const ITIMER_REAL: i32 = 0;
const ITIMER_VIRTUAL: i32 = 1;
const ITIMER_PROF: i32 = 2;

/// A thread group's interval timers (Linux signal->real_timer,
/// it_real_incr and it[CPUCLOCK_PROF], it[CPUCLOCK_VIRT]), embedded in
/// its SignalStruct
pub struct ITimers {
    /// ITIMER_REAL: its hrtimer's data is the SignalStruct (`own`)
    pub real: PosixTimer,
    /// ITIMER_VIRTUAL, ITIMER_PROF (process CPU clocks: no hrtimer)
    pub cpu: [PosixTimer; 2],
}

impl ITimers {
    /// # Safety
    /// The value is placed where it never moves (its SignalStruct's Arc)
    /// and [`own`](Self::own) is called with that SignalStruct before
    /// any timer is armed: an armed hrtimer is queued by address, and
    /// ITIMER_REAL's callback reaches the SignalStruct through it.
    pub unsafe fn new() -> Self {
        use crate::time::cpu_timer::{CpuClock, Sample};
        let cpu = |id, sample, sig: Signal| {
            let sev = SigEvent {
                sigev_signo: sig.into(),
                sigev_notify: sigev_notify::SIGEV_SIGNAL,
                ..SigEvent::default()
            };
            let clock = CpuClock {
                thread: None,
                sample,
            };
            // CLOCK_PROCESS_CPUTIME_ID
            PosixTimer::itimer(id, 2, sev, Some(clock), posix_timer_fire)
        };
        Self {
            // CLOCK_MONOTONIC
            real: PosixTimer::itimer(ITIMER_REAL_ID, 1, SigEvent::default(), None, it_real_fn),
            cpu: [
                cpu(ITIMER_VIRTUAL_ID, Sample::Virt, crate::signal::SIGVTALRM),
                cpu(ITIMER_PROF_ID, Sample::Prof, crate::signal::SIGPROF),
            ],
        }
    }

    /// Point ITIMER_REAL's hrtimer at `sig`, the SignalStruct holding
    /// these, in its Arc (before it can be armed)
    pub fn own(&self, sig: *const crate::signal::SignalStruct) {
        self.real.timer.set_data(sig as usize);
    }

    /// Wait out and stop ITIMER_REAL (its SignalStruct is going: Drop)
    pub fn cancel(&self) {
        self.real.timer.cancel_sync();
    }

    /// Itimer `which` (a valid one)
    fn get(&self, which: i32) -> &PosixTimer {
        match which {
            ITIMER_VIRTUAL => &self.cpu[0],
            ITIMER_PROF => &self.cpu[1],
            _ => &self.real,
        }
    }
}

/// ITIMER_REAL expired (`ktimers/N`; Linux it_real_fn): SIGALRM from
/// the kernel to the group's leader pid; an interval one rearms when
/// it is dequeued (`rearm_itimer_real`)
fn it_real_fn(t: &HrTimer) {
    // SAFETY: `data` is the SignalStruct embedding `t` (`ITimers::own`),
    // whose Drop waits out this callback before anything in it goes
    let sig = unsafe { &*(t.data() as *const crate::signal::SignalStruct) };
    if !sig.itimers.real.expire() {
        return;
    }
    if let Some(pid) = sig.leader_pid() {
        let info = crate::signal::SendInfo::Kernel;
        let _ = crate::signal::kill_pid_info(&pid, SIGALRM, info, |_, _| Ok(()));
    }
}

/// struct itimerval
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ITimerVal {
    pub it_interval: crate::time::time_syscall::Timeval,
    pub it_value: crate::time::time_syscall::Timeval,
}
crate::pod!(ITimerVal {
    it_interval,
    it_value
});

/// `f` on the current process's itimer `which` (a valid one); None for
/// a task with no SignalStruct (never a syscall's caller)
fn with_itimer<R>(which: i32, f: impl FnOnce(&PosixTimer) -> R) -> Option<R> {
    let sig = crate::signal::get_task_signal_struct(&current())?;
    Some(f(sig.itimers.get(which)))
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
fn which_ok(which: i32) -> KernelResult<()> {
    match which {
        ITIMER_REAL | ITIMER_VIRTUAL | ITIMER_PROF => Ok(()),
        _ => Err(KernelError::InvalidArgument),
    }
}

/// getitimer(which, curr_value)
pub fn sys_getitimer(which: i32, curr: UserPtr<ITimerVal>) -> KernelResult<()> {
    which_ok(which)?;
    let cur = with_itimer(which, PosixTimer::gettime).unwrap_or_default();
    Ok(curr.write(&to_itimerval(cur))?)
}

/// setitimer(which, new_value, old_value); a NULL new value disarms
/// (Linux accepts it for compatibility)
pub fn sys_setitimer(
    which: i32,
    new: UserPtr<ITimerVal>,
    old: UserPtr<ITimerVal>,
) -> KernelResult<()> {
    which_ok(which)?;
    let nv = if new.is_null() {
        ITimerVal::default()
    } else {
        new.read()?
    };
    let (Some(interval), Some(value)) = (tv_to_ts(nv.it_interval), tv_to_ts(nv.it_value)) else {
        return Err(KernelError::InvalidArgument);
    };
    let prev = do_setitimer(
        which,
        &ITimerSpec {
            it_interval: interval,
            it_value: value,
        },
    );
    if !old.is_null() {
        old.write(&prev)?;
    }
    Ok(())
}

/// Arm the current process's itimer `which` (a valid one) with `spec`,
/// returning its previous setting (Linux do_setitimer)
pub fn do_setitimer(which: i32, spec: &ITimerSpec) -> ITimerVal {
    to_itimerval(with_itimer(which, |t| t.settime(spec, 0)).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ids count up from the counter, skip ones in use, and wrap from
    /// INT_MAX to 0, never negative (the itimers' ids)
    #[test]
    fn ids_clamp_and_skip() {
        let mut next = 0;
        assert_eq!(next_free(&mut next, |id| id == 0 || id == 1), Some(2));
        assert_eq!(next, 3);
        let mut next = TimerT::MAX;
        assert_eq!(next_free(&mut next, |_| false), Some(TimerT::MAX));
        assert_eq!(next, TimerT::MIN);
        assert_eq!(next_free(&mut next, |id| id == 0), Some(1));
        let mut next = -5;
        let id = next_free(&mut next, |_| false);
        assert!(id.is_some_and(|id| id >= 0));
    }
}

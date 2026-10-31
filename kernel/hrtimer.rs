//! High-resolution timers, reduced (Linux kernel/time/hrtimer.c)
//!
//! An [`HrTimer`] (Linux struct hrtimer) is embedded in its pinned owner
//! and fires at an absolute ns time on CLOCK_MONOTONIC or
//! CLOCK_REALTIME. Each CPU keeps its pending timers in sorted intrusive
//! lists (one per clock, O(n) insert: no rbtree yet), in a HARD and a
//! SOFT base like the timer wheel (`timer.rs`): HARD callbacks run in
//! the timer interrupt and only wake tasks; SOFT ones run in
//! `ktimers/N`.
//!
//! The CPU's clock event device runs one-shot (`arch::clockevent_next`:
//! LAPIC one-shot count on x86-64, CNTP_CVAL on arm64), programmed for
//! the earliest pending timer; due SOFT timers waiting for `ktimers/N`
//! do not count until it has run them (`SOFT_ACTIVATED`). The scheduler tick is itself a HARD
//! timer re-armed every TICK_NS, so an interrupt comes at least that
//! often: a CLOCK_REALTIME timer is compared with the realtime clock at
//! every interrupt, so a clock step (clock_settime) delays it by at most
//! a tick (no clock_was_set retrigger). Starting a timer moves it to the
//! starting CPU's base unless its callback is running (Linux
//! switch_hrtimer_base), so a task that moved CPUs re-arms its timers
//! where it runs; a timer started while its callback runs elsewhere stays
//! there, and does not reprogram that CPU: it fires by that CPU's next
//! tick at the latest.
//!
//! Callbacks run with the base lock dropped and `running` set;
//! `cancel_sync` waits out a running callback like `del_timer_sync`,
//! and dropping a timer does that.
//!
//! Locking: `HrBase.q` is an IrqSpinlock leaf; callbacks run with no
//! timer lock held. A timer's `base` changes only under its old base's
//! lock, so lockers recheck it once they hold a lock (Linux
//! lock_hrtimer_base); two base locks are never held together.

use core::marker::PhantomPinned;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicU64, AtomicUsize, Ordering};

use crate::arch::{IrqSpinlock, IrqSpinlockGuard};
use crate::cpu::PerCpu;
use crate::list::{Link, List};
use crate::task::percpu::TICK_NS;

/// A timer callback; the owner is reached through `data`
pub type HrFn = fn(&HrTimer);

/// Callback runs in the timer interrupt (Linux HRTIMER_MODE_HARD); the
/// default is `ktimers/N` (HRTIMER_MODE_SOFT)
pub const HRTIMER_HARD: u8 = 1;

/// The clock an expiry is measured on
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HrClock {
    Monotonic = 0,
    Realtime = 1,
}

impl HrClock {
    /// The clock's time now, in ns
    pub fn now(self) -> u64 {
        match self {
            HrClock::Monotonic => crate::time::monotonic_ns(),
            HrClock::Realtime => crate::time::realtime_ns(),
        }
    }
}

/// Callbacks run per interrupt at most
const MAX_RUN: usize = 256;

/// Shortest programmed delay (an earlier event just interrupts again)
const MIN_DELTA_NS: u64 = 1_000;

/// A high-resolution timer (Linux struct hrtimer)
pub struct HrTimer {
    link: Link,
    /// Expiry on `clock`, ns (under the base lock)
    expires: AtomicU64,
    clock: AtomicU8,
    func: HrFn,
    data: AtomicUsize,
    flags: u8,
    /// The base it is started on (set at its first start, kept)
    base: AtomicPtr<HrBase>,
    /// Queued (under the base lock)
    pending: AtomicBool,
    _pin: PhantomPinned,
}

// SAFETY: links and fields shared with the expiry code are used under
// the base lock or through atomics
unsafe impl Sync for HrTimer {}
unsafe impl Send for HrTimer {}

crate::adapter!(HrAdapter, HrTimer, link);

impl HrTimer {
    /// An inactive timer calling `func` (`flags`: HRTIMER_HARD or 0)
    pub const fn new(func: HrFn, flags: u8) -> Self {
        Self {
            link: Link::new(),
            expires: AtomicU64::new(0),
            clock: AtomicU8::new(0),
            func,
            data: AtomicUsize::new(0),
            flags,
            base: AtomicPtr::new(core::ptr::null_mut()),
            pending: AtomicBool::new(false),
            _pin: PhantomPinned,
        }
    }

    /// The callback's data
    pub fn data(&self) -> usize {
        self.data.load(Ordering::Acquire)
    }

    /// Set the callback's data (before starting)
    pub fn set_data(&self, d: usize) {
        self.data.store(d, Ordering::Release);
    }

    /// Queued and not yet expired (Linux hrtimer_active, roughly)
    pub fn pending(&self) -> bool {
        self.pending.load(Ordering::Acquire)
    }

    /// Its expiry (as last started)
    pub fn expires(&self) -> u64 {
        self.expires.load(Ordering::Relaxed)
    }

    fn home(&self) -> &'static HrBase {
        let b = self.base.load(Ordering::Acquire);
        // SAFETY: bases are static
        if let Some(b) = unsafe { b.as_ref() } {
            return b;
        }
        let cpu = crate::cpu::try_this_id().unwrap_or(0);
        let want = base_of(cpu, self.flags);
        let p = want as *const HrBase as *mut HrBase;
        match self.base.compare_exchange(
            core::ptr::null_mut(),
            p,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => want,
            // SAFETY: as above
            Err(cur) => unsafe { &*cur },
        }
    }

    /// Its base, locked: the one `base` names once the lock is held
    /// (Linux lock_hrtimer_base); None if it was never started
    fn lock_base(&self) -> Option<(&'static HrBase, IrqSpinlockGuard<'static, HrQueues>)> {
        loop {
            // SAFETY: bases are static
            let base = unsafe { self.base.load(Ordering::Acquire).as_ref() }?;
            let q = base.q.lock();
            if core::ptr::eq(self.base.load(Ordering::Acquire), base) {
                return Some((base, q));
            }
        }
    }

    /// (Re)start to fire at `expires` ns on `clock` (Linux
    /// hrtimer_start, absolute mode); true if it was pending
    pub fn start(self: Pin<&Self>, expires: u64, clock: HrClock) -> bool {
        // Interrupts off: no migration or timer interrupt between
        // queueing and programming this CPU's clock event
        let flags = crate::arch::local_irq_save();
        self.home();
        let (mut base, mut q) = self.lock_base().expect("hrtimer: no base");
        let was = q.detach(&self);
        // Linux switch_hrtimer_base: onto this CPU's base, unless its
        // callback is running on the old one (cancel_sync waits there)
        if let Some(cpu) = crate::cpu::try_this_id() {
            let here = base_of(cpu, self.flags);
            let me = &*self as *const HrTimer as *mut HrTimer;
            if !core::ptr::eq(base, here) && base.running.load(Ordering::Acquire) != me {
                self.base
                    .store(here as *const HrBase as *mut HrBase, Ordering::Release);
                drop(q);
                base = here;
                q = here.q.lock();
            }
        }
        self.expires.store(expires, Ordering::Relaxed);
        self.clock.store(clock as u8, Ordering::Relaxed);
        q.insert(&self);
        drop(q);
        let cpu = base_cpu(base);
        if crate::cpu::try_this_id() == Some(cpu) {
            reprogram(cpu);
        }
        crate::arch::local_irq_restore(flags);
        was
    }

    /// Stop it if queued (Linux hrtimer_try_to_cancel without the
    /// running check); true if it was pending
    pub fn cancel(&self) -> bool {
        self.lock_base().is_some_and(|(_, mut q)| q.detach(self))
    }

    /// Stop it and wait out a running callback (Linux hrtimer_cancel);
    /// thread context unless HARD, never from its own callback
    pub fn cancel_sync(&self) -> bool {
        let me = self as *const HrTimer as *mut HrTimer;
        let mut was = false;
        loop {
            let Some((base, mut q)) = self.lock_base() else {
                return was;
            };
            was |= q.detach(self);
            drop(q);
            if base.running.load(Ordering::Acquire) != me {
                return was;
            }
            if self.flags & HRTIMER_HARD != 0 {
                core::hint::spin_loop();
            } else {
                crate::timer::wait_soft(base_cpu(base), || {
                    base.running.load(Ordering::Acquire) != me
                });
            }
        }
    }
}

impl Drop for HrTimer {
    fn drop(&mut self) {
        self.cancel_sync();
    }
}

/// A base's queued timers, each list sorted by expiry
struct HrQueues {
    mono: List<HrAdapter>,
    real: List<HrAdapter>,
}

impl HrQueues {
    fn list(&mut self, clock: u8) -> &mut List<HrAdapter> {
        if clock == HrClock::Realtime as u8 {
            &mut self.real
        } else {
            &mut self.mono
        }
    }

    /// Link `t` in expiry order (after equal ones: FIFO)
    fn insert(&mut self, t: &HrTimer) {
        let e = t.expires.load(Ordering::Relaxed);
        let list = self.list(t.clock.load(Ordering::Relaxed));
        let mut after: Option<*const HrTimer> = None;
        for x in list.iter() {
            if x.expires.load(Ordering::Relaxed) > e {
                break;
            }
            after = Some(x as *const HrTimer);
        }
        // SAFETY: pinned (callers take Pin), on no list
        unsafe {
            match after {
                Some(a) => list.insert_after(a, t),
                None => list.push_front(t),
            }
        }
        t.pending.store(true, Ordering::Release);
    }

    /// Unlink `t` if queued; true if it was
    fn detach(&mut self, t: &HrTimer) -> bool {
        if !t.pending.load(Ordering::Relaxed) {
            return false;
        }
        // SAFETY: a pending timer is on its clock's list
        unsafe { self.list(t.clock.load(Ordering::Relaxed)).remove(t) };
        t.pending.store(false, Ordering::Release);
        true
    }

    /// The first timer due by `mono`/`real` now, unlinked
    fn pop_due(&mut self, mono: u64, real: u64) -> Option<*const HrTimer> {
        let due = |l: &List<HrAdapter>, now: u64| {
            l.front()
                // SAFETY: queued timers are live
                .filter(|&t| unsafe { (*t).expires.load(Ordering::Relaxed) } <= now)
        };
        let t = due(&self.mono, mono).or_else(|| due(&self.real, real))?;
        // SAFETY: as above
        self.detach(unsafe { &*t });
        Some(t)
    }

    /// The earliest expiry, as CLOCK_MONOTONIC ns (`off`: realtime -
    /// monotonic now)
    fn next(&self, off: i128) -> Option<u64> {
        let head = |l: &List<HrAdapter>| {
            l.front()
                // SAFETY: queued timers are live
                .map(|t| unsafe { (*t).expires.load(Ordering::Relaxed) })
        };
        let real = head(&self.real).map(|e| (e as i128 - off).max(0) as u64);
        match (head(&self.mono), real) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

/// A CPU's high-resolution timers of one kind (Linux
/// hrtimer_cpu_base's clock bases, hard or soft)
pub struct HrBase {
    q: IrqSpinlock<HrQueues>,
    running: AtomicPtr<HrTimer>,
}

impl HrBase {
    const fn new() -> Self {
        Self {
            q: IrqSpinlock::new(HrQueues {
                mono: List::new(),
                real: List::new(),
            }),
            running: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// Run the callbacks due now (Linux __hrtimer_run_queues)
    fn run(&self) {
        let mut q = self.q.lock();
        for _ in 0..MAX_RUN {
            let (mono, real) = (crate::time::monotonic_ns(), crate::time::realtime_ns());
            let Some(p) = q.pop_due(mono, real) else {
                break;
            };
            self.running.store(p as *mut HrTimer, Ordering::Release);
            drop(q);
            // SAFETY: a queued timer is live (its drop unlinks it), and
            // stays so while `running` names it (cancel_sync)
            let t = unsafe { &*p };
            (t.func)(t);
            self.running.store(core::ptr::null_mut(), Ordering::Release);
            q = self.q.lock();
        }
    }

    /// A timer is due now
    fn due(&self) -> bool {
        let (mono, real) = (crate::time::monotonic_ns(), crate::time::realtime_ns());
        let q = self.q.lock();
        let due = |l: &List<HrAdapter>, now: u64| {
            l.front()
                // SAFETY: queued timers are live
                .is_some_and(|t| unsafe { (*t).expires.load(Ordering::Relaxed) } <= now)
        };
        due(&q.mono, mono) || due(&q.real, real)
    }
}

/// Per CPU: [HARD, SOFT]
static BASES: PerCpu<[HrBase; 2]> = crate::percpu![[HrBase::new(), HrBase::new()]];

/// Per CPU: due SOFT timers were handed to `ktimers/N`, which has not
/// run them yet (Linux cpu_base->softirq_activated): the clock event
/// is programmed from the HARD timers only meanwhile, or the expired
/// SOFT expiry would make it fire again at once, over and over, and
/// keep the CPU in the interrupt instead of letting `ktimers/N` run
static SOFT_ACTIVATED: PerCpu<AtomicBool> = crate::percpu![AtomicBool::new(false)];

/// The CPU whose base `b` is
fn base_cpu(b: &HrBase) -> u32 {
    let first = BASES.get(0).as_ptr() as usize;
    ((b as *const HrBase as usize - first) / core::mem::size_of::<[HrBase; 2]>()) as u32
}

fn base_of(cpu: u32, flags: u8) -> &'static HrBase {
    &BASES.get(cpu)[if flags & HRTIMER_HARD != 0 { 0 } else { 1 }]
}

/// Program `cpu`'s (this CPU's) clock event for its earliest timer
/// (interrupts off)
fn reprogram(cpu: u32) {
    let mono = crate::time::monotonic_ns();
    let off = crate::time::realtime_ns() as i128 - mono as i128;
    let [hard, soft] = BASES.get(cpu);
    // SOFT timers handed to ktimers/N are its to run (SOFT_ACTIVATED)
    let bases: &[&HrBase] = match SOFT_ACTIVATED.get(cpu).load(Ordering::Relaxed) {
        true => &[hard],
        false => &[hard, soft],
    };
    let next = bases.iter().filter_map(|b| b.q.lock().next(off)).min();
    let delta = next.map_or(TICK_NS, |n| {
        n.saturating_sub(mono).clamp(MIN_DELTA_NS, TICK_NS)
    });
    crate::arch::clockevent_next(delta);
}

/// The scheduler tick of each CPU (Linux tick_sched_timer)
static TICK: PerCpu<HrTimer> = crate::percpu![HrTimer::new(tick_fire, HRTIMER_HARD)];

/// The tick: scheduler work, then the next tick (catching up from now
/// if ticks were lost)
fn tick_fire(t: &HrTimer) {
    crate::task::percpu::scheduler_tick();
    let now = crate::time::monotonic_ns();
    let mut next = t.expires().saturating_add(TICK_NS);
    if next <= now {
        next = now + TICK_NS;
    }
    // SAFETY: a static
    unsafe { Pin::new_unchecked(t) }.start(next, HrClock::Monotonic);
}

/// The clock event interrupt of this CPU (any arch, interrupts off):
/// run the due HARD timers, wake `ktimers/N` for SOFT ones, program the
/// next event. Before the clock runs (early boot) it is a plain tick.
pub fn interrupt() {
    let Some(cpu) = crate::cpu::try_this_id() else {
        // One-shot: without a new event this CPU's clock stops
        crate::arch::clockevent_next(TICK_NS);
        return;
    };
    crate::sync::lockdep::irq_enter();
    if !crate::time::TIMEKEEPER.is_initialized() {
        crate::task::percpu::scheduler_tick();
        crate::arch::clockevent_next(TICK_NS);
        crate::sync::lockdep::irq_exit();
        return;
    }
    let tick = TICK.get(cpu);
    if !tick.pending() && tick.base.load(Ordering::Relaxed).is_null() {
        // First interrupt with a clock: the tick becomes a timer
        let now = crate::time::monotonic_ns();
        // SAFETY: a static
        unsafe { Pin::new_unchecked(tick) }.start(now + TICK_NS, HrClock::Monotonic);
    }
    let [hard, soft] = BASES.get(cpu);
    hard.run();
    // Set or cleared at every interrupt: a due timer cancelled before
    // ktimers/N ran leaves nothing to wait for
    let due = soft.due();
    SOFT_ACTIVATED.get(cpu).store(due, Ordering::Relaxed);
    if due {
        crate::timer::wake_ktimers(cpu);
    }
    reprogram(cpu);
    crate::sync::lockdep::irq_exit();
}

/// A SOFT timer of `cpu` is due (`ktimers/N`)
pub fn soft_due(cpu: u32) -> bool {
    BASES.get(cpu)[1].due()
}

/// Run `cpu`'s due SOFT timers (`ktimers/N` of `cpu`, process
/// context), then program the clock event with the SOFT timers counted
/// again (Linux hrtimer_run_softirq)
pub fn run_soft(cpu: u32) {
    BASES.get(cpu)[1].run();
    let flags = crate::arch::local_irq_save();
    SOFT_ACTIVATED.get(cpu).store(false, Ordering::Relaxed);
    reprogram(cpu);
    crate::arch::local_irq_restore(flags);
}

/// Sleep until woken or `deadline` ns on `clock` passes (Linux
/// schedule_hrtimeout): the caller set its sleep state; true if the
/// deadline passed. `None` sleeps until woken.
pub fn schedule_hrtimeout(deadline: Option<u64>, clock: HrClock) -> bool {
    let Some(d) = deadline else {
        crate::task::percpu::schedule();
        return false;
    };
    if clock.now() >= d {
        crate::task::percpu::set_current_state(crate::task::percpu::SleepState::Running);
        return true;
    }
    let t = core::pin::pin!(HrTimer::new(wakeup_fire, HRTIMER_HARD));
    t.set_data(&*crate::task::percpu::current() as *const _ as usize);
    t.as_ref().start(d, clock);
    crate::task::percpu::schedule();
    t.cancel_sync();
    clock.now() >= d
}

/// A sleep's deadline passed: wake its task
fn wakeup_fire(t: &HrTimer) {
    // SAFETY: the sleeper, which cancels the timer before it returns
    let task = unsafe { &*(t.data() as *const crate::task::percpu::KernelTask) };
    crate::task::percpu::try_to_wake_up(task, crate::task::percpu::WakeMode::Any);
}

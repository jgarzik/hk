//! Per-CPU timer wheel (Linux kernel/time/timer.c, much reduced)
//!
//! A [`TimerList`] (Linux timer_list) is embedded in its owner, pinned
//! (a static, a heap object, or the stack of a sleeper), and fires at a
//! jiffy (`task::percpu::get_ticks`, TICK_MS = 10 ms), optionally not
//! before a CLOCK_MONOTONIC instant (`mod_timer_ns`). Each CPU has two
//! bases, each a 64-slot hashed wheel:
//! - HARD: callbacks run in that CPU's tick interrupt, with interrupts
//!   off; they may only wake tasks (timeouts of sleepers);
//! - SOFT: callbacks run in the CPU's `ktimers/N` thread, in process
//!   context (they may send signals, take sleeping locks, allocate);
//!   the tick only wakes the thread when one is due.
//!
//! A timer stays on the base of the CPU that first armed it. Callbacks
//! run with the base lock dropped and `running` set; `del_timer_sync`
//! waits until the callback is done (spinning for HARD, sleeping on the
//! base's wait queue for SOFT), and dropping a timer does that too, so
//! its owner may go once it returns. A callback may re-arm its own
//! timer but must not `del_timer_sync` it.
//!
//! Locking: `TimerBase.wheel` is an IrqSpinlock leaf (only the wheel's
//! lists and the timers' `expires`/`pending` under it); callbacks run
//! with no timer lock held.

use alloc::boxed::Box;
use core::marker::PhantomPinned;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering};

use crate::arch::IrqSpinlock;
use crate::cpu::PerCpu;
use crate::list::{Link, List};
use crate::task::percpu::{TICK_NS, get_ticks};
use crate::waitqueue::WaitQueue;

/// A timer callback (Linux timer_list.function); the owner is reached
/// through `data` (or the timer's place in it)
pub type TimerFn = fn(&TimerList);

/// Callback runs in the tick interrupt (Linux TIMER_IRQSAFE / hard
/// expiry); the default is the CPU's `ktimers/N` thread
pub const TIMER_HARD: u8 = 1;

/// Wheel slots per base
const WHEEL: usize = 64;

/// Callbacks run per pass at most (a pass resumes at the next tick)
const MAX_RUN: usize = 256;

/// A timer (Linux struct timer_list)
pub struct TimerList {
    link: Link,
    /// Expiry in jiffies (under the base lock)
    expires: AtomicU64,
    /// Not before this CLOCK_MONOTONIC ns (0: no bound; `mod_timer_ns`)
    not_before: AtomicU64,
    func: TimerFn,
    /// The callback's data (an owner pointer)
    data: AtomicUsize,
    flags: u8,
    /// The base it is armed on (set at its first arm, kept)
    base: AtomicPtr<TimerBase>,
    /// On the wheel (under the base lock)
    pending: AtomicBool,
    /// Its wheel slot while pending (under the base lock)
    slot: AtomicUsize,
    _pin: PhantomPinned,
}

// SAFETY: links and fields shared with the expiry code are used under
// the base lock or through atomics
unsafe impl Sync for TimerList {}
unsafe impl Send for TimerList {}

crate::adapter!(TimerAdapter, TimerList, link);

impl TimerList {
    /// An unarmed timer calling `func` (`flags`: TIMER_HARD or 0)
    pub const fn new(func: TimerFn, flags: u8) -> Self {
        Self {
            link: Link::new(),
            expires: AtomicU64::new(0),
            not_before: AtomicU64::new(0),
            func,
            data: AtomicUsize::new(0),
            flags,
            base: AtomicPtr::new(core::ptr::null_mut()),
            pending: AtomicBool::new(false),
            slot: AtomicUsize::new(0),
            _pin: PhantomPinned,
        }
    }

    /// The callback's data
    pub fn data(&self) -> usize {
        self.data.load(Ordering::Acquire)
    }

    /// Set the callback's data (before arming)
    pub fn set_data(&self, d: usize) {
        self.data.store(d, Ordering::Release);
    }

    /// Armed and not yet expired (Linux timer_pending)
    pub fn pending(&self) -> bool {
        self.pending.load(Ordering::Acquire)
    }

    /// Its base: the one it was first armed on, else this CPU's
    fn home(&self) -> &'static TimerBase {
        let b = self.base.load(Ordering::Acquire);
        // SAFETY: bases are static
        if let Some(b) = unsafe { b.as_ref() } {
            return b;
        }
        let want = base_of(crate::cpu::try_this_id().unwrap_or(0), self.flags);
        let want = if want.ready() {
            want
        } else {
            base_of(0, self.flags)
        };
        let p = want as *const TimerBase as *mut TimerBase;
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

    /// (Re)arm to fire at jiffy `expires` (Linux mod_timer); true if it
    /// was pending
    pub fn mod_timer(self: Pin<&Self>, expires: u64) -> bool {
        self.not_before.store(0, Ordering::Relaxed);
        self.arm(expires)
    }

    /// (Re)arm to fire once CLOCK_MONOTONIC reaches `deadline_ns`, at
    /// tick granularity, never early
    pub fn mod_timer_ns(self: Pin<&Self>, deadline_ns: u64) {
        let now = crate::time::monotonic_ns();
        let ticks = deadline_ns.saturating_sub(now).div_ceil(TICK_NS);
        self.not_before.store(deadline_ns.max(1), Ordering::Relaxed);
        // The current jiffy is partly over: one more never fires early
        self.arm(get_ticks().saturating_add(ticks).saturating_add(1));
    }

    fn arm(self: Pin<&Self>, expires: u64) -> bool {
        let base = self.home();
        let mut w = base.wheel.lock();
        let was = w.detach(&self);
        w.insert(&self, expires);
        was
    }

    /// Disarm (Linux del_timer / timer_delete); true if it was pending.
    /// A callback already running may still be running.
    pub fn del_timer(&self) -> bool {
        // SAFETY: bases are static
        let Some(base) = (unsafe { self.base.load(Ordering::Acquire).as_ref() }) else {
            return false;
        };
        base.wheel.lock().detach(self)
    }

    /// Disarm and wait for a running callback to finish (Linux
    /// del_timer_sync / timer_delete_sync); thread context unless HARD,
    /// never from its own callback
    pub fn del_timer_sync(&self) -> bool {
        // SAFETY: bases are static
        let Some(base) = (unsafe { self.base.load(Ordering::Acquire).as_ref() }) else {
            return false;
        };
        let me = self as *const TimerList as *mut TimerList;
        let mut was = false;
        loop {
            was |= base.wheel.lock().detach(self);
            if base.running.load(Ordering::Acquire) != me {
                return was;
            }
            if self.flags & TIMER_HARD != 0 {
                // Its callback runs in another CPU's tick, interrupts off
                core::hint::spin_loop();
            } else {
                base.wq
                    .wait_event(|| base.running.load(Ordering::Acquire) != me);
            }
        }
    }
}

impl Drop for TimerList {
    fn drop(&mut self) {
        self.del_timer_sync();
    }
}

/// One base's timers: `WHEEL` lists hashed by expiry jiffy
struct Wheel {
    /// Allocated at CPU bring-up (`init_cpu`)
    slots: Option<Box<[List<TimerAdapter>; WHEEL]>>,
    /// The next jiffy to process
    clk: u64,
}

impl Wheel {
    fn slot(&mut self, i: usize) -> &mut List<TimerAdapter> {
        let s = self.slots.as_mut().expect("timer base not initialized");
        &mut s[i]
    }

    /// Link `t` to fire at `expires` (an expiry already past goes in
    /// the slot processed next)
    fn insert(&mut self, t: &TimerList, expires: u64) {
        t.expires.store(expires, Ordering::Relaxed);
        let i = (expires.max(self.clk) % WHEEL as u64) as usize;
        t.slot.store(i, Ordering::Relaxed);
        // SAFETY: pinned (callers take Pin), unlinked first
        unsafe { self.slot(i).push_back(t) };
        t.pending.store(true, Ordering::Release);
    }

    /// Unlink `t` if pending; true if it was
    fn detach(&mut self, t: &TimerList) -> bool {
        if !t.pending.load(Ordering::Relaxed) {
            return false;
        }
        let i = t.slot.load(Ordering::Relaxed);
        // SAFETY: a pending timer is on its recorded slot
        unsafe { self.slot(i).remove(t) };
        t.pending.store(false, Ordering::Release);
        true
    }

    /// The first timer due by jiffy `now` in the slots from `clk` on,
    /// moving `clk` past the slots with none left
    fn due(&mut self, now: u64) -> Option<*const TimerList> {
        self.slots.as_ref()?;
        let end = now.min(self.clk.saturating_add(WHEEL as u64 - 1));
        while self.clk <= end {
            let i = (self.clk % WHEEL as u64) as usize;
            let found = self
                .slot(i)
                .iter()
                .find(|t| t.expires.load(Ordering::Relaxed) <= now)
                .map(|t| t as *const TimerList);
            if found.is_some() {
                return found;
            }
            self.clk += 1;
        }
        if self.clk <= now {
            self.clk = now + 1;
        }
        None
    }

    /// Some timer is due by `now` (without moving `clk`)
    fn any_due(&mut self, now: u64) -> bool {
        let Some(s) = self.slots.as_ref() else {
            return false;
        };
        let n = now
            .saturating_sub(self.clk)
            .saturating_add(1)
            .min(WHEEL as u64);
        (0..n).any(|k| {
            s[((self.clk + k) % WHEEL as u64) as usize]
                .iter()
                .any(|t| t.expires.load(Ordering::Relaxed) <= now)
        })
    }
}

/// A CPU's timers of one kind (Linux struct timer_base)
pub struct TimerBase {
    wheel: IrqSpinlock<Wheel>,
    /// The timer whose callback runs now (Linux running_timer)
    running: AtomicPtr<TimerList>,
    /// SOFT: `ktimers/N` waits here for due timers, `del_timer_sync`
    /// for a callback to end
    wq: WaitQueue,
}

impl TimerBase {
    const fn new() -> Self {
        Self {
            wheel: IrqSpinlock::new(Wheel {
                slots: None,
                clk: 0,
            }),
            running: AtomicPtr::new(core::ptr::null_mut()),
            wq: WaitQueue::new(),
        }
    }

    fn ready(&self) -> bool {
        self.wheel.lock().slots.is_some()
    }

    /// Run the callbacks due by jiffy `now` (Linux __run_timers)
    fn run(&self, now: u64) {
        let mut w = self.wheel.lock();
        for _ in 0..MAX_RUN {
            let Some(p) = w.due(now) else { break };
            // SAFETY: a pending timer is live (its drop unlinks it)
            let t = unsafe { &*p };
            w.detach(t);
            let nb = t.not_before.load(Ordering::Relaxed);
            if nb != 0 && crate::time::monotonic_ns() < nb {
                // The tick ran ahead of the clock: next jiffy
                w.insert(t, now + 1);
                continue;
            }
            self.running.store(p as *mut TimerList, Ordering::Release);
            drop(w);
            (t.func)(t);
            self.running.store(core::ptr::null_mut(), Ordering::Release);
            w = self.wheel.lock();
        }
    }
}

/// Advance a periodic expiry past `now` (Linux hrtimer_forward): the
/// periods that ended (at least one) and the next expiry (None at or
/// past KTIME_MAX: never)
pub fn forward(expires: u64, interval: u64, now: u64) -> (u64, Option<u64>) {
    let missed = now
        .saturating_sub(expires)
        .checked_div(interval)
        .unwrap_or(0)
        + 1;
    let next = missed
        .checked_mul(interval)
        .and_then(|d| expires.checked_add(d))
        .filter(|&n| n < crate::time::KTIME_MAX);
    (missed, next)
}

/// Per CPU: [HARD, SOFT]
static BASES: PerCpu<[TimerBase; 2]> = crate::percpu![[TimerBase::new(), TimerBase::new()]];

fn base_of(cpu: u32, flags: u8) -> &'static TimerBase {
    &BASES.get(cpu)[if flags & TIMER_HARD != 0 { 0 } else { 1 }]
}

/// Give `cpu` its wheels (bring-up, thread context)
pub fn init_cpu(cpu: u32) {
    for b in BASES.get(cpu) {
        let slots = Box::new([const { List::new() }; WHEEL]);
        let mut w = b.wheel.lock();
        if w.slots.is_none() {
            w.slots = Some(slots);
            w.clk = get_ticks();
        }
    }
}

/// Tick work of this CPU's timers (interrupt context): run the due
/// HARD callbacks, wake `ktimers/N` if a SOFT one is due
pub fn run_local() {
    let Some(cpu) = crate::cpu::try_this_id() else {
        return;
    };
    let now = get_ticks();
    let [hard, soft] = BASES.get(cpu);
    hard.run(now);
    if soft.wheel.lock().any_due(now) {
        soft.wq.wake_all();
    }
}

/// `ktimers/N`: runs CPU N's SOFT timer and hrtimer callbacks (Linux
/// ktimers / the TIMER and HRTIMER softirqs)
fn ktimers(cpu: usize) {
    let cpu = cpu as u32;
    let soft = &BASES.get(cpu)[1];
    loop {
        soft.wq
            .wait_event(|| soft.wheel.lock().any_due(get_ticks()) || crate::hrtimer::soft_due(cpu));
        soft.run(get_ticks());
        crate::hrtimer::run_soft(cpu);
        // `del_timer_sync` / `cancel_sync` waiters look again
        soft.wq.wake_all();
    }
}

/// Wake `ktimers/N` of `cpu` (a SOFT hrtimer is due; any context)
pub fn wake_ktimers(cpu: u32) {
    BASES.get(cpu)[1].wq.wake_all();
}

/// Sleep until `cond` holds, woken whenever `ktimers/N` of `cpu`
/// finishes a pass (a SOFT callback cancelled with `cancel_sync`)
pub fn wait_soft(cpu: u32, cond: impl FnMut() -> bool) {
    BASES.get(cpu)[1].wq.wait_event(cond);
}

/// Start `ktimers/N` on every CPU with a scheduler
pub fn start_ktimers() {
    for cpu in 0..crate::cpu::nr_cpu_ids() {
        if !crate::task::percpu::cpu_has_scheduler(cpu) {
            continue;
        }
        let name = alloc::format!("ktimers/{}", cpu);
        if let Err(e) = crate::task::kthread::kthread_run_prio(
            &name,
            ktimers,
            cpu as usize,
            Some(cpu),
            crate::task::PRIORITY_HIGH,
        ) {
            crate::printkln!("timer: cannot start {}: {:?}", name, e);
        }
    }
}

/// A one-shot timer that tracks its earliest wanted deadline (for
/// subsystems that keep their own per-object deadlines and need one
/// kernel timer: neighbour tables, IP reassembly, TCP).
///
/// The callback must call [`Alarm::fired`] before it scans its state and
/// then re-arm for the earliest remaining deadline, so a deadline set
/// concurrently is never lost. Locking: `st` is a `crate::sync::spin::Mutex`
/// taken in thread context only and held across arming (-> the timer
/// base's IrqSpinlock); the callback runs in `ktimers/N`.
pub struct Alarm {
    /// Armed deadline (ns; u64::MAX: none)
    st: crate::sync::spin::Mutex<u64>,
    timer: TimerList,
    cb: fn(u64),
}

impl Alarm {
    pub const fn new(cb: fn(u64)) -> Self {
        Self {
            st: crate::sync::spin::Mutex::new(u64::MAX),
            timer: TimerList::new(alarm_fire, 0),
            cb,
        }
    }

    /// Fire no later than `at_ns` (monotonic)
    pub fn arm(&'static self, at_ns: u64) {
        let mut s = self.st.lock();
        if *s <= at_ns && self.timer.pending() {
            return;
        }
        *s = at_ns;
        self.timer.set_data(self as *const Alarm as usize);
        Pin::static_ref(&self.timer).mod_timer_ns(at_ns);
    }

    /// The timer ran (call first thing in the callback)
    pub fn fired(&self) {
        *self.st.lock() = u64::MAX;
    }
}

/// An `Alarm`'s timer expired: its callback (the alarm is static)
fn alarm_fire(t: &TimerList) {
    // SAFETY: set by `arm` to the static alarm owning `t`
    let a = unsafe { &*(t.data() as *const Alarm) };
    (a.cb)(0);
}

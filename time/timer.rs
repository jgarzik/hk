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
//! timer, and may drop the timer's owner (the timer with it): from its
//! own callback `del_timer_sync` does not wait (the base records the
//! task running it, and touches the timer no more once it returns),
//! as Linux frees a socket from its timer's final sock_put.
//! [`ArcTimer`] is a timer embedded in an `Arc`-owned object whose
//! pending arm holds a reference to it (Linux sk_reset_timer, neigh_hold
//! in neigh_add_timer); its callback releases that reference at its
//! end, so the owner's last drop never finds it pending or running and
//! only disarms, in any context (Linux neigh_destroy, sk_free).
//!
//! Locking: `TimerBase.wheel` is an IrqSpinlock leaf over the wheel's
//! lists, `running`/`runner`, and each armed timer's `pos` (expiry,
//! bound, slot) and `pending` (read locklessly by `pending`, Linux
//! timer_pending); callbacks run with no timer lock held.

use crate::util::kalloc::box_nofail;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::marker::PhantomPinned;
use core::mem::ManuallyDrop;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering};

use crate::sync::waitqueue::WaitQueue;
use crate::sync::{IrqSpinlock, LockedCell};
use crate::task::percpu::{TICK_NS, get_ticks};
use crate::util::list::{Link, List};

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

/// A timer's place on its wheel (Linux timer_list.expires and the
/// wheel index in its flags)
#[derive(Clone, Copy)]
struct WheelPos {
    /// Expiry in jiffies
    expires: u64,
    /// Not before this CLOCK_MONOTONIC ns (0: no bound; `mod_timer_ns`),
    /// set with the expiry
    not_before: u64,
    /// Its slot while pending
    slot: usize,
}

/// A timer (Linux struct timer_list)
pub struct TimerList {
    link: Link,
    /// Owned by its base's wheel lock (`Wheel::pos`)
    pos: LockedCell<WheelPos>,
    func: TimerFn,
    /// The callback's data (an owner pointer)
    data: AtomicUsize,
    flags: u8,
    /// The base it is armed on (set at its first arm, kept)
    base: AtomicPtr<TimerBase>,
    /// On the wheel: changed under the base lock, read without it
    /// (`pending`, Linux timer_pending)
    pending: AtomicBool,
    _pin: PhantomPinned,
}

crate::adapter!(TimerAdapter, TimerList, link);

impl TimerList {
    /// An unarmed timer calling `func` (`flags`: TIMER_HARD or 0)
    pub const fn new(func: TimerFn, flags: u8) -> Self {
        Self {
            link: Link::new(),
            pos: LockedCell::new(WheelPos {
                expires: 0,
                not_before: 0,
                slot: 0,
            }),
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
        if let Some(b) = base_ref(self.base.load(Ordering::Acquire)) {
            return b;
        }
        let want = base_of(crate::cpu::try_this_id().unwrap_or(0), self.flags);
        let want = if want.ready() {
            want
        } else {
            base_of(0, self.flags)
        };
        let p = core::ptr::from_ref::<TimerBase>(want).cast_mut();
        match self.base.compare_exchange(
            core::ptr::null_mut(),
            p,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => want,
            Err(cur) => base_ref(cur).expect("a stored base is never null"),
        }
    }

    /// (Re)arm to fire at jiffy `expires` (Linux mod_timer); true if it
    /// was pending
    pub fn mod_timer(self: Pin<&Self>, expires: u64) -> bool {
        self.arm(expires, 0)
    }

    /// (Re)arm to fire once CLOCK_MONOTONIC reaches `deadline_ns`, at
    /// tick granularity, never early; true if it was pending
    pub fn mod_timer_ns(self: Pin<&Self>, deadline_ns: u64) -> bool {
        let now = crate::time::monotonic_ns();
        let ticks = deadline_ns.saturating_sub(now).div_ceil(TICK_NS);
        // The current jiffy is partly over: one more never fires early
        let expires = get_ticks().saturating_add(ticks).saturating_add(1);
        self.arm(expires, deadline_ns.max(1))
    }

    /// Expiry and lower bound change together under the base lock, so
    /// a `run` racing a re-arm sees one arm's pair, never a mix (a
    /// jiffy-armed timer firing early on a stale bound, or the reverse)
    fn arm(self: Pin<&Self>, expires: u64, not_before: u64) -> bool {
        let base = self.home();
        let mut w = base.wheel.lock();
        let was = w.detach(&self);
        w.insert(&self, expires, not_before);
        was
    }

    /// Disarm (Linux del_timer / timer_delete); true if it was pending.
    /// A callback already running may still be running.
    pub fn del_timer(&self) -> bool {
        let Some(base) = base_ref(self.base.load(Ordering::Acquire)) else {
            return false;
        };
        base.wheel.lock().detach(self)
    }

    /// Disarm and wait for a running callback to finish (Linux
    /// del_timer_sync / timer_delete_sync); thread context unless HARD.
    /// From its own callback (the owner dropped there) it only disarms:
    /// the callback is this task, and the base does not touch the timer
    /// after it returns.
    pub fn del_timer_sync(&self) -> bool {
        let Some(base) = base_ref(self.base.load(Ordering::Acquire)) else {
            return false;
        };
        let me = core::ptr::from_ref::<TimerList>(self).addr();
        let mut was = false;
        // Linux timer_delete_sync: try_to_del_timer_sync under the base
        // lock, then wait for the callback with the lock dropped
        loop {
            let mut w = base.wheel.lock();
            was |= w.detach(self);
            if w.running != me || w.runner == crate::task::percpu::current_tid() {
                return was;
            }
            drop(w);
            if self.flags & TIMER_HARD != 0 {
                // Its callback runs in another CPU's tick, interrupts off
                core::hint::spin_loop();
            } else {
                base.wq.wait_event(|| base.wheel.lock().running != me);
            }
        }
    }
}

impl Drop for TimerList {
    fn drop(&mut self) {
        self.del_timer_sync();
    }
}

/// One base's timers: `WHEEL` lists hashed by expiry jiffy, and the
/// callback running (Linux struct timer_base under base->lock)
struct Wheel {
    /// Allocated at CPU bring-up (`init_cpu`)
    slots: Option<Box<[List<TimerAdapter>; WHEEL]>>,
    /// The next jiffy to process
    clk: u64,
    /// Address of the timer whose callback runs now, 0: none (Linux
    /// running_timer); compared only, never dereferenced
    running: usize,
    /// The task running it (valid while `running` is set): a
    /// `del_timer_sync` by that task is inside the callback
    runner: u64,
}

impl Wheel {
    fn slot(&mut self, i: usize) -> &mut List<TimerAdapter> {
        let s = self.slots.as_mut().expect("timer base not initialized");
        &mut s[i]
    }

    /// `t`'s base is this wheel's (its `pos` is ours to touch)
    fn owns(&self, t: &TimerList) -> bool {
        base_ref(t.base.load(Ordering::Acquire)).is_some_and(|b| b.wheel.owns(self))
    }

    /// `t`'s place on this wheel (panics unless armed on it)
    fn pos(&self, t: &TimerList) -> WheelPos {
        assert!(self.owns(t), "timer: not on this base");
        // SAFETY: `self` is the data of `t`'s base lock (checked), held
        // by the guard it is borrowed from
        unsafe { t.pos.get(self) }
    }

    fn set_pos(&mut self, t: &TimerList, p: WheelPos) {
        assert!(self.owns(t), "timer: not on this base");
        // SAFETY: as in `pos`, borrowed mutably
        unsafe { t.pos.set(self, p) };
    }

    /// Link `t` to fire at `expires`, not before `not_before` (an
    /// expiry already past goes in the slot processed next)
    fn insert(&mut self, t: &TimerList, expires: u64, not_before: u64) {
        let slot = (expires.max(self.clk) % WHEEL as u64) as usize;
        self.set_pos(
            t,
            WheelPos {
                expires,
                not_before,
                slot,
            },
        );
        // SAFETY: pinned (callers take Pin), unlinked first
        unsafe { self.slot(slot).push_back(t) };
        t.pending.store(true, Ordering::Release);
    }

    /// Unlink `t` if pending; true if it was
    fn detach(&mut self, t: &TimerList) -> bool {
        if !t.pending.load(Ordering::Relaxed) {
            return false;
        }
        let i = self.pos(t).slot;
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
            let found = self.due_in((self.clk % WHEEL as u64) as usize, now);
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

    /// The first timer in slot `i` due by `now`
    fn due_in(&self, i: usize, now: u64) -> Option<*const TimerList> {
        let s = self.slots.as_ref()?;
        s[i].iter()
            .find(|t| self.pos(t).expires <= now)
            .map(core::ptr::from_ref::<TimerList>)
    }

    /// Some timer is due by `now` (without moving `clk`)
    fn any_due(&self, now: u64) -> bool {
        let n = now
            .saturating_sub(self.clk)
            .saturating_add(1)
            .min(WHEEL as u64);
        (0..n).any(|k| {
            self.due_in(((self.clk + k) % WHEEL as u64) as usize, now)
                .is_some()
        })
    }
}

/// A CPU's timers of one kind (Linux struct timer_base)
pub struct TimerBase {
    wheel: IrqSpinlock<Wheel>,
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
                running: 0,
                runner: 0,
            }),
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
            let nb = w.pos(t).not_before;
            if nb != 0 && crate::time::monotonic_ns() < nb {
                // The tick ran ahead of the clock: next jiffy
                w.insert(t, now + 1, nb);
                continue;
            }
            // Linux __run_timers / expire_timers: running_timer set
            // under the lock, the lock dropped for the callback, cleared
            // once it is taken again
            w.running = p.addr();
            w.runner = crate::task::percpu::current_tid();
            drop(w);
            // `t` may be freed by its callback: not touched after it
            (t.func)(t);
            w = self.wheel.lock();
            w.running = 0;
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

crate::percpu! {
    /// Per CPU: [HARD, SOFT]
    static BASES: [TimerBase; 2] = [TimerBase::new(), TimerBase::new()];
}

fn base_of(cpu: u32, flags: u8) -> &'static TimerBase {
    &BASES.get(cpu)[if flags & TIMER_HARD != 0 { 0 } else { 1 }]
}

/// Give `cpu` its wheels (bring-up, thread context)
pub fn init_cpu(cpu: u32) {
    for b in BASES.get(cpu) {
        // CPU bring-up: failure cannot be reported
        let slots = box_nofail([const { List::new() }; WHEEL]);
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
        soft.wq.wait_event(|| {
            soft.wheel.lock().any_due(get_ticks()) || crate::time::hrtimer::soft_due(cpu)
        });
        soft.run(get_ticks());
        crate::time::hrtimer::run_soft(cpu);
        // `del_timer_sync` / `cancel_sync` waiters look again
        soft.wq.wake_all();
        // A scheduling point between passes: callbacks due again at
        // once cannot keep this CPU's tasks off it
        crate::task::percpu::cond_resched();
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

/// A SOFT timer embedded in an `Arc`-owned object, its callback given
/// a strong reference to that object (Linux sk_reset_timer /
/// sk_stop_timer around a timer_list in struct sock): a pending arm
/// holds one reference, which the callback receives and drops at its
/// end, so the owner lives while the timer can fire, and the owner's
/// last reference may go in its own timer's callback.
///
/// Its drop does not wait for a callback (Linux neigh_destroy and
/// sk_free only disarm): it runs at the owner's last drop, and a pending
/// arm or a running callback still holds a reference until the base no
/// longer touches the timer (`arc_timer_fire` reads nothing of it after
/// the callback, the base only clears `running`, an address it never
/// dereferences). So the owner may go anywhere, e.g. in `rcuc/N` after
/// `kfree_rcu`.
///
/// # Invariants
/// `timer` is the first field (`repr(C)`; `ManuallyDrop` is
/// transparent), so a `&TimerList` the base passes to
/// [`arc_timer_fire`] is this `ArcTimer`'s. While `timer` is
/// pending its data is `Arc::into_raw` of the owning `Arc<T>`, whose
/// reference the pending arm holds; at most one such reference per
/// pending period (taken when an arm finds it idle, given back by the
/// callback or by `stop` when it disarms it).
#[repr(C)]
pub struct ArcTimer<T> {
    /// Never dropped: [`ArcTimer`]'s drop disarms it, without
    /// `del_timer_sync`'s wait
    timer: ManuallyDrop<TimerList>,
    func: fn(Arc<T>),
    _owner: core::marker::PhantomData<fn(Arc<T>)>,
}

impl<T: Send + Sync> ArcTimer<T> {
    /// An idle timer calling `func` in `ktimers/N`
    pub const fn new(func: fn(Arc<T>)) -> Self {
        Self {
            timer: ManuallyDrop::new(TimerList::new(arc_timer_fire::<T>, 0)),
            func,
            _owner: core::marker::PhantomData,
        }
    }

    /// (Re)arm for CLOCK_MONOTONIC `at_ns` (Linux sk_reset_timer: an
    /// idle timer takes a reference to `owner`); true if it was pending.
    /// Panics unless this timer is a field of `*owner`.
    pub fn reset(&self, owner: &Arc<T>, at_ns: u64) -> bool {
        let base = Arc::as_ptr(owner).addr();
        let me = core::ptr::from_ref(self).addr();
        assert!(
            me >= base && me + size_of::<Self>() <= base + size_of::<T>(),
            "ArcTimer: not a field of its owner"
        );
        self.timer.set_data(Arc::as_ptr(owner).addr());
        // SAFETY: a field of `*owner`, which an `Arc` never moves; it is
        // moved or reused only through `&mut T` (`Arc::get_mut`), which
        // the reference a pending arm or a running callback holds rules
        // out until it is idle again
        let t = unsafe { Pin::new_unchecked(&*self.timer) };
        // INVARIANT: the reference an idle timer's arm hands over is
        // taken before arming: the timer may fire on another CPU at once
        // and its callback consumes it
        let raw = Arc::into_raw(owner.clone());
        let was = t.mod_timer_ns(at_ns);
        if was {
            // SAFETY: `raw` is the reference just taken; it was pending
            // already and keeps its own, so this one goes back unused
            drop(unsafe { Arc::from_raw(raw) });
        }
        was
    }

    /// Disarm (Linux sk_stop_timer); true if it was pending (its
    /// reference dropped). A running callback may still run.
    pub fn stop(&self) -> bool {
        if !self.timer.del_timer() {
            return false;
        }
        // SAFETY: it was pending, so its data is the reference the arm
        // took (type invariant), given back once here
        drop(unsafe { Arc::from_raw(self.timer.data() as *const T) });
        true
    }

    /// Disarm and wait for a running callback (Linux
    /// sk_stop_timer_sync); thread context, may sleep
    pub fn stop_sync(&self) -> bool {
        let was = self.timer.del_timer_sync();
        if was {
            // SAFETY: as in `stop`
            drop(unsafe { Arc::from_raw(self.timer.data() as *const T) });
        }
        was
    }

    /// Armed and not yet fired (Linux timer_pending)
    pub fn pending(&self) -> bool {
        self.timer.pending()
    }
}

impl<T> Drop for ArcTimer<T> {
    /// The owner's last reference went (Linux neigh_destroy's
    /// neigh_del_timer): none is pending, since an arm holds one, and no
    /// callback runs that the base still touches, since it holds one
    /// until the base is done with the timer. Disarm only, as Linux
    /// warns of the impossible pending case; never wait.
    fn drop(&mut self) {
        if self.timer.del_timer() {
            crate::printkln!("timer: ArcTimer dropped while pending");
        }
    }
}

/// An [`ArcTimer`] expired: its callback, with the arm's reference
fn arc_timer_fire<T: Send + Sync>(t: &TimerList) {
    // SAFETY: the base calls this only for an `ArcTimer<T>`'s timer
    // (its `new`), the first field of a `repr(C)` struct
    let at = unsafe { &*core::ptr::from_ref(t).cast::<ArcTimer<T>>() };
    // SAFETY: it was pending until the base detached it, so its data is
    // the reference its arm took (type invariant), handed over here
    let owner = unsafe { Arc::from_raw(t.data() as *const T) };
    // INVARIANT: `at` and `t` are not touched once `owner` is handed
    // over: the callback may drop the last reference
    let func = at.func;
    func(owner);
}

/// Boot self-test of [`ArcTimer`]'s drop: a callback hands its owner's
/// last reference to `kfree_rcu` and runs on until the owner is gone,
/// which happens in `rcuc/N`, preemption off, while the base still runs
/// that callback (Linux: a neighbour unlinked and released while its
/// timer runs). The drop must not wait for the callback (a sleep there,
/// and here it would never end before the callback gives up). True if
/// the owner went in atomic context while its callback still ran.
pub fn selftest() -> bool {
    use crate::sync::rcu::{RcuHead, kfree_rcu, rcu_barrier};
    static WQ: WaitQueue = WaitQueue::new();
    /// The owner went: 1, in atomic context: 2
    static GONE: AtomicU64 = AtomicU64::new(0);
    /// The callback saw the owner go: 1; gave up waiting: 2
    static SEEN: AtomicU64 = AtomicU64::new(0);
    /// Dropped after `timer` (fields drop in order)
    struct Gone;
    impl Drop for Gone {
        fn drop(&mut self) {
            let atomic = crate::arch::preempt_count() > 0;
            GONE.store(1 + u64::from(atomic), Ordering::Release);
            WQ.wake_all();
        }
    }
    struct Probe {
        timer: ArcTimer<Probe>,
        rcu: RcuHead,
        _gone: Gone,
    }
    crate::rcu_head!(Probe, rcu);
    fn fire(p: Arc<Probe>) {
        kfree_rcu(p);
        let left = WQ.wait_event_timeout(|| GONE.load(Ordering::Acquire) != 0, 500);
        SEEN.store(if left > 0 { 1 } else { 2 }, Ordering::Release);
        WQ.wake_all();
    }
    let probe = crate::util::kalloc::try_arc(Probe {
        timer: ArcTimer::new(fire),
        rcu: RcuHead::new(),
        _gone: Gone,
    });
    let Ok(p) = probe else {
        return false;
    };
    p.timer.reset(&p, crate::time::monotonic_ns());
    drop(p);
    WQ.wait_event_timeout(|| SEEN.load(Ordering::Acquire) != 0, 1000);
    rcu_barrier();
    SEEN.load(Ordering::Acquire) == 1 && GONE.load(Ordering::Acquire) == 2
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
        self.timer
            .set_data(core::ptr::from_ref::<Alarm>(self) as usize);
        let _ = Pin::static_ref(&self.timer).mod_timer_ns(at_ns);
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

/// The base `p` names (null: none)
///
/// # Invariants
/// `base` fields hold null or the address of a static per-CPU base: only
/// `home` stores one, from `base_of`.
fn base_ref(p: *mut TimerBase) -> Option<&'static TimerBase> {
    // SAFETY: null or a static base (above)
    unsafe { p.as_ref() }
}

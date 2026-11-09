//! Sleeping reader/writer semaphore (Linux `struct rw_semaphore`,
//! kernel/locking/rwsem.c)
//!
//! Many readers or one writer, guarding a `T` (`()` for a semaphore that
//! guards what its owner says, like `i_rwsem`). As Linux, one atomic
//! count holds the writer bit, `WAITERS` and `HANDOFF` flags and the
//! reader count: an uncontended acquire or release is one atomic op.
//! The FIFO wait list sits under a spin lock (Linux wait_lock: a leaf,
//! never held across a sleep, its lockdep class the semaphore's
//! construction site), taken only when the count says so. Wakeups are
//! queued on a `WakeQ` under it and issued after it is dropped. Linux's
//! policy, without optimistic spinning (hk cannot tell whether an owner
//! runs on another CPU):
//!
//! - A reader or writer takes a free lock only while nobody waits
//!   (Linux fast paths); otherwise it queues at the tail. A reader may
//!   still steal a lock that no reader or writer holds and no handoff
//!   protects (Linux reader optimistic lock stealing), then grants the
//!   readers queued too.
//! - Release wakes the front waiter (`mark_wake`): a writer, which then
//!   competes for the lock, or the readers: every queued reader (up to
//!   `MAX_READERS_WAKEUP`, writers skipped: phase-fair) is granted the
//!   lock by the waker before it runs.
//! - A waiter that has waited over `RWSEM_WAIT_TIMEOUT` (at once for an
//!   RT task, writers) and still finds the lock held sets `HANDOFF`: no
//!   reader steals and no other waiter takes the lock until the front
//!   waiter has it.
//!
//! `read`/`write` return guards; `*_interruptible` give up with
//! `KernelError::Interrupted` (EINTR) once a signal is pending and
//! `*_killable` once SIGKILL is (Linux down_read_interruptible,
//! down_read_killable and the write forms); a front waiter that gives
//! up wakes the next ones. `try_*` never sleep. The raw `down_*`/`up_*`
//! pairs serve callers that lock and unlock in different scopes.

use core::cell::UnsafeCell;
use core::marker::PhantomPinned;
use core::ops::{Deref, DerefMut};
use core::pin::{Pin, pin};
use core::sync::atomic::{AtomicBool, AtomicI64, Ordering};

use super::sched::{
    WakeQ, can_sleep, current_rt, get_ticks, schedule, set_current_state, signal_pending_state,
    waiter_ref, waiter_task,
};
use super::{might_sleep, spin};
use crate::task::Task;
use crate::task::percpu::{SleepState, TICK_MS};
use crate::util::error::KernelError;
use crate::util::list::{Link, List};

/// Ticks per second (Linux HZ)
const HZ: u64 = 1000 / TICK_MS;
/// Ticks a waiter waits before it may ask for a handoff (Linux
/// RWSEM_WAIT_TIMEOUT: 4 ms, at least a tick)
const RWSEM_WAIT_TIMEOUT: u64 = HZ.div_ceil(250);
/// Readers granted by one wakeup (Linux MAX_READERS_WAKEUP)
const MAX_READERS_WAKEUP: i64 = 0x100;

/// A writer holds it (Linux RWSEM_WRITER_LOCKED)
const WRITER_LOCKED: i64 = 1 << 0;
/// The wait list is not empty (Linux RWSEM_FLAG_WAITERS)
const WAITERS: i64 = 1 << 1;
/// Only the front waiter may take it (Linux RWSEM_FLAG_HANDOFF)
const HANDOFF: i64 = 1 << 2;
const READER_SHIFT: u32 = 8;
/// One reader holding or trying to take it (Linux RWSEM_READER_BIAS)
const READER_BIAS: i64 = 1 << READER_SHIFT;
const READER_MASK: i64 = !(READER_BIAS - 1);
const LOCK_MASK: i64 = WRITER_LOCKED | READER_MASK;
/// A reader that sees these takes the slow path (Linux
/// RWSEM_READ_FAILED_MASK; the count never overflows into the sign)
const READ_FAILED_MASK: i64 = WRITER_LOCKED | WAITERS | HANDOFF;

/// Readers in a count, holders and those still trying
fn readers(count: i64) -> i64 {
    count >> READER_SHIFT
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Read,
    Write,
}

/// Which waiters a wakeup may wake (Linux enum rwsem_wake_type)
#[derive(Clone, Copy, PartialEq, Eq)]
enum Wake {
    /// The front waiter, writer or readers (RWSEM_WAKE_ANY)
    Any,
    /// Front readers only, the lock possibly reader-held
    /// (RWSEM_WAKE_READERS)
    Readers,
    /// Front readers only, the waker holds the lock for reading
    /// (RWSEM_WAKE_READ_OWNED)
    ReadOwned,
}

/// A task sleeping for the semaphore (Linux `struct rwsem_waiter`)
///
/// # Invariants
/// Linked on its semaphore's wait list only while pinned on the waiting
/// task's stack; it is unlinked under the wait lock (by itself, or by
/// the waker granting it the lock) before it goes. A granting waker
/// takes its task reference before it sets `granted` and touches the
/// waiter no more after.
struct Waiter {
    link: Link,
    task: *const Task,
    kind: Kind,
    /// Tick after which it may ask for a handoff
    timeout: u64,
    /// RT task: may ask for a handoff at once
    rt: bool,
    /// This waiter's wait set `HANDOFF` (Linux waiter->handoff_set);
    /// changed under the wait lock
    handoff_set: AtomicBool,
    /// A reader granted the lock and unlinked by its waker (Linux
    /// waiter->task cleared)
    granted: AtomicBool,
    _pin: PhantomPinned,
}

// SAFETY: every field but `task` is atomic or immutable; `task` is only
// followed under the wait lock while the waiter is linked (its task is
// then asleep in `RwSem::*_slow`), to take a reference
unsafe impl Sync for Waiter {}
// SAFETY: as above
unsafe impl Send for Waiter {}

crate::adapter!(WaiterAdapter, Waiter, link);

type WaitList = List<WaiterAdapter>;

impl Waiter {
    /// A waiter of `kind` for the current task, queued at tick `now`
    fn new(kind: Kind, now: u64) -> Self {
        Self::with(kind, now, waiter_task(), current_rt())
    }

    fn with(kind: Kind, now: u64, task: *const Task, rt: bool) -> Self {
        Self {
            link: Link::new(),
            task,
            kind,
            timeout: now + RWSEM_WAIT_TIMEOUT,
            rt,
            handoff_set: AtomicBool::new(false),
            granted: AtomicBool::new(false),
            _pin: PhantomPinned,
        }
    }

    /// Waited past its timeout at tick `now` (Linux time_after(jiffies,
    /// waiter->timeout))
    fn expired(&self, now: u64) -> bool {
        now > self.timeout
    }

    /// Granted the lock: its waker is done with it (pairs with the
    /// Release in `mark_wake`)
    fn granted(&self) -> bool {
        self.granted.load(Ordering::Acquire)
    }
}

/// The front waiter of a wait list
fn first(l: &WaitList) -> Option<&Waiter> {
    // SAFETY: linked waiters are live (type invariant of `Waiter`)
    l.front().map(|p| unsafe { &*p })
}

fn is_first(l: &WaitList, w: &Waiter) -> bool {
    l.front() == Some(&raw const *w)
}

/// Sleeping reader/writer lock over a `T`
///
/// # Invariants
/// `data` is shared by the readers counted in `count` or held by the
/// one writer (`WRITER_LOCKED`), never both. `WAITERS` is set exactly
/// while `wait` is not empty and `HANDOFF` only then, both changed under
/// the wait lock (Linux keeps the same rules). A reader's bias may sit
/// in the count for a moment while it fails: it then takes it out.
pub struct RwSem<T: ?Sized = ()> {
    count: AtomicI64,
    wait: spin::Mutex<WaitList>,
    data: UnsafeCell<T>,
}

// SAFETY: `data` is shared only by readers (needs Sync) and handed to
// one writer at a time (needs Send): the type invariant
unsafe impl<T: ?Sized + Send> Send for RwSem<T> {}
// SAFETY: as above
unsafe impl<T: ?Sized + Send + Sync> Sync for RwSem<T> {}

impl<T: Default> Default for RwSem<T> {
    #[track_caller]
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T> RwSem<T> {
    /// New unlocked semaphore guarding `v`; its wait lock's lockdep
    /// class is the caller's location
    #[track_caller]
    pub const fn new(v: T) -> Self {
        Self {
            count: AtomicI64::new(0),
            wait: spin::Mutex::new(List::new()),
            data: UnsafeCell::new(v),
        }
    }
}

impl<T: ?Sized> RwSem<T> {
    /// Add `v` to the count (Linux atomic_long_add_return); the new count
    fn add(&self, v: i64, o: Ordering) -> i64 {
        self.count.fetch_add(v, o).wrapping_add(v)
    }

    /// Read hold if no writer holds and nobody waits or is handed the
    /// lock (Linux __down_read_trylock)
    fn read_trylock(&self) -> bool {
        let mut c = self.count.load(Ordering::Relaxed);
        while c & READ_FAILED_MASK == 0 {
            match self.count.compare_exchange_weak(
                c,
                c + READER_BIAS,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(v) => c = v,
            }
        }
        false
    }

    /// Write hold if free with nobody waiting (Linux rwsem_write_trylock)
    fn write_trylock(&self) -> bool {
        self.count
            .compare_exchange(0, WRITER_LOCKED, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    /// Queue `w` last (Linux rwsem_add_waiter, the caller sets `WAITERS`
    /// for a first waiter)
    fn add_waiter(l: &mut WaitList, w: Pin<&Waiter>) {
        // SAFETY: pinned, on no list, and unlinked before it goes (type
        // invariant of `Waiter`)
        unsafe { l.push_back(&raw const *w) };
    }

    /// Unqueue `w`; true if waiters remain, else the flags go (Linux
    /// rwsem_del_waiter)
    fn del_waiter(&self, l: &mut WaitList, w: &Waiter) -> bool {
        // SAFETY: queued here by `add_waiter`, not unlinked since
        unsafe { l.remove(w) };
        if l.is_empty() {
            self.count
                .fetch_and(!(HANDOFF | WAITERS), Ordering::Relaxed);
            return false;
        }
        true
    }

    /// A waiter gives up (signal): unqueue it; a front waiter's leaving
    /// may let the next ones go (Linux rwsem_del_wake_waiter)
    fn del_wake_waiter(&self, l: &mut WaitList, w: &Waiter, now: u64, q: &mut WakeQ) {
        let first = is_first(l, w);
        if self.del_waiter(l, w) && first {
            self.mark_wake(l, Wake::Any, now, q);
        }
    }

    /// Wake waiters that a just-queued one, seeing `count`, may be
    /// blocking (Linux rwsem_cond_wake_waiter)
    fn cond_wake(&self, l: &mut WaitList, count: i64, now: u64, q: &mut WakeQ) {
        if count & WRITER_LOCKED != 0 {
            return;
        }
        let kind = if count & READER_MASK != 0 {
            Wake::Readers
        } else {
            Wake::Any
        };
        self.mark_wake(l, kind, now, q);
    }

    /// Queue the front waiter's wakeup: a writer (`Wake::Any` only),
    /// which then competes for the lock, or the queued readers, granted
    /// the lock here (Linux rwsem_mark_wake). A reader front waiter that
    /// finds a writer holding the lock past its timeout asks for a
    /// handoff.
    fn mark_wake(&self, l: &mut WaitList, kind: Wake, now: u64, q: &mut WakeQ) {
        let Some(front) = first(l) else { return };
        if front.kind == Kind::Write {
            if kind == Wake::Any {
                // SAFETY: linked, under the wait lock
                q.add_safe(unsafe { waiter_ref(front.task) });
            }
            return;
        }
        let mut adj = 0;
        if kind != Wake::ReadOwned {
            // Take the read lock for the readers first: a writer may
            // steal it meanwhile
            adj = READER_BIAS;
            let old = self.count.fetch_add(adj, Ordering::AcqRel);
            if old & WRITER_LOCKED != 0 {
                if front.expired(now) {
                    if old & HANDOFF == 0 {
                        adj -= HANDOFF;
                    }
                    front.handoff_set.store(true, Ordering::Relaxed);
                }
                self.count.fetch_sub(adj, Ordering::AcqRel);
                return;
            }
        }
        // Count the readers to grant (writers skipped) and whether any
        // waiter stays
        let mut woken = 0;
        let mut stays = false;
        for w in l.iter() {
            if w.kind == Kind::Write {
                stays = true;
            } else if woken == MAX_READERS_WAKEUP {
                stays = true;
                break;
            } else {
                woken += 1;
            }
        }
        let mut adj = woken * READER_BIAS - adj;
        let old = self.count.load(Ordering::Relaxed);
        if !stays {
            adj -= WAITERS;
        }
        // A reader got the lock: no handoff is needed any more
        if (woken > 0 || !stays) && old & HANDOFF != 0 {
            adj -= HANDOFF;
        }
        if adj != 0 {
            self.count.fetch_add(adj, Ordering::AcqRel);
        }
        self.grant(l, woken, q);
    }

    /// Unqueue the first `n` readers and hand them the lock their count
    /// already holds, queueing their wakeups (second pass of Linux
    /// rwsem_mark_wake)
    fn grant(&self, l: &mut WaitList, mut n: i64, q: &mut WakeQ) {
        let mut cur = l.front();
        while let Some(p) = cur
            && n > 0
        {
            // SAFETY: on the list; its next is read before it is unlinked
            cur = unsafe { l.next(p) };
            // SAFETY: linked waiters are live (type invariant)
            let w = unsafe { &*p };
            if w.kind == Kind::Write {
                continue;
            }
            // SAFETY: on this list
            unsafe { l.remove(p) };
            // SAFETY: just unlinked under the wait lock, not yet granted:
            // its task still waits
            let t = unsafe { waiter_ref(w.task) };
            // Last touch: the waiter may leave once it sees this
            w.granted.store(true, Ordering::Release);
            q.add_safe(t);
            n -= 1;
        }
    }

    /// The queued writer `w` takes the lock if free and not handed off
    /// to another waiter (unqueueing itself), else, waited long enough,
    /// asks for a handoff (Linux rwsem_try_write_lock)
    fn try_write_lock(&self, l: &mut WaitList, w: &Waiter, now: u64) -> bool {
        let Some(front) = first(l) else {
            return false;
        };
        let mut c = self.count.load(Ordering::Relaxed);
        let new = loop {
            let handoff = c & HANDOFF != 0;
            if handoff && front.handoff_set.load(Ordering::Relaxed) && !is_first(l, w) {
                return false;
            }
            let mut new = c;
            if c & LOCK_MASK != 0 {
                if handoff || (!w.rt && !w.expired(now)) {
                    return false;
                }
                new |= HANDOFF;
            } else {
                new |= WRITER_LOCKED;
                new &= !HANDOFF;
                if l.len() == 1 {
                    new &= !WAITERS;
                }
            }
            match self
                .count
                .compare_exchange(c, new, Ordering::Acquire, Ordering::Relaxed)
            {
                Ok(_) => break new,
                Err(v) => c = v,
            }
        };
        if new & HANDOFF != 0 {
            front.handoff_set.store(true, Ordering::Relaxed);
            return false;
        }
        self.del_waiter(l, w);
        true
    }

    /// Wake the front waiter after a release saw `WAITERS` (Linux
    /// rwsem_wake)
    #[cold]
    fn wake(&self) {
        let mut q = WakeQ::new();
        let mut l = self.wait.lock();
        if !l.is_empty() {
            self.mark_wake(&mut l, Wake::Any, get_ticks(), &mut q);
        }
        drop(l);
        q.wake();
    }

    /// Read hold, sleeping in `state` while unavailable (Linux
    /// __down_read_common)
    fn lock_read(&self, state: SleepState) -> Result<(), KernelError> {
        let c = self.add(READER_BIAS, Ordering::Acquire);
        if c & READ_FAILED_MASK == 0 {
            return Ok(());
        }
        self.read_slow(c, state)
    }

    /// The reader bias in `count` takes a lock no reader or writer holds
    /// and no handoff guards, granting the queued readers too (Linux
    /// reader optimistic lock stealing); a lock other readers hold is
    /// not stolen, so readers cannot starve a waiting writer
    fn read_steal(&self, count: i64) -> bool {
        if count & (WRITER_LOCKED | HANDOFF) != 0 || readers(count) > 1 {
            return false;
        }
        if count & WAITERS != 0 {
            let mut q = WakeQ::new();
            let mut l = self.wait.lock();
            if !l.is_empty() {
                self.mark_wake(&mut l, Wake::ReadOwned, get_ticks(), &mut q);
            }
            drop(l);
            q.wake();
        }
        true
    }

    /// Read hold after the fast path's bias saw `count` (Linux
    /// rwsem_down_read_slowpath)
    #[cold]
    fn read_slow(&self, count: i64, state: SleepState) -> Result<(), KernelError> {
        if self.read_steal(count) {
            return Ok(());
        }
        if !can_sleep() {
            // Before tasks exist: nobody to queue behind
            loop {
                self.count.fetch_sub(READER_BIAS, Ordering::Relaxed);
                core::hint::spin_loop();
                let c = self.add(READER_BIAS, Ordering::Acquire);
                if c & READ_FAILED_MASK == 0 || self.read_steal(c) {
                    return Ok(());
                }
            }
        }
        let w = pin!(Waiter::new(Kind::Read, get_ticks()));
        let mut q = WakeQ::new();
        let mut l = self.wait.lock();
        let mut adj = -READER_BIAS;
        if l.is_empty() {
            // Nobody queues and no writer holds it: the bias holds it
            if self.count.load(Ordering::Acquire) & WRITER_LOCKED == 0 {
                return Ok(());
            }
            adj += WAITERS;
        }
        Self::add_waiter(&mut l, w.as_ref());
        // Waiting now, no longer trying
        let c = self.add(adj, Ordering::AcqRel);
        self.cond_wake(&mut l, c, get_ticks(), &mut q);
        drop(l);
        q.wake();
        let r = loop {
            set_current_state(state);
            if w.granted() {
                break Ok(());
            }
            if signal_pending_state(state) {
                let mut l = self.wait.lock();
                // Granted under the wait lock: no longer queued
                if w.granted() {
                    break Ok(());
                }
                self.del_wake_waiter(&mut l, &w, get_ticks(), &mut q);
                drop(l);
                q.wake();
                break Err(KernelError::Interrupted);
            }
            schedule();
        };
        set_current_state(SleepState::Running);
        r
    }

    /// Write hold, sleeping in `state` while unavailable (Linux
    /// __down_write_common)
    fn lock_write(&self, state: SleepState) -> Result<(), KernelError> {
        if self.write_trylock() {
            return Ok(());
        }
        self.write_slow(state)
    }

    /// Write hold when free and no handoff guards it, waiters or not
    /// (Linux rwsem_try_write_lock_unqueued): before tasks exist only
    fn write_unqueued(&self) -> bool {
        let mut c = self.count.load(Ordering::Relaxed);
        while c & (LOCK_MASK | HANDOFF) == 0 {
            match self.count.compare_exchange_weak(
                c,
                c | WRITER_LOCKED,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(v) => c = v,
            }
        }
        false
    }

    /// Queue and sleep for the write lock (Linux
    /// rwsem_down_write_slowpath)
    #[cold]
    fn write_slow(&self, state: SleepState) -> Result<(), KernelError> {
        if !can_sleep() {
            // Before tasks exist: nobody to queue behind
            while !self.write_unqueued() {
                core::hint::spin_loop();
            }
            return Ok(());
        }
        let w = pin!(Waiter::new(Kind::Write, get_ticks()));
        let mut q = WakeQ::new();
        let mut l = self.wait.lock();
        if l.is_empty() {
            Self::add_waiter(&mut l, w.as_ref());
            self.count.fetch_or(WAITERS, Ordering::Relaxed);
        } else {
            Self::add_waiter(&mut l, w.as_ref());
            let c = self.count.load(Ordering::Relaxed);
            self.cond_wake(&mut l, c, get_ticks(), &mut q);
            if !q.is_empty() {
                drop(l);
                q.wake();
                l = self.wait.lock();
            }
        }
        set_current_state(state);
        let r = loop {
            if self.try_write_lock(&mut l, &w, get_ticks()) {
                break Ok(());
            }
            drop(l);
            if signal_pending_state(state) {
                l = self.wait.lock();
                self.del_wake_waiter(&mut l, &w, get_ticks(), &mut q);
                break Err(KernelError::Interrupted);
            }
            schedule();
            set_current_state(state);
            l = self.wait.lock();
        };
        drop(l);
        set_current_state(SleepState::Running);
        q.wake();
        r
    }

    /// Shared acquire (Linux down_read)
    #[track_caller]
    pub fn down_read(&self) {
        might_sleep();
        let _ = self.lock_read(SleepState::Uninterruptible);
    }

    /// Release a shared hold (Linux up_read): the last reader wakes the
    /// front waiter
    ///
    /// # Safety
    /// The caller must hold the semaphore shared.
    pub unsafe fn up_read(&self) {
        let c = self.add(-READER_BIAS, Ordering::Release);
        if c & (LOCK_MASK | WAITERS) == WAITERS {
            self.wake();
        }
    }

    /// Exclusive acquire (Linux down_write)
    #[track_caller]
    pub fn down_write(&self) {
        might_sleep();
        let _ = self.lock_write(SleepState::Uninterruptible);
    }

    /// Release an exclusive hold (Linux up_write): wake the front waiter
    ///
    /// # Safety
    /// The caller must hold the semaphore exclusively.
    pub unsafe fn up_write(&self) {
        let old = self.count.fetch_sub(WRITER_LOCKED, Ordering::Release);
        if old & WAITERS != 0 {
            self.wake();
        }
    }

    /// Shared hold (Linux down_read)
    #[track_caller]
    pub fn read(&self) -> RwSemReadGuard<'_, T> {
        self.down_read();
        RwSemReadGuard { s: self }
    }

    /// Exclusive hold (Linux down_write)
    #[track_caller]
    pub fn write(&self) -> RwSemWriteGuard<'_, T> {
        self.down_write();
        RwSemWriteGuard { s: self }
    }

    /// Shared hold, or EINTR once SIGKILL is pending (Linux
    /// down_read_killable)
    #[track_caller]
    pub fn read_killable(&self) -> Result<RwSemReadGuard<'_, T>, KernelError> {
        might_sleep();
        self.lock_read(SleepState::Killable)?;
        Ok(RwSemReadGuard { s: self })
    }

    /// Exclusive hold, or EINTR once SIGKILL is pending (Linux
    /// down_write_killable)
    #[track_caller]
    pub fn write_killable(&self) -> Result<RwSemWriteGuard<'_, T>, KernelError> {
        might_sleep();
        self.lock_write(SleepState::Killable)?;
        Ok(RwSemWriteGuard { s: self })
    }

    /// Shared hold, or EINTR once a signal is pending (Linux
    /// down_read_interruptible)
    #[track_caller]
    pub fn read_interruptible(&self) -> Result<RwSemReadGuard<'_, T>, KernelError> {
        might_sleep();
        self.lock_read(SleepState::Interruptible)?;
        Ok(RwSemReadGuard { s: self })
    }

    /// Exclusive hold, or EINTR once a signal is pending (Linux
    /// down_write_interruptible)
    #[track_caller]
    pub fn write_interruptible(&self) -> Result<RwSemWriteGuard<'_, T>, KernelError> {
        might_sleep();
        self.lock_write(SleepState::Interruptible)?;
        Ok(RwSemWriteGuard { s: self })
    }

    /// Shared hold if no writer holds or waits and nobody queues,
    /// without sleeping (Linux down_read_trylock)
    pub fn try_read(&self) -> Option<RwSemReadGuard<'_, T>> {
        self.read_trylock().then(|| RwSemReadGuard { s: self })
    }

    /// Exclusive hold if free and nobody queues, without sleeping (Linux
    /// down_write_trylock)
    pub fn try_write(&self) -> Option<RwSemWriteGuard<'_, T>> {
        self.write_trylock().then(|| RwSemWriteGuard { s: self })
    }

    /// The data, through exclusive ownership (no locking)
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }

    /// Where the data lives, to tell which semaphore a borrow of it came
    /// from (never dereferenced here; std Mutex::data_ptr)
    pub fn data_ptr(&self) -> *const T {
        self.data.get()
    }
}

/// A shared hold of a `RwSem`, released on drop
pub struct RwSemReadGuard<'a, T: ?Sized> {
    s: &'a RwSem<T>,
}

impl<T: ?Sized> Deref for RwSemReadGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: readers share the data; no writer while held
        unsafe { &*self.s.data.get() }
    }
}

impl<T: ?Sized> Drop for RwSemReadGuard<'_, T> {
    fn drop(&mut self) {
        // SAFETY: the guard holds the semaphore shared
        unsafe { self.s.up_read() };
    }
}

/// The exclusive hold of a `RwSem`, released on drop
pub struct RwSemWriteGuard<'a, T: ?Sized> {
    s: &'a RwSem<T>,
}

impl<T: ?Sized> Deref for RwSemWriteGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard holds the semaphore exclusively
        unsafe { &*self.s.data.get() }
    }
}

impl<T: ?Sized> DerefMut for RwSemWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the guard holds the semaphore exclusively
        unsafe { &mut *self.s.data.get() }
    }
}

impl<T: ?Sized> Drop for RwSemWriteGuard<'_, T> {
    fn drop(&mut self) {
        // SAFETY: the guard holds the semaphore exclusively
        unsafe { self.s.up_write() };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::boxed::Box;
    use std::vec::Vec;

    type Sem = RwSem<()>;

    const T0: u64 = 100;
    const LATE: u64 = T0 + RWSEM_WAIT_TIMEOUT + 1;

    /// A waiter whose task is the tag `n`, as wakeups record it
    fn waiter(kind: Kind, n: usize) -> Waiter {
        Waiter::with(kind, T0, core::ptr::without_provenance(n), false)
    }

    fn tag(n: usize) -> *const Task {
        core::ptr::without_provenance(n)
    }

    /// Queue `w` last, as the slow paths do
    fn queue(s: &Sem, w: &Pin<&mut Waiter>) {
        let mut l = s.wait.lock();
        if l.is_empty() {
            s.count.fetch_or(WAITERS, Ordering::Relaxed);
        }
        Sem::add_waiter(&mut l, w.as_ref());
    }

    fn count(s: &Sem) -> i64 {
        s.count.load(Ordering::Relaxed)
    }

    /// Run `mark_wake`; whom it woke
    fn mark_wake(s: &Sem, kind: Wake, now: u64) -> Vec<*const Task> {
        let mut q = WakeQ::new();
        s.mark_wake(&mut s.wait.lock(), kind, now, &mut q);
        core::mem::take(&mut q.woken)
    }

    fn try_write_lock(s: &Sem, w: &Pin<&mut Waiter>, now: u64) -> bool {
        s.try_write_lock(&mut s.wait.lock(), w, now)
    }

    fn is_first_w(s: &Sem, w: &Pin<&mut Waiter>) -> bool {
        is_first(&s.wait.lock(), w)
    }

    /// Uncontended holds and releases only touch the count
    #[test]
    fn uncontended() {
        let s = Sem::new(());
        assert!(s.write_trylock());
        assert_eq!(count(&s), WRITER_LOCKED);
        assert!(!s.read_trylock() && !s.write_trylock());
        // SAFETY: held
        unsafe { s.up_write() };
        assert!(s.read_trylock());
        assert!(s.lock_read(SleepState::Uninterruptible).is_ok());
        assert_eq!(count(&s), 2 * READER_BIAS);
        assert!(!s.write_trylock());
        // SAFETY: held twice
        unsafe {
            s.up_read();
            s.up_read();
        }
        assert_eq!(count(&s), 0);
        assert!(s.wait.lock().is_empty());
    }

    /// A queued writer stops new readers (fast path and stealing while
    /// readers hold the lock); the last reader's release wakes it and
    /// it takes the lock
    #[test]
    fn writer_blocks_new_readers() {
        let s = Sem::new(());
        assert!(s.read_trylock());
        let w = pin!(waiter(Kind::Write, 1));
        assert!(!s.write_trylock());
        queue(&s, &w);
        assert!(!s.read_trylock());
        let c = s.add(READER_BIAS, Ordering::Relaxed);
        assert!(!s.read_steal(c), "stole a reader-held lock");
        s.count.fetch_sub(READER_BIAS, Ordering::Relaxed);
        assert!(!try_write_lock(&s, &w, T0));
        s.count.fetch_sub(READER_BIAS, Ordering::Relaxed);
        assert_eq!(mark_wake(&s, Wake::Any, T0), [tag(1)]);
        assert!(try_write_lock(&s, &w, T0));
        assert_eq!(count(&s), WRITER_LOCKED);
        assert!(s.wait.lock().is_empty());
    }

    /// A writer's release grants every queued reader at once, writers
    /// skipped (phase-fair), and the next writer gets the lock after
    /// them: a writer relocking at once queues behind the readers
    #[test]
    fn release_grants_readers_fifo() {
        let s = Sem::new(());
        assert!(s.write_trylock());
        let r1 = pin!(waiter(Kind::Read, 1));
        let w1 = pin!(waiter(Kind::Write, 2));
        let r2 = pin!(waiter(Kind::Read, 3));
        queue(&s, &r1);
        queue(&s, &w1);
        queue(&s, &r2);
        s.count.fetch_sub(WRITER_LOCKED, Ordering::Relaxed);
        assert_eq!(mark_wake(&s, Wake::Any, T0), [tag(1), tag(3)]);
        assert!(r1.granted() && r2.granted() && !w1.granted());
        assert_eq!(count(&s), 2 * READER_BIAS | WAITERS);
        // The old writer comes back: it cannot barge past the queue
        assert!(!s.write_trylock());
        let w0 = pin!(waiter(Kind::Write, 4));
        queue(&s, &w0);
        s.count.fetch_sub(2 * READER_BIAS, Ordering::Relaxed);
        assert_eq!(mark_wake(&s, Wake::Any, T0), [tag(2)]);
        assert!(try_write_lock(&s, &w1, T0));
        assert!(is_first_w(&s, &w0));
        assert_eq!(count(&s), WRITER_LOCKED | WAITERS);
    }

    /// A front writer that waited past the timeout sets the handoff:
    /// readers then neither steal nor take the fast path, and other
    /// queued writers keep off; the front writer gets the lock
    #[test]
    fn writer_handoff() {
        let s = Sem::new(());
        assert!(s.read_trylock());
        let w = pin!(waiter(Kind::Write, 1));
        let w2 = pin!(waiter(Kind::Write, 2));
        queue(&s, &w);
        queue(&s, &w2);
        assert!(!try_write_lock(&s, &w, T0 + RWSEM_WAIT_TIMEOUT));
        assert_eq!(count(&s) & HANDOFF, 0, "handoff before the timeout");
        assert!(!try_write_lock(&s, &w, LATE));
        assert!(count(&s) & HANDOFF != 0 && w.handoff_set.load(Ordering::Relaxed));
        s.count.fetch_sub(READER_BIAS, Ordering::Relaxed);
        let c = s.add(READER_BIAS, Ordering::Relaxed);
        assert!(!s.read_steal(c), "stole past a handoff");
        s.count.fetch_sub(READER_BIAS, Ordering::Relaxed);
        assert!(!s.read_trylock());
        assert!(!s.write_unqueued());
        assert!(!try_write_lock(&s, &w2, LATE), "took a handed-off lock");
        assert!(try_write_lock(&s, &w, LATE));
        assert_eq!(count(&s), WRITER_LOCKED | WAITERS);
        assert!(is_first_w(&s, &w2));
    }

    /// Without a handoff a reader may steal a free lock past a woken
    /// writer; behind a front reader it grants the queued readers too
    #[test]
    fn reader_steal() {
        let s = Sem::new(());
        let w = pin!(waiter(Kind::Write, 1));
        let r = pin!(waiter(Kind::Read, 2));
        queue(&s, &w);
        queue(&s, &r);
        let c = s.add(READER_BIAS, Ordering::Acquire);
        assert!(s.read_steal(c));
        assert!(!r.granted(), "readers granted past a writer");
        assert_eq!(count(&s), READER_BIAS | WAITERS);

        let s = Sem::new(());
        let r1 = pin!(waiter(Kind::Read, 3));
        let w1 = pin!(waiter(Kind::Write, 4));
        queue(&s, &r1);
        queue(&s, &w1);
        let c = s.add(READER_BIAS, Ordering::Acquire);
        assert!(s.read_steal(c));
        assert!(r1.granted());
        assert_eq!(count(&s), 2 * READER_BIAS | WAITERS);
        assert!(is_first_w(&s, &w1));
    }

    /// A front reader that a writer has kept off past the timeout sets
    /// the handoff; the writer's release grants it the lock and ends the
    /// handoff
    #[test]
    fn reader_handoff() {
        let s = Sem::new(());
        assert!(s.write_trylock());
        let r = pin!(waiter(Kind::Read, 1));
        let w = pin!(waiter(Kind::Write, 2));
        queue(&s, &r);
        queue(&s, &w);
        assert!(mark_wake(&s, Wake::Any, T0).is_empty());
        assert_eq!(count(&s), WRITER_LOCKED | WAITERS);
        assert!(mark_wake(&s, Wake::Any, LATE).is_empty());
        assert_eq!(count(&s), WRITER_LOCKED | WAITERS | HANDOFF);
        assert!(r.handoff_set.load(Ordering::Relaxed));
        // The writer waiter may not take it although it is next
        s.count.fetch_sub(WRITER_LOCKED, Ordering::Relaxed);
        assert!(!try_write_lock(&s, &w, LATE));
        assert_eq!(mark_wake(&s, Wake::Any, LATE), [tag(1)]);
        assert_eq!(count(&s), READER_BIAS | WAITERS);
    }

    /// A front writer that gives up lets the readers behind it go;
    /// the last waiter leaving ends a handoff
    #[test]
    fn front_waiter_leaves() {
        let s = Sem::new(());
        assert!(s.read_trylock());
        let w = pin!(waiter(Kind::Write, 1));
        let r = pin!(waiter(Kind::Read, 2));
        queue(&s, &w);
        queue(&s, &r);
        assert!(!try_write_lock(&s, &w, LATE));
        assert!(count(&s) & HANDOFF != 0);
        let mut q = WakeQ::new();
        s.del_wake_waiter(&mut s.wait.lock(), &w, LATE, &mut q);
        assert_eq!(q.woken, [tag(2)]);
        assert_eq!(count(&s), 2 * READER_BIAS);
        assert!(s.wait.lock().is_empty());
    }

    /// One wakeup grants at most `MAX_READERS_WAKEUP` readers; the rest
    /// stay queued
    #[test]
    fn reader_batch() {
        let s = Sem::new(());
        assert!(s.write_trylock());
        let n = MAX_READERS_WAKEUP as usize + 3;
        let ws: Vec<_> = (0..n)
            .map(|i| Box::pin(waiter(Kind::Read, i + 1)))
            .collect();
        {
            let mut l = s.wait.lock();
            s.count.fetch_or(WAITERS, Ordering::Relaxed);
            for w in &ws {
                Sem::add_waiter(&mut l, w.as_ref());
            }
        }
        s.count.fetch_sub(WRITER_LOCKED, Ordering::Relaxed);
        assert_eq!(mark_wake(&s, Wake::Any, T0).len(), n - 3);
        assert_eq!(count(&s), (n as i64 - 3) * READER_BIAS | WAITERS);
        assert_eq!(s.wait.lock().len(), 3);
        assert!(ws[n - 4].granted() && !ws[n - 3].granted());
        let mut l = s.wait.lock();
        for w in &ws[n - 3..] {
            s.del_waiter(&mut l, w);
        }
        assert_eq!(count(&s), (n as i64 - 3) * READER_BIAS);
    }

    /// A failed `try_read` or `try_write` leaves the holders' lock alone
    #[test]
    fn failed_try_keeps_lock() {
        let l = RwSem::new(());
        let w = l.write();
        assert!(l.try_read().is_none() && l.try_write().is_none());
        assert_eq!(l.count.load(Ordering::Relaxed), WRITER_LOCKED);
        drop(w);
        let r = l.read();
        assert!(l.try_write().is_none());
        assert_eq!(l.count.load(Ordering::Relaxed), READER_BIAS);
        drop(r);
    }

    /// Threads (polling waiters on the host: `schedule` yields) keep
    /// readers and writers apart through the queue and the fast paths,
    /// and leave the lock free with nobody queued
    #[test]
    fn exclusion() {
        let l = std::sync::Arc::new(RwSem::new((0u64, 0u64)));
        let ts: Vec<_> = (0..8)
            .map(|i| {
                let l = l.clone();
                std::thread::spawn(move || {
                    for j in 0..5_000u32 {
                        match (i % 4, j % 3) {
                            (0 | 1, _) => {
                                let mut g = l.write();
                                g.0 += 1;
                                g.1 += 1;
                            }
                            (2, 0) => {
                                if let Some(mut g) = l.try_write() {
                                    g.0 += 1;
                                    g.1 += 1;
                                }
                            }
                            (2, _) => {
                                if let Some(g) = l.try_read() {
                                    assert_eq!(g.0, g.1);
                                }
                            }
                            _ => {
                                let g = l.read();
                                assert_eq!(g.0, g.1);
                            }
                        }
                    }
                })
            })
            .collect();
        for t in ts {
            t.join().unwrap();
        }
        let g = l.read();
        assert!(g.0 >= 20_000 && g.0 == g.1);
        drop(g);
        assert_eq!(l.count.load(Ordering::Relaxed), 0);
        assert!(l.wait.lock().is_empty());
    }
}

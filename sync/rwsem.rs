//! Sleeping reader/writer semaphore (Linux `struct rw_semaphore`,
//! kernel/locking/rwsem.c)
//!
//! Many readers or one writer, guarding a `T` (`()` for a semaphore that
//! guards what its owner says, like `i_rwsem`). The state (reader count,
//! writer bit, `handoff` flag) and the FIFO wait list sit under one
//! `IrqSpinlock` (Linux wait_lock plus the atomic count it orders),
//! never held across a sleep. Linux's policy, without optimistic
//! spinning (hk cannot tell whether an owner runs on another CPU):
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
//!   RT task, writers) and still finds the lock held sets `handoff`
//!   (Linux RWSEM_FLAG_HANDOFF): no reader steals and no other waiter
//!   takes the lock until the front waiter has it.
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
use core::sync::atomic::{AtomicBool, Ordering};

use super::{IrqSpinlock, can_sleep, might_sleep, waiter_task, wake_waiter};
use crate::sync::waitqueue::signal_pending_state;
use crate::task::Task;
use crate::task::percpu::{SleepState, TICK_MS, get_ticks, schedule, set_current_state};
use crate::util::error::KernelError;
use crate::util::list::{Link, List};

/// Ticks per second (Linux HZ)
const HZ: u64 = 1000 / TICK_MS;
/// Ticks a waiter waits before it may ask for a handoff (Linux
/// RWSEM_WAIT_TIMEOUT: 4 ms, at least a tick)
const RWSEM_WAIT_TIMEOUT: u64 = HZ.div_ceil(250);
/// Readers granted by one wakeup (Linux MAX_READERS_WAKEUP)
const MAX_READERS_WAKEUP: u32 = 0x100;

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
/// task's stack; it is unlinked under the semaphore's lock (by itself,
/// or by the waker granting it the lock) before it goes, and the waiter
/// reads `granted` under that lock.
struct Waiter {
    link: Link,
    task: *const Task,
    kind: Kind,
    /// Tick after which it may ask for a handoff
    timeout: u64,
    /// RT task: may ask for a handoff at once
    rt: bool,
    /// This waiter's wait set `handoff` (Linux waiter->handoff_set)
    handoff_set: AtomicBool,
    /// A reader granted the lock and unlinked by its waker (Linux
    /// waiter->task cleared)
    granted: AtomicBool,
    _pin: PhantomPinned,
}

// SAFETY: every field but `task` is atomic or immutable; `task` is only
// followed under the semaphore's lock while the waiter is linked (its
// task is then asleep in `RwSem::lock_*`)
unsafe impl Sync for Waiter {}
// SAFETY: as above
unsafe impl Send for Waiter {}

crate::adapter!(WaiterAdapter, Waiter, link);

impl Waiter {
    /// A waiter of `kind` for the current task, queued at tick `now`
    fn new(kind: Kind, now: u64) -> Self {
        let task = waiter_task();
        // SAFETY: the current task, or null (host tests)
        let rt = unsafe { task.as_ref() }.is_some_and(|t| crate::task::is_rt_policy(t.se.policy()));
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

    fn granted(&self) -> bool {
        self.granted.load(Ordering::Relaxed)
    }
}

/// Wake a waiter's task: called under the semaphore's lock, so a woken
/// waiter cannot leave, nor its task exit, before that is dropped
fn wake_task(w: &Waiter) {
    // SAFETY: a linked or just-granted waiter, its task asleep in
    // `RwSem::lock_*` until it sees the lock (above)
    unsafe { wake_waiter(w.task) };
}

/// The lock word and wait list (Linux sem->count and sem->wait_list)
///
/// # Invariants
/// Never `writer` and `readers > 0` at once; `handoff` only while
/// `waiters` is not empty; `waiters` holds live pinned `Waiter`s.
struct Sem {
    readers: u32,
    writer: bool,
    /// Linux RWSEM_FLAG_HANDOFF
    handoff: bool,
    /// FIFO (Linux RWSEM_FLAG_WAITERS: not empty)
    waiters: List<WaiterAdapter>,
}

impl Sem {
    const fn new() -> Self {
        Self {
            readers: 0,
            writer: false,
            handoff: false,
            waiters: List::new(),
        }
    }

    fn first(&self) -> Option<&Waiter> {
        // SAFETY: linked waiters are live (type invariant)
        self.waiters.front().map(|p| unsafe { &*p })
    }

    fn is_first(&self, w: &Waiter) -> bool {
        self.waiters.front() == Some(&raw const *w)
    }

    /// Read hold when no writer holds or waits and nobody queues (Linux
    /// rwsem_read_trylock, __down_read_trylock)
    fn read_fast(&mut self) -> bool {
        let ok = !self.writer && !self.handoff && self.waiters.is_empty();
        if ok {
            self.readers += 1;
        }
        ok
    }

    /// Steal a lock nobody holds past the queue unless a handoff guards
    /// it, granting the queued readers too (Linux reader optimistic lock
    /// stealing in rwsem_down_read_slowpath); a lock other readers hold
    /// is not stolen, so readers cannot starve a waiting writer
    fn read_steal(&mut self, now: u64, wake: &mut impl FnMut(&Waiter)) -> bool {
        if self.readers > 0 || self.writer || self.handoff {
            return false;
        }
        self.readers = 1;
        if !self.waiters.is_empty() {
            self.mark_wake(Wake::ReadOwned, now, wake);
        }
        true
    }

    /// Write hold when the lock is free and nobody queues (Linux
    /// rwsem_write_trylock)
    fn write_fast(&mut self) -> bool {
        let ok = self.readers == 0 && !self.writer && self.waiters.is_empty();
        if ok {
            self.writer = true;
        }
        ok
    }

    /// Write hold when free and no handoff guards it (Linux
    /// rwsem_try_write_lock_unqueued): before tasks exist only
    fn write_unqueued(&mut self) -> bool {
        let ok = self.readers == 0 && !self.writer && !self.handoff;
        if ok {
            self.writer = true;
        }
        ok
    }

    /// Queue `w` last (Linux rwsem_add_waiter)
    fn add(&mut self, w: Pin<&Waiter>) {
        // SAFETY: pinned, on no list, and unlinked before it goes (type
        // invariant of `Waiter`)
        unsafe { self.waiters.push_back(&raw const *w) };
    }

    /// Unqueue `w`; true if waiters remain, else the handoff is over
    /// (Linux rwsem_del_waiter)
    fn del(&mut self, w: &Waiter) -> bool {
        // SAFETY: `add` linked it here and nobody unlinked it
        unsafe { self.waiters.remove(w) };
        if self.waiters.is_empty() {
            self.handoff = false;
            return false;
        }
        true
    }

    /// A waiter gives up (signal): unqueue it; a front waiter's leaving
    /// may let the next ones go (Linux rwsem_del_wake_waiter)
    fn del_wake(&mut self, w: &Waiter, now: u64, wake: &mut impl FnMut(&Waiter)) {
        let first = self.is_first(w);
        if self.del(w) && first {
            self.mark_wake(Wake::Any, now, wake);
        }
    }

    /// Wake waiters a just-queued one may be blocking (Linux
    /// rwsem_cond_wake_waiter)
    fn cond_wake(&mut self, now: u64, wake: &mut impl FnMut(&Waiter)) {
        if self.writer {
            return;
        }
        let kind = if self.readers > 0 {
            Wake::Readers
        } else {
            Wake::Any
        };
        self.mark_wake(kind, now, wake);
    }

    /// Wake the front waiter: a writer (`Wake::Any` only), which then
    /// competes for the lock, or the queued readers, granted the lock
    /// here (Linux rwsem_mark_wake). A reader front waiter that finds a
    /// writer holding the lock past its timeout asks for a handoff.
    fn mark_wake(&mut self, kind: Wake, now: u64, wake: &mut impl FnMut(&Waiter)) {
        let Some(first) = self.first() else { return };
        if first.kind == Kind::Write {
            if kind == Wake::Any {
                wake(first);
            }
            return;
        }
        if kind != Wake::ReadOwned && self.writer {
            if first.expired(now) {
                first.handoff_set.store(true, Ordering::Relaxed);
                self.handoff = true;
            }
            return;
        }
        let mut woken = 0;
        let mut cur = self.waiters.front();
        while let Some(p) = cur {
            // SAFETY: on the list; its next is read before it is unlinked
            cur = unsafe { self.waiters.next(p) };
            // SAFETY: linked waiters are live (type invariant)
            let w = unsafe { &*p };
            if w.kind == Kind::Write {
                continue;
            }
            // SAFETY: on this list
            unsafe { self.waiters.remove(p) };
            self.readers += 1;
            w.granted.store(true, Ordering::Relaxed);
            wake(w);
            woken += 1;
            if woken >= MAX_READERS_WAKEUP {
                break;
            }
        }
        // A reader got the lock: no handoff is needed any more
        if woken > 0 || self.waiters.is_empty() {
            self.handoff = false;
        }
    }

    /// The queued writer `w` takes the lock if free and not handed off
    /// to another waiter (unqueueing itself), else, waited long enough,
    /// asks for a handoff (Linux rwsem_try_write_lock)
    fn try_write_lock(&mut self, w: &Waiter, now: u64) -> bool {
        let Some(first) = self.first() else {
            return false;
        };
        if self.handoff && first.handoff_set.load(Ordering::Relaxed) && !self.is_first(w) {
            return false;
        }
        if self.readers > 0 || self.writer {
            if self.handoff || (!w.rt && !w.expired(now)) {
                return false;
            }
            first.handoff_set.store(true, Ordering::Relaxed);
            self.handoff = true;
            return false;
        }
        self.writer = true;
        self.handoff = false;
        self.del(w);
        true
    }
}

/// Sleeping reader/writer lock over a `T`
///
/// # Invariants
/// `data` is shared by the `sem.readers` readers or held by the one
/// writer (`sem.writer`), never both; `sem` changes only under its lock.
pub struct RwSem<T: ?Sized = ()> {
    sem: IrqSpinlock<Sem>,
    data: UnsafeCell<T>,
}

// SAFETY: `data` is shared only by readers (needs Sync) and handed to
// one writer at a time (needs Send): the type invariant
unsafe impl<T: ?Sized + Send> Send for RwSem<T> {}
// SAFETY: as above
unsafe impl<T: ?Sized + Send + Sync> Sync for RwSem<T> {}

impl<T: Default> Default for RwSem<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T> RwSem<T> {
    /// New unlocked semaphore guarding `v`
    pub const fn new(v: T) -> Self {
        Self {
            sem: IrqSpinlock::new(Sem::new()),
            data: UnsafeCell::new(v),
        }
    }
}

impl<T: ?Sized> RwSem<T> {
    /// Read hold, sleeping in `state` while unavailable (Linux
    /// __down_read_common and rwsem_down_read_slowpath)
    fn lock_read(&self, state: SleepState) -> Result<(), KernelError> {
        let mut s = self.sem.lock();
        if s.read_fast() || s.read_steal(get_ticks(), &mut wake_task) {
            return Ok(());
        }
        if !can_sleep() {
            // Before tasks exist: nobody to queue behind
            while !(s.read_fast() || s.read_steal(get_ticks(), &mut wake_task)) {
                drop(s);
                core::hint::spin_loop();
                s = self.sem.lock();
            }
            return Ok(());
        }
        let w = pin!(Waiter::new(Kind::Read, get_ticks()));
        s.add(w.as_ref());
        s.cond_wake(get_ticks(), &mut wake_task);
        let r = loop {
            set_current_state(state);
            if w.granted() {
                break Ok(());
            }
            if signal_pending_state(state) {
                s.del_wake(&w, get_ticks(), &mut wake_task);
                break Err(KernelError::Interrupted);
            }
            drop(s);
            schedule();
            s = self.sem.lock();
        };
        set_current_state(SleepState::Running);
        r
    }

    /// Write hold, sleeping in `state` while unavailable (Linux
    /// __down_write_common and rwsem_down_write_slowpath)
    fn lock_write(&self, state: SleepState) -> Result<(), KernelError> {
        let mut s = self.sem.lock();
        if s.write_fast() {
            return Ok(());
        }
        if !can_sleep() {
            // Before tasks exist: nobody to queue behind
            while !s.write_unqueued() {
                drop(s);
                core::hint::spin_loop();
                s = self.sem.lock();
            }
            return Ok(());
        }
        let w = pin!(Waiter::new(Kind::Write, get_ticks()));
        s.add(w.as_ref());
        if !s.is_first(&w) {
            s.cond_wake(get_ticks(), &mut wake_task);
        }
        let r = loop {
            set_current_state(state);
            if s.try_write_lock(&w, get_ticks()) {
                break Ok(());
            }
            if signal_pending_state(state) {
                s.del_wake(&w, get_ticks(), &mut wake_task);
                break Err(KernelError::Interrupted);
            }
            drop(s);
            schedule();
            s = self.sem.lock();
        };
        set_current_state(SleepState::Running);
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
        let mut s = self.sem.lock();
        s.readers -= 1;
        if s.readers == 0 {
            s.mark_wake(Wake::Any, get_ticks(), &mut wake_task);
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
        let mut s = self.sem.lock();
        s.writer = false;
        s.mark_wake(Wake::Any, get_ticks(), &mut wake_task);
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
        self.sem
            .lock()
            .read_fast()
            .then(|| RwSemReadGuard { s: self })
    }

    /// Exclusive hold if free and nobody queues, without sleeping (Linux
    /// down_write_trylock)
    pub fn try_write(&self) -> Option<RwSemWriteGuard<'_, T>> {
        self.sem
            .lock()
            .write_fast()
            .then(|| RwSemWriteGuard { s: self })
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
    use std::vec::Vec;

    /// Records who a wakeup woke
    #[derive(Default)]
    struct Woken(Vec<*const Waiter>);

    impl Woken {
        fn f(&mut self) -> impl FnMut(&Waiter) + '_ {
            |w| self.0.push(w)
        }
        fn take(&mut self) -> Vec<*const Waiter> {
            core::mem::take(&mut self.0)
        }
    }

    fn ptr(w: &Pin<&mut Waiter>) -> *const Waiter {
        &raw const **w
    }

    const T0: u64 = 100;
    const LATE: u64 = T0 + RWSEM_WAIT_TIMEOUT + 1;

    /// A queued writer stops new readers (fast path and stealing while
    /// readers hold the lock); the last reader's release wakes it and
    /// it takes the lock
    #[test]
    fn writer_blocks_new_readers() {
        let mut s = Sem::new();
        let mut wk = Woken::default();
        assert!(s.read_fast());
        let w = pin!(Waiter::new(Kind::Write, T0));
        assert!(!s.write_fast());
        s.add(w.as_ref());
        assert!(!s.read_fast());
        assert!(!s.read_steal(T0, &mut wk.f()));
        assert!(!s.try_write_lock(&w, T0));
        s.readers -= 1;
        s.mark_wake(Wake::Any, T0, &mut wk.f());
        assert_eq!(wk.take(), [ptr(&w)]);
        assert!(s.try_write_lock(&w, T0));
        assert!(s.writer && s.waiters.is_empty());
    }

    /// A writer's release grants every queued reader at once, writers
    /// skipped (phase-fair), and the next writer gets the lock after
    /// them: a writer relocking at once queues behind the readers
    #[test]
    fn release_grants_readers_fifo() {
        let mut s = Sem::new();
        let mut wk = Woken::default();
        assert!(s.write_fast());
        let r1 = pin!(Waiter::new(Kind::Read, T0));
        let w1 = pin!(Waiter::new(Kind::Write, T0));
        let r2 = pin!(Waiter::new(Kind::Read, T0));
        s.add(r1.as_ref());
        s.add(w1.as_ref());
        s.add(r2.as_ref());
        s.writer = false;
        s.mark_wake(Wake::Any, T0, &mut wk.f());
        assert_eq!(wk.take(), [ptr(&r1), ptr(&r2)]);
        assert!(r1.granted() && r2.granted() && !w1.granted());
        assert_eq!(s.readers, 2);
        // The old writer comes back: it cannot barge past the queue
        assert!(!s.write_fast());
        let w0 = pin!(Waiter::new(Kind::Write, T0));
        s.add(w0.as_ref());
        s.readers = 0;
        s.mark_wake(Wake::Any, T0, &mut wk.f());
        assert_eq!(wk.take(), [ptr(&w1)]);
        assert!(s.try_write_lock(&w1, T0));
        assert!(s.is_first(&w0));
    }

    /// A front writer that waited past the timeout sets the handoff:
    /// readers then neither steal nor take the fast path, and other
    /// queued writers keep off; the front writer gets the lock
    #[test]
    fn writer_handoff() {
        let mut s = Sem::new();
        let mut wk = Woken::default();
        assert!(s.read_fast());
        let w = pin!(Waiter::new(Kind::Write, T0));
        let w2 = pin!(Waiter::new(Kind::Write, T0));
        s.add(w.as_ref());
        s.add(w2.as_ref());
        assert!(!s.try_write_lock(&w, T0 + RWSEM_WAIT_TIMEOUT));
        assert!(!s.handoff, "handoff before the timeout");
        assert!(!s.try_write_lock(&w, LATE));
        assert!(s.handoff && w.handoff_set.load(Ordering::Relaxed));
        s.readers = 0;
        assert!(!s.read_steal(LATE, &mut wk.f()), "stole past a handoff");
        assert!(!s.read_fast());
        assert!(!s.try_write_lock(&w2, LATE), "took a handed-off lock");
        assert!(s.try_write_lock(&w, LATE));
        assert!(s.writer && !s.handoff);
        assert!(s.is_first(&w2));
    }

    /// Without a handoff a reader may steal a free lock past a woken
    /// writer; behind a front reader it grants the queued readers too
    #[test]
    fn reader_steal() {
        let mut wk = Woken::default();
        let mut s = Sem::new();
        let w = pin!(Waiter::new(Kind::Write, T0));
        let r = pin!(Waiter::new(Kind::Read, T0));
        s.add(w.as_ref());
        s.add(r.as_ref());
        assert!(s.read_steal(T0, &mut wk.f()));
        assert!(wk.take().is_empty(), "readers granted past a writer");
        assert_eq!(s.readers, 1);

        let mut s = Sem::new();
        let r1 = pin!(Waiter::new(Kind::Read, T0));
        let w1 = pin!(Waiter::new(Kind::Write, T0));
        s.add(r1.as_ref());
        s.add(w1.as_ref());
        assert!(s.read_steal(T0, &mut wk.f()));
        assert_eq!(wk.take(), [ptr(&r1)]);
        assert_eq!(s.readers, 2);
        assert!(s.is_first(&w1));
    }

    /// A front reader that a writer has kept off past the timeout sets
    /// the handoff; the writer's release grants it the lock and ends the
    /// handoff
    #[test]
    fn reader_handoff() {
        let mut s = Sem::new();
        let mut wk = Woken::default();
        assert!(s.write_fast());
        let r = pin!(Waiter::new(Kind::Read, T0));
        let w = pin!(Waiter::new(Kind::Write, T0));
        s.add(r.as_ref());
        s.add(w.as_ref());
        s.mark_wake(Wake::Any, T0, &mut wk.f());
        assert!(!s.handoff && wk.take().is_empty());
        s.mark_wake(Wake::Any, LATE, &mut wk.f());
        assert!(s.handoff && r.handoff_set.load(Ordering::Relaxed));
        // The writer waiter may not take it although it is next
        s.writer = false;
        assert!(!s.try_write_lock(&w, LATE));
        s.mark_wake(Wake::Any, LATE, &mut wk.f());
        assert_eq!(wk.take(), [ptr(&r)]);
        assert!(!s.handoff && s.readers == 1);
    }

    /// A front writer that gives up lets the readers behind it go;
    /// the last waiter leaving ends a handoff
    #[test]
    fn front_waiter_leaves() {
        let mut s = Sem::new();
        let mut wk = Woken::default();
        assert!(s.read_fast());
        let w = pin!(Waiter::new(Kind::Write, T0));
        let r = pin!(Waiter::new(Kind::Read, T0));
        s.add(w.as_ref());
        s.add(r.as_ref());
        assert!(!s.try_write_lock(&w, LATE));
        assert!(s.handoff);
        s.del_wake(&w, LATE, &mut wk.f());
        assert_eq!(wk.take(), [ptr(&r)]);
        assert_eq!(s.readers, 2);
        assert!(!s.handoff && s.waiters.is_empty());
    }

    /// A failed `try_read` or `try_write` leaves the holders' lock alone
    #[test]
    fn failed_try_keeps_lock() {
        let l = RwSem::new(());
        let w = l.write();
        assert!(l.try_read().is_none() && l.try_write().is_none());
        assert!(l.sem.lock().writer);
        drop(w);
        let r = l.read();
        assert!(l.try_write().is_none());
        assert_eq!(l.sem.lock().readers, 1);
        drop(r);
    }

    /// Threads (spinning on the host) keep readers and writers apart
    #[test]
    fn exclusion() {
        let l = std::sync::Arc::new(RwSem::new((0u64, 0u64)));
        let ts: Vec<_> = (0..4)
            .map(|i| {
                let l = l.clone();
                std::thread::spawn(move || {
                    for _ in 0..5_000 {
                        if i % 2 == 0 {
                            let mut g = l.write();
                            g.0 += 1;
                            g.1 += 1;
                        } else {
                            let g = l.read();
                            assert_eq!(g.0, g.1);
                        }
                    }
                })
            })
            .collect();
        for t in ts {
            t.join().unwrap();
        }
        assert_eq!(l.read().0, 10_000);
    }
}

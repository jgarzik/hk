//! Sleeping mutex (Linux `struct mutex`, kernel/locking/mutex.c)
//!
//! The owner word holds the owner's tid shifted past three flag bits
//! (Linux keeps them in the low bits of the task pointer):
//! - `WAITERS`: the wait list is not empty, so an unlock must wake its
//!   first waiter;
//! - `HANDOFF`: the first waiter was woken and still lost the lock to
//!   a barging locker; the next unlock hands the lock to it instead of
//!   releasing it, so a task that unlocks and relocks at once cannot
//!   starve the sleepers;
//! - `PICKUP`: the lock was handed to the tid in the word, which takes
//!   it on its next try; nobody else can.
//!
//! Waiters queue FIFO on `wait`, a list guarded by a spin lock (Linux
//! wait_lock: a leaf, never held across a sleep, its lockdep class the
//! mutex's construction site). The unlock queues the first waiter on a
//! `WakeQ` under it and wakes it after dropping it. A woken waiter
//! retries; the first waiter's failed retry sets `HANDOFF` (Linux
//! __mutex_trylock_or_handoff). No optimistic spinning: hk cannot tell
//! whether an owner is running on another CPU (Linux owner_on_cpu).
//!
//! `lock_interruptible` and `lock_killable` (Linux
//! mutex_lock_interruptible/_killable) give up with EINTR when a signal
//! (any, or SIGKILL) is pending while they would sleep; they first try
//! the lock, so a waiter woken by an unlock either takes it or leaves
//! it held by someone whose unlock wakes the next waiter. `try_lock`
//! (Linux mutex_trylock) never sleeps. The owner's tid also catches
//! recursive locking and foreign unlocks in debug builds.

use core::cell::UnsafeCell;
use core::marker::{PhantomData, PhantomPinned};
use core::ops::{Deref, DerefMut};
use core::pin::{Pin, pin};
use core::sync::atomic::{AtomicU64, Ordering};

use super::sched::{
    WakeQ, can_sleep, current_tid, schedule, set_current_state, signal_pending_state, waiter_ref,
    waiter_task,
};
use super::{might_sleep, spin};
use crate::task::Task;
use crate::task::percpu::SleepState;
use crate::util::error::KernelError;
use crate::util::list::{Link, List};

/// Unlock must wake the first waiter (Linux MUTEX_FLAG_WAITERS)
const WAITERS: u64 = 1;
/// Unlock hands the lock to the first waiter (Linux MUTEX_FLAG_HANDOFF)
const HANDOFF: u64 = 2;
/// Handed to the tid in the word, which picks it up (Linux
/// MUTEX_FLAG_PICKUP)
const PICKUP: u64 = 4;
const FLAGS: u64 = WAITERS | HANDOFF | PICKUP;
const SHIFT: u32 = 3;
/// Owner id when locked before tasks exist (early boot)
const NO_TASK: u64 = u64::MAX >> SHIFT;

/// The owner id in an owner word (0: unlocked)
fn owner_of(word: u64) -> u64 {
    word >> SHIFT
}

/// A task sleeping for the lock (Linux `struct mutex_waiter`)
///
/// # Invariants
/// Linked on its mutex's wait list only while pinned on the waiting
/// task's stack; it unlinks itself under the wait lock before it goes.
struct Waiter {
    link: Link,
    task: *const Task,
    /// Owner id the lock is handed to
    id: u64,
    _pin: PhantomPinned,
}

// SAFETY: `task` is only followed under the wait lock, while the waiter
// (and so its task, which is sleeping in `lock_slow`) is linked, to take
// a reference
unsafe impl Sync for Waiter {}
// SAFETY: as above
unsafe impl Send for Waiter {}

crate::adapter!(WaiterAdapter, Waiter, link);

impl Waiter {
    fn new(id: u64) -> Self {
        Self {
            link: Link::new(),
            task: waiter_task(),
            id,
            _pin: PhantomPinned,
        }
    }
}

type WaitList = List<WaiterAdapter>;

/// Sleeping mutual-exclusion lock
///
/// # Invariants
/// `data` is accessed only by the holder: the task whose id (or
/// `NO_TASK` before tasks exist) is the owner in `owner`, once it no
/// longer carries `PICKUP`; the owner is 0 when nobody holds it.
/// `WAITERS` is set exactly while `wait` is not empty, and `HANDOFF`
/// only then; both change under the wait lock, `HANDOFF` also by the
/// first waiter's CAS.
pub struct Mutex<T> {
    owner: AtomicU64,
    wait: spin::Mutex<WaitList>,
    data: UnsafeCell<T>,
}

// SAFETY: access to `data` is serialized by `owner` (type invariant)
unsafe impl<T: Send> Send for Mutex<T> {}
// SAFETY: as above
unsafe impl<T: Send> Sync for Mutex<T> {}

/// Owner id of the caller
fn me() -> u64 {
    if can_sleep() { current_tid() } else { NO_TASK }
}

impl<T> Mutex<T> {
    /// New unlocked mutex; its wait lock's lockdep class is the
    /// caller's location
    #[track_caller]
    pub const fn new(v: T) -> Self {
        Self {
            owner: AtomicU64::new(0),
            wait: spin::Mutex::new(List::new()),
            data: UnsafeCell::new(v),
        }
    }

    /// The data, through exclusive access (no lock needed)
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }

    /// Take the lock if free or handed to `me`; else, with `handoff`,
    /// ask the owner to hand it over (Linux __mutex_trylock_common).
    /// True if `me` now holds it.
    fn trylock_common(&self, me: u64, handoff: bool) -> bool {
        let mut word = self.owner.load(Ordering::Relaxed);
        loop {
            let mut flags = word & FLAGS;
            let mut owner = owner_of(word);
            if owner == 0 {
                debug_assert!(flags & (HANDOFF | PICKUP) == 0);
                owner = me;
            } else if flags & PICKUP != 0 {
                if owner != me {
                    return false;
                }
                flags &= !PICKUP;
            } else if handoff && flags & HANDOFF == 0 {
                flags |= HANDOFF;
            } else {
                return false;
            }
            let new = (owner << SHIFT) | flags;
            match self
                .owner
                .compare_exchange(word, new, Ordering::Acquire, Ordering::Relaxed)
            {
                Ok(_) => return owner == me,
                Err(w) => word = w,
            }
        }
    }

    /// Take the lock if free or handed to `me` (Linux __mutex_trylock)
    fn trylock(&self, me: u64) -> bool {
        self.trylock_common(me, false)
    }

    /// Queue `w` last; the first waiter sets `WAITERS` (Linux
    /// __mutex_add_waiter)
    fn add_waiter(&self, list: &mut WaitList, w: Pin<&Waiter>) {
        if list.is_empty() {
            self.owner.fetch_or(WAITERS, Ordering::Relaxed);
        }
        // SAFETY: pinned, on no list, and unlinked by `remove_waiter`
        // before `lock_slow` returns (type invariant of `Waiter`)
        unsafe { list.push_back(&raw const *w) };
    }

    /// Unqueue `w`; the last waiter clears the flags (Linux
    /// __mutex_remove_waiter)
    fn remove_waiter(&self, list: &mut WaitList, w: Pin<&Waiter>) {
        // SAFETY: `add_waiter` linked it on this list
        unsafe { list.remove(&raw const *w) };
        if list.is_empty() {
            self.owner.fetch_and(!FLAGS, Ordering::Relaxed);
        }
    }

    /// Give the lock to `next` (0: release it), keeping `WAITERS` and
    /// clearing `HANDOFF` (Linux __mutex_handoff)
    fn handoff(&self, next: u64) {
        let mut word = self.owner.load(Ordering::Relaxed);
        loop {
            debug_assert!(word & PICKUP == 0);
            let mut new = (word & WAITERS) | (next << SHIFT);
            if next != 0 {
                new |= PICKUP;
            }
            match self
                .owner
                .compare_exchange(word, new, Ordering::Release, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(w) => word = w,
            }
        }
    }

    /// Acquire without a guard (pair with `unlock_raw`)
    #[track_caller]
    pub fn lock_raw(&self) {
        let r = self.lock_wait(SleepState::Uninterruptible);
        debug_assert!(r.is_ok());
    }

    /// Acquire without a guard, or EINTR if a signal is pending while
    /// contended (pair with `unlock_raw`; Linux mutex_lock_interruptible)
    #[track_caller]
    pub fn lock_raw_interruptible(&self) -> Result<(), KernelError> {
        self.lock_wait(SleepState::Interruptible)
    }

    /// Acquire, sleeping in `state` while contended (Linux
    /// __mutex_lock_common): EINTR if that sleep ends on a signal
    #[track_caller]
    fn lock_wait(&self, state: SleepState) -> Result<(), KernelError> {
        might_sleep();
        let me = me();
        debug_assert!(
            me == NO_TASK || owner_of(self.owner.load(Ordering::Relaxed)) != me,
            "recursive mutex lock"
        );
        if self.trylock(me) {
            return Ok(());
        }
        if !can_sleep() {
            while !self.trylock(me) {
                core::hint::spin_loop();
            }
            return Ok(());
        }
        self.lock_slow(me, state)
    }

    /// Queue and sleep until the lock is taken or handed over, or a
    /// signal ends the wait
    fn lock_slow(&self, me: u64, state: SleepState) -> Result<(), KernelError> {
        let w = pin!(Waiter::new(me));
        let mut list = self.wait.lock();
        if self.trylock(me) {
            return Ok(());
        }
        self.add_waiter(&mut list, w.as_ref());
        set_current_state(state);
        let r = loop {
            if self.trylock(me) {
                break Ok(());
            }
            if signal_pending_state(state) {
                break Err(KernelError::Interrupted);
            }
            drop(list);
            schedule();
            list = self.wait.lock();
            set_current_state(state);
            let first = list.front() == Some(&raw const *w);
            if self.trylock_common(me, first) {
                break Ok(());
            }
        };
        set_current_state(SleepState::Running);
        self.remove_waiter(&mut list, w.as_ref());
        r
    }

    /// Release a `lock_raw` acquisition
    ///
    /// # Safety
    /// The caller must hold the lock.
    pub unsafe fn unlock_raw(&self) {
        self.unlock_as(me());
    }

    /// Release the lock `me` holds (Linux mutex_unlock): a plain unlock
    /// with no flags set, else the slow path
    fn unlock_as(&self, me: u64) {
        let word = self.owner.load(Ordering::Relaxed);
        debug_assert!(
            matches!(owner_of(word), o if o == me || o == NO_TASK),
            "mutex unlocked by a non-owner"
        );
        if self
            .owner
            .compare_exchange(me << SHIFT, 0, Ordering::Release, Ordering::Relaxed)
            .is_err()
        {
            self.unlock_slow();
        }
    }

    /// Release with flags set (Linux __mutex_unlock_slowpath): unless a
    /// handoff is pending release the lock, keeping the flags; if there
    /// are waiters, wake the first (and hand it the lock if asked) once
    /// the wait lock is dropped
    #[cold]
    fn unlock_slow(&self) {
        let mut word = self.owner.load(Ordering::Relaxed);
        loop {
            debug_assert!(word & PICKUP == 0);
            if word & HANDOFF != 0 {
                break;
            }
            match self.owner.compare_exchange(
                word,
                word & FLAGS,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) if word & WAITERS != 0 => break,
                Ok(_) => return,
                Err(w) => word = w,
            }
        }
        let mut q = WakeQ::new();
        let list = self.wait.lock();
        // SAFETY: linked waiters are live (type invariant of `Waiter`)
        let next = list.front().map(|p| unsafe { &*p });
        if word & HANDOFF != 0 {
            self.handoff(next.map_or(0, |n| n.id));
        }
        if let Some(n) = next {
            // SAFETY: linked, under the wait lock: its task is asleep in
            // `lock_slow` and cannot leave until the lock is dropped
            q.add_safe(unsafe { waiter_ref(n.task) });
        }
        drop(list);
        q.wake();
    }

    /// Acquire, sleeping while contended
    #[track_caller]
    pub fn lock(&self) -> MutexGuard<'_, T> {
        self.lock_raw();
        MutexGuard {
            m: self,
            _not_send: PhantomData,
        }
    }

    /// Acquire, or give up with EINTR if a signal is pending while
    /// contended (Linux mutex_lock_interruptible)
    #[track_caller]
    pub fn lock_interruptible(&self) -> Result<MutexGuard<'_, T>, KernelError> {
        self.lock_wait(SleepState::Interruptible)?;
        Ok(MutexGuard {
            m: self,
            _not_send: PhantomData,
        })
    }

    /// Acquire, or give up with EINTR if SIGKILL is pending while
    /// contended (Linux mutex_lock_killable)
    #[track_caller]
    pub fn lock_killable(&self) -> Result<MutexGuard<'_, T>, KernelError> {
        self.lock_wait(SleepState::Killable)?;
        Ok(MutexGuard {
            m: self,
            _not_send: PhantomData,
        })
    }

    /// Acquire if free, without sleeping (Linux mutex_trylock)
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        self.trylock(me()).then(|| MutexGuard {
            m: self,
            _not_send: PhantomData,
        })
    }
}

/// Holds a `Mutex` until dropped
pub struct MutexGuard<'a, T> {
    m: &'a Mutex<T>,
    /// Holding a lock is CPU state (preempt count, IRQ flags) or owner
    /// state: the guard stays on the task and CPU that took it
    _not_send: PhantomData<*const ()>,
}

// SAFETY: sharing the guard shares `&T`: Sync only for T: Sync (the
// Mutex itself is Sync for any T: Send)
unsafe impl<T: Sync> Sync for MutexGuard<'_, T> {}

impl<T> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard holds the lock
        unsafe { &*self.m.data.get() }
    }
}

impl<T> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the guard holds the lock
        unsafe { &mut *self.m.data.get() }
    }
}

impl<T> crate::sync::waitqueue::Relock for MutexGuard<'_, T> {
    fn unlocked<R>(&mut self, f: impl FnOnce() -> R) -> R {
        // SAFETY: the guard holds the lock; `relock` takes it again
        // before the guard is used or dropped
        unsafe { self.m.unlock_raw() };
        // However `f` ends, unwinding included (host tests unwind)
        let m = self.m;
        let relock = crate::util::scope::ScopeGuard::new(|()| m.lock_raw());
        let r = f();
        drop(relock);
        r
    }
}

impl<T> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        // SAFETY: the guard holds the lock
        unsafe { self.m.unlock_raw() };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    const A: u64 = 10;
    const B: u64 = 11;
    const C: u64 = 12;

    fn word(m: &Mutex<()>) -> (u64, u64) {
        let w = m.owner.load(Ordering::Relaxed);
        (owner_of(w), w & FLAGS)
    }

    /// Plain lock and unlock touch no flags; a held lock refuses others
    #[test]
    fn uncontended() {
        let m = Mutex::new(());
        assert!(m.trylock(A));
        assert!(!m.trylock(B));
        assert!(!m.trylock_common(B, false));
        m.unlock_as(A);
        assert_eq!(word(&m), (0, 0));
    }

    /// The first waiter's failed retry asks for a handoff; the unlock
    /// then hands the lock over, a barging locker cannot take it, and
    /// the waiter picks it up
    #[test]
    fn handoff_beats_barging() {
        let m = Mutex::new(());
        assert!(m.trylock(A));
        let w = pin!(Waiter::new(B));
        m.add_waiter(&mut m.wait.lock(), w.as_ref());
        assert_eq!(word(&m), (A, WAITERS));
        assert!(!m.trylock_common(B, true));
        assert_eq!(word(&m), (A, WAITERS | HANDOFF));
        // A second handoff request changes nothing
        assert!(!m.trylock_common(B, true));
        m.unlock_as(A);
        assert_eq!(word(&m), (B, WAITERS | PICKUP));
        assert!(!m.trylock(C), "barger took a handed-off lock");
        assert!(!m.trylock(A));
        assert!(m.trylock(B));
        assert_eq!(word(&m), (B, WAITERS));
        m.remove_waiter(&mut m.wait.lock(), w.as_ref());
        assert_eq!(word(&m), (B, 0));
        m.unlock_as(B);
        assert_eq!(word(&m), (0, 0));
    }

    /// Without a handoff request an unlock releases the lock (waiters
    /// kept), and anyone may take it: stealing before the first waiter
    /// has failed once is allowed (Linux)
    #[test]
    fn release_keeps_waiters() {
        let m = Mutex::new(());
        assert!(m.trylock(A));
        let w = pin!(Waiter::new(B));
        m.add_waiter(&mut m.wait.lock(), w.as_ref());
        m.unlock_as(A);
        assert_eq!(word(&m), (0, WAITERS));
        assert!(m.trylock(C));
        assert_eq!(word(&m), (C, WAITERS));
        m.unlock_as(C);
        m.remove_waiter(&mut m.wait.lock(), w.as_ref());
        assert_eq!(word(&m), (0, 0));
    }

    /// The handoff goes to the first waiter, in queue order; when the
    /// handoff's requester has left, the next first waiter gets it
    #[test]
    fn handoff_to_first_in_order() {
        let m = Mutex::new(());
        assert!(m.trylock(A));
        let wb = pin!(Waiter::new(B));
        let wc = pin!(Waiter::new(C));
        m.add_waiter(&mut m.wait.lock(), wb.as_ref());
        m.add_waiter(&mut m.wait.lock(), wc.as_ref());
        assert!(!m.trylock_common(B, true));
        // B gives up (a signal): HANDOFF stays for the next waiter
        m.remove_waiter(&mut m.wait.lock(), wb.as_ref());
        assert_eq!(word(&m), (A, WAITERS | HANDOFF));
        m.unlock_as(A);
        assert_eq!(word(&m), (C, WAITERS | PICKUP));
        assert!(m.trylock(C));
        m.remove_waiter(&mut m.wait.lock(), wc.as_ref());
        m.unlock_as(C);
        assert_eq!(word(&m), (0, 0));
    }

    /// A handoff whose waiters all left releases the lock
    #[test]
    fn handoff_with_no_waiter_releases() {
        let m = Mutex::new(());
        assert!(m.trylock(A));
        m.owner.fetch_or(HANDOFF, Ordering::Relaxed);
        m.unlock_as(A);
        assert_eq!(word(&m), (0, 0));
    }

    /// A failed `try_lock` leaves the holder's lock alone
    #[test]
    fn failed_try_lock_keeps_lock() {
        let m = Mutex::new(());
        assert!(m.trylock(A));
        assert!(m.try_lock().is_none());
        assert_eq!(word(&m), (A, 0));
    }

    /// Threads (spinning on the host) never share the lock
    #[test]
    fn exclusion() {
        let m = std::sync::Arc::new(Mutex::new(0u64));
        let ts: std::vec::Vec<_> = (0..4)
            .map(|_| {
                let m = m.clone();
                std::thread::spawn(move || {
                    for _ in 0..10_000 {
                        *m.lock() += 1;
                    }
                })
            })
            .collect();
        for t in ts {
            t.join().unwrap();
        }
        assert_eq!(*m.lock(), 40_000);
    }
}

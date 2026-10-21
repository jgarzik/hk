//! Sleeping mutex (Linux `struct mutex`)
//!
//! `unlock` wakes one waiter; a woken waiter retries the CAS and sleeps
//! again if it lost the race, so each unlock wakes one sleeper and no
//! wakeup is lost. The owner's tid is recorded (Linux mutex owner) to
//! catch recursive locking and foreign unlocks in debug builds.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU64, Ordering};

use super::{can_sleep, might_sleep};
use crate::task::percpu::current_tid;
use crate::waitqueue::WaitQueue;

/// Owner value of an unlocked mutex
const UNLOCKED: u64 = 0;
/// Owner value when locked before tasks exist (early boot)
const NO_TASK: u64 = u64::MAX;

/// Sleeping mutual-exclusion lock
pub struct Mutex<T> {
    owner: AtomicU64,
    wq: WaitQueue,
    data: UnsafeCell<T>,
}

// SAFETY: access to `data` is serialized by `owner`
unsafe impl<T: Send> Send for Mutex<T> {}
unsafe impl<T: Send> Sync for Mutex<T> {}

/// Owner id of the caller
fn me() -> u64 {
    if can_sleep() {
        current_tid() as u64
    } else {
        NO_TASK
    }
}

impl<T> Mutex<T> {
    /// New unlocked mutex
    pub const fn new(v: T) -> Self {
        Self {
            owner: AtomicU64::new(UNLOCKED),
            wq: WaitQueue::new(),
            data: UnsafeCell::new(v),
        }
    }

    fn try_raw(&self, me: u64) -> bool {
        self.owner
            .compare_exchange(UNLOCKED, me, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    /// Acquire without a guard (pair with `unlock_raw`)
    #[track_caller]
    pub fn lock_raw(&self) {
        might_sleep();
        let me = me();
        debug_assert!(
            me == NO_TASK || self.owner.load(Ordering::Relaxed) != me,
            "recursive mutex lock"
        );
        while !self.try_raw(me) {
            if can_sleep() {
                self.wq
                    .wait_event_exclusive(|| self.owner.load(Ordering::Acquire) == UNLOCKED);
            } else {
                core::hint::spin_loop();
            }
        }
    }

    /// Release a `lock_raw` acquisition
    ///
    /// # Safety
    /// The caller must hold the lock.
    pub unsafe fn unlock_raw(&self) {
        debug_assert!(
            matches!(self.owner.load(Ordering::Relaxed), o if o == me() || o == NO_TASK),
            "mutex unlocked by a non-owner"
        );
        self.owner.store(UNLOCKED, Ordering::Release);
        self.wq.wake_one();
    }

    /// Acquire, sleeping while contended
    #[track_caller]
    pub fn lock(&self) -> MutexGuard<'_, T> {
        self.lock_raw();
        MutexGuard { m: self }
    }
}

/// Holds a `Mutex` until dropped
pub struct MutexGuard<'a, T> {
    m: &'a Mutex<T>,
}

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

impl<T> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        // SAFETY: the guard holds the lock
        unsafe { self.m.unlock_raw() };
    }
}

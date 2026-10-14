//! Sleeping mutex (Linux `struct mutex`)
//!
//! A contended `lock()` sleeps on a wait queue instead of spinning, so
//! the holder may block (page locks, block I/O, user page faults) and
//! waiters do not burn their CPU. Before scheduling is enabled (early
//! boot) a contended lock spins.
//!
//! ## Locking
//!
//! Thread context only: never take it in IRQ context or while holding a
//! spinlock (a contended lock sleeps). Its wait queue head is an
//! `IrqSpinlock` leaf, taken only inside `lock`/`unlock`. Unlock wakes
//! one waiter; a woken waiter retries and sleeps again if it lost the
//! race, so no wakeup is lost (each unlock wakes one sleeper).

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::task::percpu::SCHEDULING_ENABLED;
use crate::waitqueue::WaitQueue;

/// Sleeping mutual-exclusion lock
pub struct SleepMutex<T> {
    locked: AtomicBool,
    wq: WaitQueue,
    data: UnsafeCell<T>,
}

// SAFETY: access to `data` is serialized by `locked`
unsafe impl<T: Send> Send for SleepMutex<T> {}
unsafe impl<T: Send> Sync for SleepMutex<T> {}

impl<T> SleepMutex<T> {
    /// New unlocked mutex
    pub const fn new(v: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            wq: WaitQueue::new(),
            data: UnsafeCell::new(v),
        }
    }

    fn try_raw(&self) -> bool {
        self.locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    /// Acquire without a guard (pair with `unlock_raw`)
    pub fn lock_raw(&self) {
        while !self.try_raw() {
            if SCHEDULING_ENABLED.load(Ordering::Acquire) {
                self.wq.wait_event(|| !self.locked.load(Ordering::Acquire));
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
        self.locked.store(false, Ordering::Release);
        self.wq.wake_one();
    }

    /// Acquire, sleeping while contended
    pub fn lock(&self) -> SleepMutexGuard<'_, T> {
        self.lock_raw();
        SleepMutexGuard { m: self }
    }

    /// True if currently held (by anyone)
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }
}

/// Holds a `SleepMutex` until dropped
pub struct SleepMutexGuard<'a, T> {
    m: &'a SleepMutex<T>,
}

impl<T> Deref for SleepMutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard holds the lock
        unsafe { &*self.m.data.get() }
    }
}

impl<T> DerefMut for SleepMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the guard holds the lock
        unsafe { &mut *self.m.data.get() }
    }
}

impl<T> Drop for SleepMutexGuard<'_, T> {
    fn drop(&mut self) {
        // SAFETY: the guard holds the lock
        unsafe { self.m.unlock_raw() };
    }
}

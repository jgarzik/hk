//! IRQ-safe spinlocks (Linux raw_spin_lock_irqsave)
//!
//! A lock that masks interrupts and raises the preempt count while
//! held, so the same lock can be taken from interrupt and thread
//! context without a same-CPU deadlock. The IRQ state comes from the
//! arch primitives (`sync::irqflags`).
//!
//! Lock ordering: IrqSpinlock is the innermost lock when combined with
//! non-IRQ-safe locks (Mutex, RwLock). Never acquire a non-IRQ-safe lock
//! from interrupt context.

use ::core::cell::UnsafeCell;
use ::core::marker::PhantomData;
use ::core::ops::{Deref, DerefMut};
use ::core::sync::atomic::{AtomicBool, Ordering};

use super::irqflags::{self, Raw};

#[cfg(not(test))]
use crate::arch as percpu;

/// Host unit tests run in userspace: no per-CPU data or preemption
#[cfg(test)]
mod percpu {
    pub fn preempt_disable() {}
    pub fn preempt_enable() {}
}

/// An IRQ-safe spinlock
///
/// This lock disables interrupts and increments preempt_count while held,
/// ensuring that:
/// 1. Timer interrupts can't preempt and try to take the same lock
/// 2. The lock holder runs to completion on its CPU
/// 3. No context switch can occur while the lock is held
///
/// Based on Linux's raw_spinlock with IRQ disable (spin_lock_irqsave).
pub struct IrqSpinlock<T> {
    lock: AtomicBool,
    data: UnsafeCell<T>,
}

// SAFETY: the lock provides mutual exclusion, so T can be sent/shared
// if it would be safe to send normally.
unsafe impl<T: Send> Send for IrqSpinlock<T> {}
// SAFETY: as above: only one guard at a time reaches `data`
unsafe impl<T: Send> Sync for IrqSpinlock<T> {}

impl<T> IrqSpinlock<T> {
    /// Create a new IRQ-safe spinlock
    pub const fn new(data: T) -> Self {
        Self {
            lock: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }

    /// Acquire the lock, disabling interrupts and preemption
    ///
    /// This is equivalent to Linux's spin_lock_irqsave():
    /// 1. Save and disable interrupts
    /// 2. Increment preempt_count
    /// 3. Acquire the spinlock
    ///
    /// Returns a guard that releases the lock and restores state on drop.
    #[inline]
    #[cfg_attr(feature = "lockdep", track_caller)]
    pub fn lock(&self) -> IrqSpinlockGuard<'_, T> {
        let irq_state = irqflags::save();
        percpu::preempt_disable();
        while self
            .lock
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        crate::sync::lockdep::irqsafe_acquire(::core::panic::Location::caller());
        IrqSpinlockGuard {
            lock: self,
            irq_state,
            _not_send: PhantomData,
        }
    }

    /// Try to acquire the lock without blocking
    ///
    /// Returns Some(guard) if the lock was acquired, None if it was already held.
    /// This is useful in interrupt context where blocking is not allowed.
    #[inline]
    #[cfg_attr(feature = "lockdep", track_caller)]
    pub fn try_lock(&self) -> Option<IrqSpinlockGuard<'_, T>> {
        let irq_state = irqflags::save();
        percpu::preempt_disable();
        if self
            .lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            crate::sync::lockdep::irqsafe_acquire(::core::panic::Location::caller());
            Some(IrqSpinlockGuard {
                lock: self,
                irq_state,
                _not_send: PhantomData,
            })
        } else {
            percpu::preempt_enable();
            irqflags::restore(irq_state);
            None
        }
    }

    /// A guard for this lock, which this CPU holds on behalf of a task
    /// that switched away (Linux finish_task_switch: the task switched
    /// to releases the rq lock). Interrupts stay as they are on drop.
    ///
    /// # Safety
    /// This CPU holds the lock (its preempt count includes it), interrupts
    /// are disabled, and nothing else releases it.
    #[inline]
    pub unsafe fn assume_held(&self) -> IrqSpinlockGuard<'_, T> {
        IrqSpinlockGuard {
            lock: self,
            irq_state: irqflags::save(),
            _not_send: PhantomData,
        }
    }
}

/// RAII guard for IrqSpinlock
///
/// When dropped, releases the lock and restores the interrupt state
/// to what it was before the lock was acquired.
pub struct IrqSpinlockGuard<'a, T> {
    lock: &'a IrqSpinlock<T>,
    /// This CPU's interrupt state before the lock was taken
    irq_state: Raw,
    /// Holding a lock is CPU state (preempt count, IRQ flags) or owner
    /// state: the guard stays on the task and CPU that took it
    _not_send: PhantomData<*const ()>,
}

// SAFETY: sharing the guard shares `&T`: Sync only for T: Sync
unsafe impl<T: Sync> Sync for IrqSpinlockGuard<'_, T> {}

impl<T> Deref for IrqSpinlockGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: we hold the lock, so access is exclusive
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for IrqSpinlockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: we hold the lock, so access is exclusive
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T> IrqSpinlockGuard<'a, T> {
    /// Hand this guard's interrupt state to a guard of `lock`, which this
    /// CPU holds instead (a context switch: the task resumes on a CPU
    /// whose rq lock the task switched from there took). This guard's
    /// lock is not released.
    ///
    /// # Safety
    /// As for [`IrqSpinlock::assume_held`] for `lock`; the lock of this
    /// guard is released by someone else.
    #[inline]
    pub unsafe fn rebind<'b>(self, lock: &'b IrqSpinlock<T>) -> IrqSpinlockGuard<'b, T> {
        let irq_state = self.irq_state;
        core::mem::forget(self);
        IrqSpinlockGuard {
            lock,
            irq_state,
            _not_send: PhantomData,
        }
    }
}

impl<T> crate::sync::waitqueue::Relock for IrqSpinlockGuard<'_, T> {
    fn unlocked<R>(&mut self, f: impl FnOnce() -> R) -> R {
        let lock = self.lock;
        let me: *mut Self = self;
        // SAFETY: the guard is dropped (unlock, IRQ state restored) and
        // rewritten by `relock` before anything reads it
        unsafe { core::ptr::drop_in_place(me) };
        // Taken again however `f` ends, unwinding included (host tests
        // unwind), so the caller's guard is never dropped twice
        let relock = crate::util::scope::ScopeGuard::new(|()| {
            // SAFETY: `*me` was dropped above, so writing it leaks nothing
            unsafe { core::ptr::write(me, lock.lock()) };
        });
        let r = f();
        drop(relock);
        r
    }
}

impl<T> Drop for IrqSpinlockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.lock.store(false, Ordering::Release);
        percpu::preempt_enable();
        crate::sync::lockdep::irqsafe_release(
            core::ptr::from_ref(self.lock).cast::<u8>() as usize,
            irqflags::enabled(self.irq_state),
        );
        // Interrupts last, after preempt_enable
        irqflags::restore(self.irq_state);
    }
}

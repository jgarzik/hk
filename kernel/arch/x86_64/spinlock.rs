//! IRQ-safe spinlocks for kernel synchronization
//!
//! This module provides spinlocks that automatically save and restore
//! interrupt state, preventing deadlocks when the same lock might be
//! taken from both interrupt and non-interrupt context.
//!
//! ## Linux-style Spinlock Semantics
//!
//! This spinlock follows Linux kernel conventions:
//! 1. Disables interrupts while held (prevents same-CPU deadlock from ISR)
//! 2. Increments preempt_count (prevents preemption while holding lock)
//! 3. Uses compare-exchange for SMP safety
//!
//! Lock ordering: IrqSpinlock should be the innermost lock when combining
//! with non-IRQ-safe locks (Mutex, RwLock). Never acquire a non-IRQ-safe
//! lock from interrupt context.

use ::core::cell::UnsafeCell;
use ::core::ops::{Deref, DerefMut};
use ::core::sync::atomic::{AtomicBool, Ordering};

#[cfg(not(test))]
use super::percpu;

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

// Safety: The lock provides mutual exclusion, so T can be sent/shared
// if it would be safe to send/share normally.
unsafe impl<T: Send> Send for IrqSpinlock<T> {}
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
    pub fn lock(&self) -> IrqSpinlockGuard<'_, T> {
        // Save interrupt state and disable interrupts FIRST
        let irq_state = save_and_disable_irq();

        // Disable preemption (increment preempt_count)
        percpu::preempt_disable();

        // Spin until we acquire the lock
        while self
            .lock
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // Spin hint to reduce bus contention
            core::hint::spin_loop();
        }

        crate::sync::lockdep::irqsafe_acquire();
        IrqSpinlockGuard {
            lock: self,
            irq_state,
        }
    }

    /// Try to acquire the lock without blocking
    ///
    /// Returns Some(guard) if the lock was acquired, None if it was already held.
    /// This is useful in interrupt context where blocking is not allowed.
    #[inline]
    pub fn try_lock(&self) -> Option<IrqSpinlockGuard<'_, T>> {
        // Save interrupt state and disable interrupts FIRST
        let irq_state = save_and_disable_irq();

        // Disable preemption (increment preempt_count)
        percpu::preempt_disable();

        // Try to acquire the lock (single attempt, no spinning)
        if self
            .lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            crate::sync::lockdep::irqsafe_acquire();
            Some(IrqSpinlockGuard {
                lock: self,
                irq_state,
            })
        } else {
            // Failed to acquire - restore state
            percpu::preempt_enable();
            restore_irq(irq_state);
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
            irq_state: save_and_disable_irq(),
        }
    }
}

/// RAII guard for IrqSpinlock
///
/// When dropped, releases the lock and restores the interrupt state
/// to what it was before the lock was acquired.
pub struct IrqSpinlockGuard<'a, T> {
    lock: &'a IrqSpinlock<T>,
    irq_state: bool, // true if interrupts were enabled before lock
}

impl<T> Deref for IrqSpinlockGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // Safety: We hold the lock, so exclusive access is guaranteed
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for IrqSpinlockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // Safety: We hold the lock, so exclusive access is guaranteed
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
        IrqSpinlockGuard { lock, irq_state }
    }
}

impl<T> Drop for IrqSpinlockGuard<'_, T> {
    fn drop(&mut self) {
        // Release the lock
        self.lock.lock.store(false, Ordering::Release);

        // Re-enable preemption (decrement preempt_count)
        percpu::preempt_enable();
        crate::sync::lockdep::irqsafe_release(
            self.lock as *const _ as *const u8 as usize,
            self.irq_state,
        );

        // Restore interrupt state (must be LAST, after preempt_enable)
        restore_irq(self.irq_state);
    }
}

/// Save current interrupt state and disable interrupts
///
/// Returns true if interrupts were enabled (IF flag was set).
#[cfg(not(test))]
#[inline]
fn save_and_disable_irq() -> bool {
    let flags: u64;
    unsafe {
        ::core::arch::asm!(
            "pushfq",
            "pop {0}",
            "cli",
            out(reg) flags,
        );
    }
    // IF (Interrupt Flag) is bit 9
    (flags & 0x200) != 0
}

/// Restore interrupt state
///
/// If `was_enabled` is true, enables interrupts; otherwise leaves them disabled.
#[cfg(not(test))]
#[inline]
fn restore_irq(was_enabled: bool) {
    if was_enabled {
        unsafe {
            ::core::arch::asm!("sti", options(nostack));
        }
    }
}

/// Host unit tests run in userspace, where IRQ masking is privileged
#[cfg(test)]
fn save_and_disable_irq() -> bool {
    false
}

#[cfg(test)]
fn restore_irq(_was_enabled: bool) {}

/// Interrupts are masked on this CPU (Linux irqs_disabled; lockdep's
/// might_sleep check)
#[cfg(not(test))]
#[inline]
#[allow(dead_code)]
pub fn irqs_disabled() -> bool {
    let flags: u64;
    unsafe {
        ::core::arch::asm!("pushfq", "pop {0}", out(reg) flags, options(nomem, preserves_flags));
    }
    flags & 0x200 == 0
}

#[cfg(test)]
#[allow(dead_code)]
pub fn irqs_disabled() -> bool {
    false
}

/// Saved interrupt state of this CPU (Linux local_irq_save flags)
#[must_use]
pub struct IrqFlags(bool);

/// Disable interrupts on this CPU, returning the previous state (Linux
/// local_irq_save)
#[inline]
pub fn local_irq_save() -> IrqFlags {
    IrqFlags(save_and_disable_irq())
}

/// Restore the state saved by [`local_irq_save`]
#[inline]
pub fn local_irq_restore(f: IrqFlags) {
    restore_irq(f.0)
}

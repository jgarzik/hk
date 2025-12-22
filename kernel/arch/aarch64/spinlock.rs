//! IRQ-safe spinlocks for kernel synchronization (aarch64)
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

use super::percpu;

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

    /// Force unlock the spinlock without restoring state
    ///
    /// # Safety
    /// This should only be called after a context switch when the previous
    /// holder will never run again on this CPU (e.g., the guard is on the
    /// old task's stack and will be dropped when that task resumes).
    ///
    /// The caller is responsible for ensuring no concurrent access.
    /// Note: This does NOT decrement preempt_count or restore interrupts.
    pub unsafe fn force_unlock(&self) {
        self.lock.store(false, Ordering::Release);
        // Decrement preempt_count since we're releasing the lock
        percpu::preempt_enable();
    }
}

/// RAII guard for IrqSpinlock
///
/// When dropped, releases the lock and restores the interrupt state
/// to what it was before the lock was acquired.
pub struct IrqSpinlockGuard<'a, T> {
    lock: &'a IrqSpinlock<T>,
    irq_state: u64, // Saved DAIF register value
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

impl<T> Drop for IrqSpinlockGuard<'_, T> {
    fn drop(&mut self) {
        // Release the lock
        self.lock.lock.store(false, Ordering::Release);

        // Re-enable preemption (decrement preempt_count)
        percpu::preempt_enable();

        // Restore interrupt state (must be LAST, after preempt_enable)
        restore_irq(self.irq_state);
    }
}

/// Save current interrupt state and disable interrupts
///
/// Returns the DAIF register value.
/// DAIF bits: [9]=D (Debug), [8]=A (SError), [7]=I (IRQ), [6]=F (FIQ)
#[inline]
fn save_and_disable_irq() -> u64 {
    let daif: u64;
    unsafe {
        // Read current DAIF state
        core::arch::asm!(
            "mrs {}, daif",
            out(reg) daif,
            options(nomem, nostack, preserves_flags)
        );
        // Disable IRQ (set bit 7 of DAIF via daifset, #2 = IRQ bit)
        core::arch::asm!("msr daifset, #2", options(nomem, nostack, preserves_flags));
    }
    daif
}

/// Restore interrupt state
///
/// Restores DAIF to the saved value.
#[inline]
fn restore_irq(saved_daif: u64) {
    unsafe {
        core::arch::asm!(
            "msr daif, {}",
            in(reg) saved_daif,
            options(nomem, nostack, preserves_flags)
        );
    }
}

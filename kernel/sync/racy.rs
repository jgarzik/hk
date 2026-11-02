//! Statics shared with hardware or with code the compiler does not see
//! (doc/UNSAFE.md rule 6): the boot page tables, IST stacks, the AP boot
//! data that a CPU reads with its MMU off.
//!
//! A `RacyCell` is an `UnsafeCell` that may be a `static`: it only hands
//! out a raw pointer, so every access is `unsafe` and states its own
//! rule (early boot on one CPU, the hardware's own use). It replaces
//! `static mut` (core's `SyncUnsafeCell` is unstable).

use core::cell::UnsafeCell;

/// A static's memory, reached only through raw pointers
#[repr(transparent)]
pub struct RacyCell<T>(UnsafeCell<T>);

// SAFETY: only a raw pointer leaves the cell (`get`); each deref is an
// unsafe block that justifies its own synchronization
unsafe impl<T> Sync for RacyCell<T> {}

impl<T> RacyCell<T> {
    pub const fn new(v: T) -> Self {
        Self(UnsafeCell::new(v))
    }

    /// The value's address
    #[inline]
    pub const fn get(&self) -> *mut T {
        self.0.get()
    }
}

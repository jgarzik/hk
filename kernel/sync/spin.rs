//! Spinning locks for thread context (Linux spinlock_t / rwlock_t
//! without IRQ disabling): `Mutex` and `RwLock`
//!
//! Kernel code takes these instead of `spin::Mutex` / `spin::RwLock`
//! directly. Like Linux spin_lock, every acquisition raises this CPU's
//! preempt count until the release, so `preempt_count() == 0` (with
//! interrupts on) means the caller holds no spin lock and may sleep:
//! `might_sleep` checks it. With the `lockdep` feature acquisitions and
//! releases are also reported to `sync::lockdep`: per-CPU held-lock
//! stacks, and lock classes (the source location of the lock's `new()`,
//! like Linux's static lock_class_key) that record the observed A -> B
//! nesting order, reporting the first inverse edge.

use core::fmt;
use core::mem::ManuallyDrop;
use core::ops::{Deref, DerefMut};

#[cfg(feature = "lockdep")]
use core::panic::Location;

#[cfg(not(test))]
use crate::arch::{preempt_disable, preempt_enable};

/// Host unit tests run in userspace: no per-CPU preempt count
#[cfg(test)]
fn preempt_disable() {}
#[cfg(test)]
fn preempt_enable() {}

/// Lock class: where the lock was created (lockdep builds; nothing
/// otherwise)
#[cfg(feature = "lockdep")]
type Class = &'static Location<'static>;
#[cfg(not(feature = "lockdep"))]
#[derive(Clone, Copy)]
struct Class;

#[track_caller]
const fn class() -> Class {
    #[cfg(feature = "lockdep")]
    return Location::caller();
    #[cfg(not(feature = "lockdep"))]
    Class
}

/// Before taking lock `id` of `class`: preemption off, then lockdep
/// (`check`: a blocking acquisition, which records order edges)
#[inline(always)]
#[track_caller]
#[allow(unused_variables)]
fn enter(id: usize, class: Class, check: bool) {
    preempt_disable();
    #[cfg(feature = "lockdep")]
    super::lockdep::acquire(id, class, Location::caller(), check);
}

/// After releasing lock `id` (or failing to take it)
#[inline(always)]
#[allow(unused_variables)]
fn leave(id: usize) {
    #[cfg(feature = "lockdep")]
    super::lockdep::release(id);
    preempt_enable();
}

fn addr<T: ?Sized>(p: &T) -> usize {
    p as *const T as *const u8 as usize
}

/// Spinning mutex (Linux spinlock_t)
pub struct Mutex<T: ?Sized> {
    class: Class,
    inner: spin::Mutex<T>,
}

/// Guard of a [`Mutex`]: releases it, then lowers the preempt count
pub struct MutexGuard<'a, T: ?Sized + 'a> {
    id: usize,
    g: ManuallyDrop<spin::MutexGuard<'a, T>>,
}

impl<T> Mutex<T> {
    #[track_caller]
    pub const fn new(v: T) -> Self {
        Self {
            class: class(),
            inner: spin::Mutex::new(v),
        }
    }

    pub fn into_inner(self) -> T {
        self.inner.into_inner()
    }
}

impl<T: ?Sized> Mutex<T> {
    #[track_caller]
    #[inline]
    pub fn lock(&self) -> MutexGuard<'_, T> {
        let id = addr(self);
        enter(id, self.class, true);
        MutexGuard {
            id,
            g: ManuallyDrop::new(self.inner.lock()),
        }
    }

    #[track_caller]
    #[inline]
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        let id = addr(self);
        enter(id, self.class, false);
        match self.inner.try_lock() {
            Some(g) => Some(MutexGuard {
                id,
                g: ManuallyDrop::new(g),
            }),
            None => {
                leave(id);
                None
            }
        }
    }

    pub fn get_mut(&mut self) -> &mut T {
        self.inner.get_mut()
    }
}

impl<T: Default> Default for Mutex<T> {
    #[track_caller]
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for Mutex<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.g
    }
}

impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.g
    }
}

impl<T: ?Sized> Drop for MutexGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: dropped once, here
        unsafe { ManuallyDrop::drop(&mut self.g) };
        leave(self.id);
    }
}

/// Spinning reader-writer lock (Linux rwlock_t; readers and the writer
/// share a lockdep class)
pub struct RwLock<T: ?Sized> {
    class: Class,
    inner: spin::RwLock<T>,
}

pub struct RwLockReadGuard<'a, T: ?Sized + 'a> {
    id: usize,
    g: ManuallyDrop<spin::RwLockReadGuard<'a, T>>,
}

pub struct RwLockWriteGuard<'a, T: ?Sized + 'a> {
    id: usize,
    g: ManuallyDrop<spin::RwLockWriteGuard<'a, T>>,
}

impl<T> RwLock<T> {
    #[track_caller]
    pub const fn new(v: T) -> Self {
        Self {
            class: class(),
            inner: spin::RwLock::new(v),
        }
    }

    pub fn into_inner(self) -> T {
        self.inner.into_inner()
    }
}

impl<T: ?Sized> RwLock<T> {
    #[track_caller]
    #[inline]
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        let id = addr(self);
        enter(id, self.class, true);
        RwLockReadGuard {
            id,
            g: ManuallyDrop::new(self.inner.read()),
        }
    }

    #[track_caller]
    #[inline]
    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        let id = addr(self);
        enter(id, self.class, true);
        RwLockWriteGuard {
            id,
            g: ManuallyDrop::new(self.inner.write()),
        }
    }

    #[track_caller]
    #[inline]
    pub fn try_read(&self) -> Option<RwLockReadGuard<'_, T>> {
        let id = addr(self);
        enter(id, self.class, false);
        match self.inner.try_read() {
            Some(g) => Some(RwLockReadGuard {
                id,
                g: ManuallyDrop::new(g),
            }),
            None => {
                leave(id);
                None
            }
        }
    }

    #[track_caller]
    #[inline]
    pub fn try_write(&self) -> Option<RwLockWriteGuard<'_, T>> {
        let id = addr(self);
        enter(id, self.class, false);
        match self.inner.try_write() {
            Some(g) => Some(RwLockWriteGuard {
                id,
                g: ManuallyDrop::new(g),
            }),
            None => {
                leave(id);
                None
            }
        }
    }

    pub fn get_mut(&mut self) -> &mut T {
        self.inner.get_mut()
    }
}

impl<T: Default> Default for RwLock<T> {
    #[track_caller]
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for RwLock<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl<T: ?Sized> Deref for RwLockReadGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.g
    }
}

impl<T: ?Sized> Drop for RwLockReadGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: dropped once, here
        unsafe { ManuallyDrop::drop(&mut self.g) };
        leave(self.id);
    }
}

impl<T: ?Sized> Deref for RwLockWriteGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.g
    }
}

impl<T: ?Sized> DerefMut for RwLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.g
    }
}

impl<T: ?Sized> Drop for RwLockWriteGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: dropped once, here
        unsafe { ManuallyDrop::drop(&mut self.g) };
        leave(self.id);
    }
}

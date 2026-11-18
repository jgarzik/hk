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
use core::marker::PhantomData;
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
#[cfg_attr(not(feature = "lockdep"), expect(unused_variables))]
fn enter(id: usize, class: Class, check: bool) {
    preempt_disable();
    #[cfg(feature = "lockdep")]
    super::lockdep::acquire(id, class, Location::caller(), check);
}

/// After releasing lock `id` (or failing to take it)
#[inline(always)]
#[cfg_attr(not(feature = "lockdep"), expect(unused_variables))]
fn leave(id: usize) {
    #[cfg(feature = "lockdep")]
    super::lockdep::release(id);
    preempt_enable();
}

/// The lockdep class of a spin lock built outside this module (a bit
/// lock: `util::hlist_bl`, Linux bit_spin_lock)
pub struct RawClass(Class);

impl RawClass {
    #[track_caller]
    pub const fn new() -> Self {
        Self(class())
    }
}

/// Before taking such a lock, `id` its address: preemption off, then
/// lockdep, as for [`Mutex::lock`]
#[inline]
#[track_caller]
pub fn raw_enter(id: usize, c: &RawClass) {
    enter(id, c.0, true);
}

/// After releasing it
#[inline]
pub fn raw_leave(id: usize) {
    leave(id);
}

fn addr<T: ?Sized>(p: &T) -> usize {
    core::ptr::from_ref::<T>(p).cast::<u8>() as usize
}

/// Spinning mutex (Linux spinlock_t on qspinlock)
pub struct Mutex<T: ?Sized> {
    class: Class,
    lock: super::qspinlock::QSpinLock,
    data: core::cell::UnsafeCell<T>,
}

// SAFETY: the lock gives one holder at a time access to `data`
unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}
// SAFETY: moving the mutex moves its data
unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}

/// Guard of a [`Mutex`]: releases it, then lowers the preempt count
pub struct MutexGuard<'a, T: ?Sized + 'a> {
    id: usize,
    m: &'a Mutex<T>,
    /// Holding a lock is CPU state (preempt count, IRQ flags) or owner
    /// state: the guard stays on the task and CPU that took it
    _not_send: PhantomData<*const ()>,
}

impl<T> Mutex<T> {
    #[track_caller]
    pub const fn new(v: T) -> Self {
        Self {
            class: class(),
            lock: super::qspinlock::QSpinLock::new(),
            data: core::cell::UnsafeCell::new(v),
        }
    }

    pub fn into_inner(self) -> T {
        self.data.into_inner()
    }
}

impl<T: ?Sized> Mutex<T> {
    #[track_caller]
    #[inline]
    pub fn lock(&self) -> MutexGuard<'_, T> {
        let id = addr(self);
        enter(id, self.class, true);
        self.lock.lock();
        MutexGuard {
            id,
            m: self,
            _not_send: PhantomData,
        }
    }

    #[track_caller]
    #[inline]
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        let id = addr(self);
        enter(id, self.class, false);
        if self.lock.try_lock() {
            Some(MutexGuard {
                id,
                m: self,
                _not_send: PhantomData,
            })
        } else {
            leave(id);
            None
        }
    }

    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }

    /// Its data's address (std Mutex::data_ptr): a `&T` there is had
    /// only through a guard of this mutex, or `get_mut`
    pub fn data_ptr(&self) -> *const T {
        self.data.get().cast_const()
    }
}

impl<T: Default> Default for Mutex<T> {
    #[track_caller]
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: ?Sized> fmt::Debug for Mutex<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mutex")
            .field("locked", &self.lock.is_locked())
            .finish_non_exhaustive()
    }
}

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard holds the lock
        unsafe { &*self.m.data.get() }
    }
}

impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the guard holds the lock, and `&mut self` is unique
        unsafe { &mut *self.m.data.get() }
    }
}

impl<T: ?Sized> Drop for MutexGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: this guard's acquisition holds it
        unsafe { self.m.lock.unlock() };
        leave(self.id);
    }
}

/// Spinning reader-writer lock (Linux rwlock_t on qrwlock; readers and
/// the writer share a lockdep class)
pub struct RwLock<T: ?Sized> {
    class: Class,
    lock: super::qrwlock::QRwLock,
    data: core::cell::UnsafeCell<T>,
}

// SAFETY: readers share `&T` (T: Sync), the writer gets `&mut T` alone
unsafe impl<T: ?Sized + Send + Sync> Sync for RwLock<T> {}
// SAFETY: moving the lock moves its data
unsafe impl<T: ?Sized + Send> Send for RwLock<T> {}

pub struct RwLockReadGuard<'a, T: ?Sized + 'a> {
    id: usize,
    l: &'a RwLock<T>,
    /// Holding a lock is CPU state (preempt count, IRQ flags) or owner
    /// state: the guard stays on the task and CPU that took it
    _not_send: PhantomData<*const ()>,
}

pub struct RwLockWriteGuard<'a, T: ?Sized + 'a> {
    id: usize,
    l: &'a RwLock<T>,
    /// Holding a lock is CPU state (preempt count, IRQ flags) or owner
    /// state: the guard stays on the task and CPU that took it
    _not_send: PhantomData<*const ()>,
}

impl<T> RwLock<T> {
    #[track_caller]
    pub const fn new(v: T) -> Self {
        Self {
            class: class(),
            lock: super::qrwlock::QRwLock::new(),
            data: core::cell::UnsafeCell::new(v),
        }
    }

    pub fn into_inner(self) -> T {
        self.data.into_inner()
    }
}

impl<T: ?Sized> RwLock<T> {
    #[track_caller]
    #[inline]
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        let id = addr(self);
        enter(id, self.class, true);
        self.lock.read_lock();
        RwLockReadGuard {
            id,
            l: self,
            _not_send: PhantomData,
        }
    }

    #[track_caller]
    #[inline]
    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        let id = addr(self);
        enter(id, self.class, true);
        self.lock.write_lock();
        RwLockWriteGuard {
            id,
            l: self,
            _not_send: PhantomData,
        }
    }

    #[track_caller]
    #[inline]
    pub fn try_read(&self) -> Option<RwLockReadGuard<'_, T>> {
        let id = addr(self);
        enter(id, self.class, false);
        if self.lock.try_read() {
            Some(RwLockReadGuard {
                id,
                l: self,
                _not_send: PhantomData,
            })
        } else {
            leave(id);
            None
        }
    }

    #[track_caller]
    #[inline]
    pub fn try_write(&self) -> Option<RwLockWriteGuard<'_, T>> {
        let id = addr(self);
        enter(id, self.class, false);
        if self.lock.try_write() {
            Some(RwLockWriteGuard {
                id,
                l: self,
                _not_send: PhantomData,
            })
        } else {
            leave(id);
            None
        }
    }

    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }
}

impl<T: Default> Default for RwLock<T> {
    #[track_caller]
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: ?Sized> fmt::Debug for RwLock<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RwLock")
            .field("locked", &self.lock.is_locked())
            .finish_non_exhaustive()
    }
}

impl<T: ?Sized> Deref for RwLockReadGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: held shared: no writer
        unsafe { &*self.l.data.get() }
    }
}

impl<T: ?Sized> Drop for RwLockReadGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: this guard's acquisition holds it shared
        unsafe { self.l.lock.read_unlock() };
        leave(self.id);
    }
}

impl<T: ?Sized> Deref for RwLockWriteGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: held exclusive
        unsafe { &*self.l.data.get() }
    }
}

impl<T: ?Sized> DerefMut for RwLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: held exclusive, and `&mut self` is unique
        unsafe { &mut *self.l.data.get() }
    }
}

impl<T: ?Sized> Drop for RwLockWriteGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: this guard's acquisition holds it exclusive
        unsafe { self.l.lock.write_unlock() };
        leave(self.id);
    }
}

// SAFETY: a guard gives `&T` to whoever shares it, so it is Sync only
// for T: Sync (a guard holding &mut T would otherwise be Sync for any T)
unsafe impl<T: ?Sized + Sync> Sync for MutexGuard<'_, T> {}
// SAFETY: as above (readers share &T)
unsafe impl<T: ?Sized + Sync> Sync for RwLockReadGuard<'_, T> {}
// SAFETY: as above
unsafe impl<T: ?Sized + Sync> Sync for RwLockWriteGuard<'_, T> {}

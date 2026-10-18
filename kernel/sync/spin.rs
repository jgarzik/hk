//! Spinning locks for thread context (Linux spinlock_t / rwlock_t
//! without IRQ disabling): `Mutex` and `RwLock`
//!
//! Kernel code takes these instead of `spin::Mutex` / `spin::RwLock`
//! directly. In a normal build they are the `spin` crate's types
//! (re-exported, zero cost). With the `lockdep` feature they are thin
//! wrappers that report every acquisition and release to
//! `sync::lockdep`: per-CPU held-lock stacks give the spin-hold depth
//! that `might_sleep` checks, and lock classes (the source location of
//! the lock's `new()`, like Linux's static lock_class_key) record the
//! observed A -> B nesting order, reporting the first inverse edge.

#[cfg(not(feature = "lockdep"))]
pub use spin::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

#[cfg(feature = "lockdep")]
pub use tracked::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

#[cfg(feature = "lockdep")]
mod tracked {
    use core::fmt;
    use core::ops::{Deref, DerefMut};
    use core::panic::Location;

    use super::super::lockdep;

    /// Tracked `spin::Mutex`
    pub struct Mutex<T: ?Sized> {
        class: &'static Location<'static>,
        inner: spin::Mutex<T>,
    }

    /// Guard of a tracked `Mutex`
    pub struct MutexGuard<'a, T: ?Sized + 'a> {
        id: usize,
        g: spin::MutexGuard<'a, T>,
    }

    impl<T> Mutex<T> {
        #[track_caller]
        pub const fn new(v: T) -> Self {
            Self {
                class: Location::caller(),
                inner: spin::Mutex::new(v),
            }
        }

        pub fn into_inner(self) -> T {
            self.inner.into_inner()
        }
    }

    impl<T: ?Sized> Mutex<T> {
        fn id(&self) -> usize {
            self as *const Self as *const u8 as usize
        }

        #[track_caller]
        pub fn lock(&self) -> MutexGuard<'_, T> {
            lockdep::acquire(self.id(), self.class, Location::caller(), true);
            MutexGuard {
                id: self.id(),
                g: self.inner.lock(),
            }
        }

        #[track_caller]
        pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
            let g = self.inner.try_lock()?;
            lockdep::acquire(self.id(), self.class, Location::caller(), false);
            Some(MutexGuard { id: self.id(), g })
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
        fn drop(&mut self) {
            lockdep::release(self.id);
        }
    }

    /// Tracked `spin::RwLock` (readers and the writer share a class)
    pub struct RwLock<T: ?Sized> {
        class: &'static Location<'static>,
        inner: spin::RwLock<T>,
    }

    pub struct RwLockReadGuard<'a, T: ?Sized + 'a> {
        id: usize,
        g: spin::RwLockReadGuard<'a, T>,
    }

    pub struct RwLockWriteGuard<'a, T: ?Sized + 'a> {
        id: usize,
        g: spin::RwLockWriteGuard<'a, T>,
    }

    impl<T> RwLock<T> {
        #[track_caller]
        pub const fn new(v: T) -> Self {
            Self {
                class: Location::caller(),
                inner: spin::RwLock::new(v),
            }
        }

        pub fn into_inner(self) -> T {
            self.inner.into_inner()
        }
    }

    impl<T: ?Sized> RwLock<T> {
        fn id(&self) -> usize {
            self as *const Self as *const u8 as usize
        }

        #[track_caller]
        pub fn read(&self) -> RwLockReadGuard<'_, T> {
            lockdep::acquire(self.id(), self.class, Location::caller(), true);
            RwLockReadGuard {
                id: self.id(),
                g: self.inner.read(),
            }
        }

        #[track_caller]
        pub fn write(&self) -> RwLockWriteGuard<'_, T> {
            lockdep::acquire(self.id(), self.class, Location::caller(), true);
            RwLockWriteGuard {
                id: self.id(),
                g: self.inner.write(),
            }
        }

        #[track_caller]
        pub fn try_read(&self) -> Option<RwLockReadGuard<'_, T>> {
            let g = self.inner.try_read()?;
            lockdep::acquire(self.id(), self.class, Location::caller(), false);
            Some(RwLockReadGuard { id: self.id(), g })
        }

        #[track_caller]
        pub fn try_write(&self) -> Option<RwLockWriteGuard<'_, T>> {
            let g = self.inner.try_write()?;
            lockdep::acquire(self.id(), self.class, Location::caller(), false);
            Some(RwLockWriteGuard { id: self.id(), g })
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
        fn drop(&mut self) {
            lockdep::release(self.id);
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
        fn drop(&mut self) {
            lockdep::release(self.id);
        }
    }
}

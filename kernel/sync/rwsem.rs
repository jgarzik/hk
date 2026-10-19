//! Sleeping reader/writer semaphore (Linux `struct rw_semaphore`)
//!
//! Many readers or one writer, guarding a `T` (`()` for a semaphore that
//! guards what its owner says, like `i_rwsem`). Writer preference: once
//! a writer waits, new readers queue behind it, so a stream of readers
//! cannot starve writers. The count word is guarded by a short
//! crate::sync::spin::Mutex (a leaf, never held across a sleep); waiters
//! sleep on one wait queue and are all woken on release (their
//! conditions differ, see LOCKING.md wait queues).
//!
//! `read`/`write` return guards; `*_killable` give up with
//! `KernelError::Interrupted` (EINTR) once SIGKILL is pending (Linux
//! down_read_killable / down_write_killable); `try_*` never sleep. The
//! raw `down_*`/`up_*` pairs serve callers that lock and unlock in
//! different scopes.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};

use crate::sync::spin::Mutex as SpinMutex;

use super::{can_sleep, might_sleep};
use crate::error::KernelError;
use crate::waitqueue::WaitQueue;

#[derive(Default)]
struct Count {
    readers: u32,
    writer: bool,
    waiting_writers: u32,
}

impl Count {
    /// A new reader may enter
    fn read_ok(&self) -> bool {
        !self.writer && self.waiting_writers == 0
    }

    /// A writer may enter
    fn write_ok(&self) -> bool {
        !self.writer && self.readers == 0
    }
}

/// Sleeping reader/writer lock over a `T`
pub struct RwSem<T: ?Sized = ()> {
    count: SpinMutex<Count>,
    wq: WaitQueue,
    data: UnsafeCell<T>,
}

// SAFETY: `data` is shared only by readers (needs Sync) and handed to
// one writer at a time (needs Send)
unsafe impl<T: ?Sized + Send> Send for RwSem<T> {}
unsafe impl<T: ?Sized + Send + Sync> Sync for RwSem<T> {}

impl<T: Default> Default for RwSem<T> {
    #[track_caller]
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T> RwSem<T> {
    /// New unlocked semaphore guarding `v`
    #[track_caller]
    pub const fn new(v: T) -> Self {
        Self {
            count: SpinMutex::new(Count {
                readers: 0,
                writer: false,
                waiting_writers: 0,
            }),
            wq: WaitQueue::new(),
            data: UnsafeCell::new(v),
        }
    }
}

impl<T: ?Sized> RwSem<T> {
    /// Sleep (or spin before scheduling) until `ok` might hold; with
    /// `killable`, give up once SIGKILL is pending
    fn wait(&self, ok: fn(&Count) -> bool, killable: bool) -> Result<(), KernelError> {
        if !can_sleep() {
            core::hint::spin_loop();
            return Ok(());
        }
        let cond = || ok(&self.count.lock());
        if killable {
            self.wq.wait_event_killable(cond)
        } else {
            self.wq.wait_event(cond);
            Ok(())
        }
    }

    /// One attempt at a read hold
    fn grab_read(&self) -> bool {
        let mut c = self.count.lock();
        let ok = c.read_ok();
        if ok {
            c.readers += 1;
        }
        ok
    }

    /// One attempt at the write hold by a counted waiting writer
    fn grab_write(&self) -> bool {
        let mut c = self.count.lock();
        let ok = c.write_ok();
        if ok {
            c.writer = true;
            c.waiting_writers -= 1;
        }
        ok
    }

    fn lock_read(&self, killable: bool) -> Result<(), KernelError> {
        while !self.grab_read() {
            self.wait(Count::read_ok, killable)?;
        }
        Ok(())
    }

    fn lock_write(&self, killable: bool) -> Result<(), KernelError> {
        self.count.lock().waiting_writers += 1;
        while !self.grab_write() {
            if let Err(e) = self.wait(Count::write_ok, killable) {
                self.count.lock().waiting_writers -= 1;
                // Readers queued behind this writer may go now
                self.wq.wake_all();
                return Err(e);
            }
        }
        Ok(())
    }

    /// Shared acquire (Linux down_read)
    #[track_caller]
    pub fn down_read(&self) {
        might_sleep();
        let _ = self.lock_read(false);
    }

    /// Release a shared hold (Linux up_read)
    ///
    /// # Safety
    /// The caller must hold the semaphore shared.
    pub unsafe fn up_read(&self) {
        let last = {
            let mut c = self.count.lock();
            c.readers -= 1;
            c.readers == 0
        };
        if last {
            self.wq.wake_all();
        }
    }

    /// Exclusive acquire (Linux down_write)
    #[track_caller]
    pub fn down_write(&self) {
        might_sleep();
        let _ = self.lock_write(false);
    }

    /// Release an exclusive hold (Linux up_write)
    ///
    /// # Safety
    /// The caller must hold the semaphore exclusively.
    pub unsafe fn up_write(&self) {
        self.count.lock().writer = false;
        self.wq.wake_all();
    }

    /// Shared hold (Linux down_read)
    #[track_caller]
    pub fn read(&self) -> RwSemReadGuard<'_, T> {
        self.down_read();
        RwSemReadGuard { s: self }
    }

    /// Exclusive hold (Linux down_write)
    #[track_caller]
    pub fn write(&self) -> RwSemWriteGuard<'_, T> {
        self.down_write();
        RwSemWriteGuard { s: self }
    }

    /// Shared hold, or EINTR once SIGKILL is pending (Linux
    /// down_read_killable)
    #[track_caller]
    pub fn read_killable(&self) -> Result<RwSemReadGuard<'_, T>, KernelError> {
        might_sleep();
        self.lock_read(true)?;
        Ok(RwSemReadGuard { s: self })
    }

    /// Exclusive hold, or EINTR once SIGKILL is pending (Linux
    /// down_write_killable)
    #[track_caller]
    pub fn write_killable(&self) -> Result<RwSemWriteGuard<'_, T>, KernelError> {
        might_sleep();
        self.lock_write(true)?;
        Ok(RwSemWriteGuard { s: self })
    }

    /// Shared hold if available without sleeping (Linux down_read_trylock)
    pub fn try_read(&self) -> Option<RwSemReadGuard<'_, T>> {
        self.grab_read().then_some(RwSemReadGuard { s: self })
    }

    /// Exclusive hold if available without sleeping (Linux
    /// down_write_trylock)
    pub fn try_write(&self) -> Option<RwSemWriteGuard<'_, T>> {
        let mut c = self.count.lock();
        if !c.write_ok() {
            return None;
        }
        c.writer = true;
        Some(RwSemWriteGuard { s: self })
    }

    /// The data, through exclusive ownership (no locking)
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }
}

/// A shared hold of a `RwSem`, released on drop
pub struct RwSemReadGuard<'a, T: ?Sized> {
    s: &'a RwSem<T>,
}

impl<T: ?Sized> Deref for RwSemReadGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: readers share the data; no writer while held
        unsafe { &*self.s.data.get() }
    }
}

impl<T: ?Sized> Drop for RwSemReadGuard<'_, T> {
    fn drop(&mut self) {
        // SAFETY: the guard holds the semaphore shared
        unsafe { self.s.up_read() };
    }
}

/// The exclusive hold of a `RwSem`, released on drop
pub struct RwSemWriteGuard<'a, T: ?Sized> {
    s: &'a RwSem<T>,
}

impl<T: ?Sized> Deref for RwSemWriteGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard holds the semaphore exclusively
        unsafe { &*self.s.data.get() }
    }
}

impl<T: ?Sized> DerefMut for RwSemWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the guard holds the semaphore exclusively
        unsafe { &mut *self.s.data.get() }
    }
}

impl<T: ?Sized> Drop for RwSemWriteGuard<'_, T> {
    fn drop(&mut self) {
        // SAFETY: the guard holds the semaphore exclusively
        unsafe { self.s.up_write() };
    }
}

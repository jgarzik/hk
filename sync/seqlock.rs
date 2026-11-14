//! Sequence counts and locks (Linux seqcount_t, seqlock_t): writers bump
//! a sequence counter around their change (odd while writing); lockless
//! readers sample the counter, read, and retry if it moved or was odd.
//! A `SeqCount`'s writers serialize on a lock of their own; a `SeqLock`
//! brings one, a spin lock, and a `SeqRwLock` a spin reader-writer lock
//! whose readers see one consistent picture. Thread context; not for
//! IRQ handlers (as Linux's mount_lock and rename_lock).

use core::sync::atomic::{AtomicU32, Ordering, fence};

use crate::sync::spin::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// A sequence counter whose writers hold a lock of their own (Linux
/// seqcount_t)
pub struct SeqCount {
    seq: AtomicU32,
}

/// A write section of a `SeqCount` (Linux write_seqcount_begin ..
/// write_seqcount_end)
#[must_use]
pub struct SeqCountGuard<'a>(&'a SeqCount);

impl SeqCount {
    pub const fn new() -> Self {
        Self {
            seq: AtomicU32::new(0),
        }
    }

    /// Begin a write, under the writers' lock (Linux
    /// write_seqcount_begin): the counter goes odd before any of the
    /// writer's stores (smp_wmb after the increment)
    pub fn write(&self) -> SeqCountGuard<'_> {
        self.seq.fetch_add(1, Ordering::Relaxed);
        fence(Ordering::Release);
        SeqCountGuard(self)
    }

    /// Begin a lockless read (Linux read_seqcount_begin): waits out a
    /// writer
    pub fn read_begin(&self) -> u32 {
        loop {
            let s = self.seq.load(Ordering::Acquire);
            if s & 1 == 0 {
                return s;
            }
            core::hint::spin_loop();
        }
    }

    /// The read since `start` raced a writer and must be repeated (Linux
    /// read_seqcount_retry: smp_rmb, then the counter)
    pub fn read_retry(&self, start: u32) -> bool {
        fence(Ordering::Acquire);
        self.seq.load(Ordering::Relaxed) != start
    }
}

impl Drop for SeqCountGuard<'_> {
    /// Linux write_seqcount_end: the writer's stores before the counter
    /// goes even (smp_wmb, then the increment)
    fn drop(&mut self) {
        self.0.seq.fetch_add(1, Ordering::Release);
    }
}

/// A spin lock with a sequence (Linux seqlock_t) over `T`: its writers
/// and locking readers own `T` (a [`super::UniqueOwner`] for data kept
/// elsewhere, as the mount tree's links under mount_lock)
pub struct SeqLock<T = ()> {
    lock: Mutex<T>,
    seq: SeqCount,
}

/// A held write side (Linux write_seqlock .. write_sequnlock): fields
/// drop in order, so the count goes even before the lock is released
pub struct SeqWriteGuard<'a, T = ()> {
    _c: SeqCountGuard<'a>,
    g: MutexGuard<'a, T>,
}

impl<T> core::ops::Deref for SeqWriteGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.g
    }
}

impl<T> core::ops::DerefMut for SeqWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.g
    }
}

impl<T> SeqLock<T> {
    #[track_caller]
    pub const fn new(v: T) -> Self {
        Self {
            lock: Mutex::new(v),
            seq: SeqCount::new(),
        }
    }

    /// Take the write side (Linux write_seqlock)
    pub fn write(&self) -> SeqWriteGuard<'_, T> {
        let g = self.lock.lock();
        SeqWriteGuard {
            _c: self.seq.write(),
            g,
        }
    }

    /// A locking read: no writer, nor another locking reader, while
    /// held; the sequence does not move (Linux read_seqlock_excl)
    pub fn read_excl(&self) -> MutexGuard<'_, T> {
        self.lock.lock()
    }

    /// Begin a lockless read (Linux read_seqbegin): waits out a writer
    pub fn read_begin(&self) -> u32 {
        self.seq.read_begin()
    }

    /// The read since `start` raced a writer and must be repeated (Linux
    /// read_seqretry)
    pub fn read_retry(&self, start: u32) -> bool {
        self.seq.read_retry(start)
    }
}

/// A spin reader-writer lock whose write side bumps a sequence (Linux
/// rename_lock, a seqlock_t: locking readers here share the lock where
/// Linux's read_seqlock_excl excludes them; lockless readers sample the
/// sequence)
pub struct SeqRwLock {
    lock: RwLock<()>,
    seq: SeqCount,
}

/// A held write side: fields drop in order, so the count goes even
/// before the lock is released
pub struct SeqRwWriteGuard<'a> {
    _c: SeqCountGuard<'a>,
    _g: RwLockWriteGuard<'a, ()>,
}

impl SeqRwLock {
    pub const fn new() -> Self {
        Self {
            lock: RwLock::new(()),
            seq: SeqCount::new(),
        }
    }

    /// The write side (Linux write_seqlock): the sequence odd while held
    pub fn write(&self) -> SeqRwWriteGuard<'_> {
        let g = self.lock.write();
        SeqRwWriteGuard {
            _c: self.seq.write(),
            _g: g,
        }
    }

    /// A locking read: no writer while held (Linux read_seqlock_excl)
    pub fn read(&self) -> RwLockReadGuard<'_, ()> {
        self.lock.read()
    }

    /// Begin a lockless read (Linux read_seqbegin): waits out a writer
    pub fn read_begin(&self) -> u32 {
        self.seq.read_begin()
    }

    /// The read since `start` raced a writer (Linux read_seqretry)
    pub fn read_retry(&self, start: u32) -> bool {
        self.seq.read_retry(start)
    }
}

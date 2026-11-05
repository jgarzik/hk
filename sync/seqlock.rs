//! Sequence lock (Linux seqlock_t): writers serialize on a spin lock and
//! bump a sequence counter around their change (odd while writing);
//! lockless readers sample the counter, read, and retry if it moved or
//! was odd. Thread context; not for IRQ handlers (the writer's lock is a
//! plain spin lock, as Linux's mount_lock).

use core::sync::atomic::{AtomicU32, Ordering, fence};

use crate::sync::spin::{Mutex, MutexGuard};

pub struct SeqLock {
    lock: Mutex<()>,
    seq: AtomicU32,
}

/// A held write side (Linux write_seqlock .. write_sequnlock)
pub struct SeqWriteGuard<'a> {
    s: &'a SeqLock,
    _g: MutexGuard<'a, ()>,
}

impl SeqLock {
    pub const fn new() -> Self {
        Self {
            lock: Mutex::new(()),
            seq: AtomicU32::new(0),
        }
    }

    /// Take the write side (Linux write_seqlock): the counter goes odd
    /// before any of the writer's stores (smp_wmb after the increment)
    pub fn write(&self) -> SeqWriteGuard<'_> {
        let g = self.lock.lock();
        self.seq.fetch_add(1, Ordering::Relaxed);
        fence(Ordering::Release);
        SeqWriteGuard { s: self, _g: g }
    }

    /// Begin a lockless read (Linux read_seqbegin): waits out a writer
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
    /// read_seqretry: smp_rmb, then the counter)
    pub fn read_retry(&self, start: u32) -> bool {
        fence(Ordering::Acquire);
        self.seq.load(Ordering::Relaxed) != start
    }
}

impl Default for SeqLock {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SeqWriteGuard<'_> {
    /// Linux write_sequnlock: the writer's stores before the counter
    /// goes even (smp_wmb, then the increment), then the lock
    fn drop(&mut self) {
        self.s.seq.fetch_add(1, Ordering::Release);
    }
}

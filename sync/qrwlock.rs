//! Queued reader-writer lock (Linux kernel/locking/qrwlock.c,
//! asm-generic/qrwlock.h)
//!
//! One 32-bit count word and a queued spin lock (`wait_lock`):
//!
//! ```text
//!     0-7: writer locked byte (_QW_LOCKED)
//!       8: a writer waits (_QW_WAITING)
//!    9-31: readers (_QR_BIAS each)
//! ```
//!
//! Uncontended, a reader adds its bias and a writer swaps 0 for locked.
//! Contenders line up on `wait_lock`, so readers and writers are served
//! in arrival order: a reader that finds a writer backs its bias out and
//! queues, a writer that finds readers marks itself waiting (which keeps
//! new readers off the fast path) and waits for them to drain. A reader
//! in interrupt context does not queue (Linux: it may interrupt the
//! holder's own CPU) and only waits for the writer to go. A write unlock
//! is a byte store-release of the locked byte (`arch::qspin`).

use core::sync::atomic::{AtomicU32, Ordering};

use super::qspinlock::QSpinLock;

const QW_WAITING: u32 = 0x100;
const QW_LOCKED: u32 = 0x0ff;
const QW_WMASK: u32 = 0x1ff;
const QR_SHIFT: u32 = 9;
const QR_BIAS: u32 = 1 << QR_SHIFT;

/// The lock (Linux struct qrwlock)
#[repr(C)]
pub struct QRwLock {
    cnts: AtomicU32,
    wait_lock: QSpinLock,
}

/// Spin until `cond` holds of the count, loads `ord` (Linux
/// atomic_cond_read_*)
#[inline]
fn cond_read(a: &AtomicU32, ord: Ordering, cond: impl Fn(u32) -> bool) -> u32 {
    loop {
        let v = a.load(ord);
        if cond(v) {
            return v;
        }
        core::hint::spin_loop();
    }
}

impl QRwLock {
    pub const fn new() -> Self {
        Self {
            cnts: AtomicU32::new(0),
            wait_lock: QSpinLock::new(),
        }
    }

    /// Readers or a writer hold it (Linux queued_rwlock_is_contended's
    /// cousin: any holder)
    pub fn is_locked(&self) -> bool {
        self.cnts.load(Ordering::Relaxed) != 0
    }

    /// Take it shared (Linux queued_read_lock)
    #[inline]
    pub fn read_lock(&self) {
        let cnts = self.cnts.fetch_add(QR_BIAS, Ordering::Acquire) + QR_BIAS;
        if cnts & QW_WMASK == 0 {
            return;
        }
        self.read_lock_slowpath();
    }

    /// Linux queued_read_lock_slowpath
    #[cold]
    fn read_lock_slowpath(&self) {
        // Interrupt context: no queueing, just wait out the writer
        if super::in_interrupt() {
            cond_read(&self.cnts, Ordering::Acquire, |v| v & QW_LOCKED == 0);
            return;
        }
        self.cnts.fetch_sub(QR_BIAS, Ordering::Relaxed);
        // Queue behind whoever came first
        self.wait_lock.lock();
        self.cnts.fetch_add(QR_BIAS, Ordering::Relaxed);
        // A writer at the head of the queue may still hold it
        cond_read(&self.cnts, Ordering::Acquire, |v| v & QW_LOCKED == 0);
        // SAFETY: taken just above
        unsafe { self.wait_lock.unlock() };
    }

    /// Take it shared if no writer holds or waits for it (Linux
    /// queued_read_trylock)
    #[inline]
    pub fn try_read(&self) -> bool {
        let cnts = self.cnts.load(Ordering::Relaxed);
        if cnts & QW_WMASK == 0 {
            let cnts = self.cnts.fetch_add(QR_BIAS, Ordering::Acquire) + QR_BIAS;
            if cnts & QW_WMASK == 0 {
                return true;
            }
            self.cnts.fetch_sub(QR_BIAS, Ordering::Relaxed);
        }
        false
    }

    /// Give back a shared hold (Linux queued_read_unlock)
    ///
    /// # Safety
    /// The caller holds it shared.
    #[inline]
    pub unsafe fn read_unlock(&self) {
        self.cnts.fetch_sub(QR_BIAS, Ordering::Release);
    }

    /// Take it exclusive (Linux queued_write_lock)
    #[inline]
    pub fn write_lock(&self) {
        if self
            .cnts
            .compare_exchange(0, QW_LOCKED, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
        self.write_lock_slowpath();
    }

    /// Linux queued_write_lock_slowpath
    #[cold]
    fn write_lock_slowpath(&self) {
        self.wait_lock.lock();
        let free = self.cnts.load(Ordering::Relaxed) == 0
            && self
                .cnts
                .compare_exchange(0, QW_LOCKED, Ordering::Acquire, Ordering::Relaxed)
                .is_ok();
        if !free {
            // Mark a writer waiting: new readers take the slow path
            self.cnts.fetch_or(QW_WAITING, Ordering::Relaxed);
            // Readers drain, then waiting -> locked
            loop {
                let c = cond_read(&self.cnts, Ordering::Relaxed, |v| v == QW_WAITING);
                if self
                    .cnts
                    .compare_exchange(c, QW_LOCKED, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
            }
        }
        // SAFETY: taken at the top
        unsafe { self.wait_lock.unlock() };
    }

    /// Take it exclusive if free (Linux queued_write_trylock)
    #[inline]
    pub fn try_write(&self) -> bool {
        self.cnts.load(Ordering::Relaxed) == 0
            && self
                .cnts
                .compare_exchange(0, QW_LOCKED, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
    }

    /// Give back the exclusive hold (Linux queued_write_unlock: a byte
    /// store-release of the locked byte)
    ///
    /// # Safety
    /// The caller holds it exclusive.
    #[inline]
    pub unsafe fn write_unlock(&self) {
        // SAFETY: the writer byte (byte 0, little-endian) of this live
        // word; only the holder writes it now (readers and a waiting
        // writer change the other bytes with 32-bit atomics)
        unsafe {
            crate::arch::qspin::store_release_u8(self.cnts.as_ptr().cast::<u8>(), 0);
        }
    }
}

impl Default for QRwLock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::cell::UnsafeCell;

    struct Shared {
        lock: QRwLock,
        pair: UnsafeCell<(u64, u64)>,
    }
    // SAFETY: `pair` is written under the write lock, read under either
    unsafe impl Sync for Shared {}

    #[test]
    fn exclusion() {
        let l = QRwLock::new();
        l.read_lock();
        assert!(l.try_read());
        assert!(!l.try_write());
        // SAFETY: two shared holds
        unsafe {
            l.read_unlock();
            l.read_unlock();
        }
        l.write_lock();
        assert!(!l.try_read());
        assert!(!l.try_write());
        // SAFETY: held exclusive
        unsafe { l.write_unlock() };
        assert_eq!(l.cnts.load(Ordering::Relaxed), 0);
    }

    /// Writers keep the two halves equal; readers never see them differ
    #[test]
    fn readers_and_writers() {
        let s = Arc::new(Shared {
            lock: QRwLock::new(),
            pair: UnsafeCell::new((0, 0)),
        });
        let hs: alloc::vec::Vec<_> = (0..8)
            .map(|i| {
                let s = s.clone();
                std::thread::spawn(move || {
                    for _ in 0..10_000 {
                        if i % 2 == 0 {
                            s.lock.write_lock();
                            // SAFETY: held exclusive
                            unsafe {
                                let p = &mut *s.pair.get();
                                p.0 += 1;
                                p.1 += 1;
                                s.lock.write_unlock();
                            }
                        } else {
                            s.lock.read_lock();
                            // SAFETY: held shared, writers excluded
                            let (a, b) = unsafe { *s.pair.get() };
                            assert_eq!(a, b);
                            // SAFETY: held shared
                            unsafe { s.lock.read_unlock() };
                        }
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        // SAFETY: every thread is done
        assert_eq!(unsafe { *s.pair.get() }, (40_000, 40_000));
        assert_eq!(s.lock.cnts.load(Ordering::Relaxed), 0);
    }
}

//! Rate limiting (Linux lib/ratelimit.c, include/linux/ratelimit.h):
//! at most `burst` events per `interval` ticks; the rest are suppressed
//! and counted, and the count is reported when the next interval
//! starts. A caller keeps its state in a static (Linux
//! DEFINE_RATELIMIT_STATE; printk_ratelimited's DEFAULT_RATELIMIT_*).
//!
//! Any context, hardirq included: the state's lock (`IrqSpinlock`
//! leaf; the report is printed after it is dropped) is only tried; a
//! caller that finds it held takes from the burst left without it, as
//! Linux.

use core::sync::atomic::{AtomicI32, Ordering};

use crate::sync::IrqSpinlock;
use crate::task::percpu::{TICK_MS, get_ticks};

/// Ticks per second (Linux HZ)
const HZ: u64 = 1000 / TICK_MS;
/// Linux DEFAULT_RATELIMIT_INTERVAL: 5 s
pub const DEFAULT_RATELIMIT_INTERVAL: u64 = 5 * HZ;
/// Linux DEFAULT_RATELIMIT_BURST
pub const DEFAULT_RATELIMIT_BURST: i32 = 10;

/// The interval's start; None before the first event (Linux begin,
/// RATELIMIT_INITIALIZED)
struct Begin(Option<u64>);

/// One rate limit (Linux struct ratelimit_state)
pub struct RatelimitState {
    lock: IrqSpinlock<Begin>,
    interval: u64,
    burst: i32,
    /// Events still allowed in this interval (Linux rs_n_left)
    n_left: AtomicI32,
    /// Events suppressed since the last report (Linux missed)
    missed: AtomicI32,
    /// No suppressed-count report at an interval's start (Linux
    /// RATELIMIT_MSG_ON_RELEASE; a static state is never released)
    msg_on_release: bool,
}

impl RatelimitState {
    /// `burst` events per `interval` ticks (Linux
    /// DEFINE_RATELIMIT_STATE)
    pub const fn new(interval: u64, burst: i32) -> Self {
        Self {
            lock: IrqSpinlock::new(Begin(None)),
            interval,
            burst,
            n_left: AtomicI32::new(0),
            missed: AtomicI32::new(0),
            msg_on_release: false,
        }
    }

    /// The state with RATELIMIT_MSG_ON_RELEASE (Linux
    /// ratelimit_set_flags)
    pub const fn msg_on_release(self) -> Self {
        Self {
            msg_on_release: true,
            ..self
        }
    }

    /// Take one event from the burst left (Linux atomic_dec_return of
    /// rs_n_left after its read)
    fn take(&self) -> bool {
        self.n_left.load(Ordering::Relaxed) > 0 && self.n_left.fetch_sub(1, Ordering::Relaxed) > 0
    }

    /// Whether the event may go ahead (Linux ___ratelimit; `func` names
    /// the caller in the suppressed-count report)
    pub fn ratelimit(&self, func: &str) -> bool {
        let ok = match self.lock.try_lock() {
            // Contended: only the burst left, maybe stale (Linux)
            None => self.take(),
            Some(mut b) => {
                let now = get_ticks();
                let begin = *b.0.get_or_insert_with(|| {
                    self.n_left.store(self.burst, Ordering::Relaxed);
                    now
                });
                let mut m = 0;
                if now.wrapping_sub(begin) > self.interval {
                    self.n_left.store(self.burst, Ordering::Relaxed);
                    b.0 = Some(now);
                    if !self.msg_on_release {
                        m = self.missed.swap(0, Ordering::Relaxed);
                    }
                }
                let ok = self.take();
                // Printed after the unlock, which keeps the lock a leaf
                // (Linux printk_deferred under it)
                drop(b);
                if m != 0 {
                    crate::printkln!("{}: {} callbacks suppressed", func, m);
                }
                ok
            }
        };
        if !ok {
            self.missed.fetch_add(1, Ordering::Relaxed);
        }
        ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `burst` events go ahead within an interval, the rest are
    /// counted as missed
    #[test]
    fn burst() {
        let rs = RatelimitState::new(u64::MAX / 2, 3);
        let ok = (0..5).filter(|_| rs.ratelimit("t")).count();
        assert_eq!(ok, 3);
        assert_eq!(rs.missed.load(Ordering::Relaxed), 2);
        // Contended: only the burst left decides (none)
        let g = rs.lock.lock();
        assert!(!rs.ratelimit("t"));
        drop(g);
        assert_eq!(rs.missed.load(Ordering::Relaxed), 3);
    }
}

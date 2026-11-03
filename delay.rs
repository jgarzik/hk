//! Busy-wait delays and register polling (Linux linux/delay.h udelay,
//! mdelay and linux/iopoll.h read_poll_timeout_atomic)
//!
//! Drivers wait for hardware in real time, not in loop iterations: an
//! iteration count tuned under KVM (where PAUSE exits make each spin
//! slow) is far too short on bare metal. The clock is the monotonic
//! timekeeper, chosen once per wait; without it (early boot, or no
//! clock source), each PAUSE counts as a nanosecond and each poll of
//! the condition (a device register read) as a microsecond: rough, but
//! bounded either way.
//!
//! These spin and may run in any context (interrupts off included);
//! code that may sleep should prefer `task::percpu::sleep_current_ms`
//! for long waits.
//!
//! Locking: none.

/// The polled register never reached the wanted state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeout;

/// A nanosecond clock and a way to pass time (the monotonic timekeeper
/// and PAUSE; host tests use a fake)
pub trait Clock {
    fn now_ns(&mut self) -> u64;
    fn relax(&mut self);
    /// The condition was polled once (a counting clock charges for it)
    fn polled(&mut self) {}
}

/// The kernel's clock: TIMEKEEPER, else counting (decided at creation,
/// so one wait never mixes the two)
pub struct Monotonic {
    timekeeper: bool,
    count_ns: u64,
}

impl Monotonic {
    pub fn new() -> Self {
        Self {
            timekeeper: crate::time::TIMEKEEPER.is_initialized(),
            count_ns: 0,
        }
    }
}

impl Default for Monotonic {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for Monotonic {
    fn now_ns(&mut self) -> u64 {
        if self.timekeeper {
            crate::time::monotonic_ns()
        } else {
            self.count_ns
        }
    }

    fn relax(&mut self) {
        core::hint::spin_loop();
        self.count_ns += 1;
    }

    fn polled(&mut self) {
        self.count_ns += 1000;
    }
}

/// Spin for at least `ns` nanoseconds on `clock`
pub fn delay_on(clock: &mut impl Clock, ns: u64) {
    let start = clock.now_ns();
    while clock.now_ns().saturating_sub(start) < ns {
        clock.relax();
    }
}

/// Spin for at least `us` microseconds (Linux udelay)
pub fn udelay(us: u64) {
    delay_on(&mut Monotonic::new(), us.saturating_mul(1000));
}

/// Spin for at least `ms` milliseconds (Linux mdelay)
pub fn mdelay(ms: u64) {
    delay_on(&mut Monotonic::new(), ms.saturating_mul(1_000_000));
}

/// Poll `cond` every `interval_us` (0: back to back) until it holds or
/// `timeout_us` passed, then look once more (Linux
/// read_poll_timeout_atomic): Ok if it held
pub fn poll_on(
    clock: &mut impl Clock,
    timeout_us: u64,
    interval_us: u64,
    mut cond: impl FnMut() -> bool,
) -> Result<(), Timeout> {
    let start = clock.now_ns();
    let timeout_ns = timeout_us.saturating_mul(1000);
    loop {
        let ok = cond();
        clock.polled();
        if ok {
            return Ok(());
        }
        if clock.now_ns().saturating_sub(start) > timeout_ns {
            return if cond() { Ok(()) } else { Err(Timeout) };
        }
        if interval_us == 0 {
            clock.relax();
        } else {
            delay_on(clock, interval_us.saturating_mul(1000));
        }
    }
}

/// `poll_on` the kernel's clock
pub fn poll_timeout(
    timeout_us: u64,
    interval_us: u64,
    cond: impl FnMut() -> bool,
) -> Result<(), Timeout> {
    poll_on(&mut Monotonic::new(), timeout_us, interval_us, cond)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Virtual time: each relax advances it by `step` ns
    pub struct FakeClock {
        pub now: u64,
        pub step: u64,
    }

    impl Clock for FakeClock {
        fn now_ns(&mut self) -> u64 {
            self.now
        }
        fn relax(&mut self) {
            self.now += self.step;
        }
    }

    #[test]
    fn delay_waits_at_least() {
        let mut c = FakeClock { now: 5, step: 7 };
        delay_on(&mut c, 1000);
        assert!(c.now - 5 >= 1000);
    }

    #[test]
    fn poll_succeeds_at_once() {
        let mut c = FakeClock { now: 0, step: 1 };
        assert_eq!(poll_on(&mut c, 0, 0, || true), Ok(()));
        assert_eq!(c.now, 0);
    }

    #[test]
    fn poll_succeeds_later() {
        let mut c = FakeClock { now: 0, step: 1000 };
        let mut n = 0;
        let r = poll_on(&mut c, 1_000_000, 10, || {
            n += 1;
            n == 5
        });
        assert_eq!(r, Ok(()));
        // four 10 us intervals passed
        assert!(c.now >= 40_000 && c.now < 1_000_000_000);
    }

    #[test]
    fn poll_times_out_in_time() {
        let mut c = FakeClock { now: 0, step: 1000 };
        let r = poll_on(&mut c, 1000, 10, || false);
        assert_eq!(r, Err(Timeout));
        assert!(c.now > 1_000_000 && c.now <= 1_000_000 + 20_000);
    }

    /// The condition that turns true just as time runs out still counts
    #[test]
    fn poll_last_look() {
        let mut c = FakeClock {
            now: 0,
            step: 1_000_000,
        };
        let mut n = 0;
        let r = poll_on(&mut c, 1, 0, || {
            n += 1;
            n == 3
        });
        assert_eq!(r, Ok(()));
    }
}

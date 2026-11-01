//! rt bandwidth (Linux kernel/sched/rt.c: rt_rq->rt_time,
//! sched_rt_runtime_exceeded, do_sched_rt_period_timer): rt tasks get
//! RT_RUNTIME_NS of each RT_PERIOD_NS on a CPU. Past it the CPU's rt
//! tasks give way to its fair tasks until the period ends; as with the
//! fair server that replaced this in Linux 6.12 (fair_server_init,
//! 50 ms of each second), they do so only while fair tasks wait, never
//! leaving the CPU idle.

/// Linux sched_rt_period_us default
pub const RT_PERIOD_NS: u64 = 1_000_000_000;

/// Linux sched_rt_runtime_us default
pub const RT_RUNTIME_NS: u64 = 950_000_000;

/// A CPU's rt running time in its current period, under its rq lock
pub struct RtBandwidth {
    /// rt time charged this period, ns, at most RT_RUNTIME_NS
    time: u64,
    /// When this period ends (monotonic ns, a multiple of RT_PERIOD_NS;
    /// 0 before the first charge)
    end: u64,
}

impl RtBandwidth {
    pub const fn new() -> Self {
        Self { time: 0, end: 0 }
    }

    /// Start a new period if this one is over (Linux
    /// do_sched_rt_period_timer): true if that ends a throttle
    pub fn roll(&mut self, now: u64) -> bool {
        if now < self.end {
            return false;
        }
        let was = self.exceeded();
        self.time = 0;
        self.end += ((now - self.end) / RT_PERIOD_NS + 1) * RT_PERIOD_NS;
        was
    }

    /// Charge `delta` ns of rt running at `now` (Linux update_curr_rt)
    pub fn charge(&mut self, now: u64, delta: u64) {
        self.roll(now);
        self.time = (self.time + delta).min(RT_RUNTIME_NS);
    }

    /// This period's rt runtime is used up (Linux rt_rq->rt_throttled)
    pub fn exceeded(&self) -> bool {
        self.time >= RT_RUNTIME_NS
    }
}

impl Default for RtBandwidth {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: u64 = 1_000_000;

    #[test]
    fn exceeded_after_runtime() {
        let mut b = RtBandwidth::new();
        let t0 = 5 * RT_PERIOD_NS;
        b.charge(t0, 10 * MS);
        for i in 1..94 {
            b.charge(t0 + i * 10 * MS, 10 * MS);
        }
        assert!(!b.exceeded());
        b.charge(t0 + 940 * MS, 10 * MS);
        assert!(b.exceeded());
        b.charge(t0 + 950 * MS, 500 * MS);
        assert!(b.exceeded());
    }

    #[test]
    fn period_end_unthrottles() {
        let mut b = RtBandwidth::new();
        let t0 = 3 * RT_PERIOD_NS + 10 * MS;
        b.charge(t0, RT_RUNTIME_NS);
        assert!(b.exceeded());
        // Periods are aligned to RT_PERIOD_NS: this one ends at 4 s
        assert!(!b.roll(t0 + RT_PERIOD_NS - 20 * MS));
        assert!(b.exceeded());
        assert!(b.roll(t0 + RT_PERIOD_NS));
        assert!(!b.exceeded());
        // A roll that ends no throttle says so
        assert!(!b.roll(t0 + 5 * RT_PERIOD_NS));
    }

    #[test]
    fn charge_in_new_period_starts_fresh() {
        let mut b = RtBandwidth::new();
        b.charge(RT_PERIOD_NS / 2, 900 * MS);
        b.charge(RT_PERIOD_NS + 1, 100 * MS);
        assert!(!b.exceeded());
    }
}

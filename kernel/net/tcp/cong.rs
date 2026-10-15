//! Congestion control (RFC 5681 slow start / congestion avoidance, fast
//! retransmit and NewReno fast recovery, RFC 6582; RFC 6928 initial
//! window; Linux tcp_cong.c)
//!
//! Pure arithmetic on byte counts; the control block calls the hooks
//! and acts on their results. The parts that differ between algorithms
//! (Linux tcp_congestion_ops: `ssthresh`, `cong_avoid`) sit behind
//! [`CongOps`]; the loss/recovery machinery around them is common, as in
//! Linux. Only Reno is built in (TCP_CONGESTION "reno"; Linux's default
//! CUBIC is not implemented, so hk's default is "reno").
//!
//! Growth follows Linux: slow start adds the bytes acknowledged (RFC
//! 3465 byte counting without the L limit, like Linux's packet count),
//! congestion avoidance adds one MSS per cwnd of acknowledged bytes,
//! and both only while the sender actually used its window (Linux
//! tcp_is_cwnd_limited, RFC 7661 spirit): an application-limited sender
//! does not inflate cwnd. After an idle period longer than the RTO the
//! window decays towards the initial window (RFC 5681 4.1, Linux
//! tcp_cwnd_restart).

use core::fmt;

use super::cb::before;

/// Duplicate ACKs that trigger fast retransmit
pub const DUPTHRESH: u32 = 3;
/// Largest name of an algorithm with its NUL (Linux TCP_CA_NAME_MAX)
pub const NAME_MAX: usize = 16;

/// What differs between congestion algorithms
pub trait CongOps: Sync {
    fn name(&self) -> &'static str;
    /// Slow start threshold after a loss with `flight` bytes out
    fn ssthresh(&self, c: &Cong, flight: u32) -> u32;
    /// `acked` new bytes acknowledged outside recovery while cwnd-limited
    fn cong_avoid(&self, c: &mut Cong, acked: u32);
}

/// RFC 5681 Reno (Linux tcp_reno_*)
pub struct Reno;

impl CongOps for Reno {
    fn name(&self) -> &'static str {
        "reno"
    }

    fn ssthresh(&self, c: &Cong, flight: u32) -> u32 {
        (flight / 2).max(2 * c.mss)
    }

    fn cong_avoid(&self, c: &mut Cong, mut acked: u32) {
        if c.in_slow_start() {
            acked = c.slow_start(acked);
            if acked == 0 {
                return;
            }
        }
        c.avoid_ai(acked);
    }
}

/// Built-in algorithms; index 0 is the default
pub static ALGOS: &[&dyn CongOps] = &[&Reno];

/// Index of algorithm `name`
pub fn find(name: &str) -> Option<usize> {
    ALGOS.iter().position(|a| a.name() == name)
}

/// Names of the built-in algorithms, space separated
pub fn names() -> alloc::string::String {
    let v: alloc::vec::Vec<&str> = ALGOS.iter().map(|a| a.name()).collect();
    v.join(" ")
}

#[derive(Clone)]
pub struct Cong {
    pub cwnd: u32,
    pub ssthresh: u32,
    mss: u32,
    dupacks: u32,
    /// In fast recovery until this sequence number is acknowledged
    recover: Option<u32>,
    /// Bytes acknowledged towards the next congestion avoidance step
    /// (Linux snd_cwnd_cnt, in bytes)
    cnt: u32,
    /// The window was the limit during the last flight (Linux
    /// is_cwnd_limited / max_packets_out / cwnd_usage_seq)
    limited: bool,
    max_flight: u32,
    usage_seq: u32,
    /// The algorithm (index into [`ALGOS`])
    algo: usize,
}

impl fmt::Debug for Cong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cong")
            .field("algo", &self.name())
            .field("cwnd", &self.cwnd)
            .field("ssthresh", &self.ssthresh)
            .finish()
    }
}

impl Default for Cong {
    fn default() -> Self {
        let mut c = Self {
            cwnd: 0,
            ssthresh: u32::MAX,
            mss: super::cb::MSS_DEFAULT,
            dupacks: 0,
            recover: None,
            cnt: 0,
            limited: false,
            max_flight: 0,
            usage_seq: 0,
            algo: 0,
        };
        c.cwnd = c.initial();
        c
    }
}

impl Cong {
    fn ops(&self) -> &'static dyn CongOps {
        ALGOS[self.algo]
    }

    pub fn name(&self) -> &'static str {
        self.ops().name()
    }

    pub fn algo(&self) -> usize {
        self.algo
    }

    /// Switch algorithm (TCP_CONGESTION); the window state carries over
    pub fn set_algo(&mut self, i: usize) {
        if i < ALGOS.len() {
            self.algo = i;
        }
    }

    /// RFC 6928 initial window: min(10*MSS, max(2*MSS, 14600))
    pub fn initial(&self) -> u32 {
        (10 * self.mss).min((2 * self.mss).max(14600))
    }

    pub fn set_mss(&mut self, mss: u32) {
        let first = self.cwnd == self.initial();
        self.mss = mss;
        if first {
            self.cwnd = self.initial();
        }
    }

    pub fn in_recovery(&self) -> bool {
        self.recover.is_some()
    }

    pub fn in_slow_start(&self) -> bool {
        self.cwnd < self.ssthresh
    }

    /// Linux tcp_slow_start: grow by `acked` up to ssthresh; returns the
    /// bytes left for congestion avoidance
    pub fn slow_start(&mut self, acked: u32) -> u32 {
        let cwnd = self.cwnd.saturating_add(acked).min(self.ssthresh);
        let left = acked - (cwnd - self.cwnd);
        self.cwnd = cwnd;
        left
    }

    /// Linux tcp_cong_avoid_ai: one MSS per cwnd of acknowledged bytes
    pub fn avoid_ai(&mut self, acked: u32) {
        self.cnt = self.cnt.saturating_add(acked);
        let w = self.cwnd.max(1);
        if self.cnt >= w {
            let steps = self.cnt / w;
            self.cnt -= steps * w;
            self.cwnd = self.cwnd.saturating_add(steps.saturating_mul(self.mss));
        }
    }

    /// Linux tcp_is_cwnd_limited
    fn cwnd_limited(&self) -> bool {
        if self.limited {
            return true;
        }
        self.in_slow_start() && self.cwnd < 2 * self.max_flight
    }

    /// After a transmit pass: `flight` bytes out, `limited` if cwnd
    /// stopped it (Linux tcp_cwnd_validate); one sample per window
    pub fn on_sent(&mut self, flight: u32, snd_una: u32, snd_nxt: u32, limited: bool) {
        if !before(snd_una, self.usage_seq)
            || limited
            || (!self.limited && flight > self.max_flight)
        {
            self.limited = limited;
            self.max_flight = flight;
            self.usage_seq = snd_nxt;
        }
    }

    /// New data acknowledged (`acked` bytes, up to `ack`). Returns true
    /// if a partial ACK in recovery asks to retransmit the next hole.
    pub fn on_ack(&mut self, acked: u32, ack: u32) -> bool {
        self.dupacks = 0;
        if let Some(r) = self.recover {
            if before(ack, r) {
                // Partial ACK: deflate by what it covered, stay
                self.cwnd = self.cwnd.saturating_sub(acked).max(self.mss) + self.mss;
                return true;
            }
            self.recover = None;
            self.cwnd = self.ssthresh;
            return false;
        }
        if self.cwnd_limited() {
            self.ops().cong_avoid(self, acked);
        }
        false
    }

    /// A duplicate ACK with `flight` bytes outstanding up to `snd_max`.
    /// Returns true when the segment at snd_una must be retransmitted.
    pub fn on_dupack(&mut self, flight: u32, snd_max: u32) -> bool {
        self.dupacks += 1;
        if self.recover.is_some() {
            self.cwnd = self.cwnd.saturating_add(self.mss);
            return false;
        }
        if self.dupacks != DUPTHRESH {
            return false;
        }
        self.ssthresh = self.ops().ssthresh(self, flight);
        self.cwnd = self.ssthresh + DUPTHRESH * self.mss;
        self.cnt = 0;
        self.recover = Some(snd_max);
        true
    }

    /// Retransmission timeout with `flight` bytes outstanding (loss
    /// window of one segment)
    pub fn on_rto(&mut self, flight: u32) {
        self.ssthresh = self.ops().ssthresh(self, flight);
        self.cwnd = self.mss;
        self.cnt = 0;
        self.dupacks = 0;
        self.recover = None;
    }

    /// Sending again after `idle` ms with nothing in flight (Linux
    /// tcp_cwnd_restart): halve per RTO idle, not below the initial
    /// window
    pub fn restart(&mut self, idle: u64, rto: u64) {
        let iw = self.initial().min(self.cwnd);
        let mut cwnd = self.cwnd;
        let mut left = idle as i64 - rto as i64;
        while left > 0 && cwnd > iw {
            cwnd >>= 1;
            left -= rto as i64;
        }
        self.cwnd = cwnd.max(iw);
        self.max_flight = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limited(c: &mut Cong) {
        c.on_sent(c.cwnd, 0, 1, true);
    }

    #[test]
    fn iw10() {
        let mut c = Cong::default();
        c.set_mss(1460);
        assert_eq!(c.cwnd, 14600);
        c.set_mss(1000);
        assert_eq!(c.cwnd, 10_000);
        c.set_mss(536);
        assert_eq!(c.cwnd, 5360);
        let mut c = Cong::default();
        c.set_mss(9000);
        assert_eq!(c.cwnd, 18_000);
    }

    #[test]
    fn slow_start_then_avoidance() {
        let mut c = Cong::default();
        c.set_mss(1000);
        assert_eq!(c.cwnd, 10_000);
        c.ssthresh = 13_000;
        limited(&mut c);
        // Slow start: every acknowledged byte, up to ssthresh
        c.on_ack(2000, 1);
        assert_eq!(c.cwnd, 12_000);
        // Crossing ssthresh: the rest counts towards avoidance
        c.on_ack(2000, 2);
        assert_eq!(c.cwnd, 13_000);
        // Avoidance: one MSS per cwnd acknowledged
        for _ in 0..12 {
            c.on_ack(1000, 3);
        }
        assert_eq!(c.cwnd, 14_000);
        c.on_ack(13_000, 4);
        assert_eq!(c.cwnd, 14_000);
        c.on_ack(1000, 5);
        assert_eq!(c.cwnd, 15_000);
    }

    #[test]
    fn app_limited_does_not_grow() {
        let mut c = Cong::default();
        c.set_mss(1000);
        // Only 2000 bytes ever in flight: slow start stops at 2x that
        c.on_sent(2000, 0, 2000, false);
        for i in 0..20 {
            c.on_ack(1000, i);
        }
        assert_eq!(c.cwnd, 10_000);
        c.on_sent(6000, 2000, 8000, false);
        for i in 0..20 {
            c.on_ack(1000, 2000 + i);
        }
        assert_eq!(c.cwnd, 12_000);
    }

    #[test]
    fn fast_recovery() {
        let mut c = Cong::default();
        c.set_mss(1000);
        c.cwnd = 10_000;
        assert!(!c.on_dupack(10_000, 500));
        assert!(!c.on_dupack(10_000, 500));
        assert!(c.on_dupack(10_000, 500));
        assert_eq!(c.ssthresh, 5000);
        assert_eq!(c.cwnd, 8000);
        assert!(!c.on_dupack(10_000, 500));
        assert_eq!(c.cwnd, 9000);
        // Partial ACK: retransmit the next hole
        assert!(c.on_ack(1000, 100));
        // Full ACK ends recovery at ssthresh
        assert!(!c.on_ack(1000, 500));
        assert_eq!(c.cwnd, 5000);
        c.on_rto(4000);
        assert_eq!((c.cwnd, c.ssthresh), (1000, 2000));
    }

    #[test]
    fn restart_after_idle() {
        let mut c = Cong::default();
        c.set_mss(1000);
        c.cwnd = 80_000;
        c.restart(150, 200);
        assert_eq!(c.cwnd, 80_000);
        c.restart(450, 200);
        assert_eq!(c.cwnd, 20_000);
        c.restart(100_000, 200);
        assert_eq!(c.cwnd, 10_000);
    }

    #[test]
    fn registry() {
        assert_eq!(find("reno"), Some(0));
        assert_eq!(find("cubic"), None);
        assert_eq!(names(), "reno");
        assert_eq!(Cong::default().name(), "reno");
    }
}

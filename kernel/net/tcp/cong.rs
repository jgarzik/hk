//! Congestion control (RFC 5681 slow start / congestion avoidance, fast
//! retransmit and NewReno fast recovery, RFC 6582)
//!
//! Pure arithmetic on byte counts; the control block calls the hooks
//! and acts on their results. P7 adds IW10 (RFC 6928) and pluggable
//! algorithms behind the same hooks.

/// Duplicate ACKs that trigger fast retransmit
pub const DUPTHRESH: u32 = 3;

#[derive(Debug, Clone)]
pub struct Cong {
    pub cwnd: u32,
    pub ssthresh: u32,
    mss: u32,
    dupacks: u32,
    /// In fast recovery until this sequence number is acknowledged
    recover: Option<u32>,
}

impl Default for Cong {
    fn default() -> Self {
        let mut c = Self {
            cwnd: 0,
            ssthresh: u32::MAX,
            mss: super::cb::MSS_DEFAULT,
            dupacks: 0,
            recover: None,
        };
        c.cwnd = c.initial();
        c
    }
}

impl Cong {
    /// RFC 5681 3.1 initial window
    fn initial(&self) -> u32 {
        (4 * self.mss).min((2 * self.mss).max(4380))
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

    /// New data acknowledged (`acked` bytes, up to `ack`). Returns true
    /// if a partial ACK in recovery asks to retransmit the next hole.
    pub fn on_ack(&mut self, acked: u32, ack: u32) -> bool {
        self.dupacks = 0;
        if let Some(r) = self.recover {
            if super::cb::before(ack, r) {
                // Partial ACK: deflate by what it covered, stay
                self.cwnd = self.cwnd.saturating_sub(acked).max(self.mss) + self.mss;
                return true;
            }
            self.recover = None;
            self.cwnd = self.ssthresh;
            return false;
        }
        if self.cwnd < self.ssthresh {
            self.cwnd = self.cwnd.saturating_add(acked.min(self.mss));
        } else {
            let inc = (self.mss as u64 * self.mss as u64 / self.cwnd.max(1) as u64).max(1);
            self.cwnd = self.cwnd.saturating_add(inc as u32);
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
        self.ssthresh = (flight / 2).max(2 * self.mss);
        self.cwnd = self.ssthresh + DUPTHRESH * self.mss;
        self.recover = Some(snd_max);
        true
    }

    /// Retransmission timeout with `flight` bytes outstanding
    pub fn on_rto(&mut self, flight: u32) {
        self.ssthresh = (flight / 2).max(2 * self.mss);
        self.cwnd = self.mss;
        self.dupacks = 0;
        self.recover = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slow_start_then_avoidance() {
        let mut c = Cong::default();
        c.set_mss(1000);
        assert_eq!(c.cwnd, 4000);
        c.ssthresh = 6000;
        c.on_ack(1000, 1);
        c.on_ack(1000, 2);
        assert_eq!(c.cwnd, 6000);
        c.on_ack(1000, 3);
        assert_eq!(c.cwnd, 6000 + 1000 * 1000 / 6000);
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
}

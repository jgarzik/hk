//! CUBIC with HyStart (Linux net/ipv4/tcp_cubic.c, "cubic", the
//! default)
//!
//! Linux's integer arithmetic, unchanged, with its module parameters'
//! defaults as constants (built in: no /sys/module parameters). Time:
//! Linux's tcp_jiffies32 is hk's ms clock (HZ 1000, so HZ / 32 is 31 and
//! usecs_to_jiffies rounds up to ms), tcp_mstamp (bictcp_clock_us) that
//! clock in us. An ACK's RTT sample is whole ms in us, so HyStart's
//! delays are ms-grained. No pacing: hystart_ack_delay is 0 and the
//! ACK-train threshold is half the minimum delay.

use super::cb::{TcpCb, before};
use super::cong::{AckSample, CaEvent, CongOps, reno_undo_cwnd};
use super::recovery::CaState;
use crate::net::mib::*;

/// Linux BICTCP_BETA_SCALE
const BETA_SCALE: u32 = 1024;
/// Linux BICTCP_HZ: the CUBIC function's time unit is 2^-10 s
const BICTCP_HZ: u32 = 10;
/// hk's jiffies per second
const HZ: u32 = 1000;

/// Linux HYSTART_ACK_TRAIN / HYSTART_DELAY
const HYSTART_ACK_TRAIN: u32 = 1;
const HYSTART_DELAY: u32 = 2;
/// Linux HYSTART_MIN_SAMPLES, HYSTART_DELAY_MIN / _MAX (us)
const HYSTART_MIN_SAMPLES: u8 = 8;
const HYSTART_DELAY_MIN: u32 = 4000;
const HYSTART_DELAY_MAX: u32 = 16000;

/// Module parameters (Linux defaults)
const FAST_CONVERGENCE: bool = true;
const BETA: u32 = 717;
const INITIAL_SSTHRESH: u32 = 0;
const BIC_SCALE: u32 = 41;
const TCP_FRIENDLINESS: bool = true;
const HYSTART: bool = true;
const HYSTART_DETECT: u32 = HYSTART_ACK_TRAIN | HYSTART_DELAY;
const HYSTART_LOW_WINDOW: u32 = 16;
const HYSTART_ACK_DELTA_US: i32 = 2000;

/// Scale factors cubictcp_register precomputes: 8 * (1024 + beta) / 3 /
/// (1024 - beta), 1024 * c / rtt, and 2^40 / (bic_scale * 10) for a
/// constant SRTT of 100 ms
const BETA_SCALE_F: u32 = 8 * (BETA_SCALE + BETA) / 3 / (BETA_SCALE - BETA);
const CUBE_RTT_SCALE: u32 = BIC_SCALE * 10;
const CUBE_FACTOR: u64 = (1u64 << (10 + 3 * BICTCP_HZ)) / (BIC_SCALE as u64 * 10);

/// Per-connection state (Linux struct bictcp)
#[derive(Clone, Copy, Debug, Default)]
pub struct Bictcp {
    /// Increase cwnd by 1 after this many ACKed packets
    pub cnt: u32,
    /// Last maximum snd_cwnd
    pub last_max_cwnd: u32,
    /// The last snd_cwnd, and when it was updated
    pub last_cwnd: u32,
    pub last_time: u32,
    /// Origin point of the CUBIC function
    pub bic_origin_point: u32,
    /// Time to the origin point from the epoch's start
    pub bic_k: u32,
    /// Minimum delay (us)
    pub delay_min: u32,
    /// Beginning of an epoch (jiffies; 0: none)
    pub epoch_start: u32,
    /// ACKs counted
    pub ack_cnt: u32,
    /// Estimated Reno window
    pub tcp_cwnd: u32,
    /// HyStart: samples taken for curr_rtt, exit point found
    pub sample_cnt: u8,
    pub found: bool,
    /// HyStart round: its start (us), its end_seq, the last close ACK
    /// (us), its minimum RTT (us)
    pub round_start: u32,
    pub end_seq: u32,
    pub last_ack: u32,
    pub curr_rtt: u32,
}

impl Bictcp {
    /// Linux bictcp_reset: all up to the HyStart sample count zeroed
    fn reset(&mut self) {
        let keep = (self.sample_cnt, self.round_start, self.end_seq);
        let (last_ack, curr_rtt) = (self.last_ack, self.curr_rtt);
        *self = Self::default();
        (self.sample_cnt, self.round_start, self.end_seq) = keep;
        (self.last_ack, self.curr_rtt) = (last_ack, curr_rtt);
    }

    /// Linux bictcp_update: the window CUBIC aims for at jiffies `now`
    /// sets `cnt`
    pub fn update(&mut self, cwnd: u32, acked: u32, now: u32) {
        self.ack_cnt = self.ack_cnt.wrapping_add(acked);
        if self.last_cwnd == cwnd && (now.wrapping_sub(self.last_time) as i32) <= (HZ / 32) as i32 {
            return;
        }
        // At most once per jiffy; a reduction zeroes epoch_start
        if !(self.epoch_start != 0 && now == self.last_time) {
            self.cubic(cwnd, acked, now);
        }
        self.friendliness(cwnd);
    }

    /// bictcp_update's CUBIC function
    fn cubic(&mut self, cwnd: u32, acked: u32, now: u32) {
        self.last_cwnd = cwnd;
        self.last_time = now;
        if self.epoch_start == 0 {
            self.epoch_start = now;
            self.ack_cnt = acked;
            self.tcp_cwnd = cwnd;
            if self.last_max_cwnd <= cwnd {
                self.bic_k = 0;
                self.bic_origin_point = cwnd;
            } else {
                // (wmax - cwnd) * (srtt / HZ) / c * 2^(3 * BICTCP_HZ)
                let d = u64::from(self.last_max_cwnd - cwnd);
                self.bic_k = cubic_root(CUBE_FACTOR.wrapping_mul(d));
                self.bic_origin_point = self.last_max_cwnd;
            }
        }
        // t in 2^-BICTCP_HZ s, the minimum delay ahead
        let mut t = i64::from(now.wrapping_sub(self.epoch_start) as i32) as u64;
        t = t.wrapping_add(u64::from(usecs_to_jiffies(self.delay_min)));
        t <<= BICTCP_HZ;
        t /= u64::from(HZ);
        let k = u64::from(self.bic_k);
        let offs = k.abs_diff(t);
        // c / rtt * (t - K)^3
        let delta = (u64::from(CUBE_RTT_SCALE)
            .wrapping_mul(offs)
            .wrapping_mul(offs)
            .wrapping_mul(offs)
            >> (10 + 3 * BICTCP_HZ)) as u32;
        let target = if t < k {
            self.bic_origin_point.wrapping_sub(delta)
        } else {
            self.bic_origin_point.wrapping_add(delta)
        };
        self.cnt = if target > cwnd {
            cwnd / (target - cwnd)
        } else {
            // Very small increment
            cwnd.wrapping_mul(100)
        };
        // Slow growth while the bandwidth is unknown: 5% per RTT
        if self.last_max_cwnd == 0 && self.cnt > 20 {
            self.cnt = 20;
        }
    }

    /// bictcp_update's TCP friendliness: no slower than Reno would be;
    /// at most 1.5x per RTT
    fn friendliness(&mut self, cwnd: u32) {
        if TCP_FRIENDLINESS {
            let delta = (cwnd.wrapping_mul(BETA_SCALE_F) >> 3).max(1);
            while self.ack_cnt > delta {
                self.ack_cnt -= delta;
                self.tcp_cwnd = self.tcp_cwnd.wrapping_add(1);
            }
            if self.tcp_cwnd > cwnd {
                let max_cnt = cwnd / (self.tcp_cwnd - cwnd);
                if self.cnt > max_cnt {
                    self.cnt = max_cnt;
                }
            }
        }
        self.cnt = self.cnt.max(2);
    }

    /// cubictcp_recalc_ssthresh: the epoch ends; Wmax with fast
    /// convergence
    pub fn recalc_ssthresh(&mut self, cwnd: u32) -> u32 {
        self.epoch_start = 0;
        if cwnd < self.last_max_cwnd && FAST_CONVERGENCE {
            self.last_max_cwnd = cwnd.wrapping_mul(BETA_SCALE + BETA) / (2 * BETA_SCALE);
        } else {
            self.last_max_cwnd = cwnd;
        }
        (cwnd.wrapping_mul(BETA) / BETA_SCALE).max(2)
    }

    /// cubictcp_cwnd_event_tx_start: idle for `delta` jiffies up to
    /// `now`: the epoch shifts to keep cwnd on the curve
    pub fn tx_start(&mut self, delta: i32, now: u32) {
        if self.epoch_start != 0 && delta > 0 {
            self.epoch_start = self.epoch_start.wrapping_add(delta as u32);
            if before(now, self.epoch_start) {
                self.epoch_start = now;
            }
        }
    }
}

/// Linux usecs_to_jiffies with HZ 1000: rounded up
fn usecs_to_jiffies(us: u32) -> u32 {
    us.div_ceil(1000)
}

/// Linux fls64
fn fls64(a: u64) -> u32 {
    64 - a.leading_zeros()
}

/// Cube root by table lookup and one Newton-Raphson step (Linux
/// cubic_root; average error about 0.195%)
pub fn cubic_root(a: u64) -> u32 {
    // cbrt(x) MSB values for x MSB values in [0..63]: v = cbrt(x << 18)
    // - 1, cbrt(x) = (v[x] + 10) >> 6 (Willy Tarreau)
    const V: [u8; 64] = [
        0, 54, 54, 54, 118, 118, 118, 118, 123, 129, 134, 138, 143, 147, 151, 156, 157, 161, 164,
        168, 170, 173, 176, 179, 181, 185, 187, 190, 192, 194, 197, 199, 200, 202, 204, 206, 209,
        211, 213, 215, 217, 219, 221, 222, 224, 225, 227, 229, 231, 232, 234, 236, 237, 239, 240,
        242, 244, 245, 246, 248, 250, 251, 252, 254,
    ];
    let b = fls64(a);
    if b < 7 {
        // a in [0..63]
        return (u32::from(V[a as usize]) + 35) >> 6;
    }
    let b = ((b * 84) >> 8) - 1;
    let shift = (a >> (b * 3)) as usize;
    let mut x = ((u32::from(V[shift]) + 10) << b) >> 6;
    // x = (2 * x + a / x^2) / 3
    let q = a / (u64::from(x) * u64::from(x - 1));
    x = x.wrapping_mul(2).wrapping_add(q as u32);
    x.wrapping_mul(341) >> 10
}

/// Linux cubictcp
pub struct Cubic;

impl Cubic {
    /// Linux bictcp_hystart_reset: a new HyStart round
    fn hystart_reset(tp: &mut TcpCb) {
        let now = tp.mstamp_us();
        let end = tp.snd_max;
        let ca = &mut tp.cong.ca.cubic;
        ca.round_start = now;
        ca.last_ack = now;
        ca.end_seq = end;
        ca.curr_rtt = !0;
        ca.sample_cnt = 0;
    }

    /// Linux hystart_update: leave slow start at the ACK train's end
    /// or once the round's delay rises
    fn hystart_update(tp: &mut TcpCb, delay: u32) {
        if before(tp.cong.ca.cubic.end_seq, tp.snd_una) {
            Self::hystart_reset(tp);
        }
        let cwnd = tp.cong.snd_cwnd();
        if cwnd < HYSTART_LOW_WINDOW {
            return;
        }
        if HYSTART_DETECT & HYSTART_ACK_TRAIN != 0 {
            let now = tp.mstamp_us();
            let ca = &mut tp.cong.ca.cubic;
            if (now.wrapping_sub(ca.last_ack) as i32) <= HYSTART_ACK_DELTA_US {
                ca.last_ack = now;
                // No pacing: no ACK delay cushion, half the delay
                let threshold = ca.delay_min >> 1;
                if now.wrapping_sub(ca.round_start) > threshold {
                    ca.found = true;
                    tp.net_stat(LINUX_MIB_TCPHYSTARTTRAINDETECT);
                    tp.net_add(LINUX_MIB_TCPHYSTARTTRAINCWND, u64::from(cwnd));
                    tp.cong.set_ssthresh(cwnd);
                }
            }
        }
        if HYSTART_DETECT & HYSTART_DELAY != 0 {
            let ca = &mut tp.cong.ca.cubic;
            if ca.curr_rtt > delay {
                ca.curr_rtt = delay;
            }
            if ca.sample_cnt < HYSTART_MIN_SAMPLES {
                ca.sample_cnt += 1;
            } else {
                let th = (ca.delay_min >> 3).clamp(HYSTART_DELAY_MIN, HYSTART_DELAY_MAX);
                if ca.curr_rtt > ca.delay_min.wrapping_add(th) {
                    ca.found = true;
                    tp.net_stat(LINUX_MIB_TCPHYSTARTDELAYDETECT);
                    tp.net_add(LINUX_MIB_TCPHYSTARTDELAYCWND, u64::from(cwnd));
                    tp.cong.set_ssthresh(cwnd);
                }
            }
        }
    }
}

impl CongOps for Cubic {
    fn name(&self) -> &'static str {
        "cubic"
    }

    /// cubictcp_init
    fn init(&self, tp: &mut TcpCb) {
        tp.cong.ca.cubic.reset();
        if HYSTART {
            Self::hystart_reset(tp);
        }
        if !HYSTART && INITIAL_SSTHRESH != 0 {
            tp.cong.set_ssthresh(INITIAL_SSTHRESH);
        }
    }

    /// cubictcp_recalc_ssthresh
    fn ssthresh(&self, tp: &mut TcpCb) -> u32 {
        let cwnd = tp.cong.snd_cwnd();
        tp.cong.ca.cubic.recalc_ssthresh(cwnd)
    }

    /// cubictcp_cong_avoid
    fn cong_avoid(&self, tp: &mut TcpCb, _ack: u32, mut acked: u32) {
        if !tp.cong.cwnd_limited() {
            return;
        }
        if tp.cong.in_slow_start() {
            acked = tp.cong.slow_start(acked);
            if acked == 0 {
                return;
            }
        }
        let now = tp.jiffies32();
        let cwnd = tp.cong.snd_cwnd();
        tp.cong.ca.cubic.update(cwnd, acked, now);
        let w = tp.cong.ca.cubic.cnt;
        tp.cong.cong_avoid_ai(w, acked);
    }

    /// cubictcp_state
    fn set_state(&self, tp: &mut TcpCb, new: CaState) {
        if new == CaState::Loss {
            tp.cong.ca.cubic.reset();
            Self::hystart_reset(tp);
        }
    }

    /// cubictcp_cwnd_event (CA_EVENT_TX_START)
    fn cwnd_event(&self, tp: &mut TcpCb, ev: CaEvent) {
        if ev == CaEvent::TxStart {
            let now = tp.jiffies32();
            let delta = now.wrapping_sub(tp.lsndtime as u32) as i32;
            tp.cong.ca.cubic.tx_start(delta, now);
        }
    }

    /// cubictcp_acked
    fn pkts_acked(&self, tp: &mut TcpCb, s: &AckSample) {
        // Some calls are for duplicates without timestamps
        if s.rtt_us < 0 {
            return;
        }
        let now = tp.jiffies32();
        let ca = &mut tp.cong.ca.cubic;
        // Discard delay samples right after fast recovery
        if ca.epoch_start != 0 && (now.wrapping_sub(ca.epoch_start) as i32) < HZ as i32 {
            return;
        }
        let delay = (s.rtt_us as u32).max(1);
        // First call, or the link delay decreased
        if ca.delay_min == 0 || ca.delay_min > delay {
            ca.delay_min = delay;
        }
        if !ca.found && tp.cong.in_slow_start() && HYSTART {
            Self::hystart_update(tp, delay);
        }
    }

    fn undo_cwnd(&self, tp: &mut TcpCb) -> u32 {
        reno_undo_cwnd(tp)
    }
}

#[cfg(test)]
mod tests {
    use super::super::cb::{Cfg, TcpState};
    use super::super::cong::find;
    use super::*;
    use alloc::sync::Arc;

    fn cb() -> TcpCb {
        let mut tp = TcpCb::new(Cfg::default(), Arc::default());
        tp.live.mss.set(1000);
        tp.state = TcpState::Established;
        tp.snd_una = 1;
        tp.snd_nxt = 1;
        tp.snd_max = 1;
        tp.assign_cc(find("cubic").unwrap());
        tp.init_cc();
        tp
    }

    /// Linux cubic_root against the true cube root: within 1 + 0.5%
    #[test]
    fn cube_root() {
        for &(a, want) in &[(0u64, 0u32), (1, 1), (8, 2), (27, 3), (63, 4)] {
            assert_eq!(cubic_root(a), want, "cbrt({a})");
        }
        for a in [64u64, 1000, 12345, 1 << 30, 1 << 40, 3 << 50, u64::MAX >> 4] {
            let x = cubic_root(a) as f64;
            let r = (a as f64).cbrt();
            assert!((x - r).abs() <= 1.0 + r * 0.005, "cbrt({a}) {x} vs {r}");
        }
    }

    #[test]
    fn constants() {
        assert_eq!(BETA_SCALE_F, 15);
        assert_eq!(CUBE_RTT_SCALE, 410);
        assert_eq!(CUBE_FACTOR, (1u64 << 40) / 410);
    }

    /// The window target of Linux bictcp_update computed apart from
    /// the epoch's K and origin: W(t) = origin + c/rtt * (t - K)^3, t in
    /// 2^-10 s with the minimum delay ahead
    fn target(k: u32, origin: u32, elapsed: u32, delay_min_us: u32) -> u32 {
        let t = ((u64::from(elapsed) + u64::from(delay_min_us.div_ceil(1000))) << 10) / 1000;
        let offs = t.abs_diff(u64::from(k));
        let d = ((410 * offs * offs * offs) >> 40) as u32;
        if t < u64::from(k) {
            origin - d
        } else {
            origin + d
        }
    }

    #[test]
    fn growth_follows_the_curve() {
        let mut ca = Bictcp {
            last_max_cwnd: 100,
            delay_min: 50_000,
            ..Default::default()
        };
        // An epoch starts at 70 (after a loss at 100): concave up to Wmax
        ca.update(70, 1, 1000);
        assert_eq!(ca.epoch_start, 1000);
        assert_eq!(ca.bic_origin_point, 100);
        let k = cubic_root(CUBE_FACTOR * 30);
        assert_eq!(ca.bic_k, k);
        // K = cbrt((Wmax - cwnd) * rtt / c) = cbrt(30 * 0.1 / 0.04) s
        assert!((i64::from(k) - 4318).abs() < 10, "K {k}");
        let pts = [
            (500u32, 75u32),
            (2000, 85),
            (4000, 95),
            (4300, 99),
            (6000, 110),
        ];
        for (elapsed, cwnd) in pts {
            ca.update(cwnd, 1, 1000 + elapsed);
            let w = target(k, 100, elapsed, 50_000);
            let want = if w > cwnd {
                cwnd / (w - cwnd)
            } else {
                100 * cwnd
            };
            // Reno friendliness is slower with these ACK counts
            assert_eq!(ca.cnt, want.max(2), "t {elapsed} cwnd {cwnd} target {w}");
        }
        // Once per jiffy: the same ms recomputes nothing
        let cnt = ca.cnt;
        ca.update(130, 1, 7000);
        assert_eq!(ca.cnt, cnt);
    }

    #[test]
    fn first_epoch_is_capped() {
        // No loss yet: 5% per RTT at most
        let mut ca = Bictcp::default();
        ca.update(100, 1, 10);
        assert_eq!(ca.cnt, 20);
    }

    #[test]
    fn friendliness_keeps_up_with_reno() {
        let mut ca = Bictcp {
            last_max_cwnd: 100,
            ..Default::default()
        };
        ca.update(100, 1, 10);
        assert_eq!(ca.cnt, 10_000);
        // Many ACKs: the Reno estimate passes cwnd, cnt follows it
        ca.update(100, 3000, 100);
        assert!(ca.tcp_cwnd > 100);
        assert_eq!(ca.cnt, (100 / (ca.tcp_cwnd - 100)).max(2));
    }

    #[test]
    fn beta_and_fast_convergence() {
        let mut ca = Bictcp {
            epoch_start: 5,
            ..Default::default()
        };
        // 100 * 717 / 1024
        assert_eq!(ca.recalc_ssthresh(100), 70);
        assert_eq!(ca.epoch_start, 0);
        assert_eq!(ca.last_max_cwnd, 100);
        // Lost again below the last maximum: Wmax backs off further
        assert_eq!(ca.recalc_ssthresh(80), 56);
        assert_eq!(ca.last_max_cwnd, 80 * 1741 / 2048);
        assert_eq!(ca.recalc_ssthresh(2), 2);
    }

    #[test]
    fn loss_resets_the_epoch() {
        let mut tp = cb();
        tp.cong.ca.cubic.epoch_start = 7;
        tp.cong.ca.cubic.last_max_cwnd = 50;
        tp.snd_max = tp.snd_max.wrapping_add(20_000);
        tp.cong.set_cwnd(20);
        tp.enter_loss();
        // ssthresh from the window before; then cubictcp_state(Loss)
        assert_eq!(tp.cong.snd_ssthresh(), 14);
        assert_eq!(tp.cong.ca.cubic.last_max_cwnd, 0);
        assert_eq!(tp.cong.ca.cubic.epoch_start, 0);
    }

    #[test]
    fn idle_shifts_the_epoch() {
        let mut ca = Bictcp {
            epoch_start: 100,
            ..Default::default()
        };
        ca.tx_start(50, 1000);
        assert_eq!(ca.epoch_start, 150);
        ca.tx_start(5000, 1000);
        assert_eq!(ca.epoch_start, 1000);
        ca.tx_start(-3, 1000);
        assert_eq!(ca.epoch_start, 1000);
    }

    fn sample(tp: &mut TcpCb, rtt_us: i32) {
        let s = AckSample {
            pkts_acked: 1,
            rtt_us,
            in_flight: 0,
        };
        Cubic.pkts_acked(tp, &s);
    }

    #[test]
    fn hystart_exits_on_delay_increase() {
        let mut tp = cb();
        tp.cong.set_cwnd(32);
        tp.snd_max = tp.snd_max.wrapping_add(64_000);
        tp.cong.ca.cubic.end_seq = tp.snd_max;
        // Samples 10 ms apart in time (no ACK train), 20 ms RTT
        for i in 0..9 {
            tp.clock = 100 + 10 * i;
            sample(&mut tp, 20_000);
        }
        assert!(!tp.cong.ca.cubic.found);
        assert_eq!(tp.cong.ca.cubic.delay_min, 20_000);
        // A new round whose minimum RTT exceeds 20 + 4 ms
        tp.snd_max = tp.snd_max.wrapping_add(64_000);
        tp.snd_una = tp.cong.ca.cubic.end_seq.wrapping_add(1000);
        for i in 0..9 {
            tp.clock = 300 + 10 * i;
            sample(&mut tp, 25_000);
        }
        assert!(tp.cong.ca.cubic.found);
        assert_eq!(tp.cong.snd_ssthresh(), 32);
        assert!(!tp.cong.in_slow_start());
    }

    #[test]
    fn hystart_exits_on_ack_train() {
        let mut tp = cb();
        tp.cong.set_cwnd(32);
        tp.snd_max = tp.snd_max.wrapping_add(64_000);
        tp.clock = 1000;
        tp.cong.ca.cubic.end_seq = tp.snd_max;
        tp.cong.ca.cubic.round_start = tp.mstamp_us();
        tp.cong.ca.cubic.last_ack = tp.mstamp_us();
        // ACKs 1 ms apart for 6 ms of a 10 ms RTT: past half of it
        for i in 0..=6 {
            tp.clock = 1000 + i;
            sample(&mut tp, 10_000);
        }
        assert!(tp.cong.ca.cubic.found);
        assert_eq!(tp.cong.snd_ssthresh(), 32);
    }

    #[test]
    fn hystart_waits_for_low_window() {
        let mut tp = cb();
        for i in 0..20 {
            tp.clock = 1000 + i;
            sample(&mut tp, 10_000);
        }
        assert!(!tp.cong.ca.cubic.found);
    }

    #[test]
    fn cong_avoid_grows_by_cnt() {
        let mut tp = cb();
        tp.cong.set_ssthresh(10);
        tp.packets_out = 10;
        tp.cwnd_validate(true);
        tp.clock = 5000;
        // First epoch: cnt 20, so 20 ACKed packets add one
        for _ in 0..19 {
            Cubic.cong_avoid(&mut tp, 0, 1);
        }
        assert_eq!(tp.cong.snd_cwnd(), 10);
        assert_eq!(tp.cong.ca.cubic.cnt, 20);
        Cubic.cong_avoid(&mut tp, 0, 1);
        assert_eq!(tp.cong.snd_cwnd(), 11);
    }
}

//! Congestion control (Linux tcp_cong.c and its call sites in
//! tcp_input.c / tcp_output.c)
//!
//! The window is in packets, as Linux's snd_cwnd / snd_ssthresh /
//! snd_cwnd_cnt, so an algorithm's arithmetic is Linux's own; the
//! sender keeps at most cwnd packets in flight (`output.rs`,
//! tcp_cwnd_test).
//!
//! What differs between algorithms sits behind [`CongOps`] (Linux struct
//! tcp_congestion_ops). Its hooks take the control block as Linux's take
//! the socket, and keep per-connection state in [`CaPriv`] (Linux
//! inet_csk_ca). Linux's split holds: this file is tcp_cong.c (the
//! registry, the hooks' callers tcp_set_ca_state / tcp_ca_event /
//! tcp_init_congestion_control..., tcp_slow_start, tcp_cong_avoid_ai,
//! Reno) and the window bookkeeping of tcp_output.c (tcp_cwnd_validate,
//! tcp_cwnd_restart); the CA state machine, PRR, undo and F-RTO that
//! call the hooks are tcp_input.c's, in `recovery.rs`.
//!
//! Algorithms are built in (no modules, so no key or reference count):
//! Reno here, CUBIC (the default) in `cubic.rs`.
//! ECN, TSO and pacing do not exist, so neither do the ECN events, the
//! in_ack_event, min_tso_segs, sndbuf_expand and cong_control hooks.

use super::cb::{TcpCb, TcpState, before};
use super::cubic::{Bictcp, Cubic};
use super::recovery::CaState;
use crate::util::error::KernelError;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU32, Ordering};

/// Largest name of an algorithm with its NUL (Linux TCP_CA_NAME_MAX)
pub const NAME_MAX: usize = 16;
/// Initial window in packets (Linux TCP_INIT_CWND)
pub const INIT_CWND: u32 = 10;
/// Slow start threshold before any loss (Linux TCP_INFINITE_SSTHRESH)
pub const INFINITE_SSTHRESH: u32 = 0x7fff_ffff;

/// Linux enum tcp_ca_event (no ECN, so no ECN_NO_CE / ECN_IS_CE)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaEvent {
    /// First transmit when nothing is in flight
    TxStart,
    /// Window restart after idle
    CwndRestart,
    /// End of a CWR or Recovery window reduction
    CompleteCwr,
    /// Retransmission timeout
    Loss,
}

/// What an ACK delivered (Linux struct ack_sample)
#[derive(Clone, Copy, Debug)]
pub struct AckSample {
    /// Packets newly acknowledged
    pub pkts_acked: u32,
    /// Round trip of the ACK in us, -1 if none
    pub rtt_us: i32,
    /// Bytes delivered over the sample's round trip
    pub in_flight: u32,
}

/// A congestion control algorithm (Linux struct tcp_congestion_ops)
pub trait CongOps: Sync {
    fn name(&self) -> &'static str;
    /// TCP_CONG_* flags (Linux tcp_congestion_ops.flags as registered)
    fn flags(&self) -> u32 {
        0
    }
    /// Set up the private state (connection established, or switched
    /// to on one)
    fn init(&self, _tp: &mut TcpCb) {}
    /// Tear it down
    fn release(&self, _tp: &mut TcpCb) {}
    /// Slow start threshold after a loss (required)
    fn ssthresh(&self, tp: &mut TcpCb) -> u32;
    /// Grow the window: `acked` packets delivered up to `ack`
    fn cong_avoid(&self, tp: &mut TcpCb, ack: u32, acked: u32);
    /// Called before the CA state changes
    fn set_state(&self, _tp: &mut TcpCb, _new: CaState) {}
    /// A window event
    fn cwnd_event(&self, _tp: &mut TcpCb, _ev: CaEvent) {}
    /// Packet accounting of every ACK
    fn pkts_acked(&self, _tp: &mut TcpCb, _s: &AckSample) {}
    /// The window after an undone reduction (required)
    fn undo_cwnd(&self, tp: &mut TcpCb) -> u32;
}

/// Linux TCP_CONG_NON_RESTRICTED: unprivileged users may select it
pub const NON_RESTRICTED: u32 = 1;

/// RFC 5681 Reno (Linux tcp_reno)
pub struct Reno;

impl CongOps for Reno {
    fn name(&self) -> &'static str {
        "reno"
    }

    fn flags(&self) -> u32 {
        NON_RESTRICTED
    }

    fn ssthresh(&self, tp: &mut TcpCb) -> u32 {
        reno_ssthresh(tp)
    }

    fn cong_avoid(&self, tp: &mut TcpCb, ack: u32, acked: u32) {
        reno_cong_avoid(tp, ack, acked);
    }

    fn undo_cwnd(&self, tp: &mut TcpCb) -> u32 {
        reno_undo_cwnd(tp)
    }
}

/// Linux tcp_reno_cong_avoid
pub fn reno_cong_avoid(tp: &mut TcpCb, _ack: u32, mut acked: u32) {
    let c = &mut tp.cong;
    if !c.cwnd_limited() {
        return;
    }
    if c.in_slow_start() {
        acked = c.slow_start(acked);
        if acked == 0 {
            return;
        }
    }
    let w = c.snd_cwnd();
    c.cong_avoid_ai(w, acked);
}

/// Linux tcp_reno_ssthresh: half the window, at least 2
pub fn reno_ssthresh(tp: &mut TcpCb) -> u32 {
    (tp.cong.snd_cwnd() >> 1).max(2)
}

/// Linux tcp_reno_undo_cwnd
pub fn reno_undo_cwnd(tp: &mut TcpCb) -> u32 {
    tp.cong.snd_cwnd().max(tp.prior_cwnd)
}

/// Built-in algorithms in registration order (what
/// tcp_available_congestion_control lists: Linux registers tcp_reno in
/// tcp_init, then cubic at its initcall)
pub static ALGOS: &[&dyn CongOps] = &[&Reno, &Cubic];

/// The boot default (Linux CONFIG_DEFAULT_TCP_CONG "cubic")
pub const DEFAULT: usize = 1;

/// The algorithms unprivileged users may select (Linux
/// TCP_CONG_NON_RESTRICTED in each ops' flags, changed under
/// tcp_cong_list_lock, read under RCU): bit i for `ALGOS[i]`. One word,
/// so a reader sees a whole list; writers store whole lists
/// (tcp_allowed_congestion_control) or add one (a new default). At boot
/// those registered with the flag, and the default
/// (tcp_set_default_congestion_control sets it).
static ALLOWED: AtomicU32 = AtomicU32::new(boot_allowed());

const fn boot_allowed() -> u32 {
    // Reno is registered with TCP_CONG_NON_RESTRICTED; cubic is not
    (1 << 0) | (1 << DEFAULT)
}

/// Index of algorithm `name` (Linux tcp_ca_find)
pub fn find(name: &str) -> Option<usize> {
    ALGOS.iter().position(|a| a.name() == name)
}

/// Names of the built-in algorithms, space separated (Linux
/// tcp_get_available_congestion_control)
pub fn names() -> String {
    let v: Vec<&str> = ALGOS.iter().map(|a| a.name()).collect();
    v.join(" ")
}

/// `ALGOS[i]` is TCP_CONG_NON_RESTRICTED
pub fn allowed(i: usize) -> bool {
    ALLOWED.load(Ordering::Relaxed) & (1 << i) != 0
}

/// Names of the unrestricted algorithms (Linux
/// tcp_get_allowed_congestion_control)
pub fn allowed_names() -> String {
    let v: Vec<&str> = (0..ALGOS.len())
        .filter(|&i| allowed(i))
        .map(|i| ALGOS[i].name())
        .collect();
    v.join(" ")
}

/// Replace the unrestricted list with the space separated `names`
/// (Linux tcp_set_allowed_congestion_control: the list ends at an empty
/// name; ENOENT, changing nothing, for an unknown one)
pub fn set_allowed(names: &str) -> Result<(), KernelError> {
    let mut mask = 0;
    for n in names.split(' ').take_while(|n| !n.is_empty()) {
        mask |= 1 << find(n).ok_or(KernelError::NotFound)?;
    }
    ALLOWED.store(mask, Ordering::Relaxed);
    Ok(())
}

/// `i` becomes a namespace's default (Linux
/// tcp_set_default_congestion_control): only the initial namespace may
/// pick a restricted one (EPERM); the default is unrestricted from then
pub fn set_default(init: bool, i: usize) -> Result<(), KernelError> {
    if !init && !allowed(i) {
        return Err(KernelError::PermissionDenied);
    }
    ALLOWED.fetch_or(1 << i, Ordering::Relaxed);
    Ok(())
}

/// Per-connection private state of the algorithms (Linux icsk_ca_priv:
/// zeroed whenever an algorithm is assigned). One area per built-in
/// algorithm with state; Reno keeps none.
#[derive(Clone, Copy, Debug, Default)]
pub struct CaPriv {
    pub cubic: Bictcp,
}

/// A connection's window and algorithm (Linux tcp_sock's snd_cwnd,
/// snd_ssthresh, snd_cwnd_cnt, snd_cwnd_clamp, is_cwnd_limited...;
/// icsk_ca_ops, icsk_ca_priv). The window and threshold, which
/// /proc/net/tcp reads, are in its control block's `cb::Live`.
pub struct Cong {
    pub(super) live: Arc<super::cb::Live>,
    /// Linux snd_cwnd_cnt: packets acknowledged towards the next
    /// congestion avoidance step
    cnt: u32,
    /// Linux snd_cwnd_clamp
    clamp: u32,
    /// Linux is_cwnd_limited / max_packets_out / cwnd_usage_seq
    limited: bool,
    max_packets_out: u32,
    usage_seq: u32,
    /// Linux snd_cwnd_used: the most packets out while the window was
    /// not the limit; snd_cwnd_stamp: when the window was last used or
    /// changed (jiffies)
    pub(super) used: u32,
    pub(super) stamp: u32,
    /// The algorithm (Linux icsk_ca_ops: index into [`ALGOS`]), whether
    /// its init ran (icsk_ca_initialized), its private state
    algo: usize,
    initialized: bool,
    pub(super) ca: CaPriv,
}

impl fmt::Debug for Cong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cong")
            .field("algo", &self.name())
            .field("cwnd", &self.snd_cwnd())
            .field("ssthresh", &self.snd_ssthresh())
            .finish()
    }
}

#[cfg(test)]
impl Default for Cong {
    fn default() -> Self {
        Self::new(Arc::default())
    }
}

impl Cong {
    /// A new socket's state (Linux tcp_init_sock), its window in `live`
    pub fn new(live: Arc<super::cb::Live>) -> Self {
        let c = Self {
            live,
            cnt: 0,
            clamp: u32::MAX,
            limited: false,
            max_packets_out: 0,
            usage_seq: 0,
            used: 0,
            stamp: 0,
            algo: DEFAULT,
            initialized: false,
            ca: CaPriv::default(),
        };
        c.live.ssthresh.set(INFINITE_SSTHRESH);
        c.live.cwnd.set(INIT_CWND);
        c
    }

    /// Linux tcp_snd_cwnd (packets)
    pub fn snd_cwnd(&self) -> u32 {
        self.live.cwnd.get()
    }

    /// Linux snd_ssthresh (packets)
    pub fn snd_ssthresh(&self) -> u32 {
        self.live.ssthresh.get()
    }

    /// Linux tcp_snd_cwnd_set
    pub fn set_cwnd(&mut self, v: u32) {
        self.live.cwnd.set(v.max(1));
    }

    pub fn set_ssthresh(&mut self, v: u32) {
        self.live.ssthresh.set(v);
    }

    /// Linux snd_cwnd_cnt = 0
    pub fn reset_cnt(&mut self) {
        self.cnt = 0;
    }

    fn ops(&self) -> &'static dyn CongOps {
        ALGOS[self.algo]
    }

    pub fn name(&self) -> &'static str {
        self.ops().name()
    }

    pub fn algo(&self) -> usize {
        self.algo
    }

    /// Linux tcp_in_slow_start
    pub fn in_slow_start(&self) -> bool {
        self.snd_cwnd() < self.snd_ssthresh()
    }

    /// Linux tcp_in_initial_slowstart
    pub fn in_initial_slowstart(&self) -> bool {
        self.snd_ssthresh() >= INFINITE_SSTHRESH
    }

    /// Linux tcp_slow_start: grow by `acked` up to ssthresh; returns
    /// the packets left for congestion avoidance
    pub fn slow_start(&mut self, acked: u32) -> u32 {
        let w = self.snd_cwnd();
        let cwnd = w.saturating_add(acked).min(self.snd_ssthresh());
        let left = acked - (cwnd - w);
        self.set_cwnd(cwnd.min(self.clamp));
        left
    }

    /// Linux tcp_cong_avoid_ai: one packet per `w` acknowledged
    pub fn cong_avoid_ai(&mut self, w: u32, acked: u32) {
        let w = w.max(1);
        // Credits accumulated at a higher w are applied gently now
        if self.cnt >= w {
            self.cnt = 0;
            self.set_cwnd(self.snd_cwnd().saturating_add(1));
        }
        self.cnt = self.cnt.saturating_add(acked);
        if self.cnt >= w {
            let delta = self.cnt / w;
            self.cnt -= delta * w;
            self.set_cwnd(self.snd_cwnd().saturating_add(delta));
        }
        self.set_cwnd(self.snd_cwnd().min(self.clamp));
    }

    /// Linux tcp_is_cwnd_limited
    pub fn cwnd_limited(&self) -> bool {
        if self.limited {
            return true;
        }
        self.in_slow_start() && self.snd_cwnd() < 2 * self.max_packets_out
    }
}

impl TcpCb {
    fn ca_ops(&self) -> &'static dyn CongOps {
        self.cong.ops()
    }

    /// Linux tcp_jiffies32: hk's jiffies are its ms clock (HZ 1000)
    pub(super) fn jiffies32(&self) -> u32 {
        self.clock as u32
    }

    /// Linux tcp_mstamp as bictcp_clock_us reads it (u32 us)
    pub(super) fn mstamp_us(&self) -> u32 {
        self.tcp_mstamp as u32
    }

    /// Linux tcp_assign_congestion_control / the algorithm switch of
    /// tcp_reinit_congestion_control: its private state zeroed
    pub(super) fn assign_cc(&mut self, i: usize) {
        if i < ALGOS.len() {
            self.cong.algo = i;
            self.cong.ca = CaPriv::default();
        }
    }

    /// Linux tcp_init_congestion_control
    pub(super) fn init_cc(&mut self) {
        self.prior_ssthresh = 0;
        self.ca_ops().init(self);
        self.cong.initialized = true;
    }

    /// Linux tcp_cleanup_congestion_control
    pub(super) fn cleanup_cc(&mut self) {
        if self.cong.initialized {
            self.ca_ops().release(self);
        }
        self.cong.initialized = false;
    }

    /// TCP_CONGESTION (Linux tcp_set_congestion_control, then
    /// tcp_reinit_congestion_control): the same algorithm is no change;
    /// another one is initialized at once on a connection
    pub(super) fn set_cc(&mut self, i: usize) {
        if i == self.cong.algo || i >= ALGOS.len() {
            return;
        }
        self.cleanup_cc();
        self.assign_cc(i);
        if !matches!(self.state, TcpState::Closed | TcpState::Listen) {
            self.init_cc();
        }
    }

    /// The handshake completed (Linux tcp_init_transfer): the initial
    /// window (one packet after more than one SYN retransmission, RFC
    /// 6298), then the algorithm
    pub(super) fn init_transfer(&mut self) {
        if self.stats.total_retrans > 1 && self.undo_marker.is_some() {
            self.cong.set_cwnd(1);
        } else {
            self.cong.set_cwnd(INIT_CWND);
        }
        self.cong.stamp = self.jiffies32();
        if !self.cong.initialized {
            self.init_cc();
        }
    }

    /// Linux tcp_disconnect's congestion part: the algorithm released
    /// and zeroed, the initial window
    pub(super) fn ca_disconnect(&mut self) {
        if self.cong.initialized {
            self.ca_ops().release(self);
        }
        self.cong.ca = CaPriv::default();
        self.cong.initialized = false;
        self.set_ca_state(CaState::Open);
        self.cong.set_ssthresh(INFINITE_SSTHRESH);
        self.cong.set_cwnd(INIT_CWND);
    }

    /// Linux tcp_set_ca_state
    pub(super) fn set_ca_state(&mut self, s: CaState) {
        self.ca_ops().set_state(self, s);
        self.ca_state = s;
    }

    /// Linux tcp_ca_event
    pub(super) fn ca_event(&mut self, ev: CaEvent) {
        self.ca_ops().cwnd_event(self, ev);
    }

    /// Linux icsk_ca_ops->ssthresh
    pub(super) fn ca_ssthresh(&mut self) -> u32 {
        self.ca_ops().ssthresh(self)
    }

    /// Linux icsk_ca_ops->undo_cwnd
    pub(super) fn ca_undo_cwnd(&mut self) -> u32 {
        self.ca_ops().undo_cwnd(self)
    }

    /// Linux tcp_clean_rtx_queue's icsk_ca_ops->pkts_acked
    pub(super) fn ca_pkts_acked(&mut self, s: &AckSample) {
        self.ca_ops().pkts_acked(self, s);
    }

    /// Linux tcp_cong_avoid
    pub(super) fn cong_avoid(&mut self, ack: u32, acked: u32) {
        self.ca_ops().cong_avoid(self, ack, acked);
        self.cong.stamp = self.jiffies32();
    }

    /// After a transmit pass, `limited` if the flight fills cwnd (Linux
    /// tcp_cwnd_validate): one sample per window; a window not used for
    /// an RTO shrinks towards what was (RFC 2861 spirit)
    pub(super) fn cwnd_validate(&mut self, limited: bool) {
        let out = self.packets_out;
        let now = self.jiffies32();
        let c = &mut self.cong;
        if !before(self.snd_una, c.usage_seq) || limited || (!c.limited && out > c.max_packets_out)
        {
            c.limited = limited;
            c.max_packets_out = out;
            c.usage_seq = self.snd_nxt;
        }
        if c.cwnd_limited() {
            // The network is fed fully
            c.used = 0;
            c.stamp = now;
            return;
        }
        // The network starves
        c.used = c.used.max(out);
        let idle = now.wrapping_sub(c.stamp) as i32;
        if self.cfg.slow_start_after_idle && i64::from(idle) >= self.rto_cur() as i64 {
            self.cwnd_application_limited();
        }
    }

    /// Linux tcp_cwnd_application_limited: limited by the application
    /// or the receiver's window (not by a full send buffer), the window
    /// goes half way down to what was used, at least the initial window
    fn cwnd_application_limited(&mut self) {
        let nospace = self
            .live
            .nospace
            .load(core::sync::atomic::Ordering::Acquire);
        if self.ca_state == CaState::Open && !self.orphan && !nospace {
            let used = self.cong.used.max(INIT_CWND);
            if used < self.cong.snd_cwnd() {
                let ss = self.current_ssthresh();
                self.cong.set_ssthresh(ss);
                let w = (self.cong.snd_cwnd() + used) >> 1;
                self.cong.set_cwnd(w);
            }
            self.cong.used = 0;
        }
        self.cong.stamp = self.jiffies32();
    }

    /// Linux tcp_slow_start_after_idle_check: about to send with nothing
    /// out after an RTO of quiet, the window restarts
    pub(super) fn slow_start_after_idle_check(&mut self, now: u64) {
        if !self.cfg.slow_start_after_idle || self.packets_out != 0 {
            return;
        }
        let delta = now.saturating_sub(self.lsndtime);
        if delta > self.rto_cur() {
            self.cwnd_restart(delta);
        }
    }

    /// Sending again after `delta` ms with nothing in flight (Linux
    /// tcp_cwnd_restart): halve per RTO idle, not below the initial
    /// window
    pub(super) fn cwnd_restart(&mut self, delta: u64) {
        let rto = self.rto_cur();
        let mut cwnd = self.cong.snd_cwnd();
        let restart = INIT_CWND.min(cwnd);
        self.ca_event(CaEvent::CwndRestart);
        let ss = self.current_ssthresh();
        self.cong.set_ssthresh(ss);
        let mut left = delta as i64 - rto as i64;
        while left > 0 && cwnd > restart {
            cwnd >>= 1;
            left -= rto as i64;
        }
        self.cong.set_cwnd(cwnd.max(restart));
        self.cong.stamp = self.jiffies32();
        self.cong.used = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::super::cb::Cfg;
    use super::*;

    /// An established Reno connection with `n` packets out, cwnd the
    /// limit
    fn cb(n: u32) -> TcpCb {
        let mut tp = TcpCb::new(Cfg::default(), Arc::default());
        tp.live.mss.set(1000);
        tp.state = TcpState::Established;
        tp.assign_cc(0);
        tp.init_cc();
        tp.packets_out = n;
        tp.cwnd_validate(true);
        tp
    }

    #[test]
    fn iw10() {
        let tp = cb(0);
        assert_eq!(tp.cong.snd_cwnd(), 10);
        assert!(tp.cong.in_initial_slowstart());
    }

    #[test]
    fn slow_start_then_avoidance() {
        let mut tp = cb(10);
        tp.cong.set_ssthresh(13);
        // Slow start: every acknowledged packet, up to ssthresh
        tp.cong_avoid(0, 2);
        assert_eq!(tp.cong.snd_cwnd(), 12);
        // Crossing ssthresh: the rest counts towards avoidance
        tp.cong_avoid(0, 2);
        assert_eq!(tp.cong.snd_cwnd(), 13);
        assert_eq!(tp.cong.cnt, 1);
        // Avoidance: one packet per cwnd acknowledged
        for _ in 0..12 {
            tp.cong_avoid(0, 1);
        }
        assert_eq!(tp.cong.snd_cwnd(), 14);
        for _ in 0..14 {
            tp.cong_avoid(0, 1);
        }
        assert_eq!(tp.cong.snd_cwnd(), 15);
    }

    #[test]
    fn app_limited_does_not_grow() {
        let mut tp = cb(0);
        // Only 2 packets ever in flight: slow start stops at 2x that
        tp.packets_out = 2;
        tp.cwnd_validate(false);
        for _ in 0..4 {
            tp.cong_avoid(0, 1);
        }
        assert_eq!(tp.cong.snd_cwnd(), 10);
        tp.packets_out = 6;
        tp.cwnd_validate(false);
        for _ in 0..6 {
            tp.cong_avoid(0, 1);
        }
        assert_eq!(tp.cong.snd_cwnd(), 12);
    }

    #[test]
    fn reno_hooks() {
        let mut tp = cb(10);
        tp.cong.set_cwnd(9);
        assert_eq!(tp.ca_ssthresh(), 4);
        tp.cong.set_cwnd(3);
        assert_eq!(tp.ca_ssthresh(), 2);
        tp.prior_cwnd = 7;
        assert_eq!(tp.ca_undo_cwnd(), 7);
    }

    #[test]
    fn restart_after_idle() {
        let mut tp = cb(0);
        tp.cong.set_cwnd(80);
        tp.live.rto.set(200);
        tp.cwnd_restart(150);
        assert_eq!(tp.cong.snd_cwnd(), 80);
        assert_eq!(tp.cong.snd_ssthresh(), INFINITE_SSTHRESH);
        tp.cwnd_restart(450);
        assert_eq!(tp.cong.snd_cwnd(), 20);
        tp.cwnd_restart(100_000);
        assert_eq!(tp.cong.snd_cwnd(), 10);
        // tcp_current_ssthresh: 3/4 of the old window
        tp.cong.set_ssthresh(4);
        tp.cong.set_cwnd(40);
        tp.cwnd_restart(0);
        assert_eq!(tp.cong.snd_ssthresh(), 30);
    }

    /// A window idle an RTO with 5 packets used, of 40 (ssthresh 8)
    fn idle_window(f: impl FnOnce(&mut TcpCb)) -> TcpCb {
        let mut tp = cb(0);
        tp.cong.set_cwnd(40);
        tp.cong.set_ssthresh(8);
        tp.live.rto.set(200);
        f(&mut tp);
        tp.packets_out = 5;
        tp.tick(300);
        tp.cwnd_validate(false);
        tp
    }

    /// Linux tcp_cwnd_validate / tcp_cwnd_application_limited: half way
    /// down to max(used, IW), ssthresh tcp_current_ssthresh
    #[test]
    fn application_limited_shrinks() {
        let tp = idle_window(|_| {});
        assert_eq!(tp.cong.snd_cwnd(), (40 + INIT_CWND) >> 1);
        assert_eq!(tp.cong.snd_ssthresh(), (40 >> 1) + (40 >> 2));
        assert_eq!((tp.cong.used, tp.cong.stamp), (0, 300));
        // A full send buffer, not the application, limited it
        let tp = idle_window(|tp| {
            tp.live
                .nospace
                .store(true, core::sync::atomic::Ordering::Release)
        });
        assert_eq!(tp.cong.snd_cwnd(), 40);
        assert_eq!((tp.cong.used, tp.cong.stamp), (5, 300));
        // tcp_slow_start_after_idle 0
        let tp = idle_window(|tp| tp.cfg.slow_start_after_idle = false);
        assert_eq!(tp.cong.snd_cwnd(), 40);
        assert_eq!(tp.cong.used, 5);
    }

    /// Linux tcp_slow_start_after_idle_check: nothing out and an RTO
    /// quiet restarts the window, unless the sysctl is off
    #[test]
    fn restart_needs_idle_and_sysctl() {
        let mut tp = cb(0);
        tp.cong.set_cwnd(80);
        tp.live.rto.set(200);
        tp.slow_start_after_idle_check(150);
        assert_eq!(tp.cong.snd_cwnd(), 80);
        tp.cfg.slow_start_after_idle = false;
        tp.slow_start_after_idle_check(450);
        assert_eq!(tp.cong.snd_cwnd(), 80);
        tp.cfg.slow_start_after_idle = true;
        tp.packets_out = 1;
        tp.slow_start_after_idle_check(450);
        assert_eq!(tp.cong.snd_cwnd(), 80);
        tp.packets_out = 0;
        tp.slow_start_after_idle_check(450);
        assert_eq!(tp.cong.snd_cwnd(), 20);
    }

    #[test]
    fn registry() {
        assert_eq!(find("reno"), Some(0));
        assert_eq!(find("cubic"), Some(1));
        assert_eq!(find("nosuch"), None);
        assert_eq!(names(), "reno cubic");
        assert_eq!(
            TcpCb::new(Cfg::default(), Arc::default()).cong.name(),
            "cubic"
        );
        assert_eq!(cb(0).cong.name(), "reno");
        // Boot: reno by its flags, cubic as the default
        let flagged = ALGOS.iter().enumerate();
        let want = flagged
            .filter(|(i, a)| a.flags() & NON_RESTRICTED != 0 || *i == DEFAULT)
            .fold(0, |m, (i, _)| m | 1 << i);
        assert_eq!(boot_allowed(), want);
    }

    #[test]
    fn allowed_list() {
        let saved = ALLOWED.load(Ordering::Relaxed);
        assert_eq!(set_allowed("cubic nosuch"), Err(KernelError::NotFound));
        assert_eq!(ALLOWED.load(Ordering::Relaxed), saved);
        set_allowed("cubic").unwrap();
        assert_eq!(allowed_names(), "cubic");
        assert_eq!(set_default(false, 0), Err(KernelError::PermissionDenied));
        set_default(true, 0).unwrap();
        assert_eq!(allowed_names(), "reno cubic");
        set_allowed("").unwrap();
        assert_eq!(allowed_names(), "");
        set_allowed("reno  cubic").unwrap();
        assert_eq!(allowed_names(), "reno");
        ALLOWED.store(saved, Ordering::Relaxed);
    }

    #[test]
    fn switch_on_a_connection_inits() {
        let mut tp = cb(0);
        tp.cong.set_cwnd(30);
        tp.set_cc(1);
        assert_eq!(tp.cong.name(), "cubic");
        // cubictcp_init's HyStart round; the window carries over
        assert_eq!(tp.cong.ca.cubic.curr_rtt, !0);
        assert_eq!(tp.cong.snd_cwnd(), 30);
    }
}

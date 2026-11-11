//! TCP timers: RTO estimation (RFC 6298 with Karn's algorithm), the
//! retransmission / persist / delayed ACK / keepalive / TIME_WAIT /
//! FIN_WAIT_2 expiry logic of the control block (I/O-free), and the
//! timer service that calls it.
//!
//! Keepalive (RFC 1122 4.2.3.6, Linux tcp_keepalive_timer): with
//! SO_KEEPALIVE, after TCP_KEEPIDLE (7200 s) without anything received
//! and nothing to send, probe every TCP_KEEPINTVL (75 s); TCP_KEEPCNT (9)
//! unanswered probes, or TCP_USER_TIMEOUT once probing, reset the
//! connection with ETIMEDOUT. TCP_USER_TIMEOUT also bounds how long
//! data may stay unacknowledged while retransmitting or probing a zero
//! window, in place of the retry counts.
//!
//! ## Timers (thread context only)
//!
//! A connection has Linux's three timers, embedded in its socket
//! (`time::timer::ArcTimer`: a pending one holds a reference to the
//! socket, Linux sk_reset_timer): the retransmit timer (RTO and the
//! zero-window probe, icsk_retransmit_timer), the delayed ACK timer
//! (icsk_delack_timer) and the keepalive timer (keepalive and an
//! orphan's FIN_WAIT_2, sk_timer); a TIME_WAIT entry has one. They run
//! in `ktimers/N` and take the socket's `slock`: unowned, the control
//! block's due work runs at once; owned by a socket call, it is left to
//! the owner's release (Linux TCP_WRITE_TIMER_DEFERRED). After each step
//! the socket re-arms them for the control block's deadlines
//! ([`TcpCb::deadlines`]). Order: socket lock -> timer base
//! (IrqSpinlock).

use super::cb::{
    ORPHAN_RETRIES, Out, RTO_FALLBACK, RTO_MAX, RTO_MIN, TIMEWAIT_LEN, TcpCb, TcpState, Tmr,
};
use super::output::Push;
use crate::util::error::KernelError;

impl TcpCb {
    /// Current timeout: the base RTO backed off, at most RTO_MAX
    pub(super) fn rto_cur(&self) -> u64 {
        (self.rto << self.backoff.min(16)).min(RTO_MAX)
    }

    /// (Re)start the retransmission timer (no later than the user
    /// timeout, Linux tcp_clamp_rto_to_user_timeout)
    pub(super) fn arm_rtx(&mut self, now: u64) {
        let mut t = self.rto_cur();
        if let Some(left) = self.user_left(now) {
            t = t.min(left.max(1));
        }
        self.tmr = Some((Tmr::Rtx, now + t));
    }

    /// TCP_USER_TIMEOUT time left while retransmitting or probing
    fn user_left(&self, now: u64) -> Option<u64> {
        let ut = u64::from(self.opts.user_timeout);
        let start = self.rtx_stamp?;
        (ut != 0).then(|| (start + ut).saturating_sub(now))
    }

    /// RFC 6298 2.2/2.3 for a measured round trip `r` ms (srtt8 = 8 *
    /// SRTT, rttvar4 = 4 * RTTVAR); a valid sample ends the backoff
    pub(super) fn rtt_sample(&mut self, r: u64) {
        let r = r.min(RTO_MAX);
        self.stats.min_rtt = Some(self.stats.min_rtt.map_or(r, |m| m.min(r)));
        if self.srtt8 == 0 {
            self.srtt8 = (r * 8).max(1);
            self.rttvar4 = r * 2;
        } else {
            let srtt = (self.srtt8 / 8) as i64;
            let delta = r as i64 - srtt;
            self.srtt8 = (self.srtt8 as i64 + delta).max(1) as u64;
            let var = (self.rttvar4 / 4) as i64;
            self.rttvar4 = (self.rttvar4 as i64 + delta.abs() - var).max(0) as u64;
        }
        self.rto = (self.srtt8 / 8 + self.rttvar4.max(1)).clamp(RTO_MIN, RTO_MAX);
        self.backoff = 0;
    }

    /// RFC 6298 5.7: SYN retransmitted and no RTT measured
    pub(super) fn set_rto_fallback(&mut self) {
        if self.srtt8 == 0 {
            self.rto = RTO_FALLBACK;
        }
    }

    /// Smoothed RTT and its variance in ms (TCP_INFO)
    pub fn rtt(&self) -> (u64, u64) {
        (self.srtt8 / 8, self.rttvar4 / 4)
    }

    /// Retransmissions allowed before giving up (Linux tcp_write_timeout)
    fn retries(&self) -> u32 {
        match self.state {
            TcpState::SynSent => self.cfg.syn_retries,
            TcpState::SynReceived => self.cfg.synack_retries,
            _ if self.orphan => ORPHAN_RETRIES.min(self.cfg.retries2),
            _ => self.cfg.retries2,
        }
    }

    /// Retransmitting or probing for too long: the retry count, or the
    /// user timeout when set (synchronized states)
    fn gave_up(&self, count: u32, now: u64) -> bool {
        if self.opts.user_timeout != 0 && self.state.synced() {
            return self.user_left(now) == Some(0);
        }
        count >= self.retries()
    }

    /// Give up: the last soft (ICMP) error, else ETIMEDOUT
    fn timed_out(&mut self, out: &mut Out) {
        let e = self.soft_err.take().unwrap_or(KernelError::TimedOut);
        self.fail(e, out);
    }

    /// A deadline passed (call at or after `next_timer()`)
    pub fn on_timer(&mut self, now: u64, out: &mut Out) {
        self.tick(now);
        if self.wait_at.is_some_and(|t| t <= now) {
            self.wait_at = None;
            match self.state {
                TcpState::TimeWait => self.set_closed(out),
                // Orphan in FIN_WAIT_2 too long (Linux tcp_keepalive_timer)
                TcpState::FinWait2 => self.abort(out),
                _ => {}
            }
            return;
        }
        if self.dack.at.is_some_and(|t| t <= now) {
            self.delack_timer(out);
        }
        if self.keep_at.is_some_and(|t| t <= now) {
            self.keep_at = None;
            self.keepalive_timer(now, out);
        }
        let Some((kind, at)) = self.tmr else {
            return;
        };
        if at > now {
            return;
        }
        self.tmr = None;
        match kind {
            Tmr::Rtx => self.rtx_timer(now, out),
            Tmr::Probe => self.probe_timer(now, out),
        }
    }

    /// Retransmission timeout (Linux tcp_retransmit_timer): back off,
    /// collapse the congestion window, resend from SND.UNA (go-back-N)
    fn rtx_timer(&mut self, now: u64, out: &mut Out) {
        let handshake = matches!(self.state, TcpState::SynSent | TcpState::SynReceived);
        if !handshake && self.snd_una == self.snd_max {
            return;
        }
        if self.rtx_stamp.is_none() {
            // The head went out about one (backed-off) RTO ago
            self.rtx_stamp = Some(now.saturating_sub(self.rto_cur()));
        }
        // Linux tcp_write_timeout: reset while the RTO is short or the
        // retries are not used up
        let reset = self.rto_cur() < RTO_MAX || !self.gave_up(self.backoff, now);
        if !handshake && self.out_of_resources(now, reset, out) {
            return;
        }
        if self.gave_up(self.backoff, now) {
            self.timed_out(out);
            return;
        }
        let flight = self.snd_max.wrapping_sub(self.snd_una);
        self.cong.on_rto(flight);
        self.rtt_seq = None;
        self.backoff += 1;
        self.stats.rto_count = self.stats.rto_count.wrapping_add(1);
        if handshake {
            self.syn_rtx = true;
            self.stats.total_retrans = self.stats.total_retrans.wrapping_add(1);
            self.syn_seg(out);
        } else {
            self.snd_nxt = self.snd_una;
            self.output(now, out);
        }
        self.arm_rtx(now);
    }

    /// Resend the SYN-ACK for a retransmitted SYN and restart the
    /// retransmission timer (Linux tcp_rtx_synack, and tcp_check_req's
    /// request timer restart)
    pub(super) fn rtx_synack(&mut self, now: u64, out: &mut Out) {
        self.syn_rtx = true;
        self.stats.total_retrans = self.stats.total_retrans.wrapping_add(1);
        self.syn_seg(out);
        self.arm_rtx(now);
    }

    /// An orphan holding send data while TCP memory is past its hard
    /// limit is dropped (Linux tcp_out_of_resources, its memory half):
    /// with a reset when `reset`, when it sent within TIME_WAIT's length,
    /// or when the peer's window is shut with nothing in flight
    fn out_of_resources(&mut self, now: u64, reset: bool, out: &mut Out) -> bool {
        if !self.orphan || !super::mem::out_of_memory(self.sndq_len()) {
            return false;
        }
        let reset = reset
            || now.saturating_sub(self.lsndtime) <= TIMEWAIT_LEN
            || (self.snd_wnd == 0 && self.snd_una == self.snd_max);
        if reset {
            self.abort(out);
        } else {
            self.set_closed(out);
        }
        true
    }

    /// Probe timer (Linux tcp_probe_timer / tcp_send_probe0): an open
    /// window means data held by cork or Nagle: push one segment; a zero
    /// window is probed, backing off; a peer that never answers is given
    /// up on
    fn probe_timer(&mut self, now: u64, out: &mut Out) {
        if self.snd_una != self.snd_max || !self.may_send() {
            return;
        }
        if self.snd_wnd != 0 {
            self.xmit(now, Push::Force, out);
            return;
        }
        if self.rtx_stamp.is_none() {
            self.rtx_stamp = Some(now);
        }
        self.probes += 1;
        if self.gave_up(self.probes - 1, now) {
            self.timed_out(out);
            return;
        }
        if self.out_of_resources(now, true, out) {
            return;
        }
        self.send_probe(out);
        self.backoff += 1;
        let mut t = self.rto_cur().max(RTO_MIN);
        if let Some(left) = self.user_left(now) {
            t = t.min(left.max(1));
        }
        self.tmr = Some((Tmr::Probe, now + t));
    }

    // --- keepalive ------------------------------------------------------------

    /// TCP_KEEPIDLE / TCP_KEEPINTVL in ms, TCP_KEEPCNT
    pub(super) fn keep_idle(&self) -> u64 {
        match self.opts.keepidle {
            0 => self.cfg.keepidle,
            s => u64::from(s) * 1000,
        }
    }

    pub(super) fn keep_intvl(&self) -> u64 {
        match self.opts.keepintvl {
            0 => self.cfg.keepintvl,
            s => u64::from(s) * 1000,
        }
    }

    pub(super) fn keep_cnt(&self) -> u32 {
        match self.opts.keepcnt {
            0 => self.cfg.keepcnt,
            n => n,
        }
    }

    /// States keepalive runs in (Linux: not CLOSE, SYN_SENT, LISTEN;
    /// TIME_WAIT has its own entry)
    fn keep_state(&self) -> bool {
        self.state.synced() && self.state != TcpState::TimeWait
    }

    /// Time since anything was last received
    fn idle(&self, now: u64) -> u64 {
        now.saturating_sub(self.dack.lrcvtime.max(self.rcv_tstamp))
    }

    /// (Re)start keepalive after the connection opened or an option
    /// changed (Linux tcp_set_keepalive / tcp_sock_set_keepidle_locked)
    pub fn arm_keepalive(&mut self, now: u64) {
        self.keep_at = None;
        if self.opts.keepalive && self.keep_state() {
            let left = self.keep_idle().saturating_sub(self.idle(now));
            self.keep_at = Some(now + left);
        }
    }

    /// SO_KEEPALIVE changed
    pub fn set_keepalive(&mut self, on: bool, now: u64) {
        self.tick(now);
        self.opts.keepalive = on;
        self.arm_keepalive(now);
    }

    /// Linux tcp_keepalive_timer (keepalive part)
    fn keepalive_timer(&mut self, now: u64, out: &mut Out) {
        if !self.opts.keepalive || !self.keep_state() {
            return;
        }
        let busy = self.snd_una != self.snd_max || self.sndq_len() != 0;
        let idle = self.idle(now);
        let next = if busy {
            self.keep_idle()
        } else if idle >= self.keep_idle() {
            let ut = u64::from(self.opts.user_timeout);
            if (ut != 0 && idle >= ut && self.probes > 0)
                || (ut == 0 && self.probes >= self.keep_cnt())
            {
                self.abort(out);
                out.err = Some(self.soft_err.take().unwrap_or(KernelError::TimedOut));
                return;
            }
            self.send_probe(out);
            self.probes += 1;
            self.keep_intvl()
        } else {
            self.keep_idle() - idle
        };
        self.keep_at = Some(now + next);
    }
}

/// Which of a connection's timers a deadline is for
pub const RTX: usize = 0;
pub const DELACK: usize = 1;
pub const KEEPALIVE: usize = 2;

impl TcpCb {
    /// The deadlines of the retransmit, delayed ACK and keepalive
    /// timers (`RTX`, `DELACK`, `KEEPALIVE`; Linux icsk_timeout,
    /// icsk_ack.timeout, sk_timer's expiry), ms
    pub fn deadlines(&self) -> [Option<u64>; 3] {
        let keep = [self.keep_at, self.wait_at].into_iter().flatten().min();
        [self.tmr.map(|t| t.1), self.dack.at, keep]
    }
}

/// Milliseconds on the monotonic clock
pub fn now_ms() -> u64 {
    crate::time::monotonic_ns() / 1_000_000
}

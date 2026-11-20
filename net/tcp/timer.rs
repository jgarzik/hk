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
    Live, ORPHAN_RETRIES, Out, RTO_FALLBACK, RTO_MAX, RTO_MIN, TIMEWAIT_LEN, TcpCb, TcpState, Tmr,
};
use super::output::Push;
use super::recovery::CaState;
use crate::net::mib::*;
use crate::util::error::KernelError;

impl Live {
    /// Current timeout: the base RTO backed off, at most RTO_MAX (Linux
    /// icsk_rto)
    pub(super) fn rto_cur(&self) -> u64 {
        (self.rto.get() << self.backoff.get().min(16)).min(RTO_MAX)
    }
}

impl TcpCb {
    pub(super) fn rto_cur(&self) -> u64 {
        self.live.rto_cur()
    }

    /// (Re)start the retransmission timer (no later than the user
    /// timeout, Linux tcp_clamp_rto_to_user_timeout)
    pub(super) fn arm_rtx(&mut self, now: u64) {
        let mut t = self.rto_cur();
        if let Some(left) = self.user_left(now) {
            t = t.min(left.max(1));
        }
        self.live.tmr.set(Some((Tmr::Rtx, now + t)));
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
        self.live
            .rto
            .set((self.srtt8 / 8 + self.rttvar4.max(1)).clamp(RTO_MIN, RTO_MAX));
        self.live.backoff.set(0);
    }

    /// RFC 6298 5.7: SYN retransmitted and no RTT measured
    pub(super) fn set_rto_fallback(&mut self) {
        if self.srtt8 == 0 {
            self.live.rto.set(RTO_FALLBACK);
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

    /// Give up: the last soft (ICMP) error, else ETIMEDOUT (Linux
    /// tcp_write_err; a listener's child is a request sock, dropped
    /// uncounted by its timer, reqsk_timer_handler)
    fn timed_out(&mut self, out: &mut Out) {
        let e = self.soft_err.take().unwrap_or(KernelError::TimedOut);
        if self.passive && self.state == TcpState::SynReceived {
            out.err = Some(e);
            self.set_closed(out);
            return;
        }
        self.fail(e, out);
        self.net_stat(LINUX_MIB_TCPABORTONTIMEOUT);
    }

    /// A deadline passed (call at or after `next_timer()`)
    pub fn on_timer(&mut self, now: u64, out: &mut Out) {
        self.tick(now);
        if self.live.wait_at.get().is_some_and(|t| t <= now) {
            self.live.wait_at.set(None);
            // Orphan in FIN_WAIT_2 too long (Linux tcp_keepalive_timer)
            if self.state == TcpState::FinWait2 {
                self.abort(out);
            }
            return;
        }
        if self.dack.at.is_some_and(|t| t <= now) {
            self.delack_timer(out);
        }
        if self.live.keep_at.get().is_some_and(|t| t <= now) {
            self.live.keep_at.set(None);
            self.keepalive_timer(now, out);
        }
        let Some((kind, at)) = self.live.tmr.get() else {
            return;
        };
        if at > now {
            return;
        }
        self.live.tmr.set(None);
        match kind {
            Tmr::Rtx => self.rtx_timer(now, out),
            Tmr::Probe => self.probe_timer(now, out),
        }
    }

    /// Retransmission timeout (Linux tcp_retransmit_timer): back off,
    /// mark the flight lost and slow-start from one packet (CA_Loss,
    /// tcp_enter_loss), resend the head
    fn rtx_timer(&mut self, now: u64, out: &mut Out) {
        let handshake = matches!(self.state, TcpState::SynSent | TcpState::SynReceived);
        if !handshake && self.packets_out == 0 && !self.syn_unacked {
            return;
        }
        if !handshake && self.snd_wnd == 0 && !self.orphan && self.packets_out != 0 {
            self.rtx_zero_window(now, out);
            return;
        }
        // Linux tcp_retransmit_timer / tcp_syn_ack_timeout
        self.net_stat(LINUX_MIB_TCPTIMEOUTS);
        if self.rtx_stamp.is_none() {
            // The head went out about one (backed-off) RTO ago
            self.rtx_stamp = Some(now.saturating_sub(self.rto_cur()));
        }
        // Linux tcp_write_timeout: reset while the RTO is short or the
        // retries are not used up
        let reset = self.rto_cur() < RTO_MAX || !self.gave_up(self.live.retransmits.get(), now);
        if !handshake && self.out_of_resources(now, reset, out) {
            return;
        }
        if self.gave_up(self.live.retransmits.get(), now) {
            self.timed_out(out);
            return;
        }
        if self.live.retransmits.get() == 0 && !handshake {
            // Linux: the first timeout ends a recovery or disorder
            let mib = match self.ca_state {
                CaState::Recovery if self.is_reno() => Some(LINUX_MIB_TCPRENORECOVERYFAIL),
                CaState::Recovery => Some(LINUX_MIB_TCPSACKRECOVERYFAIL),
                CaState::Loss => Some(LINUX_MIB_TCPLOSSFAILURES),
                CaState::Disorder if self.is_reno() => Some(LINUX_MIB_TCPRENOFAILURES),
                CaState::Disorder => Some(LINUX_MIB_TCPSACKFAILURES),
                _ if self.sacked_out != 0 && self.is_reno() => Some(LINUX_MIB_TCPRENOFAILURES),
                _ if self.sacked_out != 0 => Some(LINUX_MIB_TCPSACKFAILURES),
                _ => None,
            };
            if let Some(m) = mib {
                self.net_stat(m);
            }
        }
        if handshake {
            // The SYN or SYN-ACK alone was out: one packet, lost
            let ss = self.cong.loss_ssthresh(1);
            self.cong.set_snd_ssthresh(ss);
            self.cong.set_snd_cwnd(1);
            self.cong.reset_cnt();
        } else {
            self.enter_loss();
        }
        self.rtt_seq = None;
        // Linux tcp_update_rto_stats
        self.live.retransmits.set(self.live.retransmits.get() + 1);
        self.stats.rto_count = self.stats.rto_count.wrapping_add(1);
        if handshake || self.syn_unacked {
            // Closed in SYN_RECEIVED: the SYN-ACK heads the queue and
            // goes alone (a SYN is never collapsed), what follows once
            // it is acked (the loss state resends it)
            self.syn_rtx = handshake || self.syn_rtx;
            self.stats.total_retrans = self.stats.total_retrans.wrapping_add(1);
            self.syn_rtx(out);
        } else if let Some(head) = self.rtx_head() {
            self.retransmit_skb(head, 1, now, out);
        }
        self.live.backoff.set(self.live.backoff.get() + 1);
        self.arm_rtx(now);
    }

    /// The receiver shrank its window over data in flight (Linux
    /// tcp_retransmit_timer: "receiver dastardly shrinks window"): the
    /// retransmissions become zero-window probes of the queue's head,
    /// which may lie past the window, and never time the connection out
    /// while the peer answers them ([`Self::rtx_probe0_timed_out`]); an
    /// orphan takes the ordinary path, so it cannot hang forever
    fn rtx_zero_window(&mut self, now: u64, out: &mut Out) {
        if self.rtx_stamp.is_none() {
            // The head went out about one (backed-off) RTO ago
            self.rtx_stamp = Some(now.saturating_sub(self.rto_cur()));
        }
        if self.rtx_probe0_timed_out(now) {
            self.timed_out(out);
            return;
        }
        // Linux tcp_enter_loss, then tcp_retransmit_skb of the head
        self.enter_loss();
        if let Some(head) = self.rtx_head() {
            self.retransmit_skb(head, 1, now, out);
        }
        self.live.backoff.set(self.live.backoff.get() + 1);
        self.arm_rtx(now);
    }

    /// A shrunk-window probe sequence gives up (Linux
    /// tcp_rtx_probe0_timed_out): past TCP_USER_TIMEOUT, else when the
    /// peer has been silent for longer than twice RTO_MAX (or the user
    /// timeout, if shorter) and the probes have lasted that long
    fn rtx_probe0_timed_out(&self, now: u64) -> bool {
        let rtx_delta = now.saturating_sub(self.rtx_stamp.unwrap_or(now));
        let mut timeout = 2 * RTO_MAX;
        let ut = u64::from(self.opts.user_timeout);
        if ut != 0 {
            if rtx_delta > ut {
                return true;
            }
            timeout = timeout.min(ut);
        }
        if now.saturating_sub(self.rcv_tstamp) <= timeout {
            return false;
        }
        rtx_delta > timeout
    }

    /// Resend the SYN-ACK for a retransmitted SYN and restart the
    /// retransmission timer (Linux tcp_rtx_synack, and tcp_check_req's
    /// request timer restart)
    pub(super) fn rtx_synack(&mut self, now: u64, out: &mut Out) {
        self.syn_rtx = true;
        self.stats.total_retrans = self.stats.total_retrans.wrapping_add(1);
        self.syn_rtx(out);
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
        self.net_stat(LINUX_MIB_TCPABORTONMEMORY);
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
        self.live.probes.set(self.live.probes.get() + 1);
        if self.gave_up(self.live.probes.get() - 1, now) {
            self.timed_out(out);
            return;
        }
        if self.out_of_resources(now, true, out) {
            return;
        }
        self.send_probe(LINUX_MIB_TCPWINPROBE, out);
        self.live.backoff.set(self.live.backoff.get() + 1);
        let mut t = self.rto_cur().max(RTO_MIN);
        if let Some(left) = self.user_left(now) {
            t = t.min(left.max(1));
        }
        self.live.tmr.set(Some((Tmr::Probe, now + t)));
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
        self.live.keep_at.set(None);
        if self.opts.keepalive && self.keep_state() {
            let left = self.keep_idle().saturating_sub(self.idle(now));
            self.live.keep_at.set(Some(now + left));
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
            if (ut != 0 && idle >= ut && self.live.probes.get() > 0)
                || (ut == 0 && self.live.probes.get() >= self.keep_cnt())
            {
                // Linux tcp_keepalive_timer -> tcp_write_err
                self.abort(out);
                out.err = Some(self.soft_err.take().unwrap_or(KernelError::TimedOut));
                self.net_stat(LINUX_MIB_TCPABORTONTIMEOUT);
                return;
            }
            self.send_probe(LINUX_MIB_TCPKEEPALIVE, out);
            self.live.probes.set(self.live.probes.get() + 1);
            self.keep_intvl()
        } else {
            self.keep_idle() - idle
        };
        self.live.keep_at.set(Some(now + next));
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
        let keep = [self.live.keep_at.get(), self.live.wait_at.get()]
            .into_iter()
            .flatten()
            .min();
        [self.live.tmr.get().map(|t| t.1), self.dack.at, keep]
    }
}

/// Milliseconds on the monotonic clock
pub fn now_ms() -> u64 {
    crate::time::monotonic_ns() / 1_000_000
}

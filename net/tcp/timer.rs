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
    Live, ORPHAN_RETRIES, Out, RTO_FALLBACK, RTO_INIT, RTO_MAX, RTO_MIN, TIMEWAIT_LEN, TcpCb,
    TcpState, Tmr,
};
use super::output::Push;
use super::recovery::CaState;
use crate::net::mib::*;
use crate::util::error::KernelError;

/// Linux usecs_to_jiffies with HZ 1000 (the timers' ms): rounded up
pub(super) fn usecs_to_jiffies(us: u64) -> u64 {
    us.div_ceil(1000)
}

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

    /// (Re)start the retransmission timer
    pub(super) fn arm_rtx(&mut self, now: u64) {
        self.live.tmr.set(Some((Tmr::Rtx, now + self.rto_cur())));
    }

    /// The retransmission timer after a timeout, no later than the user
    /// timeout since the first retransmission (Linux
    /// tcp_clamp_rto_to_user_timeout)
    fn arm_rtx_clamped(&mut self, now: u64) {
        let mut t = self.rto_cur();
        let ut = u64::from(self.opts.user_timeout);
        if ut != 0 {
            let elapsed = now.saturating_sub(self.rtx_stamp.unwrap_or(now));
            t = if elapsed >= ut {
                1
            } else {
                t.min(ut - elapsed)
            };
        }
        self.live.tmr.set(Some((Tmr::Rtx, now + t)));
    }

    /// Linux retransmits_timed_out: since the first retransmission of
    /// this episode, `timeout` ms passed, or with `timeout` 0 the time
    /// `boundary` exponentially backed-off retransmissions take
    /// (tcp_model_timeout from TCP_RTO_MIN, TCP_TIMEOUT_INIT in the
    /// handshake)
    fn retransmits_timed_out(&self, boundary: u32, timeout: u64, now: u64) -> bool {
        if self.live.retransmits.get() == 0 {
            return false;
        }
        let Some(start) = self.rtx_stamp else {
            return false;
        };
        let timeout = if timeout != 0 {
            timeout
        } else {
            let base = match self.state {
                TcpState::SynSent | TcpState::SynReceived => RTO_INIT,
                _ => RTO_MIN,
            };
            model_timeout(boundary, base)
        };
        now.saturating_sub(start) >= timeout
    }

    /// Linux tcp_orphan_retries: the sysctl (which may be 0), none after
    /// an ICMP error once the RTO is at its maximum, 8 for 0 while it is
    /// below (over 100 s from a 200 ms RTO)
    pub(super) fn orphan_retries(&self, alive: bool) -> u32 {
        let mut retries = self.cfg.orphan_retries;
        if self.soft_err.is_some() && !alive {
            retries = 0;
        }
        if retries == 0 && alive {
            retries = ORPHAN_RETRIES;
        }
        retries
    }

    /// A retransmission timeout's verdict (Linux tcp_write_timeout): the
    /// handshake gives up after its retry count, a connection when
    /// retransmits_timed_out says so (tcp_retries2, or TCP_USER_TIMEOUT);
    /// an orphan may be dropped for memory first. True if it is over.
    fn write_timeout(&mut self, now: u64, out: &mut Out) -> bool {
        let mut expired = false;
        let mut retry_until;
        if matches!(self.state, TcpState::SynSent | TcpState::SynReceived) {
            retry_until = self.syn_retries();
            expired = self.live.retransmits.get() >= retry_until;
        } else {
            retry_until = self.cfg.retries2;
            if self.orphan {
                let alive = self.rto_cur() < RTO_MAX;
                retry_until = self.orphan_retries(alive);
                let reset = alive || !self.retransmits_timed_out(retry_until, 0, now);
                if self.out_of_resources(now, reset, out) {
                    return true;
                }
            }
        }
        if !expired {
            let ut = u64::from(self.opts.user_timeout);
            expired = self.retransmits_timed_out(retry_until, ut, now);
        }
        if expired {
            self.timed_out(out);
        }
        expired
    }

    /// Linux tcp_rtt_estimator (Jacobson, SIGCOMM '88, with Linux's
    /// finer gain for a falling RTT): `mrtt_us` into srtt_us (8 x SRTT),
    /// mdev_us (4 x mean deviation), mdev_max_us and rttvar_us, the
    /// latter decaying towards the round's maximum deviation once per
    /// round (rtt_seq), never below TCP_RTO_MIN
    pub(super) fn rtt_estimator(&mut self, mrtt_us: i64) {
        let mut m = mrtt_us;
        let mut srtt = self.srtt_us;
        let rto_min_us = (RTO_MIN * 1000) as u32;
        if srtt != 0 {
            m -= i64::from(srtt >> 3);
            srtt = (i64::from(srtt) + m) as u32;
            if m < 0 {
                m = -m;
                m -= i64::from(self.mdev_us >> 2);
                if m > 0 {
                    m >>= 3;
                }
            } else {
                m -= i64::from(self.mdev_us >> 2);
            }
            self.mdev_us = (i64::from(self.mdev_us) + m) as u32;
            if self.mdev_us > self.mdev_max_us {
                self.mdev_max_us = self.mdev_us;
                if self.mdev_max_us > self.rttvar_us {
                    self.rttvar_us = self.mdev_max_us;
                }
            }
            if super::cb::after(self.snd_una, self.rtt_seq) {
                if self.mdev_max_us < self.rttvar_us {
                    self.rttvar_us -= (self.rttvar_us - self.mdev_max_us) >> 2;
                }
                self.rtt_seq = self.snd_nxt;
                self.mdev_max_us = rto_min_us;
            }
        } else {
            srtt = (m << 3) as u32;
            self.mdev_us = (m << 1) as u32;
            self.rttvar_us = self.mdev_us.max(rto_min_us);
            self.mdev_max_us = self.rttvar_us;
            self.rtt_seq = self.snd_nxt;
        }
        self.srtt_us = srtt.max(1);
    }

    /// Linux tcp_set_rto / __tcp_set_rto / tcp_bound_rto: SRTT plus
    /// rttvar, in ms rounded up, at most TCP_RTO_MAX
    pub(super) fn set_rto(&mut self) {
        let us = u64::from(self.srtt_us >> 3) + u64::from(self.rttvar_us);
        self.live.rto.set(usecs_to_jiffies(us).min(RTO_MAX));
    }

    /// No RTT from the handshake (Linux tcp_init_metrics, RFC 6298 5.7):
    /// TCP_TIMEOUT_FALLBACK
    pub(super) fn set_rto_fallback(&mut self) {
        self.rttvar_us = (RTO_FALLBACK * 1000) as u32;
        self.mdev_us = self.rttvar_us;
        self.mdev_max_us = self.rttvar_us;
        self.live.rto.set(RTO_FALLBACK);
    }

    /// Smoothed RTT and its variance in us (TCP_INFO tcpi_rtt,
    /// tcpi_rttvar: srtt_us >> 3, mdev_us >> 2)
    pub fn rtt(&self) -> (u32, u32) {
        (self.srtt_us >> 3, self.mdev_us >> 2)
    }

    /// Handshake retransmissions allowed (Linux tcp_write_timeout's
    /// syn retries; a request's SYN-ACKs, reqsk_timer_handler)
    fn syn_retries(&self) -> u32 {
        match self.state {
            TcpState::SynSent => self.cfg.syn_retries,
            _ => self.cfg.synack_retries,
        }
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
        // Linux tcp_write_timer_handler: icsk_pending stays set while
        // the reordering and loss probe handlers run (tcp_rearm_rto
        // reads it)
        if !matches!(kind, Tmr::Reo | Tmr::LossProbe) {
            self.live.tmr.set(None);
        }
        match kind {
            Tmr::Rtx => self.rtx_timer(now, out),
            Tmr::Probe => self.probe_timer(now, out),
            Tmr::Reo => self.rack_reo_timeout(now, out),
            Tmr::LossProbe => self.send_loss_probe(now, out),
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
        if self.write_timeout(now, out) {
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
        // A request's SYN-ACK timer has no congestion state (Linux
        // tcp_syn_ack_timeout); a SYN_SENT or SYN_RECV socket's does
        if !(self.passive && self.state == TcpState::SynReceived) {
            self.enter_loss();
        }
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
            // tcp_retransmit_skb of the SYN: the episode's first stamp,
            // one more retransmission towards undo
            self.rtx_stamp.get_or_insert(now);
            self.undo_retrans = self.undo_retrans.max(0) + 1;
        } else if let Some(head) = self.rtx_head() {
            self.retransmit_skb(head, 1, now, out);
        }
        self.live.backoff.set(self.live.backoff.get() + 1);
        self.arm_rtx_clamped(now);
    }

    /// The receiver shrank its window over data in flight (Linux
    /// tcp_retransmit_timer: "receiver dastardly shrinks window"): the
    /// retransmissions become zero-window probes of the queue's head,
    /// which may lie past the window, and never time the connection out
    /// while the peer answers them ([`Self::rtx_probe0_timed_out`]); an
    /// orphan takes the ordinary path, so it cannot hang forever
    fn rtx_zero_window(&mut self, now: u64, out: &mut Out) {
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
        self.arm_rtx_clamped(now);
    }

    /// A shrunk-window probe sequence gives up (Linux
    /// tcp_rtx_probe0_timed_out): past TCP_USER_TIMEOUT, else when the
    /// peer has been silent for longer than twice RTO_MAX (or the user
    /// timeout, if shorter) and the probes have lasted that long
    fn rtx_probe0_timed_out(&self, now: u64) -> bool {
        // Since the first retransmission, else the head's send
        let head = self.rtx.first().map(|s| super::cb::skb_mstamp_us(s) / 1000);
        let start = self.rtx_stamp.or(head).unwrap_or(now);
        let rtx_delta = now.saturating_sub(start);
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
            self.live.probes.set(0);
            self.probes_tstamp = None;
            return;
        }
        if self.snd_wnd != 0 {
            self.xmit(now, Push::Force, out);
            return;
        }
        // Linux tcp_probe_timer: TCP_USER_TIMEOUT since the first probe
        let ut = u64::from(self.opts.user_timeout);
        match self.probes_tstamp {
            None => self.probes_tstamp = Some(now),
            Some(t) if ut != 0 && now.saturating_sub(t) >= ut => {
                self.timed_out(out);
                return;
            }
            Some(_) => {}
        }
        let mut max_probes = self.cfg.retries2;
        if self.orphan {
            let alive = self.rto_cur() < RTO_MAX;
            max_probes = self.orphan_retries(alive);
            if !alive && self.live.backoff.get() >= max_probes {
                self.timed_out(out);
                return;
            }
            if self.out_of_resources(now, true, out) {
                return;
            }
        }
        if self.live.probes.get() >= max_probes {
            self.timed_out(out);
            return;
        }
        // Linux tcp_send_probe0
        self.send_probe(LINUX_MIB_TCPWINPROBE, out);
        self.live.probes.set(self.live.probes.get() + 1);
        if self.live.backoff.get() < self.cfg.retries2 {
            self.live.backoff.set(self.live.backoff.get() + 1);
        }
        let t = self.probe0_when();
        let t = self.clamp_probe0_to_user_timeout(t, now);
        self.live.tmr.set(Some((Tmr::Probe, now + t)));
    }

    /// Linux tcp_probe0_when: the RTO, at least TCP_RTO_MIN, backed off
    /// (at most ilog2(TCP_RTO_MAX / TCP_RTO_MIN) + 1 times), at most
    /// TCP_RTO_MAX
    fn probe0_when(&self) -> u64 {
        let shift = self.live.backoff.get().min(ilog2(RTO_MAX / RTO_MIN) + 1);
        (self.live.rto.get().max(RTO_MIN) << shift).min(RTO_MAX)
    }

    /// Linux tcp_clamp_probe0_to_user_timeout: no later than
    /// TCP_USER_TIMEOUT since the first probe, at least TCP_TIMEOUT_MIN
    fn clamp_probe0_to_user_timeout(&self, when: u64, now: u64) -> u64 {
        let ut = u64::from(self.opts.user_timeout);
        let Some(t) = self.probes_tstamp.filter(|_| ut != 0) else {
            return when;
        };
        let elapsed = now.saturating_sub(t);
        let remaining = (ut as i64 - elapsed as i64).max(TIMEOUT_MIN as i64) as u64;
        remaining.min(when)
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

/// Linux ilog2
fn ilog2(v: u64) -> u32 {
    63 - v.max(1).leading_zeros()
}

/// Linux tcp_model_timeout (ms): the time `boundary` retransmissions
/// take backing off from `rto_base`, doubling up to TCP_RTO_MAX
pub(super) fn model_timeout(boundary: u32, rto_base: u64) -> u64 {
    let thresh = ilog2(RTO_MAX / rto_base);
    let (b, t) = (u64::from(boundary), u64::from(thresh));
    if b <= t {
        ((2u64 << b) - 1) * rto_base
    } else {
        ((2u64 << t) - 1) * rto_base + (b - t) * RTO_MAX
    }
}

/// Linux TCP_TIMEOUT_MIN (2 jiffies), ms
const TIMEOUT_MIN: u64 = 2;

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

//! Loss recovery (Linux tcp_input.c: the NewReno/SACK state machine,
//! tcp_fastretrans_alert, PRR tcp_cwnd_reduction, the undo heuristics;
//! tcp_recovery.c; tcp_output.c tcp_xmit_retransmit_queue), I/O-free
//!
//! Every sent skb carries scoreboard tags (Linux TCPCB_SACKED_ACKED,
//! _SACKED_RETRANS, _LOST, _EVER_RETRANS) counted in packets_out,
//! sacked_out, lost_out and retrans_out, so the packets in flight are
//! packets_out - (sacked_out + lost_out) + retrans_out and the window
//! is in packets (Linux tcp_packets_in_flight, tcp_snd_cwnd). Loss
//! detection marks skbs lost: without SACK, three duplicate ACKs (each
//! counted as a "SACKed" packet, tcp_add_reno_sack) mark the head lost
//! and a partial ACK in recovery the next (tcp_newreno_mark_lost); a
//! timeout marks the whole queue (tcp_timeout_mark_lost). What is lost
//! and not yet retransmitted goes out as the window allows
//! (tcp_xmit_retransmit_queue); in Recovery the window follows PRR (RFC
//! 6937), after a timeout it slow-starts from one packet (CA_Loss).
//! Reductions found spurious (timestamps, D-SACKs) are undone.

use super::cb::{RTO_INIT, RTO_MIN, TcpCb, TcpState, Tmr, after, before, skb_mstamp_us};
use super::cong::{CaEvent, INFINITE_SSTHRESH};
use crate::net::mib::*;
use crate::net::skb::SkBuff;

/// Congestion states (Linux enum tcp_ca_state, its values)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CaState {
    Open = 0,
    Disorder = 1,
    Cwr = 2,
    Recovery = 3,
    Loss = 4,
}

/// Scoreboard tags of a sent skb (Linux TCPCB_*)
pub mod tag {
    pub const SACKED_ACKED: u8 = 0x01;
    pub const SACKED_RETRANS: u8 = 0x02;
    pub const LOST: u8 = 0x04;
    pub const TAGBITS: u8 = 0x07;
    pub const EVER_RETRANS: u8 = 0x80;
    pub const RETRANS: u8 = SACKED_RETRANS | EVER_RETRANS;
}

/// What an incoming ACK did (Linux FLAG_*)
pub mod flag {
    pub const DATA: u32 = 0x01;
    pub const WIN_UPDATE: u32 = 0x02;
    pub const DATA_ACKED: u32 = 0x04;
    pub const RETRANS_DATA_ACKED: u32 = 0x08;
    pub const SYN_ACKED: u32 = 0x10;
    pub const DATA_SACKED: u32 = 0x20;
    pub const LOST_RETRANS: u32 = 0x80;
    pub const ORIG_SACK_ACKED: u32 = 0x200;
    pub const SND_UNA_ADVANCED: u32 = 0x400;
    pub const DSACKING_ACK: u32 = 0x800;
    pub const SET_XMIT_TIMER: u32 = 0x1000;
    pub const SACK_RENEGING: u32 = 0x2000;
    pub const ACK_MAYBE_DELAYED: u32 = 0x10000;
    pub const DSACK_TLP: u32 = 0x20000;
    pub const ACKED: u32 = DATA_ACKED | SYN_ACKED;
    pub const NOT_DUP: u32 = DATA | WIN_UPDATE | ACKED;
    pub const CA_ALERT: u32 = DATA_SACKED | DSACKING_ACK;
    pub const FORWARD_PROGRESS: u32 = ACKED | DATA_SACKED;
}

/// What an ACK asks to (re)transmit (Linux REXMIT_*)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Rexmit {
    None,
    /// Lost skbs (tcp_xmit_retransmit_queue)
    Lost,
    /// F-RTO: new data first
    New,
}

/// RACK state (Linux tcp_sock.rack, RFC 8985)
#[derive(Clone, Copy, Debug)]
pub struct Rack {
    /// Send time (us) and end of the most recently (re)sent packet
    /// s/acked (Linux rack.mstamp, rack.end_seq)
    pub mstamp: u64,
    pub end_seq: u32,
    /// Its RTT, us (Linux rack.rtt_us)
    pub rtt_us: u64,
    /// The reordering window in min_rtt/4 steps, the recoveries it
    /// persists for
    pub reo_wnd_steps: u8,
    pub reo_wnd_persist: u8,
    /// A D-SACK asks to widen the window
    pub dsack_seen: bool,
    /// Something was s/acked since the last loss detection
    pub advanced: bool,
    /// The delivered count when the window last widened
    pub last_delivered: u32,
}

impl Default for Rack {
    fn default() -> Self {
        Self {
            mstamp: 0,
            end_seq: 0,
            rtt_us: 0,
            reo_wnd_steps: 1,
            reo_wnd_persist: 0,
            dsack_seen: false,
            advanced: false,
            last_delivered: 0,
        }
    }
}

/// net.ipv4.tcp_recovery bits (Linux TCP_RACK_*)
pub const RACK_STATIC_REO_WND: u8 = 2;
pub const RACK_NO_DUPTHRESH: u8 = 4;
/// Recoveries a widened reordering window persists for (Linux
/// TCP_RACK_RECOVERY_THRESH)
const RACK_RECOVERY_THRESH: u8 = 16;
/// Slack added to the reordering timer, ms (Linux TCP_TIMEOUT_MIN_US)
const TIMEOUT_MIN: u64 = 2;

/// Segments of `len` bytes at `mss` each (Linux tcp_set_skb_tso_segs):
/// (pcount, gso_size)
pub(super) fn tso_segs(len: usize, mss: u32) -> (u32, u32) {
    let mss = mss.max(1);
    if len <= mss as usize {
        (1, 0)
    } else {
        ((len as u32).div_ceil(mss), mss)
    }
}

/// Bytes per segment of `skb` (Linux tcp_skb_seglen / tcp_skb_mss)
pub(super) fn seglen(skb: &SkBuff) -> u32 {
    if skb.tcp().pcount() <= 1 {
        skb.len() as u32
    } else {
        skb.tcp().gso_size()
    }
}

impl TcpCb {
    // --- the retransmit queue by sequence number --------------------------

    /// Run `f` on the sent skb starting at `seq`
    pub(super) fn rtx_with<R>(&mut self, seq: u32, f: impl FnOnce(&mut SkBuff) -> R) -> Option<R> {
        let mut c = self.rtx.cursor_floor_mut(|s| !after(s.tcp().seq, seq));
        if c.current().is_none_or(|s| s.tcp().seq != seq) {
            return None;
        }
        c.with_current_mut(f)
    }

    /// The seq of the sent skb after the one starting at `seq`
    pub(super) fn rtx_next(&mut self, seq: u32) -> Option<u32> {
        let mut c = self.rtx.cursor_floor_mut(|s| !after(s.tcp().seq, seq));
        c.move_next();
        c.current().map(|s| s.tcp().seq)
    }

    /// The first sent skb's seq (Linux tcp_rtx_queue_head)
    pub(super) fn rtx_head(&self) -> Option<u32> {
        self.rtx.first().map(|s| s.tcp().seq)
    }

    // --- counts -----------------------------------------------------------

    /// Linux tcp_left_out
    pub(super) fn left_out(&self) -> u32 {
        self.sacked_out + self.lost_out
    }

    /// Linux tcp_packets_in_flight
    pub(super) fn in_flight(&self) -> u32 {
        (self.packets_out + self.retrans_out).saturating_sub(self.left_out())
    }

    /// Linux tcp_is_reno: no SACK scoreboard, duplicate ACKs stand in
    /// for SACKed packets
    pub(super) fn is_reno(&self) -> bool {
        !self.is_sack()
    }

    /// Linux tcp_in_cwnd_reduction
    pub(super) fn in_cwnd_reduction(&self) -> bool {
        matches!(self.ca_state, CaState::Cwr | CaState::Recovery)
    }

    /// Linux tcp_current_ssthresh, packets
    pub(super) fn current_ssthresh(&self) -> u32 {
        let ss = self.cong.snd_ssthresh();
        if self.in_cwnd_reduction() {
            ss
        } else {
            let c = self.cong.snd_cwnd();
            ss.max((c >> 1) + (c >> 2))
        }
    }

    /// Linux tcp_adjust_pcount: `skb_tags`' skb counts `decr` fewer
    /// packets
    pub(super) fn adjust_pcount(&mut self, skb_tags: u8, decr: i32) {
        let sub = |v: &mut u32| *v = (*v as i32).wrapping_sub(decr).max(0) as u32;
        sub(&mut self.packets_out);
        if skb_tags & tag::SACKED_ACKED != 0 {
            sub(&mut self.sacked_out);
        }
        if skb_tags & tag::SACKED_RETRANS != 0 {
            sub(&mut self.retrans_out);
        }
        if skb_tags & tag::LOST != 0 {
            sub(&mut self.lost_out);
        }
        if self.is_reno() && decr > 0 {
            self.sacked_out -= self.sacked_out.min(decr as u32);
        }
    }

    /// Linux tcp_count_delivered
    pub(super) fn count_delivered(&mut self, n: u32) {
        self.delivered = self.delivered.wrapping_add(n);
    }

    // --- Reno: duplicate ACKs as SACKed packets ---------------------------

    /// Linux tcp_limit_reno_sacked: sacked_out + holes <= packets_out
    fn limit_reno_sacked(&mut self) -> bool {
        let holes = self.lost_out.max(1).min(self.packets_out);
        if self.sacked_out + holes > self.packets_out {
            self.sacked_out = self.packets_out - holes;
            return true;
        }
        false
    }

    /// Linux tcp_check_reno_reordering: more duplicate ACKs than
    /// packets out means reordering
    fn check_reno_reordering(&mut self, addend: u32) {
        if !self.limit_reno_sacked() {
            return;
        }
        self.reordering = (self.packets_out + addend).min(self.cfg.max_reordering);
        self.reord_seen = self.reord_seen.wrapping_add(1);
        self.net_stat(LINUX_MIB_TCPRENOREORDER);
    }

    /// Linux tcp_add_reno_sack
    fn add_reno_sack(&mut self, num_dupack: u32) {
        if num_dupack == 0 {
            return;
        }
        let prior = self.sacked_out;
        self.sacked_out += num_dupack;
        self.check_reno_reordering(0);
        let delivered = self.sacked_out.saturating_sub(prior);
        self.count_delivered(delivered);
    }

    /// Linux tcp_remove_reno_sacks: `acked` packets cumulatively acked
    pub(super) fn remove_reno_sacks(&mut self, acked: u32) {
        if acked > 0 {
            // One ACK acked the hole, the rest ate duplicate ACKs
            self.count_delivered(acked.saturating_sub(self.sacked_out).max(1));
            if acked > self.sacked_out {
                self.sacked_out = 0;
            } else {
                self.sacked_out -= acked - 1;
            }
        }
        self.check_reno_reordering(acked);
    }

    /// Linux tcp_reset_reno_sack
    fn reset_reno_sack(&mut self) {
        self.sacked_out = 0;
    }

    // --- marking lost -----------------------------------------------------

    /// Linux tcp_init_undo
    fn init_undo(&mut self) {
        self.undo_marker = Some(self.snd_una);
        // Retransmissions in flight may come back D-SACKed, a probe's too
        self.undo_retrans = self.retrans_out as i32;
        if self.tlp_high_seq.is_some() && self.tlp_retrans {
            self.undo_retrans += 1;
        }
        if self.undo_retrans == 0 {
            self.undo_retrans = -1;
        }
    }

    /// Linux tcp_verify_retransmit_hint: called before lost_out or
    /// retrans_out change on a new loss
    fn verify_retransmit_hint(&mut self, seq: u32) {
        let set = match self.rtx_hint {
            None => self.retrans_out >= self.lost_out,
            Some(h) => before(seq, h),
        };
        if set {
            self.rtx_hint = Some(seq);
        }
    }

    /// Linux tcp_mark_skb_lost: the skb at `seq` is lost (a lost
    /// retransmission too: it may go again)
    pub(super) fn mark_skb_lost(&mut self, seq: u32) {
        let Some((sacked, pc)) = self.rtx_with(seq, |s| (s.tcp().sacked, s.tcp().pcount())) else {
            return;
        };
        if sacked & tag::SACKED_ACKED != 0 {
            return;
        }
        self.verify_retransmit_hint(seq);
        if sacked & tag::LOST != 0 {
            if sacked & tag::SACKED_RETRANS != 0 {
                self.rtx_with(seq, |s| s.tcp_mut().sacked &= !tag::SACKED_RETRANS);
                self.retrans_out = self.retrans_out.saturating_sub(pc);
                self.net_add(LINUX_MIB_TCPLOSTRETRANSMIT, u64::from(pc));
                self.lost = self.lost.wrapping_add(pc);
            }
        } else {
            self.lost_out += pc;
            self.rtx_with(seq, |s| s.tcp_mut().sacked |= tag::LOST);
            self.lost = self.lost.wrapping_add(pc);
        }
    }

    /// Linux tcp_rack_skb_timeout: us left before the skb sent at `sent`
    /// (us) counts as lost
    pub(super) fn rack_skb_timeout(&self, sent: u64, reo_wnd: u64) -> i64 {
        (sent + self.rack.rtt_us + reo_wnd) as i64 - self.tcp_mstamp as i64
    }

    /// Linux tcp_timeout_mark_lost: everything not SACKed is lost but
    /// the most recently sent; a SACKed head means the receiver reneged
    fn timeout_mark_lost(&mut self) {
        let head = self.rtx_head();
        let reneg = self
            .rtx
            .first()
            .is_some_and(|h| h.tcp().sacked & tag::SACKED_ACKED != 0);
        if reneg {
            self.net_stat(LINUX_MIB_TCPSACKRENEGING);
            self.sacked_out = 0;
            // Until this loss is recovered from
            self.is_sack_reneg = true;
        } else if self.is_reno() {
            self.reset_reno_sack();
        }
        let mut cur = head;
        while let Some(seq) = cur {
            let sent = self.rtx_with(seq, |s| skb_mstamp_us(s)).unwrap_or(0);
            if reneg {
                self.rtx_with(seq, |s| s.tcp_mut().sacked &= !tag::SACKED_ACKED);
            } else if Some(seq) != head && self.rack_skb_timeout(sent, 0) > 0 {
                // Recently sent: not lost yet
                cur = self.rtx_next(seq);
                continue;
            }
            self.mark_skb_lost(seq);
            cur = self.rtx_next(seq);
        }
        self.rtx_hint = None;
    }

    /// Linux tcp_enter_loss: a retransmission timeout
    pub(super) fn enter_loss(&mut self) {
        let new_recovery = self.ca_state < CaState::Recovery;
        self.timeout_mark_lost();
        if self.ca_state <= CaState::Disorder
            || !after(self.high_seq, self.snd_una)
            || (self.ca_state == CaState::Loss && self.live.retransmits.get() == 0)
        {
            self.prior_ssthresh = self.current_ssthresh();
            self.prior_cwnd = self.cong.snd_cwnd();
            let ss = self.ca_ssthresh();
            self.cong.set_ssthresh(ss);
            self.ca_event(CaEvent::Loss);
            self.init_undo();
        }
        self.cong.set_cwnd(self.in_flight() + 1);
        self.cong.reset_cnt();
        self.cong.stamp = self.jiffies32();
        // Many duplicate ACKs, then a timeout: reordering overestimated
        if self.ca_state <= CaState::Disorder && self.sacked_out >= self.cfg.reordering {
            self.reordering = self.reordering.min(self.cfg.reordering);
        }
        self.set_ca_state(CaState::Loss);
        self.high_seq = self.snd_max;
        self.tlp_high_seq = None;
        // F-RTO (RFC 5682 3.1 step 1): resend SND.UNA unless a recovery
        // was underway, but for repeated timeouts of one SND.UNA (3.2)
        // (hk has no MTU probing)
        self.frto = self.cfg.frto != 0 && (new_recovery || self.live.retransmits.get() != 0);
    }

    /// Linux tcp_simple_retransmit (path MTU reduced): what no longer
    /// fits a segment is lost and resent without a window reduction
    pub(super) fn simple_retransmit(&mut self, out: &mut super::cb::Out) {
        let mss = self.cur_mss();
        let mut cur = self.rtx_head();
        while let Some(seq) = cur {
            if self.rtx_with(seq, |s| seglen(s)).unwrap_or(0) > mss {
                self.mark_skb_lost(seq);
            }
            cur = self.rtx_next(seq);
        }
        if self.lost_out == 0 {
            return;
        }
        if self.is_reno() {
            self.limit_reno_sacked();
        }
        // Linux tcp_non_congestion_loss_retransmit
        if self.ca_state != CaState::Loss {
            self.high_seq = self.snd_max;
            let ss = self.current_ssthresh();
            self.cong.set_ssthresh(ss);
            self.prior_ssthresh = 0;
            self.undo_marker = None;
            self.set_ca_state(CaState::Loss);
        }
        self.xmit_retransmit_queue(out);
    }

    // --- undo ---------------------------------------------------------------

    /// The ACK's echo is older than our TSval at `when` (Linux
    /// tcp_tsopt_ecr_before)
    fn tsopt_ecr_before(&self, when: u64) -> bool {
        let ts = (when as u32).wrapping_add(self.ts_off);
        self.rcv_tsecr.is_some_and(|e| e != 0 && before(e, ts))
    }

    /// Linux tcp_packet_delayed: nothing was retransmitted, or the echo
    /// predates the first retransmission
    fn packet_delayed(&self) -> bool {
        if let Some(t) = self.rtx_stamp {
            return self.tsopt_ecr_before(t);
        }
        if !self.is_sack() && !before(self.snd_una, self.high_seq) {
            return false;
        }
        self.state != TcpState::SynSent
    }

    /// Linux tcp_any_retrans_done
    pub(super) fn any_retrans_done(&self) -> bool {
        self.retrans_out != 0
            || self
                .rtx
                .first()
                .is_some_and(|s| s.tcp().sacked & tag::EVER_RETRANS != 0)
    }

    /// Linux tcp_retrans_stamp_cleanup
    fn retrans_stamp_cleanup(&mut self) {
        if !self.any_retrans_done() {
            self.rtx_stamp = None;
        }
    }

    /// Linux tcp_undo_cwnd_reduction
    fn undo_cwnd_reduction(&mut self, unmark_loss: bool) {
        if unmark_loss {
            let mut cur = self.rtx_head();
            while let Some(seq) = cur {
                self.rtx_with(seq, |s| s.tcp_mut().sacked &= !tag::LOST);
                cur = self.rtx_next(seq);
            }
            self.lost_out = 0;
            self.rtx_hint = None;
        }
        if self.prior_ssthresh != 0 {
            let c = self.ca_undo_cwnd();
            self.cong.set_cwnd(c);
            if self.prior_ssthresh > self.cong.snd_ssthresh() {
                self.cong.set_ssthresh(self.prior_ssthresh);
            }
        }
        self.cong.stamp = self.jiffies32();
        self.undo_marker = None;
        // Force RACK to examine the losses again
        self.rack.advanced = true;
    }

    /// Linux tcp_may_undo
    fn may_undo(&self) -> bool {
        self.undo_marker.is_some() && (self.undo_retrans == 0 || self.packet_delayed())
    }

    /// Linux tcp_is_non_sack_preventing_reopen: Reno holds the state
    /// until something above high_seq is acked (RFC 6582)
    fn non_sack_preventing_reopen(&mut self) -> bool {
        if self.snd_una == self.high_seq && self.is_reno() {
            if !self.any_retrans_done() {
                self.rtx_stamp = None;
            }
            return true;
        }
        false
    }

    /// Linux tcp_try_undo_recovery
    fn try_undo_recovery(&mut self) -> bool {
        if self.may_undo() {
            self.undo_cwnd_reduction(false);
            self.net_stat(if self.ca_state == CaState::Loss {
                LINUX_MIB_TCPLOSSUNDO
            } else {
                LINUX_MIB_TCPFULLUNDO
            });
        } else if self.rack.reo_wnd_persist > 0 {
            self.rack.reo_wnd_persist -= 1;
        }
        if self.non_sack_preventing_reopen() {
            return true;
        }
        self.set_ca_state(CaState::Open);
        self.is_sack_reneg = false;
        false
    }

    /// Linux tcp_try_undo_dsack: D-SACKs covered every retransmission
    fn try_undo_dsack(&mut self) -> bool {
        if self.undo_marker.is_some() && self.undo_retrans == 0 {
            self.rack.reo_wnd_persist = (self.rack.reo_wnd_persist + 1).min(RACK_RECOVERY_THRESH);
            self.undo_cwnd_reduction(false);
            self.net_stat(LINUX_MIB_TCPDSACKUNDO);
            return true;
        }
        false
    }

    /// Linux tcp_try_undo_loss: after a partial ACK, or F-RTO found the
    /// timeout spurious (`frto_undo`)
    fn try_undo_loss(&mut self, frto_undo: bool) -> bool {
        if !(frto_undo || self.may_undo()) {
            return false;
        }
        self.undo_cwnd_reduction(true);
        self.net_stat(LINUX_MIB_TCPLOSSUNDO);
        if frto_undo {
            self.net_stat(LINUX_MIB_TCPSPURIOUSRTOS);
        }
        self.live.retransmits.set(0);
        if self.non_sack_preventing_reopen() {
            return true;
        }
        if frto_undo || self.is_sack() {
            self.set_ca_state(CaState::Open);
            self.is_sack_reneg = false;
        }
        true
    }

    /// Linux tcp_try_undo_partial: a partial ACK of a delayed packet
    fn try_undo_partial(&mut self, prior_snd_una: u32) -> bool {
        if self.undo_marker.is_none() || !self.packet_delayed() {
            return false;
        }
        self.check_sack_reordering(prior_snd_una, true);
        if self.retrans_out != 0 {
            return true;
        }
        if !self.any_retrans_done() {
            self.rtx_stamp = None;
        }
        self.undo_cwnd_reduction(true);
        self.net_stat(LINUX_MIB_TCPPARTIALUNDO);
        self.try_keep_open();
        false
    }

    /// Linux tcp_check_sack_reordering: data at `low_seq` arrived after
    /// higher data was SACKed: the reordering degree is at least that
    /// distance in segments
    pub(super) fn check_sack_reordering(&mut self, low_seq: u32, ts: bool) {
        let mss = self.live.mss.get();
        let fack = self.highest_sack_seq();
        if !before(low_seq, fack) {
            return;
        }
        let metric = fack.wrapping_sub(low_seq);
        if mss != 0 && metric > self.reordering.saturating_mul(mss) {
            self.reordering = metric.div_ceil(mss).min(self.cfg.max_reordering);
        }
        self.reord_seen = self.reord_seen.wrapping_add(1);
        self.net_stat(if ts {
            LINUX_MIB_TCPTSREORDER
        } else {
            LINUX_MIB_TCPSACKREORDER
        });
    }

    /// Linux tcp_highest_sack_seq
    pub(super) fn highest_sack_seq(&self) -> u32 {
        if self.sacked_out == 0 {
            return self.snd_una;
        }
        self.highest_sack.unwrap_or(self.snd_max)
    }

    // --- window reduction (PRR) ---------------------------------------------

    /// Linux tcp_init_cwnd_reduction
    fn init_cwnd_reduction(&mut self) {
        self.high_seq = self.snd_max;
        self.tlp_high_seq = None;
        self.cong.reset_cnt();
        self.prior_cwnd = self.cong.snd_cwnd();
        self.prr_delivered = 0;
        self.prr_out = 0;
        let ss = self.ca_ssthresh();
        self.cong.set_ssthresh(ss);
    }

    /// Linux tcp_cwnd_reduction (RFC 6937 PRR): spread the reduction
    /// over the round trip while the flight exceeds ssthresh, then send
    /// as much as was delivered (slow start towards ssthresh when
    /// SND.UNA advanced with no new loss)
    pub(super) fn cwnd_reduction(&mut self, newly_acked_sacked: u32, newly_lost: u32, flg: u32) {
        if newly_acked_sacked == 0 || self.prior_cwnd == 0 {
            return;
        }
        let ss = self.cong.snd_ssthresh();
        let delta = i64::from(ss) - i64::from(self.in_flight());
        self.prr_delivered += newly_acked_sacked;
        let mut sndcnt: i64 = if delta < 0 {
            let dividend =
                u64::from(ss) * u64::from(self.prr_delivered) + u64::from(self.prior_cwnd) - 1;
            (dividend / u64::from(self.prior_cwnd)) as i64 - i64::from(self.prr_out)
        } else {
            let mut n = (i64::from(self.prr_delivered) - i64::from(self.prr_out))
                .max(i64::from(newly_acked_sacked));
            if flg & flag::SND_UNA_ADVANCED != 0 && newly_lost == 0 {
                n += 1;
            }
            delta.min(n)
        };
        // Force a fast retransmit upon entering fast recovery
        sndcnt = sndcnt.max(if self.prr_out != 0 { 0 } else { 1 });
        let c = (i64::from(self.in_flight()) + sndcnt).max(0) as u32;
        self.cong.set_cwnd(c);
    }

    /// Linux tcp_end_cwnd_reduction: back to ssthresh (unless undone)
    fn end_cwnd_reduction(&mut self) {
        let ss = self.cong.snd_ssthresh();
        if ss < INFINITE_SSTHRESH && (self.ca_state == CaState::Cwr || self.undo_marker.is_some()) {
            self.cong.set_cwnd(ss);
            self.cong.stamp = self.jiffies32();
        }
        self.ca_event(CaEvent::CompleteCwr);
    }

    /// Linux tcp_try_keep_open
    fn try_keep_open(&mut self) {
        let st = if self.left_out() != 0 || self.any_retrans_done() {
            CaState::Disorder
        } else {
            CaState::Open
        };
        if self.ca_state != st {
            self.set_ca_state(st);
            self.high_seq = self.snd_max;
        }
    }

    /// Linux tcp_try_to_open
    fn try_to_open(&mut self) {
        if !self.any_retrans_done() {
            self.rtx_stamp = None;
        }
        if self.ca_state != CaState::Cwr {
            self.try_keep_open();
        }
    }

    /// Linux tcp_enter_recovery
    pub(super) fn enter_recovery(&mut self) {
        self.retrans_stamp_cleanup();
        self.net_stat(if self.is_reno() {
            LINUX_MIB_TCPRENORECOVERY
        } else {
            LINUX_MIB_TCPSACKRECOVERY
        });
        self.prior_ssthresh = 0;
        self.init_undo();
        if !self.in_cwnd_reduction() {
            self.prior_ssthresh = self.current_ssthresh();
            self.init_cwnd_reduction();
        }
        self.set_ca_state(CaState::Recovery);
    }

    // --- the state machine --------------------------------------------------

    /// Linux tcp_process_loss: an ACK in CA_Loss ends it when the lost
    /// data is recovered or found spurious (F-RTO, RFC 5682 3.1, or the
    /// timestamp echo); else it retransmits more
    fn process_loss(&mut self, flg: u32, num_dupack: u32, rexmit: &mut Rexmit) {
        let recovered = !before(self.snd_una, self.high_seq);
        if flg & flag::SND_UNA_ADVANCED != 0 && self.try_undo_loss(false) {
            return;
        }
        if self.frto {
            // Step 3.b: a timeout is spurious if not all data are lost,
            // i.e. never retransmitted data are (s)acked
            if flg & flag::ORIG_SACK_ACKED != 0 && self.try_undo_loss(true) {
                return;
            }
            if after(self.snd_max, self.high_seq) {
                // Step 3.a: the loss was real
                if flg & flag::DATA_SACKED != 0 || num_dupack != 0 {
                    self.frto = false;
                }
            } else if flg & flag::SND_UNA_ADVANCED != 0 && !recovered {
                self.high_seq = self.snd_max;
                // Step 2.b: send new data (once cwnd is updated in
                // tcp_ack), else the conventional recovery
                let wnd_end = self.snd_una.wrapping_add(self.snd_wnd);
                if !self.wq.is_empty() && after(wnd_end, self.snd_max) {
                    *rexmit = Rexmit::New;
                    return;
                }
                self.frto = false;
            }
        }
        if recovered {
            self.try_undo_recovery();
            return;
        }
        if self.is_reno() {
            if after(self.snd_max, self.high_seq) && num_dupack != 0 {
                self.add_reno_sack(num_dupack);
            } else if flg & flag::SND_UNA_ADVANCED != 0 {
                self.reset_reno_sack();
            }
        }
        *rexmit = Rexmit::Lost;
    }

    /// Linux tcp_newreno_mark_lost (RFC 6582): the head is lost after
    /// dupthresh duplicate ACKs, and after each partial ACK in recovery
    fn newreno_mark_lost(&mut self, snd_una_advanced: bool) {
        let st = self.ca_state;
        if !((st < CaState::Recovery && self.sacked_out >= self.reordering)
            || (st == CaState::Recovery && snd_una_advanced))
        {
            return;
        }
        let Some(head) = self.rtx_head() else {
            return;
        };
        let Some((sacked, pc, len, mss)) = self.rtx_with(head, |s| {
            (s.tcp().sacked, s.tcp().pcount(), s.len(), seglen(s))
        }) else {
            return;
        };
        if sacked & tag::LOST != 0 {
            return;
        }
        if pc > 1 && len > mss as usize {
            self.rtx_fragment(head, mss as usize, mss);
        }
        self.mark_skb_lost(head);
    }

    /// Linux tcp_identify_packet_loss
    fn identify_packet_loss(&mut self, flg: &mut u32) {
        if self.rtx.is_empty() {
            return;
        }
        if self.is_reno() {
            self.newreno_mark_lost(*flg & flag::SND_UNA_ADVANCED != 0);
        } else {
            let prior = self.retrans_out;
            if self.rack_mark_lost() {
                *flg &= !flag::SET_XMIT_TIMER;
            }
            if prior > self.retrans_out {
                *flg |= flag::LOST_RETRANS;
            }
        }
    }

    /// Linux tcp_time_to_recover: loss detection marked a packet lost
    fn time_to_recover(&self) -> bool {
        self.lost_out != 0
    }

    /// Linux tcp_fastretrans_alert: an ACK that may change the packets
    /// in flight other than trivially (duplicate, SACK, D-SACK, or any
    /// ACK outside CA_Open): update the state and say what to
    /// retransmit; the window itself changes in `cong_control`
    pub(super) fn fastretrans_alert(
        &mut self,
        prior_snd_una: u32,
        num_dupack: u32,
        flg: &mut u32,
        rexmit: &mut Rexmit,
    ) {
        let f = *flg;
        if self.packets_out == 0 && self.sacked_out != 0 {
            self.sacked_out = 0;
        }
        // B. In all the states check for reneging SACKs
        if self.check_sack_reneging(flg) {
            return;
        }
        // D. State exit when high_seq is acked
        if self.ca_state == CaState::Open {
            self.rtx_stamp = None;
        } else if !before(self.snd_una, self.high_seq) {
            match self.ca_state {
                CaState::Cwr => {
                    if self.snd_una != self.high_seq {
                        self.end_cwnd_reduction();
                        self.set_ca_state(CaState::Open);
                    }
                }
                CaState::Recovery => {
                    if self.is_reno() {
                        self.reset_reno_sack();
                    }
                    if self.try_undo_recovery() {
                        return;
                    }
                    self.end_cwnd_reduction();
                }
                _ => {}
            }
        }
        // E. Process the state
        match self.ca_state {
            CaState::Recovery => {
                if f & flag::SND_UNA_ADVANCED == 0 {
                    if self.is_reno() {
                        self.add_reno_sack(num_dupack);
                    }
                } else if self.try_undo_partial(prior_snd_una) {
                    return;
                }
                if self.try_undo_dsack() {
                    self.try_to_open();
                }
                self.identify_packet_loss(flg);
                if self.ca_state != CaState::Recovery {
                    if !self.time_to_recover() {
                        return;
                    }
                    // Undone, but the loss is evident: recover again
                    self.enter_recovery();
                }
            }
            CaState::Loss => {
                self.process_loss(f, num_dupack, rexmit);
                self.identify_packet_loss(flg);
                // Change state if undone or a retransmission was lost
                if !(self.ca_state == CaState::Open || *flg & flag::LOST_RETRANS != 0) {
                    return;
                }
                if !self.alert_default(f, num_dupack, flg) {
                    return;
                }
            }
            _ => {
                if !self.alert_default(f, num_dupack, flg) {
                    return;
                }
            }
        }
        *rexmit = Rexmit::Lost;
    }

    /// tcp_fastretrans_alert's default case (Open, Disorder, CWR, and
    /// Loss once undone or a retransmission was lost): false if no
    /// loss is evident (nothing to retransmit)
    fn alert_default(&mut self, f: u32, num_dupack: u32, flg: &mut u32) -> bool {
        if self.is_reno() {
            if f & flag::SND_UNA_ADVANCED != 0 {
                self.reset_reno_sack();
            }
            self.add_reno_sack(num_dupack);
        }
        if self.ca_state <= CaState::Disorder {
            self.try_undo_dsack();
        }
        self.identify_packet_loss(flg);
        if !self.time_to_recover() {
            self.try_to_open();
            return false;
        }
        self.enter_recovery();
        true
    }

    /// Linux tcp_ack_is_dubious
    pub(super) fn ack_is_dubious(&self, f: u32) -> bool {
        f & flag::NOT_DUP == 0 || f & flag::CA_ALERT != 0 || self.ca_state != CaState::Open
    }

    /// Linux tcp_may_raise_cwnd
    fn may_raise_cwnd(&self, f: u32) -> bool {
        if self.reordering > self.cfg.reordering {
            return f & flag::FORWARD_PROGRESS != 0;
        }
        f & flag::DATA_ACKED != 0
    }

    /// Linux tcp_cong_control (no cong_control op): PRR while reducing,
    /// else the algorithm's growth for the packets delivered up to `ack`
    pub(super) fn cong_control(&mut self, ack: u32, acked_sacked: u32, losses: u32, f: u32) {
        if self.in_cwnd_reduction() {
            self.cwnd_reduction(acked_sacked, losses, f);
        } else if self.may_raise_cwnd(f) {
            self.cong_avoid(ack, acked_sacked);
        }
    }

    /// Linux tcp_xmit_recovery: with cwnd updated, F-RTO's new data or
    /// the retransmissions loss recovery allows
    pub(super) fn xmit_recovery(&mut self, rexmit: Rexmit, out: &mut super::cb::Out) {
        if rexmit == Rexmit::None || self.state == TcpState::SynSent {
            return;
        }
        if rexmit == Rexmit::New {
            self.xmit(self.clock, super::output::Push::NagleOff, out);
            if after(self.snd_max, self.high_seq) {
                return;
            }
            self.frto = false;
        }
        self.xmit_retransmit_queue(out);
    }

    /// Linux tcp_rearm_rto: restart the retransmission timer after
    /// forward progress, or stop it with nothing in flight; replacing
    /// the reordering or loss probe timer, only what is left of the RTO
    /// since the head was sent (tcp_rto_delta_us)
    pub(super) fn rearm_rto(&mut self, now: u64) {
        if self.packets_out == 0 {
            self.live.tmr.set(None);
            return;
        }
        let pending = self.live.tmr.get().map(|t| t.0);
        if matches!(pending, Some(Tmr::Reo) | Some(Tmr::LossProbe)) {
            let delta = self.rto_delta(now).max(1) as u64;
            self.live.tmr.set(Some((Tmr::Rtx, now + delta)));
        } else {
            self.arm_rtx(now);
        }
    }

    /// Linux tcp_rto_delta_us: how far in the future the RTO of the
    /// head's last transmission is (ms here: the timers' unit)
    pub(super) fn rto_delta(&self, _now: u64) -> i64 {
        let sent = self.rtx.first().map_or(self.tcp_mstamp, skb_mstamp_us);
        let delta = (self.rto_cur() * 1000) as i64 - self.tcp_mstamp.saturating_sub(sent) as i64;
        delta / 1000
    }

    /// Linux tcp_check_sack_reneging: SND.UNA advanced onto a SACKed
    /// skb, so the receiver dropped what it SACKed (or the scoreboard is
    /// briefly odd): give it max(RTT/2, 10 ms) to set it straight
    /// before the RTO clears the scoreboard
    fn check_sack_reneging(&mut self, flg: &mut u32) -> bool {
        if *flg & flag::SACK_RENEGING != 0 && *flg & flag::SND_UNA_ADVANCED != 0 {
            let delay = u64::from(self.srtt_us >> 4).div_ceil(1000).max(10);
            self.live.tmr.set(Some((Tmr::Rtx, self.clock + delay)));
            *flg &= !flag::SET_XMIT_TIMER;
            return true;
        }
        false
    }

    // --- RACK (Linux tcp_recovery.c, RFC 8985) ------------------------------

    /// Linux tcp_rack_advance: the most recently (re)sent packet
    /// s/acked; a retransmission acked sooner than min_rtt is ambiguous
    /// and skipped
    pub(super) fn rack_advance(&mut self, sacked: u8, end_seq: u32, xmit: u64) {
        let rtt = self.tcp_mstamp.saturating_sub(xmit);
        if rtt < self.min_rtt() && sacked & tag::RETRANS != 0 {
            return;
        }
        self.rack.advanced = true;
        self.rack.rtt_us = rtt;
        if super::sack::sent_after(xmit, self.rack.mstamp, end_seq, self.rack.end_seq) {
            self.rack.mstamp = xmit;
            self.rack.end_seq = end_seq;
        }
    }

    /// Linux tcp_rack_reo_wnd: no settling time before reordering is
    /// seen once recovery started or dupthresh packets are SACKed, else
    /// min_rtt/4 per step, at most SRTT
    fn rack_reo_wnd(&self) -> u64 {
        if self.reord_seen == 0 {
            if self.ca_state >= CaState::Recovery {
                return 0;
            }
            if self.sacked_out >= self.reordering && self.cfg.recovery & RACK_NO_DUPTHRESH == 0 {
                return 0;
            }
        }
        let srtt_us = u64::from(self.srtt_us >> 3);
        ((self.min_rtt() >> 2) * u64::from(self.rack.reo_wnd_steps)).min(srtt_us)
    }

    /// Linux tcp_min_rtt: the windowed minimum RTT, us (~0U for none)
    pub(super) fn min_rtt(&self) -> u64 {
        u64::from(self.rtt_min.get())
    }

    /// Linux tcp_update_rtt_min: the RTT `rtt_us` into the windowed
    /// minimum (tcp_min_rtt_wlen seconds; 0 counts as one jiffy), but
    /// not a suspected delayed ACK's longer one
    pub(super) fn update_rtt_min(&mut self, rtt_us: u64, flg: u32) {
        if flg & flag::ACK_MAYBE_DELAYED != 0 && rtt_us > self.min_rtt() {
            return;
        }
        let wlen = self.cfg.min_rtt_wlen.saturating_mul(1000);
        let r = if rtt_us == 0 {
            1000
        } else {
            rtt_us.min(u64::from(u32::MAX)) as u32
        };
        let now = self.jiffies32();
        self.rtt_min.running_min(wlen, now, r);
    }

    /// Linux tcp_rack_detect_loss: a packet sent before the most
    /// recently s/acked one and not s/acked within RTT + the reordering
    /// window is lost. Returns the longest wait left for the others, us
    /// (Linux walks tsorted_sent_queue in send order and stops at the
    /// first sent later; hk checks every skb of the queue: the same set)
    fn rack_detect_loss(&mut self) -> u64 {
        let reo_wnd = self.rack_reo_wnd();
        let mut wait = 0;
        let mut cur = self.rtx_head();
        while let Some(seq) = cur {
            cur = self.rtx_next(seq);
            let Some((t, tx)) = self.rtx_with(seq, |s| (s.tcp(), skb_mstamp_us(s))) else {
                break;
            };
            if t.sacked & tag::SACKED_ACKED != 0 {
                continue;
            }
            // Marked lost, not yet retransmitted
            if t.sacked & tag::LOST != 0 && t.sacked & tag::SACKED_RETRANS == 0 {
                continue;
            }
            if !super::sack::sent_after(self.rack.mstamp, tx, self.rack.end_seq, t.end_seq) {
                continue;
            }
            let left = self.rack_skb_timeout(tx, reo_wnd);
            if left <= 0 {
                self.mark_skb_lost(seq);
            } else {
                wait = wait.max(left as u64);
            }
        }
        wait
    }

    /// Linux tcp_rack_mark_lost: detect losses after an advance; arm
    /// the reordering timer for the ones still waiting
    fn rack_mark_lost(&mut self) -> bool {
        if !self.rack.advanced {
            return false;
        }
        self.rack.advanced = false;
        let wait = self.rack_detect_loss();
        if wait != 0 {
            // usecs_to_jiffies, then TCP_TIMEOUT_MIN
            let at = self.clock + (wait.div_ceil(1000) + TIMEOUT_MIN).min(self.rto_cur().max(1));
            self.live.tmr.set(Some((Tmr::Reo, at)));
        }
        wait != 0
    }

    /// Linux tcp_rack_reo_timeout: the reordering window passed: mark
    /// the expired packets lost and retransmit them
    pub(super) fn rack_reo_timeout(&mut self, now: u64, out: &mut super::cb::Out) {
        let lost = self.lost;
        let prior = self.in_flight();
        self.rack_detect_loss();
        if prior != self.in_flight() {
            if self.ca_state != CaState::Recovery {
                self.enter_recovery();
                self.cwnd_reduction(1, self.lost.wrapping_sub(lost), 0);
            }
            self.xmit_retransmit_queue(out);
        }
        if self.live.tmr.get().is_none_or(|t| t.0 != Tmr::Rtx) {
            self.rearm_rto(now);
        }
    }

    /// Linux tcp_rack_update_reo_wnd: widen the window by a step for a
    /// D-SACK at most once a round trip, keep it for
    /// RACK_RECOVERY_THRESH recoveries, then back to one step
    pub(super) fn rack_update_reo_wnd(&mut self, prior_delivered: Option<u32>) {
        let Some(pd) = prior_delivered.filter(|&d| d != 0) else {
            return;
        };
        if self.cfg.recovery & RACK_STATIC_REO_WND != 0 {
            return;
        }
        if before(pd, self.rack.last_delivered) {
            self.rack.dsack_seen = false;
        }
        if self.rack.dsack_seen {
            self.rack.reo_wnd_steps = self.rack.reo_wnd_steps.saturating_add(1);
            self.rack.dsack_seen = false;
            self.rack.last_delivered = self.delivered;
            self.rack.reo_wnd_persist = RACK_RECOVERY_THRESH;
        } else if self.rack.reo_wnd_persist == 0 {
            self.rack.reo_wnd_steps = 1;
        }
    }

    /// Linux tcp_set_xmit_timer: a loss probe if one may go, else the
    /// RTO
    pub(super) fn set_xmit_timer(&mut self, now: u64) {
        if self.packets_out == 0 || !self.schedule_loss_probe(now, true) {
            self.rearm_rto(now);
        }
    }

    // --- tail loss probe (Linux tcp_output.c, RFC 8985 TLP) -----------------

    /// Linux tcp_schedule_loss_probe: in Open or CWR with SACK, probe
    /// after 2 RTT (plus the minimum RTO for a lone packet, the delayed
    /// ACK), 1 s without an RTT, never later than the RTO
    pub(super) fn schedule_loss_probe(&mut self, now: u64, advancing_rto: bool) -> bool {
        if !matches!(self.cfg.early_retrans, 3 | 4)
            || !self.is_sack()
            || !matches!(self.ca_state, CaState::Open | CaState::Cwr)
        {
            return false;
        }
        let mut timeout = if self.srtt_us != 0 {
            let t = u64::from(self.srtt_us >> 2).div_ceil(1000);
            if self.packets_out == 1 {
                t + RTO_MIN
            } else {
                t + TIMEOUT_MIN
            }
        } else {
            RTO_INIT
        };
        let rto_delta = if advancing_rto {
            self.rto_cur() as i64
        } else {
            self.rto_delta(now)
        };
        if rto_delta > 0 {
            timeout = timeout.min(rto_delta as u64);
        }
        self.live.tmr.set(Some((Tmr::LossProbe, now + timeout)));
        true
    }

    /// Linux tcp_send_loss_probe: the probe timer fired: send a new
    /// segment if the window allows, else the last one again; then the
    /// RTO
    pub(super) fn send_loss_probe(&mut self, now: u64, out: &mut super::cb::Out) {
        if self.tlp_high_seq.is_none() && self.loss_probe(now, out) {
            self.tlp_high_seq = Some(self.snd_max);
            self.net_stat(LINUX_MIB_TCPLOSSPROBES);
            // Restart the RTO from now
            self.live.tmr.set(None);
        }
        self.rearm_rto(now);
    }

    /// The probe itself: true if it went out
    fn loss_probe(&mut self, now: u64, out: &mut super::cb::Out) -> bool {
        self.tlp_retrans = false;
        let mss = self.cur_mss();
        let wnd_end = self.snd_una.wrapping_add(self.snd_wnd);
        if let Some(head) = self.wq.front() {
            let len = (head.len() as u32).min(mss);
            if !after(self.snd_nxt.wrapping_add(len), wnd_end) {
                let pc = self.packets_out;
                self.xmit(now, super::output::Push::Tlp, out);
                return self.packets_out > pc;
            }
        }
        let Some(last) = self
            .rtx
            .last()
            .map(|s| (s.tcp().seq, s.tcp().pcount(), s.len()))
        else {
            return false;
        };
        let (mut seq, pc, len) = last;
        if pc > 1 && len > ((pc - 1) * mss) as usize {
            if !self.rtx_fragment(seq, ((pc - 1) * mss) as usize, mss) {
                return false;
            }
            let Some(next) = self.rtx_next(seq) else {
                return false;
            };
            seq = next;
        }
        if self.retransmit_raw(seq, 1, out).is_none() {
            return false;
        }
        self.tlp_retrans = true;
        true
    }

    /// Linux tcp_process_tlp_ack: ACKs during a probe episode; one
    /// beyond it after a retransmitted probe means a loss repaired by
    /// the probe: reduce the window once (CWR)
    pub(super) fn process_tlp_ack(&mut self, ack: u32, f: u32) {
        let Some(h) = self.tlp_high_seq else {
            return;
        };
        if before(ack, h) {
            return;
        }
        if !self.tlp_retrans || f & flag::DSACK_TLP != 0 {
            // New data probed, or the original and the probe both
            // arrived: no loss
            self.tlp_high_seq = None;
        } else if after(ack, h) {
            self.init_cwnd_reduction();
            self.set_ca_state(CaState::Cwr);
            self.end_cwnd_reduction();
            self.try_keep_open();
            self.net_stat(LINUX_MIB_TCPLOSSPROBERECOVERY);
        } else if f & (flag::SND_UNA_ADVANCED | flag::NOT_DUP | flag::DATA_SACKED) == 0 {
            // A pure duplicate: the original and the probe arrived
            self.tlp_high_seq = None;
        }
    }
}

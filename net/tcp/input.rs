//! Segment arrival (RFC 9293 3.10.7, RFC 5961, RFC 7323; Linux
//! tcp_input.c tcp_rcv_state_process / tcp_validate_incoming / tcp_ack /
//! tcp_data_queue / tcp_fin), I/O-free
//!
//! Order for synchronized states: PAWS (RFC 7323 5: an old timestamp
//! drops the segment with a duplicate ACK, except RSTs and Linux's
//! "disordered ACK" exception), sequence acceptability (Linux
//! tcp_sequence: a segment may start at the right window edge, so a
//! zero window still lets ACKs, RSTs and window probes in), RST
//! (exactly RCV.NXT resets, else challenge ACK), SYN (challenge ACK,
//! or SYN-ACK retransmission for a duplicate SYN in SYN_RECEIVED),
//! TS.Recent update, ACK (RFC 5961 range check, send queue, RTT from the
//! timestamp echo or Karn's timed segment, congestion, scaled window
//! update), text (in order to the receive queue, else the out-of-order
//! map; never beyond the advertised window), FIN; then data or an ACK
//! goes out, or the delayed ACK timer is armed (`ack.rs`).

use super::cb::{
    Ins, MemKind, OOW_RATELIMIT, Out, PAWS_WRAP, RCV_SHUTDOWN, Seg, SegIn, TcpCb, TcpState, Tmr,
    after, before, between, flags, skb_mstamp_us, wake,
};
use super::cong::AckSample;
use super::mem;
use super::recovery::{Rexmit, flag, tag};
use super::sack::SackState;
use crate::net::mib::*;
use crate::net::skb::SkBuff;
use crate::util::error::KernelError;
use alloc::boxed::Box;

impl TcpCb {
    /// Process a segment for this connection: its header `s`, its
    /// payload the data of `skb` (queued as it is, nothing copied)
    pub fn input(&mut self, s: &SegIn, skb: Box<SkBuff>, now: u64, out: &mut Out) {
        self.tick(now);
        self.stats.segs_in = self.stats.segs_in.wrapping_add(1);
        if s.data_len() != 0 {
            self.stats.data_segs_in = self.stats.data_segs_in.wrapping_add(1);
        }
        match self.state {
            TcpState::Closed | TcpState::Listen => {}
            TcpState::SynSent => self.rcv_syn_sent(s, skb, now, out),
            _ => self.rcv_synced(s, skb, now, out),
        }
    }

    /// RFC 9293 3.10.7.3 (Linux tcp_rcv_synsent_state_process)
    fn rcv_syn_sent(&mut self, s: &SegIn, skb: Box<SkBuff>, now: u64, out: &mut Out) {
        let ack_ok = s.has(flags::ACK);
        if ack_ok
            && (!after(s.ack, self.iss) || after(s.ack, self.snd_max) || !self.synack_ts_ok(s))
        {
            if after(s.ack, self.iss) && !after(s.ack, self.snd_max) {
                // In range, so the echoed timestamp failed
                self.net_stat(LINUX_MIB_PAWSACTIVEREJECTED);
            }
            if !s.has(flags::RST) {
                self.reset_seg(
                    Seg {
                        seq: s.ack,
                        flags: flags::RST,
                        ..Default::default()
                    },
                    out,
                );
            }
            return;
        }
        if s.has(flags::RST) {
            if ack_ok {
                self.fail(KernelError::ConnectionRefused, out);
            }
            return;
        }
        if !s.has(flags::SYN) {
            return;
        }
        self.syn_rcvd(s, now);
        if !ack_ok {
            // Simultaneous open: SYN-ACK from our ISS, wait for its ACK
            // (not in OutSegs: its end is not beyond SND.NXT, as Linux)
            self.set_state(TcpState::SynReceived);
            self.syn_seg(out);
            return;
        }
        let prior_snd_una = self.snd_una;
        self.snd_una = s.ack;
        // Linux tcp_clean_rtx_queue acknowledges the SYN, a packet
        // delivered (FLAG_SYN_ACKED clears retrans_stamp)
        self.count_delivered(1);
        self.net_stat(LINUX_MIB_TCPDELIVERED);
        self.syn_unacked = false;
        self.rtx_stamp = None;
        // Linux tcp_ack of the SYN-ACK: a timed-out SYN left CA_Loss
        // (tcp_fastretrans_alert), before tcp_finish_connect
        let mut flg = flag::SND_UNA_ADVANCED | flag::SYN_ACKED;
        if self.ack_is_dubious(flg) {
            let mut rexmit = Rexmit::None;
            self.rcv_tsecr = s.ts.filter(|_| self.ts_ok).map(|(_, e)| e);
            self.fastretrans_alert(prior_snd_una, 0, &mut flg, &mut rexmit);
        }
        self.established(s, now, out);
        self.ack_now = true;
        self.rcv_text(s, skb, now, out);
        self.output(now, out);
    }

    /// A SYN-ACK's echo must lie between our SYN's TSval and now (Linux
    /// tcp_rcv_synsent_state_process "PAWS active rejected")
    fn synack_ts_ok(&self, s: &SegIn) -> bool {
        match s.ts {
            Some((_, e)) if self.ts_ok && e != 0 => {
                let sent = (self.lsndtime as u32).wrapping_add(self.ts_off);
                between(e, sent, self.tsval())
            }
            _ => true,
        }
    }

    /// The handshake completed with `s`
    fn established(&mut self, s: &SegIn, now: u64, out: &mut Out) {
        self.set_state(TcpState::Established);
        // The handshake's timeouts are over (Linux tcp_finish_connect,
        // tcp_rcv_state_process SYN_RECV: icsk_retransmits = 0)
        self.live.retransmits.set(0);
        // Linux tcp_create_openreq_child: the request became a socket
        self.tcp_stat_if(self.passive, TCP_MIB_PASSIVEOPENS);
        self.snd_wnd = self.seg_wnd(s);
        self.max_wnd = self.max_wnd.max(self.snd_wnd);
        self.snd_wl1 = s.seq;
        // The handshake's RTT (Linux tcp_ack of the SYN-ACK,
        // tcp_synack_rtt_meas): our SYN's or SYN-ACK's unless it was
        // resent (Karn), else the timestamp echo; none: RFC 6298 5.7's
        // 3 s (tcp_init_metrics)
        let rtt = if self.syn_rtx {
            -1
        } else {
            self.tcp_mstamp.saturating_sub(self.syn_mstamp) as i64
        };
        let mut st = SackState::default();
        (st.seq_rtt_us, st.ca_rtt_us) = (rtt, rtt);
        self.ack_update_rtt(s, flag::SYN_ACKED, &mut st);
        if self.srtt_us == 0 {
            self.set_rto_fallback();
        }
        self.live.backoff.set(0);
        self.rtx_stamp = None;
        self.live.tmr.set(None);
        self.rcv_tstamp = now;
        self.init_transfer();
        self.arm_keepalive(now);
        out.established = true;
        out.wake |= wake::STATE | wake::EST;
    }

    /// Linux tcp_sequence: the segment overlaps [RCV.NXT, RCV.NXT+WND]
    fn acceptable(&self, s: &SegIn) -> bool {
        let end = s.seq.wrapping_add(s.seq_len());
        !before(end, self.rcv_nxt) && !after(s.seq, self.rcv_nxt.wrapping_add(self.rcv_wnd()))
    }

    /// Linux tcp_paws_check: TSval not older than TS.Recent by more than
    /// `win`, or TS.Recent unset or too old to trust
    fn paws_ok(&self, tsval: u32, win: i32) -> bool {
        (self.ts_recent.wrapping_sub(tsval) as i32) <= win
            || self.clock.saturating_sub(self.ts_stamp) >= PAWS_WRAP
            || self.ts_recent == 0
    }

    /// RFC 7323 5.3 PAWS (Linux tcp_validate_incoming + tcp_paws_discard
    /// + tcp_disordered_ack_check): true if `s` must be dropped
    fn paws_reject(&self, s: &SegIn) -> bool {
        let Some((v, _)) = s.ts else {
            return false;
        };
        if !self.ts_ok || self.paws_ok(v, 1) || s.has(flags::RST) {
            return false;
        }
        // A reordered pure duplicate ACK within the replay window passes
        let replay = (self.live.rto.get() * 6 / 5) as i32;
        let disordered = s.has(flags::ACK)
            && s.seq_len() == 0
            && s.seq == self.rcv_nxt
            && s.ack == self.snd_una
            && !self.may_update_window(s)
            && (self.ts_recent.wrapping_sub(v) as i32) <= replay;
        !disordered
    }

    /// Linux tcp_may_update_window
    fn may_update_window(&self, s: &SegIn) -> bool {
        after(s.ack, self.snd_una)
            || after(s.seq, self.snd_wl1)
            || (s.seq == self.snd_wl1 && (self.seg_wnd(s) > self.snd_wnd || s.wnd == 0))
    }

    /// RFC 7323 4.3 (Linux tcp_replace_ts_recent): remember the TSval of
    /// a segment at or before Last.ACK.sent
    fn update_ts_recent(&mut self, s: &SegIn) {
        if let Some((v, _)) = s.ts
            && self.ts_ok
            && !after(s.seq, self.rcv_wup)
            && self.paws_ok(v, 0)
        {
            self.ts_recent = v;
            self.ts_stamp = self.clock;
        }
    }

    /// RTT in us from the timestamp echo of a segment acknowledging new
    /// data (RFC 7323 4; Linux tcp_rtt_tsopt_us: ms in us, at least 1)
    fn ts_rtt(&self, s: &SegIn) -> Option<u64> {
        let (_, e) = s.ts?;
        if !self.ts_ok || e == 0 {
            return None;
        }
        let d = self.tsval().wrapping_sub(e) as i32;
        (d >= 0).then_some((d as u64 * 1000).max(1))
    }

    /// Synchronized states and SYN_RECEIVED
    fn rcv_synced(&mut self, s: &SegIn, skb: Box<SkBuff>, now: u64, out: &mut Out) {
        let req = self.passive && self.state == TcpState::SynReceived;
        if req
            && s.has(flags::SYN)
            && !s.has(flags::ACK | flags::RST)
            && s.seq == self.irs
            && !self.paws_reject(s)
        {
            // Retransmitted SYN: the SYN-ACK was lost (Linux
            // tcp_check_req, rate limited)
            if !self.oow_recent() {
                self.rtx_synack(now, out);
            } else {
                self.net_stat(LINUX_MIB_TCPACKSKIPPEDSYNRECV);
            }
            return;
        }
        if self.paws_reject(s) {
            if s.has(flags::SYN) {
                self.syn_challenge(out);
                return;
            }
            if s.has(flags::ACK) && s.seq_len() == 0 && before(s.seq, self.rcv_nxt) {
                // An old pure ACK is just dropped (Linux
                // tcp_disordered_ack_check TCP_RFC7323_PAWS_ACK)
                self.net_stat(LINUX_MIB_PAWS_OLD_ACK);
                return;
            }
            self.net_stat(LINUX_MIB_PAWSESTABREJECTED);
            if !self.oow_limited(s, LINUX_MIB_TCPACKSKIPPEDPAWS) {
                self.send_ack(out); // dupack
            }
            return;
        }
        if !self.acceptable(s) {
            if s.has(flags::SYN) {
                self.syn_challenge(out);
                return;
            }
            if s.has(flags::RST) {
                return;
            }
            // Linux tcp_sequence: starting past the window
            let edge = self.rcv_nxt.wrapping_add(self.rcv_wnd());
            self.net_stat_if(after(s.seq, edge), LINUX_MIB_BEYOND_WINDOW);
            if !self.oow_limited(s, LINUX_MIB_TCPACKSKIPPEDSEQ) {
                self.dupack(s, out);
            }
            return;
        }
        if s.has(flags::RST) {
            if s.seq != self.rcv_nxt {
                self.challenge_ack(out); // RFC 5961 3.2
            } else if req {
                // Linux tcp_check_req: the request dies (embryonic_reset)
                self.tcp_stat(TCP_MIB_ATTEMPTFAILS);
                self.net_stat(LINUX_MIB_EMBRYONICRSTS);
                self.on_reset(out);
            } else {
                self.on_reset(out);
            }
            return;
        }
        // Crossed SYNs: the peer's bare SYN-ACK for our SYN completes
        // the handshake (Linux tcp_validate_incoming, since 6.11; a user
        // socket only: not a request, not an orphan)
        // (Linux also tests sk->sk_socket: an orphan never stays in
        // SYN_RECEIVED here, close() takes it to FIN_WAIT_1 or CLOSED)
        let cross = self.state == TcpState::SynReceived
            && !self.passive
            && s.has(flags::ACK)
            && s.seq_len() == 1
            && s.seq.wrapping_add(1) == self.rcv_nxt
            && s.ack == self.snd_nxt;
        if s.has(flags::SYN) && !cross {
            if req {
                // A new SYN in window: reset, drop the request (Linux
                // tcp_check_req embryonic_reset)
                self.tcp_stat(TCP_MIB_ATTEMPTFAILS);
                if let Some(r) = super::output::reset_for(s) {
                    self.reset_seg(r, out);
                }
                self.net_stat(LINUX_MIB_EMBRYONICRSTS);
                self.set_closed(out);
            } else {
                self.syn_challenge(out); // RFC 5961 4.2
            }
            return;
        }
        if !s.has(flags::ACK) {
            return;
        }
        if self.state == TcpState::SynReceived {
            if !after(s.ack, self.snd_una) || after(s.ack, self.snd_max) {
                self.reset_seg(
                    Seg {
                        seq: s.ack,
                        flags: flags::RST,
                        ..Default::default()
                    },
                    out,
                );
                return;
            }
            if req && !self.req_full {
                // tcp_check_req accepted it: the listener makes the
                // child, then the child processes it (state unchanged)
                out.req_ack = Some(skb);
                return;
            }
            self.update_ts_recent(s);
            // Linux tcp_rcv_state_process: tcp_ack(FLAG_SLOWPATH)
            self.net_stat_if(s.seq_len() == 0, LINUX_MIB_TCPPUREACKS);
            self.snd_una = s.ack;
            if !self.passive {
                // Simultaneous open: our SYN is on the retransmit queue,
                // acked in tcp_ack (tcp_clean_rtx_queue, TCPDelivered)
                self.count_delivered(1);
                self.net_stat(LINUX_MIB_TCPDELIVERED);
            }
            self.syn_unacked = false;
            // SYN-ACK delivery, which tcp_ack does not track
            self.count_delivered(1);
            self.established(s, now, out);
            // Linux tcp_rcv_state_process scales the completing
            // segment's window, a SYN-ACK's too
            self.snd_wnd = u32::from(s.wnd) << self.snd_wscale;
            if cross {
                // Its SYN is old: a duplicate, ACKed at once (Linux
                // tcp_data_queue: a retransmit, DelayedACKLost)
                self.net_stat(LINUX_MIB_DELAYEDACKLOST);
                self.enter_quickack();
                self.ack_now = true;
            }
        } else if !self.rcv_ack(s, now, out) {
            return;
        }
        if !self.after_ack(now, out) {
            return;
        }
        if self.state == TcpState::Established && !out.established {
            // Linux tcp_rcv_established, after tcp_ack
            self.rcv_rtt_measure_ts(s.seq_len());
        }
        self.rcv_text(s, skb, now, out);
        self.output(now, out);
    }

    /// Linux __tcp_oow_rate_limited: true if an out-of-window or
    /// challenge ACK went out less than OOW_RATELIMIT ago (else note now)
    fn oow_recent(&mut self) -> bool {
        let now = self.clock;
        if self
            .last_oow
            .is_some_and(|t| now.saturating_sub(t) < OOW_RATELIMIT)
        {
            return true;
        }
        self.last_oow = Some(now);
        false
    }

    /// Linux tcp_oow_rate_limited: data segments are never limited
    /// (they are not part of an ACK loop), pure ones and SYNs are; a
    /// skipped ACK counts in `mib`
    fn oow_limited(&mut self, s: &SegIn, mib: usize) -> bool {
        if s.data_len() != 0 && !s.has(flags::SYN) {
            return false;
        }
        if !self.oow_recent() {
            return false;
        }
        self.net_stat(mib);
        true
    }

    /// RFC 5961 challenge ACK, rate limited per connection (Linux
    /// tcp_send_challenge_ack)
    fn challenge_ack(&mut self, out: &mut Out) {
        if self.oow_recent() {
            self.net_stat(LINUX_MIB_TCPACKSKIPPEDCHALLENGE);
            return;
        }
        self.net_stat(LINUX_MIB_TCPCHALLENGEACK);
        self.send_ack(out);
    }

    /// A SYN on a synchronized connection (Linux tcp_validate_incoming
    /// syn_challenge: an input error in ESTABLISHED, where
    /// tcp_rcv_established passes syn_inerr)
    fn syn_challenge(&mut self, out: &mut Out) {
        self.tcp_stat_if(self.state == TcpState::Established, TCP_MIB_INERRS);
        self.net_stat(LINUX_MIB_TCPSYNCHALLENGE);
        self.challenge_ack(out);
    }

    /// An unacceptable or old segment: ACK at once (Linux
    /// tcp_send_dupack: duplicated data means our ACK was lost, so stop
    /// delaying ACKs for a while)
    fn dupack(&mut self, s: &SegIn, out: &mut Out) {
        if s.seq_len() != 0 && before(s.seq, self.rcv_nxt) {
            self.net_stat(LINUX_MIB_DELAYEDACKLOST);
            self.enter_quickack();
            let end = s.seq.wrapping_add(s.seq_len());
            let end = if after(end, self.rcv_nxt) {
                self.rcv_nxt
            } else {
                end
            };
            self.dsack_set(s.seq, end);
        }
        self.send_ack(out);
    }

    /// State changes once our FIN is acknowledged; false if the segment
    /// is consumed
    fn after_ack(&mut self, now: u64, out: &mut Out) -> bool {
        if !self.fin_acked() {
            return true;
        }
        match self.state {
            TcpState::FinWait1 => {
                self.set_state(TcpState::FinWait2);
                self.live.tmr.set(None);
                self.arm_fw2(now);
                out.wake |= wake::STATE;
                true
            }
            TcpState::Closing => {
                self.time_wait(out);
                false
            }
            TcpState::LastAck => {
                self.set_closed(out);
                false
            }
            _ => true,
        }
    }

    /// RST accepted (Linux tcp_reset): the error a user sees
    fn on_reset(&mut self, out: &mut Out) {
        let err = match self.state {
            TcpState::SynReceived => KernelError::ConnectionRefused,
            TcpState::CloseWait => KernelError::BrokenPipe,
            _ => KernelError::ConnectionReset,
        };
        self.fail(err, out);
    }

    /// The ACK field (RFC 9293 3.10.7.4 fifth check, RFC 5961 5.2: the
    /// acceptable range below SND.UNA is min(max window, bytes acked) as
    /// in Linux tcp_ack); false if the segment must be dropped. An old
    /// ACK (below SND.UNA) updates TS.Recent but not the window.
    /// Then Linux tcp_ack: the window, the retransmit queue
    /// (tcp_clean_rtx_queue), loss recovery for a dubious ACK
    /// (tcp_fastretrans_alert), the timers, the congestion window
    /// (tcp_cong_control) and the retransmissions it allows
    /// (tcp_xmit_recovery).
    fn rcv_ack(&mut self, s: &SegIn, now: u64, out: &mut Out) -> bool {
        let ack = s.ack;
        let span = self
            .max_wnd
            .min(self.stats.bytes_acked.min(u64::from(u32::MAX)) as u32);
        if after(ack, self.snd_max) || before(ack, self.snd_una.wrapping_sub(span)) {
            self.challenge_ack(out);
            return false;
        }
        let prior_snd_una = self.snd_una;
        self.rcv_tsecr = s.ts.filter(|_| self.ts_ok).map(|(_, e)| e);
        let blocks = if self.is_sack() { s.sack.blocks() } else { &[] };
        let mut st = SackState::default();
        let mut rexmit = Rexmit::None;
        if before(ack, prior_snd_una) {
            // Linux old_ack: it may carry new data, so TS.Recent first,
            // before SACK processing can trigger a retransmission; its
            // SACK blocks may still tell something
            self.update_ts_recent(s);
            if !blocks.is_empty() {
                let prior_delivered = self.delivered;
                let mut flg = self.sacktag_write_queue(ack, blocks, prior_snd_una, &mut st);
                self.fastretrans_alert(prior_snd_una, 0, &mut flg, &mut rexmit);
                self.newly_delivered(prior_delivered);
                self.xmit_recovery(rexmit, out);
            }
            return true;
        }
        let mut flg = 0;
        if after(ack, prior_snd_una) {
            flg |= flag::SND_UNA_ADVANCED;
            self.live.retransmits.set(0);
        }
        let prior_fack = if self.is_reno() {
            self.snd_una
        } else {
            self.highest_sack_seq()
        };
        let prior_packets = self.packets_out;
        let (prior_delivered, prior_lost) = (self.delivered, self.lost);
        // Linux tcp_ack's slow path (hk has no header prediction, so
        // never TCPHPAcks)
        if s.seq_len() != 0 {
            flg |= flag::DATA;
        } else {
            self.net_stat(LINUX_MIB_TCPPUREACKS);
        }
        self.update_ts_recent(s);
        flg |= self.ack_update_window(s, out);
        if !blocks.is_empty() {
            flg |= self.sacktag_write_queue(ack, blocks, prior_snd_una, &mut st);
        }
        if st.sack_delivered != 0 {
            self.count_delivered(st.sack_delivered);
        }
        // Something worked: the soft error log goes (Linux tcp_ack)
        self.soft_err = None;
        self.live.probes.set(0);
        self.rcv_tstamp = now;
        let acked = ack.wrapping_sub(prior_snd_una);
        if acked != 0 {
            self.stats.bytes_acked += u64::from(acked);
            self.snd_una = ack;
            if self.syn_unacked {
                // Linux tcp_clean_rtx_queue: the SYN skb, FLAG_SYN_ACKED
                self.syn_unacked = false;
                self.rtx_stamp = None;
                flg |= flag::SYN_ACKED | flag::SET_XMIT_TIMER;
            }
            if before(self.snd_nxt, ack) {
                self.snd_nxt = ack;
            }
            out.wake |= wake::SPACE;
        }
        if prior_packets == 0 {
            // Linux no_queue: a D-SACK may undo a reduction
            if flg & flag::DSACKING_ACK != 0 {
                self.fastretrans_alert(prior_snd_una, 0, &mut flg, &mut rexmit);
                self.newly_delivered(prior_delivered);
            }
            if flg & flag::SET_XMIT_TIMER != 0 {
                self.set_xmit_timer(now);
            }
            self.process_tlp_ack(ack, flg);
            self.mem_settle();
            return true;
        }
        flg |= self.clean_rtx_queue(prior_snd_una, prior_fack, &mut st);
        self.ack_update_rtt(s, flg, &mut st);
        self.ca_acked(&st);
        self.mem_settle();
        // Linux tcp_check_space -> sk_stream_write_space
        if self.writable() {
            use core::sync::atomic::Ordering;
            self.live.nospace.store(false, Ordering::Release);
        }
        self.rack_update_reo_wnd(st.prior_delivered);
        self.process_tlp_ack(ack, flg);
        if self.ack_is_dubious(flg) {
            let num_dupack =
                u32::from(flg & (flag::SND_UNA_ADVANCED | flag::NOT_DUP | flag::DSACKING_ACK) == 0);
            self.fastretrans_alert(prior_snd_una, num_dupack, &mut flg, &mut rexmit);
        }
        if flg & flag::SET_XMIT_TIMER != 0 {
            self.set_xmit_timer(now);
        }
        let delivered = self.newly_delivered(prior_delivered);
        let lost = self.lost.wrapping_sub(prior_lost);
        self.cong_control(ack, delivered, lost, flg);
        self.xmit_recovery(rexmit, out);
        true
    }

    /// Linux tcp_newly_delivered: the packets this ACK delivered
    fn newly_delivered(&self, prior: u32) -> u32 {
        let d = self.delivered.wrapping_sub(prior);
        self.net_add(LINUX_MIB_TCPDELIVERED, u64::from(d));
        d
    }

    /// The window of an acceptable ACK, taken when Linux
    /// tcp_may_update_window allows (tcp_ack_update_window: SND.WL1
    /// follows; a changed window with data waiting may restart an idle
    /// window); one opening a zero window stops the probes (Linux
    /// tcp_ack_probe). Returns FLAG_WIN_UPDATE if taken
    fn ack_update_window(&mut self, s: &SegIn, out: &mut Out) -> u32 {
        if !self.may_update_window(s) {
            return 0;
        }
        self.snd_wl1 = s.seq;
        let nwin = self.seg_wnd(s);
        if self.snd_wnd == nwin {
            return flag::WIN_UPDATE;
        }
        let old_wnd = self.snd_wnd;
        self.snd_wnd = nwin;
        if self.send_head() {
            self.slow_start_after_idle_check(self.clock);
        }
        self.max_wnd = self.max_wnd.max(nwin);
        if old_wnd == 0 && nwin > 0 && self.live.tmr.get().is_some_and(|t| t.0 == Tmr::Probe) {
            // Linux tcp_ack_probe
            self.live.tmr.set(None);
            self.live.backoff.set(0);
            self.probes_tstamp = None;
            out.wake |= wake::SPACE;
        }
        flag::WIN_UPDATE
    }

    /// Linux tcp_ack_update_rtt: the RTT of the packets acked or SACKed
    /// (none if retransmitted data was acked: Karn), else of the
    /// timestamp echo, feeds the congestion sample (rs->rtt_us), the
    /// minimum RTT and the RTO estimator; a valid sample ends the backoff
    fn ack_update_rtt(&mut self, s: &SegIn, flg: u32, st: &mut SackState) {
        if st.seq_rtt_us < 0
            && flg & flag::ACKED != 0
            && let Some(r) = self.ts_rtt(s)
        {
            st.seq_rtt_us = r as i64;
            st.ca_rtt_us = st.seq_rtt_us;
        }
        if st.seq_rtt_us < 0 {
            return;
        }
        self.update_rtt_min(st.ca_rtt_us.max(0) as u64, flg);
        self.rtt_estimator(st.seq_rtt_us);
        self.set_rto();
        self.live.backoff.set(0);
    }

    /// The algorithm's accounting of the ACK (Linux tcp_clean_rtx_queue
    /// calling icsk_ca_ops->pkts_acked): the packets it acknowledged,
    /// its RTT (us, -1 if none), the bytes delivered over that round
    /// trip
    fn ca_acked(&mut self, st: &SackState) {
        let rtt_us = st.ca_rtt_us.clamp(-1, i64::from(i32::MAX)) as i32;
        let dlv = st
            .prior_delivered
            .map_or(0, |p| self.delivered.wrapping_sub(p));
        let s = AckSample {
            pkts_acked: st.pkts_acked,
            rtt_us,
            in_flight: self.live.mss.get().saturating_mul(dlv),
        };
        self.ca_pkts_acked(&s);
    }

    /// Linux tcp_clean_rtx_queue: skbs wholly acknowledged leave the
    /// retransmit queue, their tags and packets with them; an skb of
    /// several segments loses the acknowledged ones (tcp_tso_acked).
    /// Returns the ACK's FLAG_* bits.
    fn clean_rtx_queue(&mut self, prior_snd_una: u32, prior_fack: u32, st: &mut SackState) -> u32 {
        let mut flg = 0;
        let mut reord = self.snd_max;
        let mut pkts_acked = 0;
        let (mut first_ackt, mut last_ackt) = (None, 0);
        let prior_sacked = self.sacked_out;
        let mut fully_acked = true;
        while let Some(f) = self.rtx.first() {
            let (t, tx) = (f.tcp(), skb_mstamp_us(f));
            let acked_pcount;
            let mut fully = true;
            // Where the skb starts once its acked head is trimmed
            let mut at = t.seq;
            if after(t.end_seq, self.snd_una) {
                if t.pcount() == 1 || !after(self.snd_una, t.seq) {
                    break;
                }
                acked_pcount = self.rtx_trim_head(t.seq, self.snd_una.wrapping_sub(t.seq) as usize);
                if acked_pcount == 0 {
                    break;
                }
                at = self.snd_una;
                fully = false;
            } else {
                acked_pcount = t.pcount();
            }
            if t.sacked & tag::RETRANS != 0 {
                if t.sacked & tag::SACKED_RETRANS != 0 {
                    self.retrans_out = self.retrans_out.saturating_sub(acked_pcount);
                }
                flg |= flag::RETRANS_DATA_ACKED;
            } else if t.sacked & tag::SACKED_ACKED == 0 {
                last_ackt = tx;
                first_ackt.get_or_insert(tx);
                if before(t.seq, reord) {
                    reord = t.seq;
                }
                if !after(t.end_seq, self.high_seq) {
                    flg |= flag::ORIG_SACK_ACKED;
                }
            }
            if t.sacked & tag::SACKED_ACKED != 0 {
                self.sacked_out = self.sacked_out.saturating_sub(acked_pcount);
            } else if !self.is_reno() {
                self.count_delivered(acked_pcount);
                if !self.spurious_retrans(t.sacked, tx) {
                    self.rack_advance(t.sacked, t.end_seq, tx);
                }
            }
            if t.sacked & tag::LOST != 0 {
                self.lost_out = self.lost_out.saturating_sub(acked_pcount);
            }
            self.packets_out = self.packets_out.saturating_sub(acked_pcount);
            pkts_acked += acked_pcount;
            // Linux tcp_rate_skb_delivered: the skb as trimmed
            self.rate_skb_delivered(st, at);
            flg |= flag::DATA_ACKED;
            fully_acked = fully;
            if !fully {
                break;
            }
            if self.rtx_hint == Some(t.seq) {
                self.rtx_hint = None;
            }
            drop(self.rtx.pop_first());
            if self.highest_sack == Some(t.seq) {
                // Linux tcp_highest_sack_replace
                self.highest_sack = self.rtx_head();
            }
        }
        if self
            .rtx
            .first()
            .is_some_and(|h| h.tcp().sacked & tag::SACKED_ACKED != 0)
        {
            flg |= flag::SACK_RENEGING;
        }
        st.pkts_acked = pkts_acked;
        // The RTTs: of the oldest and newest never retransmitted data
        // acked (Karn), of the newest SACKed
        let now = self.tcp_mstamp;
        let delta = |t: u64| now.saturating_sub(t) as i64;
        (st.seq_rtt_us, st.ca_rtt_us) = (-1, -1);
        if let Some(first) = first_ackt
            && flg & flag::RETRANS_DATA_ACKED == 0
        {
            st.seq_rtt_us = delta(first);
            st.ca_rtt_us = delta(last_ackt);
            // A lone runt packet over the round trip, nothing SACKed:
            // conservatively a delayed ACK
            if pkts_acked == 1
                && fully_acked
                && prior_sacked == 0
                && self.snd_una.wrapping_sub(prior_snd_una) < self.live.mss.get()
                && st.prior_delivered.map(|p| p.wrapping_add(1)) == Some(self.delivered)
                && flg & (flag::CA_ALERT | flag::SYN_ACKED) == 0
            {
                flg |= flag::ACK_MAYBE_DELAYED;
            }
        }
        let mut sack_rtt_us = -1;
        if let (Some(first), Some(last)) = (st.first_sackt, st.last_sackt) {
            sack_rtt_us = delta(first);
            st.ca_rtt_us = delta(last);
        }
        if st.seq_rtt_us < 0 {
            st.seq_rtt_us = sack_rtt_us;
        }
        if flg & flag::ACKED != 0 {
            flg |= flag::SET_XMIT_TIMER;
            if self.is_reno() {
                self.remove_reno_sacks(pkts_acked);
                // A cumulative ACK cannot tell which copy arrived
                if flg & flag::RETRANS_DATA_ACKED != 0 {
                    flg &= !flag::ORIG_SACK_ACKED;
                }
            } else if before(reord, prior_fack) {
                // A never retransmitted hole filled: reordering
                self.check_sack_reordering(reord, false);
            }
        } else if let Some(first) = st.first_sackt
            && self.rtx.first().is_some_and(|h| first < skb_mstamp_us(h))
        {
            // The SACK round trip is from data sent before the head was
            // last (re)sent: rearm (else the RTO keeps stretching)
            flg |= flag::SET_XMIT_TIMER;
        }
        flg
    }

    /// Linux tcp_skb_spurious_retrans: a retransmitted skb whose echo
    /// predates its (last) transmission at `sent` us
    fn spurious_retrans(&self, sacked: u8, sent: u64) -> bool {
        let ts = ((sent / 1000) as u32).wrapping_add(self.ts_off);
        sacked & tag::RETRANS != 0 && self.rcv_tsecr.is_some_and(|e| e != 0 && before(e, ts))
    }

    /// Segment text and FIN (Linux tcp_data_queue / tcp_fin): `skb`'s
    /// data is the payload of `s`
    fn rcv_text(&mut self, s: &SegIn, mut skb: Box<SkBuff>, now: u64, out: &mut Out) {
        let mut seq = s.seq.wrapping_add(u32::from(s.has(flags::SYN)));
        let mut len = skb.len();
        let mut fin = s.has(flags::FIN);
        if len != 0 || fin {
            // Linux tcp_data_queue: a D-SACK is for this segment only
            self.dsack.on = false;
        }
        if before(seq, self.rcv_nxt) {
            // Old bytes: acknowledge again, keep only what is new
            let skip = self.rcv_nxt.wrapping_sub(seq) as usize;
            if skip > len || (skip == len && !fin) {
                if len != 0 {
                    // Linux tcp_data_queue: a retransmit of what we have
                    self.net_stat(LINUX_MIB_DELAYEDACKLOST);
                    self.enter_quickack();
                }
                let end = seq.wrapping_add(len as u32 + u32::from(fin));
                self.dsack_set(seq, end);
                self.ack_now = true;
                return;
            }
            // Partly old (Linux tcp_data_queue: D-SACK its head)
            self.dsack_set(seq, self.rcv_nxt);
            self.ack_now = true;
            let _ = skb.pull(skip);
            len -= skip;
            seq = self.rcv_nxt;
        }
        let deliver = matches!(
            self.state,
            TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2
        );
        if !deliver {
            // FIN already received: nothing new can arrive
            if len != 0 || fin {
                self.ack_now = true;
            }
            return;
        }
        let edge = self.rcv_nxt.wrapping_add(self.rcv_wnd());
        if len != 0 {
            // Linux tcp_data_queue: in order into a closed window, or
            // starting at or past the window's end
            if seq == self.rcv_nxt && self.rcv_wnd() == 0 {
                self.net_stat(LINUX_MIB_TCPZEROWINDOWDROP);
            } else if !before(seq, edge) {
                self.net_stat(LINUX_MIB_BEYOND_WINDOW);
            }
        }
        let room = if after(edge, seq) {
            edge.wrapping_sub(seq) as usize
        } else {
            0
        };
        if len > room {
            let _ = skb.trim(len - room);
            len = room;
            fin = false;
            self.ack_now = true;
        }
        if len != 0 && self.rcv_shut && self.state != TcpState::Established {
            // Data for a closed reader (Linux: abort on data in FIN_WAIT)
            self.net_stat(LINUX_MIB_TCPABORTONDATA);
            self.abort(out);
            out.err = Some(KernelError::ConnectionReset);
            return;
        }
        if len != 0 && !self.rmem_ok(seq, skb.truesize(), out) {
            // Dropped whole, FIN too; it comes again
            return;
        }
        if len != 0 {
            skb.tcp_mut().seq = seq;
            skb.tcp_mut().end_seq = seq.wrapping_add(len as u32);
            self.queue_data(skb, now, out);
        }
        if fin {
            let fs = seq.wrapping_add(len as u32);
            // In sequence, or remembered beyond a hole
            if !before(fs, self.rcv_nxt) {
                self.ooo_fin = Some(fs);
                self.ack_now = true;
            }
        }
        if self.ooo_fin == Some(self.rcv_nxt) && self.ooo.is_empty() {
            self.ooo_fin = None;
            self.rcv_fin(out);
        }
    }

    /// Memory for an skb of truesize `size` at `seq` (Linux
    /// tcp_data_queue / tcp_data_queue_ofo around
    /// tcp_try_rmem_schedule). Out-of-order data that does not fit is
    /// dropped (TCPOFODrop); in-order data is still taken into an empty
    /// receive queue (sk_forced_mem_schedule, so the reader can always
    /// progress), else dropped (TCPRcvQDrop), with an immediate
    /// zero-window ACK (ICSK_ACK_NOMEM) either way. The reader is woken
    /// when it fails.
    fn rmem_ok(&mut self, seq: u32, size: usize, out: &mut Out) -> bool {
        let in_order = seq == self.rcv_nxt;
        if self.try_rmem_schedule(seq, size) {
            if !in_order {
                self.net_stat(LINUX_MIB_TCPOFOQUEUE);
            }
            return true;
        }
        out.wake |= wake::DATA;
        if !in_order {
            self.net_stat(LINUX_MIB_TCPOFODROP);
            return false;
        }
        self.ack_nomem = true;
        self.ack_now = true;
        if !self.rcvq.is_empty() {
            self.net_stat(LINUX_MIB_TCPRCVQDROP);
            return false;
        }
        self.mem_force(size);
        true
    }

    /// Linux tcp_try_rmem_schedule: past the receive buffer or the
    /// memory limits, prune; still short of memory, drop out-of-order
    /// skbs beyond `seq` until it is granted
    fn try_rmem_schedule(&mut self, seq: u32, size: usize) -> bool {
        if self.rmem_alloc() <= self.rcvbuf as usize && self.mem_schedule(size, MemKind::Recv) {
            return true;
        }
        if !self.prune_queue(seq) {
            return false;
        }
        while !self.mem_schedule(size, MemKind::Recv) {
            if !self.prune_ofo_queue(seq) {
                return false;
            }
        }
        true
    }

    /// Linux tcp_prune_queue: get within the receive buffer again;
    /// false (RcvPruned) when even pruning the out-of-order queue
    /// beyond `seq` leaves it over. Collapsing the queues into fewer
    /// skbs (tcp_collapse_ofo_queue, tcp_collapse) is not done.
    fn prune_queue(&mut self, seq: u32) -> bool {
        self.net_stat(LINUX_MIB_PRUNECALLED);
        let over = |c: &Self| c.rmem_alloc() > c.rcvbuf as usize;
        if self.rmem_alloc() >= self.rcvbuf as usize {
            self.clamp_window();
        } else if mem::under_pressure() {
            self.adjust_rcv_ssthresh();
        }
        if !over(self) {
            return true;
        }
        self.prune_ofo_queue(seq);
        if !over(self) {
            return true;
        }
        self.net_stat(LINUX_MIB_RCVPRUNED);
        false
    }

    /// Linux tcp_prune_ofo_queue: drop out-of-order skbs from the
    /// highest sequence down, stopping at one `seq` would follow, at
    /// least 1/8 of the receive buffer each pass until the socket is
    /// within it and not under memory pressure; true if any went
    fn prune_ofo_queue(&mut self, seq: u32) -> bool {
        if self.ooo.is_empty() {
            return false;
        }
        let goal0 = i64::from(self.rcvbuf >> 3);
        let mut goal = goal0;
        let mut pruned = false;
        while let Some(ts) = self.ooo.prune_after(seq) {
            pruned = true;
            goal -= ts as i64;
            if self.ooo.is_empty() || goal <= 0 {
                if self.rmem_alloc() <= self.rcvbuf as usize && !mem::under_pressure() {
                    break;
                }
                goal = goal0;
            }
        }
        if pruned {
            self.net_stat(LINUX_MIB_OFOPRUNED);
            // The blocks are stale now
            if self.is_sack() {
                self.sack_reset();
            }
        }
        pruned
    }

    /// An accepted skb (its payload at `skb.tcp.seq`): in order to the
    /// receive queue (owing a possibly delayed ACK), the out-of-order
    /// skbs it reached behind it (Linux tcp_ofo_queue), else to the
    /// out-of-order queue (ACK at once; also when a hole is filled, RFC
    /// 5681 4.2). Linked through the skb itself: nothing allocates; the
    /// device reference is dropped (TCP has no further use for it).
    fn queue_data(&mut self, mut skb: Box<SkBuff>, now: u64, out: &mut Out) {
        let len = skb.len();
        let truesize = skb.truesize() as u32;
        self.stats.bytes_received += len as u64;
        skb.dev = None;
        if skb.tcp().seq != self.rcv_nxt {
            let (seq, end) = (skb.tcp().seq, skb.tcp().seq.wrapping_add(len as u32));
            let first = self.ooo.is_empty();
            let d = self.dsack_on().then_some(&mut self.dsack);
            let (ins, sets) = self.ooo.insert(skb, d);
            self.net_add(LINUX_MIB_TCPDSACKOFOSENT, sets);
            if self.is_sack() {
                if first {
                    // Linux tcp_data_queue_ofo: the first one, one block
                    self.selective_acks.n = 1;
                    self.selective_acks.b[0] = (seq, end);
                } else {
                    self.sack_new_ofo_skb(seq, end);
                }
            }
            let m = core::mem::take(&mut self.ooo.merged);
            self.net_add(LINUX_MIB_TCPOFOMERGE, m);
            if ins == Ins::Queued {
                // Linux tcp_data_queue_ofo: an skb kept grows the window
                self.grow_window(len as u32, truesize, true);
            }
            self.ack_now = true;
            self.mem_settle();
            return;
        }
        let had_ooo = !self.ooo.is_empty();
        self.rcv_queue(skb);
        // Linux tcp_ofo_queue: bytes below RCV.NXT as it starts are
        // D-SACKed
        let high = self.rcv_nxt;
        loop {
            let d = self.dsack_on().then_some(&mut self.dsack);
            let (next, sets) = self.ooo.take(self.rcv_nxt, high, d);
            self.net_add(LINUX_MIB_TCPDSACKOLDSENT, sets);
            let Some(next) = next else {
                break;
            };
            self.rcv_queue(next);
        }
        if self.selective_acks.n != 0 {
            self.sack_remove();
        }
        self.data_recv(len as u32, truesize, now);
        if had_ooo {
            self.ack_now = true;
        }
        out.wake |= wake::DATA;
        self.mem_settle();
    }

    /// Append an in-order skb starting at RCV.NXT (Linux tcp_queue_rcv)
    fn rcv_queue(&mut self, skb: Box<SkBuff>) {
        let n = skb.len();
        self.rcv_nxt = self.rcv_nxt.wrapping_add(n as u32);
        self.rcv_bytes += n;
        self.rcvq_truesize += skb.truesize();
        self.rcvq.push_back(skb);
    }

    /// The peer's FIN is in sequence (RFC 9293 eighth check)
    fn rcv_fin(&mut self, out: &mut Out) {
        self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
        // Linux tcp_fin: nothing beyond the FIN is held
        if self.is_sack() {
            self.sack_reset();
        }
        self.ack_now = true;
        out.shut |= RCV_SHUTDOWN;
        out.wake |= wake::STATE | wake::FIN;
        match self.state {
            TcpState::Established => self.set_state(TcpState::CloseWait),
            TcpState::FinWait1 if self.fin_acked() => self.time_wait(out),
            TcpState::FinWait1 => self.set_state(TcpState::Closing),
            TcpState::FinWait2 => self.time_wait(out),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mm::page_alloc::Gfp;

    /// A partially acknowledged skb of two segments is trimmed, then
    /// sampled as trimmed (Linux tcp_clean_rtx_queue: tcp_tso_acked,
    /// then tcp_rate_skb_delivered on the same skb)
    #[test]
    fn partial_ack_rate_sample() {
        let mut cb = TcpCb::new(super::super::cb::Cfg::default(), Default::default());
        let seq = 1000;
        let mut skb = SkBuff::alloc_tx(2000, Gfp::KERNEL).unwrap();
        skb.put_slice(&[0; 2000]).unwrap();
        let t = skb.tcp_mut();
        t.seq = seq;
        t.end_seq = seq + 2000;
        t.set_pcount(2);
        t.set_gso_size(1000);
        t.tx_delivered = 5;
        t.tx_delivered_mstamp = 1;
        skb.tstamp = 1000;
        cb.rtx
            .insert_by(skb, |a, b| before(a.tcp().seq, b.tcp().seq));
        cb.packets_out = 2;
        cb.snd_max = seq + 2000;
        cb.snd_nxt = cb.snd_max;
        cb.snd_una = seq + 1000;
        let mut st = SackState::default();
        cb.clean_rtx_queue(seq, seq, &mut st);
        assert_eq!(cb.rtx_head(), Some(seq + 1000));
        assert_eq!(cb.packets_out, 1);
        assert_eq!(st.prior_delivered, Some(5));
    }
}

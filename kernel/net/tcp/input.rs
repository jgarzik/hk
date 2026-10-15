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
    OOW_RATELIMIT, Out, PAWS_WRAP, RCV_SHUTDOWN, Seg, SegIn, TIMEWAIT_LEN, TcpCb, TcpState, Tmr,
    after, before, between, flags,
};
use crate::error::KernelError;

impl TcpCb {
    /// Process a segment for this connection
    pub fn input(&mut self, s: &SegIn, now: u64, out: &mut Out) {
        self.tick(now);
        self.stats.segs_in += 1;
        if !s.data.is_empty() {
            self.stats.data_segs_in += 1;
        }
        match self.state {
            TcpState::Closed | TcpState::Listen => {}
            TcpState::SynSent => self.rcv_syn_sent(s, now, out),
            _ => self.rcv_synced(s, now, out),
        }
    }

    /// RFC 9293 3.10.7.3 (Linux tcp_rcv_synsent_state_process)
    fn rcv_syn_sent(&mut self, s: &SegIn, now: u64, out: &mut Out) {
        let ack_ok = s.has(flags::ACK);
        if ack_ok
            && (!after(s.ack, self.iss) || after(s.ack, self.snd_max) || !self.synack_ts_ok(s))
        {
            if !s.has(flags::RST) {
                out.segs.push(Seg {
                    seq: s.ack,
                    flags: flags::RST,
                    ..Default::default()
                });
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
            self.state = TcpState::SynReceived;
            let syn = self.syn_seg();
            out.segs.push(syn);
            return;
        }
        self.snd_una = s.ack;
        self.established(s, now, out);
        self.ack_now = true;
        self.rcv_text(s, now, out);
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
        // shutdown(SHUT_WR) in SYN_RECEIVED queued a FIN
        self.state = if self.fin_queued {
            TcpState::FinWait1
        } else {
            TcpState::Established
        };
        self.snd_wnd = self.seg_wnd(s);
        self.max_wnd = self.max_wnd.max(self.snd_wnd);
        self.snd_wl1 = s.seq;
        self.snd_wl2 = s.ack;
        if let Some(r) = self.ts_rtt(s) {
            self.rtt_sample(r);
        } else if let Some((seq, t)) = self.rtt_seq
            && !before(s.ack, seq)
        {
            self.rtt_sample(now.saturating_sub(t));
        } else if self.syn_rtx {
            self.set_rto_fallback();
        }
        self.rtt_seq = None;
        self.backoff = 0;
        self.rtx_stamp = None;
        self.tmr = None;
        self.rcv_tstamp = now;
        self.arm_keepalive(now);
        out.established = true;
        out.wake = true;
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
        let replay = (self.rto * 6 / 5) as i32;
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

    /// RTT from the timestamp echo of a segment acknowledging new data
    /// (RFC 7323 4; valid for retransmitted data too)
    fn ts_rtt(&self, s: &SegIn) -> Option<u64> {
        let (_, e) = s.ts?;
        if !self.ts_ok || e == 0 {
            return None;
        }
        let d = self.tsval().wrapping_sub(e) as i32;
        (d >= 0).then_some(d as u64)
    }

    /// Synchronized states and SYN_RECEIVED
    fn rcv_synced(&mut self, s: &SegIn, now: u64, out: &mut Out) {
        if self.state == TcpState::SynReceived
            && s.has(flags::SYN)
            && !s.has(flags::ACK | flags::RST)
            && s.seq == self.irs
        {
            // Duplicate SYN: the SYN-ACK was lost (Linux tcp_check_req)
            let syn = self.syn_seg();
            out.segs.push(syn);
            return;
        }
        if self.paws_reject(s) {
            if s.has(flags::SYN) {
                self.challenge_ack(out);
            } else if !(s.seq_len() == 0 && before(s.seq, self.rcv_nxt)) && !self.oow_limited(s) {
                self.send_ack(out); // dupack (an old pure ACK is just dropped)
            }
            return;
        }
        if !self.acceptable(s) {
            if s.has(flags::SYN) {
                self.challenge_ack(out);
            } else if !s.has(flags::RST) && !self.oow_limited(s) {
                self.dupack(s, out);
            }
            return;
        }
        if s.has(flags::RST) {
            if s.seq == self.rcv_nxt {
                self.on_reset(out);
            } else {
                self.challenge_ack(out); // RFC 5961 3.2
            }
            return;
        }
        if s.has(flags::SYN) {
            self.challenge_ack(out); // RFC 5961 4.2
            return;
        }
        if !s.has(flags::ACK) {
            return;
        }
        if self.state == TcpState::SynReceived {
            if !after(s.ack, self.snd_una) || after(s.ack, self.snd_max) {
                out.segs.push(Seg {
                    seq: s.ack,
                    flags: flags::RST,
                    ..Default::default()
                });
                return;
            }
            self.update_ts_recent(s);
            self.snd_una = s.ack;
            self.established(s, now, out);
        } else if !self.rcv_ack(s, now, out) {
            return;
        }
        if !self.after_ack(now, out) {
            return;
        }
        self.rcv_text(s, now, out);
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
    /// (they are not part of an ACK loop), pure ones and SYNs are
    fn oow_limited(&mut self, s: &SegIn) -> bool {
        if !s.data.is_empty() && !s.has(flags::SYN) {
            return false;
        }
        self.oow_recent()
    }

    /// RFC 5961 challenge ACK, rate limited per connection (Linux
    /// tcp_send_challenge_ack)
    fn challenge_ack(&mut self, out: &mut Out) {
        if !self.oow_recent() {
            self.send_ack(out);
        }
    }

    /// An unacceptable or old segment: ACK at once (Linux
    /// tcp_send_dupack: duplicated data means our ACK was lost, so stop
    /// delaying ACKs for a while)
    fn dupack(&mut self, s: &SegIn, out: &mut Out) {
        if !s.data.is_empty() && before(s.seq, self.rcv_nxt) {
            self.enter_quickack();
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
                self.state = TcpState::FinWait2;
                self.tmr = None;
                self.arm_fw2(now);
                out.wake = true;
                true
            }
            TcpState::Closing => {
                self.time_wait(now, out);
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
    /// ACK (below SND.UNA) updates neither TS.Recent nor the window.
    fn rcv_ack(&mut self, s: &SegIn, now: u64, out: &mut Out) -> bool {
        let ack = s.ack;
        let span = self
            .max_wnd
            .min(self.stats.bytes_acked.min(u32::MAX as u64) as u32);
        if after(ack, self.snd_max) || before(ack, self.snd_una.wrapping_sub(span)) {
            self.challenge_ack(out);
            return false;
        }
        if before(ack, self.snd_una) {
            return true;
        }
        self.update_ts_recent(s);
        self.probes = 0;
        self.rcv_tstamp = now;
        let old_wnd = self.snd_wnd;
        let wnd = self.seg_wnd(s);
        if after(ack, self.snd_una) {
            self.ack_new(s, now, out);
        } else if ack == self.snd_una
            && s.data.is_empty()
            && !s.has(flags::FIN)
            && wnd == old_wnd
            && self.snd_una != self.snd_max
        {
            let flight = self.snd_max.wrapping_sub(self.snd_una);
            if self.cong.on_dupack(flight, self.snd_max) {
                self.retransmit_head(out);
            }
        }
        // Window update (SND.WL1/WL2 rule)
        if before(self.snd_wl1, s.seq) || (self.snd_wl1 == s.seq && !before(ack, self.snd_wl2)) {
            self.snd_wnd = wnd;
            self.snd_wl1 = s.seq;
            self.snd_wl2 = ack;
            self.max_wnd = self.max_wnd.max(self.snd_wnd);
            if old_wnd == 0 && self.snd_wnd > 0 && self.tmr.is_some_and(|t| t.0 == Tmr::Probe) {
                self.tmr = None;
                self.backoff = 0;
                self.rtx_stamp = None;
                out.wake = true;
            }
        }
        true
    }

    /// `s` acknowledges new data (Linux tcp_clean_rtx_queue)
    fn ack_new(&mut self, s: &SegIn, now: u64, out: &mut Out) {
        let ack = s.ack;
        let acked = ack.wrapping_sub(self.snd_una);
        // Data bytes covered (not the FIN)
        let upto = if after(ack, self.data_end()) {
            self.data_end()
        } else {
            ack
        };
        if after(upto, self.sndq_seq) {
            let n = upto.wrapping_sub(self.sndq_seq) as usize;
            self.sndq.drain(..n.min(self.sndq.len()));
            self.sndq_seq = upto;
            self.charge();
        }
        self.stats.bytes_acked += acked as u64;
        self.snd_una = ack;
        if before(self.snd_nxt, ack) {
            self.snd_nxt = ack;
        }
        let timed = self.rtt_seq.filter(|&(seq, _)| !before(ack, seq));
        if let Some(r) = self.ts_rtt(s) {
            self.rtt_sample(r);
        } else if let Some((_, t)) = timed {
            self.rtt_sample(now.saturating_sub(t));
        }
        if timed.is_some() {
            self.rtt_seq = None;
        }
        self.rtx_stamp = None;
        if self.cong.on_ack(acked, ack) {
            self.retransmit_head(out);
        }
        if self.snd_una == self.snd_max {
            self.tmr = None;
        } else {
            self.arm_rtx(now);
        }
        out.wake = true;
    }

    /// Segment text and FIN (Linux tcp_data_queue / tcp_fin)
    fn rcv_text(&mut self, s: &SegIn, now: u64, out: &mut Out) {
        let mut seq = s.seq.wrapping_add(s.has(flags::SYN) as u32);
        let mut data = s.data;
        let mut fin = s.has(flags::FIN);
        if before(seq, self.rcv_nxt) {
            // Old bytes: acknowledge again, keep only what is new
            let skip = self.rcv_nxt.wrapping_sub(seq) as usize;
            if skip > data.len() || (skip == data.len() && !fin) {
                if !data.is_empty() {
                    self.enter_quickack();
                }
                self.ack_now = true;
                if fin && self.state == TcpState::TimeWait {
                    self.wait_at = Some(now + TIMEWAIT_LEN);
                }
                return;
            }
            self.ack_now = true;
            data = &data[skip..];
            seq = self.rcv_nxt;
        }
        let deliver = matches!(
            self.state,
            TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2
        );
        if !deliver {
            // FIN already received: nothing new can arrive
            if !data.is_empty() || fin {
                self.ack_now = true;
            }
            return;
        }
        let edge = self.rcv_nxt.wrapping_add(self.rcv_wnd());
        let room = if after(edge, seq) {
            edge.wrapping_sub(seq) as usize
        } else {
            0
        };
        let room = if seq == self.rcv_nxt {
            room.min(self.hard_room())
        } else {
            room
        };
        if data.len() > room {
            data = &data[..room];
            fin = false;
            self.ack_now = true;
        }
        if !data.is_empty() && self.rcv_shut && self.state != TcpState::Established {
            // Data for a closed reader (Linux: abort on data in FIN_WAIT)
            self.abort(out);
            out.err = Some(KernelError::ConnectionReset);
            return;
        }
        if !data.is_empty() {
            self.queue_data(seq, data, now, out);
        }
        if fin {
            let fs = seq.wrapping_add(data.len() as u32);
            // In sequence, or remembered beyond a hole
            if !before(fs, self.rcv_nxt) {
                self.ooo_fin = Some(fs);
                self.ack_now = true;
            }
        }
        if self.ooo_fin == Some(self.rcv_nxt) && self.ooo.is_empty() {
            self.ooo_fin = None;
            self.rcv_fin(now, out);
        }
    }

    /// In-order bytes the receive queue may still take: twice the
    /// window space, i.e. SO_RCVBUF (the window is half of it, as in
    /// Linux). A scaled window rounds up to its unit and never shrinks
    /// (Linux tcp_select_window), so a peer trickling bytes can creep
    /// the right edge past the window space; Linux bounds that with its
    /// memory accounting (tcp_try_rmem_schedule drops), hk with this.
    fn hard_room(&self) -> usize {
        let hard = 2 * self.full_space() as usize;
        hard.saturating_sub(self.rcvq.len())
    }

    /// Accepted bytes at `seq`: in order to the receive queue (owing a
    /// possibly delayed ACK), else held out of order (ACK at once; also
    /// when a hole is filled, RFC 5681 4.2)
    fn queue_data(&mut self, seq: u32, data: &[u8], now: u64, out: &mut Out) {
        self.stats.bytes_received += data.len() as u64;
        if seq != self.rcv_nxt {
            self.ooo.insert(self.rcv_nxt, seq, data);
            self.ack_now = true;
            self.charge();
            return;
        }
        let had_ooo = !self.ooo.is_empty();
        self.rcvq.extend(data);
        self.rcv_nxt = self.rcv_nxt.wrapping_add(data.len() as u32);
        while let Some(d) = self.ooo.take(self.rcv_nxt) {
            self.rcv_nxt = self.rcv_nxt.wrapping_add(d.len() as u32);
            self.rcvq.extend(&d);
        }
        self.data_recv(data.len() as u32, now);
        if had_ooo {
            self.ack_now = true;
        }
        out.wake = true;
        self.charge();
    }

    /// The peer's FIN is in sequence (RFC 9293 eighth check)
    fn rcv_fin(&mut self, now: u64, out: &mut Out) {
        self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
        self.ack_now = true;
        out.shut |= RCV_SHUTDOWN;
        out.wake = true;
        match self.state {
            TcpState::Established => self.state = TcpState::CloseWait,
            TcpState::FinWait1 if self.fin_acked() => self.time_wait(now, out),
            TcpState::FinWait1 => self.state = TcpState::Closing,
            TcpState::FinWait2 => self.time_wait(now, out),
            _ => {}
        }
    }
}

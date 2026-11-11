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
    MemKind, OOO_OVERHEAD, OOW_RATELIMIT, Out, PAWS_WRAP, RCV_SHUTDOWN, Seg, SegIn, TIMEWAIT_LEN,
    TcpCb, TcpState, Tmr, after, before, between, flags, wake,
};
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
            if !s.has(flags::RST) {
                out.ctl(Seg {
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
            self.syn_seg(out);
            return;
        }
        self.snd_una = s.ack;
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
            }
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
            if req {
                // A new SYN in window: reset, drop the request (Linux
                // tcp_check_req embryonic_reset)
                if let Some(r) = super::output::reset_for(s) {
                    out.ctl(r);
                }
                self.set_closed(out);
            } else {
                self.challenge_ack(out); // RFC 5961 4.2
            }
            return;
        }
        if !s.has(flags::ACK) {
            return;
        }
        if self.state == TcpState::SynReceived {
            if !after(s.ack, self.snd_una) || after(s.ack, self.snd_max) {
                out.ctl(Seg {
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
    /// (they are not part of an ACK loop), pure ones and SYNs are
    fn oow_limited(&mut self, s: &SegIn) -> bool {
        if s.data_len() != 0 && !s.has(flags::SYN) {
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
        if s.data_len() != 0 && before(s.seq, self.rcv_nxt) {
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
                out.wake |= wake::STATE;
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
            .min(self.stats.bytes_acked.min(u64::from(u32::MAX)) as u32);
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
            && s.data_len() == 0
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
                out.wake |= wake::SPACE;
            }
        }
        true
    }

    /// `s` acknowledges new data (Linux tcp_clean_rtx_queue)
    fn ack_new(&mut self, s: &SegIn, now: u64, out: &mut Out) {
        let ack = s.ack;
        let acked = ack.wrapping_sub(self.snd_una);
        // Data bytes covered (not the FIN)
        self.clean_rtx(ack);
        self.stats.bytes_acked += u64::from(acked);
        self.snd_una = ack;
        self.mem_settle();
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
        out.wake |= wake::SPACE;
    }

    /// The retransmit queue after an ACK of `ack` (Linux
    /// tcp_clean_rtx_queue): skbs wholly acknowledged go, a partly
    /// acknowledged head loses its acknowledged bytes (tcp_trim_head)
    fn clean_rtx(&mut self, ack: u32) {
        while self.rtx.first().is_some_and(|f| !after(f.tcp.end_seq, ack)) {
            drop(self.rtx.pop_first());
        }
        let mut c = self.rtx.cursor_front_mut();
        let _ = c.with_current_mut(|h| {
            if before(h.tcp.seq, ack) {
                let n = (ack.wrapping_sub(h.tcp.seq) as usize).min(h.len());
                let _ = h.pull(n);
                h.tcp.seq = ack;
            }
        });
    }

    /// Segment text and FIN (Linux tcp_data_queue / tcp_fin): `skb`'s
    /// data is the payload of `s`
    fn rcv_text(&mut self, s: &SegIn, mut skb: Box<SkBuff>, now: u64, out: &mut Out) {
        let mut seq = s.seq.wrapping_add(u32::from(s.has(flags::SYN)));
        let mut len = skb.len();
        let mut fin = s.has(flags::FIN);
        if before(seq, self.rcv_nxt) {
            // Old bytes: acknowledge again, keep only what is new
            let skip = self.rcv_nxt.wrapping_sub(seq) as usize;
            if skip > len || (skip == len && !fin) {
                if len != 0 {
                    self.enter_quickack();
                }
                self.ack_now = true;
                if fin && self.state == TcpState::TimeWait {
                    self.wait_at = Some(now + TIMEWAIT_LEN);
                }
                return;
            }
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
        if len > room {
            let _ = skb.trim(len - room);
            len = room;
            fin = false;
            self.ack_now = true;
        }
        if len != 0 && self.rcv_shut && self.state != TcpState::Established {
            // Data for a closed reader (Linux: abort on data in FIN_WAIT)
            self.abort(out);
            out.err = Some(KernelError::ConnectionReset);
            return;
        }
        if len != 0 && !self.rmem_ok(seq, len, out) {
            // Dropped whole, FIN too; it comes again
            return;
        }
        if len != 0 {
            skb.tcp.seq = seq;
            skb.tcp.end_seq = seq.wrapping_add(len as u32);
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
        hard.saturating_sub(self.rcv_bytes)
    }

    /// Memory for `len` bytes at `seq` (Linux tcp_try_rmem_schedule in
    /// tcp_data_queue / tcp_data_queue_ofo): out-of-order skbs beyond
    /// `seq` are pruned to make room. Failing that, out-of-order data is
    /// dropped; in-order data is still taken into an empty receive queue
    /// (sk_forced_mem_schedule, so the reader can always progress), else
    /// dropped with an immediate zero-window ACK (ICSK_ACK_NOMEM). The
    /// reader is woken either way.
    fn rmem_ok(&mut self, seq: u32, len: usize, out: &mut Out) -> bool {
        let in_order = seq == self.rcv_nxt;
        let size = if in_order { len } else { len + OOO_OVERHEAD };
        loop {
            if self.mem_schedule(size, MemKind::Recv) {
                return true;
            }
            if !self.ooo.prune_after(seq) {
                break;
            }
        }
        self.mem_settle();
        out.wake |= wake::DATA;
        if !in_order {
            return false;
        }
        self.ack_nomem = true;
        self.ack_now = true;
        self.rcv_bytes == 0
    }

    /// An accepted skb (its payload at `skb.tcp.seq`): in order to the
    /// receive queue (owing a possibly delayed ACK), the out-of-order
    /// skbs it reached behind it (Linux tcp_ofo_queue), else to the
    /// out-of-order queue (ACK at once; also when a hole is filled, RFC
    /// 5681 4.2). Linked through the skb itself: nothing allocates; the
    /// device reference is dropped (TCP has no further use for it).
    fn queue_data(&mut self, mut skb: Box<SkBuff>, now: u64, out: &mut Out) {
        let len = skb.len();
        self.stats.bytes_received += len as u64;
        skb.dev = None;
        if skb.tcp.seq != self.rcv_nxt {
            self.ooo.insert(skb);
            self.ack_now = true;
            self.mem_settle();
            return;
        }
        let had_ooo = !self.ooo.is_empty();
        self.rcv_queue(skb);
        while let Some(d) = self.ooo.take(self.rcv_nxt) {
            self.rcv_queue(d);
        }
        self.data_recv(len as u32, now);
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
        self.rcvq.push_back(skb);
    }

    /// The peer's FIN is in sequence (RFC 9293 eighth check)
    fn rcv_fin(&mut self, now: u64, out: &mut Out) {
        self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
        self.ack_now = true;
        out.shut |= RCV_SHUTDOWN;
        out.wake |= wake::STATE | wake::FIN;
        match self.state {
            TcpState::Established => self.state = TcpState::CloseWait,
            TcpState::FinWait1 if self.fin_acked() => self.time_wait(now, out),
            TcpState::FinWait1 => self.state = TcpState::Closing,
            TcpState::FinWait2 => self.time_wait(now, out),
            _ => {}
        }
    }
}

//! Segment arrival (RFC 9293 3.10.7, RFC 5961; Linux tcp_input.c
//! tcp_rcv_state_process / tcp_validate_incoming / tcp_ack /
//! tcp_data_queue / tcp_fin), I/O-free
//!
//! Order for synchronized states: sequence acceptability (Linux
//! tcp_sequence: a segment may start at the right window edge, so a
//! zero window still lets ACKs, RSTs and window probes in), RST
//! (exactly RCV.NXT resets, else challenge ACK), SYN (challenge ACK,
//! or SYN-ACK retransmission for a duplicate SYN in SYN_RECEIVED), ACK
//! (RFC 5961 range check, send queue, RTT, congestion, window update),
//! text (in order to the receive queue, else the out-of-order map; never
//! beyond the advertised window), FIN.

use super::cb::{
    Out, RCV_SHUTDOWN, Seg, SegIn, TIMEWAIT_LEN, TcpCb, TcpState, Tmr, after, before, flags,
};
use crate::error::KernelError;

impl TcpCb {
    /// Process a segment for this connection
    pub fn input(&mut self, s: &SegIn, now: u64, out: &mut Out) {
        match self.state {
            TcpState::Closed | TcpState::Listen => {}
            TcpState::SynSent => self.rcv_syn_sent(s, now, out),
            _ => self.rcv_synced(s, now, out),
        }
    }

    /// RFC 9293 3.10.7.3 (Linux tcp_rcv_synsent_state_process)
    fn rcv_syn_sent(&mut self, s: &SegIn, now: u64, out: &mut Out) {
        let ack_ok = s.has(flags::ACK);
        if ack_ok && (!after(s.ack, self.iss) || after(s.ack, self.snd_max)) {
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
        self.syn_rcvd(s);
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

    /// The handshake completed with `s`
    fn established(&mut self, s: &SegIn, now: u64, out: &mut Out) {
        // shutdown(SHUT_WR) in SYN_RECEIVED queued a FIN
        self.state = if self.fin_queued {
            TcpState::FinWait1
        } else {
            TcpState::Established
        };
        self.snd_wnd = s.wnd as u32;
        self.max_wnd = self.max_wnd.max(self.snd_wnd);
        self.snd_wl1 = s.seq;
        self.snd_wl2 = s.ack;
        if let Some((seq, t)) = self.rtt_seq
            && !before(s.ack, seq)
        {
            self.rtt_sample(now.saturating_sub(t));
        } else if self.syn_rtx {
            self.set_rto_fallback();
        }
        self.rtt_seq = None;
        self.backoff = 0;
        self.tmr = None;
        out.established = true;
        out.wake = true;
    }

    /// Linux tcp_sequence: the segment overlaps [RCV.NXT, RCV.NXT+WND]
    fn acceptable(&self, s: &SegIn) -> bool {
        let end = s.seq.wrapping_add(s.seq_len());
        !before(end, self.rcv_nxt) && !after(s.seq, self.rcv_nxt.wrapping_add(self.rcv_wnd()))
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
        if !self.acceptable(s) {
            if !s.has(flags::RST) {
                self.send_ack(out);
            }
            return;
        }
        if s.has(flags::RST) {
            if s.seq == self.rcv_nxt {
                self.on_reset(out);
            } else {
                self.send_ack(out); // RFC 5961 3.2 challenge ACK
            }
            return;
        }
        if s.has(flags::SYN) {
            self.send_ack(out); // RFC 5961 4.2 challenge ACK
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

    /// The ACK field (RFC 9293 3.10.7.4 fifth check, RFC 5961 5.2);
    /// false if the segment must be dropped
    fn rcv_ack(&mut self, s: &SegIn, now: u64, out: &mut Out) -> bool {
        let ack = s.ack;
        if after(ack, self.snd_max) || before(ack, self.snd_una.wrapping_sub(self.max_wnd)) {
            self.send_ack(out);
            return false;
        }
        self.probes = 0;
        let old_wnd = self.snd_wnd;
        if after(ack, self.snd_una) {
            self.ack_new(ack, now, out);
        } else if ack == self.snd_una
            && s.data.is_empty()
            && !s.has(flags::FIN)
            && s.wnd as u32 == old_wnd
            && self.snd_una != self.snd_max
        {
            let flight = self.snd_max.wrapping_sub(self.snd_una);
            if self.cong.on_dupack(flight, self.snd_max) {
                self.retransmit_head(out);
            }
        }
        // Window update (SND.WL1/WL2 rule)
        if before(self.snd_wl1, s.seq) || (self.snd_wl1 == s.seq && !before(ack, self.snd_wl2)) {
            self.snd_wnd = s.wnd as u32;
            self.snd_wl1 = s.seq;
            self.snd_wl2 = ack;
            self.max_wnd = self.max_wnd.max(self.snd_wnd);
            if old_wnd == 0 && self.snd_wnd > 0 && self.tmr.is_some_and(|t| t.0 == Tmr::Probe) {
                self.tmr = None;
                self.backoff = 0;
                out.wake = true;
            }
        }
        true
    }

    /// `ack` acknowledges new data (Linux tcp_clean_rtx_queue)
    fn ack_new(&mut self, ack: u32, now: u64, out: &mut Out) {
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
        self.snd_una = ack;
        if before(self.snd_nxt, ack) {
            self.snd_nxt = ack;
        }
        if let Some((seq, t)) = self.rtt_seq
            && !before(ack, seq)
        {
            self.rtt_sample(now.saturating_sub(t));
            self.rtt_seq = None;
        }
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
            self.ack_now = true;
            if skip > data.len() {
                if fin && self.state == TcpState::TimeWait {
                    self.wait_at = Some(now + TIMEWAIT_LEN);
                }
                return;
            }
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
            self.ack_now = true;
            if seq == self.rcv_nxt {
                self.rcvq.extend(data);
                self.rcv_nxt = self.rcv_nxt.wrapping_add(data.len() as u32);
                while let Some(d) = self.ooo.take(self.rcv_nxt) {
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(d.len() as u32);
                    self.rcvq.extend(&d);
                }
                out.wake = true;
            } else {
                self.ooo.insert(self.rcv_nxt, seq, data);
            }
            self.charge();
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

//! Segment output: what the control block sends (Linux tcp_output.c,
//! I/O-free) and the wire format (header, options, checksum).
//!
//! Data goes out skb by skb (Linux tcp_write_xmit): the write queue's
//! head, cut at the MSS or the window (tcp_fragment), is cloned for
//! transmission and moves to the retransmit queue; a retransmission
//! (after a timeout rewound SND.NXT, or a fast retransmit of the head,
//! which first merges small skbs behind it, tcp_retrans_try_collapse)
//! sends the queued skb at SND.NXT again. Transmitted clones and
//! header-only segments are allocated GFP_ATOMIC (Linux
//! __tcp_push_pending_frames, tcp_send_ack, tcp_retransmit_skb); a
//! failed allocation sends nothing now and the retransmit or probe
//! timer tries again.
//!
//! Partial segments follow Linux: Nagle with Minshall's variant (hold a
//! partial segment only while an earlier partial one is unacknowledged)
//! unless TCP_NODELAY; TCP_CORK and MSG_MORE hold every partial segment
//! until uncorked, a full segment forms, or the 200 ms (RTO-based) probe
//! timer pushes it out (Linux tcp_write_wakeup). A FIN is never held.

use alloc::boxed::Box;

use super::ack::DELACK_MAX;
use super::cb::{Out, RTO_MIN, Seg, SegIn, TcpCb, TcpState, Tmr, after, before, flags};
use crate::mm::page_alloc::Gfp;
use crate::net::ipv4::{self, IPPROTO_TCP, Ipv4Addr};
use crate::net::skb::SkBuff;

/// TCP header without options
pub const HLEN: usize = 20;
/// TCP header with every option it may carry
const HLEN_MAX: usize = 60;
/// TCP option kinds
const OPT_EOL: u8 = 0;
const OPT_NOP: u8 = 1;
const OPT_MSS: u8 = 2;
const OPT_WS: u8 = 3;
const OPT_TS: u8 = 8;

/// How partial segments are pushed (Linux nonagle modes)
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Push {
    /// Nagle / TCP_NODELAY / TCP_CORK as set
    Normal,
    /// MSG_MORE: hold partial segments for this call
    More,
    /// Probe timer: one segment regardless (Linux tcp_write_wakeup)
    Force,
}

/// A copy of `skb`'s payload with headroom for the headers (Linux
/// skb_clone in tcp_transmit_skb: hk's skbs do not share data)
fn clone_data(skb: &SkBuff, gfp: Gfp) -> Option<Box<SkBuff>> {
    let mut c = SkBuff::alloc_tx(skb.len(), gfp)?;
    c.put_slice(skb.data())?;
    Some(c)
}

/// Cut `skb` after `at` payload bytes (Linux tcp_fragment): the rest
/// moves to a new skb, which takes the FIN and PSH flags; None without
/// memory (`skb` unchanged)
fn fragment(skb: &mut SkBuff, at: usize, gfp: Gfp) -> Option<Box<SkBuff>> {
    let rest = skb.len().checked_sub(at)?;
    let mut n = SkBuff::alloc_tx(rest, gfp)?;
    n.put_slice(&skb.data()[at..])?;
    skb.trim(rest)?;
    n.tcp = skb.tcp;
    n.tcp.seq = skb.tcp.seq.wrapping_add(at as u32);
    skb.tcp.end_seq = n.tcp.seq;
    skb.tcp.flags &= !(flags::FIN | flags::PSH);
    Some(n)
}

impl TcpCb {
    /// Queue a SYN (SYN_SENT) or SYN-ACK (SYN_RECEIVED) with our options
    pub(super) fn syn_seg(&mut self, out: &mut Out) {
        let synack = self.state == TcpState::SynReceived;
        let ts = if !self.ts_ok {
            None
        } else if synack {
            Some((self.tsval(), self.ts_recent))
        } else {
            Some((self.tsval(), 0))
        };
        let h = Seg {
            seq: self.iss,
            ack: if synack { self.rcv_nxt } else { 0 },
            flags: flags::SYN | if synack { flags::ACK } else { 0 },
            wnd: self.syn_window(),
            mss: Some(self.adv_mss.min(u32::from(u16::MAX)) as u16),
            ws: self.wscale_ok.then_some(self.rcv_wscale),
            ts,
            ..Default::default()
        };
        out.ctl(h);
    }

    /// The header of a segment of this connection at `seq` with flags
    /// `fl` and `len` payload bytes: ACK field, window, timestamp; an
    /// ACK going out settles what was owed
    fn hdr(&mut self, seq: u32, fl: u8, len: u32) -> Seg {
        let wnd = if fl & flags::ACK != 0 {
            self.select_window()
        } else {
            0
        };
        let ts = self.ts_ok.then(|| (self.tsval(), self.ts_recent));
        if fl & flags::ACK != 0 {
            self.ack_sent();
        }
        self.stats.segs_out = self.stats.segs_out.wrapping_add(1);
        if len != 0 {
            self.stats.data_segs_out = self.stats.data_segs_out.wrapping_add(1);
        }
        let mut h = Seg {
            seq,
            ack: if fl & flags::ACK != 0 {
                self.rcv_nxt
            } else {
                0
            },
            flags: fl,
            wnd,
            ts,
            ..Default::default()
        };
        h.set_len(len);
        h
    }

    /// Send `skb`'s payload (a queued skb) at `seq` with flags `fl`
    /// (Linux tcp_transmit_skb on a clone); false without memory
    fn transmit(&mut self, skb: &SkBuff, seq: u32, fl: u8, out: &mut Out) -> bool {
        let Some(mut c) = clone_data(skb, out.gfp) else {
            return false;
        };
        c.tcp = self.hdr(seq, fl, skb.len() as u32);
        out.segs.push_back(c);
        true
    }

    /// A header-only segment at `seq` with flags `fl` (Linux
    /// tcp_send_ack, tcp_xmit_probe_skb). Without memory an owed ACK
    /// waits for the delayed ACK timer (Linux __tcp_send_ack:
    /// inet_csk_schedule_ack + TCP_DELACK_MAX)
    fn send_ctl(&mut self, seq: u32, fl: u8, out: &mut Out) {
        let Some(mut skb) = SkBuff::alloc_tx(0, out.gfp) else {
            self.dack.pending = true;
            self.dack.at = Some(self.clock + DELACK_MAX);
            return;
        };
        skb.tcp = self.hdr(seq, fl, 0);
        out.segs.push_back(skb);
    }

    /// Our FIN was sent and acknowledged
    pub(super) fn fin_acked(&self) -> bool {
        self.fin_queued && self.snd_una == self.write_seq.wrapping_add(1)
    }

    /// States that may send data or FIN
    pub(super) fn may_send(&self) -> bool {
        matches!(
            self.state,
            TcpState::Established
                | TcpState::CloseWait
                | TcpState::FinWait1
                | TcpState::Closing
                | TcpState::LastAck
        )
    }

    /// Send what the peer's window and the congestion window allow,
    /// from `snd_nxt` on (new data, or queued segments again after a
    /// timeout rewound it), ending with the FIN once all data went out;
    /// else an owed ACK (Linux tcp_write_xmit + tcp_send_ack / delayed
    /// ACK)
    pub fn output(&mut self, now: u64, out: &mut Out) {
        self.xmit(now, Push::Normal, out);
    }

    /// `output` for a send with MSG_MORE
    pub fn output_more(&mut self, now: u64, out: &mut Out) {
        self.xmit(now, Push::More, out);
    }

    pub(super) fn xmit(&mut self, now: u64, push: Push, out: &mut Out) {
        self.tick(now);
        let mut sent = false;
        let mut limited = false;
        while self.may_send() {
            let Some(fin) = self.next_seg(now, push, &mut limited, out) else {
                break;
            };
            sent = true;
            if fin || push == Push::Force {
                break;
            }
        }
        if sent {
            if self.tmr.is_none_or(|t| t.0 != Tmr::Rtx) {
                self.arm_rtx(now);
            }
            let flight = self.snd_max.wrapping_sub(self.snd_una);
            self.cong
                .on_sent(flight, self.snd_una, self.snd_nxt, limited);
        } else if self.state.synced() {
            self.ack_snd_check(now, out);
        }
        self.check_persist(now);
    }

    /// Room in the window from `snd_nxt`, and whether cwnd is the
    /// smaller window
    fn room(&self) -> (u32, bool) {
        let wnd = self.snd_wnd.min(self.cong.cwnd);
        let end = self.snd_una.wrapping_add(wnd);
        let room = if after(end, self.snd_nxt) {
            end.wrapping_sub(self.snd_nxt)
        } else {
            0
        };
        (room, self.cong.cwnd < self.snd_wnd)
    }

    /// Hold a partial segment (Linux tcp_nagle_check with Minshall's
    /// rule; cork and MSG_MORE hold all partial segments)
    fn nagle_hold(&self, push: Push) -> bool {
        if push == Push::Force {
            return false;
        }
        if self.opts.cork || push == Push::More {
            return true;
        }
        !self.opts.nodelay
            && self.snd_nxt != self.snd_una
            && after(self.snd_sml, self.snd_una)
            && !after(self.snd_sml, self.snd_nxt)
    }

    /// The payload length of the queued skb at `snd_nxt`: one of the
    /// retransmit queue after a rewind, else the write queue's head
    fn len_at_nxt(&self) -> u32 {
        if before(self.snd_nxt, self.snd_max) {
            self.rtx
                .iter()
                .find(|s| s.tcp.seq == self.snd_nxt)
                .map_or(0, |s| s.len() as u32)
        } else {
            self.wq.front().map_or(0, |s| s.len() as u32)
        }
    }

    /// Send the next segment `output` may send, if any: Some(it carried
    /// the FIN)
    fn next_seg(
        &mut self,
        now: u64,
        push: Push,
        limited: &mut bool,
        out: &mut Out,
    ) -> Option<bool> {
        if after(self.snd_nxt, self.write_seq) {
            return None; // FIN already sent
        }
        let avail = self.write_seq.wrapping_sub(self.snd_nxt);
        let (room, cwnd_bound) = self.room();
        let n = self.len_at_nxt().min(self.mss).min(room);
        let rexmit = before(self.snd_nxt, self.snd_max);
        let fin = self.fin_queued && self.snd_nxt.wrapping_add(n) == self.write_seq && room > n;
        if n == 0 && !fin {
            *limited |= avail > 0 && cwnd_bound;
            return None;
        }
        let in_flight = self.snd_nxt != self.snd_una;
        // Retransmissions are never held (Linux tcp_retransmit_skb
        // ignores Nagle and cork)
        if n < self.mss && !fin && push != Push::Force && !rexmit {
            // Sender SWS avoidance (RFC 9293 3.8.6.2.1): with data in
            // flight, wait for a full segment unless this ends the queue
            if n < avail && in_flight && n < self.max_wnd / 2 {
                *limited |= cwnd_bound;
                return None;
            }
            if n == avail && self.nagle_hold(push) {
                return None;
            }
        }
        let seq = self.snd_nxt;
        let mut fl = flags::ACK;
        if n > 0 && seq.wrapping_add(n) == self.write_seq {
            fl |= flags::PSH;
        }
        if fin {
            fl |= flags::FIN;
        }
        let sent = if rexmit {
            self.send_rtx_at(seq, n, fl, out)
        } else {
            self.send_new(n, fl, out)
        };
        if !sent {
            return None;
        }
        if self.snd_nxt == self.snd_max
            && !in_flight
            && now.saturating_sub(self.lsndtime) > self.rto
        {
            // Idle longer than an RTO: restart from the initial window
            self.cong.restart(now - self.lsndtime, self.rto);
        }
        let next = seq.wrapping_add(n + u32::from(fin));
        let new = after(next, self.snd_max);
        if self.snd_nxt == self.snd_max && self.rtt_seq.is_none() {
            self.rtt_seq = Some((next, now));
        }
        if n < self.mss {
            self.snd_sml = next;
        }
        if new && n > 0 {
            self.data_sent(now);
            self.lsndtime = now;
        }
        if before(seq, self.snd_max) {
            self.stats.total_retrans = self.stats.total_retrans.wrapping_add(1);
            self.stats.bytes_retrans += u64::from(n);
        }
        self.stats.bytes_sent += u64::from(n);
        self.snd_nxt = next;
        if new {
            self.snd_max = next;
        }
        Some(fin)
    }

    /// Send `n` bytes from the write queue's head (cut there if longer,
    /// Linux tcp_fragment) and move them to the retransmit queue; a FIN
    /// in `fl` rides on them, or on an skb of its own once the data is
    /// gone (Linux tcp_send_fin). False without memory.
    fn send_new(&mut self, n: u32, fl: u8, out: &mut Out) -> bool {
        let mut skb = match self.wq.pop_front() {
            Some(s) => s,
            None => {
                let Some(mut s) = SkBuff::alloc_tx(0, out.gfp) else {
                    return false;
                };
                s.tcp.seq = self.write_seq;
                s.tcp.end_seq = self.write_seq;
                s
            }
        };
        if skb.len() > n as usize {
            let Some(rest) = fragment(&mut skb, n as usize, out.gfp) else {
                self.wq.push_front(skb);
                return false;
            };
            self.wq.push_front(rest);
        }
        if !self.transmit(&skb, skb.tcp.seq, fl, out) {
            self.requeue(skb);
            return false;
        }
        skb.tcp.flags |= fl;
        if fl & flags::FIN != 0 {
            skb.tcp.end_seq = skb.tcp.end_seq.wrapping_add(1);
        }
        self.rtx.insert_by(skb, |a, b| before(a.tcp.seq, b.tcp.seq));
        true
    }

    /// Put an skb back at the head of the write queue (an empty FIN skb
    /// is just dropped)
    fn requeue(&mut self, skb: Box<SkBuff>) {
        if !skb.is_empty() {
            self.wq.push_front(skb);
        }
    }

    /// Send the queued skb at `seq` again, cut to `n` bytes first if
    /// longer (Linux __tcp_retransmit_skb with tcp_fragment); false
    /// without memory
    fn send_rtx_at(&mut self, seq: u32, n: u32, fl: u8, out: &mut Out) -> bool {
        let gfp = out.gfp;
        let mut c = self.rtx.cursor_floor_mut(|s| !after(s.tcp.seq, seq));
        let cut = c.with_current_mut(|s| {
            if s.len() > n as usize {
                fragment(s, n as usize, gfp).map(Some)
            } else {
                Some(None)
            }
        });
        match cut {
            Some(Some(rest)) => {
                if let Some(r) = rest {
                    self.rtx.insert_by(r, |a, b| before(a.tcp.seq, b.tcp.seq));
                }
            }
            _ => return false,
        }
        let Some(clone) = self
            .rtx
            .iter()
            .find(|s| s.tcp.seq == seq)
            .and_then(|s| clone_data(s, gfp))
        else {
            return false;
        };
        self.send_clone(clone, seq, fl, out);
        true
    }

    /// Send `c`, a copy of a queued skb's payload, at `seq` with `fl`
    fn send_clone(&mut self, mut c: Box<SkBuff>, seq: u32, fl: u8, out: &mut Out) {
        c.tcp = self.hdr(seq, fl, c.len() as u32);
        out.segs.push_back(c);
    }

    /// A pure ACK of everything received (also the RFC 5961 challenge ACK)
    pub(super) fn send_ack(&mut self, out: &mut Out) {
        self.send_ctl(self.snd_nxt, flags::ACK, out);
    }

    /// Resend the oldest unacknowledged segment (fast retransmit, NewReno
    /// partial ACK; Linux tcp_retransmit_skb): the retransmit queue's
    /// head, cut to the MSS, or merged with the small skbs behind it up
    /// to the MSS (tcp_retrans_try_collapse); never an RTT sample (Karn)
    pub(super) fn retransmit_head(&mut self, out: &mut Out) {
        self.rtt_seq = None;
        if matches!(self.state, TcpState::SynSent | TcpState::SynReceived) {
            self.syn_seg(out);
            return;
        }
        let Some(head) = self.rtx.first() else {
            return;
        };
        let (seq, len) = (head.tcp.seq, head.len());
        let mss = self.mss as usize;
        if len > mss {
            if !self.send_rtx_at(seq, self.mss, flags::ACK, out) {
                return;
            }
        } else {
            self.collapse_head();
            let Some(head) = self.rtx.first() else {
                return;
            };
            let mut fl = flags::ACK;
            if head.tcp.has(flags::FIN) {
                fl |= flags::FIN;
            }
            if head.is_empty() && fl & flags::FIN == 0 {
                return;
            }
            let Some(clone) = clone_data(head, out.gfp) else {
                return;
            };
            self.send_clone(clone, seq, fl, out);
        }
        let n = len.min(mss);
        self.stats.total_retrans = self.stats.total_retrans.wrapping_add(1);
        self.stats.bytes_retrans += n as u64;
    }

    /// Merge the skbs after the retransmit queue's head into it while
    /// they fit its room and the MSS and were sent up to SND.NXT (Linux
    /// tcp_retrans_try_collapse / tcp_collapse_retrans: the next skb's
    /// data and FIN move into it)
    fn collapse_head(&mut self) {
        let mss = self.mss as usize;
        loop {
            let mut c = self.rtx.cursor_front_mut();
            let (Some(h), Some(n)) = (c.current(), c.peek_next()) else {
                return;
            };
            if h.tcp.has(flags::FIN)
                || h.len() + n.len() > mss
                || n.len() > h.tailroom()
                || h.tcp.end_seq != n.tcp.seq
                || after(n.tcp.end_seq, self.snd_nxt)
            {
                return;
            }
            c.move_next();
            let Some(next) = c.remove_current() else {
                return;
            };
            let mut c = self.rtx.cursor_front_mut();
            let _ = c.with_current_mut(|h| {
                let _ = h.put_slice(next.data());
                h.tcp.end_seq = next.tcp.end_seq;
                h.tcp.flags |= next.tcp.flags & (flags::FIN | flags::PSH);
            });
        }
    }

    /// Zero-window or keepalive probe: an old sequence number that the
    /// peer answers with an ACK carrying its window (Linux
    /// tcp_xmit_probe_skb)
    pub(super) fn send_probe(&mut self, out: &mut Out) {
        self.send_ctl(self.snd_una.wrapping_sub(1), flags::ACK, out);
    }

    /// Something to send and nothing in flight, yet nothing went out
    /// (zero window, a partial segment held by cork/Nagle, or no
    /// memory): arm the probe timer (Linux tcp_check_probe_timer)
    pub(super) fn check_persist(&mut self, now: u64) {
        let pending = self.snd_nxt != self.write_seq.wrapping_add(u32::from(self.fin_queued));
        if self.may_send() && pending && self.snd_una == self.snd_max && self.tmr.is_none() {
            let t = self.rto_cur().max(RTO_MIN);
            self.tmr = Some((Tmr::Probe, now + t));
        }
    }
}

/// RST answering segment `s` that has no connection (RFC 9293 3.10.7.1,
/// Linux tcp_v4_send_reset): seq = its ACK if any, else ACK its end
pub fn reset_for(s: &SegIn) -> Option<Seg> {
    if s.has(flags::RST) {
        return None;
    }
    let mut r = if s.has(flags::ACK) {
        Seg {
            seq: s.ack,
            flags: flags::RST,
            ..Default::default()
        }
    } else {
        Seg {
            seq: 0,
            ack: s.seq.wrapping_add(s.seq_len()),
            flags: flags::RST | flags::ACK,
            ..Default::default()
        }
    };
    r.set_len(0);
    Some(r)
}

// ============================================================================
// Wire format
// ============================================================================

/// Internet checksum of a TCP segment with the IPv4 pseudo header
pub fn checksum(saddr: Ipv4Addr, daddr: Ipv4Addr, seg: &[u8]) -> u16 {
    let mut sum = u64::from(ipv4::pseudo_header_checksum(
        saddr,
        daddr,
        IPPROTO_TCP,
        seg.len() as u16,
    ));
    let (words, rest) = seg.as_chunks::<2>();
    for w in words {
        sum += u64::from(u16::from_be_bytes(*w));
    }
    if let [b] = rest {
        sum += u64::from(*b) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Endpoints of a segment on the wire
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Tuple {
    pub laddr: Ipv4Addr,
    pub lport: u16,
    pub raddr: Ipv4Addr,
    pub rport: u16,
}

/// The header of `h` from `t.lport` to `t.rport` into `b` (options in
/// Linux's order and padding, tcp_options_write without SACK: MSS, NOP
/// NOP TS, NOP WS); its length
fn put_hdr(h: &Seg, t: &Tuple, b: &mut [u8; HLEN_MAX]) -> usize {
    b[0..2].copy_from_slice(&t.lport.to_be_bytes());
    b[2..4].copy_from_slice(&t.rport.to_be_bytes());
    b[4..8].copy_from_slice(&h.seq.to_be_bytes());
    b[8..12].copy_from_slice(&h.ack.to_be_bytes());
    b[12..14].copy_from_slice(&[0, h.flags]);
    b[14..16].copy_from_slice(&h.wnd.to_be_bytes());
    b[16..20].fill(0);
    let mut n = HLEN;
    if let Some(m) = h.mss {
        b[n..n + 2].copy_from_slice(&[OPT_MSS, 4]);
        b[n + 2..n + 4].copy_from_slice(&m.to_be_bytes());
        n += 4;
    }
    if let Some((v, e)) = h.ts {
        b[n..n + 4].copy_from_slice(&[OPT_NOP, OPT_NOP, OPT_TS, 10]);
        b[n + 4..n + 8].copy_from_slice(&v.to_be_bytes());
        b[n + 8..n + 12].copy_from_slice(&e.to_be_bytes());
        n += 12;
    }
    if let Some(w) = h.ws {
        b[n..n + 4].copy_from_slice(&[OPT_NOP, OPT_WS, 3, w]);
        n += 4;
    }
    b[12] = ((n / 4) as u8) << 4;
    n
}

/// Put the TCP header of `skb.tcp` before its payload, from
/// `t.laddr:lport` to `t.raddr:rport`, checksummed (Linux
/// tcp_transmit_skb's header part); None if the headroom is short
pub fn push_hdr(skb: &mut SkBuff, t: &Tuple) -> Option<()> {
    let mut b = [0u8; HLEN_MAX];
    let n = put_hdr(&skb.tcp, t, &mut b);
    skb.push(n)?.copy_from_slice(&b[..n]);
    let c = checksum(t.laddr, t.raddr, skb.data());
    skb.data_mut()[16..18].copy_from_slice(&c.to_be_bytes());
    skb.saddr = Some(t.laddr);
    skb.daddr = Some(t.raddr);
    Some(())
}

/// A header-only segment `h` from `t`, ready for IP (no socket: RSTs
/// for unknown tuples, a listener's stray-ACK reset)
pub fn build(h: &Seg, t: &Tuple, gfp: Gfp) -> Option<Box<SkBuff>> {
    let mut skb = SkBuff::alloc_tx(0, gfp)?;
    skb.tcp = *h;
    push_hdr(&mut skb, t)?;
    Some(skb)
}

/// Parse a received segment (`b` = TCP header onwards, checksum already
/// verified): its header with ports and sequence space, and the header
/// length
pub fn parse(b: &[u8]) -> Option<(Seg, usize)> {
    if b.len() < HLEN {
        return None;
    }
    let doff = ((b[12] >> 4) as usize) * 4;
    if doff < HLEN || doff > b.len() {
        return None;
    }
    let be16 = |i: usize| u16::from_be_bytes([b[i], b[i + 1]]);
    let be32 = |i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
    let mut s = Seg {
        seq: be32(4),
        ack: be32(8),
        flags: b[13] & 0x3f,
        wnd: be16(14),
        sport: be16(0),
        dport: be16(2),
        ..Default::default()
    };
    s.set_len((b.len() - doff) as u32);
    parse_opts(&b[HLEN..doff], &mut s);
    Some((s, doff))
}

/// The options of a segment (Linux tcp_parse_options: parsing stops at
/// EOL, a length below 2 or past the header; an MSS of 0 is ignored;
/// MSS and window scale count only on a SYN; a scale above 14 is 14)
fn parse_opts(mut o: &[u8], s: &mut Seg) {
    let syn = s.has(flags::SYN);
    while let Some(&k) = o.first() {
        match k {
            OPT_EOL => return,
            OPT_NOP => o = &o[1..],
            _ => {
                let Some(&l) = o.get(1) else {
                    return;
                };
                let l = l as usize;
                if l < 2 || l > o.len() {
                    return;
                }
                match (k, l) {
                    (OPT_MSS, 4) if syn => {
                        let m = u16::from_be_bytes([o[2], o[3]]);
                        s.mss = (m != 0).then_some(m);
                    }
                    (OPT_WS, 3) if syn => s.ws = Some(o[2].min(super::cb::MAX_WSCALE)),
                    (OPT_TS, 10) => {
                        let v = u32::from_be_bytes([o[2], o[3], o[4], o[5]]);
                        let e = u32::from_be_bytes([o[6], o[7], o[8], o[9]]);
                        s.ts = Some((v, e));
                    }
                    _ => {}
                }
                o = &o[l..];
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(o: &[u8], syn: bool) -> Seg {
        let mut s = Seg {
            flags: if syn { flags::SYN } else { flags::ACK },
            ..Default::default()
        };
        parse_opts(o, &mut s);
        s
    }

    #[test]
    fn header_bounds() {
        let mut h = [0u8; 24];
        h[13] = flags::SYN;
        h[12] = 0x40; // doff 4 words: below the minimum
        assert!(parse(&h).is_none());
        h[12] = 0x70; // doff 28 bytes > segment
        assert!(parse(&h).is_none());
        h[12] = 0x60;
        h[20..24].copy_from_slice(&[2, 4, 0, 0]);
        let (s, doff) = parse(&h).unwrap();
        assert_eq!((s.mss, s.data_len(), doff), (None, 0, 24));
        h[22..24].copy_from_slice(&[0x05, 0xb4]);
        assert_eq!(parse(&h).unwrap().0.mss, Some(1460));
        // An option running past the header is not read
        h[20..24].copy_from_slice(&[1, 2, 4, 5]);
        assert_eq!(parse(&h[..24]).unwrap().0.mss, None);
        assert!(parse(&h[..19]).is_none());
    }

    #[test]
    fn options() {
        let m = |o: &[u8]| opts(o, true).mss;
        assert_eq!(m(&[1, 1, 2, 4, 0x05, 0xb4]), Some(1460));
        assert_eq!(m(&[3, 3, 7, 2, 4, 0x02, 0x18]), Some(536));
        assert_eq!(m(&[0, 2, 4, 1, 1]), None);
        assert_eq!(m(&[2, 9, 0]), None);
        assert_eq!(m(&[8, 0]), None);
        assert_eq!(m(&[8, 1, 2, 4, 5, 0]), None);
        assert_eq!(m(&[2, 4, 5]), None);
        // MSS and window scale only on a SYN; scale capped at 14
        assert_eq!(opts(&[2, 4, 0x05, 0xb4], false).mss, None);
        assert_eq!(opts(&[1, 3, 3, 7], true).ws, Some(7));
        assert_eq!(opts(&[1, 3, 3, 30], true).ws, Some(14));
        assert_eq!(opts(&[1, 3, 3, 7], false).ws, None);
        let ts = [1, 1, 8, 10, 0, 0, 1, 2, 0, 0, 3, 4];
        assert_eq!(opts(&ts, false).ts, Some((0x102, 0x304)));
        // A truncated timestamp is ignored
        assert_eq!(opts(&ts[..11], false).ts, None);
    }

    #[test]
    fn syn_options_on_wire() {
        let seg = Seg {
            seq: 1,
            flags: flags::SYN,
            wnd: 65535,
            mss: Some(1460),
            ws: Some(7),
            ts: Some((0x11223344, 0)),
            ..Default::default()
        };
        let t = Tuple::default();
        let skb = build(&seg, &t, Gfp::KERNEL).unwrap();
        let b = skb.data();
        assert_eq!(b.len(), 40);
        assert_eq!(b[12] >> 4, 10);
        assert_eq!(
            &b[20..40],
            &[
                2, 4, 5, 0xb4, 1, 1, 8, 10, 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0, 1, 3, 3, 7
            ]
        );
        let (s, _) = parse(b).unwrap();
        assert_eq!(
            (s.mss, s.ws, s.ts),
            (Some(1460), Some(7), Some((0x11223344, 0)))
        );
    }

    #[test]
    fn reset_rules() {
        let mut s = Seg {
            seq: 100,
            ack: 7,
            flags: flags::SYN,
            ..Default::default()
        };
        s.set_len(3);
        let r = reset_for(&s).unwrap();
        assert_eq!((r.seq, r.ack, r.flags), (0, 104, flags::RST | flags::ACK));
        let a = Seg {
            flags: flags::ACK,
            ..s
        };
        let r = reset_for(&a).unwrap();
        assert_eq!((r.seq, r.flags), (7, flags::RST));
        let rst = Seg {
            flags: flags::RST,
            ..s
        };
        assert!(reset_for(&rst).is_none());
    }

    /// tcp_fragment: the rest takes the end, the FIN and PSH
    #[test]
    fn fragment_moves_the_tail() {
        let mut skb = SkBuff::alloc_tx(10, Gfp::KERNEL).unwrap();
        skb.put_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]).unwrap();
        skb.tcp.seq = 100;
        skb.tcp.flags = flags::ACK | flags::PSH | flags::FIN;
        skb.tcp.set_len(10);
        let rest = fragment(&mut skb, 4, Gfp::KERNEL).unwrap();
        assert_eq!(
            (skb.data(), skb.tcp.seq, skb.tcp.end_seq),
            (&[1, 2, 3, 4][..], 100, 104)
        );
        assert_eq!(skb.tcp.flags, flags::ACK);
        assert_eq!(
            (rest.data().len(), rest.tcp.seq, rest.tcp.end_seq),
            (6, 104, 111)
        );
        assert!(rest.tcp.has(flags::FIN | flags::PSH));
    }
}

//! Segment output: what the control block sends (Linux tcp_output.c,
//! I/O-free) and the wire format (header, options, checksum).
//!
//! Partial segments follow Linux: Nagle with Minshall's variant (hold a
//! partial segment only while an earlier partial one is unacknowledged)
//! unless TCP_NODELAY; TCP_CORK and MSG_MORE hold every partial segment
//! until uncorked, a full segment forms, or the 200 ms (RTO-based) probe
//! timer pushes it out (Linux tcp_write_wakeup). A FIN is never held.

use alloc::vec::Vec;

use super::cb::{Out, RTO_MIN, Seg, SegIn, TcpCb, TcpState, Tmr, after, before, copy_out, flags};
use crate::net::ipv4::{self, IPPROTO_TCP, Ipv4Addr};
use crate::net::skb::SkBuff;

/// TCP header without options
pub const HLEN: usize = 20;
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

impl TcpCb {
    /// SYN (SYN_SENT) or SYN-ACK (SYN_RECEIVED) with our options
    pub(super) fn syn_seg(&mut self) -> Seg {
        let synack = self.state == TcpState::SynReceived;
        let ts = if !self.ts_ok {
            None
        } else if synack {
            Some((self.tsval(), self.ts_recent))
        } else {
            Some((self.tsval(), 0))
        };
        Seg {
            seq: self.iss,
            ack: if synack { self.rcv_nxt } else { 0 },
            flags: flags::SYN | if synack { flags::ACK } else { 0 },
            wnd: self.syn_window(),
            mss: Some(self.adv_mss.min(u16::MAX as u32) as u16),
            ws: self.wscale_ok.then_some(self.rcv_wscale),
            ts,
            data: Vec::new(),
        }
    }

    /// A segment of this connection: ACK field, window, timestamp; an
    /// ACK going out settles what was owed
    pub(super) fn mk_seg(&mut self, seq: u32, fl: u8, data: Vec<u8>) -> Seg {
        let wnd = if fl & flags::ACK != 0 {
            self.select_window()
        } else {
            0
        };
        let ts = self.ts_ok.then(|| (self.tsval(), self.ts_recent));
        if fl & flags::ACK != 0 {
            self.ack_sent();
        }
        self.stats.segs_out += 1;
        if !data.is_empty() {
            self.stats.data_segs_out += 1;
        }
        Seg {
            seq,
            ack: if fl & flags::ACK != 0 {
                self.rcv_nxt
            } else {
                0
            },
            flags: fl,
            wnd,
            mss: None,
            ws: None,
            ts,
            data,
        }
    }

    /// Sequence number just past the queued data
    pub(super) fn data_end(&self) -> u32 {
        self.sndq_seq.wrapping_add(self.sndq.len() as u32)
    }

    /// Our FIN was sent and acknowledged
    pub(super) fn fin_acked(&self) -> bool {
        self.fin_queued && self.snd_una == self.data_end().wrapping_add(1)
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
    /// from `snd_nxt` on (new data, or a rewound range after a timeout),
    /// ending with the FIN once all data went out; else an owed ACK
    /// (Linux tcp_write_xmit + tcp_send_ack / delayed ACK)
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
            let Some(seg) = self.next_seg(now, push, &mut limited) else {
                break;
            };
            let fin = seg.has(flags::FIN);
            out.segs.push(seg);
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

    /// What `next_seg` may send from queue offset `off`: (bytes queued
    /// there, room in the window, cwnd is the smaller window)
    fn room(&self, off: u32) -> (u32, u32, bool) {
        let len = self.sndq.len() as u32;
        let wnd = self.snd_wnd.min(self.cong.cwnd);
        let end = self.snd_una.wrapping_add(wnd);
        let room = if after(end, self.snd_nxt) {
            end.wrapping_sub(self.snd_nxt)
        } else {
            0
        };
        (len - off, room, self.cong.cwnd < self.snd_wnd)
    }

    /// Hold a partial segment of `n` bytes (Linux tcp_nagle_check with
    /// Minshall's rule; cork and MSG_MORE hold all partial segments)
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

    /// The next segment `output` may send, if any
    fn next_seg(&mut self, now: u64, push: Push, limited: &mut bool) -> Option<Seg> {
        let len = self.sndq.len() as u32;
        let off = self.snd_nxt.wrapping_sub(self.sndq_seq);
        if off > len {
            return None; // FIN already sent
        }
        let (avail, room, cwnd_bound) = self.room(off);
        let n = avail.min(self.mss).min(room);
        let fin = self.fin_queued && off + n == len && room > n;
        if n == 0 && !fin {
            *limited |= avail > 0 && cwnd_bound;
            return None;
        }
        let in_flight = self.snd_nxt != self.snd_una;
        // Retransmissions (after a timeout rewound SND.NXT) are never
        // held (Linux tcp_retransmit_skb ignores Nagle and cork)
        let rexmit = before(self.snd_nxt, self.snd_max);
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
        if self.snd_nxt == self.snd_max
            && !in_flight
            && now.saturating_sub(self.lsndtime) > self.rto
        {
            // Idle longer than an RTO: restart from the initial window
            self.cong.restart(now - self.lsndtime, self.rto);
        }
        let mut data = alloc::vec![0u8; n as usize];
        copy_out(&self.sndq, off as usize, &mut data);
        let seq = self.snd_nxt;
        let mut fl = flags::ACK;
        if n > 0 && off + n == len {
            fl |= flags::PSH;
        }
        if fin {
            fl |= flags::FIN;
        }
        let next = seq.wrapping_add(n + fin as u32);
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
            self.stats.total_retrans += 1;
            self.stats.bytes_retrans += n as u64;
        }
        self.stats.bytes_sent += n as u64;
        self.snd_nxt = next;
        if new {
            self.snd_max = next;
        }
        Some(self.mk_seg(seq, fl, data))
    }

    /// A pure ACK of everything received (also the RFC 5961 challenge ACK)
    pub(super) fn send_ack(&mut self, out: &mut Out) {
        let s = self.mk_seg(self.snd_nxt, flags::ACK, Vec::new());
        out.segs.push(s);
    }

    /// Resend the oldest unacknowledged segment (fast retransmit, NewReno
    /// partial ACK); never an RTT sample (Karn)
    pub(super) fn retransmit_head(&mut self, out: &mut Out) {
        self.rtt_seq = None;
        match self.state {
            TcpState::SynSent | TcpState::SynReceived => {
                let s = self.syn_seg();
                out.segs.push(s);
                return;
            }
            _ => {}
        }
        let off = self.snd_una.wrapping_sub(self.sndq_seq) as usize;
        let len = self.sndq.len();
        if off > len {
            return;
        }
        let n = (len - off).min(self.mss as usize);
        let mut data = alloc::vec![0u8; n];
        copy_out(&self.sndq, off, &mut data);
        let fin_sent = self.fin_queued && after(self.snd_max, self.data_end());
        let mut fl = flags::ACK;
        if fin_sent && off + n == len {
            fl |= flags::FIN;
        }
        if n == 0 && fl & flags::FIN == 0 {
            return;
        }
        self.stats.total_retrans += 1;
        self.stats.bytes_retrans += n as u64;
        let s = self.mk_seg(self.snd_una, fl, data);
        out.segs.push(s);
    }

    /// Zero-window or keepalive probe: an old sequence number that the
    /// peer answers with an ACK carrying its window (Linux
    /// tcp_xmit_probe_skb)
    pub(super) fn send_probe(&mut self, out: &mut Out) {
        let s = self.mk_seg(self.snd_una.wrapping_sub(1), flags::ACK, Vec::new());
        out.segs.push(s);
    }

    /// Something to send and nothing in flight, yet nothing went out
    /// (zero window, or a partial segment held by cork/Nagle): arm the
    /// probe timer (Linux tcp_check_probe_timer)
    pub(super) fn check_persist(&mut self, now: u64) {
        let pending = self.snd_nxt != self.data_end().wrapping_add(self.fin_queued as u32);
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
    Some(if s.has(flags::ACK) {
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
    })
}

// ============================================================================
// Wire format
// ============================================================================

/// Internet checksum of a TCP segment with the IPv4 pseudo header
pub fn checksum(saddr: Ipv4Addr, daddr: Ipv4Addr, seg: &[u8]) -> u16 {
    let mut sum = ipv4::pseudo_header_checksum(saddr, daddr, IPPROTO_TCP, seg.len() as u16) as u64;
    let (words, rest) = seg.as_chunks::<2>();
    for w in words {
        sum += u16::from_be_bytes(*w) as u64;
    }
    if let [b] = rest {
        sum += (*b as u64) << 8;
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

/// Option bytes of `seg` in Linux's order and padding (tcp_options_write
/// without SACK): MSS, NOP NOP TS, NOP WS
fn put_opts(seg: &Seg, o: &mut Vec<u8>) {
    if let Some(m) = seg.mss {
        o.extend_from_slice(&[OPT_MSS, 4]);
        o.extend_from_slice(&m.to_be_bytes());
    }
    if let Some((v, e)) = seg.ts {
        o.extend_from_slice(&[OPT_NOP, OPT_NOP, OPT_TS, 10]);
        o.extend_from_slice(&v.to_be_bytes());
        o.extend_from_slice(&e.to_be_bytes());
    }
    if let Some(w) = seg.ws {
        o.extend_from_slice(&[OPT_NOP, OPT_WS, 3, w]);
    }
}

/// Build the IP payload of `seg` from `t.laddr:lport` to `t.raddr:rport`
pub fn build(seg: &Seg, t: &Tuple) -> Option<alloc::boxed::Box<SkBuff>> {
    let mut h = Vec::with_capacity(HLEN + 20);
    h.extend_from_slice(&t.lport.to_be_bytes());
    h.extend_from_slice(&t.rport.to_be_bytes());
    h.extend_from_slice(&seg.seq.to_be_bytes());
    h.extend_from_slice(&seg.ack.to_be_bytes());
    h.extend_from_slice(&[0, seg.flags]);
    h.extend_from_slice(&seg.wnd.to_be_bytes());
    h.extend_from_slice(&[0; 4]);
    put_opts(seg, &mut h);
    h[12] = ((h.len() / 4) as u8) << 4;
    let mut skb = SkBuff::alloc_tx(h.len() + seg.data.len())?;
    skb.put_slice(&h)?;
    skb.put_slice(&seg.data)?;
    let c = checksum(t.laddr, t.raddr, skb.data());
    skb.data_mut()[16..18].copy_from_slice(&c.to_be_bytes());
    skb.saddr = Some(t.laddr);
    skb.daddr = Some(t.raddr);
    Some(skb)
}

/// Parse a received segment (`b` = TCP header onwards, checksum already
/// verified): (source port, destination port, segment)
pub fn parse(b: &[u8]) -> Option<(u16, u16, SegIn<'_>)> {
    if b.len() < HLEN {
        return None;
    }
    let doff = ((b[12] >> 4) as usize) * 4;
    if doff < HLEN || doff > b.len() {
        return None;
    }
    let be16 = |i: usize| u16::from_be_bytes([b[i], b[i + 1]]);
    let be32 = |i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
    let mut s = SegIn {
        seq: be32(4),
        ack: be32(8),
        flags: b[13] & 0x3f,
        wnd: be16(14),
        data: &b[doff..],
        ..Default::default()
    };
    parse_opts(&b[HLEN..doff], &mut s);
    Some((be16(0), be16(2), s))
}

/// The options of a segment (Linux tcp_parse_options: parsing stops at
/// EOL, a length below 2 or past the header; an MSS of 0 is ignored;
/// MSS and window scale count only on a SYN; a scale above 14 is 14)
fn parse_opts(mut o: &[u8], s: &mut SegIn) {
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

    fn opts(o: &[u8], syn: bool) -> SegIn<'static> {
        let mut s = SegIn {
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
        let (_, _, s) = parse(&h).unwrap();
        assert_eq!((s.mss, s.data.len()), (None, 0));
        h[22..24].copy_from_slice(&[0x05, 0xb4]);
        assert_eq!(parse(&h).unwrap().2.mss, Some(1460));
        // An option running past the header is not read
        h[20..24].copy_from_slice(&[1, 2, 4, 5]);
        assert_eq!(parse(&h[..24]).unwrap().2.mss, None);
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
        let skb = build(&seg, &t).unwrap();
        let b = skb.data();
        assert_eq!(b.len(), 40);
        assert_eq!(b[12] >> 4, 10);
        assert_eq!(
            &b[20..40],
            &[
                2, 4, 5, 0xb4, 1, 1, 8, 10, 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0, 1, 3, 3, 7
            ]
        );
        let (_, _, s) = parse(b).unwrap();
        assert_eq!(
            (s.mss, s.ws, s.ts),
            (Some(1460), Some(7), Some((0x11223344, 0)))
        );
    }

    #[test]
    fn reset_rules() {
        let s = SegIn {
            seq: 100,
            ack: 7,
            flags: flags::SYN,
            data: &[1, 2, 3],
            ..Default::default()
        };
        let r = reset_for(&s).unwrap();
        assert_eq!((r.seq, r.ack, r.flags), (0, 104, flags::RST | flags::ACK));
        let a = SegIn {
            flags: flags::ACK,
            ..s
        };
        let r = reset_for(&a).unwrap();
        assert_eq!((r.seq, r.flags), (7, flags::RST));
        let rst = SegIn {
            flags: flags::RST,
            ..s
        };
        assert!(reset_for(&rst).is_none());
    }
}

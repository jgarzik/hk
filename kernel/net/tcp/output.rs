//! Segment output: what the control block sends (Linux tcp_output.c,
//! I/O-free) and the wire format (header, MSS option, checksum).

use alloc::vec::Vec;

use super::cb::{Out, Seg, SegIn, TcpCb, TcpState, Tmr, after, copy_out, flags};
use crate::net::ipv4::{self, IPPROTO_TCP, Ipv4Addr};
use crate::net::skb::SkBuff;

/// TCP header without options
pub const HLEN: usize = 20;
/// TCP option kinds
const OPT_EOL: u8 = 0;
const OPT_NOP: u8 = 1;
const OPT_MSS: u8 = 2;

impl TcpCb {
    /// SYN (SYN_SENT) or SYN-ACK (SYN_RECEIVED) with our MSS
    pub(super) fn syn_seg(&mut self) -> Seg {
        let synack = self.state == TcpState::SynReceived;
        Seg {
            seq: self.iss,
            ack: if synack { self.rcv_nxt } else { 0 },
            flags: flags::SYN | if synack { flags::ACK } else { 0 },
            wnd: if synack {
                self.select_window()
            } else {
                self.full_space() as u16
            },
            mss: Some(self.adv_mss.min(u16::MAX as u32) as u16),
            data: Vec::new(),
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
    fn may_send(&self) -> bool {
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
    /// ending with the FIN once all data went out; else a pure ACK if
    /// one is owed (Linux tcp_write_xmit + tcp_send_ack)
    pub fn output(&mut self, now: u64, out: &mut Out) {
        let mut sent = false;
        while self.may_send() {
            let Some(seg) = self.next_seg(now) else {
                break;
            };
            let fin = seg.has(flags::FIN);
            out.segs.push(seg);
            sent = true;
            if fin {
                break;
            }
        }
        if sent {
            self.ack_now = false;
            if self.tmr.is_none_or(|t| t.0 != Tmr::Rtx) {
                self.arm_rtx(now);
            }
        } else if self.ack_now {
            self.send_ack(out);
        }
        self.check_persist(now);
    }

    /// The next segment `output` may send, if any
    fn next_seg(&mut self, now: u64) -> Option<Seg> {
        let len = self.sndq.len() as u32;
        let off = self.snd_nxt.wrapping_sub(self.sndq_seq);
        if off > len {
            return None; // FIN already sent
        }
        let wnd = self.snd_wnd.min(self.cong.cwnd);
        let end = self.snd_una.wrapping_add(wnd);
        let room = if after(end, self.snd_nxt) {
            end.wrapping_sub(self.snd_nxt)
        } else {
            0
        };
        let avail = len - off;
        let n = avail.min(self.mss).min(room);
        let fin = self.fin_queued && off + n == len && room > n;
        if n == 0 && !fin {
            return None;
        }
        // Sender SWS avoidance (RFC 9293 3.8.6.2.1): with data in flight,
        // wait for a full segment unless this ends the queue
        let in_flight = self.snd_nxt != self.snd_una;
        if n < avail && n < self.mss && in_flight && n < self.max_wnd / 2 {
            return None;
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
        let seg = Seg {
            seq,
            ack: self.rcv_nxt,
            flags: fl,
            wnd: self.select_window(),
            mss: None,
            data,
        };
        let next = seq.wrapping_add(n + fin as u32);
        if self.snd_nxt == self.snd_max && self.rtt_seq.is_none() {
            self.rtt_seq = Some((next, now));
        }
        self.snd_nxt = next;
        if after(next, self.snd_max) {
            self.snd_max = next;
        }
        Some(seg)
    }

    /// A pure ACK of everything received (also the RFC 5961 challenge ACK)
    pub(super) fn send_ack(&mut self, out: &mut Out) {
        self.ack_now = false;
        let wnd = self.select_window();
        out.segs.push(Seg {
            seq: self.snd_nxt,
            ack: self.rcv_nxt,
            flags: flags::ACK,
            wnd,
            ..Default::default()
        });
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
        let wnd = self.select_window();
        out.segs.push(Seg {
            seq: self.snd_una,
            ack: self.rcv_nxt,
            flags: fl,
            wnd,
            mss: None,
            data,
        });
        self.ack_now = false;
    }

    /// Zero-window probe: an old sequence number that the peer answers
    /// with an ACK carrying its window (Linux tcp_xmit_probe_skb)
    pub(super) fn send_probe(&mut self, out: &mut Out) {
        let wnd = self.select_window();
        out.segs.push(Seg {
            seq: self.snd_una.wrapping_sub(1),
            ack: self.rcv_nxt,
            flags: flags::ACK,
            wnd,
            ..Default::default()
        });
    }

    /// Something to send, nothing in flight and a zero window: probe
    pub(super) fn check_persist(&mut self, now: u64) {
        let pending = self.snd_nxt != self.data_end().wrapping_add(self.fin_queued as u32);
        if self.may_send()
            && self.snd_wnd == 0
            && pending
            && self.snd_una == self.snd_max
            && self.tmr.is_none()
        {
            self.tmr = Some((Tmr::Probe, now + self.rto_cur()));
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

/// Build the IP payload of `seg` from `t.laddr:lport` to `t.raddr:rport`
pub fn build(seg: &Seg, t: &Tuple) -> Option<alloc::boxed::Box<SkBuff>> {
    let opt = if seg.mss.is_some() { 4 } else { 0 };
    let mut skb = SkBuff::alloc_tx(HLEN + opt + seg.data.len())?;
    let mut h = [0u8; HLEN + 4];
    h[0..2].copy_from_slice(&t.lport.to_be_bytes());
    h[2..4].copy_from_slice(&t.rport.to_be_bytes());
    h[4..8].copy_from_slice(&seg.seq.to_be_bytes());
    h[8..12].copy_from_slice(&seg.ack.to_be_bytes());
    h[12] = (((HLEN + opt) / 4) as u8) << 4;
    h[13] = seg.flags;
    h[14..16].copy_from_slice(&seg.wnd.to_be_bytes());
    if let Some(m) = seg.mss {
        h[20] = OPT_MSS;
        h[21] = 4;
        h[22..24].copy_from_slice(&m.to_be_bytes());
    }
    skb.put_slice(&h[..HLEN + opt])?;
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
    let s = SegIn {
        seq: be32(4),
        ack: be32(8),
        flags: b[13] & 0x3f,
        wnd: be16(14),
        mss: mss_opt(&b[HLEN..doff]),
        data: &b[doff..],
    };
    Some((be16(0), be16(2), s))
}

/// The MSS option of a SYN, if present and well formed
fn mss_opt(mut o: &[u8]) -> Option<u16> {
    while let Some(&k) = o.first() {
        match k {
            OPT_EOL => return None,
            OPT_NOP => o = &o[1..],
            _ => {
                let l = *o.get(1)? as usize;
                if l < 2 || l > o.len() {
                    return None;
                }
                if k == OPT_MSS && l == 4 {
                    return Some(u16::from_be_bytes([o[2], o[3]]));
                }
                o = &o[l..];
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options() {
        assert_eq!(mss_opt(&[1, 1, 2, 4, 0x05, 0xb4]), Some(1460));
        assert_eq!(mss_opt(&[3, 3, 7, 2, 4, 0x02, 0x18]), Some(536));
        assert_eq!(mss_opt(&[0, 2, 4, 1, 1]), None);
        assert_eq!(mss_opt(&[2, 9, 0]), None);
        assert_eq!(mss_opt(&[8, 0]), None);
    }

    #[test]
    fn reset_rules() {
        let s = SegIn {
            seq: 100,
            ack: 7,
            flags: flags::SYN,
            wnd: 0,
            mss: None,
            data: &[1, 2, 3],
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

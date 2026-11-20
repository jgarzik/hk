//! Segment output: what the control block sends (Linux tcp_output.c,
//! I/O-free) and the wire format (header, options, checksum).
//!
//! Data goes out skb by skb (Linux tcp_write_xmit): the write queue's
//! head, cut at the MSS or the window (tcp_fragment), is cloned for
//! transmission and moves to the retransmit queue, where the skbs
//! marked lost are sent again as the window allows
//! (tcp_xmit_retransmit_queue; `recovery.rs` decides what is lost),
//! cut to the MSS or merged with the small skbs behind them
//! (tcp_retrans_try_collapse). SND.NXT never moves back. Transmitted clones and
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
use super::recovery::{CaState, tag, tso_segs};
use crate::mm::page_alloc::Gfp;
use crate::net::ipv4::{self, IPPROTO_TCP, Ipv4Addr};
use crate::net::mib::*;
use crate::net::skb::{Sacks, SkBuff};

/// TCP header without options
pub const HLEN: usize = 20;
/// TCP header with every option it may carry
const HLEN_MAX: usize = 60;
/// TCP option kinds
const OPT_EOL: u8 = 0;
const OPT_NOP: u8 = 1;
const OPT_MSS: u8 = 2;
const OPT_WS: u8 = 3;
const OPT_SACK_PERM: u8 = 4;
const OPT_SACK: u8 = 5;
const OPT_TS: u8 = 8;
/// SACK option bytes: the kind and length (with two NOPs before them,
/// Linux TCPOLEN_SACK_BASE_ALIGNED), then 8 per block
pub(super) const SACK_BASE: u32 = 4;
pub(super) const SACK_PERBLOCK: u32 = 8;

/// How partial segments are pushed (Linux nonagle modes)
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Push {
    /// Nagle / TCP_NODELAY / TCP_CORK as set
    Normal,
    /// MSG_MORE: hold partial segments for this call
    More,
    /// Probe timer: one segment regardless (Linux tcp_write_wakeup)
    Force,
    /// Tail loss probe: one new segment, Nagle off, no probe scheduled
    /// for it (Linux tcp_write_xmit with push_one 2)
    Tlp,
}

impl Push {
    /// One segment, never held
    fn one(self) -> bool {
        matches!(self, Push::Force | Push::Tlp)
    }
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
    n.set_tcp(skb.tcp());
    n.tcp_mut().seq = skb.tcp().seq.wrapping_add(at as u32);
    skb.tcp_mut().end_seq = n.tcp().seq;
    skb.tcp_mut().flags &= !(flags::FIN | flags::PSH);
    Some(n)
}

impl TcpCb {
    /// Queue a SYN (SYN_SENT) or SYN-ACK (the peer's SYN received:
    /// SYN_RECEIVED, or FIN_WAIT_1 after a close there) with our
    /// options; false without memory
    pub(super) fn syn_seg(&mut self, out: &mut Out) -> bool {
        let synack = self.state != TcpState::SynSent;
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
            sack_perm: self.sack_ok != 0,
            ..Default::default()
        };
        out.ctl(h)
    }

    /// A SYN or SYN-ACK again (Linux __tcp_retransmit_skb /
    /// tcp_rtx_synack)
    pub(super) fn syn_rtx(&mut self, out: &mut Out) {
        self.syn_seg(out);
        self.tcp_stat(TCP_MIB_RETRANSSEGS);
        self.net_stat(LINUX_MIB_TCPSYNRETRANS);
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
        // Linux tcp_established_options / tcp_options_write: the blocks
        // that fit, a pending D-SACK sent once
        let sack = self.sack_blocks();
        if sack.n != 0 {
            self.dsack.on = false;
        }
        if fl & flags::ACK != 0 {
            self.ack_sent();
        }
        // Linux __tcp_transmit_skb: OutSegs leaves out retransmissions
        // (hk's SND.MAX is Linux's snd_nxt)
        let end = seq.wrapping_add(len + u32::from(fl & flags::FIN != 0));
        self.tcp_stat_if(after(end, self.snd_max) || end == seq, TCP_MIB_OUTSEGS);
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
            sack,
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
        c.set_tcp(self.hdr(seq, fl, skb.len() as u32));
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
        skb.set_tcp(self.hdr(seq, fl, 0));
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

    /// Send the new data the peer's window and the congestion window
    /// allow, from `snd_nxt` on, ending with the FIN once all data went out;
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
        let prior_packets = self.packets_out;
        while self.may_send() {
            let Some(fin) = self.next_seg(now, push, &mut limited, out) else {
                break;
            };
            sent = true;
            if fin || push.one() {
                break;
            }
        }
        if sent {
            // Linux tcp_event_new_data_sent: the RTO starts with the
            // first packet out, or replaces a loss probe
            let pending = self.live.tmr.get().map(|t| t.0);
            if prior_packets == 0 || matches!(pending, None | Some(Tmr::LossProbe | Tmr::Probe)) {
                self.rearm_rto(now);
            }
            // Linux tcp_write_xmit: one loss probe per tail episode (not
            // from the probe itself, nor from tcp_write_wakeup's segment)
            if !push.one() {
                self.schedule_loss_probe(now, false);
            }
            let flight = self.snd_max.wrapping_sub(self.snd_una);
            self.cong
                .on_sent(flight, self.snd_una, self.snd_nxt, limited);
        } else if self.state.synced() {
            self.ack_snd_check(now, out);
        }
        self.check_persist(now);
    }

    /// Room for new data: the bytes the peer's window leaves from
    /// SND.NXT (Linux tcp_snd_wnd_test), none while the packets in
    /// flight fill the congestion window (tcp_cwnd_test); and whether
    /// cwnd was the limit
    fn room(&self) -> (u32, bool) {
        if self.in_flight() >= self.cong.snd_cwnd() {
            return (0, true);
        }
        let end = self.snd_una.wrapping_add(self.snd_wnd);
        let room = if after(end, self.snd_nxt) {
            end.wrapping_sub(self.snd_nxt)
        } else {
            0
        };
        (room, false)
    }

    /// Hold a partial segment (Linux tcp_nagle_check with Minshall's
    /// rule; cork and MSG_MORE hold all partial segments)
    fn nagle_hold(&self, push: Push) -> bool {
        if push.one() {
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

    /// Send the next new segment `output` may send, if any: Some(it
    /// carried the FIN) (Linux tcp_write_xmit's loop body)
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
        let mss = self.cur_mss();
        let head = self.wq.front().map_or(0, |s| s.len() as u32);
        let n = head.min(mss).min(room);
        let fin = self.fin_queued && self.snd_nxt.wrapping_add(n) == self.write_seq && room > n;
        if n == 0 && !fin {
            *limited |= avail > 0 && cwnd_bound;
            return None;
        }
        let in_flight = self.snd_nxt != self.snd_una;
        if n < mss && !fin && !push.one() {
            // Sender SWS avoidance (RFC 9293 3.8.6.2.1): with data in
            // flight, wait for a full segment unless this ends the queue
            if n < avail && in_flight && n < self.max_wnd / 2 {
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
        if !self.send_new(n, fl, now, out) {
            return None;
        }
        if !in_flight && now.saturating_sub(self.lsndtime) > self.live.rto.get() {
            // Idle longer than an RTO: restart from the initial window
            self.cong.restart(now - self.lsndtime, self.live.rto.get());
        }
        let next = seq.wrapping_add(n + u32::from(fin));
        if self.rtt_seq.is_none() {
            self.rtt_seq = Some((next, now));
        }
        if n < mss {
            self.snd_sml = next;
        }
        if n > 0 {
            self.data_sent(now);
            self.lsndtime = now;
        }
        // Linux tcp_event_new_data_sent
        self.net_stat(LINUX_MIB_TCPORIGDATASENT);
        // Linux tcp_write_xmit: new data sent while reducing counts in PRR
        if self.in_cwnd_reduction() {
            self.prr_out += 1;
        }
        self.stats.bytes_sent += u64::from(n);
        self.snd_nxt = next;
        self.snd_max = next;
        Some(fin)
    }

    /// Send `n` bytes from the write queue's head (cut there if longer,
    /// Linux tcp_fragment) and move them to the retransmit queue, one
    /// packet more out (tcp_event_new_data_sent); a FIN in `fl` rides on
    /// them, or on an skb of its own once the data is gone (Linux
    /// tcp_send_fin). False without memory.
    fn send_new(&mut self, n: u32, fl: u8, now: u64, out: &mut Out) -> bool {
        let mut skb = match self.wq.pop_front() {
            Some(s) => s,
            None => {
                let Some(mut s) = SkBuff::alloc_tx(0, out.gfp) else {
                    return false;
                };
                s.tcp_mut().seq = self.write_seq;
                s.tcp_mut().end_seq = self.write_seq;
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
        if !self.transmit(&skb, skb.tcp().seq, fl, out) {
            self.requeue(skb);
            return false;
        }
        let t = skb.tcp_mut();
        t.flags |= fl;
        if fl & flags::FIN != 0 {
            t.end_seq = t.end_seq.wrapping_add(1);
        }
        t.sacked = 0;
        t.pcount = 1;
        t.gso_size = 0;
        t.sent = now;
        self.tx_count += 1;
        t.tx_order = self.tx_count;
        // Linux tcp_rate_skb_sent
        t.tx_delivered = self.delivered;
        t.tx_counted = false;
        self.packets_out += 1;
        self.rtx
            .insert_by(skb, |a, b| before(a.tcp().seq, b.tcp().seq));
        true
    }

    /// Put an skb back at the head of the write queue (an empty FIN skb
    /// is just dropped)
    fn requeue(&mut self, skb: Box<SkBuff>) {
        if !skb.is_empty() {
            self.wq.push_front(skb);
        }
    }

    /// Send `c`, a copy of a queued skb's payload, at `seq` with `fl`
    fn send_clone(&mut self, mut c: Box<SkBuff>, seq: u32, fl: u8, out: &mut Out) {
        c.set_tcp(self.hdr(seq, fl, c.len() as u32));
        out.segs.push_back(c);
    }

    /// A pure ACK of everything received (also the RFC 5961 challenge ACK)
    pub(super) fn send_ack(&mut self, out: &mut Out) {
        self.send_ctl(self.snd_nxt, flags::ACK, out);
    }

    // --- the retransmit queue ------------------------------------------------

    /// Cut the sent skb at `seq` after `len` bytes (Linux tcp_fragment,
    /// TCP_FRAG_IN_RTX_QUEUE): the rest keeps its tags and send time,
    /// both are segmented at `mss` and the packet counts follow; false
    /// without memory
    pub(super) fn rtx_fragment(&mut self, seq: u32, len: usize, mss: u32) -> bool {
        let gfp = Gfp::ATOMIC;
        let Some(Some((mut rest, old, p1, tags))) = self.rtx_with(seq, |s| {
            let old = s.tcp().pcount;
            let rest = fragment(s, len, gfp)?;
            let (p1, g1) = tso_segs(s.len(), mss);
            s.tcp_mut().pcount = p1;
            s.tcp_mut().gso_size = g1;
            Some((rest, old, p1, s.tcp().sacked))
        }) else {
            return false;
        };
        let (p2, g2) = tso_segs(rest.len(), mss);
        rest.tcp_mut().pcount = p2;
        rest.tcp_mut().gso_size = g2;
        let diff = old as i32 - p1 as i32 - p2 as i32;
        if diff != 0 && !before(self.snd_max, rest.tcp().end_seq) {
            self.adjust_pcount(tags, diff);
        }
        self.rtx
            .insert_by(rest, |a, b| before(a.tcp().seq, b.tcp().seq));
        true
    }

    /// Drop the first `n` bytes of the sent skb at `seq` (Linux
    /// tcp_trim_head): its seq moves, the references to it follow, an
    /// skb of several segments is segmented again; returns the packets
    /// it no longer counts (its caller accounts for them)
    pub(super) fn rtx_trim_head(&mut self, seq: u32, n: usize) -> u32 {
        let Some((new, diff)) = self.rtx_with(seq, |s| {
            let k = n.min(s.len());
            let _ = s.pull(k);
            let old = s.tcp().pcount;
            if old > 1 {
                let (p, g) = tso_segs(s.len(), s.tcp().gso_size);
                s.tcp_mut().pcount = p;
                s.tcp_mut().gso_size = g;
            }
            let t = s.tcp_mut();
            t.seq = t.seq.wrapping_add(k as u32);
            (t.seq, old - t.pcount)
        }) else {
            return 0;
        };
        if self.highest_sack == Some(seq) {
            self.highest_sack = Some(new);
        }
        if self.rtx_hint == Some(seq) {
            self.rtx_hint = Some(new);
        }
        diff
    }

    /// Merge the skb after the one at `seq` into it (Linux
    /// tcp_collapse_retrans): its data, FIN and PSH move over and it
    /// goes, one packet less out; false if the data does not fit
    fn collapse_retrans(&mut self, seq: u32) -> bool {
        let mut c = self.rtx.cursor_floor_mut(|s| !after(s.tcp().seq, seq));
        c.move_next();
        let Some(next) = c.remove_current() else {
            return false;
        };
        let fits = self.rtx_with(seq, |h| h.tailroom() >= next.len()) == Some(true);
        if !fits {
            self.rtx
                .insert_by(next, |a, b| before(a.tcp().seq, b.tcp().seq));
            return false;
        }
        let nt = next.tcp();
        self.rtx_with(seq, |h| {
            let _ = h.put_slice(next.data());
            let t = h.tcp_mut();
            t.end_seq = nt.end_seq;
            t.flags |= nt.flags & (flags::FIN | flags::PSH);
            t.sacked |= nt.sacked & tag::EVER_RETRANS;
        });
        if self.highest_sack == Some(nt.seq) {
            self.highest_sack = Some(seq);
        }
        if self.rtx_hint == Some(nt.seq) {
            self.rtx_hint = Some(seq);
        }
        self.adjust_pcount(nt.sacked, nt.pcount as i32);
        true
    }

    /// Merge the skbs after the one at `seq` into it while they fit in
    /// `space` bytes and the peer's window (Linux
    /// tcp_retrans_try_collapse with tcp_can_collapse: one segment, not
    /// SACKed; nothing goes after a FIN)
    fn retrans_try_collapse(&mut self, seq: u32, space: i64) {
        let can = |s: &SkBuff| s.tcp().pcount <= 1 && s.tcp().sacked & tag::SACKED_ACKED == 0;
        let Some(len) = self.rtx_with(seq, |s| s.len()) else {
            return;
        };
        let mut space = space - len as i64;
        let wnd_end = self.snd_una.wrapping_add(self.snd_wnd);
        loop {
            if self.rtx_with(seq, |s| can(s) && !s.tcp().has(flags::FIN)) != Some(true) {
                return;
            }
            let Some(nseq) = self.rtx_next(seq) else {
                return;
            };
            let Some((ok, nlen, nend)) =
                self.rtx_with(nseq, |s| (can(s), s.len(), s.tcp().end_seq))
            else {
                return;
            };
            if !ok {
                return;
            }
            space -= nlen as i64;
            if space < 0 || after(nend, wnd_end) || !self.collapse_retrans(seq) {
                return;
            }
        }
    }

    /// Send the sent skb at `seq` again, up to `segs` segments of it
    /// (Linux __tcp_retransmit_skb: an acknowledged head is trimmed, an
    /// skb beyond a shrunk window waits unless it heads the queue,
    /// longer ones are cut, shorter ones merged with the next). Returns
    /// the seq it went out at, None if nothing did
    pub(super) fn retransmit_raw(
        &mut self,
        seq: u32,
        segs: u32,
        now: u64,
        out: &mut Out,
    ) -> Option<u32> {
        let mut seq = seq;
        let (start, end) = self.rtx_with(seq, |s| (s.tcp().seq, s.tcp().end_seq))?;
        if before(start, self.snd_una) {
            if before(end, self.snd_una) {
                return None;
            }
            self.rtx_trim_head(seq, self.snd_una.wrapping_sub(start) as usize);
            seq = self.snd_una;
        }
        let cur_mss = self.cur_mss();
        let wnd_end = self.snd_una.wrapping_add(self.snd_wnd);
        let mut avail = i64::from(wnd_end.wrapping_sub(seq) as i32);
        if avail <= 0 {
            if seq != self.snd_una {
                return None;
            }
            avail = i64::from(cur_mss);
        }
        let mut len = i64::from(cur_mss) * i64::from(segs.max(1));
        if len > avail {
            len = avail / i64::from(cur_mss) * i64::from(cur_mss);
            if len == 0 {
                len = avail;
            }
        }
        let skb_len = self.rtx_with(seq, |s| s.len())? as i64;
        if skb_len > len {
            if !self.rtx_fragment(seq, len as usize, cur_mss) {
                self.net_stat(LINUX_MIB_TCPRETRANSFAIL);
                return None;
            }
        } else {
            let (tags, diff) = self.rtx_with(seq, |s| {
                let old = s.tcp().pcount;
                let (p, g) = tso_segs(s.len(), cur_mss);
                s.tcp_mut().pcount = p;
                s.tcp_mut().gso_size = g;
                (s.tcp().sacked, old as i32 - p as i32)
            })?;
            if diff != 0 {
                self.adjust_pcount(tags, diff);
            }
            let avail = avail.min(i64::from(cur_mss));
            if skb_len < avail {
                self.retrans_try_collapse(seq, avail);
            }
        }
        let gfp = out.gfp;
        let Some(Some((clone, fl, pc))) = self.rtx_with(seq, |s| {
            let fl = flags::ACK | (s.tcp().flags & (flags::FIN | flags::PSH));
            clone_data(s, gfp).map(|c| (c, fl, s.tcp().pcount))
        }) else {
            self.net_stat(LINUX_MIB_TCPRETRANSFAIL);
            return None;
        };
        let n = clone.len();
        self.send_clone(clone, seq, fl, out);
        self.tcp_add(TCP_MIB_RETRANSSEGS, u64::from(pc));
        self.stats.total_retrans = self.stats.total_retrans.wrapping_add(pc);
        self.stats.bytes_retrans += n as u64;
        let delivered = self.delivered;
        self.tx_count += 1;
        let order = self.tx_count;
        self.rtx_with(seq, |s| {
            let t = s.tcp_mut();
            t.sacked |= tag::EVER_RETRANS;
            t.sent = now;
            t.tx_order = order;
            t.tx_delivered = delivered;
            t.tx_counted = false;
        });
        Some(seq)
    }

    /// Linux tcp_retransmit_skb: `retransmit_raw`, then the skb is a
    /// retransmission in flight; the first (attempted) retransmission of
    /// an episode stamps it (retrans_stamp: the skb's send time after the
    /// attempt) and each one
    /// counts towards undo. Returns the seq it went out at.
    pub(super) fn retransmit_skb(
        &mut self,
        seq: u32,
        segs: u32,
        now: u64,
        out: &mut Out,
    ) -> Option<u32> {
        let r = self.retransmit_raw(seq, segs, now, out);
        let mut pc = 1;
        if let Some(at) = r
            && let Some((tags, p)) = self.rtx_with(at, |s| {
                let old = s.tcp().sacked;
                s.tcp_mut().sacked |= tag::RETRANS;
                (old, s.tcp().pcount)
            })
        {
            pc = p;
            if tags & tag::SACKED_RETRANS == 0 {
                self.retrans_out += p;
            }
        }
        if self.rtx_stamp.is_none() {
            let at = r.unwrap_or(seq);
            self.rtx_stamp = Some(self.rtx_with(at, |s| s.tcp().sent).unwrap_or(now));
        }
        if self.undo_retrans < 0 {
            self.undo_retrans = 0;
        }
        self.undo_retrans += pc as i32;
        // Karn: no RTT sample from a retransmitted range
        self.rtt_seq = None;
        r
    }

    /// Linux tcp_xmit_retransmit_queue: resend what is marked lost and
    /// not retransmitted yet, oldest first, while the window allows
    pub(super) fn xmit_retransmit_queue(&mut self, out: &mut Out) {
        if self.packets_out == 0 || self.syn_unacked {
            return;
        }
        let now = self.clock;
        let head = self.rtx_head();
        let start = match self.rtx_hint {
            Some(h) => {
                let c = self.rtx.cursor_floor_mut(|s| !after(s.tcp().seq, h));
                c.current().map(|s| s.tcp().seq).or(head)
            }
            None => head,
        };
        let mut hole = false;
        let mut rearm = false;
        let mut cur = start;
        while let Some(seq) = cur {
            if !hole {
                self.rtx_hint = Some(seq);
            }
            let segs = i64::from(self.cong.snd_cwnd()) - i64::from(self.in_flight());
            if segs <= 0 || self.retrans_out >= self.lost_out {
                break;
            }
            let Some(sacked) = self.rtx_with(seq, |s| s.tcp().sacked) else {
                break;
            };
            if sacked & tag::LOST == 0 {
                if !hole && sacked & (tag::SACKED_RETRANS | tag::SACKED_ACKED) == 0 {
                    hole = true;
                }
                cur = self.rtx_next(seq);
                continue;
            }
            let mib = if self.ca_state != CaState::Loss {
                LINUX_MIB_TCPFASTRETRANS
            } else {
                LINUX_MIB_TCPSLOWSTARTRETRANS
            };
            if sacked & (tag::SACKED_ACKED | tag::SACKED_RETRANS) != 0 {
                cur = self.rtx_next(seq);
                continue;
            }
            // One segment per transmit: hk has no GSO (Linux max_segs)
            let Some(at) = self.retransmit_skb(seq, 1, now, out) else {
                break;
            };
            let pc = self.rtx_with(at, |s| s.tcp().pcount).unwrap_or(1);
            self.net_add(mib, u64::from(pc));
            if self.in_cwnd_reduction() {
                self.prr_out += pc;
            }
            if Some(at) == self.rtx_head() && self.live.tmr.get().is_none_or(|t| t.0 != Tmr::Reo) {
                rearm = true;
            }
            cur = self.rtx_next(at);
        }
        if rearm {
            self.arm_rtx(now);
        }
    }

    /// Zero-window or keepalive probe: an old sequence number that the
    /// peer answers with an ACK carrying its window (Linux
    /// tcp_xmit_probe_skb), counted in `mib` (TCPWinProbe or
    /// TCPKeepAlive)
    pub(super) fn send_probe(&mut self, mib: usize, out: &mut Out) {
        self.net_stat(mib);
        self.send_ctl(self.snd_una.wrapping_sub(1), flags::ACK, out);
    }

    /// Something to send and nothing in flight, yet nothing went out
    /// (zero window, a partial segment held by cork/Nagle, or no
    /// memory): arm the probe timer (Linux tcp_check_probe_timer)
    pub(super) fn check_persist(&mut self, now: u64) {
        let pending = self.snd_nxt != self.write_seq.wrapping_add(u32::from(self.fin_queued));
        if self.may_send()
            && pending
            && self.snd_una == self.snd_max
            && self.live.tmr.get().is_none()
        {
            let t = self.rto_cur().max(RTO_MIN);
            self.live.tmr.set(Some((Tmr::Probe, now + t)));
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
/// Linux's order and padding, tcp_options_write: MSS, NOP NOP TS (SACK
/// PERM TS when both), NOP NOP SACK_PERM without TS, NOP WS, NOP NOP
/// SACK and its blocks); its length
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
    let mut sack_perm = h.sack_perm;
    if let Some((v, e)) = h.ts {
        let lead = if sack_perm {
            sack_perm = false;
            [OPT_SACK_PERM, 2]
        } else {
            [OPT_NOP, OPT_NOP]
        };
        b[n..n + 2].copy_from_slice(&lead);
        b[n + 2..n + 4].copy_from_slice(&[OPT_TS, 10]);
        b[n + 4..n + 8].copy_from_slice(&v.to_be_bytes());
        b[n + 8..n + 12].copy_from_slice(&e.to_be_bytes());
        n += 12;
    }
    if sack_perm {
        b[n..n + 4].copy_from_slice(&[OPT_NOP, OPT_NOP, OPT_SACK_PERM, 2]);
        n += 4;
    }
    if let Some(w) = h.ws {
        b[n..n + 4].copy_from_slice(&[OPT_NOP, OPT_WS, 3, w]);
        n += 4;
    }
    let blocks = h.sack.blocks();
    if !blocks.is_empty() {
        let len = (SACK_BASE - 2 + SACK_PERBLOCK * blocks.len() as u32) as u8;
        b[n..n + 4].copy_from_slice(&[OPT_NOP, OPT_NOP, OPT_SACK, len]);
        n += 4;
        for &(start, end) in blocks {
            b[n..n + 4].copy_from_slice(&start.to_be_bytes());
            b[n + 4..n + 8].copy_from_slice(&end.to_be_bytes());
            n += 8;
        }
    }
    b[12] = ((n / 4) as u8) << 4;
    n
}

/// Put the TCP header of `skb.tcp` before its payload, from
/// `t.laddr:lport` to `t.raddr:rport`, checksummed (Linux
/// tcp_transmit_skb's header part); None if the headroom is short
pub fn push_hdr(skb: &mut SkBuff, t: &Tuple) -> Option<()> {
    let mut b = [0u8; HLEN_MAX];
    let n = put_hdr(&skb.tcp(), t, &mut b);
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
    skb.set_tcp(*h);
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
/// MSS, window scale and SACK-permitted count only on a SYN; a scale
/// above 14 is 14; a SACK option needs a whole number of blocks, at
/// most four of them are read). Whether the connection may use them
/// (the sysctls, what was negotiated) the control block decides.
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
                    (OPT_SACK_PERM, 2) if syn => s.sack_perm = true,
                    (OPT_SACK, _)
                        if l >= (SACK_BASE - 2 + SACK_PERBLOCK) as usize
                            && (l - 2).is_multiple_of(SACK_PERBLOCK as usize) =>
                    {
                        s.sack = Sacks::default();
                        for c in o[2..l].as_chunks::<8>().0 {
                            let be =
                                |i: usize| u32::from_be_bytes([c[i], c[i + 1], c[i + 2], c[i + 3]]);
                            if !s.sack.push((be(0), be(4))) {
                                break;
                            }
                        }
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

    /// SACK_PERM rides in the timestamp's NOPs, or has its own word;
    /// SACK blocks follow NOP NOP (Linux tcp_options_write)
    #[test]
    fn sack_options_on_wire() {
        let t = Tuple::default();
        let mut seg = Seg {
            seq: 1,
            flags: flags::SYN,
            mss: Some(1460),
            ws: Some(7),
            ts: Some((5, 0)),
            sack_perm: true,
            ..Default::default()
        };
        let skb = build(&seg, &t, Gfp::KERNEL).unwrap();
        assert_eq!(
            &skb.data()[20..40],
            &[
                2, 4, 5, 0xb4, 4, 2, 8, 10, 0, 0, 0, 5, 0, 0, 0, 0, 1, 3, 3, 7
            ]
        );
        assert!(parse(skb.data()).unwrap().0.sack_perm);
        seg.ts = None;
        let skb = build(&seg, &t, Gfp::KERNEL).unwrap();
        assert_eq!(
            &skb.data()[20..32],
            &[2, 4, 5, 0xb4, 1, 1, 4, 2, 1, 3, 3, 7]
        );
        assert!(parse(skb.data()).unwrap().0.sack_perm);
        let mut a = Seg {
            seq: 9,
            flags: flags::ACK,
            ts: Some((1, 2)),
            ..Default::default()
        };
        a.sack.push((100, 200));
        a.sack.push((300, 400));
        let skb = build(&a, &t, Gfp::KERNEL).unwrap();
        let b = skb.data();
        assert_eq!(b.len(), 20 + 12 + 4 + 16);
        assert_eq!(&b[32..36], &[1, 1, 5, 18]);
        let (s, _) = parse(b).unwrap();
        assert_eq!(s.sack.blocks(), &[(100, 200), (300, 400)]);
        assert!(!s.sack_perm);
    }

    #[test]
    fn sack_option_parsing() {
        let blk = |v: u32| v.to_be_bytes();
        let mut o = alloc::vec![1, 1, 5, 10];
        o.extend_from_slice(&blk(7));
        o.extend_from_slice(&blk(9));
        assert_eq!(opts(&o, false).sack.blocks(), &[(7, 9)]);
        // A length that is not a whole number of blocks is ignored
        let mut bad = alloc::vec![5, 9];
        bad.extend_from_slice(&[0; 7]);
        assert_eq!(opts(&bad, false).sack.n, 0);
        // SACK_PERM counts only on a SYN
        assert!(opts(&[4, 2], true).sack_perm);
        assert!(!opts(&[4, 2], false).sack_perm);
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
        skb.tcp_mut().seq = 100;
        skb.tcp_mut().flags = flags::ACK | flags::PSH | flags::FIN;
        skb.tcp_mut().set_len(10);
        let rest = fragment(&mut skb, 4, Gfp::KERNEL).unwrap();
        assert_eq!(
            (skb.data(), skb.tcp().seq, skb.tcp().end_seq),
            (&[1, 2, 3, 4][..], 100, 104)
        );
        assert_eq!(skb.tcp().flags, flags::ACK);
        assert_eq!(
            (rest.data().len(), rest.tcp().seq, rest.tcp().end_seq),
            (6, 104, 111)
        );
        assert!(rest.tcp().has(flags::FIN | flags::PSH));
    }
}

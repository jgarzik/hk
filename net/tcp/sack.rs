//! Selective acknowledgment (RFC 2018, D-SACK RFC 2883; Linux
//! tcp_input.c), I/O-free
//!
//! Receiver: out-of-order data is reported in up to four SACK blocks,
//! the most recently changed first (Linux tcp_sack_new_ofo_skb,
//! selective_acks), merged as holes fill (tcp_sack_maybe_coalesce) and
//! dropped as RCV.NXT passes them (tcp_sack_remove); a duplicate
//! segment is reported once in a D-SACK block ahead of them
//! (tcp_dsack_set / tcp_dsack_extend, duplicate_sack). Every segment
//! carries as many blocks as fit next to the timestamp (Linux
//! tcp_established_options: three with it, four without), and the
//! sender's MSS shrinks by their bytes (tcp_current_mss).
//!
//! Sender: the blocks of each ACK tag the retransmit queue (Linux
//! tcp_sacktag_write_queue): validated against SND.UNA..SND.NXT (a
//! D-SACK back to undo_marker), sorted, walked with the cache of the
//! previous ACK's blocks; skbs of several segments are cut at segment
//! boundaries (tcp_match_skb_to_sack), newly SACKed bytes join the
//! SACKed skb before them when its buffer has room
//! (tcp_shift_skb_data: hk's skbs are linear, so the bytes are copied
//! where Linux moves pages), and each skb is tagged
//! (tcp_sacktag_one), feeding RACK, reordering detection and undo.

use super::cb::{DSACK_SEEN, TcpCb, after, before, flags, skb_mstamp_us};
use super::output::{SACK_BASE, SACK_PERBLOCK};
use super::recovery::{CaState, flag, seglen, tag};
use crate::mm::page_alloc::Gfp;
use crate::net::mib::*;
use crate::net::skb::{NUM_SACKS, Sacks, TX_HEADROOM};

/// Option space of a header (Linux MAX_TCP_OPTION_SPACE)
const MAX_OPTION_SPACE: u32 = 40;

/// The D-SACK block to report (Linux rx_opt.dsack and duplicate_sack[0])
#[derive(Clone, Copy, Debug, Default)]
pub struct Dsack {
    pub on: bool,
    pub blk: (u32, u32),
}

impl Dsack {
    /// Linux tcp_dsack_extend's body without its MIB: extend the block
    /// over [`seq`, `end`), or start it if none is set; true if started
    pub fn extend(&mut self, seq: u32, end: u32) -> bool {
        if !self.on {
            *self = Self {
                on: true,
                blk: (seq, end),
            };
            return true;
        }
        sack_extend(&mut self.blk, seq, end);
        false
    }
}

/// Linux tcp_sack_extend: grow `sp` over [`seq`, `end`) if they touch
pub(super) fn sack_extend(sp: &mut (u32, u32), seq: u32, end: u32) -> bool {
    if !after(seq, sp.1) && !after(sp.0, end) {
        if before(seq, sp.0) {
            sp.0 = seq;
        }
        if after(end, sp.1) {
            sp.1 = end;
        }
        return true;
    }
    false
}

impl TcpCb {
    /// Linux tcp_is_sack
    pub(super) fn is_sack(&self) -> bool {
        self.sack_ok != 0
    }

    /// D-SACKs are sent (Linux tcp_is_sack && sysctl_tcp_dsack)
    pub(super) fn dsack_on(&self) -> bool {
        self.is_sack() && self.cfg.dsack
    }

    /// Count a D-SACK started for [`seq`, ..) (Linux tcp_dsack_set's MIB)
    pub(super) fn dsack_count(&self, seq: u32) {
        self.net_stat(if before(seq, self.rcv_nxt) {
            LINUX_MIB_TCPDSACKOLDSENT
        } else {
            LINUX_MIB_TCPDSACKOFOSENT
        });
    }

    /// Linux tcp_dsack_set: report [`seq`, `end`) as a duplicate
    pub(super) fn dsack_set(&mut self, seq: u32, end: u32) {
        if self.dsack_on() {
            self.dsack_count(seq);
            self.dsack = Dsack {
                on: true,
                blk: (seq, end),
            };
        }
    }

    /// Linux tcp_sack_reset
    pub(super) fn sack_reset(&mut self) {
        self.dsack.on = false;
        self.selective_acks.n = 0;
    }

    /// Linux tcp_sack_maybe_coalesce: merge the first block with the
    /// others it now reaches
    fn sack_maybe_coalesce(&mut self) {
        let sp = &mut self.selective_acks;
        let mut i = 1;
        while i < usize::from(sp.n) {
            let (s, e) = sp.b[i];
            if sack_extend(&mut sp.b[0], s, e) {
                sp.n -= 1;
                sp.b.copy_within(i + 1..=usize::from(sp.n), i);
                continue;
            }
            i += 1;
        }
    }

    /// Linux tcp_sack_new_ofo_skb: [`seq`, `end`) arrived out of order:
    /// extend the block it touches and move it first, else start a new
    /// first block (forgetting the last when all four are in use)
    pub(super) fn sack_new_ofo_skb(&mut self, seq: u32, end: u32) {
        let cur = usize::from(self.selective_acks.n);
        if cur == 0 {
            self.selective_acks.n = 1;
            self.selective_acks.b[0] = (seq, end);
            return;
        }
        let sp = &mut self.selective_acks.b;
        for i in 0..cur {
            if sack_extend(&mut sp[i], seq, end) {
                sp[..=i].rotate_right(1);
                if cur > 1 {
                    self.sack_maybe_coalesce();
                }
                return;
            }
        }
        let keep = cur.min(NUM_SACKS - 1);
        sp.copy_within(0..keep, 1);
        sp[0] = (seq, end);
        self.selective_acks.n = (keep + 1) as u8;
    }

    /// Linux tcp_sack_remove: RCV.NXT advanced; blocks it covers go
    pub(super) fn sack_remove(&mut self) {
        if self.ooo.is_empty() {
            self.selective_acks.n = 0;
            return;
        }
        let nxt = self.rcv_nxt;
        let sp = &mut self.selective_acks;
        let mut i = 0;
        while i < usize::from(sp.n) {
            if !before(nxt, sp.b[i].0) {
                sp.n -= 1;
                sp.b.copy_within(i + 1..=usize::from(sp.n), i);
                continue;
            }
            i += 1;
        }
    }

    /// The SACK blocks the next segment carries (Linux
    /// tcp_established_options: num_sacks plus a pending D-SACK, as many
    /// as fit beside the timestamp; tcp_options_write starts at
    /// duplicate_sack when a D-SACK is pending, which sits just before
    /// selective_acks)
    pub(super) fn sack_blocks(&self) -> Sacks {
        let mut out = Sacks::default();
        let eff = usize::from(self.selective_acks.n) + usize::from(self.dsack.on);
        let n = eff.min(self.sack_room());
        let mut src = self.selective_acks.blocks().iter().copied();
        for i in 0..n {
            let blk = if i == 0 && self.dsack.on {
                self.dsack.blk
            } else {
                match src.next() {
                    Some(b) => b,
                    None => break,
                }
            };
            out.push(blk);
        }
        out
    }

    /// Blocks that fit beside the other options of a segment
    fn sack_room(&self) -> usize {
        let remaining = MAX_OPTION_SPACE - self.opt_len();
        if remaining < SACK_BASE + SACK_PERBLOCK {
            return 0;
        }
        ((remaining - SACK_BASE) / SACK_PERBLOCK) as usize
    }

    /// Option bytes the SACK blocks of the next segment take
    fn sack_opt_len(&self) -> u32 {
        let n = self.sack_blocks().n;
        if n == 0 {
            0
        } else {
            SACK_BASE + SACK_PERBLOCK * u32::from(n)
        }
    }

    /// The MSS of the next segment (Linux tcp_current_mss: the cached
    /// MSS less the options beyond the timestamp, i.e. SACK blocks)
    pub(super) fn cur_mss(&self) -> u32 {
        self.live
            .mss
            .get()
            .saturating_sub(self.sack_opt_len())
            .max(super::cb::MSS_MIN)
    }
}

// ============================================================================
// Sender: the SACK scoreboard (Linux tcp_sacktag_write_queue and helpers)
// ============================================================================

/// Per-ACK SACK tagging state (Linux struct tcp_sacktag_state, and the
/// rate sample's prior_delivered from tcp_rate_skb_delivered)
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct SackState {
    /// Send times (us) of the earliest and latest never retransmitted
    /// segment newly SACKed
    pub first_sackt: Option<u64>,
    pub last_sackt: Option<u64>,
    /// Lowest never retransmitted seq SACKed in a hole (reordering)
    pub reord: u32,
    /// Packets newly SACKed, or D-SACKed duplicates
    pub sack_delivered: u32,
    /// Packets cumulatively acknowledged (tcp_clean_rtx_queue's
    /// pkts_acked)
    pub pkts_acked: u32,
    pub flag: u32,
    /// Delivered count when the most recently sent s/acked skb went out,
    /// that skb's send time (us) and end (Linux rs->prior_delivered,
    /// tp->first_tx_mstamp, rs->last_end_seq)
    pub prior_delivered: Option<u32>,
    first_tx_mstamp: u64,
    last_end_seq: u32,
    /// RTTs of this ACK, us, -1 if none (Linux tcp_clean_rtx_queue's
    /// seq_rtt_us, sack_rtt_us, ca_rtt_us)
    pub seq_rtt_us: i64,
    pub ca_rtt_us: i64,
}

/// What tcp_shift_skb_data did
enum Shift {
    /// Nothing could move: tag the skb as it is (NULL)
    Fallback,
    /// Not shifted, nothing to tag here (skb)
    Noop,
    /// Shifted into the skb before, at this seq (prev)
    Moved(u32),
}

/// Linux tcp_skb_sent_after: sent at `t1` (us, ending at `seq1`) after
/// `t2` (`seq2`), the end deciding a tie
pub(super) fn sent_after(t1: u64, t2: u64, seq1: u32, seq2: u32) -> bool {
    t1 > t2 || (t1 == t2 && after(seq1, seq2))
}

impl TcpCb {
    /// Linux tcp_highest_sack_reset
    fn highest_sack_reset(&mut self) {
        self.highest_sack = self.rtx_head();
    }

    /// Linux tcp_advance_highest_sack: the skb after the one at `seq`
    fn advance_highest_sack(&mut self, seq: u32) {
        self.highest_sack = self.rtx_next(seq);
    }

    /// Linux tcp_dsack_seen: a D-SACK of [`start`, `end`); the
    /// duplicates it reports, 0 if dubious (wider than any window, or
    /// more than were ever retransmitted)
    fn dsack_seen(&mut self, start: u32, end: u32, st: &mut SackState) -> u32 {
        if !before(start, end) {
            return 0;
        }
        let len = end.wrapping_sub(start);
        if len > self.max_wnd {
            return 0;
        }
        let mss = self.live.mss.get().max(1);
        let mut dup = 1;
        if len > mss {
            dup = len.div_ceil(mss);
        } else if self.tlp_high_seq == Some(end) {
            st.flag |= flag::DSACK_TLP;
        }
        self.dsack_dups = self.dsack_dups.wrapping_add(dup);
        if self.dsack_dups > self.stats.total_retrans {
            return 0;
        }
        self.sack_ok |= DSACK_SEEN;
        // RACK widens its window for D-SACKs that reordering may have
        // caused (not for TLP probes)
        if self.reord_seen != 0 && st.flag & flag::DSACK_TLP == 0 {
            self.rack.dsack_seen = true;
        }
        st.flag |= flag::DSACKING_ACK;
        st.sack_delivered += dup;
        dup
    }

    /// Linux tcp_check_dsack: is the first block a D-SACK (below the
    /// ACK, or inside the second block)?
    fn check_dsack(
        &mut self,
        ack: u32,
        sp: &[(u32, u32)],
        prior_snd_una: u32,
        st: &mut SackState,
    ) -> bool {
        let (s0, e0) = sp[0];
        if before(s0, ack) {
            self.net_stat(LINUX_MIB_TCPDSACKRECV);
        } else if sp.len() > 1 {
            let (s1, e1) = sp[1];
            if after(e0, e1) || before(s0, s1) {
                return false;
            }
            self.net_stat(LINUX_MIB_TCPDSACKOFORECV);
        } else {
            return false;
        }
        let dup = self.dsack_seen(s0, e0, st);
        if dup == 0 {
            self.net_stat(LINUX_MIB_TCPDSACKIGNOREDDUBIOUS);
            return false;
        }
        self.net_add(LINUX_MIB_TCPDSACKRECVSEGS, u64::from(dup));
        // A D-SACK for data already forgotten: dumb counting
        if let Some(um) = self.undo_marker
            && self.undo_retrans > 0
            && !after(e0, prior_snd_una)
            && after(e0, um)
        {
            self.undo_retrans = (self.undo_retrans - dup as i32).max(0);
        }
        true
    }

    /// Linux tcp_is_sackblock_valid: within SND.UNA..SND.NXT, or a
    /// D-SACK below SND.UNA back to undo_marker (max_window across it)
    fn is_sackblock_valid(&self, is_dsack: bool, start: u32, end: u32) -> bool {
        let nxt = self.snd_max;
        if after(end, nxt) || !before(start, end) || !before(start, nxt) {
            return false;
        }
        if after(start, self.snd_una) {
            return true;
        }
        let Some(um) = self.undo_marker.filter(|_| is_dsack) else {
            return false;
        };
        if after(end, self.snd_una) {
            return false;
        }
        if !before(start, um) {
            return true;
        }
        if !after(end, um) {
            return false;
        }
        !before(start, end.wrapping_sub(self.max_wnd))
    }

    /// Linux tcp_match_skb_to_sack: 1 if the skb at `seq` lies inside
    /// [`start`, `end`), after cutting an skb of several segments at a
    /// segment boundary so that one part does; 0 if not; -1 if the cut
    /// failed
    fn match_skb_to_sack(&mut self, seq: u32, start: u32, end: u32) -> i32 {
        let Some((sseq, send, pc, len, mss)) = self.rtx_with(seq, |s| {
            let t = s.tcp();
            (t.seq, t.end_seq, t.pcount(), s.len() as u32, t.gso_size())
        }) else {
            return 0;
        };
        let mut in_sack = !after(start, sseq) && !before(end, send);
        if pc > 1 && !in_sack && after(send, start) {
            in_sack = !after(start, sseq);
            let mut pkt_len = if !in_sack {
                start.wrapping_sub(sseq).max(mss)
            } else {
                let l = end.wrapping_sub(sseq);
                if l < mss {
                    return -1;
                }
                l
            };
            // Whole segments only, and the small rest if any
            if pkt_len > mss {
                let mut n = pkt_len / mss * mss;
                if !in_sack && n < pkt_len {
                    n += mss;
                }
                pkt_len = n;
            }
            if pkt_len >= len && !in_sack {
                return 0;
            }
            if !self.rtx_fragment(seq, pkt_len as usize, mss) {
                return -1;
            }
        }
        i32::from(in_sack)
    }

    /// Linux tcp_sacktag_one: count the newly SACKed range [`start`,
    /// `end`) of an skb tagged `sacked`; its new tags
    #[expect(clippy::too_many_arguments)]
    fn sacktag_one(
        &mut self,
        st: &mut SackState,
        mut sacked: u8,
        start: u32,
        end: u32,
        dup_sack: bool,
        pcount: u32,
        xmit: u64,
    ) -> u8 {
        // A D-SACK of a retransmission
        if dup_sack && sacked & tag::RETRANS != 0 {
            if let Some(um) = self.undo_marker
                && self.undo_retrans > 0
                && after(end, um)
            {
                self.undo_retrans = (self.undo_retrans - pcount as i32).max(0);
            }
            if sacked & tag::SACKED_ACKED != 0 && before(start, st.reord) {
                st.reord = start;
            }
        }
        // About to be dropped: cumulatively acked
        if !after(end, self.snd_una) {
            return sacked;
        }
        if sacked & tag::SACKED_ACKED == 0 {
            self.rack_advance(sacked, end, xmit);
            if sacked & tag::SACKED_RETRANS != 0 {
                // Not lost: the retransmission is still believed in flight
                if sacked & tag::LOST != 0 {
                    sacked &= !(tag::LOST | tag::SACKED_RETRANS);
                    self.lost_out = self.lost_out.saturating_sub(pcount);
                    self.retrans_out = self.retrans_out.saturating_sub(pcount);
                }
            } else {
                if sacked & tag::RETRANS == 0 {
                    // Never retransmitted, in a hole: reordering
                    if before(start, self.highest_sack_seq()) && before(start, st.reord) {
                        st.reord = start;
                    }
                    if !after(end, self.high_seq) {
                        st.flag |= flag::ORIG_SACK_ACKED;
                    }
                    if st.first_sackt.is_none() {
                        st.first_sackt = Some(xmit);
                    }
                    st.last_sackt = Some(xmit);
                }
                if sacked & tag::LOST != 0 {
                    sacked &= !tag::LOST;
                    self.lost_out = self.lost_out.saturating_sub(pcount);
                }
            }
            sacked |= tag::SACKED_ACKED;
            st.flag |= flag::DATA_SACKED;
            self.sacked_out += pcount;
            st.sack_delivered += pcount;
        }
        // D-SACK: a redundant retransmission (S|R, plain R) is over
        if dup_sack && sacked & tag::SACKED_RETRANS != 0 {
            sacked &= !tag::SACKED_RETRANS;
            self.retrans_out = self.retrans_out.saturating_sub(pcount);
        }
        sacked
    }

    /// Linux tcp_rate_skb_delivered (its prior_delivered part): the skb
    /// at `seq` was s/acked; a SACKed one counts once
    pub(super) fn rate_skb_delivered(&mut self, st: &mut SackState, seq: u32) {
        let Some((t, tx)) = self.rtx_with(seq, |s| (s.tcp(), skb_mstamp_us(s))) else {
            return;
        };
        if t.tx_delivered_mstamp == 0 {
            return;
        }
        if st.prior_delivered.is_none()
            || sent_after(tx, st.first_tx_mstamp, t.end_seq, st.last_end_seq)
        {
            st.prior_delivered = Some(t.tx_delivered);
            st.first_tx_mstamp = tx;
            st.last_end_seq = t.end_seq;
        }
        // A SACKed skb's delivery is counted once
        if t.sacked & tag::SACKED_ACKED != 0 {
            self.rtx_with(seq, |s| s.tcp_mut().tx_delivered_mstamp = 0);
        }
    }

    /// Move `len` bytes, `pcount` segments, from the head of the skb at
    /// `skb` to the end of the one at `prev` (Linux tcp_skb_shift:
    /// skb_shift moves pages and their truesize; hk's skbs are linear,
    /// so the bytes are copied into `prev`'s buffer, grown for them,
    /// and `skb`'s is fitted to what is left), then account for them
    /// (tcp_shifted_skb). Returns true if `skb` was eaten whole; None if
    /// nothing moved.
    #[expect(clippy::too_many_arguments)]
    fn shift(
        &mut self,
        prev: u32,
        skb: u32,
        st: &mut SackState,
        pcount: u32,
        len: u32,
        mss: u32,
        dup_sack: bool,
    ) -> Option<bool> {
        let (ppc, plen) = self.rtx_with(prev, |p| (p.tcp().pcount(), p.len()))?;
        if plen + len as usize >= 65535 * 8 || ppc + pcount > 65535 {
            return None;
        }
        let frag = super::output::FRAG;
        self.rtx_with(prev, |p| {
            p.grow(len as usize, frag, usize::MAX, Gfp::ATOMIC)
        })??;
        // Linux tcp_shifted_skb: tag the range first (seq advancing
        // moves tcp_highest_sack_seq along when skb is highest_sack)
        let (t, tx) = self.rtx_with(skb, |s| (s.tcp(), skb_mstamp_us(s)))?;
        self.sacktag_one(
            st,
            t.sacked,
            t.seq,
            t.seq.wrapping_add(len),
            dup_sack,
            pcount,
            tx,
        );
        self.rate_skb_delivered(st, skb);
        let mut c = self.rtx.cursor_floor_mut(|s| !after(s.tcp().seq, skb));
        let mut s = c.remove_current()?;
        let fin = s.tcp().has(flags::FIN);
        self.rtx_with(prev, |p| {
            let _ = p.put_slice(&s.data()[..len as usize]);
            p.set_truesize(p.truesize() + len as usize);
            let pt = p.tcp_mut();
            pt.end_seq = pt.end_seq.wrapping_add(len);
            pt.set_pcount(pt.pcount() + pcount);
            if pt.gso_size() == 0 {
                pt.set_gso_size(mss);
            }
            pt.sacked |= t.sacked & tag::EVER_RETRANS;
        });
        let _ = s.pull(len as usize);
        s.set_truesize(s.truesize().saturating_sub(len as usize));
        s.compact(TX_HEADROOM, frag, Gfp::ATOMIC);
        let new_seq = t.seq.wrapping_add(len);
        if !s.is_empty() {
            let st_ = s.tcp_mut();
            st_.seq = new_seq;
            st_.set_pcount(st_.pcount() - pcount.min(st_.pcount()));
            if st_.pcount() <= 1 {
                st_.set_gso_size(0);
            }
            self.rtx
                .insert_by(s, |a, b| before(a.tcp().seq, b.tcp().seq));
            if self.highest_sack == Some(skb) {
                self.highest_sack = Some(new_seq);
            }
            if self.rtx_hint == Some(skb) {
                self.rtx_hint = Some(new_seq);
            }
            self.net_stat(LINUX_MIB_SACKSHIFTED);
            return Some(false);
        }
        // Whole skb eaten
        if self.rtx_hint == Some(skb) {
            self.rtx_hint = Some(prev);
        }
        self.rtx_with(prev, |p| {
            let pt = p.tcp_mut();
            pt.flags |= t.flags;
            if fin {
                pt.end_seq = pt.end_seq.wrapping_add(1);
            }
        });
        if self.highest_sack == Some(skb) {
            self.advance_highest_sack(prev);
        }
        self.wmem_free(s);
        self.net_stat(LINUX_MIB_SACKMERGED);
        Some(true)
    }

    /// Linux tcp_shift_skb_data: SACKed bytes of the skb at `skb` join
    /// the SACKed skb before it, so the queue stays short
    fn shift_skb_data(
        &mut self,
        skb: u32,
        st: &mut SackState,
        start: u32,
        end: u32,
        dup_sack: bool,
    ) -> Shift {
        let fallback = |c: &Self| {
            c.net_stat(LINUX_MIB_SACKSHIFTFALLBACK);
            Shift::Fallback
        };
        let Some((t, slen, sseglen)) = self.rtx_with(skb, |s| (s.tcp(), s.len() as u32, seglen(s)))
        else {
            return fallback(self);
        };
        // Normally R without L does not become plain S
        if !dup_sack && t.sacked & (tag::LOST | tag::SACKED_RETRANS) == tag::SACKED_RETRANS {
            return fallback(self);
        }
        if !after(t.end_seq, self.snd_una) {
            return fallback(self);
        }
        let prev = {
            let mut c = self.rtx.cursor_floor_mut(|s| !after(s.tcp().seq, skb));
            c.move_prev();
            c.current().map(|p| {
                (
                    p.tcp().seq,
                    p.tcp().sacked,
                    seglen(p),
                    p.tcp().has(flags::FIN),
                )
            })
        };
        let Some((prev, psacked, pseglen, pfin)) = prev else {
            return fallback(self);
        };
        if psacked & tag::TAGBITS != tag::SACKED_ACKED || pfin {
            return fallback(self);
        }
        let in_sack = !after(start, t.seq) && !before(end, t.end_seq);
        let (len, pcount, mss);
        if in_sack {
            len = slen;
            pcount = t.pcount();
            mss = sseglen;
            if mss != pseglen {
                return fallback(self);
            }
        } else {
            if !after(t.end_seq, start) || t.pcount() <= 1 {
                return Shift::Noop;
            }
            if after(start, t.seq) {
                return fallback(self);
            }
            let l = end.wrapping_sub(t.seq);
            mss = t.gso_size();
            if mss != pseglen {
                return fallback(self);
            }
            if l == mss {
                pcount = 1;
                len = l;
            } else if l < mss {
                return Shift::Noop;
            } else {
                pcount = l / mss;
                len = pcount * mss;
            }
        }
        // tcp_sacktag_one() won't SACK-tag ranges below snd_una
        if !after(t.seq.wrapping_add(len), self.snd_una) {
            return fallback(self);
        }
        match self.shift(prev, skb, st, pcount, len, mss, dup_sack) {
            None => return fallback(self),
            Some(false) => return Shift::Moved(prev),
            Some(true) => {}
        }
        // A hole filled: the next may join as well
        let Some(next) = self.rtx_next(prev) else {
            return Shift::Moved(prev);
        };
        let Some((ns, nlen, npc, nseglen)) = self.rtx_with(next, |s| {
            (s.tcp().sacked, s.len() as u32, s.tcp().pcount(), seglen(s))
        }) else {
            return Shift::Moved(prev);
        };
        if ns & tag::TAGBITS != tag::SACKED_ACKED || mss != nseglen {
            return Shift::Moved(prev);
        }
        let _ = self.shift(prev, next, st, npc, nlen, mss, false);
        Shift::Moved(prev)
    }

    /// Linux tcp_sacktag_walk: tag the skbs from `skb` that
    /// [`start`, `end`) covers (and those `next_dup` covers, as
    /// D-SACKed); the skb the walk stopped at
    fn sacktag_walk(
        &mut self,
        mut skb: Option<u32>,
        next_dup: Option<(u32, u32)>,
        st: &mut SackState,
        start: u32,
        end: u32,
        dup_in: bool,
    ) -> Option<u32> {
        while let Some(cur) = skb {
            let seq = self.rtx_with(cur, |s| s.tcp().seq)?;
            if !before(seq, end) {
                break;
            }
            let mut in_sack = 0;
            let mut dup = dup_in;
            if let Some((ds, de)) = next_dup
                && before(seq, de)
            {
                in_sack = self.match_skb_to_sack(cur, ds, de);
                if in_sack > 0 {
                    dup = true;
                }
            }
            if in_sack <= 0 {
                match self.shift_skb_data(cur, st, start, end, dup) {
                    Shift::Moved(prev) => {
                        skb = self.rtx_next(prev);
                        continue;
                    }
                    Shift::Noop => in_sack = 0,
                    Shift::Fallback => in_sack = self.match_skb_to_sack(cur, start, end),
                }
            }
            if in_sack < 0 {
                break;
            }
            if in_sack > 0 {
                let Some((t, tx)) = self.rtx_with(cur, |s| (s.tcp(), skb_mstamp_us(s))) else {
                    break;
                };
                let sacked = self.sacktag_one(st, t.sacked, t.seq, t.end_seq, dup, t.pcount(), tx);
                self.rtx_with(cur, |s| s.tcp_mut().sacked = sacked);
                self.rate_skb_delivered(st, cur);
                if !before(t.seq, self.highest_sack_seq()) {
                    self.advance_highest_sack(cur);
                }
            }
            skb = self.rtx_next(cur);
        }
        skb
    }

    /// Linux tcp_sacktag_bsearch: the skb holding `seq`
    fn sacktag_bsearch(&mut self, seq: u32) -> Option<u32> {
        let c = self.rtx.cursor_floor_mut(|s| !after(s.tcp().seq, seq));
        c.current()
            .filter(|s| before(seq, s.tcp().end_seq))
            .map(|s| s.tcp().seq)
    }

    /// Linux tcp_sacktag_skip: `skb` if it lies beyond `seq`, else the
    /// skb holding `seq`
    fn sacktag_skip(&mut self, skb: Option<u32>, seq: u32) -> Option<u32> {
        if let Some(s) = skb
            && after(s, seq)
        {
            return skb;
        }
        self.sacktag_bsearch(seq)
    }

    /// Linux tcp_maybe_skipping_dsack
    fn maybe_skipping_dsack(
        &mut self,
        skb: Option<u32>,
        next_dup: Option<(u32, u32)>,
        st: &mut SackState,
        skip_to: u32,
    ) -> Option<u32> {
        let Some((ds, de)) = next_dup else {
            return skb;
        };
        if before(ds, skip_to) {
            let skb = self.sacktag_skip(skb, ds);
            return self.sacktag_walk(skb, None, st, ds, de, true);
        }
        skb
    }

    /// Linux tcp_sacktag_write_queue: tag the retransmit queue with the
    /// SACK blocks of an ACK of `ack`; the FLAG_* bits it sets
    pub(super) fn sacktag_write_queue(
        &mut self,
        ack: u32,
        blocks: &[(u32, u32)],
        prior_snd_una: u32,
        st: &mut SackState,
    ) -> u32 {
        st.flag = 0;
        st.reord = self.snd_max;
        if self.sacked_out == 0 {
            self.highest_sack_reset();
        }
        let found_dup = self.check_dsack(ack, blocks, prior_snd_una, st);
        // Too old an ACK (its SACK info may still be fresh otherwise)
        if before(ack, prior_snd_una.wrapping_sub(self.max_wnd)) {
            return 0;
        }
        if self.packets_out == 0 {
            return st.flag;
        }
        let mut sp = [(0u32, 0u32); NUM_SACKS];
        let mut used = 0;
        let mut first_idx: isize = 0;
        for (i, &(s, e)) in blocks.iter().enumerate() {
            let dup = i == 0 && found_dup;
            if !self.is_sackblock_valid(dup, s, e) {
                let mib = if dup {
                    if self.undo_marker.is_none() {
                        LINUX_MIB_TCPDSACKIGNOREDNOUNDO
                    } else {
                        LINUX_MIB_TCPDSACKIGNOREDOLD
                    }
                } else {
                    // Old blocks of a reordered ACK are not counted
                    if ack != self.snd_una && !after(e, self.snd_una) {
                        continue;
                    }
                    LINUX_MIB_TCPSACKDISCARD
                };
                self.net_stat(mib);
                if i == 0 {
                    first_idx = -1;
                }
                continue;
            }
            // Ignore very old stuff early
            if !after(e, prior_snd_una) {
                if i == 0 {
                    first_idx = -1;
                }
                continue;
            }
            sp[used] = (s, e);
            used += 1;
        }
        // Order the blocks for an in-order walk of the queue
        for i in (1..used).rev() {
            for j in 0..i {
                if after(sp[j].0, sp[j + 1].0) {
                    sp.swap(j, j + 1);
                    if j as isize == first_idx {
                        first_idx = j as isize + 1;
                    }
                }
            }
        }
        let cache_n = self.recv_sack_cache.len();
        let mut cache = if self.sacked_out == 0 {
            cache_n
        } else {
            let mut c = 0;
            while c < cache_n && self.recv_sack_cache[c] == (0, 0) {
                c += 1;
            }
            c
        };
        let mut skb: Option<u32> = None;
        let mut i = 0;
        while i < used {
            let (start, end) = sp[i];
            let dup = found_dup && i as isize == first_idx;
            let next_dup = (found_dup && (i + 1) as isize == first_idx).then(|| sp[i + 1]);
            // Skip too early cached blocks
            while cache < cache_n && !before(start, self.recv_sack_cache[cache].1) {
                cache += 1;
            }
            let mut walk_from = None;
            if cache < cache_n && !dup && after(end, self.recv_sack_cache[cache].0) {
                let (cs, ce) = self.recv_sack_cache[cache];
                // Head to do?
                if before(start, cs) {
                    skb = self.sacktag_skip(skb, start);
                    skb = self.sacktag_walk(skb, next_dup, st, start, cs, dup);
                }
                // Rest of the block already processed?
                if !after(end, ce) {
                    i += 1;
                    continue;
                }
                skb = self.maybe_skipping_dsack(skb, next_dup, st, ce);
                // ...the tail remains to do
                if self.highest_sack_seq() == ce {
                    // ...but a better entry point exists
                    skb = self.highest_sack;
                    if skb.is_none() {
                        break;
                    }
                    cache += 1;
                    walk_from = skb;
                } else {
                    skb = self.sacktag_skip(skb, ce);
                    cache += 1;
                    continue;
                }
            }
            if walk_from.is_none() {
                if !before(start, self.highest_sack_seq()) {
                    skb = self.highest_sack;
                    if skb.is_none() {
                        break;
                    }
                }
                skb = self.sacktag_skip(skb, start);
            }
            skb = self.sacktag_walk(skb, next_dup, st, start, end, dup);
            i += 1;
        }
        // The cache keeps this ACK's blocks, at its end
        let keep = cache_n - used;
        for c in &mut self.recv_sack_cache[..keep] {
            *c = (0, 0);
        }
        self.recv_sack_cache[keep..].copy_from_slice(&sp[..used]);
        if self.ca_state != CaState::Loss || self.undo_marker.is_some() {
            self.check_sack_reordering(st.reord, false);
        }
        st.flag
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cb() -> TcpCb {
        let mut c = TcpCb::new(Default::default(), Default::default());
        c.sack_ok = super::super::cb::SACK_SEEN;
        c.ts_ok = true;
        c
    }

    /// The newest block first; touching ones merge; at most four kept
    #[test]
    fn ofo_blocks() {
        let mut c = cb();
        c.sack_new_ofo_skb(100, 200);
        c.sack_new_ofo_skb(300, 400);
        c.sack_new_ofo_skb(500, 600);
        assert_eq!(
            c.selective_acks.blocks(),
            &[(500, 600), (300, 400), (100, 200)]
        );
        // Extending an older block moves it first
        c.sack_new_ofo_skb(400, 450);
        assert_eq!(
            c.selective_acks.blocks(),
            &[(300, 450), (500, 600), (100, 200)]
        );
        // Filling the gap merges two blocks
        c.sack_new_ofo_skb(450, 500);
        assert_eq!(c.selective_acks.blocks(), &[(300, 600), (100, 200)]);
        for k in 0..4 {
            c.sack_new_ofo_skb(1000 + k * 100, 1050 + k * 100);
        }
        assert_eq!(
            c.selective_acks.blocks(),
            &[(1300, 1350), (1200, 1250), (1100, 1150), (1000, 1050)]
        );
        // With timestamps three fit; a D-SACK goes first
        assert_eq!(c.sack_blocks().blocks(), &c.selective_acks.b[..3]);
        c.dsack = Dsack {
            on: true,
            blk: (5, 6),
        };
        assert_eq!(
            c.sack_blocks().blocks(),
            &[(5, 6), (1300, 1350), (1200, 1250)]
        );
        c.ts_ok = false;
        assert_eq!(c.sack_blocks().n, 4);
    }

    #[test]
    fn dsack_extend_only_touching() {
        let mut d = Dsack::default();
        assert!(d.extend(10, 20));
        assert!(!d.extend(20, 30));
        assert!(!d.extend(50, 60));
        assert_eq!(d.blk, (10, 30));
    }
}

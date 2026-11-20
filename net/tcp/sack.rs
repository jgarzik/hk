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

use super::cb::{TcpCb, after, before};
use super::output::{SACK_BASE, SACK_PERBLOCK};
use crate::net::mib::*;
use crate::net::skb::{NUM_SACKS, Sacks};

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

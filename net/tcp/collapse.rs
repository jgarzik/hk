//! Receive queue collapsing (Linux tcp_input.c tcp_collapse,
//! tcp_collapse_ofo_queue: tcp_prune_queue's first, non-destructive
//! half), I/O-free
//!
//! Under receive memory pressure the receive queue (from copied_seq to
//! RCV.NXT) and each contiguous range of the out-of-order queue are
//! copied into compact skbs of up to `COLLAPSE_MAX` bytes, freeing the
//! bloated ones (an skb whose truesize is worth more window than the
//! bytes it holds) and the bytes already read or duplicated; each freed
//! skb counts TCPRcvCollapsed. Skbs with SYN or FIN are never collapsed.
//! A failed GFP_ATOMIC allocation stops it, nothing lost.

use alloc::boxed::Box;

use super::buf::win_from_space;
use super::cb::{TcpCb, before, flags};
use crate::mm::page_alloc::Gfp;
use crate::net::mib::LINUX_MIB_TCPRCVCOLLAPSED;
use crate::net::skb::{SkBuff, SkbHead};

/// Bytes of one collapsed skb (Linux SKB_MAX_ORDER(0, 0): a page less
/// the shared info)
const COLLAPSE_MAX: usize = 4096 - 320;

/// Linux SKB_WITH_OVERHEAD(PAGE_SIZE): a range at least this long is
/// collapsed even when it is one skb
const PAGE_WITH_OVERHEAD: u32 = 4096 - 320;

type Queue = SkbHead<Box<SkBuff>>;

/// `skb`'s payload end
fn data_end(skb: &SkBuff) -> u32 {
    skb.tcp().seq.wrapping_add(skb.len() as u32)
}

/// SYN or FIN: not collapsed ("only because this simplifies code")
fn syn_fin(skb: &SkBuff) -> bool {
    skb.tcp().flags & (flags::SYN | flags::FIN) != 0
}

/// Linux tcp_collapse over `q` (skbs in sequence order, the bytes
/// [`start`, `end`) wanted), the result appended to `keep` in order;
/// returns the skbs freed and the truesize gone and made. `ratio`: the
/// connection's scaling ratio (tcp_win_from_space). Skbs it does not
/// copy are moved as they are, never reallocated.
fn collapse(q: &mut Queue, mut start: u32, end: u32, keep: &mut Queue, ratio: u8) -> Collapsed {
    let mut c = Collapsed::default();
    // First, the point where collapsing can be useful
    loop {
        let Some(skb) = q.front() else {
            return c;
        };
        if !before(start, data_end(skb)) {
            // No new bits
            c.drop(q.pop_front());
            continue;
        }
        let next_gap = q
            .iter()
            .nth(1)
            .is_some_and(|n| data_end(skb) != n.tcp().seq);
        let useful = !syn_fin(skb)
            && (win_from_space(ratio, skb.truesize() as i64) > skb.len() as i64
                || before(skb.tcp().seq, start));
        if useful || next_gap {
            break;
        }
        start = data_end(skb);
        if let Some(s) = q.pop_front() {
            keep.push_back(s);
        }
    }
    if q.front().is_some_and(syn_fin) {
        while let Some(s) = q.pop_front() {
            keep.push_back(s);
        }
        return c;
    }
    'copy: while before(start, end) {
        let Some(head) = q.front() else {
            break;
        };
        let mut copy = COLLAPSE_MAX.min(end.wrapping_sub(start) as usize);
        let Some(mut nskb) = SkBuff::alloc(0, copy, Gfp::ATOMIC) else {
            break;
        };
        let mut t = head.tcp();
        t.seq = start;
        t.end_seq = start;
        *nskb.tcp_mut() = t;
        c.made += nskb.truesize();
        while copy > 0 {
            let Some(skb) = q.front() else {
                break;
            };
            let off = start.wrapping_sub(skb.tcp().seq) as usize;
            let size = data_end(skb).wrapping_sub(start) as i32;
            if size > 0 {
                let size = copy.min(size as usize);
                if nskb.put_slice(&skb.data()[off..off + size]).is_none() {
                    break;
                }
                let c = nskb.tcp_mut();
                c.end_seq = c.end_seq.wrapping_add(size as u32);
                copy -= size;
                start = start.wrapping_add(size as u32);
            }
            if !before(start, data_end(skb)) {
                c.drop(q.pop_front());
                if q.front().is_none_or(syn_fin) {
                    keep.push_back(nskb);
                    break 'copy;
                }
            }
        }
        keep.push_back(nskb);
    }
    while let Some(s) = q.pop_front() {
        keep.push_back(s);
    }
    c
}

/// What a collapse did: skbs freed, their truesize, the new skbs'
#[derive(Default)]
struct Collapsed {
    freed: u64,
    gone: usize,
    made: usize,
}

impl Collapsed {
    /// An skb freed (Linux tcp_collapse_one)
    fn drop(&mut self, s: Option<Box<SkBuff>>) {
        if let Some(s) = s {
            self.freed += 1;
            self.gone += s.truesize();
        }
    }
}

impl TcpCb {
    /// Collapse the receive queue (Linux tcp_prune_queue: tcp_collapse
    /// of sk_receive_queue from copied_seq to rcv_nxt)
    pub(super) fn collapse_rcvq(&mut self) {
        let mut q = core::mem::take(&mut self.rcvq);
        let mut keep = Queue::new();
        let c = collapse(
            &mut q,
            self.copied_seq,
            self.rcv_nxt,
            &mut keep,
            self.scaling_ratio,
        );
        // sk_rmem_alloc follows the skbs freed and made
        self.rcvq_truesize = self.rcvq_truesize - c.gone + c.made;
        self.rcvq = keep;
        self.net_add(LINUX_MIB_TCPRCVCOLLAPSED, c.freed);
    }

    /// Linux tcp_collapse_ofo_queue: walk the out-of-order queue in
    /// place range by range; a range of more than one skb, or of at
    /// least a page, is collapsed (only its own nodes replaced); a tiny
    /// one is left, and once the tiny ones add up to an eighth of the
    /// receive buffer the walk stops, the rest of the tree untouched
    pub(super) fn collapse_ofo(&mut self) {
        let rcvbuf = self.rcvbuf as usize;
        let ratio = self.scaling_ratio;
        let (mut sum_tiny, mut freed) = (0, 0);
        let mut from = None;
        while let Some(r) = self.ooo.range_after(from) {
            if r.truesize != r.head_truesize || r.end.wrapping_sub(r.start) >= PAGE_WITH_OVERHEAD {
                let mut range = self.ooo.take_range(&r);
                let mut keep = Queue::new();
                freed += collapse(&mut range, r.start, r.end, &mut keep, ratio).freed;
                self.ooo.put_all(keep);
            } else {
                sum_tiny += r.truesize;
                if sum_tiny > rcvbuf >> 3 {
                    break;
                }
            }
            from = Some(r.end);
        }
        self.net_add(LINUX_MIB_TCPRCVCOLLAPSED, freed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// tcp_win_from_space at half: the old default
    const RATIO: u8 = 128;

    /// `len` bytes at `seq` in an skb with `room` bytes spare
    fn skb(seq: u32, len: usize, room: usize) -> Box<SkBuff> {
        let mut s = SkBuff::alloc(0, len + room, Gfp::KERNEL).unwrap();
        s.put_slice(&alloc::vec![seq as u8; len]).unwrap();
        let t = s.tcp_mut();
        t.seq = seq;
        t.end_seq = seq + len as u32;
        s
    }

    fn queue(v: impl IntoIterator<Item = Box<SkBuff>>) -> Queue {
        let mut q = Queue::new();
        for s in v {
            q.push_back(s);
        }
        q
    }

    /// Bloated skbs and the bytes before `start` are copied into one
    /// compact skb; the bytes stay in order; a FIN skb ends it
    #[test]
    fn collapse_bloated() {
        let mut q = queue([skb(100, 10, 2000), skb(110, 10, 2000), skb(120, 10, 2000)]);
        let mut keep = Queue::new();
        let n = collapse(&mut q, 105, 130, &mut keep, RATIO).freed;
        assert_eq!(n, 3);
        let v: alloc::vec::Vec<_> = keep.iter().map(|s| (s.tcp().seq, s.len())).collect();
        assert_eq!(v, [(105, 25)]);
        let d = keep.front().unwrap().data();
        assert!(d[..5].iter().all(|&b| b == 100) && d[5..15].iter().all(|&b| b == 110));
        // A FIN skb stays as it is
        let mut fin = skb(130, 10, 2000);
        fin.tcp_mut().flags = flags::FIN;
        let mut q = queue([skb(120, 10, 2000), fin]);
        let mut keep = Queue::new();
        assert_eq!(collapse(&mut q, 120, 140, &mut keep, RATIO).freed, 1);
        let v: alloc::vec::Vec<_> = keep.iter().map(|s| (s.tcp().seq, s.len())).collect();
        assert_eq!(v, [(120, 10), (130, 10)]);
    }

    /// The out-of-order queue's contiguous ranges collapse into compact
    /// skbs (fewer pieces, the same bytes, TCPRcvCollapsed), a range of
    /// one short skb stays; the receive queue from copied_seq likewise
    #[test]
    fn collapse_queues() {
        use crate::net::mib::NetMib;
        let mut cb = TcpCb::new(super::super::cb::Cfg::default(), Default::default());
        let mib = NetMib::new().unwrap();
        cb.mib = Some(mib.clone());
        cb.rcv_nxt = 1000;
        cb.copied_seq = 990;
        for i in 0..8 {
            cb.ooo.insert(skb(2000 + i * 100, 100, 1500), None);
        }
        cb.ooo.insert(skb(5000, 100, 1500), None);
        let bytes = cb.ooo.bytes();
        cb.collapse_ofo();
        assert_eq!(cb.ooo.pieces(), 2);
        assert_eq!(cb.ooo.bytes(), bytes);
        assert_eq!(mib.net.fold(LINUX_MIB_TCPRCVCOLLAPSED), 8);
        for q in [skb(980, 10, 1500), skb(990, 10, 1500)] {
            cb.rcvq_truesize += q.truesize();
            cb.rcvq.push_back(q);
        }
        cb.collapse_rcvq();
        assert_eq!(cb.rcvq.len(), 1);
        let f = cb.rcvq.front().unwrap();
        assert_eq!((f.tcp().seq, f.len()), (990, 10));
        assert_eq!(cb.rcvq_truesize, f.truesize());
    }

    /// The walk stops once tiny ranges reach an eighth of the buffer:
    /// a collapsible range after that point is left as it was, its
    /// skbs the same allocations (Linux tcp_collapse_ofo_queue's early
    /// return), while one before it is collapsed
    #[test]
    fn collapse_ofo_stops_early() {
        let mut cb = TcpCb::new(super::super::cb::Cfg::default(), Default::default());
        cb.rcvbuf = 64 * 1024;
        cb.rcv_nxt = 1000;
        cb.copied_seq = 1000;
        // A collapsible range, then tiny lone skbs past the budget,
        // then another collapsible range
        for i in 0..4 {
            cb.ooo.insert(skb(2000 + i * 10, 10, 1500), None);
        }
        let mut seq = 10_000;
        for _ in 0..64 {
            cb.ooo.insert(skb(seq, 10, 1500), None);
            seq += 100;
        }
        let tail: alloc::vec::Vec<u32> = (0..4).map(|i| seq + 1000 + i * 10).collect();
        for &t in &tail {
            cb.ooo.insert(skb(t, 10, 1500), None);
        }
        let ids = |cb: &mut TcpCb| -> alloc::vec::Vec<(u32, usize)> {
            let r = cb.ooo.range_after(Some(seq)).unwrap();
            let q = cb.ooo.take_range(&r);
            let v = q
                .iter()
                .map(|s| (s.tcp().seq, core::ptr::from_ref(s).addr()))
                .collect();
            cb.ooo.put_all(q);
            v
        };
        let before = ids(&mut cb);
        let pieces = cb.ooo.pieces();
        cb.collapse_ofo();
        // The first range became one skb; the last is untouched
        assert_eq!(cb.ooo.pieces(), pieces - 3);
        assert_eq!(ids(&mut cb), before);
    }

    /// Compact skbs are left alone
    #[test]
    fn collapse_compact_untouched() {
        let mut q = queue([skb(100, 1000, 0), skb(1100, 1000, 0)]);
        let mut keep = Queue::new();
        assert_eq!(collapse(&mut q, 100, 2100, &mut keep, RATIO).freed, 0);
        assert_eq!(keep.len(), 2);
    }
}

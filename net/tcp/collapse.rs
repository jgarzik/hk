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
use super::cb::{TcpCb, after, before, flags};
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
/// returns the skbs freed. `ratio`: the connection's scaling ratio
/// (tcp_win_from_space)
fn collapse(q: &mut Queue, mut start: u32, end: u32, keep: &mut Queue, ratio: u8) -> u64 {
    let mut freed = 0;
    // First, the point where collapsing can be useful
    loop {
        let Some(skb) = q.front() else {
            return freed;
        };
        if !before(start, data_end(skb)) {
            // No new bits
            drop(q.pop_front());
            freed += 1;
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
        return freed;
    }
    'copy: while before(start, end) {
        let Some(head) = q.front() else {
            break;
        };
        let mut copy = COLLAPSE_MAX.min(end.wrapping_sub(start) as usize);
        let Some(mut nskb) = SkBuff::alloc(0, copy, Gfp::ATOMIC) else {
            break;
        };
        let mut cb = head.tcp();
        cb.seq = start;
        cb.end_seq = start;
        *nskb.tcp_mut() = cb;
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
                drop(q.pop_front());
                freed += 1;
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
    freed
}

impl TcpCb {
    /// Collapse the receive queue (Linux tcp_prune_queue: tcp_collapse
    /// of sk_receive_queue from copied_seq to rcv_nxt)
    pub(super) fn collapse_rcvq(&mut self) {
        let mut q = core::mem::take(&mut self.rcvq);
        let mut keep = Queue::new();
        let n = collapse(
            &mut q,
            self.copied_seq,
            self.rcv_nxt,
            &mut keep,
            self.scaling_ratio,
        );
        // sk_rmem_alloc follows the skbs freed and made
        self.rcvq_truesize = keep.iter().map(|s| s.truesize()).sum();
        self.rcvq = keep;
        self.net_add(LINUX_MIB_TCPRCVCOLLAPSED, n);
    }

    /// Linux tcp_collapse_ofo_queue: each contiguous (or overlapping)
    /// range of the out-of-order queue is collapsed, unless it is one
    /// skb shorter than a page; tiny ranges stop the walk once they add
    /// up to an eighth of the receive buffer
    pub(super) fn collapse_ofo(&mut self) {
        let mut all = self.ooo.take_all();
        let mut keep = Queue::new();
        let rcvbuf = self.rcvbuf as usize;
        let mut sum_tiny = 0;
        let mut freed = 0;
        while let Some(first) = all.pop_front() {
            let (mut start, mut end) = (first.tcp().seq, data_end(&first));
            let head_true = first.truesize();
            let mut range_true = head_true;
            let mut range = Queue::new();
            range.push_back(first);
            while let Some(n) = all.front() {
                if after(n.tcp().seq, end) || before(data_end(n), start) {
                    break;
                }
                range_true += n.truesize();
                if before(n.tcp().seq, start) {
                    start = n.tcp().seq;
                }
                if after(data_end(n), end) {
                    end = data_end(n);
                }
                if let Some(n) = all.pop_front() {
                    range.push_back(n);
                }
            }
            if range_true != head_true || end.wrapping_sub(start) >= PAGE_WITH_OVERHEAD {
                freed += collapse(&mut range, start, end, &mut keep, self.scaling_ratio);
            } else {
                while let Some(s) = range.pop_front() {
                    keep.push_back(s);
                }
                sum_tiny += range_true;
                if sum_tiny > rcvbuf >> 3 {
                    break;
                }
            }
        }
        while let Some(s) = all.pop_front() {
            keep.push_back(s);
        }
        self.ooo.put_all(keep);
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
        let n = collapse(&mut q, 105, 130, &mut keep, RATIO);
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
        assert_eq!(collapse(&mut q, 120, 140, &mut keep, RATIO), 1);
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
        cb.rcvq.push_back(skb(980, 10, 1500));
        cb.rcvq.push_back(skb(990, 10, 1500));
        cb.collapse_rcvq();
        assert_eq!(cb.rcvq.len(), 1);
        let f = cb.rcvq.front().unwrap();
        assert_eq!((f.tcp().seq, f.len()), (990, 10));
    }

    /// Compact skbs are left alone
    #[test]
    fn collapse_compact_untouched() {
        let mut q = queue([skb(100, 1000, 0), skb(1100, 1000, 0)]);
        let mut keep = Queue::new();
        assert_eq!(collapse(&mut q, 100, 2100, &mut keep, RATIO), 0);
        assert_eq!(keep.len(), 2);
    }
}

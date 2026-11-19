//! IPv4 reassembly (Linux net/ipv4/ip_fragment.c, inet_fragment.c)
//!
//! Fragments of a datagram (keyed by source, destination, id and
//! protocol) collect in a [`FragQueue`] until the first and last pieces
//! are in and the payload has no holes. As Linux, each queue is an
//! object of its own (struct inet_frag_queue): found in a hash table
//! under RCU, made GFP_ATOMIC on the first fragment, with its own lock,
//! its own expiry timer, and the fragments themselves (the received
//! skbs, nothing copied) in an rbtree by offset. Peer-reachable, so
//! everything is bounded like Linux:
//! - memory: fragments are charged to the namespace; above
//!   `ipfrag_high_thresh` new fragments are dropped (Linux
//!   inet_frag_find); queues die after `ipfrag_time` (30 s), sending
//!   ICMP time exceeded (reassembly) when the first fragment was in;
//! - overlap: a fragment overlapping another kills the whole queue
//!   (RFC 5722 style, Linux IPFRAG_OVERLAP); an exact duplicate is
//!   dropped alone; inconsistent last-fragment lengths, empty
//!   fragments and datagrams beyond 65535 bytes kill the queue;
//! - CPU: a log-time insert, and a queue holds at most `MAX_FRAGS`
//!   fragments.
//!
//! ## Locking
//!
//! A hash bucket's lock (spin, `util::hlist_nulls`; Linux the fqdir
//! rhashtable's bucket locks) orders the insert of a new queue against
//! a racing one; lookups walk a bucket under RCU and take a reference.
//! `FragQueue.st` (spin, Linux q->lock; thread only: softnet and the
//! queue's timer on ktimers/N) holds its fragments and lengths; killing
//! a queue (Linux inet_frag_kill) unhashes it under it (order
//! `FragQueue.st` -> bucket lock) and stops its timer. Nothing is
//! allocated under either: a completed datagram is assembled, and an
//! expiry's ICMP error sent, after `st` is dropped, from the fragments
//! taken out of the dead queue. A queue's table reference goes a grace
//! period after it is unhashed, possibly in `rcuc/N`.

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::mm::page_alloc::Gfp;
use crate::net::NetNamespace;
use crate::net::inet::route::IpInput;
use crate::net::ipv4::Ipv4Addr;
use crate::net::mib::*;
use crate::net::skb::{SkBuff, SkbCb, SkbTree};
use crate::sync::rcu::RcuPuts;
use crate::sync::spin::Mutex;
use crate::time::timer::ArcTimer;
use crate::util::hlist_nulls::{NullsHead, NullsLink};
use crate::util::kalloc::try_arc_gfp;

/// Largest IPv4 datagram
const IP_MAX: usize = 65535;
/// Fragments per queue (a 64 KB datagram over the minimum 68-byte MTU
/// needs 1366)
pub const MAX_FRAGS: usize = 2048;
/// Bytes charged per fragment besides its payload
const OVERHEAD: usize = 256;

/// Queue identity (Linux ipq: saddr, daddr, id, protocol)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FragKey {
    pub saddr: Ipv4Addr,
    pub daddr: Ipv4Addr,
    pub id: u16,
    pub proto: u8,
}

/// Where a queued fragment's payload lies (Linux FRAG_CB's
/// ip_defrag_offset): payload bytes [`off`, `end`) of the datagram,
/// after its own `ihl`-byte IP header in the skb
#[derive(Clone, Copy, Debug, Default)]
pub struct FragCb {
    off: u32,
    end: u32,
    ihl: u16,
}

fn cb(skb: &SkBuff) -> FragCb {
    match skb.cb {
        SkbCb::Frag(c) => c,
        _ => FragCb::default(),
    }
}

/// Result of adding a fragment
#[derive(Debug, PartialEq, Eq)]
pub enum Ins {
    /// Stored; datagram not complete yet
    More,
    /// Exact duplicate: this fragment is dropped, the queue kept
    Dup,
    /// Corrupt: drop the whole queue
    Kill,
    /// Overlapping a stored piece: drop the whole queue (Linux
    /// IPFRAG_OVERLAP, counted in ReasmOverlaps)
    Overlap,
    /// All pieces present
    Done,
}

/// A queue's fragments and lengths (under `FragQueue.st`)
#[derive(Default)]
struct Frags {
    /// The fragments by payload offset (Linux q->rb_fragments)
    tree: SkbTree,
    /// Payload length (exact once the last fragment is in)
    len: usize,
    /// Payload bytes received
    meat: usize,
    last_in: bool,
    /// Header length of the first fragment, once it is in (Linux
    /// INET_FRAG_FIRST_IN)
    first_ihl: Option<usize>,
    /// Bytes charged to the namespace
    mem: usize,
    /// Killed: no more fragments (Linux INET_FRAG_COMPLETE)
    complete: bool,
    /// Input device of the latest fragment (Linux qp->iif)
    iif: u32,
}

impl Frags {
    /// Add `skb`, an IP fragment whose header is `ihl` bytes, at payload
    /// offset `off` (`more`: MF set); Linux ip_frag_queue. A dropped
    /// fragment is freed.
    fn insert(&mut self, mut skb: Box<SkBuff>, ihl: usize, off: usize, more: bool) -> Ins {
        let mut end = off + skb.len() - ihl;
        if !more {
            if end < self.len || (self.last_in && end != self.len) {
                return Ins::Kill;
            }
            self.last_in = true;
            self.len = end;
        } else {
            end &= !7;
            if end > self.len {
                if self.last_in {
                    return Ins::Kill;
                }
                self.len = end;
            }
        }
        // The whole datagram, with the first fragment's header, must fit
        // in 16 bits (ping of death): never truncate a length later
        let fihl = if off == 0 {
            ihl
        } else {
            self.first_ihl.unwrap_or(crate::net::ipv4::IP_HLEN_MIN)
        };
        if end <= off || fihl + self.len > IP_MAX {
            return Ins::Kill;
        }
        match self.place(off, end) {
            Some(true) => {}
            Some(false) => return Ins::Dup,
            None => return Ins::Overlap,
        }
        if self.tree.len() >= MAX_FRAGS {
            return Ins::Kill;
        }
        skb.cb = SkbCb::Frag(FragCb {
            off: off as u32,
            end: end as u32,
            ihl: ihl as u16,
        });
        self.tree.insert_by(skb, |a, b| cb(a).off < cb(b).off);
        self.meat += end - off;
        self.mem += end - off + OVERHEAD;
        if off == 0 {
            self.first_ihl = Some(ihl);
        }
        if self.done() { Ins::Done } else { Ins::More }
    }

    /// Where [off, end) fits: Some(true) free, Some(false) exact
    /// duplicate of a stored piece, None overlap (Linux
    /// inet_frag_queue_insert)
    fn place(&mut self, off: usize, end: usize) -> Option<bool> {
        let (off, end) = (off as u32, end as u32);
        let c = self.tree.cursor_floor_mut(|x| cb(x).off <= off);
        let next = match c.current().map(cb) {
            Some(p) if off < p.end => return (end <= p.end).then_some(false),
            Some(_) => c.peek_next().map(cb),
            None => None,
        };
        // Nothing at or before `off`: the first one is next
        let next = next.or_else(|| self.tree.first().map(cb).filter(|f| f.off > off));
        match next {
            Some(n) if n.off < end => None,
            _ => Some(true),
        }
    }

    fn done(&self) -> bool {
        self.last_in && self.first_ihl.is_some() && self.meat == self.len
    }
}

/// The whole datagram from a complete queue's fragments: the first
/// one's header (fixed up), then each payload; in an skb made GFP_ATOMIC
/// with `last`'s receive metadata (Linux ip_frag_reasm); None beyond
/// 65535 bytes or out of memory (Linux out_oversize, out_nomem)
fn assemble(f: &Frags, last: &Meta) -> Option<Box<SkBuff>> {
    let ihl = f.first_ihl?;
    if ihl + f.len > IP_MAX {
        return None;
    }
    let mut s = SkBuff::alloc(crate::net::skb::NET_SKB_PAD, ihl + f.len, Gfp::ATOMIC)?;
    let first = f.tree.first()?;
    s.put_slice(&first.data()[..ihl])?;
    for frag in f.tree.iter() {
        let c = cb(frag);
        let from = usize::from(c.ihl);
        s.put_slice(&frag.data()[from..from + (c.end - c.off) as usize])?;
    }
    let out = s.data_mut();
    let tot = u16::try_from(out.len()).ok()?;
    out[2..4].copy_from_slice(&tot.to_be_bytes());
    out[6] = 0;
    out[7] = 0;
    out[10] = 0;
    out[11] = 0;
    let c = crate::net::ipv4::ip_checksum(&out[..ihl]);
    out[10..12].copy_from_slice(&c.to_be_bytes());
    s.dev = last.dev.clone();
    s.pkt_type = last.pkt_type;
    s.ip_bcast = last.ip_bcast;
    Some(s)
}

/// What the reassembled skb takes from the fragment that completed it
struct Meta {
    dev: Option<Arc<crate::net::NetDevice>>,
    pkt_type: crate::net::ethernet::PktType,
    ip_bcast: bool,
}

/// One datagram being reassembled (Linux struct ipq / inet_frag_queue)
pub struct FragQueue {
    key: FragKey,
    /// Its bucket's index (the namespace may be gone at expiry)
    bkt: usize,
    /// Its namespace (Linux q->fqdir->net)
    net: Weak<NetNamespace>,
    st: Mutex<Frags>,
    /// Link on its hash bucket (Linux q->node)
    link: NullsLink,
    /// Expiry (Linux q->timer, ip_expire)
    timer: ArcTimer<FragQueue>,
    rcu: RcuPuts,
}

crate::nulls_adapter!(FragHash, FragQueue, link);
crate::rcu_puts!(FragQueue, rcu);

/// Queues of every namespace (Linux each fqdir's rhashtable)
static FRAG_TABLE: spin::Once<Box<[NullsHead<FragHash>]>> = spin::Once::new();

/// Size the table from memory (one bucket per 2 MiB, 256 to 64 Ki)
pub fn init() {
    let n = (crate::FRAME_ALLOCATOR.buffer_pages() >> 9)
        .next_power_of_two()
        .clamp(256, 1 << 16);
    FRAG_TABLE.call_once(|| NullsHead::table(n).expect("ipfrag: hash table"));
}

fn table() -> &'static [NullsHead<FragHash>] {
    FRAG_TABLE.get().expect("ipfrag table not initialized")
}

/// Linux ipqhashfn: a keyed hash of the key and the namespace's mix
fn bucket_index(net: &NetNamespace, k: &FragKey) -> usize {
    let h = crate::net::inet::port::secure_hash(
        0x6970_6672_6167,
        &[
            u64::from(net.hash_mix),
            (u64::from(k.saddr.0) << 32) | u64::from(k.daddr.0),
            (u64::from(k.id) << 8) | u64::from(k.proto),
        ],
    );
    h as usize & (table().len() - 1)
}

/// A namespace's reassembly accounting (Linux struct fqdir's mem and
/// the rhashtable's nelems)
#[derive(Default)]
pub struct FragTable {
    mem: AtomicUsize,
    queues: AtomicUsize,
}

/// What `FragTable::add` decided
pub enum Defrag {
    /// Keep waiting (or dropped)
    Pending,
    /// The complete datagram (IP header first)
    Whole(Box<SkBuff>),
}

impl FragTable {
    /// Queues and bytes held (as /proc/net/sockstat's FRAG line shows
    /// them)
    pub fn usage(&self) -> (usize, usize) {
        (
            self.queues.load(Ordering::Relaxed),
            self.mem.load(Ordering::Relaxed),
        )
    }

    /// Add `skb`, a fragment for us (header validated) in `net`
    /// (Linux ip_defrag). Counted as Linux does: ReasmReqds for each,
    /// ReasmFails (and ReasmOverlaps) when the queue dies or the
    /// datagram cannot be built; the caller counts ReasmOKs for a
    /// `Whole`.
    pub fn add(&self, net: &Arc<NetNamespace>, skb: Box<SkBuff>) -> Defrag {
        let ip = &net.mib.ip;
        ip.inc(IPSTATS_MIB_REASMREQDS);
        let pkt = skb.data();
        let ihl = ((pkt[0] & 0x0f) as usize) * 4;
        let fo = u16::from_be_bytes([pkt[6], pkt[7]]);
        let key = FragKey {
            saddr: Ipv4Addr::from_be_bytes([pkt[12], pkt[13], pkt[14], pkt[15]]),
            daddr: Ipv4Addr::from_be_bytes([pkt[16], pkt[17], pkt[18], pkt[19]]),
            id: u16::from_be_bytes([pkt[4], pkt[5]]),
            proto: pkt[9],
        };
        let off = ((fo & 0x1fff) as usize) * 8;
        let more = fo & 0x2000 != 0;
        let Some(q) = self.find(net, &key) else {
            // Linux ip_find fails: over the memory limit, or no memory
            ip.inc(IPSTATS_MIB_REASMFAILS);
            return Defrag::Pending;
        };
        let meta = Meta {
            dev: skb.dev.clone(),
            pkt_type: skb.pkt_type,
            ip_bcast: skb.ip_bcast,
        };
        let mut st = q.st.lock();
        if st.complete {
            // Lost a race with its completion or expiry (Linux
            // ip_frag_queue's INET_FRAG_COMPLETE check)
            drop(st);
            ip.inc(IPSTATS_MIB_REASMFAILS);
            return Defrag::Pending;
        }
        let before = st.mem;
        st.iif = meta.dev.as_ref().map_or(0, |d| d.ifindex());
        let r = st.insert(skb, ihl, off, more);
        self.mem.fetch_add(st.mem - before, Ordering::Relaxed);
        match r {
            Ins::More | Ins::Dup => Defrag::Pending,
            Ins::Kill | Ins::Overlap => {
                let dead = self.kill(&q, &mut st);
                drop(st);
                drop(dead);
                if r == Ins::Overlap {
                    ip.inc(IPSTATS_MIB_REASM_OVERLAPS);
                }
                ip.inc(IPSTATS_MIB_REASMFAILS);
                Defrag::Pending
            }
            Ins::Done => {
                let dead = self.kill(&q, &mut st);
                drop(st);
                match assemble(&dead, &meta) {
                    Some(s) => Defrag::Whole(s),
                    None => {
                        ip.inc(IPSTATS_MIB_REASMFAILS);
                        Defrag::Pending
                    }
                }
            }
        }
    }

    /// The queue for `key`, made if there is none and memory allows
    /// (Linux inet_frag_find: lookup under RCU, then inet_frag_create's
    /// GFP_ATOMIC allocation and an insert that keeps a racing one)
    fn find(&self, net: &Arc<NetNamespace>, key: &FragKey) -> Option<Arc<FragQueue>> {
        let high = net.sysctl.frag_high.load(Ordering::Relaxed);
        if self.mem.load(Ordering::Relaxed) > high {
            return None;
        }
        let bkt = bucket_index(net, key);
        let head = &table()[bkt];
        let mine = |q: &FragQueue| q.key == *key && q.net.as_ptr() == Arc::as_ptr(net);
        {
            let g = crate::sync::rcu::read_lock();
            if let Some(q) = head.find_rcu(&g, |q| mine(q)) {
                return Some(q.arc());
            }
        }
        let q = try_arc_gfp(
            FragQueue {
                key: *key,
                bkt,
                net: Arc::downgrade(net),
                st: Mutex::new(Frags::default()),
                link: NullsLink::new(),
                timer: ArcTimer::new(ip_expire),
                rcu: RcuPuts::new(),
            },
            Gfp::ATOMIC,
        )
        .ok()?;
        let mut b = head.lock();
        if let Some(old) = b.find(|x| mine(x)) {
            return Some(old);
        }
        b.add_head_rcu(q.clone());
        drop(b);
        self.queues.fetch_add(1, Ordering::Relaxed);
        let secs = net.sysctl.frag_time.load(Ordering::Relaxed).max(1) as u64;
        let at = crate::net::neigh::now_ms().saturating_add(secs * 1000);
        q.timer.reset(&q, at.saturating_mul(1_000_000));
        Some(q)
    }

    /// Kill `q` (Linux inet_frag_kill, `q.st` held): no more fragments,
    /// off the table, its timer stopped, its charge returned; its
    /// fragments come back to be used or freed after the lock
    fn kill(&self, q: &FragQueue, st: &mut Frags) -> Frags {
        if unhash(q, st) {
            self.queues.fetch_sub(1, Ordering::Relaxed);
        }
        self.mem.fetch_sub(st.mem, Ordering::Relaxed);
        core::mem::replace(
            st,
            Frags {
                complete: true,
                ..Default::default()
            },
        )
    }
}

/// Mark `q` complete, stop its timer and take it off the table (`q.st`
/// held); whether it was on it
fn unhash(q: &FragQueue, st: &mut Frags) -> bool {
    st.complete = true;
    q.timer.stop();
    let gone = table()[q.bkt].lock().del_rcu(q);
    gone.map(|g| g.defer()).is_some()
}

/// A queue's timer expired (Linux ip_expire, ktimers/N): kill it and,
/// if its first fragment was in and its route still holds, send ICMP
/// time exceeded (reassembly) from that fragment's header and first 8
/// payload bytes
fn ip_expire(q: Arc<FragQueue>) {
    let Some(net) = q.net.upgrade() else {
        // Its namespace is gone (its accounting with it): off the table,
        // its fragments freed after the lock
        let mut st = q.st.lock();
        unhash(&q, &mut st);
        let dead = core::mem::take(&mut *st);
        drop(st);
        drop(dead);
        return;
    };
    let mut st = q.st.lock();
    if st.complete {
        return;
    }
    let dead = net.frags.kill(&q, &mut st);
    drop(st);
    net.mib.ip.inc(IPSTATS_MIB_REASMFAILS);
    net.mib.ip.inc(IPSTATS_MIB_REASMTIMEOUT);
    let Some(ihl) = dead.first_ihl else {
        return;
    };
    let Some(first) = dead.tree.first() else {
        return;
    };
    // The head has no route: look it up again on the input device, the
    // full way (Linux ip_route_input_noref; a looped skb's output dst
    // is gone), so a loopback-addressed or self-sourced datagram gets
    // no error (martian), as on Linux
    if net.dev_get_by_index(dead.iif).is_none() {
        return;
    }
    let d = first.data();
    let saddr = Ipv4Addr::from_be_bytes([d[12], d[13], d[14], d[15]]);
    let daddr = Ipv4Addr::from_be_bytes([d[16], d[17], d[18], d[19]]);
    let rt = crate::net::inet::route::classify_in(&net, saddr, daddr, false);
    if matches!(rt, IpInput::Local | IpInput::Broadcast) {
        crate::net::icmp::frag_expired(&net, &d[..(ihl + 8).min(d.len())]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HDR: [u8; 20] = [
        0x45, 0, 0, 0, 0, 1, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
    ];

    /// A fragment: `hdr`, then `n` payload bytes of `v`
    fn frag(hdr: &[u8], n: usize, v: u8) -> Box<SkBuff> {
        let mut s = SkBuff::alloc(0, hdr.len() + n, Gfp::KERNEL).unwrap();
        s.put_slice(hdr).unwrap();
        s.put_slice(&alloc::vec![v; n]).unwrap();
        s
    }

    fn ins(f: &mut Frags, off: usize, n: usize, v: u8, more: bool) -> Ins {
        f.insert(frag(&HDR, n, v), 20, off, more)
    }

    fn meta() -> Meta {
        Meta {
            dev: None,
            pkt_type: Default::default(),
            ip_bcast: false,
        }
    }

    #[test]
    fn in_order_and_reordered() {
        let mut q = Frags::default();
        assert_eq!(ins(&mut q, 0, 16, 1, true), Ins::More);
        assert_eq!(ins(&mut q, 16, 8, 2, false), Ins::Done);
        let s = assemble(&q, &meta()).unwrap();
        let d = s.data();
        assert_eq!(d.len(), 44);
        assert_eq!(u16::from_be_bytes([d[2], d[3]]), 44);
        assert_eq!(&d[20..36], &[1; 16]);
        assert_eq!(&d[36..], &[2; 8]);
        assert_eq!(crate::net::ipv4::ip_checksum(&d[..20]), 0);

        let mut q = Frags::default();
        assert_eq!(ins(&mut q, 16, 4, 2, false), Ins::More);
        assert_eq!(ins(&mut q, 8, 8, 3, true), Ins::More);
        assert_eq!(ins(&mut q, 0, 8, 1, true), Ins::Done);
    }

    #[test]
    fn overlap_kills_duplicate_drops() {
        let mut q = Frags::default();
        assert_eq!(ins(&mut q, 0, 16, 1, true), Ins::More);
        assert_eq!(ins(&mut q, 0, 16, 1, true), Ins::Dup);
        assert_eq!(ins(&mut q, 8, 8, 1, true), Ins::Dup);
        assert_eq!(ins(&mut q, 8, 16, 9, true), Ins::Overlap);
        let mut q = Frags::default();
        assert_eq!(ins(&mut q, 16, 16, 1, true), Ins::More);
        assert_eq!(ins(&mut q, 8, 16, 1, true), Ins::Overlap);
    }

    #[test]
    fn inconsistent_lengths_kill() {
        // Two different last fragments
        let mut q = Frags::default();
        assert_eq!(ins(&mut q, 16, 8, 1, false), Ins::More);
        assert_eq!(ins(&mut q, 16, 16, 1, false), Ins::Kill);
        // Data beyond the last fragment
        let mut q = Frags::default();
        assert_eq!(ins(&mut q, 8, 8, 1, false), Ins::More);
        assert_eq!(ins(&mut q, 16, 8, 1, true), Ins::Kill);
        // Empty fragment
        let mut q = Frags::default();
        assert_eq!(ins(&mut q, 8, 4, 1, true), Ins::Kill);
        // Beyond 65535
        let mut q = Frags::default();
        assert_eq!(ins(&mut q, 65528, 16, 1, false), Ins::Kill);
    }

    #[test]
    fn non_final_trimmed_to_8() {
        let mut q = Frags::default();
        assert_eq!(ins(&mut q, 0, 13, 1, true), Ins::More);
        assert_eq!(ins(&mut q, 8, 8, 2, false), Ins::Done);
        assert_eq!(assemble(&q, &meta()).unwrap().len(), 36);
    }

    #[test]
    fn oversized_never_truncated() {
        // A long first header, then a fragment pushing the total past
        // 65535 with a short header of its own
        let mut big = [0u8; 60];
        big[0] = 0x4f;
        let mut q = Frags::default();
        assert_eq!(q.insert(frag(&big, 8, 1), 60, 0, true), Ins::More);
        assert_eq!(ins(&mut q, 65464, 16, 2, false), Ins::Kill);
        // Same pieces, first fragment last
        let mut q = Frags::default();
        assert_eq!(ins(&mut q, 65464, 16, 2, false), Ins::More);
        assert_eq!(q.insert(frag(&big, 8, 1), 60, 0, true), Ins::Kill);
        // Exactly 65535 is fine and its header says so
        let mut q = Frags::default();
        assert_eq!(ins(&mut q, 0, 65512, 1, true), Ins::More);
        assert_eq!(ins(&mut q, 65512, 3, 2, false), Ins::Done);
        let s = assemble(&q, &meta()).unwrap();
        assert_eq!(s.len(), 65535);
        assert_eq!(u16::from_be_bytes([s.data()[2], s.data()[3]]), 65535);
        // Largest offset with a payload overflowing 16 bits
        let mut q = Frags::default();
        assert_eq!(ins(&mut q, 65528, 64, 1, false), Ins::Kill);
    }

    #[test]
    fn memory_charged() {
        let mut q = Frags::default();
        ins(&mut q, 0, 800, 1, true);
        assert_eq!(q.mem, 800 + OVERHEAD);
    }
}

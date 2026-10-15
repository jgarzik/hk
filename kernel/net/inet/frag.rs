//! IPv4 reassembly (Linux net/ipv4/ip_fragment.c, inet_fragment.c)
//!
//! Fragments of a datagram (keyed by source, destination, id and
//! protocol) collect in a `FragQueue` until the first and last pieces
//! are in and the payload has no holes. Peer-reachable, so everything
//! is bounded like Linux:
//! - memory: fragments are charged to the namespace; above
//!   `ipfrag_high_thresh` new fragments are dropped (Linux
//!   inet_frag_find); queues die after `ipfrag_time` (30 s), sending
//!   ICMP time exceeded (reassembly) when the first fragment was in;
//! - overlap: a fragment overlapping another kills the whole queue
//!   (RFC 5722 style, Linux IPFRAG_OVERLAP); an exact duplicate is
//!   dropped alone; inconsistent last-fragment lengths, empty
//!   fragments and datagrams beyond 65535 bytes kill the queue;
//! - CPU: fragments live in an ordered map (log-time insert) and a
//!   queue holds at most `MAX_FRAGS` of them.
//!
//! ## Locking
//!
//! `FragTable.st` is a `crate::sync::spin::Mutex` (thread only: softnet and the
//! reassembly timer on ktimerd), a leaf: completed datagrams and expiry
//! ICMP errors are handled after it is dropped.

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use crate::sync::spin::Mutex;

use crate::net::ipv4::Ipv4Addr;

/// Largest IPv4 datagram
const IP_MAX: usize = 65535;
/// Fragments per queue (a 64 KB datagram over the minimum 68-byte MTU
/// needs 1366)
pub const MAX_FRAGS: usize = 2048;
/// Bytes charged per fragment besides its payload
const OVERHEAD: usize = 256;

/// Queue identity (Linux ipq: saddr, daddr, id, protocol)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FragKey {
    pub saddr: Ipv4Addr,
    pub daddr: Ipv4Addr,
    pub id: u16,
    pub proto: u8,
}

/// Result of adding a fragment
#[derive(Debug, PartialEq, Eq)]
pub enum Ins {
    /// Stored; datagram not complete yet
    More,
    /// Exact duplicate: this fragment is dropped, the queue kept
    Dup,
    /// Corrupt or overlapping: drop the whole queue
    Kill,
    /// All pieces present
    Done,
}

/// One datagram being reassembled
#[derive(Default)]
pub struct FragQueue {
    /// payload offset -> payload bytes
    frags: BTreeMap<usize, Vec<u8>>,
    /// Payload length (exact once the last fragment is in)
    len: usize,
    /// Payload bytes received
    meat: usize,
    last_in: bool,
    /// IP header of the first fragment (offset 0), options included,
    /// plus the start of its payload (for ICMP time exceeded)
    first: Option<Vec<u8>>,
    /// Bytes charged
    pub mem: usize,
    /// Expiry (ms)
    pub expires: u64,
}

impl FragQueue {
    pub fn new(expires: u64) -> Self {
        Self {
            expires,
            ..Default::default()
        }
    }

    /// Add `data` at payload offset `off` (`more`: MF set); `hdr` is the
    /// fragment's IP header (kept for offset 0). Linux ip_frag_queue.
    pub fn insert(&mut self, off: usize, data: &[u8], more: bool, hdr: &[u8]) -> Ins {
        let mut end = off + data.len();
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
            hdr.len()
        } else {
            self.first_ihl()
        };
        if end <= off || fihl + self.len > IP_MAX {
            return Ins::Kill;
        }
        match self.place(off, end) {
            Some(true) => {}
            Some(false) => return Ins::Dup,
            None => return Ins::Kill,
        }
        if self.frags.len() >= MAX_FRAGS {
            return Ins::Kill;
        }
        self.frags.insert(off, data[..end - off].to_vec());
        self.meat += end - off;
        self.mem += end - off + OVERHEAD;
        if off == 0 {
            let mut f = hdr.to_vec();
            f.extend_from_slice(&data[..(end - off).min(8)]);
            self.first = Some(f);
        }
        if self.done() { Ins::Done } else { Ins::More }
    }

    /// Where [off, end) fits: Some(true) free, Some(false) exact
    /// duplicate of a stored piece, None overlap (Linux
    /// inet_frag_queue_insert)
    fn place(&self, off: usize, end: usize) -> Option<bool> {
        if let Some((&o, d)) = self.frags.range(..=off).next_back() {
            let e = o + d.len();
            if off < e {
                return (off >= o && end <= e).then_some(false);
            }
        }
        match self.frags.range(off..).next() {
            Some((&o, _)) if o < end => None,
            _ => Some(true),
        }
    }

    /// Header length of the first fragment (minimum until it arrived)
    fn first_ihl(&self) -> usize {
        self.first
            .as_ref()
            .map_or(crate::net::ipv4::IP_HLEN_MIN, |f| {
                ((f[0] & 0x0f) as usize) * 4
            })
    }

    fn done(&self) -> bool {
        self.last_in && self.first.is_some() && self.meat == self.len
    }

    /// First fragment's header + leading payload, if it arrived
    pub fn first(&self) -> Option<&[u8]> {
        self.first.as_deref()
    }

    /// The whole datagram: first header (fixed up) + payload; None if
    /// incomplete or beyond 65535 bytes (Linux "Oversized IP packet")
    pub fn assemble(&self) -> Option<Vec<u8>> {
        let first = self.first.as_ref()?;
        let ihl = ((first[0] & 0x0f) as usize) * 4;
        if !self.done() || ihl + self.len > IP_MAX {
            return None;
        }
        let mut out = Vec::with_capacity(ihl + self.len);
        out.extend_from_slice(&first[..ihl]);
        for d in self.frags.values() {
            out.extend_from_slice(d);
        }
        let tot = u16::try_from(out.len()).ok()?;
        out[2..4].copy_from_slice(&tot.to_be_bytes());
        out[6] = 0;
        out[7] = 0;
        out[10] = 0;
        out[11] = 0;
        let c = crate::net::ipv4::ip_checksum(&out[..ihl]);
        out[10..12].copy_from_slice(&c.to_be_bytes());
        Some(out)
    }
}

/// What `FragTable::add` decided
pub enum Defrag {
    /// Keep waiting (or dropped)
    Pending,
    /// Complete datagram (IP header first)
    Whole(Vec<u8>),
}

struct State {
    q: BTreeMap<FragKey, FragQueue>,
    mem: usize,
}

/// A namespace's reassembly queues
pub struct FragTable {
    st: Mutex<State>,
}

impl Default for FragTable {
    fn default() -> Self {
        Self {
            st: Mutex::new(State {
                q: BTreeMap::new(),
                mem: 0,
            }),
        }
    }
}

/// Registered tables, for the expiry timer
static TABLES: Mutex<Vec<Weak<crate::net::NetNamespace>>> = Mutex::new(Vec::new());
static ALARM: crate::timer::Alarm = crate::timer::Alarm::new(frag_timer);

impl FragTable {
    /// Add a fragment (`pkt` = whole IP packet, header validated) of a
    /// datagram for us in `net`. `high`: ipfrag_high_thresh;
    /// `timeout`: ipfrag_time in ms.
    pub fn add(&self, net: &Arc<crate::net::NetNamespace>, pkt: &[u8]) -> Defrag {
        let s = &net.sysctl;
        let high = s.frag_high.load(core::sync::atomic::Ordering::Relaxed);
        let secs = s
            .frag_time
            .load(core::sync::atomic::Ordering::Relaxed)
            .max(1) as u64;
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
        let now = crate::net::neigh::now_ms();
        let mut st = self.st.lock();
        if st.mem > high {
            return Defrag::Pending;
        }
        let fresh = !st.q.contains_key(&key);
        let q =
            st.q.entry(key)
                .or_insert_with(|| FragQueue::new(now + secs * 1000));
        let before = q.mem;
        let r = q.insert(off, &pkt[ihl..], more, &pkt[..ihl]);
        let after = q.mem;
        st.mem = st.mem + after - before;
        let out = match r {
            Ins::More | Ins::Dup => Defrag::Pending,
            Ins::Kill => {
                self.remove(&mut st, &key);
                Defrag::Pending
            }
            Ins::Done => {
                let whole = st.q.get(&key).and_then(|q| q.assemble());
                self.remove(&mut st, &key);
                whole.map_or(Defrag::Pending, Defrag::Whole)
            }
        };
        let exp = st.q.get(&key).map(|q| q.expires);
        drop(st);
        if fresh && exp.is_some() {
            register(net);
        }
        if let Some(e) = exp {
            ALARM.arm(e.saturating_mul(1_000_000));
        }
        out
    }

    fn remove(&self, st: &mut State, key: &FragKey) {
        if let Some(q) = st.q.remove(key) {
            st.mem -= q.mem;
        }
    }

    /// Bytes held (ipfrag memory)
    pub fn mem(&self) -> usize {
        self.st.lock().mem
    }

    /// Drop expired queues; returns the first-fragment headers of those
    /// that had one (for ICMP time exceeded) and the next expiry
    fn expire(&self, now: u64) -> (Vec<Vec<u8>>, Option<u64>) {
        let mut st = self.st.lock();
        let dead: Vec<FragKey> =
            st.q.iter()
                .filter(|(_, q)| q.expires <= now)
                .map(|(k, _)| *k)
                .collect();
        let mut firsts = Vec::new();
        for k in dead {
            if let Some(q) = st.q.remove(&k) {
                st.mem -= q.mem;
                if let Some(f) = q.first {
                    firsts.push(f);
                }
            }
        }
        let next = st.q.values().map(|q| q.expires).min();
        (firsts, next)
    }
}

fn register(net: &Arc<crate::net::NetNamespace>) {
    let mut t = TABLES.lock();
    if !t.iter().any(|w| w.as_ptr() == Arc::as_ptr(net)) {
        t.push(Arc::downgrade(net));
    }
}

/// Expiry timer (ktimerd): free timed-out queues, report them
fn frag_timer(_: u64) {
    ALARM.fired();
    let nets: Vec<Arc<crate::net::NetNamespace>> = {
        let mut t = TABLES.lock();
        t.retain(|w| w.strong_count() > 0);
        t.iter().filter_map(|w| w.upgrade()).collect()
    };
    let now = crate::net::neigh::now_ms();
    let mut next: Option<u64> = None;
    for net in nets {
        let (firsts, n) = net.frags.expire(now);
        for f in firsts {
            crate::net::icmp::frag_expired(&net, &f);
        }
        next = match (next, n) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
    }
    if let Some(at) = next {
        ALARM.arm(at.max(now + 10).saturating_mul(1_000_000));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HDR: [u8; 20] = [
        0x45, 0, 0, 0, 0, 1, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
    ];

    fn data(n: usize, v: u8) -> Vec<u8> {
        alloc::vec![v; n]
    }

    #[test]
    fn in_order_and_reordered() {
        let mut q = FragQueue::new(0);
        assert_eq!(q.insert(0, &data(16, 1), true, &HDR), Ins::More);
        assert_eq!(q.insert(16, &data(8, 2), false, &HDR), Ins::Done);
        let d = q.assemble().unwrap();
        assert_eq!(d.len(), 44);
        assert_eq!(u16::from_be_bytes([d[2], d[3]]), 44);
        assert_eq!(&d[20..36], &[1; 16]);
        assert_eq!(&d[36..], &[2; 8]);
        assert_eq!(crate::net::ipv4::ip_checksum(&d[..20]), 0);

        let mut q = FragQueue::new(0);
        assert_eq!(q.insert(16, &data(4, 2), false, &HDR), Ins::More);
        assert_eq!(q.insert(8, &data(8, 3), true, &HDR), Ins::More);
        assert_eq!(q.insert(0, &data(8, 1), true, &HDR), Ins::Done);
    }

    #[test]
    fn overlap_kills_duplicate_drops() {
        let mut q = FragQueue::new(0);
        assert_eq!(q.insert(0, &data(16, 1), true, &HDR), Ins::More);
        assert_eq!(q.insert(0, &data(16, 1), true, &HDR), Ins::Dup);
        assert_eq!(q.insert(8, &data(8, 1), true, &HDR), Ins::Dup);
        assert_eq!(q.insert(8, &data(16, 9), true, &HDR), Ins::Kill);
        let mut q = FragQueue::new(0);
        assert_eq!(q.insert(16, &data(16, 1), true, &HDR), Ins::More);
        assert_eq!(q.insert(8, &data(16, 1), true, &HDR), Ins::Kill);
    }

    #[test]
    fn inconsistent_lengths_kill() {
        // Two different last fragments
        let mut q = FragQueue::new(0);
        assert_eq!(q.insert(16, &data(8, 1), false, &HDR), Ins::More);
        assert_eq!(q.insert(16, &data(16, 1), false, &HDR), Ins::Kill);
        // Data beyond the last fragment
        let mut q = FragQueue::new(0);
        assert_eq!(q.insert(8, &data(8, 1), false, &HDR), Ins::More);
        assert_eq!(q.insert(16, &data(8, 1), true, &HDR), Ins::Kill);
        // Empty fragment
        let mut q = FragQueue::new(0);
        assert_eq!(q.insert(8, &data(4, 1), true, &HDR), Ins::Kill);
        // Beyond 65535
        let mut q = FragQueue::new(0);
        assert_eq!(q.insert(65528, &data(16, 1), false, &HDR), Ins::Kill);
    }

    #[test]
    fn non_final_trimmed_to_8() {
        let mut q = FragQueue::new(0);
        assert_eq!(q.insert(0, &data(13, 1), true, &HDR), Ins::More);
        assert_eq!(q.insert(8, &data(8, 2), false, &HDR), Ins::Done);
        assert_eq!(q.assemble().unwrap().len(), 36);
    }

    #[test]
    fn oversized_never_truncated() {
        // A long first header, then a fragment pushing the total past
        // 65535 with a short header of its own
        let mut big = [0u8; 60];
        big[0] = 0x4f;
        let mut q = FragQueue::new(0);
        assert_eq!(q.insert(0, &data(8, 1), true, &big), Ins::More);
        assert_eq!(q.insert(65464, &data(16, 2), false, &HDR), Ins::Kill);
        // Same pieces, first fragment last
        let mut q = FragQueue::new(0);
        assert_eq!(q.insert(65464, &data(16, 2), false, &HDR), Ins::More);
        assert_eq!(q.insert(0, &data(8, 1), true, &big), Ins::Kill);
        // Exactly 65535 is fine and its header says so
        let mut q = FragQueue::new(0);
        assert_eq!(q.insert(0, &data(65512, 1), true, &HDR), Ins::More);
        assert_eq!(q.insert(65512, &data(3, 2), false, &HDR), Ins::Done);
        let d = q.assemble().unwrap();
        assert_eq!(d.len(), 65535);
        assert_eq!(u16::from_be_bytes([d[2], d[3]]), 65535);
        // Largest offset with a payload overflowing 16 bits
        let mut q = FragQueue::new(0);
        assert_eq!(q.insert(65528, &data(64, 1), false, &HDR), Ins::Kill);
    }

    #[test]
    fn memory_charged() {
        let mut q = FragQueue::new(0);
        q.insert(0, &data(800, 1), true, &HDR);
        assert_eq!(q.mem, 800 + OVERHEAD);
    }
}

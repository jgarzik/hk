//! Network Buffer (SkBuff)
//!
//! This module implements the network buffer structure, equivalent to
//! Linux's sk_buff. It provides efficient packet manipulation with
//! the head/data/tail/end pointer model.
//!
//! ## Memory Layout
//!
//! ```text
//! +-------+------+------+-------+
//! | head  | data |      | tail  | end
//! +-------+------+------+-------+
//!    ^       ^              ^       ^
//!    |       |              |       |
//!    |       +- start of    |       +- end of buffer
//!    |          packet data |
//!    |                      +- end of packet data
//!    +- start of buffer
//!
//! Headroom: head..data (for pushing headers)
//! Data:     data..tail (actual packet data)
//! Tailroom: tail..end  (for appending data)
//! ```
//!
//! ## Queues
//!
//! An skb is linked into a queue through its own `list` link (Linux
//! skb->next/prev): an [`SkbHead`] (Linux sk_buff_head used with the
//! unlocked `__skb_*` calls under its owner's lock) or an [`SkbQueue`]
//! (an `SkbHead` with its own lock: skb_queue_tail, skb_dequeue). A
//! queue owns each skb through `P`: a `Box` where the skb has one owner
//! (the per-CPU backlog), an `Arc` where it is shared (Linux
//! skb->users). Queueing never allocates. An skb taken off under the
//! lock is dropped after it (its device reference may be the last).

use crate::util::kalloc::{try_box, with_gfp};
use alloc::boxed::Box;
use alloc::sync::Arc;

use crate::mm::page_alloc::Gfp;
use crate::sync::spin::{Mutex, MutexGuard};
use crate::util::list::{Link, ListPtr, PtrList};

use crate::net::device::NetDevice;
use crate::net::ethernet::{EtherType, PktType};
use crate::net::ipv4::Ipv4Addr;

/// Standard headroom to reserve for headers
pub const NET_SKB_PAD: usize = 64;

/// Maximum packet size we'll allocate
/// Largest buffer: a 64 KB IP datagram plus headroom (loopback MTU)
pub const MAX_SKB_SIZE: usize = 65536 + 512;

/// Network buffer - equivalent to Linux sk_buff
///
/// # Invariants
/// `data <= tail <= buf.len()`; `mac` and `nh`, when set, are at most
/// `tail` (moving `tail` below one clears it).
#[derive(Default)]
pub struct SkBuff {
    /// Its link on a queue (Linux skb->next/prev)
    list: Link,
    /// The buffer: headroom, packet data, tailroom
    buf: Box<[u8]>,
    /// Start of the packet data (moves with push/pull)
    data: usize,
    /// End of the packet data (moves with put/trim)
    tail: usize,

    // Protocol information
    /// EtherType (set by eth_type_trans)
    pub protocol: EtherType,
    /// IP protocol number (set by IP layer)
    pub ip_protocol: u8,

    // Device reference
    /// Source/destination device
    pub dev: Option<Arc<NetDevice>>,

    // IP addresses (set by IP layer for routing)
    pub saddr: Option<Ipv4Addr>,
    pub daddr: Option<Ipv4Addr>,

    /// Receive classification (set by eth_type_trans)
    pub pkt_type: PktType,
    /// Received IP packet was addressed to a broadcast address (Linux
    /// RTCF_BROADCAST; set by ip_rcv)
    pub ip_bcast: bool,
    /// Received IP header TTL and TOS (for IP_RECVTTL / IP_RECVTOS)
    pub ip_ttl: u8,
    pub ip_tos: u8,
    /// Sending socket of a frame from an AF_PACKET socket (its address
    /// as an id, 0 if none): its own outgoing tap skips it (Linux
    /// skb_loop_sk)
    pub owner: usize,
    /// Start of the MAC header in the buffer (None until received)
    mac: Option<usize>,
    /// Start of the IP header of a received packet (None until marked)
    nh: Option<usize>,
}

impl SkBuff {
    /// Allocate an skb with `headroom` bytes reserved before the data
    /// and room for `data_len` bytes of it (Linux alloc_skb +
    /// skb_reserve), both allocations under `gfp`: GFP_ATOMIC where
    /// Linux allocates in atomic context (receive and protocol paths,
    /// drivers), GFP_KERNEL for a socket's sendmsg. None on failure.
    pub fn alloc(headroom: usize, data_len: usize, gfp: Gfp) -> Option<Box<Self>> {
        let total_size = headroom.checked_add(data_len)?;
        if total_size > MAX_SKB_SIZE {
            return None;
        }
        with_gfp(gfp, || {
            let buf = crate::util::kmem::try_vec(total_size, 0u8).ok()?;
            try_box(Self {
                buf: buf.into_boxed_slice(),
                data: headroom,
                tail: headroom,
                ..Default::default()
            })
            .ok()
        })
    }

    /// Allocate an skb for transmitting `data_len` bytes, with headroom
    /// for every header below them (Ethernet + IP + TCP)
    pub fn alloc_tx(data_len: usize, gfp: Gfp) -> Option<Box<Self>> {
        // Reserve space for: Ethernet (14) + IP (20-60) + TCP (20-60)
        let headroom = 14 + 60 + 60;
        Self::alloc(headroom, data_len, gfp)
    }

    /// Get current data length
    #[inline]
    pub fn len(&self) -> usize {
        self.tail - self.data
    }

    /// Check if buffer is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get headroom (space before data)
    #[inline]
    pub fn headroom(&self) -> usize {
        self.data
    }

    /// Get tailroom (space after tail)
    #[inline]
    pub fn tailroom(&self) -> usize {
        self.buf.len() - self.tail
    }

    /// Get the data as a byte slice
    #[inline]
    pub fn data(&self) -> &[u8] {
        &self.buf[self.data..self.tail]
    }

    /// Get the data as a mutable byte slice
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.data..self.tail]
    }

    /// Get raw data pointer
    #[inline]
    pub fn data_ptr(&self) -> *const u8 {
        self.data().as_ptr()
    }

    /// Get raw data pointer (mutable)
    #[inline]
    pub fn data_ptr_mut(&mut self) -> *mut u8 {
        self.data_mut().as_mut_ptr()
    }

    /// Reserve headroom (call before adding data): moves the (empty) data
    /// forward; clamped to the buffer
    pub fn reserve(&mut self, len: usize) {
        debug_assert!(self.is_empty(), "reserve called on non-empty skb");
        let at = self.tail.saturating_add(len).min(self.buf.len());
        // INVARIANT: data == tail <= buf.len()
        self.data = at;
        self.tail = at;
    }

    /// Push header - prepend bytes to the front
    ///
    /// Moves the data pointer backward, returns slice to fill.
    /// Used for adding headers (Ethernet, IP, TCP).
    pub fn push(&mut self, len: usize) -> Option<&mut [u8]> {
        if self.headroom() < len {
            return None;
        }
        self.data -= len;
        Some(&mut self.buf[self.data..self.data + len])
    }

    /// Pull header - consume bytes from the front
    ///
    /// Moves the data pointer forward, returns consumed data.
    /// Used for parsing headers.
    pub fn pull(&mut self, len: usize) -> Option<&[u8]> {
        if self.len() < len {
            return None;
        }
        let start = self.data;
        self.data += len;
        Some(&self.buf[start..start + len])
    }

    /// Put data - append bytes to the tail
    ///
    /// Moves the tail pointer forward, returns slice to fill.
    /// Used for adding payload data.
    pub fn put(&mut self, len: usize) -> Option<&mut [u8]> {
        if self.tailroom() < len {
            return None;
        }
        let start = self.tail;
        self.tail += len;
        Some(&mut self.buf[start..start + len])
    }

    /// Put data from a slice
    pub fn put_slice(&mut self, data: &[u8]) -> Option<()> {
        let buf = self.put(data.len())?;
        buf.copy_from_slice(data);
        Some(())
    }

    /// Trim data from the tail
    ///
    /// Moves the tail pointer backward.
    pub fn trim(&mut self, len: usize) -> Option<()> {
        if self.len() < len {
            return None;
        }
        self.tail -= len;
        // INVARIANT: a header mark past the new tail is gone
        let tail = self.tail;
        self.mac = self.mac.filter(|&m| m <= tail);
        self.nh = self.nh.filter(|&n| n <= tail);
        Some(())
    }

    /// Set the data length (adjusts tail)
    pub fn set_len(&mut self, len: usize) -> Option<()> {
        let current_len = self.len();
        if len > current_len {
            self.put(len - current_len)?;
        } else if len < current_len {
            self.trim(current_len - len)?;
        }
        Some(())
    }

    /// Reset the buffer to initial state (keeps allocation); the headroom
    /// is clamped to the buffer
    pub fn reset(&mut self, headroom: usize) {
        self.data = headroom.min(self.buf.len());
        self.tail = self.data;
        self.protocol = EtherType::Unknown(0);
        self.ip_protocol = 0;
        self.saddr = None;
        self.daddr = None;
        self.pkt_type = PktType::Host;
        self.ip_bcast = false;
        self.owner = 0;
        self.mac = None;
        self.nh = None;
    }

    /// Record the current data pointer as the start of the MAC header
    pub fn mark_mac_header(&mut self) {
        self.mac = Some(self.data);
    }

    /// The received frame from its MAC header to the end (after the
    /// header was pulled), if one was recorded
    pub fn frame_from_mac(&self) -> Option<&[u8]> {
        self.buf.get(self.mac?..self.tail)
    }

    /// Record the current data pointer as the start of the IP header
    pub fn mark_network_header(&mut self) {
        self.nh = Some(self.data);
    }

    /// The received packet from its IP header to the end (after the
    /// header was pulled), if one was recorded
    pub fn network_packet(&self) -> Option<&[u8]> {
        self.buf.get(self.nh?..self.tail)
    }

    /// Network namespace of the skb's device (receive path: the namespace
    /// the packet arrived in; never the current task's)
    pub fn net(&self) -> Option<Arc<crate::net::NetNamespace>> {
        self.dev.as_ref()?.net()
    }
}

crate::adapter!(pub SkbLink, SkBuff, list);

/// A queue of skbs, each owned through `P` (Linux sk_buff_head with the
/// unlocked `__skb_queue_tail`/`__skb_dequeue`/`skb_queue_walk_safe`
/// calls): used under its owner's lock, or as an [`SkbQueue`]'s
/// contents under the queue's own. Dropping it frees what is left
/// (Linux __skb_queue_purge).
pub type SkbHead<P = Arc<SkBuff>> = PtrList<SkbLink, P>;

/// An skb queue with its own lock (Linux sk_buff_head and its lock):
/// thread context only (no protocol code runs in an interrupt
/// handler), a leaf: nothing is taken under it and nothing is dropped
/// under it that could take a lock or sleep
pub struct SkbQueue<P: ListPtr<Target = SkBuff> = Arc<SkBuff>> {
    q: Mutex<SkbHead<P>>,
}

impl<P: ListPtr<Target = SkBuff>> SkbQueue<P> {
    /// An empty queue; its lockdep class is the caller's location (Linux
    /// skb_queue_head_init's static key)
    #[track_caller]
    pub const fn new() -> Self {
        Self {
            q: Mutex::new(SkbHead::new()),
        }
    }

    /// Take the queue's lock for several steps at once (Linux
    /// spin_lock(&list->lock) around `__skb_*` calls)
    #[track_caller]
    pub fn lock(&self) -> MutexGuard<'_, SkbHead<P>> {
        self.q.lock()
    }

    /// The first skb, taken off (Linux skb_dequeue)
    pub fn dequeue(&self) -> Option<P> {
        self.q.lock().pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alloc_and_put() {
        let mut skb = SkBuff::alloc(64, 1500, Gfp::KERNEL).unwrap();
        assert_eq!(skb.len(), 0);
        assert!(skb.headroom() >= 64);

        // Add some data
        let buf = skb.put(100).unwrap();
        buf.fill(0xAB);
        assert_eq!(skb.len(), 100);
        assert_eq!(skb.data()[0], 0xAB);
    }

    #[test]
    fn test_push_and_pull() {
        let mut skb = SkBuff::alloc(64, 1500, Gfp::KERNEL).unwrap();

        // Add payload
        skb.put(100);

        // Push header
        let hdr = skb.push(14).unwrap();
        hdr.fill(0xCD);
        assert_eq!(skb.len(), 114);

        // Pull header
        let pulled = skb.pull(14).unwrap();
        assert_eq!(pulled[0], 0xCD);
        assert_eq!(skb.len(), 100);
    }

    #[test]
    fn test_bounds_from_safe_calls() {
        let mut skb = SkBuff::alloc(16, 32, Gfp::KERNEL).unwrap();
        // A headroom past the buffer is clamped: no tailroom overflow
        skb.reset(1000);
        assert_eq!(skb.tailroom(), 0);
        assert!(skb.put(1).is_none());
        // A MAC mark above a trimmed tail is dropped, not underflowed
        skb.reset(16);
        skb.put(20);
        skb.pull(14);
        skb.mark_mac_header();
        skb.push(14);
        skb.trim(skb.len());
        assert!(skb.frame_from_mac().is_none());
    }

    fn skb(n: usize) -> Box<SkBuff> {
        let mut s = SkBuff::alloc(0, 8, Gfp::ATOMIC).unwrap();
        s.put(n).unwrap();
        s
    }

    fn lens<P: ListPtr<Target = SkBuff>>(h: &SkbHead<P>) -> alloc::vec::Vec<usize> {
        h.iter().map(SkBuff::len).collect()
    }

    /// FIFO order; a walk unlinks the ones it picks into another head
    /// in order (Linux skb_queue_walk_safe + __skb_unlink)
    #[test]
    fn queue_fifo_and_walk_unlink() {
        let q: SkbQueue<Box<SkBuff>> = SkbQueue::new();
        for n in 1..=5 {
            q.lock().push_back(skb(n));
        }
        assert_eq!(q.lock().len(), 5);
        assert_eq!(q.dequeue().map(|s| s.len()), Some(1));
        let mut gone: SkbHead<Box<SkBuff>> = SkbHead::new();
        q.lock()
            .drain_if(|s| s.len() % 2 == 0, |s| gone.push_back(s));
        assert_eq!(lens(&gone), [2, 4]);
        assert_eq!(lens(&q.lock()), [3, 5]);
        // The link is free again once off every queue
        let s = gone.pop_front().unwrap();
        q.lock().push_back(s);
        assert_eq!(lens(&q.lock()), [3, 5, 2]);
    }

    /// A shared skb stays alive in the queue while its other reference
    /// goes, and the queue's drop frees the rest
    #[test]
    fn shared_queue_holds_references() {
        let a: Arc<SkBuff> = Arc::from(skb(3));
        let q: SkbQueue = SkbQueue::new();
        q.lock().push_back(a.clone());
        q.lock().push_back(Arc::from(skb(4)));
        assert_eq!(Arc::strong_count(&a), 2);
        drop(q);
        assert_eq!(Arc::strong_count(&a), 1);
    }
}

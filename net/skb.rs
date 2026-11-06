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

use crate::util::kalloc::try_box;
use alloc::boxed::Box;
use alloc::sync::Arc;

use crate::net::device::NetDevice;
use crate::net::ethernet::{EtherType, PktType};
use crate::net::ipv4::Ipv4Addr;

/// Standard headroom to reserve for headers
pub const NET_SKB_PAD: usize = 64;

/// Maximum Ethernet frame size (without VLAN)
pub const ETH_FRAME_LEN: usize = 1514;

/// Maximum packet size we'll allocate
/// Largest buffer: a 64 KB IP datagram plus headroom (loopback MTU)
pub const MAX_SKB_SIZE: usize = 65536 + 512;

/// Network buffer - equivalent to Linux sk_buff
///
/// # Invariants
/// `data <= tail <= buf.len()`; `mac` and `nh`, when set, are at most
/// `tail` (moving `tail` below one clears it).
pub struct SkBuff {
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
    /// Allocate a new SkBuff with given size
    ///
    /// The buffer will have `headroom` bytes reserved before data
    /// and space for `data_len` bytes of data.
    pub fn alloc(headroom: usize, data_len: usize) -> Option<Box<Self>> {
        let total_size = headroom.checked_add(data_len)?;
        if total_size > MAX_SKB_SIZE {
            return None;
        }
        let mut v = alloc::vec::Vec::new();
        v.try_reserve_exact(total_size).ok()?;
        v.resize(total_size, 0u8);

        try_box(Self {
            buf: v.into_boxed_slice(),
            data: headroom,
            tail: headroom,
            protocol: EtherType::Unknown(0),
            ip_protocol: 0,
            dev: None,
            saddr: None,
            daddr: None,
            pkt_type: PktType::Host,
            ip_bcast: false,
            ip_ttl: 0,
            ip_tos: 0,
            owner: 0,
            mac: None,
            nh: None,
        })
        .ok()
    }

    /// Allocate a new SkBuff for receiving packets
    ///
    /// This allocates with standard headroom and space for max Ethernet frame.
    pub fn alloc_rx() -> Option<Box<Self>> {
        Self::alloc(NET_SKB_PAD, ETH_FRAME_LEN)
    }

    /// Allocate a new SkBuff for transmitting packets
    ///
    /// This allocates with space for all headers (Ethernet + IP + TCP).
    pub fn alloc_tx(data_len: usize) -> Option<Box<Self>> {
        // Reserve space for: Ethernet (14) + IP (20-60) + TCP (20-60)
        let headroom = 14 + 60 + 60;
        Self::alloc(headroom, data_len)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alloc_and_put() {
        let mut skb = SkBuff::alloc(64, 1500).unwrap();
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
        let mut skb = SkBuff::alloc(64, 1500).unwrap();

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
        let mut skb = SkBuff::alloc(16, 32).unwrap();
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
}

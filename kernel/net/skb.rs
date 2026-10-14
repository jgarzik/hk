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

use alloc::boxed::Box;
use alloc::sync::Arc;

use crate::dma::DmaAddr;
use crate::net::device::NetDevice;
use crate::net::ethernet::{EtherType, PktType};
use crate::net::ipv4::Ipv4Addr;

/// Standard headroom to reserve for headers
pub const NET_SKB_PAD: usize = 64;

/// Maximum Ethernet frame size (without VLAN)
pub const ETH_FRAME_LEN: usize = 1514;

/// Maximum packet size we'll allocate
pub const MAX_SKB_SIZE: usize = 2048;

/// Network buffer - equivalent to Linux sk_buff
pub struct SkBuff {
    // Buffer pointers (all within the same allocation)
    /// Start of allocated buffer (fixed)
    head: *mut u8,
    /// Start of actual packet data (moves with push/pull)
    data: *mut u8,
    /// End of actual packet data (moves with put/trim)
    tail: *mut u8,
    /// End of allocated buffer (fixed)
    end: *mut u8,

    /// Total allocation size
    alloc_size: usize,

    // Protocol information
    /// EtherType (set by eth_type_trans)
    pub protocol: EtherType,
    /// IP protocol number (set by IP layer)
    pub ip_protocol: u8,

    // Header offsets (from data pointer)
    /// Transport header offset
    pub transport_header: usize,
    /// Network header offset
    pub network_header: usize,
    /// MAC header offset (usually 0)
    pub mac_header: usize,

    // Device reference
    /// Source/destination device
    pub dev: Option<Arc<NetDevice>>,

    // DMA address (for zero-copy with device)
    pub dma_addr: Option<DmaAddr>,

    // Checksum state
    pub ip_summed: ChecksumState,

    // IP addresses (set by IP layer for routing)
    pub saddr: Option<Ipv4Addr>,
    pub daddr: Option<Ipv4Addr>,

    /// Receive classification (set by eth_type_trans)
    pub pkt_type: PktType,
    /// Received IP packet was addressed to a broadcast address (Linux
    /// RTCF_BROADCAST; set by ip_rcv)
    pub ip_bcast: bool,
    /// Start of the MAC header in the buffer (null until received)
    mac: *mut u8,
}

/// Checksum state for hardware offload
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChecksumState {
    /// No checksum computed
    #[default]
    None,
    /// Checksum verified by hardware
    Unnecessary,
    /// Partial checksum computed by hardware
    Partial,
    /// Complete checksum computed by hardware
    Complete,
}

// SkBuff contains raw pointers but manages its own memory
unsafe impl Send for SkBuff {}
unsafe impl Sync for SkBuff {}

impl SkBuff {
    /// Allocate a new SkBuff with given size
    ///
    /// The buffer will have `headroom` bytes reserved before data
    /// and space for `data_len` bytes of data.
    pub fn alloc(headroom: usize, data_len: usize) -> Option<Box<Self>> {
        let total_size = headroom + data_len;
        if total_size > MAX_SKB_SIZE {
            return None;
        }

        // Allocate aligned buffer
        let layout = alloc::alloc::Layout::from_size_align(total_size, 16).ok()?;
        let buffer = unsafe { alloc::alloc::alloc_zeroed(layout) };

        if buffer.is_null() {
            return None;
        }

        let head = buffer;
        let end = unsafe { buffer.add(total_size) };
        let data = unsafe { buffer.add(headroom) };
        let tail = data; // Initially empty

        Some(Box::new(Self {
            head,
            data,
            tail,
            end,
            alloc_size: total_size,
            protocol: EtherType::Unknown(0),
            ip_protocol: 0,
            transport_header: 0,
            network_header: 0,
            mac_header: 0,
            dev: None,
            dma_addr: None,
            ip_summed: ChecksumState::None,
            saddr: None,
            daddr: None,
            pkt_type: PktType::Host,
            ip_bcast: false,
            mac: core::ptr::null_mut(),
        }))
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
        self.tail as usize - self.data as usize
    }

    /// Check if buffer is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get headroom (space before data)
    #[inline]
    pub fn headroom(&self) -> usize {
        self.data as usize - self.head as usize
    }

    /// Get tailroom (space after tail)
    #[inline]
    pub fn tailroom(&self) -> usize {
        self.end as usize - self.tail as usize
    }

    /// Get the data as a byte slice
    #[inline]
    pub fn data(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.data, self.len()) }
    }

    /// Get the data as a mutable byte slice
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.data, self.len()) }
    }

    /// Get raw data pointer
    #[inline]
    pub fn data_ptr(&self) -> *const u8 {
        self.data
    }

    /// Get raw data pointer (mutable)
    #[inline]
    pub fn data_ptr_mut(&mut self) -> *mut u8 {
        self.data
    }

    /// Reserve headroom (call before adding data)
    ///
    /// Moves the data pointer forward, creating more headroom.
    /// Must be called on an empty buffer.
    pub fn reserve(&mut self, len: usize) {
        debug_assert!(self.is_empty(), "reserve called on non-empty skb");
        debug_assert!(
            self.headroom() + len <= self.alloc_size,
            "reserve exceeds buffer"
        );

        unsafe {
            self.data = self.data.add(len);
            self.tail = self.data;
        }
    }

    /// Push header - prepend bytes to the front
    ///
    /// Moves the data pointer backward, returns slice to fill.
    /// Used for adding headers (Ethernet, IP, TCP).
    pub fn push(&mut self, len: usize) -> Option<&mut [u8]> {
        if self.headroom() < len {
            return None;
        }

        unsafe {
            self.data = self.data.sub(len);
            Some(core::slice::from_raw_parts_mut(self.data, len))
        }
    }

    /// Pull header - consume bytes from the front
    ///
    /// Moves the data pointer forward, returns consumed data.
    /// Used for parsing headers.
    pub fn pull(&mut self, len: usize) -> Option<&[u8]> {
        if self.len() < len {
            return None;
        }

        let result = unsafe { core::slice::from_raw_parts(self.data, len) };
        unsafe {
            self.data = self.data.add(len);
        }
        Some(result)
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
        unsafe {
            self.tail = self.tail.add(len);
            Some(core::slice::from_raw_parts_mut(start, len))
        }
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

        unsafe {
            self.tail = self.tail.sub(len);
        }
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

    /// Reset the buffer to initial state (keeps allocation)
    pub fn reset(&mut self, headroom: usize) {
        unsafe {
            self.data = self.head.add(headroom);
            self.tail = self.data;
        }
        self.protocol = EtherType::Unknown(0);
        self.ip_protocol = 0;
        self.transport_header = 0;
        self.network_header = 0;
        self.mac_header = 0;
        self.ip_summed = ChecksumState::None;
        self.saddr = None;
        self.daddr = None;
        self.pkt_type = PktType::Host;
        self.ip_bcast = false;
        self.mac = core::ptr::null_mut();
    }

    // Header offset helpers

    /// Set the network header position (current data offset)
    pub fn set_network_header(&mut self) {
        self.network_header = 0;
    }

    /// Set the network header position with offset from data
    pub fn set_network_header_offset(&mut self, offset: usize) {
        self.network_header = offset;
    }

    /// Set the transport header position
    pub fn set_transport_header(&mut self, offset: usize) {
        self.transport_header = offset;
    }

    /// Set the MAC header position
    pub fn set_mac_header(&mut self) {
        self.mac_header = 0;
    }

    /// Get network header as slice
    pub fn network_header(&self) -> &[u8] {
        &self.data()[self.network_header..]
    }

    /// Get transport header as slice
    pub fn transport_header(&self) -> &[u8] {
        &self.data()[self.transport_header..]
    }

    /// Get MAC header as slice
    pub fn mac_header(&self) -> &[u8] {
        &self.data()[self.mac_header..]
    }

    /// Record the current data pointer as the start of the MAC header
    pub fn mark_mac_header(&mut self) {
        self.mac = self.data;
    }

    /// The received frame from its MAC header to the end (after the
    /// header was pulled), if one was recorded
    pub fn frame_from_mac(&self) -> Option<&[u8]> {
        if self.mac.is_null() {
            return None;
        }
        let len = self.tail as usize - self.mac as usize;
        Some(unsafe { core::slice::from_raw_parts(self.mac, len) })
    }

    /// Network namespace of the skb's device (receive path: the namespace
    /// the packet arrived in; never the current task's)
    pub fn net(&self) -> Option<Arc<crate::net::NetNamespace>> {
        self.dev.as_ref()?.net()
    }
}

impl Drop for SkBuff {
    fn drop(&mut self) {
        if !self.head.is_null() {
            let layout =
                alloc::alloc::Layout::from_size_align(self.alloc_size, 16).expect("valid layout");
            unsafe {
                alloc::alloc::dealloc(self.head, layout);
            }
        }
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
}

//! ICMP Protocol Implementation
//!
//! This module implements the Internet Control Message Protocol (ICMP)
//! for IPv4. Currently supports:
//! - Echo Request/Reply (ping)

use core::sync::atomic::{AtomicU64, Ordering};

use crate::net::NetNamespace;
use crate::net::ipv4::{self, IPPROTO_ICMP, Ipv4Addr};
use crate::net::skb::SkBuff;
use crate::waitqueue::WaitQueue;

/// ICMP header length (fixed 8 bytes for echo)
pub const ICMP_HLEN: usize = 8;

/// ICMP types
pub mod icmp_type {
    /// Echo reply
    pub const ECHO_REPLY: u8 = 0;
    /// Destination unreachable
    pub const DEST_UNREACHABLE: u8 = 3;
    /// Echo request (ping)
    pub const ECHO_REQUEST: u8 = 8;
    /// Time exceeded
    pub const TIME_EXCEEDED: u8 = 11;
}

/// ICMP header structure
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct IcmpHdr {
    /// ICMP type
    pub icmp_type: u8,
    /// ICMP code
    pub code: u8,
    /// Checksum (big-endian)
    pub checksum: [u8; 2],
    /// Identifier (for echo, big-endian)
    pub id: [u8; 2],
    /// Sequence number (for echo, big-endian)
    pub sequence: [u8; 2],
}

impl IcmpHdr {
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.checksum)
    }

    pub fn id(&self) -> u16 {
        u16::from_be_bytes(self.id)
    }

    pub fn sequence(&self) -> u16 {
        u16::from_be_bytes(self.sequence)
    }
}

/// ICMP counters (Linux Icmp: InEchos / InEchoReps / OutEchoReps; global,
/// not yet per namespace)
pub static ICMP_IN_ECHOS: AtomicU64 = AtomicU64::new(0);
pub static ICMP_IN_ECHO_REPS: AtomicU64 = AtomicU64::new(0);
pub static ICMP_OUT_ECHO_REPS: AtomicU64 = AtomicU64::new(0);
/// Woken on every received echo reply
pub static ICMP_ECHO_REPLY_WQ: WaitQueue = WaitQueue::new();

/// Receive an ICMP packet (called from ipv4::ip_rcv; thread context; the
/// reply goes out in the receiving device's namespace)
pub fn icmp_rcv(skb: SkBuff) {
    let Some(net) = skb.net() else {
        return;
    };
    // Check minimum length
    if skb.len() < ICMP_HLEN {
        return;
    }

    // Parse ICMP header
    let hdr = unsafe { &*(skb.data().as_ptr() as *const IcmpHdr) };

    // Verify checksum
    if !verify_checksum(skb.data()) {
        return;
    }

    // Get source/dest IPs from skb (set by ip_rcv)
    let saddr = match skb.saddr {
        Some(a) => a,
        None => return,
    };
    let daddr = match skb.daddr {
        Some(a) => a,
        None => return,
    };

    // Handle ICMP type
    match hdr.icmp_type {
        icmp_type::ECHO_REQUEST => {
            ICMP_IN_ECHOS.fetch_add(1, Ordering::Relaxed);
            icmp_echo_reply(&net, saddr, daddr, hdr, &skb.data()[ICMP_HLEN..]);
        }
        icmp_type::ECHO_REPLY => {
            // No ping sockets yet (P5): count and notify
            let _ = (saddr, hdr.id(), hdr.sequence());
            ICMP_IN_ECHO_REPS.fetch_add(1, Ordering::Relaxed);
            ICMP_ECHO_REPLY_WQ.wake_all();
        }
        _ => {
            // Other ICMP types not handled yet
        }
    }
}

/// Send an ICMP echo reply
fn icmp_echo_reply(
    net: &NetNamespace,
    dest: Ipv4Addr,
    src: Ipv4Addr,
    req_hdr: &IcmpHdr,
    data: &[u8],
) {
    // Allocate skb for response
    let payload_len = data.len();
    let mut skb = match SkBuff::alloc_tx(ICMP_HLEN + payload_len) {
        Some(s) => s,
        None => return,
    };

    // Copy echo data
    if skb.put(payload_len).is_none() {
        return;
    }
    skb.data_mut()[..payload_len].copy_from_slice(data);

    // Build ICMP header (prepend)
    let hdr_bytes = match skb.push(ICMP_HLEN) {
        Some(b) => b,
        None => return,
    };

    // Type: Echo Reply
    hdr_bytes[0] = icmp_type::ECHO_REPLY;
    // Code: 0
    hdr_bytes[1] = 0;
    // Checksum (compute after header is built)
    hdr_bytes[2] = 0;
    hdr_bytes[3] = 0;
    // Copy ID and sequence from request
    hdr_bytes[4..6].copy_from_slice(&req_hdr.id);
    hdr_bytes[6..8].copy_from_slice(&req_hdr.sequence);

    // Compute checksum
    let checksum = compute_checksum(skb.data());
    skb.data_mut()[2..4].copy_from_slice(&checksum.to_be_bytes());

    // Set addresses for IP layer
    skb.saddr = Some(src);
    skb.daddr = Some(dest);

    // Send through IP layer
    if ipv4::ip_queue_xmit(net, skb, IPPROTO_ICMP).is_ok() {
        ICMP_OUT_ECHO_REPS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Send an ICMP echo request from `net` (kernel self-test; ping sockets
/// come with P5)
pub fn icmp_send_echo(
    net: &NetNamespace,
    dest: Ipv4Addr,
    id: u16,
    seq: u16,
    payload: &[u8],
) -> Result<(), crate::error::KernelError> {
    use crate::error::KernelError;
    let mut skb = SkBuff::alloc_tx(ICMP_HLEN + payload.len()).ok_or(KernelError::NoBufferSpace)?;
    skb.put_slice(payload).ok_or(KernelError::NoBufferSpace)?;
    let hdr = skb.push(ICMP_HLEN).ok_or(KernelError::NoBufferSpace)?;
    hdr[0] = icmp_type::ECHO_REQUEST;
    hdr[1] = 0;
    hdr[2] = 0;
    hdr[3] = 0;
    hdr[4..6].copy_from_slice(&id.to_be_bytes());
    hdr[6..8].copy_from_slice(&seq.to_be_bytes());
    let checksum = compute_checksum(skb.data());
    skb.data_mut()[2..4].copy_from_slice(&checksum.to_be_bytes());
    skb.daddr = Some(dest);
    ipv4::ip_queue_xmit(net, skb, IPPROTO_ICMP)
}

/// Compute ICMP checksum
fn compute_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Sum all 16-bit words
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }

    // Add odd byte if present
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Take one's complement
    !(sum as u16)
}

/// Verify ICMP checksum
fn verify_checksum(data: &[u8]) -> bool {
    compute_checksum(data) == 0
}

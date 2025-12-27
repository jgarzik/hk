//! UDP Protocol Implementation
//!
//! This module implements the UDP protocol for datagram sockets.
//! UDP is connectionless and stateless - no handshaking or connection state.

use alloc::sync::Arc;

use crate::net::KernelError;
use crate::net::ipv4::{self, IPPROTO_UDP, Ipv4Addr};
use crate::net::skb::SkBuff;
use crate::net::socket::{Socket, SocketType};

/// UDP header length (fixed 8 bytes)
pub const UDP_HLEN: usize = 8;

/// UDP header structure
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct UdpHdr {
    /// Source port (big-endian)
    pub source: [u8; 2],
    /// Destination port (big-endian)
    pub dest: [u8; 2],
    /// Length of UDP header + data (big-endian)
    pub len: [u8; 2],
    /// Checksum (big-endian)
    pub check: [u8; 2],
}

impl UdpHdr {
    pub fn source_port(&self) -> u16 {
        u16::from_be_bytes(self.source)
    }

    pub fn dest_port(&self) -> u16 {
        u16::from_be_bytes(self.dest)
    }

    pub fn length(&self) -> u16 {
        u16::from_be_bytes(self.len)
    }

    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.check)
    }
}

/// UDP two-tuple for socket lookup (local addr:port)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UdpTwoTuple {
    pub local_addr: Ipv4Addr,
    pub local_port: u16,
}

/// Register a UDP socket in the current namespace
pub fn udp_register_socket(tuple: UdpTwoTuple, socket: Arc<Socket>) {
    crate::net::current_net_ns().udp_register(tuple, socket);
}

/// Unregister a UDP socket from the current namespace
pub fn udp_unregister_socket(tuple: &UdpTwoTuple) {
    crate::net::current_net_ns().udp_unregister(tuple);
}

/// Look up a UDP socket in the current namespace by port
pub fn udp_lookup_socket(local_port: u16) -> Option<Arc<Socket>> {
    crate::net::current_net_ns().udp_lookup_by_port(local_port)
}

/// Receive a UDP packet (called from ipv4::ip_rcv)
pub fn udp_rcv(skb: SkBuff) {
    // Check minimum length
    if skb.len() < UDP_HLEN {
        return;
    }

    // Parse UDP header
    let hdr = unsafe { &*(skb.data().as_ptr() as *const UdpHdr) };

    let dest_port = hdr.dest_port();
    let source_port = hdr.source_port();
    let udp_len = hdr.length() as usize;

    // Validate length
    if udp_len < UDP_HLEN || udp_len > skb.len() {
        return;
    }

    // Get source/dest IPs from skb (set by ip_rcv)
    let saddr = match skb.saddr {
        Some(a) => a,
        None => return,
    };
    let _daddr = match skb.daddr {
        Some(a) => a,
        None => return,
    };

    // Optional: verify checksum (UDP checksum is optional in IPv4)
    // For now, accept all packets

    // Extract payload (skip UDP header)
    let payload_len = udp_len - UDP_HLEN;
    let payload = &skb.data()[UDP_HLEN..UDP_HLEN + payload_len];

    // Look up socket by destination port
    if let Some(socket) = udp_lookup_socket(dest_port) {
        // Verify socket type is datagram
        if socket.sock_type != SocketType::Dgram {
            return;
        }

        // Deliver datagram to socket's receive queue
        socket.deliver_datagram(saddr, source_port, payload);
        socket.wake_rx();
    }
    // If no socket found, silently drop (could send ICMP port unreachable)
}

/// Send a UDP datagram
///
/// # Arguments
/// * `socket` - The sending socket
/// * `data` - The data to send
/// * `dest` - Optional destination (addr, port). If None, uses socket's remote address.
pub fn udp_sendmsg(
    socket: &Arc<Socket>,
    data: &[u8],
    dest: Option<(Ipv4Addr, u16)>,
) -> Result<usize, KernelError> {
    // Get destination address
    let (dest_addr, dest_port) = match dest {
        Some((addr, port)) => (addr, port),
        None => {
            // Use connected address
            socket.remote_addr().ok_or(KernelError::InvalidArgument)?
        }
    };

    // Get source address and port
    let (src_addr, src_port) = match socket.local_addr() {
        Some((addr, port)) => {
            if port == 0 {
                // Need to allocate ephemeral port and register for receiving
                let port = crate::net::current_net_ns().alloc_port();
                socket.set_local(addr, port);
                // Register socket so we can receive replies
                let tuple = UdpTwoTuple {
                    local_addr: addr,
                    local_port: port,
                };
                udp_register_socket(tuple, Arc::clone(socket));
                (addr, port)
            } else {
                (addr, port)
            }
        }
        None => {
            // Get source IP from config and allocate port
            let config = crate::net::get_config().ok_or(KernelError::InvalidArgument)?;
            let port = crate::net::current_net_ns().alloc_port();
            socket.set_local(config.ipv4_addr, port);
            // Register socket so we can receive replies
            let tuple = UdpTwoTuple {
                local_addr: config.ipv4_addr,
                local_port: port,
            };
            udp_register_socket(tuple, Arc::clone(socket));
            (config.ipv4_addr, port)
        }
    };

    // Build and send UDP packet
    udp_build_and_send(src_addr, src_port, dest_addr, dest_port, data)?;

    Ok(data.len())
}

/// Build UDP header, add IP header, and transmit
fn udp_build_and_send(
    saddr: Ipv4Addr,
    sport: u16,
    daddr: Ipv4Addr,
    dport: u16,
    data: &[u8],
) -> Result<(), KernelError> {
    // Allocate skb for UDP packet (returns Box<SkBuff>)
    let mut skb = SkBuff::alloc_tx(UDP_HLEN + data.len()).ok_or(KernelError::NoBufferSpace)?;

    // Copy payload data
    skb.put(data.len()).ok_or(KernelError::NoBufferSpace)?;
    skb.data_mut()[..data.len()].copy_from_slice(data);

    // Build UDP header (prepend)
    let udp_len = (UDP_HLEN + data.len()) as u16;
    let hdr_bytes = skb.push(UDP_HLEN).ok_or(KernelError::NoBufferSpace)?;

    // Source port
    hdr_bytes[0..2].copy_from_slice(&sport.to_be_bytes());
    // Destination port
    hdr_bytes[2..4].copy_from_slice(&dport.to_be_bytes());
    // Length
    hdr_bytes[4..6].copy_from_slice(&udp_len.to_be_bytes());
    // Checksum (compute after header is built)
    hdr_bytes[6..8].copy_from_slice(&[0, 0]);

    // Compute checksum over pseudo-header + UDP header + data
    let checksum = udp_checksum(saddr, daddr, skb.data());
    skb.data_mut()[6..8].copy_from_slice(&checksum.to_be_bytes());

    // Set destination for IP layer
    skb.saddr = Some(saddr);
    skb.daddr = Some(daddr);

    // Hand off to IP layer (skb is already Box<SkBuff>)
    ipv4::ip_queue_xmit(skb, IPPROTO_UDP)?;

    Ok(())
}

/// Compute UDP checksum
///
/// UDP checksum is computed over a pseudo-header (source IP, dest IP,
/// protocol, UDP length) plus the UDP header and data.
pub fn udp_checksum(saddr: Ipv4Addr, daddr: Ipv4Addr, udp_data: &[u8]) -> u16 {
    let len = udp_data.len() as u16;

    // Start with pseudo-header
    let mut sum = ipv4::pseudo_header_checksum(saddr, daddr, IPPROTO_UDP, len);

    // Add UDP header and data
    let mut i = 0;
    while i + 1 < udp_data.len() {
        sum += u16::from_be_bytes([udp_data[i], udp_data[i + 1]]) as u32;
        i += 2;
    }
    if i < udp_data.len() {
        sum += (udp_data[i] as u32) << 8;
    }

    // Fold and complement
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let result = !(sum as u16);

    // UDP checksum of 0 is transmitted as 0xFFFF (0 means "no checksum")
    if result == 0 { 0xFFFF } else { result }
}

//! Address Resolution Protocol (ARP)
//!
//! This module implements ARP for IPv4 to Ethernet address resolution.
//!
//! ARP cache entries are stored per-namespace in NetNamespace.

use alloc::boxed::Box;
use alloc::sync::Arc;

use crate::net::KernelError;
use crate::net::device::NetDevice;
use crate::net::ethernet::{self, ETH_ALEN, ETH_BROADCAST, ETH_HLEN, EtherType};
use crate::net::inet::fib::RouteType;
use crate::net::inet::ifaddr::{RT_SCOPE_LINK, inet_select_addr};
use crate::net::ipv4::{self, Ipv4Addr};
use crate::net::skb::SkBuff;

/// ARP hardware type: Ethernet
pub const ARPHRD_ETHER: u16 = 1;

/// ARP operation: Request
pub const ARPOP_REQUEST: u16 = 1;
/// ARP operation: Reply
pub const ARPOP_REPLY: u16 = 2;

/// ARP header size (for Ethernet/IPv4)
pub const ARP_HLEN: usize = 28;

/// ARP cache entry timeout (in timer ticks, ~5 minutes)
const ARP_TIMEOUT: u64 = 300 * 100; // 300 seconds at 100Hz

/// ARP entry state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpState {
    /// Entry is incomplete (waiting for reply)
    Incomplete,
    /// Entry is reachable
    Reachable,
    /// Entry is stale (needs refresh)
    Stale,
    /// ARP failed (no response)
    Failed,
}

/// ARP cache entry
#[derive(Clone)]
pub struct ArpEntry {
    /// Target IP address
    pub ip: Ipv4Addr,
    /// Resolved MAC address
    pub mac: [u8; ETH_ALEN],
    /// Entry state
    pub state: ArpState,
    /// Expiration time (timer ticks)
    pub expires: u64,
    /// Retry count
    pub retries: u8,
    /// Device the neighbour was learned on
    pub ifindex: u32,
}

/// Packets waiting for ARP resolution
pub struct PendingPacket {
    pub skb: Box<SkBuff>,
}

/// ARP header structure (Ethernet/IPv4)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct ArpHdr {
    /// Hardware type (ARPHRD_ETHER = 1)
    pub ar_hrd: [u8; 2],
    /// Protocol type (ETH_P_IP = 0x0800)
    pub ar_pro: [u8; 2],
    /// Hardware address length (6 for Ethernet)
    pub ar_hln: u8,
    /// Protocol address length (4 for IPv4)
    pub ar_pln: u8,
    /// Operation (ARPOP_REQUEST or ARPOP_REPLY)
    pub ar_op: [u8; 2],
    /// Sender hardware address
    pub ar_sha: [u8; ETH_ALEN],
    /// Sender protocol address
    pub ar_sip: [u8; 4],
    /// Target hardware address
    pub ar_tha: [u8; ETH_ALEN],
    /// Target protocol address
    pub ar_tip: [u8; 4],
}

impl ArpHdr {
    pub fn hardware_type(&self) -> u16 {
        u16::from_be_bytes(self.ar_hrd)
    }

    pub fn protocol_type(&self) -> u16 {
        u16::from_be_bytes(self.ar_pro)
    }

    pub fn operation(&self) -> u16 {
        u16::from_be_bytes(self.ar_op)
    }

    pub fn sender_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from_be_bytes(self.ar_sip)
    }

    pub fn target_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from_be_bytes(self.ar_tip)
    }
}

/// Receive an ARP packet (EtherType 0x0806 handler; thread context)
///
/// Uses the receiving device's namespace.
pub fn arp_rcv(skb: SkBuff) {
    if skb.len() < ARP_HLEN {
        return;
    }

    // Parse ARP header
    let hdr = unsafe { &*(skb.data().as_ptr() as *const ArpHdr) };

    // Validate hardware/protocol types
    if hdr.hardware_type() != ARPHRD_ETHER || hdr.protocol_type() != 0x0800 {
        return;
    }
    if hdr.ar_hln != 6 || hdr.ar_pln != 4 {
        return;
    }

    let sender_ip = hdr.sender_ip();
    let sender_mac = hdr.ar_sha;
    let target_ip = hdr.target_ip();
    let op = hdr.operation();

    let Some(ns) = skb.net() else {
        return;
    };
    let now = crate::time::current_ticks();

    let Some(dev) = skb.dev.as_ref() else {
        return;
    };

    // Update cache with sender's info (learning)
    ns.arp_insert(ArpEntry {
        ip: sender_ip,
        mac: sender_mac,
        state: ArpState::Reachable,
        expires: now + ARP_TIMEOUT,
        retries: 0,
        ifindex: dev.ifindex(),
    });

    // If we have pending packets for this IP, send them
    let pending = ns.arp_take_pending(sender_ip);
    for packet in pending {
        let _ = ipv4::ip_finish_output(packet.skb, sender_mac);
    }

    match op {
        ARPOP_REQUEST => {
            // Answer for any local address (Linux arp_ignore=0)
            if ns.fib.addr_type(target_ip) == RouteType::Local {
                send_arp_reply(dev, target_ip, sender_ip, &sender_mac);
            }
        }
        ARPOP_REPLY => {
            // Already handled by cache update above
            crate::printkln!(
                "arp: reply from {} ({:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
                sender_ip,
                sender_mac[0],
                sender_mac[1],
                sender_mac[2],
                sender_mac[3],
                sender_mac[4],
                sender_mac[5]
            );
        }
        _ => {}
    }
}

/// Resolve an IP address to MAC address
///
/// Returns the MAC if cached, otherwise sends ARP request and
/// queues the packet for later transmission.
///
/// Uses the ARP cache of `ns` (the output device's namespace).
pub fn arp_resolve(
    ns: &crate::net::NetNamespace,
    dev: &Arc<NetDevice>,
    ip: Ipv4Addr,
    skb: Box<SkBuff>,
) -> Result<(), KernelError> {
    let now = crate::time::current_ticks();

    // Cached: transmit now; else queue until the reply arrives
    let skb = match ns.arp_resolve_or_queue(ip, PendingPacket { skb }) {
        Ok(()) => None,
        Err((mac, packet)) => Some((mac, packet.skb)),
    };
    if let Some((mac, skb)) = skb {
        return crate::net::ipv4::ip_finish_output(skb, mac);
    }

    // Add incomplete entry if not present (never overwrites a reply that
    // raced in)
    ns.arp_insert_if_absent(ArpEntry {
        ip,
        mac: [0; 6],
        state: ArpState::Incomplete,
        expires: now + ARP_TIMEOUT,
        retries: 0,
        ifindex: dev.ifindex(),
    });

    // Send ARP request
    send_arp_request(ns, dev, ip);

    // Packet is queued, return success (it will be sent when ARP completes)
    Ok(())
}

/// Send an ARP request (Linux arp_solicit; sender address from
/// inet_select_addr, 0.0.0.0 if the device has none)
fn send_arp_request(ns: &crate::net::NetNamespace, dev: &NetDevice, target_ip: Ipv4Addr) {
    let our_ip = inet_select_addr(ns, dev, target_ip, RT_SCOPE_LINK).unwrap_or_default();

    let mut skb = match SkBuff::alloc(64, ARP_HLEN + ETH_HLEN) {
        Some(s) => s,
        None => return,
    };

    // Build ARP payload
    let arp_data = skb.put(ARP_HLEN).unwrap();

    // Hardware type: Ethernet
    arp_data[0..2].copy_from_slice(&ARPHRD_ETHER.to_be_bytes());
    // Protocol type: IPv4
    arp_data[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
    // Hardware address length
    arp_data[4] = 6;
    // Protocol address length
    arp_data[5] = 4;
    // Operation: Request
    arp_data[6..8].copy_from_slice(&ARPOP_REQUEST.to_be_bytes());
    // Sender hardware address
    arp_data[8..14].copy_from_slice(&dev.mac());
    // Sender protocol address
    arp_data[14..18].copy_from_slice(&our_ip.to_be_bytes());
    // Target hardware address (unknown)
    arp_data[18..24].copy_from_slice(&[0; 6]);
    // Target protocol address
    arp_data[24..28].copy_from_slice(&target_ip.to_be_bytes());

    // Build Ethernet header (broadcast)
    ethernet::eth_header(&mut skb, &ETH_BROADCAST, &dev.mac(), EtherType::Arp);

    // Transmit
    let _ = dev.xmit(skb);
}

/// Send an ARP reply claiming `our_ip`
fn send_arp_reply(
    dev: &NetDevice,
    our_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    target_mac: &[u8; ETH_ALEN],
) {
    let mut skb = match SkBuff::alloc(64, ARP_HLEN + ETH_HLEN) {
        Some(s) => s,
        None => return,
    };

    // Build ARP payload
    let arp_data = skb.put(ARP_HLEN).unwrap();

    // Hardware type: Ethernet
    arp_data[0..2].copy_from_slice(&ARPHRD_ETHER.to_be_bytes());
    // Protocol type: IPv4
    arp_data[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
    // Hardware address length
    arp_data[4] = 6;
    // Protocol address length
    arp_data[5] = 4;
    // Operation: Reply
    arp_data[6..8].copy_from_slice(&ARPOP_REPLY.to_be_bytes());
    // Sender hardware address (our MAC)
    arp_data[8..14].copy_from_slice(&dev.mac());
    // Sender protocol address (our IP)
    arp_data[14..18].copy_from_slice(&our_ip.to_be_bytes());
    // Target hardware address
    arp_data[18..24].copy_from_slice(target_mac);
    // Target protocol address
    arp_data[24..28].copy_from_slice(&target_ip.to_be_bytes());

    // Build Ethernet header
    ethernet::eth_header(&mut skb, target_mac, &dev.mac(), EtherType::Arp);

    // Transmit
    let _ = dev.xmit(skb);
}

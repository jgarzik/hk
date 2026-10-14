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

/// What to do with a received ARP packet (Linux arp_process with
/// arp_accept=0, arp_ignore=0, route_localnet=0)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpAction {
    /// Ignore it (reason, for debugging)
    Drop(&'static str),
    /// Another host claims one of our addresses: log, ignore
    Conflict,
    /// Duplicate address probe (sender 0.0.0.0) for our address: reply,
    /// learn nothing
    ProbeReply,
    /// Request for one of our addresses: create/update the sender's
    /// entry, reply
    Reply,
    /// Anything else: update an existing entry for the sender only
    Update,
}

/// Decide how to handle an ARP packet from `sip`/`sha` for `tip`
/// received on a device with MAC `our_mac`. `addr_type` classifies
/// addresses in the device's namespace. Entries are only *created* for
/// requests addressed to us, so unsolicited replies and gratuitous ARP
/// cannot poison the cache.
pub fn classify(
    op: u16,
    sip: Ipv4Addr,
    sha: &[u8; ETH_ALEN],
    tip: Ipv4Addr,
    our_mac: &[u8; ETH_ALEN],
    addr_type: impl Fn(Ipv4Addr) -> RouteType,
) -> ArpAction {
    if op != ARPOP_REQUEST && op != ARPOP_REPLY {
        return ArpAction::Drop("unknown op");
    }
    if tip.is_multicast() || tip.is_loopback() {
        return ArpAction::Drop("bad target");
    }
    if sha[0] & 1 != 0 || sha.iter().all(|&b| b == 0) {
        return ArpAction::Drop("multicast or zero sender MAC");
    }
    let tip_local = addr_type(tip) == RouteType::Local;
    if sip.is_unspecified() {
        return if op == ARPOP_REQUEST && tip_local {
            ArpAction::ProbeReply
        } else {
            ArpAction::Drop("zero sender")
        };
    }
    if sip.is_multicast() || sip.is_broadcast() || sip.is_loopback() || (sip.0 >> 24) == 0 {
        return ArpAction::Drop("martian sender");
    }
    match addr_type(sip) {
        RouteType::Local if sha != our_mac => return ArpAction::Conflict,
        RouteType::Local => return ArpAction::Drop("own packet"),
        RouteType::Broadcast => return ArpAction::Drop("broadcast sender"),
        _ => {}
    }
    if op == ARPOP_REQUEST && tip_local {
        ArpAction::Reply
    } else {
        ArpAction::Update
    }
}

/// Receive an ARP packet (EtherType 0x0806 handler; thread context)
///
/// Uses the receiving device's namespace.
pub fn arp_rcv(skb: SkBuff) {
    if skb.len() < ARP_HLEN {
        return;
    }
    let hdr = unsafe { core::ptr::read_unaligned(skb.data().as_ptr() as *const ArpHdr) };
    if hdr.hardware_type() != ARPHRD_ETHER || hdr.protocol_type() != 0x0800 {
        return;
    }
    if hdr.ar_hln != 6 || hdr.ar_pln != 4 {
        return;
    }
    let (Some(ns), Some(dev)) = (skb.net(), skb.dev.as_ref()) else {
        return;
    };
    let (sip, sha, tip) = (hdr.sender_ip(), hdr.ar_sha, hdr.target_ip());
    let act = classify(hdr.operation(), sip, &sha, tip, &dev.mac(), |a| {
        ns.fib.addr_type(a)
    });
    match act {
        ArpAction::Drop(_) => {}
        ArpAction::Conflict => conflict(sip, &sha),
        ArpAction::ProbeReply => send_arp_reply(dev, tip, sip, &sha),
        ArpAction::Reply => {
            learn(&ns, sip, &sha, dev.ifindex(), true);
            send_arp_reply(dev, tip, sip, &sha);
        }
        ArpAction::Update => learn(&ns, sip, &sha, dev.ifindex(), false),
    }
}

/// Record `sip` at `sha` (`create`: even without an existing entry),
/// then transmit the packets that were waiting for it
fn learn(
    ns: &crate::net::NetNamespace,
    sip: Ipv4Addr,
    sha: &[u8; ETH_ALEN],
    ifindex: u32,
    create: bool,
) {
    let entry = ArpEntry {
        ip: sip,
        mac: *sha,
        state: ArpState::Reachable,
        expires: crate::time::current_ticks() + ARP_TIMEOUT,
        retries: 0,
        ifindex,
    };
    if !ns.arp_update(entry, create) {
        return;
    }
    for packet in ns.arp_take_pending(sip) {
        let _ = ipv4::ip_finish_output(packet.skb, *sha);
    }
}

/// Log a host claiming one of our addresses (rate limited)
fn conflict(sip: Ipv4Addr, sha: &[u8; ETH_ALEN]) {
    static LAST: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    let now = crate::time::current_ticks();
    let last = LAST.load(core::sync::atomic::Ordering::Relaxed);
    if last != 0 && now.wrapping_sub(last) < 500 {
        return;
    }
    LAST.store(now, core::sync::atomic::Ordering::Relaxed);
    crate::printkln!(
        "arp: {} claimed by {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, ignored",
        sip,
        sha[0],
        sha[1],
        sha[2],
        sha[3],
        sha[4],
        sha[5]
    );
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

#[cfg(test)]
mod tests {
    use super::*;

    const OUR: [u8; 6] = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
    const PEER: [u8; 6] = [0x52, 0x55, 0x0a, 0, 2, 2];

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    fn atype(a: Ipv4Addr) -> RouteType {
        if a == ip(10, 0, 2, 15) {
            RouteType::Local
        } else if a == ip(10, 0, 2, 255) {
            RouteType::Broadcast
        } else {
            RouteType::Unicast
        }
    }

    fn c(op: u16, sip: Ipv4Addr, sha: [u8; 6], tip: Ipv4Addr) -> ArpAction {
        classify(op, sip, &sha, tip, &OUR, atype)
    }

    #[test]
    fn creates_only_for_requests_to_us() {
        let (gw, me) = (ip(10, 0, 2, 2), ip(10, 0, 2, 15));
        assert_eq!(c(ARPOP_REQUEST, gw, PEER, me), ArpAction::Reply);
        // Unsolicited reply / gratuitous ARP / request for someone else:
        // update only
        assert_eq!(c(ARPOP_REPLY, gw, PEER, me), ArpAction::Update);
        assert_eq!(c(ARPOP_REQUEST, gw, PEER, gw), ArpAction::Update);
        assert_eq!(
            c(ARPOP_REQUEST, gw, PEER, ip(10, 0, 2, 3)),
            ArpAction::Update
        );
    }

    #[test]
    fn spoofing_and_martians() {
        let me = ip(10, 0, 2, 15);
        assert_eq!(c(ARPOP_REPLY, me, PEER, me), ArpAction::Conflict);
        assert!(matches!(c(ARPOP_REPLY, me, OUR, me), ArpAction::Drop(_)));
        for bad in [
            ip(255, 255, 255, 255),
            ip(224, 0, 0, 1),
            ip(127, 0, 0, 1),
            ip(0, 1, 2, 3),
            ip(10, 0, 2, 255),
        ] {
            assert!(
                matches!(c(ARPOP_REQUEST, bad, PEER, me), ArpAction::Drop(_)),
                "{bad}"
            );
        }
        assert!(matches!(
            c(ARPOP_REQUEST, ip(10, 0, 2, 2), PEER, ip(127, 0, 0, 1)),
            ArpAction::Drop(_)
        ));
        assert!(matches!(
            c(ARPOP_REQUEST, ip(10, 0, 2, 2), [0xff; 6], me),
            ArpAction::Drop(_)
        ));
        assert!(matches!(
            c(ARPOP_REQUEST, ip(10, 0, 2, 2), [0; 6], me),
            ArpAction::Drop(_)
        ));
        assert!(matches!(
            c(3, ip(10, 0, 2, 2), PEER, me),
            ArpAction::Drop(_)
        ));
    }

    #[test]
    fn duplicate_address_probe() {
        let me = ip(10, 0, 2, 15);
        assert_eq!(
            c(ARPOP_REQUEST, ip(0, 0, 0, 0), PEER, me),
            ArpAction::ProbeReply
        );
        assert!(matches!(
            c(ARPOP_REQUEST, ip(0, 0, 0, 0), PEER, ip(10, 0, 2, 9)),
            ArpAction::Drop(_)
        ));
    }
}

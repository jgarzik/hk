//! Address Resolution Protocol (Linux net/ipv4/arp.c)
//!
//! ARP is the IPv4 user of the generic neighbour table
//! (`net::neigh`): each namespace has an `arp` table with `ARP_OPS`
//! (solicit = ARP request, output = Ethernet transmit of an IPv4
//! packet, error report = ICMP host unreachable to the sender). This
//! module parses and answers ARP packets and feeds the table.
//!
//! One table serves every namespace (Linux arp_tbl): entries are keyed
//! by device, and dumps and /proc/net/arp show the reader's namespace.

use crate::mm::page_alloc::Gfp;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;

use crate::net::device::NetDevice;
use crate::net::ethernet::{self, ETH_ALEN, ETH_BROADCAST, ETH_HLEN, EtherType, PktType};
use crate::net::inet::fib::RouteType;
use crate::net::inet::ifaddr::{RT_SCOPE_LINK, inet_select_addr};
use crate::net::ipv4::{self, Ipv4Addr};
use crate::net::neigh::{self, HASH_RND, Key, Lladdr, NeighOps, NeighTable, Neighbour, nud, upd};
use crate::net::skb::SkBuff;

/// ARP hardware type: Ethernet
pub const ARPHRD_ETHER: u16 = 1;

/// ARP operation: Request
pub const ARPOP_REQUEST: u16 = 1;
/// ARP operation: Reply
pub const ARPOP_REPLY: u16 = 2;

/// ARP header size (for Ethernet/IPv4)
pub const ARP_HLEN: usize = 28;

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
crate::pod!(ArpHdr {
    ar_hrd,
    ar_pro,
    ar_hln,
    ar_pln,
    ar_op,
    ar_sha,
    ar_sip,
    ar_tha,
    ar_tip
});

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

/// The ARP table hooks
pub static ARP_OPS: NeighOps = NeighOps {
    family: 2,
    key_len: 4,
    hash: arp_hash,
    solicit: arp_solicit,
    output: ipv4::ip_finish_output,
    error_report: ipv4::ip_link_failure,
};

/// The ARP table (Linux arp_tbl), made by `arp_init`
static ARP_TBL: spin::Once<NeighTable> = spin::Once::new();

/// The ARP table (after `arp_init`)
pub fn arp_tbl() -> &'static NeighTable {
    ARP_TBL.get().expect("arp: used before arp_init")
}

/// Make the ARP table and start its GC (Linux arp_init ->
/// neigh_table_init); boot, before any device
pub fn arp_init() {
    ARP_TBL.call_once(|| NeighTable::new(&ARP_OPS)).start();
}

/// Linux arp_hashfn: the address mixed with the device's address
/// (hash32_ptr) times the table's first random word
fn arp_hash(key: &Key, dev: &NetDevice, rnd: &[u32; HASH_RND]) -> u32 {
    let k = u32::from_ne_bytes([key[0], key[1], key[2], key[3]]);
    let p = core::ptr::from_ref(dev).addr() as u64;
    // Folded to 32 bits on purpose (Linux hash32_ptr)
    let hp = (p ^ (p >> 32)) as u32;
    (k ^ hp).wrapping_mul(rnd[0])
}

/// Receive an ARP packet (EtherType 0x0806 handler; thread context)
///
/// Uses the receiving device's namespace.
pub fn arp_rcv(skb: alloc::boxed::Box<SkBuff>) {
    if skb.len() < ARP_HLEN {
        return;
    }
    let Some(hdr) = <ArpHdr as crate::util::pod::FromBytes>::read_from(skb.data()) else {
        return;
    };
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
    let op = hdr.operation();
    let act = classify(op, sip, &sha, tip, &dev.mac(), |a| ns.fib.addr_type(a));
    match act {
        ArpAction::Drop(_) => {}
        ArpAction::Conflict => conflict(sip, &sha),
        ArpAction::ProbeReply => send_arp_reply(dev, tip, sip, &sha),
        ArpAction::Reply => {
            // Linux neigh_event_ns: the requester's entry, STALE
            let tbl = arp_tbl();
            if let Ok(n) = tbl.create(dev, &neigh::key4(sip), false) {
                tbl.update(&n, Some(sha), nud::STALE, upd::OVERRIDE);
            }
            send_arp_reply(dev, tip, sip, &sha);
        }
        ArpAction::Update => {
            let tbl = arp_tbl();
            let Some(n) = tbl.lookup(dev, &neigh::key4(sip)) else {
                return;
            };
            // Only a unicast reply to us confirms reachability
            let state = if op == ARPOP_REPLY && skb.pkt_type == PktType::Host {
                nud::REACHABLE
            } else {
                nud::STALE
            };
            let garp = op == ARPOP_REQUEST && tip == sip;
            let flags = if garp || tbl.may_override(&n) {
                upd::OVERRIDE
            } else {
                0
            };
            tbl.update(&n, Some(sha), state, flags);
        }
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

/// Send an ARP request for `n` (Linux arp_solicit, arp_announce = 0):
/// the queued packet's source if it is ours, else the device address
/// facing the target; unicast to `dst` when re-probing a known entry
fn arp_solicit(n: &Neighbour, dst: Option<Lladdr>, hint: Option<Key>) {
    let Some(net) = n.dev.net() else {
        return;
    };
    let target = n.key4();
    let hint = hint.map(|k| Ipv4Addr::from_be_bytes([k[0], k[1], k[2], k[3]]));
    let saddr = match hint {
        Some(a) if net.fib.addr_type(a) == RouteType::Local => a,
        _ => inet_select_addr(&net, &n.dev, target, RT_SCOPE_LINK).unwrap_or_default(),
    };
    send_arp(&n.dev, ARPOP_REQUEST, saddr, target, dst.as_ref(), None);
}

/// Build and transmit an ARP packet: Ethernet destination `eth_dst`
/// (broadcast if None), target hardware address `tha` (zero if None)
fn send_arp(
    dev: &Arc<NetDevice>,
    op: u16,
    sip: Ipv4Addr,
    tip: Ipv4Addr,
    eth_dst: Option<&Lladdr>,
    tha: Option<&Lladdr>,
) {
    let Some(mut skb) = SkBuff::alloc(64, ARP_HLEN + ETH_HLEN, Gfp::ATOMIC) else {
        return;
    };
    let Some(d) = skb.put(ARP_HLEN) else {
        return;
    };
    d[0..2].copy_from_slice(&ARPHRD_ETHER.to_be_bytes());
    d[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
    d[4] = 6;
    d[5] = 4;
    d[6..8].copy_from_slice(&op.to_be_bytes());
    d[8..14].copy_from_slice(&dev.mac());
    d[14..18].copy_from_slice(&sip.to_be_bytes());
    d[18..24].copy_from_slice(tha.unwrap_or(&[0; 6]));
    d[24..28].copy_from_slice(&tip.to_be_bytes());
    let dst = eth_dst.unwrap_or(&ETH_BROADCAST);
    ethernet::eth_header(&mut skb, dst, &dev.mac(), EtherType::Arp);
    skb.dev = Some(dev.clone());
    let _ = crate::net::dev::dev_queue_xmit(skb);
}

/// Send an ARP reply claiming `our_ip`
fn send_arp_reply(
    dev: &Arc<NetDevice>,
    our_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    target_mac: &Lladdr,
) {
    send_arp(
        dev,
        ARPOP_REPLY,
        our_ip,
        target_ip,
        Some(target_mac),
        Some(target_mac),
    );
}

/// ATF_* flags of /proc/net/arp (Linux arp_state_to_flags)
const ATF_COM: u32 = 0x02;
const ATF_PERM: u32 = 0x04;

/// `/proc/net/arp` (Linux arp_seq_show; NOARP entries are hidden):
/// the reader's namespace's entries, walked under RCU into a fixed
/// buffer (Linux neigh_seq_start's rcu_read_lock)
pub fn proc_net_arp() -> Vec<u8> {
    let net = crate::net::current_net_ns();
    crate::fs::proc::seq::generate(|m| {
        let _ = m.write_str(
            "IP address       HW type     Flags       HW address            Mask     Device\n",
        );
        let g = crate::sync::rcu::read_lock();
        for n in arp_tbl().iter_rcu(&g).filter(|n| n.dev.net_is(&net)) {
            arp_format_neigh_entry(m, n);
        }
    })
}

/// One entry's line (Linux arp_format_neigh_entry)
fn arp_format_neigh_entry(m: &mut crate::fs::proc::seq::SeqBuf, n: &Neighbour) {
    let e = n.info(0);
    if e.state & nud::NOARP != 0 {
        return;
    }
    let flags = if e.state & nud::PERMANENT != 0 {
        ATF_PERM | ATF_COM
    } else if e.state & nud::VALID != 0 {
        ATF_COM
    } else {
        0
    };
    let h = e.ha;
    // "%-16s " for the address
    m.setwidth(16);
    let _ = write!(m, "{}", n.key4());
    m.pad(' ');
    let _ = writeln!(
        m,
        "0x{:<10x}0x{:<10x}{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}     *        {}",
        ARPHRD_ETHER,
        flags,
        h[0],
        h[1],
        h[2],
        h[3],
        h[4],
        h[5],
        n.dev.name()
    );
}

/// Send an IPv4 packet to its next hop on `dev` through the ARP table
/// (Linux ip_finish_output2: ip_neigh_gw4, then neigh_output)
pub fn output(
    dev: &Arc<NetDevice>,
    nexthop: Ipv4Addr,
    skb: Box<SkBuff>,
) -> Result<(), crate::util::error::KernelError> {
    let tbl = arp_tbl();
    let n = tbl.create(dev, &neigh::key4(nexthop), dev.is_loopback())?;
    tbl.output(&n, skb)
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

//! NETLINK_ROUTE (Linux net/core/rtnetlink.c, net/ipv4/devinet.c,
//! fib_frontend.c, route.c, net/core/neighbour.c)
//!
//! Requests are dispatched by message type and family: links (any
//! family), IPv4 addresses and routes (AF_INET), the ARP neighbour
//! table (RTM_{NEW,DEL,GET}NEIGH) and an empty rule dump. AF_INET6 requests get empty
//! dumps (no IPv6 addresses/routes exist yet) and EAFNOSUPPORT for
//! changes. NEW/DEL/SET need CAP_NET_ADMIN.
//!
//! Dumps are resumable cursors (`RtDump`): parts of at most `DUMP_SIZE`
//! bytes are produced as the reader drains its queue, NLMSG_DONE last.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::attr::{Attrs, Hdr, Msg, NLMSG_HDRLEN, align, header};
use super::*;
use crate::net::NetNamespace;
use crate::net::device::{NetDevice, flags as dflags};
use crate::net::inet::fib::{
    self, FibConfig, FibEntry, FlowKey, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE, RT_TABLE_MAIN,
    RTNH_F_LINKDOWN, RouteType,
};
use crate::net::inet::ifaddr::{self, IFA_F_PERMANENT, IFNAMSIZ, INFINITY_LIFE_TIME, InIfaddr};
use crate::net::inet::route;
use crate::net::ipv4::Ipv4Addr;
use crate::net::neigh::{self, NeighInfo, nud};
use crate::net::rtnl;

// Message types (Linux RTM_*)
pub const RTM_BASE: u16 = 16;
pub const RTM_NEWLINK: u16 = 16;
pub const RTM_DELLINK: u16 = 17;
pub const RTM_GETLINK: u16 = 18;
pub const RTM_SETLINK: u16 = 19;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_DELADDR: u16 = 21;
pub const RTM_GETADDR: u16 = 22;
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;
pub const RTM_GETROUTE: u16 = 26;
pub const RTM_NEWNEIGH: u16 = 28;
pub const RTM_DELNEIGH: u16 = 29;
pub const RTM_GETNEIGH: u16 = 30;
pub const RTM_GETRULE: u16 = 34;
const RTM_MAX: u16 = 123;

// Multicast groups (Linux RTNLGRP_*)
pub const RTNLGRP_LINK: u32 = 1;
pub const RTNLGRP_IPV4_IFADDR: u32 = 5;
pub const RTNLGRP_IPV4_ROUTE: u32 = 7;

const AF_UNSPEC: u8 = 0;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

// IFLA_*
const IFLA_ADDRESS: u16 = 1;
const IFLA_BROADCAST: u16 = 2;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_QDISC: u16 = 6;
const IFLA_STATS: u16 = 7;
const IFLA_TXQLEN: u16 = 13;
const IFLA_OPERSTATE: u16 = 16;
const IFLA_LINKMODE: u16 = 17;
const IFLA_STATS64: u16 = 23;
const IFLA_GROUP: u16 = 27;
const IFLA_PROMISCUITY: u16 = 30;
const IFLA_NUM_TX_QUEUES: u16 = 31;
const IFLA_NUM_RX_QUEUES: u16 = 32;
const IFLA_CARRIER: u16 = 33;
const IFLA_CARRIER_CHANGES: u16 = 35;
const IFLA_PROTO_DOWN: u16 = 39;
const IFLA_MIN_MTU: u16 = 50;
const IFLA_MAX_MTU: u16 = 51;
const IFLA_ALT_IFNAME: u16 = 53;
const IFLA_MAX: u16 = 64;

// IFA_*
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_LABEL: u16 = 3;
const IFA_BROADCAST: u16 = 4;
const IFA_CACHEINFO: u16 = 6;
const IFA_FLAGS: u16 = 8;
const IFA_RT_PRIORITY: u16 = 9;
const IFA_PROTO: u16 = 11;
const IFA_MAX: u16 = 11;

// RTA_*
const RTA_DST: u16 = 1;
const RTA_SRC: u16 = 2;
const RTA_IIF: u16 = 3;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_PREFSRC: u16 = 7;
const RTA_MULTIPATH: u16 = 9;
const RTA_CACHEINFO: u16 = 12;
const RTA_TABLE: u16 = 15;
const RTA_UID: u16 = 25;
const RTA_NH_ID: u16 = 30;
const RTA_MAX: u16 = 31;
const RTM_F_CLONED: u32 = 0x200;
const RTM_F_FIB_MATCH: u32 = 0x2000;
const RT_TABLE_COMPAT: u8 = 252;

// NDA_*
const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;
const NDA_CACHEINFO: u16 = 3;
const NDA_PROBES: u16 = 4;
const NDA_MAX: u16 = 16;

/// Family header sizes
const IFINFOMSG_LEN: usize = 16;
const IFADDRMSG_LEN: usize = 8;
const RTMSG_LEN: usize = 12;
const NDMSG_LEN: usize = 12;

/// Largest dump datagram
pub const DUMP_SIZE: usize = 8192;

/// Result of handling one request
enum Done {
    /// Handled; ACK if NLM_F_ACK
    Ok,
    /// A dump was queued (no ACK; DONE ends it)
    Dump,
}

// ============================================================================
// Request processing
// ============================================================================

/// Process a buffer of requests sent to the kernel (Linux
/// netlink_rcv_skb + rtnetlink_rcv_msg)
pub fn rcv(sk: &Arc<NlSock>, mut data: &[u8], explicit: bool) {
    while data.len() >= NLMSG_HDRLEN {
        let h = Hdr::parse(data).unwrap();
        let len = h.len as usize;
        if len < NLMSG_HDRLEN || data.len() < len {
            return;
        }
        let msg = &data[..len];
        let res = if h.flags & NLM_F_REQUEST == 0 || h.ty < NLMSG_MIN_TYPE {
            Ok(Done::Ok)
        } else {
            rcv_msg(sk, &h, &msg[NLMSG_HDRLEN..], explicit)
        };
        match res {
            Ok(Done::Dump) => {}
            Ok(Done::Ok) if h.flags & NLM_F_ACK != 0 => ack(sk, &h, msg, 0),
            Ok(Done::Ok) => {}
            Err(e) => ack(sk, &h, msg, -e.errno()),
        }
        data = &data[align(len).min(data.len())..];
    }
}

/// Queue an NLMSG_ERROR (err 0 = ACK) for request `msg` (Linux
/// netlink_ack): errors echo the whole request unless NETLINK_CAP_ACK
fn ack(sk: &NlSock, h: &Hdr, msg: &[u8], err: i32) {
    let capped = err == 0 || sk.has_flag(sflags::CAP_ACK);
    let flags = if capped { NLM_F_CAPPED } else { 0 };
    let mut m = Msg::new(NLMSG_ERROR, flags, h.seq, sk.portid());
    let orig = if capped { &msg[..NLMSG_HDRLEN] } else { msg };
    let mut body = Vec::with_capacity(4 + orig.len());
    body.extend_from_slice(&err.to_ne_bytes());
    body.extend_from_slice(orig);
    m.put(&body);
    reply(sk, m.finish());
}

fn reply(sk: &NlSock, data: Vec<u8>) {
    sk.queue(NlSkb {
        data,
        portid: 0,
        group: 0,
    });
}

/// One request: permission, then dump or do
fn rcv_msg(sk: &Arc<NlSock>, h: &Hdr, p: &[u8], explicit: bool) -> Result<Done, KernelError> {
    if h.ty > RTM_MAX {
        return Err(KernelError::OperationNotSupported);
    }
    // All messages carry at least the family byte
    let Some(&family) = p.first() else {
        return Ok(Done::Ok);
    };
    let kind = (h.ty - RTM_BASE) & 3;
    const KIND_GET: u16 = 2;
    if kind != KIND_GET && !sk.net_capable(crate::task::CAP_NET_ADMIN, explicit) {
        return Err(KernelError::NotPermitted);
    }
    if kind == KIND_GET && h.flags & NLM_F_DUMP != 0 {
        if !matches!(
            h.ty,
            RTM_GETLINK | RTM_GETADDR | RTM_GETROUTE | RTM_GETNEIGH | RTM_GETRULE
        ) {
            return Err(KernelError::OperationNotSupported);
        }
        let cb = RtDump::new(sk, h, family, p);
        sk.dump_start(Box::new(cb), h.seq)?;
        return Ok(Done::Dump);
    }
    let nl = NlInfo {
        portid: sk.portid(),
        seq: h.seq,
    };
    match h.ty {
        RTM_NEWNEIGH => newneigh(sk, h, p),
        RTM_DELNEIGH => delneigh(sk, p),
        RTM_GETNEIGH => getneigh(sk, h, p),
        RTM_NEWLINK | RTM_SETLINK => setlink(sk, h, p, nl),
        RTM_GETLINK => getlink(sk, h, p),
        RTM_NEWADDR | RTM_DELADDR | RTM_NEWROUTE | RTM_DELROUTE | RTM_GETROUTE => match family {
            AF_INET => match h.ty {
                RTM_NEWADDR => newaddr(sk, h, p, nl),
                RTM_DELADDR => deladdr(sk, p, nl),
                RTM_NEWROUTE => newroute(sk, h, p, nl),
                RTM_DELROUTE => delroute(sk, h, p, nl),
                _ => getroute(sk, h, p),
            },
            AF_INET6 => Err(KernelError::AddressFamilyNotSupported),
            _ => Err(KernelError::OperationNotSupported),
        },
        _ => Err(KernelError::OperationNotSupported),
    }
}

/// What a dump lists
enum DumpKind {
    Link,
    /// Addresses (of one ifindex if non-zero)
    Addr(u32),
    /// Routes (of one table if non-zero)
    Route(u32),
    Neigh,
    /// Nothing (other families, empty rule dump, RTM_F_CLONED)
    Empty,
    /// Request rejected by strict checking: DONE carries the error
    Bad(KernelError),
}

/// A resumable rtnetlink dump: `pos` counts the objects already sent;
/// each part re-snapshots the table and continues from there (Linux
/// cb->args), so changes between parts are tolerated like on Linux
struct RtDump {
    kind: DumpKind,
    flags: u16,
    seq: u32,
    pid: u32,
    pos: usize,
}

impl RtDump {
    fn new(sk: &NlSock, h: &Hdr, family: u8, p: &[u8]) -> Self {
        let strict = sk.has_flag(sflags::STRICT_CHK);
        let mut flags = NLM_F_MULTI;
        let inet = family != AF_INET6;
        let kind = match h.ty {
            RTM_GETLINK if strict => match link_dump_check(p) {
                Ok(()) => DumpKind::Link,
                Err(e) => DumpKind::Bad(e),
            },
            RTM_GETLINK => DumpKind::Link,
            RTM_GETADDR if inet => addr_dump_kind(sk.net(), p, strict, &mut flags),
            RTM_GETROUTE if inet => route_dump_kind(p, strict, &mut flags),
            RTM_GETNEIGH if inet => DumpKind::Neigh,
            _ => DumpKind::Empty,
        };
        Self {
            kind,
            flags,
            seq: h.seq,
            pid: sk.portid(),
            pos: 0,
        }
    }

    /// Append messages for `items[pos..]` while they fit in a part
    fn take<T>(&mut self, buf: &mut Vec<u8>, items: &[T], f: impl Fn(&T) -> Vec<u8>) -> bool {
        for it in items.iter().skip(self.pos) {
            let m = f(it);
            if !buf.is_empty() && buf.len() + m.len() > DUMP_SIZE {
                return false;
            }
            buf.extend_from_slice(&m);
            self.pos += 1;
        }
        // Leave room for NLMSG_DONE in the same part, like Linux
        buf.len() + NLMSG_HDRLEN + 4 <= DUMP_SIZE || buf.is_empty()
    }
}

impl DumpCb for RtDump {
    fn fill(&mut self, sk: &NlSock, buf: &mut Vec<u8>) -> Result<bool, KernelError> {
        let net = sk.net();
        let (f, seq, pid) = (self.flags, self.seq, self.pid);
        match self.kind {
            DumpKind::Bad(e) => Err(e),
            DumpKind::Empty => Ok(true),
            DumpKind::Link => {
                let devs = net.devices();
                Ok(self.take(buf, &devs, |d| fill_link(d, RTM_NEWLINK, f, seq, pid, 0)))
            }
            DumpKind::Addr(only) => {
                let addrs: Vec<(Arc<NetDevice>, InIfaddr)> = net
                    .devices()
                    .into_iter()
                    .filter(|d| only == 0 || d.ifindex() == only)
                    .flat_map(|d| d.inet_addrs().into_iter().map(move |a| (d.clone(), a)))
                    .collect();
                Ok(self.take(buf, &addrs, |(d, a)| {
                    fill_addr(d, a, RTM_NEWADDR, f, seq, pid)
                }))
            }
            DumpKind::Route(table) => {
                let rts: Vec<Arc<FibEntry>> = net
                    .fib
                    .dump()
                    .into_iter()
                    .filter(|e| table == 0 || e.table == table)
                    .collect();
                Ok(self.take(buf, &rts, |e| fill_route(e, RTM_NEWROUTE, f, seq, pid)))
            }
            DumpKind::Neigh => {
                let n = net.arp.dump();
                Ok(self.take(buf, &n, |e| fill_neigh(e, RTM_NEWNEIGH, f, seq, pid)))
            }
        }
    }
}

// ============================================================================
// Links
// ============================================================================

/// Strict link dump header (Linux rtnl_valid_dump_ifinfo_req)
fn link_dump_check(p: &[u8]) -> Result<(), KernelError> {
    if p.len() < IFINFOMSG_LEN {
        return Err(KernelError::InvalidArgument);
    }
    if p[1..IFINFOMSG_LEN].iter().any(|&b| b != 0) {
        return Err(KernelError::InvalidArgument);
    }
    Ok(())
}

/// struct ifinfomsg fields
struct IfInfo {
    index: u32,
    flags: u32,
    change: u32,
}

fn ifinfo(p: &[u8]) -> Result<IfInfo, KernelError> {
    if p.len() < IFINFOMSG_LEN {
        return Err(KernelError::InvalidArgument);
    }
    let h: [u8; IFINFOMSG_LEN] = header(p);
    let w = |o: usize| u32::from_ne_bytes([h[o], h[o + 1], h[o + 2], h[o + 3]]);
    Ok(IfInfo {
        index: w(4),
        flags: w(8),
        change: w(12),
    })
}

/// Device named by ifi_index or IFLA_IFNAME/IFLA_ALT_IFNAME
fn link_dev(
    net: &NetNamespace,
    ifm: &IfInfo,
    a: &Attrs,
) -> Result<Option<Arc<NetDevice>>, KernelError> {
    if ifm.index > 0 {
        return Ok(net.dev_get_by_index(ifm.index));
    }
    let name = match a.str(IFLA_IFNAME, IFNAMSIZ)? {
        Some(n) => Some(n),
        None => a.str(IFLA_ALT_IFNAME, 128)?,
    };
    match name {
        Some(n) => Ok(net.get_device(n)),
        None => Err(KernelError::InvalidArgument),
    }
}

/// RTM_GETLINK for one device
fn getlink(sk: &NlSock, h: &Hdr, p: &[u8]) -> Result<Done, KernelError> {
    let ifm = ifinfo(p)?;
    let a = Attrs::parse(&p[IFINFOMSG_LEN..], IFLA_MAX)?;
    let dev = link_dev(sk.net(), &ifm, &a)?.ok_or(KernelError::NoDevice)?;
    reply(sk, fill_link(&dev, RTM_NEWLINK, 0, h.seq, sk.portid(), 0));
    Ok(Done::Ok)
}

/// RTM_NEWLINK / RTM_SETLINK on an existing device (Linux rtnl_newlink
/// without link kinds): IFLA_MTU and ifi_flags/ifi_change
fn setlink(sk: &NlSock, h: &Hdr, p: &[u8], nl: NlInfo) -> Result<Done, KernelError> {
    let ifm = ifinfo(p)?;
    let a = Attrs::parse(&p[IFINFOMSG_LEN..], IFLA_MAX)?;
    let net = sk.net();
    let found = match link_dev(net, &ifm, &a) {
        Err(KernelError::InvalidArgument) if h.ty == RTM_NEWLINK => None,
        r => r?,
    };
    let Some(dev) = found else {
        if h.ty == RTM_NEWLINK && h.flags & NLM_F_CREATE != 0 {
            // Creating links (veth, bridge, ...) needs link kinds
            return Err(KernelError::OperationNotSupported);
        }
        return Err(KernelError::NoDevice);
    };
    if h.ty == RTM_NEWLINK {
        if h.flags & NLM_F_EXCL != 0 {
            return Err(KernelError::AlreadyExists);
        }
        if h.flags & NLM_F_REPLACE != 0 {
            return Err(KernelError::OperationNotSupported);
        }
    }
    if ifm.index > 0
        && let Some(n) = a.str(IFLA_IFNAME, IFNAMSIZ)?
        && n != dev.name()
    {
        // Renaming is not supported
        return Err(KernelError::OperationNotSupported);
    }
    let r = rtnl::lock();
    if let Some(mtu) = a.u32(IFLA_MTU)? {
        rtnl::dev_set_mtu(&r, net, &dev, mtu, nl)?;
    }
    if ifm.flags != 0 || ifm.change != 0 {
        let mut f = ifm.flags;
        if ifm.change != 0 {
            f = (f & ifm.change) | (dev.get_flags() & !ifm.change);
        }
        rtnl::dev_change_flags(&r, net, &dev, f, nl)?;
    }
    Ok(Done::Ok)
}

/// RTM_NEWLINK message for `dev` (Linux rtnl_fill_ifinfo subset)
pub fn fill_link(dev: &NetDevice, ty: u16, flags: u16, seq: u32, pid: u32, change: u32) -> Vec<u8> {
    let mut m = Msg::new(ty, flags, seq, pid);
    let mut h = [0u8; IFINFOMSG_LEN];
    h[0] = AF_UNSPEC;
    h[2..4].copy_from_slice(&dev.link().dev_type.to_ne_bytes());
    h[4..8].copy_from_slice(&dev.ifindex().to_ne_bytes());
    h[8..12].copy_from_slice(&dev.get_flags().to_ne_bytes());
    h[12..16].copy_from_slice(&change.to_ne_bytes());
    let (min_mtu, max_mtu) = dev.mtu_range();
    let promisc = (dev.admin_flags() & dflags::IFF_PROMISC != 0) as u32;
    m.put(&h)
        .str(IFLA_IFNAME, dev.name())
        .u32(IFLA_TXQLEN, dev.link().txqlen)
        .u8(IFLA_OPERSTATE, dev.operstate())
        .u8(IFLA_LINKMODE, 0)
        .u32(IFLA_MTU, dev.mtu())
        .u32(IFLA_MIN_MTU, min_mtu)
        .u32(IFLA_MAX_MTU, max_mtu)
        .u32(IFLA_GROUP, 0)
        .u32(IFLA_PROMISCUITY, promisc)
        .u32(IFLA_NUM_TX_QUEUES, 1)
        .u32(IFLA_NUM_RX_QUEUES, 1)
        .u8(IFLA_CARRIER, dev.carrier_ok() as u8)
        .str(IFLA_QDISC, "noqueue")
        .u32(IFLA_CARRIER_CHANGES, dev.carrier_changes())
        .u8(IFLA_PROTO_DOWN, 0)
        .attr(IFLA_ADDRESS, &dev.mac())
        .attr(IFLA_BROADCAST, &dev.link().broadcast)
        .attr(IFLA_STATS64, &stats64(dev))
        .attr(IFLA_STATS, &stats32(dev));
    m.finish()
}

/// Counters in struct rtnl_link_stats64 order (25 x u64)
fn stats_vals(dev: &NetDevice) -> [u64; 25] {
    use core::sync::atomic::Ordering::Relaxed;
    let s = &dev.stats;
    let mut v = [0u64; 25];
    v[0] = s.rx_packets.load(Relaxed);
    v[1] = s.tx_packets.load(Relaxed);
    v[2] = s.rx_bytes.load(Relaxed);
    v[3] = s.tx_bytes.load(Relaxed);
    v[4] = s.rx_errors.load(Relaxed);
    v[5] = s.tx_errors.load(Relaxed);
    v[6] = s.rx_dropped.load(Relaxed);
    v[7] = s.tx_dropped.load(Relaxed);
    v[8] = s.multicast.load(Relaxed);
    v[9] = s.collisions.load(Relaxed);
    v[23] = s.rx_nohandler.load(Relaxed);
    v
}

fn stats64(dev: &NetDevice) -> Vec<u8> {
    stats_vals(dev)
        .iter()
        .flat_map(|v| v.to_ne_bytes())
        .collect()
}

/// struct rtnl_link_stats (24 x u32)
fn stats32(dev: &NetDevice) -> Vec<u8> {
    stats_vals(dev)[..24]
        .iter()
        .flat_map(|&v| (v as u32).to_ne_bytes())
        .collect()
}

/// Announce a link change to RTNLGRP_LINK
pub fn notify_link(net: &NetNamespace, dev: &NetDevice, nl: NlInfo) {
    let data = fill_link(dev, RTM_NEWLINK, 0, nl.seq, nl.portid, 0);
    notify(net, data, RTNLGRP_LINK);
}

fn notify(net: &NetNamespace, data: Vec<u8>, group: u32) {
    let skb = NlSkb {
        data,
        portid: 0,
        group,
    };
    broadcast(net, NETLINK_ROUTE, skb, 0);
}

// ============================================================================
// Addresses
// ============================================================================

/// struct ifaddrmsg fields
struct IfAddrMsg {
    prefixlen: u8,
    flags: u8,
    scope: u8,
    index: u32,
}

fn ifaddrmsg(p: &[u8]) -> Result<IfAddrMsg, KernelError> {
    if p.len() < IFADDRMSG_LEN {
        return Err(KernelError::InvalidArgument);
    }
    Ok(IfAddrMsg {
        prefixlen: p[1],
        flags: p[2],
        scope: p[3],
        index: u32::from_ne_bytes([p[4], p[5], p[6], p[7]]),
    })
}

/// Address dump filter (Linux inet_valid_dump_ifaddr_req when strict)
fn addr_dump_kind(net: &NetNamespace, p: &[u8], strict: bool, flags: &mut u16) -> DumpKind {
    if !strict {
        return DumpKind::Addr(0);
    }
    let ifm = match ifaddrmsg(p) {
        Ok(m) => m,
        Err(e) => return DumpKind::Bad(e),
    };
    if ifm.prefixlen != 0 || ifm.flags != 0 || ifm.scope != 0 {
        return DumpKind::Bad(KernelError::InvalidArgument);
    }
    if ifm.index != 0 {
        *flags |= NLM_F_DUMP_FILTERED;
        if net.dev_get_by_index(ifm.index).is_none() {
            return DumpKind::Bad(KernelError::NoDevice);
        }
    }
    DumpKind::Addr(ifm.index)
}

/// RTM_NEWADDR/DELADDR message (Linux inet_fill_ifaddr)
pub fn fill_addr(
    dev: &NetDevice,
    ifa: &InIfaddr,
    ty: u16,
    flags: u16,
    seq: u32,
    pid: u32,
) -> Vec<u8> {
    let mut m = Msg::new(ty, flags, seq, pid);
    let mut h = [0u8; IFADDRMSG_LEN];
    h[0] = AF_INET;
    h[1] = ifa.prefixlen;
    h[2] = ifa.flags as u8;
    h[3] = ifa.scope;
    h[4..8].copy_from_slice(&dev.ifindex().to_ne_bytes());
    m.put(&h)
        .attr(IFA_ADDRESS, &ifa.address.to_be_bytes())
        .attr(IFA_LOCAL, &ifa.local.to_be_bytes());
    if !ifa.broadcast.is_unspecified() {
        m.attr(IFA_BROADCAST, &ifa.broadcast.to_be_bytes());
    }
    m.str(IFA_LABEL, &ifa.label);
    if ifa.proto != 0 {
        m.u8(IFA_PROTO, ifa.proto);
    }
    m.u32(IFA_FLAGS, ifa.flags);
    if ifa.rt_priority != 0 {
        m.u32(IFA_RT_PRIORITY, ifa.rt_priority);
    }
    let ci: Vec<u8> = [INFINITY_LIFE_TIME, INFINITY_LIFE_TIME, 0, 0]
        .iter()
        .flat_map(|v| v.to_ne_bytes())
        .collect();
    m.attr(IFA_CACHEINFO, &ci);
    m.finish()
}

/// Announce an address change to RTNLGRP_IPV4_IFADDR
pub fn notify_addr(net: &NetNamespace, dev: &NetDevice, ifa: &InIfaddr, ty: u16, nl: NlInfo) {
    notify(
        net,
        fill_addr(dev, ifa, ty, 0, nl.seq, nl.portid),
        RTNLGRP_IPV4_IFADDR,
    );
}

/// RTM_NEWADDR (Linux inet_rtm_newaddr)
fn newaddr(sk: &NlSock, h: &Hdr, p: &[u8], nl: NlInfo) -> Result<Done, KernelError> {
    let ifm = ifaddrmsg(p)?;
    let a = Attrs::parse(&p[IFADDRMSG_LEN..], IFA_MAX)?;
    if ifm.prefixlen > 32 {
        return Err(KernelError::InvalidArgument);
    }
    let local = a.in_addr(IFA_LOCAL)?.ok_or(KernelError::InvalidArgument)?;
    if let Some(ci) = a.get(IFA_CACHEINFO) {
        if ci.len() < 16 {
            return Err(KernelError::InvalidArgument);
        }
        let w = |o: usize| u32::from_ne_bytes([ci[o], ci[o + 1], ci[o + 2], ci[o + 3]]);
        let (prefered, valid) = (w(0), w(4));
        if valid == 0 || prefered > valid {
            return Err(KernelError::InvalidArgument);
        }
    }
    if local.is_unspecified() {
        return Ok(Done::Ok);
    }
    let net = sk.net();
    let r = rtnl::lock();
    let dev = net
        .dev_get_by_index(ifm.index)
        .ok_or(KernelError::NoDevice)?;
    let mut ifa = InIfaddr::new(local, ifm.prefixlen, dev.name());
    ifa.address = a.in_addr(IFA_ADDRESS)?.unwrap_or(local);
    ifa.flags = a.u32(IFA_FLAGS)?.unwrap_or(ifm.flags as u32) | IFA_F_PERMANENT;
    ifa.scope = ifm.scope;
    if let Some(b) = a.in_addr(IFA_BROADCAST)? {
        ifa.broadcast = b;
    }
    if let Some(l) = a.str(IFA_LABEL, IFNAMSIZ)? {
        ifa.label = l.into();
    }
    ifa.rt_priority = a.u32(IFA_RT_PRIORITY)?.unwrap_or(0);
    ifa.proto = a.u8(IFA_PROTO)?.unwrap_or(0);
    let exists = dev
        .inet_addrs()
        .iter()
        .any(|x| x.prefixlen == ifa.prefixlen && ifa.matches(x.address) && x.local == ifa.local);
    if !exists {
        ifaddr::inet_insert_ifa(&r, net, &dev, ifa, nl)?;
    } else if h.flags & NLM_F_EXCL != 0 || h.flags & NLM_F_REPLACE == 0 {
        return Err(KernelError::AlreadyExists);
    } else {
        ifaddr::inet_replace_ifa(&r, net, &dev, &ifa, nl);
    }
    Ok(Done::Ok)
}

/// RTM_DELADDR (Linux inet_rtm_deladdr)
fn deladdr(sk: &NlSock, p: &[u8], nl: NlInfo) -> Result<Done, KernelError> {
    let ifm = ifaddrmsg(p)?;
    let a = Attrs::parse(&p[IFADDRMSG_LEN..], IFA_MAX)?;
    let local = a.in_addr(IFA_LOCAL)?;
    let label = a.str(IFA_LABEL, IFNAMSIZ)?;
    let address = a.in_addr(IFA_ADDRESS)?;
    let net = sk.net();
    let r = rtnl::lock();
    let dev = net
        .dev_get_by_index(ifm.index)
        .ok_or(KernelError::NoDevice)?;
    let victim = dev.inet_addrs().into_iter().find(|x| {
        local.is_none_or(|l| l == x.local)
            && label.is_none_or(|l| l == x.label)
            && address.is_none_or(|ad| ifm.prefixlen == x.prefixlen && x.matches(ad))
    });
    let ifa = victim.ok_or(KernelError::AddressNotAvailable)?;
    ifaddr::inet_del_ifa(&r, net, &dev, &ifa, nl);
    Ok(Done::Ok)
}

// ============================================================================
// Routes
// ============================================================================

/// struct rtmsg fields
struct RtMsg {
    dst_len: u8,
    tos: u8,
    table: u8,
    protocol: u8,
    scope: u8,
    rtype: u8,
    flags: u32,
}

fn rtmsg(p: &[u8]) -> Result<RtMsg, KernelError> {
    if p.len() < RTMSG_LEN {
        return Err(KernelError::InvalidArgument);
    }
    Ok(RtMsg {
        dst_len: p[1],
        tos: p[3],
        table: p[4],
        protocol: p[5],
        scope: p[6],
        rtype: p[7],
        flags: u32::from_ne_bytes([p[8], p[9], p[10], p[11]]),
    })
}

/// Request -> fib config (Linux rtm_to_fib_config)
fn fib_config(h: &Hdr, p: &[u8], nl: NlInfo) -> Result<FibConfig, KernelError> {
    let rtm = rtmsg(p)?;
    let a = Attrs::parse(&p[RTMSG_LEN..], RTA_MAX)?;
    if rtm.rtype > fib::RTN_MAX {
        return Err(KernelError::InvalidArgument);
    }
    if a.has(RTA_MULTIPATH) || a.has(RTA_NH_ID) {
        return Err(KernelError::OperationNotSupported);
    }
    Ok(FibConfig {
        table: a.u32(RTA_TABLE)?.unwrap_or(rtm.table as u32),
        dst: a.in_addr(RTA_DST)?.unwrap_or_default(),
        dst_len: rtm.dst_len,
        tos: rtm.tos,
        rtype: rtm.rtype,
        scope: rtm.scope,
        protocol: rtm.protocol,
        priority: a.u32(RTA_PRIORITY)?.unwrap_or(0),
        prefsrc: a.in_addr(RTA_PREFSRC)?,
        gateway: a.in_addr(RTA_GATEWAY)?.filter(|g| !g.is_unspecified()),
        oif: a.u32(RTA_OIF)?.unwrap_or(0),
        flags: rtm.flags & 0xff,
        nlflags: h.flags,
        nl,
    })
}

fn newroute(sk: &NlSock, h: &Hdr, p: &[u8], nl: NlInfo) -> Result<Done, KernelError> {
    let cfg = fib_config(h, p, nl)?;
    let r = rtnl::lock();
    fib::fib_table_insert(&r, sk.net(), &cfg)?;
    Ok(Done::Ok)
}

fn delroute(sk: &NlSock, h: &Hdr, p: &[u8], nl: NlInfo) -> Result<Done, KernelError> {
    let cfg = fib_config(h, p, nl)?;
    let r = rtnl::lock();
    fib::fib_table_delete(&r, sk.net(), &cfg)?;
    Ok(Done::Ok)
}

/// Route dump filter (strict: table, RTM_F_CLONED = empty cache dump)
fn route_dump_kind(p: &[u8], strict: bool, flags: &mut u16) -> DumpKind {
    if !strict {
        return DumpKind::Route(0);
    }
    let parse = || -> Result<DumpKind, KernelError> {
        let rtm = rtmsg(p)?;
        let a = Attrs::parse(&p[RTMSG_LEN..], RTA_MAX)?;
        if rtm.flags & RTM_F_CLONED != 0 {
            return Ok(DumpKind::Empty);
        }
        Ok(DumpKind::Route(
            a.u32(RTA_TABLE)?.unwrap_or(rtm.table as u32),
        ))
    };
    match parse() {
        Ok(DumpKind::Route(t)) => {
            if t != 0 {
                *flags |= NLM_F_DUMP_FILTERED;
            }
            DumpKind::Route(t)
        }
        Ok(k) => k,
        Err(e) => DumpKind::Bad(e),
    }
}

/// RTM_NEWROUTE/DELROUTE message for a FIB entry (Linux fib_dump_info)
pub fn fill_route(e: &FibEntry, ty: u16, flags: u16, seq: u32, pid: u32) -> Vec<u8> {
    let mut m = Msg::new(ty, flags, seq, pid);
    let mut rflags = e.flags;
    if e.dev.as_ref().is_some_and(|d| !d.carrier_ok()) && e.rtype == RouteType::Unicast {
        rflags |= RTNH_F_LINKDOWN;
    }
    let table8 = if e.table < 256 {
        e.table as u8
    } else {
        RT_TABLE_COMPAT
    };
    let mut h = [0u8; RTMSG_LEN];
    h[0] = AF_INET;
    h[1] = e.dst_len;
    h[3] = e.tos;
    h[4] = table8;
    h[5] = e.protocol;
    h[6] = e.scope;
    h[7] = e.rtype as u8;
    h[8..12].copy_from_slice(&rflags.to_ne_bytes());
    m.put(&h).u32(RTA_TABLE, e.table);
    if e.dst_len != 0 {
        m.attr(RTA_DST, &e.dst.to_be_bytes());
    }
    if e.priority != 0 {
        m.u32(RTA_PRIORITY, e.priority);
    }
    if let Some(s) = e.prefsrc {
        m.attr(RTA_PREFSRC, &s.to_be_bytes());
    }
    if let Some(g) = e.gateway {
        m.attr(RTA_GATEWAY, &g.to_be_bytes());
    }
    if e.dev.is_some() {
        m.u32(RTA_OIF, e.oif());
    }
    m.finish()
}

/// Announce a route change to RTNLGRP_IPV4_ROUTE
pub fn notify_route(net: &NetNamespace, e: &FibEntry, ty: u16, nl: NlInfo) {
    notify(
        net,
        fill_route(e, ty, 0, nl.seq, nl.portid),
        RTNLGRP_IPV4_ROUTE,
    );
}

/// RTM_GETROUTE for one destination ("ip route get"; Linux
/// inet_rtm_getroute, output routes only)
fn getroute(sk: &NlSock, h: &Hdr, p: &[u8]) -> Result<Done, KernelError> {
    let rtm = rtmsg(p)?;
    let a = Attrs::parse(&p[RTMSG_LEN..], RTA_MAX)?;
    if a.u32(RTA_IIF)?.unwrap_or(0) != 0 {
        // Input route simulation
        return Err(KernelError::OperationNotSupported);
    }
    let dst = a.in_addr(RTA_DST)?.unwrap_or_default();
    let src = a.in_addr(RTA_SRC)?.unwrap_or_default();
    let oif = a.u32(RTA_OIF)?.unwrap_or(0);
    let net = sk.net();
    if rtm.flags & RTM_F_FIB_MATCH != 0 {
        let key = FlowKey {
            daddr: dst,
            oif,
            ..Default::default()
        };
        let e = net.fib.lookup(&key)?;
        reply(sk, fill_route(&e, RTM_NEWROUTE, 0, h.seq, sk.portid()));
        return Ok(Done::Ok);
    }
    let rt = route::output(net, dst, src, oif)?;
    reply(sk, fill_rt(&rt, src, h.seq, sk.portid()));
    Ok(Done::Ok)
}

/// RTM_NEWROUTE answer for an output route (Linux rt_fill_info)
fn fill_rt(rt: &route::Rtable, src: Ipv4Addr, seq: u32, pid: u32) -> Vec<u8> {
    let table = if rt.table != 0 {
        rt.table
    } else {
        RT_TABLE_MAIN
    };
    let mut m = Msg::new(RTM_NEWROUTE, 0, seq, pid);
    let mut hd = [0u8; RTMSG_LEN];
    hd[0] = AF_INET;
    hd[1] = 32;
    hd[2] = if src.is_unspecified() { 0 } else { 32 };
    hd[4] = table as u8;
    hd[7] = rt.rtype as u8;
    hd[8..12].copy_from_slice(&RTM_F_CLONED.to_ne_bytes());
    m.put(&hd)
        .u32(RTA_TABLE, table)
        .attr(RTA_DST, &rt.daddr.to_be_bytes());
    if !src.is_unspecified() {
        m.attr(RTA_SRC, &src.to_be_bytes());
    }
    m.u32(RTA_OIF, rt.dev.ifindex());
    if !rt.saddr.is_unspecified() {
        m.attr(RTA_PREFSRC, &rt.saddr.to_be_bytes());
    }
    if let Some(g) = rt.gateway {
        m.attr(RTA_GATEWAY, &g.to_be_bytes());
    }
    let uid = crate::task::percpu::current_cred().uid;
    m.u32(RTA_UID, uid).attr(RTA_CACHEINFO, &[0u8; 32]);
    m.finish()
}

// ============================================================================
// Neighbours
// ============================================================================

/// RTM_NEWNEIGH message for a neighbour (Linux neigh_fill_info)
fn fill_neigh(e: &NeighInfo, ty: u16, flags: u16, seq: u32, pid: u32) -> Vec<u8> {
    let mut m = Msg::new(ty, flags, seq, pid);
    let mut h = [0u8; NDMSG_LEN];
    h[0] = AF_INET;
    h[4..8].copy_from_slice(&e.ifindex.to_ne_bytes());
    h[8..10].copy_from_slice(&(e.state as u16).to_ne_bytes());
    h[11] = RouteType::Unicast as u8;
    m.put(&h).attr(NDA_DST, &e.key[..4]);
    if e.state & nud::VALID != 0 {
        m.attr(NDA_LLADDR, &e.ha);
    }
    // struct nda_cacheinfo: ages in clock_t (USER_HZ = 100)
    let mut ci = [0u8; 16];
    ci[0..4].copy_from_slice(&((e.confirmed / 10) as u32).to_ne_bytes());
    ci[4..8].copy_from_slice(&((e.used / 10) as u32).to_ne_bytes());
    ci[8..12].copy_from_slice(&((e.updated / 10) as u32).to_ne_bytes());
    m.u32(NDA_PROBES, e.probes).attr(NDA_CACHEINFO, &ci);
    m.finish()
}

/// struct ndmsg fields and the request's attributes
struct NdReq<'a> {
    family: u8,
    ifindex: u32,
    state: u8,
    attrs: Attrs<'a>,
}

fn ndmsg(p: &[u8]) -> Result<NdReq<'_>, KernelError> {
    if p.len() < NDMSG_LEN {
        return Err(KernelError::InvalidArgument);
    }
    Ok(NdReq {
        family: p[0],
        ifindex: u32::from_ne_bytes([p[4], p[5], p[6], p[7]]),
        state: u16::from_ne_bytes([p[8], p[9]]) as u8,
        attrs: Attrs::parse(&p[NDMSG_LEN..], NDA_MAX)?,
    })
}

/// Device and key of a neighbour request (Linux neigh_add/neigh_delete
/// checks, in their order): EINVAL without NDA_DST or a device,
/// ENODEV for an unknown device, EAFNOSUPPORT for other families
fn nd_target(net: &NetNamespace, r: &NdReq) -> Result<(Arc<NetDevice>, neigh::Key), KernelError> {
    let dst = r.attrs.get(NDA_DST).ok_or(KernelError::InvalidArgument)?;
    let dev = match r.ifindex {
        0 => None,
        i => Some(net.dev_get_by_index(i).ok_or(KernelError::NoDevice)?),
    };
    if r.family != AF_INET {
        return Err(KernelError::AddressFamilyNotSupported);
    }
    if dst.len() < 4 {
        return Err(KernelError::InvalidArgument);
    }
    let dev = dev.ok_or(KernelError::InvalidArgument)?;
    let a = Ipv4Addr::from_be_bytes([dst[0], dst[1], dst[2], dst[3]]);
    Ok((dev, neigh::key4(a)))
}

/// RTM_NEWNEIGH ("ip neigh add/replace/change"; Linux neigh_add)
fn newneigh(sk: &NlSock, h: &Hdr, p: &[u8]) -> Result<Done, KernelError> {
    let r = ndmsg(p)?;
    let (dev, key) = nd_target(sk.net(), &r)?;
    let ll = match r.attrs.get(NDA_LLADDR) {
        Some(a) if a.len() < 6 => return Err(KernelError::InvalidArgument),
        Some(a) => Some([a[0], a[1], a[2], a[3], a[4], a[5]]),
        None => None,
    };
    // Configuration change: under RTNL (Linux neigh_add is a locked doit)
    let _r = rtnl::lock();
    sk.net().arp.admin_add(&dev, &key, ll, r.state, h.flags)?;
    Ok(Done::Ok)
}

/// RTM_DELNEIGH (Linux neigh_delete): ENOENT if absent
fn delneigh(sk: &NlSock, p: &[u8]) -> Result<Done, KernelError> {
    let r = ndmsg(p)?;
    let (dev, key) = nd_target(sk.net(), &r)?;
    let _r = rtnl::lock();
    sk.net().arp.admin_del(dev.ifindex(), &key)?;
    Ok(Done::Ok)
}

/// RTM_GETNEIGH for one entry (Linux neigh_get): ENOENT if absent
fn getneigh(sk: &NlSock, h: &Hdr, p: &[u8]) -> Result<Done, KernelError> {
    let r = ndmsg(p)?;
    let (dev, key) = nd_target(sk.net(), &r)?;
    let e = sk
        .net()
        .arp
        .dump()
        .into_iter()
        .find(|e| e.ifindex == dev.ifindex() && e.key == key)
        .ok_or(KernelError::NotFound)?;
    reply(sk, fill_neigh(&e, RTM_NEWNEIGH, 0, h.seq, sk.portid()));
    Ok(Done::Ok)
}

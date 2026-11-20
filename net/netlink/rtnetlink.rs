//! NETLINK_ROUTE (Linux net/core/rtnetlink.c, net/ipv4/devinet.c,
//! fib_frontend.c, route.c, net/core/neighbour.c)
//!
//! Requests are dispatched by message type and family: links (any
//! family), IPv4 addresses and routes (AF_INET), the ARP neighbour
//! table (RTM_{NEW,DEL,GET}NEIGH, `neigh_nl`) and the IPv4 rule dump. AF_INET6
//! requests get empty dumps (no IPv6 addresses/routes exist yet; rule
//! dumps are EAFNOSUPPORT) and EAFNOSUPPORT for changes. NEW/DEL/SET
//! need CAP_NET_ADMIN.
//!
//! Dumps are resumable cursors (`RtDump`): parts of at most `DUMP_SIZE`
//! bytes are produced as the reader drains its queue, NLMSG_DONE last.

use crate::util::kalloc::try_box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::attr::{
    Attrs, Hdr, Msg, NLA_HDRLEN, NLMSG_HDRLEN, NlBuf, align, attr_size, header, msg_size, nlmsg_new,
};
use super::*;
use crate::net::NetNamespace;
use crate::net::device::{NetDevice, flags as dflags, operstate};
use crate::net::inet::fib::{
    self, FibConfig, FibEntry, FlowKey, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE, RT_TABLE_MAIN,
    RTNH_F_DEAD, RTNH_F_LINKDOWN, RouteType,
};
use crate::net::inet::ifaddr::{
    self, IFA_F_PERMANENT, IFNAMSIZ, INFINITY_LIFE_TIME, IfaLabel, InIfaddr,
};
use crate::net::inet::route;
use crate::net::ipv4::Ipv4Addr;
use crate::net::neigh_nl::{self, NeighFilter};
use crate::net::rtnl::{self, RtnlGuard};
use crate::ns::NetRef;
use crate::util::kmem::KVec;

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
pub use crate::net::neigh_nl::{RTM_DELNEIGH, RTM_NEWNEIGH};
pub const RTM_GETNEIGH: u16 = 30;
pub use crate::net::fib_rules::{RTM_DELRULE, RTM_NEWRULE};
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
const IFLA_MASTER: u16 = 10;
const IFLA_TXQLEN: u16 = 13;
const IFLA_MAP: u16 = 14;
const IFLA_OPERSTATE: u16 = 16;
const IFLA_LINKMODE: u16 = 17;
const IFLA_LINKINFO: u16 = 18;
const IFLA_NET_NS_PID: u16 = 19;
const IFLA_IFALIAS: u16 = 20;
const IFLA_VFINFO_LIST: u16 = 22;
const IFLA_STATS64: u16 = 23;
const IFLA_VF_PORTS: u16 = 24;
const IFLA_PORT_SELF: u16 = 25;
const IFLA_AF_SPEC: u16 = 26;
const IFLA_GROUP: u16 = 27;
const IFLA_NET_NS_FD: u16 = 28;
const IFLA_PROMISCUITY: u16 = 30;
const IFLA_NUM_TX_QUEUES: u16 = 31;
const IFLA_NUM_RX_QUEUES: u16 = 32;
const IFLA_CARRIER: u16 = 33;
const IFLA_CARRIER_CHANGES: u16 = 35;
const IFLA_LINK_NETNSID: u16 = 37;
const IFLA_PROTO_DOWN: u16 = 39;
const IFLA_GSO_MAX_SEGS: u16 = 40;
const IFLA_GSO_MAX_SIZE: u16 = 41;
const IFLA_XDP: u16 = 43;
const IFLA_TARGET_NETNSID: u16 = 46;
const IFLA_MIN_MTU: u16 = 50;
const IFLA_MAX_MTU: u16 = 51;
const IFLA_ALT_IFNAME: u16 = 53;
const IFLA_PERM_ADDRESS: u16 = 54;
const IFLA_PROTO_DOWN_REASON: u16 = 55;
const IFLA_GRO_MAX_SIZE: u16 = 58;
const IFLA_TSO_MAX_SIZE: u16 = 59;
const IFLA_TSO_MAX_SEGS: u16 = 60;
const IFLA_ALLMULTI: u16 = 61;
const IFLA_GSO_IPV4_MAX_SIZE: u16 = 63;
const IFLA_GRO_IPV4_MAX_SIZE: u16 = 64;
const IFLA_NETNS_IMMUTABLE: u16 = 67;
const IFLA_HEADROOM: u16 = 68;
const IFLA_TAILROOM: u16 = 69;
const IFLA_MAX: u16 = 69;
// IFLA_INFO_* (nested in IFLA_LINKINFO)
const IFLA_INFO_DATA: u16 = 2;
const IFLA_INFO_SLAVE_DATA: u16 = 5;
const IFLA_INFO_MAX: u16 = 5;
// IFLA_VF_INFO (nested in IFLA_VFINFO_LIST)
const IFLA_VF_INFO: u16 = 1;
// IFLA_XDP_* (nested in IFLA_XDP) and XDP_FLAGS_*
const IFLA_XDP_FD: u16 = 1;
const IFLA_XDP_ATTACHED: u16 = 2;
const IFLA_XDP_FLAGS: u16 = 3;
const IFLA_XDP_PROG_ID: u16 = 4;
const IFLA_XDP_EXPECTED_FD: u16 = 8;
const IFLA_XDP_MAX: u16 = 8;
const XDP_FLAGS_MODES: u32 = 0xe;
const XDP_FLAGS_REPLACE: u32 = 0x10;
const XDP_FLAGS_MASK: u32 = 0x1f;
/// IF_OPER_* the device module has no use for
const IF_OPER_TESTING: u8 = 4;
const IF_OPER_DORMANT: u8 = 5;
/// Linux INIT_NETDEV_GROUP, IFALIASZ, ETH_ALEN
const INIT_NETDEV_GROUP: u32 = 0;
const IFALIASZ: usize = 256;
const ETH_ALEN: usize = 6;

// IFA_*
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_LABEL: u16 = 3;
const IFA_BROADCAST: u16 = 4;
const IFA_CACHEINFO: u16 = 6;
const IFA_FLAGS: u16 = 8;
const IFA_RT_PRIORITY: u16 = 9;
const IFA_TARGET_NETNSID: u16 = 10;
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

/// Family header sizes
const IFINFOMSG_LEN: usize = 16;
const IFADDRMSG_LEN: usize = 8;
const RTMSG_LEN: usize = 12;

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
        let ext = ExtAck::default();
        let res = if h.flags & NLM_F_REQUEST == 0 || h.ty < NLMSG_MIN_TYPE {
            Ok(Done::Ok)
        } else {
            rcv_msg(sk, &h, &msg[NLMSG_HDRLEN..], explicit, &ext)
        };
        match res {
            Ok(Done::Dump) => {}
            Ok(Done::Ok) if h.flags & NLM_F_ACK != 0 => ack(sk, &h, msg, 0, &ext),
            Ok(Done::Ok) => {}
            Err(e) => ack(sk, &h, msg, -e.errno(), &ext),
        }
        data = &data[align(len).min(data.len())..];
    }
}

/// Queue an NLMSG_ERROR (err 0 = ACK) for request `msg` (Linux
/// netlink_ack): errors echo the whole request unless NETLINK_CAP_ACK;
/// with NETLINK_EXT_ACK the handler's message and, for an error, the
/// offending attribute's offset follow (netlink_ack_tlv_fill)
fn ack(sk: &NlSock, h: &Hdr, msg: &[u8], err: i32, ext: &ExtAck) {
    let echo = err != 0 && !sk.has_flag(sflags::CAP_ACK);
    let tlv = if sk.has_flag(sflags::EXT_ACK) {
        AckTlv {
            msg: ext.get_msg(),
            offs: ext.offs(msg).filter(|_| err != 0),
        }
    } else {
        AckTlv::default()
    };
    match ack_msg(h.seq, sk.portid(), msg, err, echo, &tlv) {
        Some(m) => reply(sk, m),
        // Linux netlink_ack: no memory for even the capped ACK reports
        // ENOBUFS on the socket
        None => sk.sk.set_err(KernelError::NoBufferSpace),
    }
}

/// nlmsghdr bytes
fn nlmsg_hdr(len: usize, ty: u16, flags: u16, seq: u32, pid: u32) -> [u8; NLMSG_HDRLEN] {
    let mut b = [0u8; NLMSG_HDRLEN];
    b[0..4].copy_from_slice(&(len as u32).to_ne_bytes());
    b[4..6].copy_from_slice(&ty.to_ne_bytes());
    b[6..8].copy_from_slice(&flags.to_ne_bytes());
    b[8..12].copy_from_slice(&seq.to_ne_bytes());
    b[12..16].copy_from_slice(&pid.to_ne_bytes());
    b
}

/// The extended ACK attributes of an NLMSG_ERROR (Linux
/// netlink_ack_tlv_len / netlink_ack_tlv_fill)
#[derive(Default)]
struct AckTlv {
    /// NLMSGERR_ATTR_MSG
    msg: Option<&'static str>,
    /// NLMSGERR_ATTR_OFFS (errors only)
    offs: Option<u32>,
}

impl AckTlv {
    fn len(&self) -> usize {
        self.msg.map_or(0, |m| attr_size(m.len() + 1)) + self.offs.map_or(0, |_| attr_size(4))
    }

    /// Append them to `m` (room reserved by the caller)
    fn fill(&self, m: &mut KVec<u8>) -> Option<()> {
        if let Some(s) = self.msg {
            tlv_put(m, NLMSGERR_ATTR_MSG, &[s.as_bytes(), &[0]])?;
        }
        if let Some(o) = self.offs {
            tlv_put(m, NLMSGERR_ATTR_OFFS, &[&o.to_ne_bytes()])?;
        }
        Some(())
    }
}

/// One attribute whose payload is `parts`, padded to 4
fn tlv_put(m: &mut KVec<u8>, ty: u16, parts: &[&[u8]]) -> Option<()> {
    let n: usize = parts.iter().map(|p| p.len()).sum();
    let len = u16::try_from(NLA_HDRLEN + n).ok()?;
    m.try_extend_from_slice(&len.to_ne_bytes()).ok()?;
    m.try_extend_from_slice(&ty.to_ne_bytes()).ok()?;
    for p in parts {
        m.try_extend_from_slice(p).ok()?;
    }
    m.try_resize(align(m.len()), 0).ok()
}

/// The NLMSG_ERROR for request `msg`: the error, then the whole request
/// when `echo` and the message fits a fallible allocation; else the
/// error and the request header with NLM_F_CAPPED (Linux netlink_ack
/// fails instead: hk falls back to the small form); the extended ACK
/// attributes `tlv` last, with NLM_F_ACK_TLVS. None if no memory.
fn ack_msg(seq: u32, pid: u32, msg: &[u8], err: i32, echo: bool, tlv: &AckTlv) -> Option<Vec<u8>> {
    if echo && let Some(m) = err_msg(seq, pid, msg, err, false, tlv) {
        return Some(m);
    }
    err_msg(seq, pid, &msg[..NLMSG_HDRLEN], err, true, tlv)
}

/// An NLMSG_ERROR carrying `req` (the whole request, or its header:
/// NLM_F_CAPPED), allocated fallibly in one exact piece
fn err_msg(
    seq: u32,
    pid: u32,
    req: &[u8],
    err: i32,
    capped: bool,
    tlv: &AckTlv,
) -> Option<Vec<u8>> {
    let body = NLMSG_HDRLEN + 4 + align(req.len());
    let len = body + tlv.len();
    let mut flags = if capped { NLM_F_CAPPED } else { 0 };
    if tlv.len() != 0 {
        flags |= NLM_F_ACK_TLVS;
    }
    let mut m = KVec::try_with_capacity(len).ok()?;
    m.try_extend_from_slice(&nlmsg_hdr(len, NLMSG_ERROR, flags, seq, pid))
        .ok()?;
    m.try_extend_from_slice(&err.to_ne_bytes()).ok()?;
    m.try_extend_from_slice(req).ok()?;
    m.try_resize(body, 0).ok()?;
    tlv.fill(&mut m)?;
    Some(m.into_vec())
}

fn reply(sk: &NlSock, data: Vec<u8>) {
    sk.queue(kernel_skb(data, 0));
}

/// One request: permission, then dump or do
fn rcv_msg(
    sk: &Arc<NlSock>,
    h: &Hdr,
    p: &[u8],
    explicit: bool,
    ext: &ExtAck,
) -> Result<Done, KernelError> {
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
        sk.dump_start(try_box(cb)?, h.seq)?;
        return Ok(Done::Dump);
    }
    let nl = NlInfo {
        portid: sk.portid(),
        seq: h.seq,
        report: h.flags & NLM_F_ECHO != 0,
    };
    match h.ty {
        RTM_NEWNEIGH | RTM_DELNEIGH => {
            // Configuration changes: under RTNL from the device lookup
            // on (Linux neigh_add / neigh_delete are locked doits)
            let _r = rtnl::lock();
            match h.ty {
                RTM_NEWNEIGH => neigh_nl::newneigh(sk, h.flags, p, ext)?,
                _ => neigh_nl::delneigh(sk, p, ext)?,
            }
            Ok(Done::Ok)
        }
        RTM_GETNEIGH => {
            reply(sk, neigh_nl::getneigh(sk, h.seq, p, ext)?);
            Ok(Done::Ok)
        }
        RTM_NEWRULE | RTM_DELRULE => {
            let r = rtnl::lock();
            let net = sk.net();
            match h.ty {
                RTM_NEWRULE => crate::net::fib_rules::newrule(&r, net, h.flags, p, nl, ext)?,
                _ => crate::net::fib_rules::delrule(&r, net, p, nl, ext)?,
            }
            Ok(Done::Ok)
        }
        RTM_NEWLINK => newlink(sk, h, p, nl, ext),
        RTM_SETLINK => setlink(sk, p, nl, ext),
        RTM_GETLINK => getlink(sk, h, p, ext),
        RTM_NEWADDR | RTM_DELADDR | RTM_NEWROUTE | RTM_DELROUTE | RTM_GETROUTE => match family {
            AF_INET => match h.ty {
                RTM_NEWADDR => newaddr(sk, h, p, nl, ext),
                RTM_DELADDR => deladdr(sk, p, nl, ext),
                RTM_NEWROUTE => newroute(sk, h, p, nl, ext),
                RTM_DELROUTE => delroute(sk, h, p, nl, ext),
                _ => getroute(sk, h, p, ext),
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
    /// Neighbours or proxy entries
    Neigh(NeighFilter),
    /// IPv4 routing rules
    Rule,
    /// Nothing (other families, RTM_F_CLONED)
    Empty,
    /// Request rejected by strict checking: DONE carries the error and
    /// its extended ACK message
    Bad(KernelError, Option<&'static str>),
}

/// A dump request refused: `e`, with message `m`
fn bad(e: KernelError, m: &'static str) -> DumpKind {
    DumpKind::Bad(e, Some(m))
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
            RTM_GETLINK if strict => link_dump_check(p),
            RTM_GETLINK => DumpKind::Link,
            RTM_GETADDR if inet => addr_dump_kind(sk.net(), p, strict, &mut flags),
            RTM_GETROUTE if inet => route_dump_kind(p, strict, &mut flags),
            RTM_GETNEIGH if inet => neigh_dump_kind(p, strict, &mut flags),
            RTM_GETRULE => rule_dump_kind(sk.net(), p, strict),
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

    /// Fill messages for the objects of `items` past `pos` into the
    /// part while they fit (Linux: a dump's fill meets EMSGSIZE, the
    /// part ends there and the next resumes at that object); one too
    /// large for an empty part ends the dump with EMSGSIZE. `items` may
    /// be an RCU walk: nothing here allocates.
    fn take_nl<T>(
        &mut self,
        nb: &mut NlBuf<'_>,
        items: impl IntoIterator<Item = T>,
        f: impl Fn(&mut NlBuf<'_>, T) -> Result<(), KernelError>,
    ) -> Result<bool, KernelError> {
        for it in items.into_iter().skip(self.pos) {
            if let Err(e) = f(nb, it) {
                return if nb.is_empty() { Err(e) } else { Ok(false) };
            }
            self.pos += 1;
        }
        // Leave room for NLMSG_DONE in the same part, like Linux
        Ok(nb.len() + NLMSG_HDRLEN + 4 <= DUMP_SIZE || nb.is_empty())
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
            DumpKind::Bad(e, _) => Err(e),
            DumpKind::Empty => Ok(true),
            DumpKind::Link => {
                let devs = net.devices();
                Ok(self.take(buf, &devs, |d| fill_link(d, RTM_NEWLINK, f, seq, pid, 0)))
            }
            DumpKind::Addr(only) => {
                // Linux inet_dump_ifaddr: devices and addresses walked
                // under RCU, filled into the part as they are reached
                let g = crate::sync::rcu::read_lock();
                let addrs = net
                    .devices_rcu(&g)
                    .filter(|d| only == 0 || d.ifindex() == only)
                    .flat_map(|d| d.in_dev().addrs(&g).map(move |a| (d, a)));
                let mut nb = NlBuf::new(buf, DUMP_SIZE);
                self.take_nl(&mut nb, addrs, |nb, (d, a)| {
                    fill_addr(nb, d, a, RTM_NEWADDR, f, seq, pid)
                })
            }
            DumpKind::Route(table) => {
                // Linux inet_dump_fib: the tables walked under RCU, each
                // route filled into the part as it is reached
                let g = crate::sync::rcu::read_lock();
                let rts = net
                    .fib
                    .entries(&g)
                    .filter(|e| table == 0 || e.table == table);
                let mut nb = NlBuf::new(buf, DUMP_SIZE);
                self.take_nl(&mut nb, rts, |nb, e| {
                    fill_route(nb, e, RTM_NEWROUTE, f, seq, pid)
                })
            }
            DumpKind::Neigh(nf) if nf.proxy => {
                // Linux pneigh_dump_table: the chains walked under RCU
                let g = crate::sync::rcu::read_lock();
                let ns = neigh_nl::dump_pneighs(&g, net, nf);
                let mut nb = NlBuf::new(buf, DUMP_SIZE);
                self.take_nl(&mut nb, ns, |nb, n| {
                    neigh_nl::fill_pneigh(nb, n, RTM_NEWNEIGH, f, seq, pid)
                })
            }
            DumpKind::Neigh(nf) => {
                // Linux neigh_dump_table: the buckets walked under RCU,
                // each entry of the namespace filled as it is reached
                let g = crate::sync::rcu::read_lock();
                let now = crate::net::neigh::now_ms();
                let ns = neigh_nl::dump_neighs(&g, net, nf);
                let mut nb = NlBuf::new(buf, DUMP_SIZE);
                self.take_nl(&mut nb, ns, |nb, n| {
                    neigh_nl::fill_neigh(nb, &n.info(now), RTM_NEWNEIGH, f, seq, pid)
                })
            }
            DumpKind::Rule => {
                // Linux dump_rules: the list walked under RCU
                let g = crate::sync::rcu::read_lock();
                let rules = &net.fib.rules;
                let mut nb = NlBuf::new(buf, DUMP_SIZE);
                self.take_nl(&mut nb, rules.iter(&g), |nb, r| {
                    crate::net::fib_rules::fill_rule(nb, rules, &g, r, RTM_NEWRULE, f, seq, pid)
                })
            }
        }
    }

    fn ext_msg(&self) -> Option<&'static str> {
        match self.kind {
            DumpKind::Bad(_, m) => m,
            _ => None,
        }
    }
}

/// Neighbour dump request (Linux neigh_dump_info): its filter, or the
/// strict check's error
fn neigh_dump_kind(p: &[u8], strict: bool, flags: &mut u16) -> DumpKind {
    let ext = ExtAck::default();
    match neigh_nl::dump_req(p, strict, &ext) {
        Ok(nf) => {
            *flags |= nf.nlflags();
            DumpKind::Neigh(nf)
        }
        Err(e) => DumpKind::Bad(e, ext.get_msg()),
    }
}

// ============================================================================
// Rules
// ============================================================================

/// Rule dump request (Linux fib_nl_dumprule)
fn rule_dump_kind(net: &NetNamespace, p: &[u8], strict: bool) -> DumpKind {
    match crate::net::fib_rules::dump_req(net, p, strict) {
        Ok(()) => DumpKind::Rule,
        Err((e, m)) => DumpKind::Bad(e, m),
    }
}

// ============================================================================
// Links
// ============================================================================

/// Strict link dump header (Linux rtnl_valid_dump_ifinfo_req)
fn link_dump_check(p: &[u8]) -> DumpKind {
    use KernelError::InvalidArgument as E;
    let Some(h) = p.get(..IFINFOMSG_LEN) else {
        return bad(E, "Invalid header for link dump");
    };
    // __ifi_pad, ifi_type, ifi_flags, ifi_change
    if h[1..4].iter().chain(&h[8..16]).any(|&b| b != 0) {
        return bad(E, "Invalid values in header for link dump request");
    }
    if h[4..8].iter().any(|&b| b != 0) {
        return bad(E, "Filter by device index not supported for link dumps");
    }
    DumpKind::Link
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
    a: &Attrs<'_>,
) -> Result<Option<Arc<NetDevice>>, KernelError> {
    if ifm.index.cast_signed() > 0 {
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
fn getlink(sk: &NlSock, h: &Hdr, p: &[u8], ext: &ExtAck) -> Result<Done, KernelError> {
    let ifm = ifinfo(p)?;
    let a = Attrs::parse(&p[IFINFOMSG_LEN..], IFLA_MAX)?.ext(ext);
    let dev = link_dev(sk.net(), &ifm, &a)?.ok_or(KernelError::NoDevice)?;
    reply(sk, fill_link(&dev, RTM_NEWLINK, 0, h.seq, sk.portid(), 0));
    Ok(Done::Ok)
}

/// ifla_policy's NLA_REJECT attributes (read-only, EINVAL in requests)
const IFLA_REJECT: [u16; 7] = [
    IFLA_PERM_ADDRESS,
    IFLA_TSO_MAX_SIZE,
    IFLA_TSO_MAX_SEGS,
    IFLA_ALLMULTI,
    IFLA_NETNS_IMMUTABLE,
    IFLA_HEADROOM,
    IFLA_TAILROOM,
];

/// The parts of Linux ifla_policy the link requests rely on beyond the
/// typed reads: rejected attributes, the txqlen range
fn ifla_validate(a: &Attrs<'_>) -> Result<(), KernelError> {
    if IFLA_REJECT.iter().any(|&t| a.has(t)) {
        return Err(KernelError::InvalidArgument);
    }
    // NLA_POLICY_FULL_RANGE(NLA_U32, 0..INT_MAX)
    if a.u32(IFLA_TXQLEN)?.is_some_and(|q| q > i32::MAX as u32) {
        return Err(KernelError::Range);
    }
    Ok(())
}

/// At most one of the attributes naming a namespace (Linux
/// rtnl_ensure_unique_netns)
fn ensure_unique_netns(a: &Attrs<'_>, ext: &ExtAck) -> Result<(), KernelError> {
    let n = [IFLA_NET_NS_PID, IFLA_NET_NS_FD, IFLA_TARGET_NETNSID]
        .iter()
        .filter(|&&t| a.has(t))
        .count();
    if n > 1 {
        ext.msg("multiple netns identifying attributes specified");
        return Err(KernelError::InvalidArgument);
    }
    Ok(())
}

/// The namespace a link request names, None for the socket's own
/// (Linux rtnl_link_get_net_capable). hk assigns no namespace ids, so
/// IFLA_TARGET_NETNSID names none (EINVAL, Linux get_net_ns_by_id
/// failing). The CAP_NET_ADMIN check over the namespace's owner is the
/// caller's own, made for every request (hk capabilities ignore user
/// namespaces, BUGS.md).
fn link_get_net(a: &Attrs<'_>) -> Result<Option<NetRef>, KernelError> {
    if let Some(pid) = a.u32(IFLA_NET_NS_PID)? {
        return Ok(Some(crate::ns::net::get_net_ns_by_pid(pid)?));
    }
    if let Some(fd) = a.u32(IFLA_NET_NS_FD)? {
        return Ok(Some(crate::ns::net::get_net_ns_by_fd(fd)?));
    }
    if a.has(IFLA_TARGET_NETNSID) {
        return Err(KernelError::InvalidArgument);
    }
    Ok(None)
}

/// RTM_SETLINK (Linux rtnl_setlink)
fn setlink(sk: &NlSock, p: &[u8], nl: NlInfo, ext: &ExtAck) -> Result<Done, KernelError> {
    let ifm = ifinfo(p)?;
    let a = Attrs::parse(&p[IFINFOMSG_LEN..], IFLA_MAX)?.ext(ext);
    ifla_validate(&a)?;
    ensure_unique_netns(&a, ext)?;
    let tgt = link_get_net(&a)?;
    let net = sk.net();
    // The lookup under RTNL too: an unregistered device is never found
    let r = rtnl::lock();
    let dev = link_dev(net, &ifm, &a)?.ok_or(KernelError::NoDevice)?;
    do_setlink(&r, net, &dev, tgt.as_deref(), &ifm, &a, nl, ext)?;
    Ok(Done::Ok)
}

/// RTM_NEWLINK (Linux rtnl_newlink): no link kinds are registered, so
/// it only changes existing devices (rtnl_changelink) or a group
fn newlink(sk: &NlSock, h: &Hdr, p: &[u8], nl: NlInfo, ext: &ExtAck) -> Result<Done, KernelError> {
    let ifm = ifinfo(p)?;
    let a = Attrs::parse(&p[IFINFOMSG_LEN..], IFLA_MAX)?.ext(ext);
    ifla_validate(&a)?;
    ensure_unique_netns(&a, ext)?;
    let linkinfo = match a.get(IFLA_LINKINFO) {
        Some(b) => Some(Attrs::parse(b, IFLA_INFO_MAX)?.ext(ext)),
        None => None,
    };
    let tgt = link_get_net(&a)?;
    if a.has(IFLA_LINK_NETNSID) {
        // No namespace ids (Linux get_net_ns_by_id failing)
        ext.msg("Unknown network namespace id");
        return Err(KernelError::InvalidArgument);
    }
    let net = sk.net();
    let r = rtnl::lock();
    // When creating, the device is looked up in the target namespace
    let create = h.flags & NLM_F_CREATE != 0;
    let dnet = match &tgt {
        Some(t) if create && h.flags & NLM_F_EXCL != 0 => t,
        _ => net,
    };
    if ifm.index.cast_signed() < 0 {
        ext.msg("ifindex can't be negative");
        return Err(KernelError::InvalidArgument);
    }
    let specified = ifm.index != 0 || a.has(IFLA_IFNAME) || a.has(IFLA_ALT_IFNAME);
    let dev = if specified {
        link_dev(dnet, &ifm, &a)?
    } else {
        None
    };
    if let Some(dev) = dev {
        // Linux rtnl_changelink
        if h.flags & NLM_F_EXCL != 0 {
            return Err(KernelError::AlreadyExists);
        }
        if h.flags & NLM_F_REPLACE != 0 {
            return Err(KernelError::OperationNotSupported);
        }
        // Kind data needs the device's link ops, slave data its
        // master's: hk devices have neither
        if let Some(li) = &linkinfo
            && (li.has(IFLA_INFO_DATA) || li.has(IFLA_INFO_SLAVE_DATA))
        {
            return Err(KernelError::OperationNotSupported);
        }
        do_setlink(&r, net, &dev, tgt.as_deref(), &ifm, &a, nl, ext)?;
        return Ok(Done::Ok);
    }
    if !create {
        let Some(group) = a.u32(IFLA_GROUP)?.filter(|_| !specified) else {
            return Err(KernelError::NoDevice);
        };
        // Linux rtnl_group_changelink: every device is in the default
        // group (0)
        if group == INIT_NETDEV_GROUP {
            for dev in net.devices() {
                do_setlink(&r, net, &dev, tgt.as_deref(), &ifm, &a, nl, ext)?;
            }
        }
        return Ok(Done::Ok);
    }
    // Creating links (veth, bridge, ...) needs link kinds
    Err(KernelError::OperationNotSupported)
}

/// Linux validate_linkmsg: hardware addresses at least the device's
/// length (6: hk links are Ethernet-like), IFLA_AF_SPEC of known
/// families (AF_INET, AF_INET6; Linux rtnl_af_lookup, EAFNOSUPPORT)
fn validate_linkmsg(a: &Attrs<'_>) -> Result<(), KernelError> {
    for t in [IFLA_ADDRESS, IFLA_BROADCAST] {
        if a.get(t).is_some_and(|b| b.len() < ETH_ALEN) {
            return Err(KernelError::InvalidArgument);
        }
    }
    if let Some(b) = a.get(IFLA_AF_SPEC) {
        for (af, _) in nested(b)? {
            if af != u16::from(AF_INET) && af != u16::from(AF_INET6) {
                return Err(KernelError::AddressFamilyNotSupported);
            }
        }
    }
    Ok(())
}

/// The (type, payload) attributes nested in `b` (Linux
/// nla_for_each_nested); EINVAL if malformed
fn nested(mut b: &[u8]) -> Result<Vec<(u16, &[u8])>, KernelError> {
    let mut v = Vec::new();
    while b.len() >= 4 {
        let len = usize::from(u16::from_ne_bytes([b[0], b[1]]));
        let ty = u16::from_ne_bytes([b[2], b[3]]) & 0x3fff;
        if len < 4 || len > b.len() {
            return Err(KernelError::InvalidArgument);
        }
        v.try_reserve(1).map_err(|_| KernelError::OutOfMemory)?;
        v.push((ty, &b[4..len]));
        b = &b[align(len).min(b.len())..];
    }
    Ok(v)
}

/// The operational state IFLA_OPERSTATE `transition` would leave
/// (Linux set_operstate; hk devices are never dormant or testing)
fn set_operstate(cur: u8, transition: u8) -> u8 {
    let oper_up = cur == operstate::IF_OPER_UP || cur == operstate::IF_OPER_UNKNOWN;
    match transition {
        operstate::IF_OPER_UP
            if matches!(
                cur,
                IF_OPER_DORMANT | IF_OPER_TESTING | operstate::IF_OPER_UNKNOWN
            ) =>
        {
            operstate::IF_OPER_UP
        }
        IF_OPER_TESTING | IF_OPER_DORMANT if oper_up => transition,
        _ => cur,
    }
}

/// Change device `dev` as link request `a` asks (Linux do_setlink), in
/// Linux's order, each attribute applied or refused: an earlier one
/// stays applied when a later one fails, as in Linux. What hk devices
/// cannot do fails with the errno Linux gives for a device or driver
/// without it; a setting equal to the device's fixed value is a no-op.
#[allow(clippy::too_many_arguments)]
fn do_setlink(
    r: &RtnlGuard,
    net: &NetNamespace,
    dev: &Arc<NetDevice>,
    tgt: Option<&NetNamespace>,
    ifm: &IfInfo,
    a: &Attrs<'_>,
    nl: NlInfo,
    ext: &ExtAck,
) -> Result<(), KernelError> {
    use KernelError::{InvalidArgument, OperationNotSupported};
    validate_linkmsg(a)?;
    if let Some(t) = tgt
        && !dev.net_is(t)
    {
        // Linux __dev_change_net_namespace: a netns-immutable device
        // (lo) stays
        if dev.is_loopback() {
            return Err(InvalidArgument);
        }
        // Moving a device between namespaces is not supported yet
        return Err(OperationNotSupported);
    }
    // No ndo_set_config, no ndo_set_mac_address in hk drivers
    if a.has(IFLA_MAP) || a.has(IFLA_ADDRESS) {
        return Err(OperationNotSupported);
    }
    if let Some(mtu) = a.u32(IFLA_MTU)? {
        // Linux do_setlink hands the u32 to an int parameter: above
        // INT_MAX it is negative and dev_set_mtu refuses it
        rtnl::dev_set_mtu(r, net, dev, mtu.cast_signed(), nl)?;
    }
    // Devices stay in the default group
    if a.u32(IFLA_GROUP)?.is_some_and(|g| g != INIT_NETDEV_GROUP) {
        return Err(OperationNotSupported);
    }
    if ifm.index.cast_signed() > 0
        && let Some(n) = a.str(IFLA_IFNAME, IFNAMSIZ)?
        && !n.is_empty()
        && n != dev.name()
    {
        // Renaming is not supported
        return Err(OperationNotSupported);
    }
    // No aliases: only clearing (an empty one) is a no-op
    if let Some(al) = a.get(IFLA_IFALIAS) {
        if al.len() >= IFALIASZ {
            return Err(InvalidArgument);
        }
        if !al.is_empty() {
            return Err(OperationNotSupported);
        }
    }
    if a.get(IFLA_BROADCAST)
        .is_some_and(|b| b[..ETH_ALEN] != dev.link().broadcast)
    {
        return Err(OperationNotSupported);
    }
    if ifm.flags != 0 || ifm.change != 0 {
        let mut f = ifm.flags;
        if ifm.change != 0 {
            f = (f & ifm.change) | (dev.get_flags() & !ifm.change);
        }
        rtnl::dev_change_flags(r, net, dev, f, nl)?;
    }
    // Linux do_set_master: no device has a master; one named must
    // exist and take slaves (ndo_add_slave)
    if let Some(m) = a.u32(IFLA_MASTER)?
        && m != 0
    {
        return Err(match net.dev_get_by_index(m) {
            Some(_) => OperationNotSupported,
            None => InvalidArgument,
        });
    }
    // No ndo_change_carrier
    if a.u8(IFLA_CARRIER)?.is_some() {
        return Err(OperationNotSupported);
    }
    if a.u32(IFLA_TXQLEN)?.is_some_and(|q| q != dev.link().txqlen) {
        return Err(OperationNotSupported);
    }
    // No GSO/GRO limits to set
    if [
        IFLA_GSO_MAX_SIZE,
        IFLA_GSO_MAX_SEGS,
        IFLA_GRO_MAX_SIZE,
        IFLA_GSO_IPV4_MAX_SIZE,
        IFLA_GRO_IPV4_MAX_SIZE,
    ]
    .iter()
    .any(|&t| a.has(t))
    {
        return Err(OperationNotSupported);
    }
    // Operational state and link mode follow the carrier only
    if let Some(t) = a.u8(IFLA_OPERSTATE)? {
        let cur = dev.operstate();
        if set_operstate(cur, t) != cur {
            return Err(OperationNotSupported);
        }
    }
    if a.u8(IFLA_LINKMODE)?.is_some_and(|m| m != 0) {
        return Err(OperationNotSupported);
    }
    // The first VF entry decides (Linux do_setvfinfo: nothing to set is
    // EINVAL, anything needs an ndo_set_vf_*: no SR-IOV)
    if let Some(b) = a.get(IFLA_VFINFO_LIST)
        && let Some(&(ty, vf)) = nested(b)?.first()
    {
        if ty != IFLA_VF_INFO || nested(vf)?.is_empty() {
            return Err(InvalidArgument);
        }
        return Err(OperationNotSupported);
    }
    // No ndo_set_vf_port
    if a.has(IFLA_VF_PORTS) {
        return Err(OperationNotSupported);
    }
    if let Some(b) = a.get(IFLA_PORT_SELF) {
        nested(b)?;
        return Err(OperationNotSupported);
    }
    // No per-family link settings (Linux inet/inet6 set_link_af:
    // devconf)
    if a.get(IFLA_AF_SPEC).is_some_and(|b| !b.is_empty()) {
        return Err(OperationNotSupported);
    }
    // No device supports proto_down (Linux do_set_proto_down)
    if a.has(IFLA_PROTO_DOWN) || a.has(IFLA_PROTO_DOWN_REASON) {
        ext.msg("Protodown not supported by device");
        return Err(OperationNotSupported);
    }
    if let Some(b) = a.get(IFLA_XDP) {
        setlink_xdp(b)?;
    }
    Ok(())
}

/// IFLA_XDP of a link request (Linux do_setlink): checked as Linux
/// does; attaching a program is not supported (no XDP)
fn setlink_xdp(b: &[u8]) -> Result<(), KernelError> {
    let x = Attrs::parse(b, IFLA_XDP_MAX)?;
    if x.has(IFLA_XDP_ATTACHED) || x.has(IFLA_XDP_PROG_ID) {
        return Err(KernelError::InvalidArgument);
    }
    let flags = x.u32(IFLA_XDP_FLAGS)?.unwrap_or(0);
    if flags & !XDP_FLAGS_MASK != 0 || (flags & XDP_FLAGS_MODES).count_ones() > 1 {
        return Err(KernelError::InvalidArgument);
    }
    if let Some(fd) = x.u32(IFLA_XDP_FD)? {
        let replace = flags & XDP_FLAGS_REPLACE != 0;
        if replace && !x.has(IFLA_XDP_EXPECTED_FD) {
            return Err(KernelError::InvalidArgument);
        }
        // A detach with nothing attached succeeds (Linux dev_xdp_attach:
        // new == old == NULL, the driver untouched), unless REPLACE
        // expects a program (EEXIST); hk attaches none (EOPNOTSUPP)
        if (fd as i32) >= 0 {
            return Err(KernelError::OperationNotSupported);
        }
        let expected = x.u32(IFLA_XDP_EXPECTED_FD)?.map_or(-1, |e| e as i32);
        if replace && expected >= 0 {
            return Err(KernelError::AlreadyExists);
        }
    }
    Ok(())
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
    let promisc = u32::from(dev.admin_flags() & dflags::IFF_PROMISC != 0);
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
        .u8(IFLA_CARRIER, u8::from(dev.carrier_ok()))
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
    use crate::net::device::stat;
    let s = &dev.stats;
    let mut v = [0u64; 25];
    // rtnl_link_stats64 slots 0..=9 are stat 0..=9, rx_nohandler 23
    for (f, slot) in v.iter_mut().enumerate().take(stat::COLLISIONS + 1) {
        *slot = s.get(f);
    }
    v[23] = s.get(stat::RX_NOHANDLER);
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

/// Announce a link change to RTNLGRP_LINK (Linux __dev_notify_flags'
/// rtmsg_ifinfo: never echoed)
pub fn notify_link(net: &NetNamespace, dev: &NetDevice, nl: NlInfo) {
    let data = fill_link(dev, RTM_NEWLINK, 0, nl.seq, nl.portid, 0);
    rtnl_notify(net, data, RTNLGRP_LINK, NlInfo::default());
}

/// RTM_DELLINK for an unregistered device (Linux
/// unregister_netdevice_many_notify's rtmsg_ifinfo, change ~0)
pub fn notify_dellink(net: &NetNamespace, dev: &NetDevice) {
    let data = fill_link(dev, RTM_DELLINK, 0, 0, 0, !0);
    rtnl_notify(net, data, RTNLGRP_LINK, NlInfo::default());
}

/// Send a notification to `group`, and back to the requester when it
/// asked (NLM_F_ECHO; Linux rtnl_notify -> nlmsg_notify)
fn rtnl_notify(net: &NetNamespace, data: Vec<u8>, group: u32, nl: NlInfo) {
    // Linux rtnl_notify(GFP_KERNEL): no lock held here
    let skb = kernel_skb(data, group);
    notify(net, NETLINK_ROUTE, skb, nl.portid, nl.report, Gfp::KERNEL);
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
    use KernelError::InvalidArgument as E;
    if !strict {
        return DumpKind::Addr(0);
    }
    let Ok(ifm) = ifaddrmsg(p) else {
        return bad(E, "ipv4: Invalid header for address dump request");
    };
    if ifm.prefixlen != 0 || ifm.flags != 0 || ifm.scope != 0 {
        return bad(E, "ipv4: Invalid values in header for address dump request");
    }
    if ifm.index != 0 {
        *flags |= NLM_F_DUMP_FILTERED;
    }
    match Attrs::parse(&p[IFADDRMSG_LEN..], IFA_MAX) {
        Err(e) => return DumpKind::Bad(e, None),
        // No namespace ids: none is valid (Linux
        // rtnl_get_net_ns_capable failing)
        Ok(a) if a.has(IFA_TARGET_NETNSID) => {
            return bad(E, "ipv4: Invalid target network namespace id");
        }
        Ok(a) if (1..=IFA_MAX).any(|t| a.has(t)) => {
            return bad(E, "ipv4: Unsupported attribute in dump request");
        }
        Ok(_) => {}
    }
    if ifm.index != 0 && net.dev_get_by_index(ifm.index).is_none() {
        return DumpKind::Bad(KernelError::NoDevice, None);
    }
    DumpKind::Addr(ifm.index)
}

/// Largest address message (Linux inet_nlmsg_size)
const ADDR_NLMSG_SIZE: usize = msg_size(IFADDRMSG_LEN)
    + attr_size(4) * 3 // IFA_ADDRESS, IFA_LOCAL, IFA_BROADCAST
    + attr_size(IFNAMSIZ) // IFA_LABEL
    + attr_size(1) // IFA_PROTO
    + attr_size(4) // IFA_FLAGS
    + attr_size(4) // IFA_RT_PRIORITY
    + attr_size(16); // IFA_CACHEINFO

/// An RTM_NEWADDR/DELADDR message in `nb` (Linux inet_fill_ifaddr):
/// EMSGSIZE, nothing left behind, if it does not fit
pub fn fill_addr(
    nb: &mut NlBuf<'_>,
    dev: &NetDevice,
    ifa: &InIfaddr,
    ty: u16,
    flags: u16,
    seq: u32,
    pid: u32,
) -> Result<(), KernelError> {
    let ifa_flags = ifa.flags();
    let mut h = [0u8; IFADDRMSG_LEN];
    h[0] = AF_INET;
    h[1] = ifa.prefixlen;
    h[2] = ifa_flags as u8; // ifa_flags holds the low byte
    h[3] = ifa.scope;
    h[4..8].copy_from_slice(&dev.ifindex().to_ne_bytes());
    let m = nb.msg_put(ty, flags, seq, pid, &h)?;
    match addr_attrs(nb, ifa, ifa_flags) {
        Ok(()) => {
            nb.msg_end(m);
            Ok(())
        }
        Err(e) => {
            nb.msg_cancel(m);
            Err(e)
        }
    }
}

/// An address's attributes (inet_fill_ifaddr's nla_puts)
fn addr_attrs(nb: &mut NlBuf<'_>, ifa: &InIfaddr, flags: u32) -> Result<(), KernelError> {
    nb.put(IFA_ADDRESS, &ifa.address.to_be_bytes())?;
    nb.put(IFA_LOCAL, &ifa.local.to_be_bytes())?;
    if !ifa.broadcast.is_unspecified() {
        nb.put(IFA_BROADCAST, &ifa.broadcast.to_be_bytes())?;
    }
    // NUL-terminated (nla_put_string)
    let label = ifa.label.as_str().as_bytes();
    let mut l = [0u8; IFNAMSIZ];
    l[..label.len()].copy_from_slice(label);
    nb.put(IFA_LABEL, &l[..=label.len()])?;
    let proto = ifa.proto();
    if proto != 0 {
        nb.put(IFA_PROTO, &[proto])?;
    }
    nb.put_u32(IFA_FLAGS, flags)?;
    let prio = ifa.rt_priority();
    if prio != 0 {
        nb.put_u32(IFA_RT_PRIORITY, prio)?;
    }
    // struct ifa_cacheinfo: preferred, valid, cstamp, tstamp
    let mut ci = [0u8; 16];
    ci[0..4].copy_from_slice(&INFINITY_LIFE_TIME.to_ne_bytes());
    ci[4..8].copy_from_slice(&INFINITY_LIFE_TIME.to_ne_bytes());
    nb.put(IFA_CACHEINFO, &ci)
}

/// Announce an address change to RTNLGRP_IPV4_IFADDR (Linux rtmsg_ifa:
/// a message sized first, then filled; dropped if no memory)
pub fn notify_addr(net: &NetNamespace, dev: &NetDevice, ifa: &InIfaddr, ty: u16, nl: NlInfo) {
    let Ok(mut v) = nlmsg_new(ADDR_NLMSG_SIZE) else {
        return;
    };
    let mut nb = NlBuf::new(&mut v, ADDR_NLMSG_SIZE);
    if fill_addr(&mut nb, dev, ifa, ty, 0, nl.seq, nl.portid).is_ok() {
        rtnl_notify(net, v, RTNLGRP_IPV4_IFADDR, nl);
    }
}

/// The attributes of an address request, read as Linux's
/// ifa_ipv4_policy validates them: every one before any other check
struct IfaAttrs<'a> {
    local: Option<Ipv4Addr>,
    address: Option<Ipv4Addr>,
    broadcast: Option<Ipv4Addr>,
    label: Option<&'a str>,
    flags: Option<u32>,
    /// IFA_CACHEINFO's (preferred, valid) lifetimes
    cacheinfo: Option<(u32, u32)>,
    rt_priority: Option<u32>,
    proto: Option<u8>,
}

fn ifa_attrs<'a>(a: &Attrs<'a>) -> Result<IfaAttrs<'a>, KernelError> {
    let cacheinfo = a.min(IFA_CACHEINFO, 16)?.map(|ci| {
        let w = |o: usize| u32::from_ne_bytes([ci[o], ci[o + 1], ci[o + 2], ci[o + 3]]);
        (w(0), w(4))
    });
    Ok(IfaAttrs {
        address: a.in_addr(IFA_ADDRESS)?,
        local: a.in_addr(IFA_LOCAL)?,
        label: a.str(IFA_LABEL, IFNAMSIZ)?,
        broadcast: a.in_addr(IFA_BROADCAST)?,
        cacheinfo,
        flags: a.u32(IFA_FLAGS)?,
        rt_priority: a.u32(IFA_RT_PRIORITY)?,
        proto: a.u8(IFA_PROTO)?,
    })
}

/// RTM_NEWADDR (Linux inet_rtm_newaddr, inet_validate_rtm)
fn newaddr(sk: &NlSock, h: &Hdr, p: &[u8], nl: NlInfo, ext: &ExtAck) -> Result<Done, KernelError> {
    let ifm = ifaddrmsg(p)?;
    let a = Attrs::parse(&p[IFADDRMSG_LEN..], IFA_MAX)?.ext(ext);
    let at = ifa_attrs(&a)?;
    if ifm.prefixlen > 32 {
        ext.msg("ipv4: Invalid prefix length");
        return Err(KernelError::InvalidArgument);
    }
    let Some(local) = at.local else {
        ext.msg("ipv4: Local address is not supplied");
        return Err(KernelError::InvalidArgument);
    };
    if let Some((prefered, valid)) = at.cacheinfo
        && (valid == 0 || prefered > valid)
    {
        ext.msg("ipv4: address lifetime invalid");
        return Err(KernelError::InvalidArgument);
    }
    if local.is_unspecified() {
        return Ok(Done::Ok);
    }
    let net = sk.net();
    let r = rtnl::lock();
    let Some(dev) = net.dev_get_by_index(ifm.index) else {
        ext.msg("ipv4: Device not found");
        return Err(KernelError::NoDevice);
    };
    let mut ifa = InIfaddr::new(local, ifm.prefixlen, dev.name());
    ifa.address = at.address.unwrap_or(local);
    ifa.set_flags(at.flags.unwrap_or(u32::from(ifm.flags)) | IFA_F_PERMANENT);
    ifa.scope = ifm.scope;
    if let Some(b) = at.broadcast {
        ifa.broadcast = b;
    }
    if let Some(l) = at.label {
        ifa.label = IfaLabel::new(l);
    }
    ifa.set_rt_priority(at.rt_priority.unwrap_or(0));
    ifa.set_proto(at.proto.unwrap_or(0));
    if ifaddr::find_matching_ifa(&dev, &ifa).is_none() {
        ifaddr::inet_insert_ifa(&r, net, &dev, ifa, nl, Some(ext))?;
    } else if h.flags & NLM_F_EXCL != 0 || h.flags & NLM_F_REPLACE == 0 {
        ext.msg("ipv4: Address already assigned");
        return Err(KernelError::AlreadyExists);
    } else {
        ifaddr::inet_replace_ifa(&r, net, &dev, &ifa, nl);
    }
    Ok(Done::Ok)
}

/// RTM_DELADDR (Linux inet_rtm_deladdr)
fn deladdr(sk: &NlSock, p: &[u8], nl: NlInfo, ext: &ExtAck) -> Result<Done, KernelError> {
    let ifm = ifaddrmsg(p)?;
    let a = Attrs::parse(&p[IFADDRMSG_LEN..], IFA_MAX)?.ext(ext);
    let at = ifa_attrs(&a)?;
    let (local, label, address) = (at.local, at.label, at.address);
    let net = sk.net();
    let r = rtnl::lock();
    let Some(dev) = net.dev_get_by_index(ifm.index) else {
        ext.msg("ipv4: Device not found");
        return Err(KernelError::NoDevice);
    };
    let victim = dev.in_dev().ifa_list.find(|x| {
        local.is_none_or(|l| l == x.local)
            && label.is_none_or(|l| l == x.label.as_str())
            && address.is_none_or(|ad| ifm.prefixlen == x.prefixlen && x.matches(ad))
    });
    let Some(ifa) = victim else {
        ext.msg("ipv4: Address not found");
        return Err(KernelError::AddressNotAvailable);
    };
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
fn fib_config(h: &Hdr, p: &[u8], nl: NlInfo, ext: &ExtAck) -> Result<FibConfig, KernelError> {
    let rtm = rtmsg(p)?;
    let a = Attrs::parse(&p[RTMSG_LEN..], RTA_MAX)?.ext(ext);
    let cfg = FibConfig {
        table: a.u32(RTA_TABLE)?.unwrap_or(u32::from(rtm.table)),
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
    };
    if rtm.rtype > fib::RTN_MAX {
        ext.msg("Invalid route type");
        return Err(KernelError::InvalidArgument);
    }
    if cfg.dst_len > 32 {
        ext.msg("Invalid prefix length");
        return Err(KernelError::InvalidArgument);
    }
    if cfg.dst.0 & !ifaddr::inet_make_mask(cfg.dst_len).0 != 0 {
        ext.msg("Invalid prefix for given prefix length");
        return Err(KernelError::InvalidArgument);
    }
    if a.has(RTA_MULTIPATH) || a.has(RTA_NH_ID) {
        return Err(KernelError::OperationNotSupported);
    }
    Ok(cfg)
}

fn newroute(sk: &NlSock, h: &Hdr, p: &[u8], nl: NlInfo, ext: &ExtAck) -> Result<Done, KernelError> {
    let cfg = fib_config(h, p, nl, ext)?;
    let r = rtnl::lock();
    fib::fib_table_insert(&r, sk.net(), &cfg)?;
    Ok(Done::Ok)
}

fn delroute(sk: &NlSock, h: &Hdr, p: &[u8], nl: NlInfo, ext: &ExtAck) -> Result<Done, KernelError> {
    let cfg = fib_config(h, p, nl, ext)?;
    let r = rtnl::lock();
    fib::fib_table_delete(&r, sk.net(), &cfg)?;
    Ok(Done::Ok)
}

/// Route dump filter (strict: table, RTM_F_CLONED = empty cache dump;
/// Linux ip_valid_fib_dump_req)
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
            a.u32(RTA_TABLE)?.unwrap_or(u32::from(rtm.table)),
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
        Err(e) => DumpKind::Bad(e, None),
    }
}

/// Largest route message (Linux fib_nlmsg_size, one nexthop, no
/// metrics)
const ROUTE_NLMSG_SIZE: usize = msg_size(RTMSG_LEN) + attr_size(4) * 6; // RTA_TABLE, _DST, _PRIORITY, _PREFSRC, _GATEWAY, _OIF

/// An RTM_NEWROUTE/DELROUTE message for a FIB entry in `nb` (Linux
/// fib_dump_info): EMSGSIZE, nothing left behind, if it does not fit
pub fn fill_route(
    nb: &mut NlBuf<'_>,
    e: &FibEntry,
    ty: u16,
    flags: u16,
    seq: u32,
    pid: u32,
) -> Result<(), KernelError> {
    let mut rflags = e.flags;
    if e.dead() {
        rflags |= RTNH_F_DEAD;
    }
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
    let m = nb.msg_put(ty, flags, seq, pid, &h)?;
    match route_attrs(nb, e) {
        Ok(()) => {
            nb.msg_end(m);
            Ok(())
        }
        Err(err) => {
            nb.msg_cancel(m);
            Err(err)
        }
    }
}

/// A route's attributes (fib_dump_info's nla_puts)
fn route_attrs(nb: &mut NlBuf<'_>, e: &FibEntry) -> Result<(), KernelError> {
    nb.put_u32(RTA_TABLE, e.table)?;
    if e.dst_len != 0 {
        nb.put(RTA_DST, &e.dst.to_be_bytes())?;
    }
    if e.priority != 0 {
        nb.put_u32(RTA_PRIORITY, e.priority)?;
    }
    if let Some(s) = e.prefsrc {
        nb.put(RTA_PREFSRC, &s.to_be_bytes())?;
    }
    if let Some(g) = e.gateway {
        nb.put(RTA_GATEWAY, &g.to_be_bytes())?;
    }
    if e.dev.is_some() {
        nb.put_u32(RTA_OIF, e.oif())?;
    }
    Ok(())
}

/// A route as one message in a buffer of its own (sized first, Linux
/// nlmsg_new(fib_nlmsg_size)); None if no memory
fn route_msg(e: &FibEntry, ty: u16, seq: u32, pid: u32) -> Option<Vec<u8>> {
    let mut v = nlmsg_new(ROUTE_NLMSG_SIZE).ok()?;
    let mut nb = NlBuf::new(&mut v, ROUTE_NLMSG_SIZE);
    fill_route(&mut nb, e, ty, 0, seq, pid).ok()?;
    Some(v)
}

/// Announce a route change to RTNLGRP_IPV4_ROUTE (Linux rtmsg_fib;
/// dropped if no memory)
pub fn notify_route(net: &NetNamespace, e: &FibEntry, ty: u16, nl: NlInfo) {
    if let Some(v) = route_msg(e, ty, nl.seq, nl.portid) {
        rtnl_notify(net, v, RTNLGRP_IPV4_ROUTE, nl);
    }
}

/// RTM_GETROUTE for one destination ("ip route get"; Linux
/// inet_rtm_getroute, output routes only)
fn getroute(sk: &NlSock, h: &Hdr, p: &[u8], ext: &ExtAck) -> Result<Done, KernelError> {
    let rtm = rtmsg(p)?;
    let a = Attrs::parse(&p[RTMSG_LEN..], RTA_MAX)?.ext(ext);
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
        let m = route_msg(&e, RTM_NEWROUTE, h.seq, sk.portid()).ok_or(KernelError::OutOfMemory)?;
        reply(sk, m);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::kmem::MAX_KMALLOC;

    fn req(len: usize) -> Vec<u8> {
        let mut m = alloc::vec![0xabu8; len];
        m[..4].copy_from_slice(&(len as u32).to_ne_bytes());
        m
    }

    fn u32_at(b: &[u8], o: usize) -> u32 {
        u32::from_ne_bytes(b[o..o + 4].try_into().unwrap())
    }

    /// An error echoes the request, padded to 4
    #[test]
    fn ack_echoes() {
        let r = req(21);
        let m = ack_msg(7, 9, &r, -22, true, &AckTlv::default()).unwrap();
        assert_eq!(m.len(), 16 + 4 + 24);
        assert_eq!(u32_at(&m, 0) as usize, m.len());
        assert_eq!(u16::from_ne_bytes([m[6], m[7]]), 0);
        assert_eq!(u32_at(&m, 8), 7);
        assert_eq!(u32_at(&m, 16) as i32, -22);
        assert_eq!(&m[20..41], &r[..]);
    }

    /// An ACK (or CAP_ACK) carries the error and the request header
    #[test]
    fn ack_capped() {
        let r = req(40);
        let m = ack_msg(1, 2, &r, 0, false, &AckTlv::default()).unwrap();
        assert_eq!(m.len(), 36);
        assert_eq!(u32_at(&m, 0), 36);
        assert_eq!(u16::from_ne_bytes([m[4], m[5]]), NLMSG_ERROR);
        assert_eq!(u16::from_ne_bytes([m[6], m[7]]), NLM_F_CAPPED);
        assert_eq!(u32_at(&m, 16), 0);
        assert_eq!(&m[20..36], &r[..16]);
    }

    /// A request whose echo would pass MAX_KMALLOC once the headers are
    /// added gets the capped form, never an oversized allocation
    #[test]
    fn ack_echo_too_big() {
        let r = req(MAX_KMALLOC - 8);
        let m = ack_msg(1, 2, &r, -22, true, &AckTlv::default()).unwrap();
        assert_eq!(m.len(), 36);
        assert_eq!(u16::from_ne_bytes([m[6], m[7]]), NLM_F_CAPPED);
        assert_eq!(u32_at(&m, 16) as i32, -22);
    }

    /// Extended ACK attributes follow the (padded) request: the message
    /// NUL-terminated, the offset as a u32, and NLM_F_ACK_TLVS is set
    #[test]
    fn ack_tlvs() {
        let r = req(21);
        let tlv = AckTlv {
            msg: Some("abc"),
            offs: Some(24),
        };
        let m = ack_msg(3, 4, &r, -34, true, &tlv).unwrap();
        assert_eq!(m.len(), 16 + 4 + 24 + 8 + 8);
        assert_eq!(u32_at(&m, 0) as usize, m.len());
        assert_eq!(u16::from_ne_bytes([m[6], m[7]]), NLM_F_ACK_TLVS);
        let a = Attrs::parse(&m[44..], 2).unwrap();
        assert_eq!(a.get(NLMSGERR_ATTR_MSG), Some(&b"abc\0"[..]));
        assert_eq!(a.u32(NLMSGERR_ATTR_OFFS).unwrap(), Some(24));
        // Capped: the request header only
        let m = ack_msg(3, 4, &r, -34, false, &tlv).unwrap();
        assert_eq!(m.len(), 36 + 16);
        assert_eq!(
            u16::from_ne_bytes([m[6], m[7]]),
            NLM_F_CAPPED | NLM_F_ACK_TLVS
        );
    }

    /// An attribute offset is reported only inside the request's
    /// payload (Linux nlmsg_check_in_payload)
    #[test]
    fn ext_offs() {
        let r = req(40);
        let ext = ExtAck::default();
        assert_eq!(ext.offs(&r), None);
        ext.bad_attr(&r[28..32]);
        assert_eq!(ext.offs(&r), Some(24));
        ext.bad_attr(&r[2..4]);
        assert_eq!(ext.offs(&r), None);
        let other = req(40);
        ext.bad_attr(&other[28..32]);
        assert_eq!(ext.offs(&r), None);
    }
}

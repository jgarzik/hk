//! Neighbour tables over NETLINK_ROUTE (Linux net/core/neighbour.c:
//! neigh_add, neigh_delete, neigh_get, neigh_dump_info,
//! __neigh_fill_info, pneigh_fill_info, __neigh_notify)
//!
//! RTM_NEWNEIGH / RTM_DELNEIGH / RTM_GETNEIGH for the ARP table and its
//! proxy entries (NTF_PROXY), the dumps' filters, and the RTNLGRP_NEIGH
//! notifications the table sends under an entry's lock (GFP_ATOMIC).

use alloc::sync::Arc;

use crate::mm::page_alloc::Gfp;
use crate::net::NetNamespace;
use crate::net::arp::arp_tbl;
use crate::net::device::NetDevice;
use crate::net::inet::fib::{NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE, RouteType};
use crate::net::neigh::{Key, NeighInfo, Neighbour, nud, upd};
use crate::net::netlink::attr::{Attrs, NlBuf, align, attr_size, msg_size, nlmsg_new};
use crate::net::netlink::{
    ExtAck, NETLINK_ROUTE, NLM_F_DUMP_FILTERED, NlSock, kernel_skb, notify as nl_notify,
};
use crate::net::pneigh::PneighEntry;
use crate::util::error::KernelError;
use crate::util::kalloc::with_gfp;

pub const RTM_NEWNEIGH: u16 = 28;
pub const RTM_DELNEIGH: u16 = 29;
/// Multicast group (Linux RTNLGRP_NEIGH)
pub const RTNLGRP_NEIGH: u32 = 3;

const AF_INET: u8 = 2;

// NDA_*
const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;
const NDA_CACHEINFO: u16 = 3;
const NDA_PROBES: u16 = 4;
const NDA_IFINDEX: u16 = 8;
const NDA_MASTER: u16 = 9;
const NDA_PROTOCOL: u16 = 12;
const NDA_FLAGS_EXT: u16 = 15;
pub const NDA_MAX: u16 = 16;

// NTF_* (ndm_flags) and NTF_EXT_* (NDA_FLAGS_EXT, above bit 8)
pub const NTF_USE: u32 = 0x01;
pub const NTF_PROXY: u32 = 0x08;
const NTF_EXT_SHIFT: u32 = 8;
const NTF_MANAGED: u32 = 1 << NTF_EXT_SHIFT;
const NTF_EXT_VALIDATED: u32 = 4 << NTF_EXT_SHIFT;

/// struct ndmsg
pub const NDMSG_LEN: usize = 12;
/// Longest hardware or protocol address (Linux MAX_ADDR_LEN)
const MAX_ADDR_LEN: usize = 32;
/// Ethernet address length (hk neighbours are on Ethernet-like links)
const ETH_ALEN: usize = 6;
/// The ARP table's key length
const KEY_LEN: usize = 4;

/// An RTM_*NEIGH message (Linux neigh_nlmsg_size: DST, LLADDR,
/// CACHEINFO, PROBES, FLAGS_EXT, PROTOCOL)
const NEIGH_NLMSG_SIZE: usize = msg_size(
    align(NDMSG_LEN)
        + 2 * attr_size(MAX_ADDR_LEN)
        + attr_size(16)
        + attr_size(4)
        + attr_size(4)
        + attr_size(1),
);

/// struct ndmsg bytes
fn ndmsg_hdr(ifindex: u32, state: u16, flags: u8) -> [u8; NDMSG_LEN] {
    let mut h = [0u8; NDMSG_LEN];
    h[0] = AF_INET;
    h[4..8].copy_from_slice(&ifindex.to_ne_bytes());
    h[8..10].copy_from_slice(&state.to_ne_bytes());
    h[10] = flags;
    h[11] = RouteType::Unicast as u8;
    h
}

/// One neighbour as a message in `nb` (Linux __neigh_fill_info):
/// EMSGSIZE, nothing left behind, if it does not fit
pub fn fill_neigh(
    nb: &mut NlBuf<'_>,
    e: &NeighInfo,
    ty: u16,
    flags: u16,
    seq: u32,
    pid: u32,
) -> Result<(), KernelError> {
    let h = ndmsg_hdr(e.ifindex, u16::from(e.state), 0);
    let m = nb.msg_put(ty, flags, seq, pid, &h)?;
    match neigh_attrs(nb, e) {
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

/// A neighbour's attributes (__neigh_fill_info's nla_puts)
fn neigh_attrs(nb: &mut NlBuf<'_>, e: &NeighInfo) -> Result<(), KernelError> {
    nb.put(NDA_DST, &e.key[..KEY_LEN])?;
    if e.state & nud::VALID != 0 {
        nb.put(NDA_LLADDR, &e.ha)?;
    }
    // struct nda_cacheinfo: ages in clock_t
    let ck = |ms: u64| (crate::time::ms_to_clock_t(ms) as u32).to_ne_bytes();
    let mut ci = [0u8; 16];
    ci[0..4].copy_from_slice(&ck(e.confirmed));
    ci[4..8].copy_from_slice(&ck(e.used));
    ci[8..12].copy_from_slice(&ck(e.updated));
    nb.put_u32(NDA_PROBES, e.probes)?;
    nb.put(NDA_CACHEINFO, &ci)?;
    if e.protocol != 0 {
        nb.put(NDA_PROTOCOL, &[e.protocol])?;
    }
    Ok(())
}

/// One proxy entry as a message in `nb` (Linux pneigh_fill_info):
/// NTF_PROXY, NUD_NONE
pub fn fill_pneigh(
    nb: &mut NlBuf<'_>,
    pn: &PneighEntry,
    ty: u16,
    flags: u16,
    seq: u32,
    pid: u32,
) -> Result<(), KernelError> {
    let f = pn.flags();
    // ndm_flags holds the low byte (Linux NTF_OLD_MASK)
    let h = ndmsg_hdr(pn.ifindex(), 0, (f & 0xff) as u8 | NTF_PROXY as u8);
    let m = nb.msg_put(ty, flags, seq, pid, &h)?;
    let r = (|| {
        nb.put(NDA_DST, &pn.key[..KEY_LEN])?;
        if pn.protocol() != 0 {
            nb.put(NDA_PROTOCOL, &[pn.protocol()])?;
        }
        let ext = f >> NTF_EXT_SHIFT;
        if ext != 0 {
            nb.put_u32(NDA_FLAGS_EXT, ext)?;
        }
        Ok(())
    })();
    match r {
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

/// Announce `e` to RTNLGRP_NEIGH (Linux __neigh_notify), with the
/// port id of the request that caused it (0: none): called under the
/// entry's lock, so the message is allocated GFP_ATOMIC; without
/// memory the group's listeners get ENOBUFS (rtnl_set_sk_err)
pub fn notify(net: &NetNamespace, e: &NeighInfo, ty: u16, pid: u32) {
    let built = with_gfp(Gfp::ATOMIC, || {
        let mut v = nlmsg_new(NEIGH_NLMSG_SIZE)?;
        fill_neigh(&mut NlBuf::new(&mut v, NEIGH_NLMSG_SIZE), e, ty, 0, 0, pid)?;
        Ok::<_, KernelError>(v)
    });
    match built {
        Ok(v) => {
            let skb = kernel_skb(v, RTNLGRP_NEIGH);
            nl_notify(net, NETLINK_ROUTE, skb, 0, false, Gfp::ATOMIC);
        }
        Err(_) => crate::net::netlink::set_err(
            net,
            NETLINK_ROUTE,
            RTNLGRP_NEIGH,
            KernelError::NoBufferSpace,
        ),
    }
}

// ============================================================================
// Requests
// ============================================================================

/// struct ndmsg fields and the request's attributes
struct NdReq<'a> {
    family: u8,
    ifindex: u32,
    state: u16,
    flags: u8,
    pad: bool,
    ty: u8,
    attrs: Attrs<'a>,
}

fn ndmsg<'a>(p: &'a [u8], ext: &'a ExtAck) -> Result<NdReq<'a>, KernelError> {
    if p.len() < NDMSG_LEN {
        return Err(KernelError::InvalidArgument);
    }
    Ok(NdReq {
        family: p[0],
        ifindex: u32::from_ne_bytes([p[4], p[5], p[6], p[7]]),
        state: u16::from_ne_bytes([p[8], p[9]]),
        flags: p[10],
        pad: p[1..4].iter().any(|&b| b != 0),
        ty: p[11],
        attrs: Attrs::parse(&p[NDMSG_LEN..], NDA_MAX)?.ext(ext),
    })
}

/// The key of NDA_DST `dst`, after the family check (Linux
/// neigh_find_table: only ARP here)
fn key_of(family: u8, dst: &[u8], ext: &ExtAck, msg: &'static str) -> Result<Key, KernelError> {
    if family != AF_INET {
        return Err(KernelError::AddressFamilyNotSupported);
    }
    if dst.len() < KEY_LEN {
        ext.msg(msg);
        return Err(KernelError::InvalidArgument);
    }
    let mut k = [0u8; 16];
    k[..KEY_LEN].copy_from_slice(&dst[..KEY_LEN]);
    Ok(k)
}

/// The device of ifindex `i` (None for 0); ENODEV if unknown
fn nd_dev(net: &NetNamespace, i: u32) -> Result<Option<Arc<NetDevice>>, KernelError> {
    match i {
        0 => Ok(None),
        i => net
            .dev_get_by_index(i)
            .map(Some)
            .ok_or(KernelError::NoDevice),
    }
}

/// RTM_NEWNEIGH (Linux neigh_add; RTNL held by the caller)
pub fn newneigh(sk: &NlSock, nlflags: u16, p: &[u8], ext: &ExtAck) -> Result<(), KernelError> {
    let r = ndmsg(p, ext)?;
    let a = &r.attrs;
    let dst = a.max(NDA_DST, MAX_ADDR_LEN)?;
    let lladdr = a.max(NDA_LLADDR, MAX_ADDR_LEN)?;
    let protocol = a.u8(NDA_PROTOCOL)?.unwrap_or(0);
    let flags_ext = a.u32(NDA_FLAGS_EXT)?;
    let Some(dst) = dst else {
        ext.msg("Network address not specified");
        return Err(KernelError::InvalidArgument);
    };
    let ndm_flags = u32::from(r.flags) | (flags_ext.unwrap_or(0) << NTF_EXT_SHIFT);
    let net = sk.net();
    let dev = nd_dev(net, r.ifindex)?;
    if dev.is_some() && lladdr.is_some_and(|l| l.len() < ETH_ALEN) {
        ext.msg("Invalid link address");
        return Err(KernelError::InvalidArgument);
    }
    let key = key_of(r.family, dst, ext, "Invalid network address")?;
    let ll = lladdr.map(|l| [l[0], l[1], l[2], l[3], l[4], l[5]]);
    let state = r.state as u8; // ndm_state is a u16 holding a u8 state
    if ndm_flags & NTF_PROXY != 0 {
        if ndm_flags & (NTF_MANAGED | NTF_EXT_VALIDATED) != 0 {
            ext.msg("Invalid NTF_* flag combination");
            return Err(KernelError::InvalidArgument);
        }
        let perm = state & nud::PERMANENT != 0;
        return arp_tbl()
            .phash
            .create(net, &key, dev.as_ref(), ndm_flags, protocol, perm);
    }
    let Some(dev) = dev else {
        ext.msg("Device not specified");
        return Err(KernelError::InvalidArgument);
    };
    let tbl = arp_tbl();
    let mut flags = upd::ADMIN | upd::OVERRIDE;
    let n = match tbl.lookup(&dev, &key) {
        None if nlflags & NLM_F_CREATE == 0 => return Err(KernelError::NotFound),
        None => tbl.create(&dev, &key, state & nud::PERMANENT != 0)?,
        Some(_) if nlflags & NLM_F_EXCL != 0 => return Err(KernelError::AlreadyExists),
        Some(n) => {
            if nlflags & NLM_F_REPLACE == 0 {
                flags &= !upd::OVERRIDE;
            }
            n
        }
    };
    if protocol != 0 {
        n.set_protocol(protocol);
    }
    if ndm_flags & NTF_USE != 0 {
        flags |= upd::USE;
    }
    let r = tbl.update(&n, ll, state, flags, sk.portid());
    if let Err(e) = r {
        ext.msg(match e {
            KernelError::InvalidArgument => "No link layer address given",
            _ => "Neighbor entry is now dead",
        });
        // A non-administrative refusal cannot happen here (ADMIN)
        return Err(e);
    }
    if ndm_flags & NTF_USE != 0 {
        tbl.event_send(&n);
    }
    Ok(())
}

/// RTM_DELNEIGH (Linux neigh_delete; RTNL held by the caller): ENOENT
/// if absent; the entry fails, then leaves the table unless someone
/// still uses it (then GC frees it later)
pub fn delneigh(sk: &NlSock, p: &[u8], ext: &ExtAck) -> Result<(), KernelError> {
    let r = ndmsg(p, ext)?;
    let Some(dst) = r.attrs.get(NDA_DST) else {
        ext.msg("Network address not specified");
        return Err(KernelError::InvalidArgument);
    };
    let net = sk.net();
    let dev = nd_dev(net, r.ifindex)?;
    let key = key_of(r.family, dst, ext, "Invalid network address")?;
    let tbl = arp_tbl();
    if u32::from(r.flags) & NTF_PROXY != 0 {
        return tbl.phash.delete(net, &key, dev.as_deref());
    }
    let dev = dev.ok_or(KernelError::InvalidArgument)?;
    let n = tbl.lookup(&dev, &key).ok_or(KernelError::NotFound)?;
    let r = tbl.update(
        &n,
        None,
        nud::FAILED,
        upd::ADMIN | upd::OVERRIDE,
        sk.portid(),
    );
    if r.is_err() {
        ext.msg("Neighbor entry is now dead");
    }
    tbl.remove_one(&n);
    r
}

/// Linux neigh_valid_get_req: a clean header, NDA_DST and nothing else
fn valid_get_req(r: &NdReq<'_>, ext: &ExtAck) -> Result<(), KernelError> {
    use KernelError::InvalidArgument as E;
    if r.pad || r.state != 0 || r.ty != 0 {
        ext.msg("Invalid values in header for neighbor get request");
        return Err(E);
    }
    if u32::from(r.flags) & !NTF_PROXY != 0 {
        ext.msg("Invalid flags in header for neighbor get request");
        return Err(E);
    }
    if u32::from(r.flags) & NTF_PROXY == 0 && r.ifindex == 0 {
        ext.msg("No device specified");
        return Err(E);
    }
    // Linux NL_SET_ERR_ATTR_MISS (no message)
    if !r.attrs.has(NDA_DST) {
        return Err(E);
    }
    if (1..=NDA_MAX).any(|t| t != NDA_DST && r.attrs.has(t)) {
        ext.msg("Unsupported attribute in neighbor get request");
        return Err(E);
    }
    Ok(())
}

/// RTM_GETNEIGH for one entry (Linux neigh_get): the reply, allocated
/// first
pub fn getneigh(
    sk: &NlSock,
    seq: u32,
    p: &[u8],
    ext: &ExtAck,
) -> Result<alloc::vec::Vec<u8>, KernelError> {
    if p.len() < NDMSG_LEN {
        ext.msg("Invalid header for neighbor get request");
        return Err(KernelError::InvalidArgument);
    }
    let r = ndmsg(p, ext)?;
    valid_get_req(&r, ext)?;
    let mut v = nlmsg_new(NEIGH_NLMSG_SIZE)?;
    if r.family != AF_INET {
        ext.msg("Unsupported family in header for neighbor get request");
        return Err(KernelError::AddressFamilyNotSupported);
    }
    let dst = r.attrs.get(NDA_DST).unwrap_or_default();
    if dst.len() != KEY_LEN {
        ext.msg("Invalid network address in neighbor get request");
        return Err(KernelError::InvalidArgument);
    }
    let key = key_of(r.family, dst, ext, "")?;
    let net = sk.net();
    let dev = nd_dev(net, r.ifindex).inspect_err(|_| ext.msg("Unknown device ifindex"))?;
    // Under RCU from the lookup to the fill (Linux neigh_get)
    let mut nb = NlBuf::new(&mut v, NEIGH_NLMSG_SIZE);
    let pid = sk.portid();
    if u32::from(r.flags) & NTF_PROXY != 0 {
        let g = crate::sync::rcu::read_lock();
        let Some(pn) = arp_tbl().phash.get(&g, net, &key, dev.as_deref()) else {
            ext.msg("Proxy neighbour entry not found");
            return Err(KernelError::NotFound);
        };
        fill_pneigh(&mut nb, pn, RTM_NEWNEIGH, 0, seq, pid)?;
    } else {
        // valid_get_req required a device
        let dev = dev.ok_or(KernelError::InvalidArgument)?;
        let Some(e) = arp_tbl().info(&dev, &key) else {
            ext.msg("Neighbour entry not found");
            return Err(KernelError::NotFound);
        };
        fill_neigh(&mut nb, &e, RTM_NEWNEIGH, 0, seq, pid)?;
    }
    Ok(v)
}

// ============================================================================
// Dumps
// ============================================================================

/// What a neighbour dump lists (Linux struct neigh_dump_filter and the
/// proxy choice)
#[derive(Clone, Copy)]
pub struct NeighFilter {
    /// Proxy entries instead of neighbours (ndm_flags == NTF_PROXY)
    pub proxy: bool,
    /// NDA_IFINDEX (0: any)
    dev_idx: u32,
    /// NDA_MASTER (0: any; u32::MAX, Linux -1: devices without a master)
    master_idx: u32,
}

impl NeighFilter {
    /// The dump's NLM_F_DUMP_FILTERED
    pub fn nlflags(&self) -> u16 {
        if self.dev_idx != 0 || self.master_idx != 0 {
            NLM_F_DUMP_FILTERED
        } else {
            0
        }
    }

    /// Linux neigh_ifindex_filtered + neigh_master_filtered: hk devices
    /// have no master
    pub fn filtered(&self, dev: Option<&NetDevice>) -> bool {
        if self.dev_idx != 0 && dev.is_none_or(|d| d.ifindex() != self.dev_idx) {
            return true;
        }
        self.master_idx != 0 && self.master_idx != u32::MAX
    }
}

/// A neighbour dump request (Linux neigh_dump_info's proxy test and
/// neigh_valid_dump_req): the filter, or the error (and message) that
/// ends it, only when strict
pub fn dump_req(p: &[u8], strict: bool, ext: &ExtAck) -> Result<NeighFilter, KernelError> {
    use KernelError::InvalidArgument as E;
    let proxy = p.len() >= NDMSG_LEN && u32::from(p[10]) == NTF_PROXY;
    let mut f = NeighFilter {
        proxy,
        dev_idx: 0,
        master_idx: 0,
    };
    if strict {
        let Ok(r) = ndmsg(p, ext) else {
            ext.msg("Invalid header for neighbor dump request");
            return Err(E);
        };
        if r.pad || r.ifindex != 0 || r.state != 0 || r.ty != 0 {
            ext.msg("Invalid values in header for neighbor dump request");
            return Err(E);
        }
        if u32::from(r.flags) & !NTF_PROXY != 0 {
            ext.msg("Invalid flags in header for neighbor dump request");
            return Err(E);
        }
    }
    let Some(a) = p
        .get(NDMSG_LEN..)
        .and_then(|b| Attrs::parse(b, NDA_MAX).ok())
    else {
        // Linux: a parse error ends only a strict dump
        return if strict { Err(E) } else { Ok(f) };
    };
    for t in 1..=NDA_MAX {
        match t {
            _ if !a.has(t) => {}
            NDA_IFINDEX => f.dev_idx = a.u32(t).unwrap_or(None).unwrap_or(0),
            NDA_MASTER => f.master_idx = a.u32(t).unwrap_or(None).unwrap_or(0),
            _ if strict => {
                ext.msg("Unsupported attribute in neighbor dump request");
                return Err(E);
            }
            _ => {}
        }
    }
    Ok(f)
}

/// `net`'s neighbours a dump with `f` lists, under `g` (Linux
/// neigh_dump_table)
pub fn dump_neighs<'a>(
    g: &'a crate::sync::rcu::RcuReadGuard,
    net: &'a NetNamespace,
    f: NeighFilter,
) -> impl Iterator<Item = &'a Neighbour> + 'a {
    arp_tbl()
        .iter_rcu(g)
        .filter(move |n| n.dev.net_is(net) && !f.filtered(Some(&n.dev)))
}

/// `net`'s proxy entries a dump with `f` lists, under `g` (Linux
/// pneigh_dump_table)
pub fn dump_pneighs<'a>(
    g: &'a crate::sync::rcu::RcuReadGuard,
    net: &'a NetNamespace,
    f: NeighFilter,
) -> impl Iterator<Item = &'a PneighEntry> + 'a {
    arp_tbl()
        .phash
        .iter(g, net)
        .filter(move |n| !f.filtered(n.dev.as_deref()))
}

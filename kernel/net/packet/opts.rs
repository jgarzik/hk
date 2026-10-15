//! AF_PACKET socket options (Linux packet_setsockopt/getsockopt,
//! packet_mc_add/drop) and the SO_ATTACH_FILTER family
//! (net/core/sock.c, net/core/filter.c sk_attach_filter)

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::rcv::{PACKET_AUXDATA, SOL_PACKET};
use super::{PacketSock, pf};
use crate::error::KernelError;
use crate::net::filter::{BPF_MAXINSNS, Filter, Insn};
use crate::net::rtnl;
use crate::net::socket::{OptIn, OptOut, SOL_SOCKET};

const PACKET_ADD_MEMBERSHIP: i32 = 1;
const PACKET_DROP_MEMBERSHIP: i32 = 2;
const PACKET_STATISTICS: i32 = 6;
const PACKET_ORIGDEV: i32 = 9;
const PACKET_IGNORE_OUTGOING: i32 = 23;

/// packet_mreq.mr_type
const PACKET_MR_PROMISC: u16 = 1;
const PACKET_MR_ALLMULTI: u16 = 2;

/// SOL_SOCKET filter options
const SO_ATTACH_FILTER: i32 = 26;
const SO_DETACH_FILTER: i32 = 27;
const SO_LOCK_FILTER: i32 = 44;

/// sizeof(struct packet_mreq) and of its 32-byte-address variant
const MREQ_LEN: usize = 16;
const MREQ_MAX: usize = 40;
/// sizeof(struct sock_fprog) (64-bit)
const FPROG_LEN: usize = 16;

/// A membership (struct packet_mreq + use count)
#[derive(Clone, Debug)]
pub struct Mreq {
    ifindex: i32,
    ty: u16,
    alen: u16,
    addr: [u8; 32],
    count: u32,
}

impl Mreq {
    fn same(&self, o: &Mreq) -> bool {
        self.ifindex == o.ifindex
            && self.ty == o.ty
            && self.alen == o.alen
            && self.addr[..self.alen as usize] == o.addr[..o.alen as usize]
    }
}

/// setsockopt: SOL_PACKET options and the SOL_SOCKET filter options;
/// None for the generic SOL_SOCKET code
pub fn set(s: &PacketSock, level: i32, opt: i32, v: OptIn) -> Option<Result<(), KernelError>> {
    match level {
        SOL_SOCKET => match opt {
            SO_ATTACH_FILTER | SO_DETACH_FILTER | SO_LOCK_FILTER => Some(set_filter(s, opt, v)),
            _ => None,
        },
        SOL_PACKET => Some(set_packet(s, opt, v)),
        _ => Some(Err(KernelError::NoProtocolOption)),
    }
}

fn set_packet(s: &PacketSock, opt: i32, v: OptIn) -> Result<(), KernelError> {
    match opt {
        PACKET_ADD_MEMBERSHIP | PACKET_DROP_MEMBERSHIP => {
            let m = read_mreq(v)?;
            if opt == PACKET_ADD_MEMBERSHIP {
                mc_add(s, m)
            } else {
                mc_drop(s, &m)
            }
        }
        // Linux: at least an int, any value
        PACKET_AUXDATA | PACKET_ORIGDEV => {
            let f = if opt == PACKET_AUXDATA {
                pf::AUXDATA
            } else {
                pf::ORIGDEV
            };
            s.set_flag(f, v.int()? != 0);
            Ok(())
        }
        PACKET_IGNORE_OUTGOING => {
            if v.len != 4 {
                return Err(KernelError::InvalidArgument);
            }
            let val = v.int()?;
            if !(0..=1).contains(&val) {
                return Err(KernelError::InvalidArgument);
            }
            s.set_flag(pf::IGNORE_OUTGOING, val == 1);
            Ok(())
        }
        // Rings, fanout, versions, vnet headers: not supported
        _ => Err(KernelError::NoProtocolOption),
    }
}

/// struct packet_mreq (Linux: at least 16 bytes, mr_alen within)
fn read_mreq(v: OptIn) -> Result<Mreq, KernelError> {
    if v.len < MREQ_LEN {
        return Err(KernelError::InvalidArgument);
    }
    let b = v.bytes(MREQ_MAX)?;
    let alen = u16::from_ne_bytes([b[6], b[7]]);
    if b.len() < alen as usize + 8 {
        return Err(KernelError::InvalidArgument);
    }
    let mut addr = [0u8; 32];
    let n = (b.len() - 8).min(32);
    addr[..n].copy_from_slice(&b[8..8 + n]);
    Ok(Mreq {
        ifindex: i32::from_ne_bytes([b[0], b[1], b[2], b[3]]),
        ty: u16::from_ne_bytes([b[4], b[5]]),
        alen,
        addr,
        count: 1,
    })
}

/// Linux packet_mc_add: ENODEV for an unknown device, EINVAL for an
/// address longer than the device's; duplicates are counted
fn mc_add(s: &PacketSock, m: Mreq) -> Result<(), KernelError> {
    let r = rtnl::lock();
    let dev = s.dev(m.ifindex).ok_or(KernelError::NoDevice)?;
    if m.alen as usize > crate::net::ethernet::ETH_ALEN {
        return Err(KernelError::InvalidArgument);
    }
    let ty = m.ty;
    {
        let mut l = s.mclist.lock();
        if let Some(e) = l.iter_mut().find(|e| e.same(&m)) {
            e.count += 1;
            return Ok(());
        }
        l.push(m);
    }
    // RTNL serializes membership changes: no list lock over the driver
    dev_mc(&r, &dev, ty, 1);
    Ok(())
}

/// Linux packet_mc_drop: dropping a membership we do not have is not
/// an error
fn mc_drop(s: &PacketSock, m: &Mreq) -> Result<(), KernelError> {
    let r = rtnl::lock();
    let gone = {
        let mut l = s.mclist.lock();
        let Some(i) = l.iter().position(|e| e.same(m)) else {
            return Ok(());
        };
        l[i].count -= 1;
        (l[i].count == 0).then(|| l.remove(i))
    };
    if let Some(e) = gone
        && let Some(dev) = s.dev(e.ifindex)
    {
        dev_mc(&r, &dev, e.ty, -1);
    }
    Ok(())
}

/// Drop all memberships (close; Linux packet_flush_mclist)
pub fn flush_mclist(s: &PacketSock) {
    let r = rtnl::lock();
    let l: Vec<Mreq> = core::mem::take(&mut *s.mclist.lock());
    for e in l {
        if let Some(dev) = s.dev(e.ifindex) {
            dev_mc(&r, &dev, e.ty, -1);
        }
    }
}

/// Apply a membership to the device (Linux packet_dev_mc; multicast
/// and unicast address lists are not filtered by the drivers, so only
/// promiscuity and allmulti counts change)
fn dev_mc(r: &rtnl::RtnlGuard, dev: &crate::net::NetDevice, ty: u16, inc: i32) {
    match ty {
        PACKET_MR_PROMISC => dev.set_promiscuity(r, inc),
        PACKET_MR_ALLMULTI => dev.set_allmulti(r, inc),
        _ => {}
    }
}

/// SO_ATTACH_FILTER / SO_DETACH_FILTER / SO_LOCK_FILTER (Linux
/// sk_setsockopt: an int-sized option first, then the specific rules)
fn set_filter(s: &PacketSock, opt: i32, v: OptIn) -> Result<(), KernelError> {
    let val = v.int()?;
    let locked = s.flag(pf::FILTER_LOCKED);
    match opt {
        SO_ATTACH_FILTER => {
            let f = read_fprog(v, locked)?;
            *s.filter.write() = Some(Arc::new(f));
        }
        SO_DETACH_FILTER => {
            if locked {
                return Err(KernelError::NotPermitted);
            }
            s.filter.write().take().ok_or(KernelError::NotFound)?;
        }
        _ => {
            if val == 0 && locked {
                return Err(KernelError::NotPermitted);
            }
            s.set_flag(pf::FILTER_LOCKED, val != 0);
        }
    }
    Ok(())
}

/// struct sock_fprog { u16 len; struct sock_filter *filter; } (Linux
/// copy_bpf_fprog_from_user + __get_filter)
fn read_fprog(v: OptIn, locked: bool) -> Result<Filter, KernelError> {
    if v.len != FPROG_LEN {
        return Err(KernelError::InvalidArgument);
    }
    let b = v.bytes(FPROG_LEN)?;
    if locked {
        return Err(KernelError::NotPermitted);
    }
    let n = u16::from_ne_bytes([b[0], b[1]]) as usize;
    let ptr = u64::from_ne_bytes(b[8..16].try_into().unwrap());
    if ptr == 0 || n == 0 || n > BPF_MAXINSNS {
        return Err(KernelError::InvalidArgument);
    }
    let raw = OptIn { ptr, len: n * 8 }.bytes(n * 8)?;
    let insns = raw
        .as_chunks::<8>()
        .0
        .iter()
        .map(Insn::from_bytes)
        .collect();
    Filter::new(insns)
}

/// getsockopt: SOL_PACKET options and SO_LOCK_FILTER
pub fn get(s: &PacketSock, level: i32, opt: i32) -> Option<Result<OptOut, KernelError>> {
    match (level, opt) {
        (SOL_SOCKET, SO_LOCK_FILTER) => Some(Ok(OptOut::Int(s.flag(pf::FILTER_LOCKED) as i32))),
        (SOL_SOCKET, _) => None,
        (SOL_PACKET, _) => Some(get_packet(s, opt)),
        _ => Some(Err(KernelError::NoProtocolOption)),
    }
}

fn get_packet(s: &PacketSock, opt: i32) -> Result<OptOut, KernelError> {
    let flag = |f| Ok(OptOut::Int(s.flag(f) as i32));
    match opt {
        PACKET_AUXDATA => flag(pf::AUXDATA),
        PACKET_ORIGDEV => flag(pf::ORIGDEV),
        PACKET_IGNORE_OUTGOING => flag(pf::IGNORE_OUTGOING),
        // struct tpacket_stats, read and reset; packets include drops
        PACKET_STATISTICS => {
            let drops = s.drops.swap(0, Ordering::AcqRel);
            let packets = s.packets.swap(0, Ordering::AcqRel) + drops;
            let mut b = Vec::with_capacity(8);
            b.extend_from_slice(&packets.to_ne_bytes());
            b.extend_from_slice(&drops.to_ne_bytes());
            Ok(OptOut::Bytes(b))
        }
        _ => Err(KernelError::NoProtocolOption),
    }
}

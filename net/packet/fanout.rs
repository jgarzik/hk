//! AF_PACKET fanout groups (Linux af_packet.c fanout_add,
//! fanout_release, packet_rcv_fanout, fanout_demux_*)
//!
//! Sockets bound alike (protocol and device) join a group by id;
//! the group takes their frames instead of them and hands each frame
//! to one member, chosen by flow hash, round robin, CPU, random,
//! queue (always 0 here: one receive queue), rollover or a classic BPF
//! program. With PACKET_FANOUT_FLAG_ROLLOVER a member short of room
//! passes the frame on to the next with room (PACKET_ROLLOVER_STATS).
//!
//! Locking: `FANOUT` (sleeping, Linux fanout_mutex) serializes joins,
//! leaves and the id allocator (global, as Linux's fanout_next_id; the
//! groups list is per namespace, which Linux's global fanout_list
//! filters by). A group's running members (`arr`, Linux arr and
//! num_members under f->lock) change under the member's `bind_lock`
//! (hook registration): `FANOUT` -> `bind_lock` -> `arr`. The tap reads
//! the namespace's list and a group's members under their spin read
//! locks, choosing a member there (rollover reads members' room: `arr`
//! -> `rx`), and delivers after dropping them.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::net::dev::Tap;
use crate::net::ethernet::PktType;
use crate::net::filter::{Ctx, Filter};
use crate::net::socket::{OptIn, OptOut};
use crate::sync::spin::RwLock;
use crate::util::error::KernelError;
use crate::util::kalloc::try_arc;
use crate::util::kmem::KVec;

use super::ring::Room;
use super::{ETH_P_ALL, PacketSock, pf};

pub const PACKET_FANOUT_HASH: u8 = 0;
pub const PACKET_FANOUT_LB: u8 = 1;
pub const PACKET_FANOUT_CPU: u8 = 2;
pub const PACKET_FANOUT_ROLLOVER: u8 = 3;
pub const PACKET_FANOUT_RND: u8 = 4;
pub const PACKET_FANOUT_QM: u8 = 5;
pub const PACKET_FANOUT_CBPF: u8 = 6;
pub const PACKET_FANOUT_EBPF: u8 = 7;
const FLAG_ROLLOVER: u16 = 0x1000;
const FLAG_UNIQUEID: u16 = 0x2000;
const FLAG_IGNORE_OUTGOING: u16 = 0x4000;
/// Linux PACKET_FANOUT_MAX
const PACKET_FANOUT_MAX: u32 = 1 << 16;
/// Members when the caller gives no max_num_members (legacy)
const FANOUT_DEFAULT_MAX: u32 = 256;
/// Linux ROLLOVER_HLEN (L1_CACHE_BYTES / sizeof(u32))
const ROLLOVER_HLEN: usize = 16;

/// Joins, leaves and the next free id (Linux fanout_mutex,
/// fanout_next_id)
static FANOUT: crate::sync::Mutex<u16> = crate::sync::Mutex::new(0);

/// A fanout group (Linux struct packet_fanout)
pub struct Fanout {
    pub id: u16,
    pub ty: u8,
    /// Flags (type_flags >> 8)
    pub flags: u8,
    max_num_members: u32,
    /// The hook's protocol and device (the first member's binding;
    /// device 0: all)
    proto: u16,
    ifindex: i32,
    ignore_outgoing: bool,
    rr_cur: AtomicU32,
    bpf: RwLock<Option<Arc<Filter>>>,
    /// Running members (Linux arr[num_members])
    arr: RwLock<Vec<Arc<PacketSock>>>,
    /// Members, running or not (Linux sk_ref; under `FANOUT`)
    sk_ref: AtomicU32,
}

/// A rolling member's statistics and flow history (Linux struct
/// packet_rollover)
#[derive(Default)]
pub struct Rollover {
    sock: AtomicU32,
    num: AtomicU64,
    num_huge: AtomicU64,
    num_failed: AtomicU64,
    history: [AtomicU32; ROLLOVER_HLEN],
}

impl Fanout {
    fn has_flag(&self, f: u16) -> bool {
        self.flags & (f >> 8) as u8 != 0
    }

    /// The group takes this frame (Linux: its prot_hook's type and dev,
    /// ignore_outgoing, and match_fanout_group skipping a member's own
    /// outgoing frames)
    fn wants(&self, t: &Tap<'_>, proto: u16) -> bool {
        if self.ifindex > 0 && self.ifindex as u32 != t.dev.ifindex() {
            return false;
        }
        if t.pkt_type != PktType::Outgoing {
            return self.proto == ETH_P_ALL || self.proto == proto;
        }
        self.proto == ETH_P_ALL
            && !self.ignore_outgoing
            && !self.arr.read().iter().any(|m| m.id() == t.owner)
    }
}

/// Member `m` has room (Linux packet_rcv_has_room: the receive buffer
/// or ring), noting pressure
fn has_room(m: &PacketSock, truesize: usize) -> Room {
    let r = if m.flag(pf::TPACKET) {
        m.ring_room()
    } else {
        let rcvbuf = i64::from(m.sk.rcvbuf());
        let avail = rcvbuf - m.rxq.rmem() as i64 - truesize as i64;
        if avail > rcvbuf >> 2 {
            Room::Normal
        } else if avail > 0 {
            Room::Low
        } else {
            Room::None
        }
    };
    m.set_flag(pf::PRESSURE, r != Room::Normal);
    r
}

/// Linux fanout_flow_is_huge: the flow fills more than half of the
/// member's recent history
fn flow_is_huge(r: &Rollover, hash: u32) -> bool {
    let count = r
        .history
        .iter()
        .filter(|h| h.load(Ordering::Relaxed) == hash)
        .count();
    let victim = (crate::random::get_random_u32() as usize) % ROLLOVER_HLEN;
    if r.history[victim].load(Ordering::Relaxed) != hash {
        r.history[victim].store(hash, Ordering::Relaxed);
    }
    count > ROLLOVER_HLEN >> 1
}

/// Linux fanout_demux_rollover: `idx` if it has room (`try_self`),
/// else the next member with room, else `idx`
fn demux_rollover(
    arr: &[Arc<PacketSock>],
    idx: usize,
    try_self: bool,
    truesize: usize,
    hash: u32,
) -> usize {
    let num = arr.len();
    let po = &arr[idx];
    let Some(ro) = po.rollover.lock().clone() else {
        return idx;
    };
    let mut room = Room::None;
    let mut skip = None;
    if try_self {
        room = has_room(po, truesize);
        if room == Room::Normal || (room == Room::Low && !flow_is_huge(&ro, hash)) {
            return idx;
        }
        skip = Some(idx);
    }
    let j = (ro.sock.load(Ordering::Relaxed) as usize).min(num - 1);
    let mut i = j;
    loop {
        let next = &arr[i];
        if Some(i) != skip && !next.flag(pf::PRESSURE) && has_room(next, truesize) == Room::Normal {
            if i != j {
                ro.sock.store(i as u32, Ordering::Relaxed);
            }
            ro.num.fetch_add(1, Ordering::Relaxed);
            if room == Room::Low {
                ro.num_huge.fetch_add(1, Ordering::Relaxed);
            }
            return i;
        }
        i += 1;
        if i == num {
            i = 0;
        }
        if i == j {
            break;
        }
    }
    ro.num_failed.fetch_add(1, Ordering::Relaxed);
    idx
}

/// Linux packet_rcv_fanout: the member that takes the frame
fn pick(f: &Fanout, t: &Tap<'_>, proto: u16) -> Option<Arc<PacketSock>> {
    let arr = f.arr.read();
    let num = arr.len();
    if num == 0 {
        return None;
    }
    let truesize = t.frame.len() + crate::net::skb::NET_SKB_PAD;
    let hash = super::rcv::flow_hash(t.frame, false);
    let mut idx = match f.ty {
        PACKET_FANOUT_LB => {
            (f.rr_cur.fetch_add(1, Ordering::Relaxed).wrapping_add(1) as usize) % num
        }
        PACKET_FANOUT_CPU => crate::cpu::this_id() as usize % num,
        PACKET_FANOUT_RND => crate::random::get_random_u32() as usize % num,
        // One receive queue: skb_get_queue_mapping is 0
        PACKET_FANOUT_QM => 0,
        PACKET_FANOUT_ROLLOVER => demux_rollover(&arr, 0, false, truesize, hash),
        PACKET_FANOUT_CBPF | PACKET_FANOUT_EBPF => {
            let prog = f.bpf.read().clone();
            prog.map_or(0, |p| p.run(&ctx(t, proto)) as usize % num)
        }
        // PACKET_FANOUT_HASH: reciprocal_scale of the symmetric hash
        _ => {
            let h = super::rcv::flow_hash(t.frame, true);
            ((u64::from(h) * num as u64) >> 32) as usize
        }
    };
    if f.has_flag(FLAG_ROLLOVER) {
        idx = demux_rollover(&arr, idx, true, truesize, hash);
    }
    Some(arr[idx].clone())
}

/// The classic BPF context of a frame: from the network header as
/// received, from the link header as sent (Linux: the skb as the hook
/// gets it)
fn ctx<'a>(t: &'a Tap<'_>, proto: u16) -> Ctx<'a> {
    let data = if t.pkt_type == PktType::Outgoing {
        t.frame
    } else {
        &t.frame[crate::net::ethernet::ETH_HLEN..]
    };
    Ctx {
        data,
        frame: t.frame,
        net_off: crate::net::ethernet::ETH_HLEN,
        protocol: proto,
        pkt_type: t.pkt_type.num(),
        ifindex: t.dev.ifindex(),
        hatype: t.dev.link().dev_type,
        mark: 0,
    }
}

/// Deliver a tapped frame to the namespace's groups that take it
pub fn deliver(net: &crate::net::NetNamespace, t: &Tap<'_>, proto: u16) {
    let mut i = 0;
    loop {
        let Some(f) = net.packet.fanouts.read().get(i).cloned() else {
            return;
        };
        i += 1;
        if f.wants(t, proto)
            && let Some(m) = pick(&f, t, proto)
        {
            m.rcv(t, proto);
        }
    }
}

impl PacketSock {
    /// Into its group's running members (Linux __fanout_link),
    /// `bind_lock` held
    pub(super) fn fanout_link(&self, f: &Fanout) {
        if let Some(me) = self.me.get().and_then(alloc::sync::Weak::upgrade) {
            let mut arr = f.arr.write();
            // Room for every member (`add`): no allocation here
            debug_assert!(arr.len() < arr.capacity());
            if arr.len() < arr.capacity() {
                arr.push(me);
            }
        }
    }

    /// Out of them (Linux __fanout_unlink), `bind_lock` held
    pub(super) fn fanout_unlink(&self, f: &Fanout) {
        let mut arr = f.arr.write();
        if let Some(i) = arr.iter().position(|m| m.id() == self.id()) {
            arr.swap_remove(i);
        }
    }
}

/// Linux fanout_add: join group `id` (or a new unique one), the socket
/// bound with a protocol and like the group
pub fn add(s: &PacketSock, id: u16, type_flags: u16, max: u32) -> Result<(), KernelError> {
    let ty = (type_flags & 0xff) as u8;
    let mut flags = (type_flags >> 8) as u8;
    match ty {
        PACKET_FANOUT_ROLLOVER if type_flags & FLAG_ROLLOVER != 0 => {
            return Err(KernelError::InvalidArgument);
        }
        PACKET_FANOUT_HASH..=PACKET_FANOUT_EBPF => {}
        _ => return Err(KernelError::InvalidArgument),
    }
    let net = &s.sk.net;
    let mut next_id = FANOUT.lock();
    if s.fanout.lock().is_some() {
        return Err(KernelError::AlreadyInProgress);
    }
    let rollover = if ty == PACKET_FANOUT_ROLLOVER || type_flags & FLAG_ROLLOVER != 0 {
        Some(try_arc(Rollover::default())?)
    } else {
        None
    };
    let mut id = id;
    if type_flags & FLAG_UNIQUEID != 0 {
        if id != 0 {
            return Err(KernelError::InvalidArgument);
        }
        id = find_new_id(net, &mut next_id).ok_or(KernelError::OutOfMemory)?;
        // Ephemeral flag for the first socket in the group
        flags &= !((FLAG_UNIQUEID >> 8) as u8);
    }
    let found = net
        .packet
        .fanouts
        .read()
        .iter()
        .find(|f| f.id == id)
        .cloned();
    let (num, ifindex) = s.bound();
    let f = match found {
        Some(f) => {
            if f.flags != flags || (max != 0 && max != f.max_num_members) {
                return Err(KernelError::InvalidArgument);
            }
            f
        }
        None => {
            if max > PACKET_FANOUT_MAX {
                return Err(KernelError::InvalidArgument);
            }
            let max = if max == 0 { FANOUT_DEFAULT_MAX } else { max };
            // The member array whole, before any spin lock (Linux
            // kvzalloc_flex of arr[max_num_members]): linking a member
            // under bind_lock never allocates
            let arr = KVec::try_with_capacity(max as usize)?.into_vec();
            let f = try_arc(Fanout {
                id,
                ty,
                flags,
                max_num_members: max,
                proto: num,
                ifindex: ifindex.max(0),
                ignore_outgoing: type_flags & FLAG_IGNORE_OUTGOING != 0,
                rr_cur: AtomicU32::new(0),
                bpf: RwLock::new(None),
                arr: RwLock::new(arr),
                sk_ref: AtomicU32::new(0),
            })?;
            list_add(net, f.clone())?;
            f
        }
    };
    let r = {
        let g = s.bind_lock.lock();
        let (num, ifindex) = s.bound();
        if num != 0 && f.ty == ty && f.proto == num && f.ifindex == ifindex.max(0) {
            let refs = f.sk_ref.load(Ordering::Relaxed);
            if refs < f.max_num_members {
                *s.fanout.lock() = Some(f.clone());
                *s.rollover.lock() = rollover;
                f.sk_ref.store(refs + 1, Ordering::Relaxed);
                if s.flag(pf::RUNNING) {
                    // Its own hook replaced by the group's
                    s.fanout_link(&f);
                }
                drop(g);
                Ok(())
            } else {
                Err(KernelError::NoSpace)
            }
        } else {
            Err(KernelError::InvalidArgument)
        }
    };
    if r.is_err() && f.sk_ref.load(Ordering::Relaxed) == 0 {
        net.packet.fanouts.write().retain(|g| !Arc::ptr_eq(g, &f));
    }
    r
}

/// Add a group to the namespace's list (Linux list_add to
/// fanout_list), `FANOUT` held: a full list is grown into a vector
/// allocated before the spin lock, the old one freed after it
fn list_add(net: &crate::net::NetNamespace, f: Arc<Fanout>) -> Result<(), KernelError> {
    let (len, cap) = {
        let l = net.packet.fanouts.read();
        (l.len(), l.capacity())
    };
    let mut grown = None;
    if len == cap {
        // `FANOUT` keeps other writers out until the swap
        grown = Some(KVec::try_with_capacity(cap * 2 + 4)?.into_vec());
    }
    let old = {
        let mut l = net.packet.fanouts.write();
        let old = grown.map(|mut g| {
            g.append(&mut l);
            core::mem::replace(&mut *l, g)
        });
        debug_assert!(l.len() < l.capacity());
        l.push(f);
        old
    };
    drop(old);
    Ok(())
}

/// Linux __fanout_id_is_free / fanout_find_new_id
fn find_new_id(net: &crate::net::NetNamespace, next: &mut u16) -> Option<u16> {
    let l = net.packet.fanouts.read();
    let start = *next;
    let mut id = start;
    loop {
        if !l.iter().any(|f| f.id == id) {
            *next = id.wrapping_add(1);
            return Some(id);
        }
        id = id.wrapping_add(1);
        if id == start {
            return None;
        }
    }
}

/// Linux fanout_release: leave the group (already unhooked), which goes
/// with its last member
pub fn release(s: &PacketSock) {
    let _m = FANOUT.lock();
    let Some(f) = s.fanout.lock().take() else {
        return;
    };
    if f.sk_ref.fetch_sub(1, Ordering::Relaxed) == 1 {
        s.sk.net
            .packet
            .fanouts
            .write()
            .retain(|g| !Arc::ptr_eq(g, &f));
        f.bpf.write().take();
    }
    s.rollover.lock().take();
}

/// PACKET_FANOUT: an int (id, type and flags) or a struct fanout_args
/// (with max_num_members)
pub fn set(s: &PacketSock, v: OptIn) -> Result<(), KernelError> {
    if v.len != 4 && v.len != 8 {
        return Err(KernelError::InvalidArgument);
    }
    let b = v.bytes(8)?;
    let id = u16::from_ne_bytes([b[0], b[1]]);
    let type_flags = u16::from_ne_bytes([b[2], b[3]]);
    let max = if v.len == 8 {
        u32::from_ne_bytes([b[4], b[5], b[6], b[7]])
    } else {
        0
    };
    add(s, id, type_flags, max)
}

/// PACKET_FANOUT_DATA (Linux fanout_set_data): a classic program for a
/// CBPF group (EPERM with a locked filter), an eBPF program fd for an
/// EBPF group (hk has no bpf(2): EBADF for a closed fd, else EINVAL, as
/// a descriptor that is no BPF program)
pub fn set_data(s: &PacketSock, v: OptIn) -> Result<(), KernelError> {
    let f = s
        .fanout
        .lock()
        .clone()
        .ok_or(KernelError::InvalidArgument)?;
    match f.ty {
        PACKET_FANOUT_CBPF => {
            let locked = s.flag(pf::FILTER_LOCKED);
            if locked {
                return Err(KernelError::NotPermitted);
            }
            let prog = super::opts::read_fprog(v, locked)?;
            *f.bpf.write() = Some(try_arc(prog)?);
            Ok(())
        }
        PACKET_FANOUT_EBPF => {
            if s.flag(pf::FILTER_LOCKED) {
                return Err(KernelError::NotPermitted);
            }
            if v.len != 4 {
                return Err(KernelError::InvalidArgument);
            }
            let fd = v.int()?;
            crate::fs::io::fget(fd).map_err(|_| KernelError::BadFd)?;
            Err(KernelError::InvalidArgument)
        }
        _ => Err(KernelError::InvalidArgument),
    }
}

/// getsockopt PACKET_FANOUT: id | type << 16 | flags << 24, 0 alone
pub fn get(s: &PacketSock) -> OptOut {
    let v = s.fanout.lock().as_ref().map_or(0, |f| {
        u32::from(f.id) | (u32::from(f.ty) << 16) | (u32::from(f.flags) << 24)
    });
    OptOut::Int(v as i32)
}

/// getsockopt PACKET_ROLLOVER_STATS: struct tpacket_rollover_stats,
/// EINVAL without rollover
pub fn rollover_stats(s: &PacketSock) -> Result<OptOut, KernelError> {
    let r = s
        .rollover
        .lock()
        .clone()
        .ok_or(KernelError::InvalidArgument)?;
    let mut b = Vec::with_capacity(24);
    for c in [&r.num, &r.num_huge, &r.num_failed] {
        b.extend_from_slice(&c.load(Ordering::Relaxed).to_ne_bytes());
    }
    Ok(OptOut::Bytes(b))
}

/// Linux __packet_rcv_try_clear_pressure (poll, recvmsg)
pub fn try_clear_pressure(s: &PacketSock) {
    if s.flag(pf::PRESSURE) && has_room(s, 0) == Room::Normal {
        s.set_flag(pf::PRESSURE, false);
    }
}

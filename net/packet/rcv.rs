//! AF_PACKET receive side: the per-namespace socket list, the device
//! tap (Linux packet_rcv via ptype_all/ptype_base), the bounded receive
//! queue and recvmsg delivery (Linux packet_recvmsg)

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::mm::page_alloc::Gfp;
use crate::net::skb::{SkBuff, SkbCb, SkbQueue};
use crate::util::kalloc::try_arc_gfp;
use crate::util::rculist::RcuList;

use super::{ETH_P_802_2, ETH_P_802_3, ETH_P_ALL, PacketSock, SLL_LEN, Sll, pf};
use crate::io::poll::{POLLERR, POLLIN, POLLOUT, POLLRDNORM, POLLWRBAND, POLLWRNORM};
use crate::net::dev::Tap;
use crate::net::ethernet::{ETH_HLEN, PktType};
use crate::net::filter::Ctx;
use crate::net::msg::{MSG_DONTWAIT, MSG_PEEK, MSG_TRUNC, RecvMsg};
use crate::net::sock::Sock;
use crate::net::socket::SOCK_RAW;
use crate::util::error::KernelError;

/// Socket level of packet options and control messages
pub const SOL_PACKET: i32 = 263;
/// PACKET_AUXDATA (option and control message type)
pub const PACKET_AUXDATA: i32 = 8;
use super::ring::{TP_STATUS_CSUM_VALID, TP_STATUS_USER};

/// A frame's flow hash (Linux skb_get_hash; with `symmetric` the two
/// directions of a flow hash alike, __skb_get_hash_symmetric): IPv4
/// addresses, protocol and, unless a fragment, TCP/UDP/SCTP ports;
/// other frames by EtherType. Keyed by a boot-time random seed, as
/// Linux's hashrnd (Linux uses siphash over flow_keys)
pub(super) fn flow_hash(frame: &[u8], symmetric: bool) -> u32 {
    static SEED: spin::Once<u32> = spin::Once::new();
    let seed = *SEED.call_once(crate::random::get_random_u32);
    let ty = eth_proto(frame);
    let ip = frame.get(ETH_HLEN..).unwrap_or(&[]);
    if ty != 0x0800 || ip.len() < 20 || ip[0] >> 4 != 4 {
        return crate::util::jhash::jhash_1word(u32::from(ty), seed);
    }
    let mut src = u32::from_be_bytes([ip[12], ip[13], ip[14], ip[15]]);
    let mut dst = u32::from_be_bytes([ip[16], ip[17], ip[18], ip[19]]);
    let proto = ip[9];
    let frag = u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff != 0;
    let ihl = usize::from(ip[0] & 0xf) * 4;
    let (mut sp, mut dp) = match (proto, ip.get(ihl..ihl + 4)) {
        (6 | 17 | 132, Some(p)) if !frag => (
            u16::from_be_bytes([p[0], p[1]]),
            u16::from_be_bytes([p[2], p[3]]),
        ),
        _ => (0, 0),
    };
    if symmetric && (dst < src || (dst == src && dp < sp)) {
        core::mem::swap(&mut src, &mut dst);
        core::mem::swap(&mut sp, &mut dp);
    }
    let ports = (u32::from(sp) << 16) | u32::from(dp);
    crate::util::jhash::jhash_3words(src, dst, ports ^ u32::from(proto), seed)
}

/// Packet sockets in all namespaces (fast path: no socket, no work)
static NSOCKS: AtomicUsize = AtomicUsize::new(0);

/// What a frame queued to a packet socket keeps beside its data (Linux
/// PACKET_SKB_CB: the sockaddr_ll and the original length)
#[derive(Clone, Copy, Default)]
pub struct PktCb {
    /// Length before the filter's snap (tpacket_auxdata.tp_len)
    origlen: usize,
    sll: Sll,
    /// Offset of the network header in the data
    net_off: u16,
    /// tp_status checksum bits (`csum_status`)
    csum: u32,
}

impl PktCb {
    /// A whole copy queued beside a ring frame too small for it (Linux
    /// tpacket_rcv's copy_skb: its PACKET_SKB_CB zeroed, so recvmsg
    /// reports no device, no address and origlen 0)
    pub(super) fn copy(proto: u16, net_off: usize) -> Self {
        Self {
            sll: Sll {
                protocol: proto,
                ..Sll::default()
            },
            net_off: net_off as u16,
            ..Self::default()
        }
    }
}

/// tp_status checksum bits of a tapped frame (Linux tpacket_rcv and
/// packet_recvmsg from skb->ip_summed)
pub(super) fn csum_status(t: &Tap<'_>) -> u32 {
    if t.dev.is_loopback() && t.pkt_type != PktType::Outgoing {
        // Linux loopback marks received packets CHECKSUM_UNNECESSARY
        TP_STATUS_CSUM_VALID
    } else {
        0
    }
}

/// A socket's receive queue, bounded by SO_RCVBUF: the copied frames
/// as skbs, each wrapped in an `Arc` (Linux skb->users) before the
/// lock, so queueing allocates nothing and MSG_PEEK takes a reference
/// under the lock and copies after it
pub struct PktQueue {
    q: SkbQueue,
    rmem: AtomicUsize,
}

impl Default for PktQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl PktQueue {
    #[track_caller]
    pub const fn new() -> Self {
        Self {
            q: SkbQueue::new(),
            rmem: AtomicUsize::new(0),
        }
    }

    /// Room for another frame (Linux packet_rcv: admit while rmem <
    /// rcvbuf, checked before the copy is made)
    pub(super) fn has_room(&self, sk: &Sock) -> bool {
        self.rmem.load(Ordering::Acquire) < sk.rcvbuf() as usize
    }

    /// Queue a frame
    pub(super) fn enqueue(&self, sk: &Sock, skb: Arc<SkBuff>) {
        self.rmem.fetch_add(skb.truesize(), Ordering::AcqRel);
        self.q.lock().push_back(skb);
        sk.data_ready();
    }

    fn readable(&self) -> bool {
        !self.q.is_empty()
    }

    fn dequeue(&self, peek: bool) -> Option<Arc<SkBuff>> {
        if peek {
            return self.q.peek();
        }
        let skb = self.q.dequeue()?;
        self.rmem.fetch_sub(skb.truesize(), Ordering::AcqRel);
        Some(skb)
    }

    /// Length of the next frame (SIOCINQ)
    pub fn inq(&self) -> usize {
        self.q.lock().front().map_or(0, SkBuff::len)
    }

    pub fn rmem(&self) -> usize {
        self.rmem.load(Ordering::Relaxed)
    }

    /// Purge the queue, uncharging exactly what it held (a concurrent
    /// enqueue charges before it pushes, a dequeue uncharges after it
    /// pops: zeroing the counter would let them skew it); the frames are
    /// freed after the lock
    pub fn clear(&self) {
        let q = self.q.purge();
        let n: usize = q.iter().map(SkBuff::truesize).sum();
        self.rmem.fetch_sub(n, Ordering::AcqRel);
    }

    /// Wait for a frame (Linux __skb_recv_datagram: a pending error
    /// first, EAGAIN when non-blocking or on timeout)
    pub fn recv(&self, sk: &Sock, flags: i32) -> Result<Arc<SkBuff>, KernelError> {
        let mut timeo = sk.rcv_timeo(flags & MSG_DONTWAIT != 0);
        loop {
            if let Some(e) = sk.take_err() {
                return Err(e);
            }
            if let Some(f) = self.dequeue(flags & MSG_PEEK != 0) {
                return Ok(f);
            }
            if timeo == 0 {
                return Err(KernelError::WouldBlock);
            }
            timeo = sk.wait(timeo, || self.readable() || sk.has_err())?;
        }
    }

    /// Linux datagram_poll (no shutdown on packet sockets)
    pub fn poll(&self, sk: &Sock) -> u16 {
        let mut mask = POLLOUT | POLLWRNORM | POLLWRBAND;
        if sk.err_pending() {
            mask |= POLLERR;
        }
        if self.readable() {
            mask |= POLLIN | POLLRDNORM;
        }
        mask
    }
}

/// Copy a frame into a receive request (Linux packet_recvmsg): data
/// (MSG_TRUNC when cut), a full sockaddr_ll, SOL_SOCKET control
/// messages and PACKET_AUXDATA
pub fn deliver(
    s: &PacketSock,
    m: &mut RecvMsg<'_>,
    skb: &SkBuff,
    flags: i32,
) -> Result<usize, KernelError> {
    let SkbCb::Pkt(cb) = skb.cb else {
        return Err(KernelError::InvalidArgument);
    };
    let data = skb.data();
    let n = m.data.put(0, data)?;
    if n < data.len() {
        m.flags |= MSG_TRUNC;
    }
    if m.want_name {
        m.name = Some(cb.sll.bytes()[..SLL_LEN].to_vec());
    }
    crate::net::dgram::sock_cmsgs(&s.sk, m, skb.tstamp, skb.dropcount);
    if s.flag(pf::AUXDATA) {
        m.cmsg
            .put(SOL_PACKET, PACKET_AUXDATA, &auxdata(&cb, data.len()));
    }
    Ok(if flags & MSG_TRUNC != 0 {
        data.len()
    } else {
        n
    })
}

/// struct tpacket_auxdata (20 bytes) of a frame of `snaplen` bytes
fn auxdata(f: &PktCb, snaplen: usize) -> [u8; 20] {
    let status = TP_STATUS_USER | f.csum;
    let mut b = [0u8; 20];
    b[0..4].copy_from_slice(&status.to_ne_bytes());
    b[4..8].copy_from_slice(&(f.origlen as u32).to_ne_bytes());
    b[8..12].copy_from_slice(&(snaplen as u32).to_ne_bytes());
    // tp_mac 0, tp_net, no VLAN tag
    b[14..16].copy_from_slice(&f.net_off.to_ne_bytes());
    b
}

// ============================================================================
// Table (per namespace) and the device tap
// ============================================================================

crate::adapter!(pub(super) PacketLink, PacketSock, link);
crate::rcu_head!(PacketSock, rcu);

/// Packet sockets of a namespace (Linux net->packet.sklist: an RCU list
/// the device tap and notifiers walk, changed by create and release)
#[derive(Default)]
pub struct PacketTable {
    sklist: RcuList<PacketLink>,
    /// Fanout groups (Linux fanout_list, its entries of this
    /// namespace; changed under the fanout mutex)
    pub(super) fanouts: crate::sync::spin::RwLock<Vec<Arc<super::fanout::Fanout>>>,
}

impl PacketTable {
    /// Linux packet_create's sk_add_node_tail_rcu
    pub(super) fn insert(&self, s: &Arc<PacketSock>) {
        self.sklist.push_back(s.clone());
        NSOCKS.fetch_add(1, Ordering::AcqRel);
    }

    /// Linux packet_release's sk_del_node_init_rcu: the list's
    /// reference goes after a grace period
    pub(super) fn remove(&self, s: &PacketSock) {
        if let Some(u) = self.sklist.remove_first(|o| core::ptr::eq(o, s)) {
            u.defer();
            NSOCKS.fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// Call `f` on each socket under RCU (Linux sk_for_each_rcu)
    pub(super) fn for_each(&self, mut f: impl FnMut(&PacketSock)) {
        let g = crate::sync::rcu::read_lock();
        self.sklist.iter_ref(&g).for_each(|s| f(&s));
    }

    /// References to every socket, for work that sleeps per socket
    /// (allocated before the walk, not under it)
    pub(super) fn snapshot(&self) -> Vec<Arc<PacketSock>> {
        self.sklist.snapshot()
    }
}

/// EtherType of a frame as Linux eth_type_trans reports it
fn eth_proto(frame: &[u8]) -> u16 {
    let ty = u16::from_be_bytes([frame[12], frame[13]]);
    if ty >= 0x600 {
        ty
    } else if frame.get(14..16) == Some(&[0xff, 0xff]) {
        ETH_P_802_3
    } else {
        ETH_P_802_2
    }
}

impl PacketSock {
    /// This socket gets a copy of the frame (Linux: its prot_hook is on
    /// ptype_all for ETH_P_ALL, ptype_base otherwise; outgoing frames
    /// only go to ptype_all, never back to their sender)
    fn wants(&self, t: &Tap<'_>, proto: u16) -> bool {
        // A fanout member's frames come through its group
        if !self.flag(pf::RUNNING) || self.fanout.lock().is_some() {
            return false;
        }
        let (num, ifindex) = self.bound();
        if num == 0 || (ifindex != 0 && ifindex as u32 != t.dev.ifindex()) {
            return false;
        }
        if t.pkt_type != PktType::Outgoing {
            return num == ETH_P_ALL || num == proto;
        }
        num == ETH_P_ALL && !self.flag(pf::IGNORE_OUTGOING) && t.owner != self.id()
    }

    /// Queue a copy of a tapped frame (Linux packet_rcv), or put it in
    /// the receive ring (tpacket_rcv)
    pub(super) fn rcv(&self, t: &Tap<'_>, proto: u16) {
        let raw = self.sk.stype == SOCK_RAW;
        let data = if raw { t.frame } else { &t.frame[ETH_HLEN..] };
        let mut snap = data.len();
        // The filter is cloned out and run with no lock held (an `if let`
        // scrutinee's guard would live across the run)
        let filter = self.filter.read().clone();
        if let Some(f) = filter {
            let res = f.run(&Ctx {
                data,
                frame: t.frame,
                net_off: ETH_HLEN,
                protocol: proto,
                pkt_type: t.pkt_type.num(),
                ifindex: t.dev.ifindex(),
                hatype: t.dev.link().dev_type,
                mark: 0,
            });
            if res == 0 {
                return;
            }
            snap = snap.min(res as usize);
        }
        if self.flag(pf::TPACKET) {
            return self.tpacket_rcv(t, proto, data, snap);
        }
        let sll = self.rx_sll(t, proto);
        if !self.rxq.has_room(&self.sk) {
            self.sk.drops.fetch_add(1, Ordering::Relaxed);
            self.drops.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let cb = PktCb {
            origlen: data.len(),
            sll,
            net_off: if raw { ETH_HLEN as u16 } else { 0 },
            csum: csum_status(t),
        };
        // No memory for the copy: dropped and counted (Linux packet_rcv's
        // failed skb_clone(GFP_ATOMIC) goes to drop_n_acct)
        let Some(skb) = frame_skb(&data[..snap], cb, self.sk.drops.load(Ordering::Relaxed)) else {
            self.sk.drops.fetch_add(1, Ordering::Relaxed);
            self.drops.fetch_add(1, Ordering::Relaxed);
            return;
        };
        self.rxq.enqueue(&self.sk, skb);
        self.packets.fetch_add(1, Ordering::Relaxed);
    }
}

/// A queued copy of a tapped frame's `data`, allocated GFP_ATOMIC (a
/// receive or transmit path, possibly under a socket's lock) and
/// wrapped in its `Arc` before any queue lock
pub(super) fn frame_skb(data: &[u8], cb: PktCb, drops: u32) -> Option<Arc<SkBuff>> {
    let mut skb = SkBuff::alloc(0, data.len(), Gfp::ATOMIC)?;
    skb.put_slice(data)?;
    skb.cb = SkbCb::Pkt(cb);
    skb.tstamp = crate::net::dgram::now();
    skb.dropcount = drops;
    try_arc_gfp(*skb, Gfp::ATOMIC).ok()
}

/// The ptype_all tap: give every matching packet socket of the device's
/// namespace a copy (thread context: softnet or a transmitting task)
pub fn tap(t: &Tap<'_>) {
    if NSOCKS.load(Ordering::Acquire) == 0 || t.frame.len() < ETH_HLEN {
        return;
    }
    let Some(net) = t.dev.net() else {
        return;
    };
    let proto = eth_proto(t.frame);
    net.packet.for_each(|s| {
        if s.wants(t, proto) {
            s.rcv(t, proto);
        }
    });
    super::fanout::deliver(&net, t, proto);
}

/// `/proc/net/packet` (Linux packet_seq_show; socket addresses
/// hidden), generated under RCU into a buffer that never grows
pub fn proc_net_packet(net: &crate::net::NetNamespace) -> Vec<u8> {
    crate::fs::proc::seq::generate(|m| {
        let _ = m.write_str("sk               RefCnt Type Proto  Iface R Rmem   User   Inode\n");
        let g = crate::sync::rcu::read_lock();
        for s in net.packet.sklist.iter_ref(&g) {
            let (num, ifindex) = s.bound();
            // The walk's own reference not counted
            let refs = Arc::strong_count(&s.get()) - 1;
            let _ = writeln!(
                m,
                "{:016x} {:<6} {:<4} {:04x}   {:<5} {:1} {:<6} {:<6} {:<6}",
                0,
                refs,
                s.sk.stype,
                num,
                ifindex,
                u8::from(num != 0),
                s.rxq.rmem(),
                s.sk.cred.fsuid,
                s.sk.ino.load(Ordering::Acquire),
            );
        }
    })
}

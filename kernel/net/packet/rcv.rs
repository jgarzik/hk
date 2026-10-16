//! AF_PACKET receive side: the per-namespace socket table, the device
//! tap (Linux packet_rcv via ptype_all/ptype_base), the bounded receive
//! queue and recvmsg delivery (Linux packet_recvmsg)

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::sync::spin::{Mutex, RwLock};

use super::{ETH_P_802_2, ETH_P_802_3, ETH_P_ALL, PacketSock, SLL_LEN, Sll, pf};
use crate::error::KernelError;
use crate::net::dev::Tap;
use crate::net::ethernet::{ETH_ALEN, ETH_HLEN, PktType};
use crate::net::filter::Ctx;
use crate::net::msg::{MSG_DONTWAIT, MSG_PEEK, MSG_TRUNC, RecvMsg};
use crate::net::sock::Sock;
use crate::net::socket::SOCK_RAW;
use crate::poll::{POLLERR, POLLIN, POLLOUT, POLLRDNORM, POLLWRBAND, POLLWRNORM};

/// Socket level of packet options and control messages
pub const SOL_PACKET: i32 = 263;
/// PACKET_AUXDATA (option and control message type)
pub const PACKET_AUXDATA: i32 = 8;
/// tpacket_auxdata.tp_status bits
const TP_STATUS_USER: u32 = 0x1;
const TP_STATUS_CSUM_VALID: u32 = 0x80;

/// Packet sockets in all namespaces (fast path: no socket, no work)
static NSOCKS: AtomicUsize = AtomicUsize::new(0);

/// A queued frame
#[derive(Clone)]
pub struct Frame {
    /// What the socket receives (snapped by the filter)
    data: Vec<u8>,
    /// Length before the filter's snap (tpacket_auxdata.tp_len)
    origlen: usize,
    sll: Sll,
    /// Offset of the network header in `data`
    net_off: u16,
    loopback: bool,
    stamp: i128,
    drops: u32,
}

/// Bytes charged to rcvbuf per frame (data + skb overhead)
fn truesize(len: usize) -> usize {
    len + 512
}

/// A socket's receive queue, bounded by SO_RCVBUF
#[derive(Default)]
pub struct PktQueue {
    q: Mutex<VecDeque<Frame>>,
    rmem: AtomicUsize,
}

impl PktQueue {
    /// Queue unless the receive buffer is full (Linux packet_rcv:
    /// admit while rmem < rcvbuf); false if dropped
    fn enqueue(&self, sk: &Sock, mut f: Frame) -> bool {
        if self.rmem.load(Ordering::Acquire) >= sk.rcvbuf() as usize {
            sk.drops.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        self.rmem
            .fetch_add(truesize(f.data.len()), Ordering::AcqRel);
        f.drops = sk.drops.load(Ordering::Relaxed);
        self.q.lock().push_back(f);
        sk.data_ready();
        true
    }

    fn readable(&self) -> bool {
        !self.q.lock().is_empty()
    }

    fn dequeue(&self, peek: bool) -> Option<Frame> {
        let mut q = self.q.lock();
        if peek {
            return q.front().cloned();
        }
        let f = q.pop_front()?;
        drop(q);
        self.rmem
            .fetch_sub(truesize(f.data.len()), Ordering::AcqRel);
        Some(f)
    }

    /// Length of the next frame (SIOCINQ)
    pub fn inq(&self) -> usize {
        self.q.lock().front().map_or(0, |f| f.data.len())
    }

    pub fn rmem(&self) -> usize {
        self.rmem.load(Ordering::Relaxed)
    }

    /// Purge the queue, uncharging exactly what it held (a concurrent
    /// enqueue charges before it pushes, a dequeue uncharges after it
    /// pops: zeroing the counter would let them skew it)
    pub fn clear(&self) {
        let q = core::mem::take(&mut *self.q.lock());
        let n: usize = q.iter().map(|x| truesize(x.data.len())).sum();
        self.rmem.fetch_sub(n, Ordering::AcqRel);
    }

    /// Wait for a frame (Linux __skb_recv_datagram: a pending error
    /// first, EAGAIN when non-blocking or on timeout)
    pub fn recv(&self, sk: &Sock, flags: i32) -> Result<Frame, KernelError> {
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
    m: &mut RecvMsg,
    f: &Frame,
    flags: i32,
) -> Result<usize, KernelError> {
    let n = m.data.put(0, &f.data)?;
    if n < f.data.len() {
        m.flags |= MSG_TRUNC;
    }
    if m.want_name {
        m.name = Some(f.sll.bytes()[..SLL_LEN].to_vec());
    }
    crate::net::dgram::sock_cmsgs(&s.sk, m, f.stamp, f.drops);
    if s.flag(pf::AUXDATA) {
        m.cmsg.put(SOL_PACKET, PACKET_AUXDATA, &auxdata(f));
    }
    Ok(if flags & MSG_TRUNC != 0 {
        f.data.len()
    } else {
        n
    })
}

/// struct tpacket_auxdata (20 bytes)
fn auxdata(f: &Frame) -> [u8; 20] {
    let mut status = TP_STATUS_USER;
    if f.loopback && f.sll.pkttype != PktType::Outgoing.num() {
        // Linux loopback marks received packets CHECKSUM_UNNECESSARY
        status |= TP_STATUS_CSUM_VALID;
    }
    let mut b = [0u8; 20];
    b[0..4].copy_from_slice(&status.to_ne_bytes());
    b[4..8].copy_from_slice(&(f.origlen as u32).to_ne_bytes());
    b[8..12].copy_from_slice(&(f.data.len() as u32).to_ne_bytes());
    // tp_mac 0, tp_net, no VLAN tag
    b[14..16].copy_from_slice(&f.net_off.to_ne_bytes());
    b
}

// ============================================================================
// Table (per namespace) and the device tap
// ============================================================================

/// Packet sockets of a namespace
#[derive(Default)]
pub struct PacketTable {
    socks: RwLock<Vec<Arc<PacketSock>>>,
}

impl PacketTable {
    pub(super) fn insert(&self, s: &Arc<PacketSock>) {
        self.socks.write().push(s.clone());
        NSOCKS.fetch_add(1, Ordering::AcqRel);
    }

    pub(super) fn remove(&self, s: &PacketSock) {
        let mut t = self.socks.write();
        let n = t.len();
        t.retain(|o| !core::ptr::eq(Arc::as_ptr(o), s));
        if t.len() != n {
            NSOCKS.fetch_sub(1, Ordering::AcqRel);
        }
    }

    fn matching(&self, t: &Tap, proto: u16) -> Vec<Arc<PacketSock>> {
        self.socks
            .read()
            .iter()
            .filter(|s| s.wants(t, proto))
            .cloned()
            .collect()
    }

    fn all(&self) -> Vec<Arc<PacketSock>> {
        self.socks.read().clone()
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
    fn wants(&self, t: &Tap, proto: u16) -> bool {
        let (num, ifindex) = self.bound();
        if num == 0 || (ifindex != 0 && ifindex as u32 != t.dev.ifindex()) {
            return false;
        }
        if t.pkt_type != PktType::Outgoing {
            return num == ETH_P_ALL || num == proto;
        }
        num == ETH_P_ALL && !self.flag(pf::IGNORE_OUTGOING) && t.owner != self.id()
    }

    /// Queue a copy of a tapped frame (Linux packet_rcv)
    fn rcv(&self, t: &Tap, proto: u16) {
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
        let mut sll = Sll {
            protocol: proto,
            ifindex: t.dev.ifindex() as i32,
            hatype: t.dev.link().dev_type,
            pkttype: t.pkt_type.num(),
            halen: ETH_ALEN as u8,
            addr: [0; 8],
        };
        sll.addr[..ETH_ALEN].copy_from_slice(&t.frame[6..12]);
        let f = Frame {
            data: data[..snap].to_vec(),
            origlen: data.len(),
            sll,
            net_off: if raw { ETH_HLEN as u16 } else { 0 },
            loopback: t.dev.is_loopback(),
            stamp: crate::time::TIMEKEEPER.current_time().to_nanos(),
            drops: 0,
        };
        if self.rxq.enqueue(&self.sk, f) {
            self.packets.fetch_add(1, Ordering::Relaxed);
        } else {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// The ptype_all tap: give every matching packet socket of the device's
/// namespace a copy (thread context: softnet or a transmitting task)
pub fn tap(t: &Tap) {
    if NSOCKS.load(Ordering::Acquire) == 0 || t.frame.len() < ETH_HLEN {
        return;
    }
    let Some(net) = t.dev.net() else {
        return;
    };
    let proto = eth_proto(t.frame);
    for s in net.packet.matching(t, proto) {
        s.rcv(t, proto);
    }
}

/// `/proc/net/packet` (Linux packet_seq_show; socket addresses hidden)
pub fn proc_net_packet() -> Vec<u8> {
    let mut out = String::from("sk               RefCnt Type Proto  Iface R Rmem   User   Inode\n");
    for s in crate::net::current_net_ns().packet.all() {
        let (num, ifindex) = s.bound();
        let _ = writeln!(
            out,
            "{:016x} {:<6} {:<4} {:04x}   {:<5} {:1} {:<6} {:<6} {:<6}",
            0,
            Arc::strong_count(&s),
            s.sk.stype,
            num,
            ifindex,
            (num != 0) as u8,
            s.rxq.rmem(),
            s.sk.cred.fsuid,
            s.sk.ino.load(Ordering::Acquire),
        );
    }
    out.into_bytes()
}

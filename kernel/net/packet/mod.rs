//! AF_PACKET sockets: socket(AF_PACKET, SOCK_RAW | SOCK_DGRAM, proto)
//! (Linux net/packet/af_packet.c, without the mmap rings and fanout)
//!
//! Need CAP_NET_RAW (EPERM). A socket bound to a protocol (htons
//! ETH_P_ALL or an EtherType; from socket() or bind(sockaddr_ll)) and
//! optionally a device receives a copy of matching frames: ETH_P_ALL
//! sees every frame in both directions (received ones as PACKET_HOST /
//! BROADCAST / MULTICAST / OTHERHOST, transmitted ones as
//! PACKET_OUTGOING, except its own), a specific protocol only received
//! frames of that EtherType. SOCK_RAW frames start at the link-layer
//! header, SOCK_DGRAM ones at the network header; recvfrom() returns a
//! sockaddr_ll with the source hardware address. Sends take a whole
//! frame (SOCK_RAW) or get a link-layer header built from sll_addr and
//! sll_protocol (SOCK_DGRAM). Nothing depends on IP configuration, so
//! this works on interfaces without addresses (DHCP clients).
//!
//! Receive queues are bounded by SO_RCVBUF (drops counted for
//! PACKET_STATISTICS); a classic BPF filter (SO_ATTACH_FILTER) can
//! drop or truncate frames before they are queued.
//!
//! ## Locking (thread context only)
//!
//! `PacketTable.socks` (`spin::RwLock`, per namespace, leaf): delivery
//! clones the matching `Arc`s and queues after dropping it. Per socket:
//! `bind` is an atomic; `rxq` (`spin::Mutex` leaf) and `filter`
//! (`spin::RwLock` leaf, the `Arc` is cloned out before running it).
//! `mclist` (`spin::Mutex` leaf) is changed under RTNL, which device
//! promiscuity changes need: RTNL -> `mclist`.

mod opts;
mod rcv;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use spin::{Mutex, RwLock};

use crate::error::KernelError;
use crate::net::device::NetDevice;
use crate::net::ethernet::{ETH_ALEN, ETH_HLEN};
use crate::net::filter::Filter;
use crate::net::msg::{MSG_DONTWAIT, MSG_ERRQUEUE, MSG_PEEK, MSG_TRUNC};
use crate::net::msg::{RecvMsg, SendMsg};
use crate::net::skb::{NET_SKB_PAD, SkBuff};
use crate::net::sock::Sock;
use crate::net::socket::{
    AF_PACKET, OptIn, OptOut, ProtoOps, SIOCINQ, SIOCOUTQ, SOCK_DGRAM, SOCK_RAW,
};

pub use rcv::{PacketTable, proc_net_packet, tap};

/// All protocols (ETH_P_ALL, host order)
pub const ETH_P_ALL: u16 = 0x0003;
/// 802.3 frame without 802.2 header / 802.2 frame (eth_type_trans)
const ETH_P_802_3: u16 = 0x0001;
const ETH_P_802_2: u16 = 0x0004;
/// VLAN tag EtherTypes (a tagged frame may be 4 bytes over the MTU)
const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88a8;
const VLAN_HLEN: usize = 4;

/// sizeof(struct sockaddr_ll) and offsetof(sll_addr)
pub const SLL_LEN: usize = 20;
const SLL_ADDR_OFF: usize = 12;

/// Socket flags (`PacketSock.flags`)
mod pf {
    pub const AUXDATA: u32 = 1 << 0;
    pub const ORIGDEV: u32 = 1 << 1;
    pub const IGNORE_OUTGOING: u32 = 1 << 2;
    /// SO_LOCK_FILTER
    pub const FILTER_LOCKED: u32 = 1 << 3;
}

/// A link-layer address (struct sockaddr_ll)
#[derive(Clone, Copy, Debug, Default)]
pub struct Sll {
    /// EtherType, host order
    pub protocol: u16,
    pub ifindex: i32,
    pub hatype: u16,
    pub pkttype: u8,
    pub halen: u8,
    pub addr: [u8; 8],
}

impl Sll {
    pub fn bytes(&self) -> [u8; SLL_LEN] {
        let mut b = [0u8; SLL_LEN];
        b[0..2].copy_from_slice(&AF_PACKET.to_ne_bytes());
        b[2..4].copy_from_slice(&self.protocol.to_be_bytes());
        b[4..8].copy_from_slice(&self.ifindex.to_ne_bytes());
        b[8..10].copy_from_slice(&self.hatype.to_ne_bytes());
        b[10] = self.pkttype;
        b[11] = self.halen;
        b[12..20].copy_from_slice(&self.addr);
        b
    }

    /// Parse a user sockaddr_ll (at least SLL_LEN bytes)
    fn parse(a: &[u8]) -> Self {
        let mut addr = [0u8; 8];
        addr.copy_from_slice(&a[12..20]);
        Self {
            protocol: u16::from_be_bytes([a[2], a[3]]),
            ifindex: i32::from_ne_bytes([a[4], a[5], a[6], a[7]]),
            hatype: u16::from_ne_bytes([a[8], a[9]]),
            pkttype: a[10],
            halen: a[11],
            addr,
        }
    }
}

/// Where a send goes: device, EtherType and (SOCK_DGRAM) link address
struct Dest {
    dev: Arc<NetDevice>,
    proto: u16,
    addr: Option<[u8; 8]>,
}

/// An AF_PACKET socket
pub struct PacketSock {
    sk: Sock,
    /// Bound protocol (host order, 0 = none) << 32 | ifindex (0 = all)
    bind: AtomicU64,
    flags: AtomicU32,
    rxq: rcv::PktQueue,
    filter: RwLock<Option<Arc<Filter>>>,
    /// PACKET_STATISTICS since the last read
    packets: AtomicU32,
    drops: AtomicU32,
    /// PACKET_ADD_MEMBERSHIP entries (changed under RTNL)
    mclist: Mutex<Vec<opts::Mreq>>,
}

/// socket(AF_PACKET, type, protocol) (Linux packet_create: EPERM
/// without CAP_NET_RAW, then ESOCKTNOSUPPORT for other types; the
/// protocol is a network-order EtherType, 16 bits used)
pub fn create(stype: i32, protocol: i32) -> Result<Arc<dyn ProtoOps>, KernelError> {
    if !crate::task::capable(crate::task::CAP_NET_RAW) {
        return Err(KernelError::NotPermitted);
    }
    if stype != SOCK_RAW && stype != SOCK_DGRAM {
        // SOCK_PACKET (obsolete) is not supported
        return Err(KernelError::SocketTypeNotSupported);
    }
    let proto = u16::from_be(protocol as u16);
    let net = crate::net::current_net_ns();
    let s = Arc::new(PacketSock {
        sk: Sock::new(net.clone(), AF_PACKET, stype, protocol),
        bind: AtomicU64::new((proto as u64) << 32),
        flags: AtomicU32::new(0),
        rxq: rcv::PktQueue::default(),
        filter: RwLock::new(None),
        packets: AtomicU32::new(0),
        drops: AtomicU32::new(0),
        mclist: Mutex::new(Vec::new()),
    });
    net.packet.insert(&s);
    Ok(s)
}

impl PacketSock {
    /// (protocol, ifindex) bound
    fn bound(&self) -> (u16, i32) {
        let b = self.bind.load(Ordering::Acquire);
        ((b >> 32) as u16, b as u32 as i32)
    }

    fn set_bound(&self, proto: u16, ifindex: i32) {
        let v = ((proto as u64) << 32) | ifindex as u32 as u64;
        self.bind.store(v, Ordering::Release);
    }

    fn flag(&self, f: u32) -> bool {
        self.flags.load(Ordering::Acquire) & f != 0
    }

    fn set_flag(&self, f: u32, on: bool) {
        if on {
            self.flags.fetch_or(f, Ordering::AcqRel);
        } else {
            self.flags.fetch_and(!f, Ordering::AcqRel);
        }
    }

    /// Identity for skipping our own outgoing frames
    fn id(&self) -> usize {
        self as *const Self as usize
    }

    fn dev(&self, ifindex: i32) -> Option<Arc<NetDevice>> {
        if ifindex <= 0 {
            return None;
        }
        self.sk.net.dev_get_by_index(ifindex as u32)
    }

    /// Destination of a send, from msg_name or the binding (Linux
    /// packet_snd)
    fn dest(&self, m: &SendMsg) -> Result<Dest, KernelError> {
        let Some(a) = &m.addr else {
            let (proto, ifindex) = self.bound();
            let dev = self.dev(ifindex).ok_or(KernelError::NoDeviceOrAddress)?;
            return Ok(Dest {
                dev,
                proto,
                addr: None,
            });
        };
        if a.len() < SLL_LEN || a.len() < a[11] as usize + SLL_ADDR_OFF {
            return Err(KernelError::InvalidArgument);
        }
        let sll = Sll::parse(a);
        let dev = self.dev(sll.ifindex);
        let mut addr = None;
        if self.sk.stype == SOCK_DGRAM {
            if dev.is_some() && a.len() < ETH_ALEN + SLL_ADDR_OFF {
                return Err(KernelError::InvalidArgument);
            }
            addr = Some(sll.addr);
        }
        let dev = dev.ok_or(KernelError::NoDeviceOrAddress)?;
        Ok(Dest {
            dev,
            proto: sll.protocol,
            addr,
        })
    }

    /// Build the frame of a send (link header for SOCK_DGRAM)
    fn build(
        &self,
        dev: &NetDevice,
        proto: u16,
        addr: Option<[u8; 8]>,
        data: &[u8],
    ) -> Result<alloc::boxed::Box<SkBuff>, KernelError> {
        let mut skb =
            SkBuff::alloc(NET_SKB_PAD, data.len() + ETH_HLEN).ok_or(KernelError::NoBufferSpace)?;
        if self.sk.stype == SOCK_DGRAM {
            skb.reserve(ETH_HLEN);
            skb.put_slice(data).ok_or(KernelError::NoBufferSpace)?;
            eth_hard_header(&mut skb, dev, proto, addr, data.len())?;
        } else {
            skb.put_slice(data).ok_or(KernelError::NoBufferSpace)?;
        }
        Ok(skb)
    }
}

/// Linux eth_header: destination from `addr` (if missing: zero on
/// loopback/NOARP devices, EINVAL elsewhere), our source address, the
/// EtherType (or the length for 802.3/802.2)
fn eth_hard_header(
    skb: &mut SkBuff,
    dev: &NetDevice,
    proto: u16,
    addr: Option<[u8; 8]>,
    len: usize,
) -> Result<(), KernelError> {
    use crate::net::device::flags::{IFF_LOOPBACK, IFF_NOARP};
    let ty = if proto == ETH_P_802_3 || proto == ETH_P_802_2 {
        len as u16
    } else {
        proto
    };
    let h = skb.push(ETH_HLEN).ok_or(KernelError::NoBufferSpace)?;
    h[6..12].copy_from_slice(&dev.mac());
    h[12..14].copy_from_slice(&ty.to_be_bytes());
    match addr {
        Some(a) => h[0..6].copy_from_slice(&a[..ETH_ALEN]),
        None if dev.get_flags() & (IFF_LOOPBACK | IFF_NOARP) != 0 => h[0..6].fill(0),
        None => return Err(KernelError::InvalidArgument),
    }
    Ok(())
}

/// Largest send (Linux packet_snd: MTU plus the link header for
/// SOCK_RAW, plus a VLAN tag for tagged frames)
fn check_len(stype: i32, mtu: usize, data: &[u8]) -> Result<(), KernelError> {
    let reserve = if stype == SOCK_RAW { ETH_HLEN } else { 0 };
    if data.len() > mtu + reserve + VLAN_HLEN {
        return Err(KernelError::MessageTooLong);
    }
    if stype == SOCK_RAW && data.len() < ETH_HLEN {
        return Err(KernelError::InvalidArgument);
    }
    if data.len() > mtu + reserve {
        let ty = if stype == SOCK_RAW {
            u16::from_be_bytes([data[12], data[13]])
        } else {
            0
        };
        if ty != ETH_P_8021Q && ty != ETH_P_8021AD {
            return Err(KernelError::MessageTooLong);
        }
    }
    Ok(())
}

impl ProtoOps for PacketSock {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn sk(&self) -> &Sock {
        &self.sk
    }

    fn release(&self) {
        self.sk.net.packet.remove(self);
        opts::flush_mclist(self);
        self.rxq.clear();
        self.sk.purge_err();
    }

    /// Linux packet_bind: a sockaddr_ll; protocol 0 keeps the current
    /// one; ENODEV for an unknown device; a down device is ENETDOWN on
    /// the socket (the bind itself succeeds)
    fn bind(&self, a: &[u8]) -> Result<(), KernelError> {
        if a.len() < SLL_LEN || u16::from_ne_bytes([a[0], a[1]]) != AF_PACKET {
            return Err(KernelError::InvalidArgument);
        }
        let sll = Sll::parse(a);
        let dev = if sll.ifindex != 0 {
            Some(self.dev(sll.ifindex).ok_or(KernelError::NoDevice)?)
        } else {
            None
        };
        let (cur, cur_if) = self.bound();
        let proto = if sll.protocol != 0 { sll.protocol } else { cur };
        if proto == cur && sll.ifindex == cur_if {
            return Ok(());
        }
        self.set_bound(proto, sll.ifindex);
        if proto != 0 && dev.is_some_and(|d| !d.is_up()) {
            self.sk.set_err(KernelError::NetworkDown);
        }
        Ok(())
    }

    /// Linux packet_getname: no peer; the bound device's address
    fn getname(&self, peer: bool) -> Result<Vec<u8>, KernelError> {
        if peer {
            return Err(KernelError::OperationNotSupported);
        }
        let (proto, ifindex) = self.bound();
        let mut sll = Sll {
            protocol: proto,
            ifindex,
            ..Default::default()
        };
        if let Some(d) = self.dev(ifindex) {
            sll.hatype = d.link().dev_type;
            sll.halen = ETH_ALEN as u8;
            sll.addr[..ETH_ALEN].copy_from_slice(&d.mac());
        }
        Ok(sll.bytes()[..SLL_ADDR_OFF + sll.halen as usize].to_vec())
    }

    fn poll(&self) -> u16 {
        self.rxq.poll(&self.sk)
    }

    /// SIOCINQ: length of the next frame; SIOCOUTQ: nothing is queued
    fn ioctl(&self, cmd: u32, arg: u64) -> Result<i64, KernelError> {
        let v = match cmd {
            SIOCINQ => self.rxq.inq(),
            SIOCOUTQ => 0,
            _ => return Err(KernelError::NotTty),
        };
        crate::uaccess::put_user::<crate::arch::Uaccess, i32>(arg, v as i32)
            .map_err(|_| KernelError::BadAddress)?;
        Ok(0)
    }

    fn inq(&self) -> usize {
        self.rxq.inq()
    }

    fn setsockopt(&self, level: i32, opt: i32, v: OptIn) -> Option<Result<(), KernelError>> {
        opts::set(self, level, opt, v)
    }

    fn getsockopt(&self, level: i32, opt: i32) -> Option<Result<OptOut, KernelError>> {
        opts::get(self, level, opt)
    }

    /// Linux packet_snd
    fn sendmsg(&self, m: &mut SendMsg, _flags: i32) -> Result<usize, KernelError> {
        let Dest { dev, proto, addr } = self.dest(m)?;
        if !dev.is_up() {
            return Err(KernelError::NetworkDown);
        }
        let len = m.data.len();
        let mtu = dev.mtu() as usize;
        if len > mtu + ETH_HLEN + VLAN_HLEN {
            return Err(KernelError::MessageTooLong);
        }
        let data = m.data.take(len)?;
        check_len(self.sk.stype, mtu, &data)?;
        let mut skb = self.build(&dev, proto, addr, &data)?;
        skb.dev = Some(dev);
        skb.owner = self.id();
        crate::net::dev::dev_queue_xmit(skb)?;
        Ok(len)
    }

    /// Linux packet_recvmsg
    fn recvmsg(&self, m: &mut RecvMsg, flags: i32) -> Result<usize, KernelError> {
        let ok = MSG_PEEK | MSG_DONTWAIT | MSG_TRUNC | MSG_ERRQUEUE;
        if flags & !ok != 0 {
            return Err(KernelError::InvalidArgument);
        }
        if flags & MSG_ERRQUEUE != 0 {
            // Nothing is ever queued (no TX timestamps)
            return Err(KernelError::WouldBlock);
        }
        let f = self.rxq.recv(&self.sk, flags)?;
        rcv::deliver(self, m, &f, flags)
    }
}

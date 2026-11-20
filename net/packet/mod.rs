//! AF_PACKET sockets: socket(AF_PACKET, SOCK_RAW | SOCK_DGRAM, proto),
//! and the obsolete SOCK_PACKET (`spkt`)
//! (Linux net/packet/af_packet.c; the mmap rings in `ring`)
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
//! `PacketTable.sklist` (`util::rculist`, per namespace; its writers'
//! spin leaf taken by create and release only): the device tap, the
//! NETDEV_DOWN notifier and /proc/net/packet walk it under RCU (Linux
//! sk_for_each_rcu), queueing GFP_ATOMIC copies; the unregister
//! notifier, which sleeps per socket, takes a snapshot first. A
//! released socket's list reference goes a grace period later (Linux
//! SOCK_RCU_FREE), possibly in `rcuc/N`. Per socket: `sk_lock`
//! (sleeping, Linux lock_sock) serializes bind and the ring options;
//! `bind_lock` (spin, Linux po->bind_lock) guards the binding's
//! changes and the hook (RUNNING: the device tap delivers to the
//! socket), taken by bind, the device notifiers and release:
//! `sk_lock` -> `bind_lock`. The binding is one atomic word, read
//! lock-free (receive, send, getname); `rxq` (an `SkbQueue`, spin leaf: frames are
//! copied into skbs GFP_ATOMIC before it, freed after it) and `filter`
//! (`crate::sync::spin::RwLock` leaf, the `Arc` is cloned out before running it).
//! `mclist` (sleeping `crate::sync::Mutex` leaf; Linux keeps po->mclist
//! under RTNL) is changed under RTNL, which device promiscuity changes
//! need: RTNL -> `mclist`.

mod fanout;
mod opts;
mod rcv;
mod ring;
mod spkt;
mod tx;
mod v3;
mod vnet;

use crate::mm::page_alloc::Gfp;
use crate::util::kalloc::try_arc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::sync::spin::RwLock;

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
use crate::util::error::KernelError;

pub use rcv::{PacketTable, PktCb, proc_net_packet, tap};

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
    /// The hook is registered: the tap delivers to the socket (Linux
    /// PACKET_SOCK_RUNNING; changed under `bind_lock`)
    pub const RUNNING: u32 = 1 << 4;
    /// A receive ring takes the frames (Linux prot_hook.func is
    /// tpacket_rcv; changed under `PacketSock.rx`)
    pub const TPACKET: u32 = 1 << 5;
    /// PACKET_TX_HAS_OFF (Linux PACKET_SOCK_TX_HAS_OFF)
    pub const TX_HAS_OFF: u32 = 1 << 6;
    /// PACKET_LOSS (Linux PACKET_SOCK_TP_LOSS)
    pub const TP_LOSS: u32 = 1 << 7;
    /// Short of room, skipped by rollover (Linux PACKET_SOCK_PRESSURE)
    pub const PRESSURE: u32 = 1 << 8;
    /// PACKET_QDISC_BYPASS (Linux PACKET_SOCK_QDISC_BYPASS: hk has no
    /// qdisc, dev_queue_xmit already goes straight to the driver as
    /// Linux packet_direct_xmit)
    pub const QDISC_BYPASS: u32 = 1 << 9;
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
    /// Bound protocol (host order, 0 = none) << 32 | ifindex (0 = all,
    /// -1 = a device that went away): one word, read lock-free
    /// (receive, send, getname), changed under `bind_lock` (Linux
    /// po->num, po->ifindex)
    bind: AtomicU64,
    /// Linux lock_sock: bind and the ring options
    sk_lock: crate::sync::Mutex<()>,
    /// Linux po->bind_lock: the binding's changes and RUNNING
    bind_lock: crate::sync::spin::Mutex<()>,
    flags: AtomicU32,
    rxq: rcv::PktQueue,
    filter: RwLock<Option<Arc<Filter>>>,
    /// PACKET_STATISTICS since the last read (Linux po->stats,
    /// po->tp_drops)
    packets: AtomicU32,
    drops: AtomicU32,
    /// tpacket_stats_v3.tp_freeze_q_cnt
    freeze_q_cnt: AtomicU32,
    /// Linux po->pg_vec_lock: ring swaps against mmap
    pg_vec_lock: crate::sync::Mutex<()>,
    /// The receive ring (Linux po->rx_ring, under the receive queue
    /// lock)
    rx: crate::sync::spin::Mutex<ring::RxRing>,
    /// The transmit ring (Linux po->tx_ring)
    tx: crate::sync::spin::Mutex<tx::TxRing>,
    /// TX ring frames sent and not yet freed (Linux tx_ring's
    /// pending_refcnt, per CPU there: one counter per socket here, hit
    /// once per frame each way), their completions (Linux
    /// po->skb_completion's count and wait queue)
    tx_pending: AtomicU32,
    tx_done: AtomicU32,
    tx_wq: crate::sync::waitqueue::WaitQueue,
    /// Its own `Arc`, weakly (a fanout group's member list holds it)
    me: spin::Once<alloc::sync::Weak<PacketSock>>,
    /// Its fanout group (Linux po->fanout; changed under `FANOUT` and
    /// `bind_lock`) and rollover state (po->rollover)
    fanout: crate::sync::spin::Mutex<Option<Arc<fanout::Fanout>>>,
    rollover: crate::sync::spin::Mutex<Option<Arc<fanout::Rollover>>>,
    /// The V3 ring's retire timer (Linux prb_bdqc.retire_blk_timer)
    retire: Arc<v3::Retire>,
    /// User mappings of the rings (Linux po->mapped)
    mapped: Arc<ring::Mapped>,
    /// PACKET_VERSION, the ring frame header length (Linux
    /// po->tp_hdrlen), PACKET_RESERVE, PACKET_TIMESTAMP,
    /// PACKET_COPY_THRESH
    tp_version: AtomicU32,
    tp_hdrlen: AtomicU32,
    tp_reserve: AtomicU32,
    tp_tstamp: AtomicU32,
    copy_thresh: AtomicU32,
    /// PACKET_VNET_HDR(_SZ): 0, 10 or 12 (Linux po->vnet_hdr_sz)
    vnet_hdr_sz: AtomicU32,
    /// PACKET_ADD_MEMBERSHIP entries (changed under RTNL)
    mclist: crate::sync::Mutex<Vec<opts::Mreq>>,
    /// Link on its namespace's list (Linux sk_node)
    link: crate::util::list::Link,
    /// The list reference's deferred release
    rcu: crate::sync::rcu::RcuHead,
}

/// socket(AF_PACKET, type, protocol) (Linux packet_create: EPERM
/// without CAP_NET_RAW, then ESOCKTNOSUPPORT for other types; the
/// protocol is a network-order EtherType, 16 bits used)
pub fn create(stype: i32, protocol: i32) -> Result<Arc<dyn ProtoOps>, KernelError> {
    if !crate::task::capable(crate::task::CAP_NET_RAW) {
        return Err(KernelError::NotPermitted);
    }
    if stype != SOCK_RAW && stype != SOCK_DGRAM && stype != spkt::SOCK_PACKET {
        return Err(KernelError::SocketTypeNotSupported);
    }
    let proto = u16::from_be(protocol as u16);
    let net = crate::net::current_net_ns();
    let s = try_arc(PacketSock {
        sk: Sock::new(net.clone(), AF_PACKET, stype, protocol),
        bind: AtomicU64::new(pack(proto, 0)),
        sk_lock: crate::sync::Mutex::new(()),
        bind_lock: crate::sync::spin::Mutex::new(()),
        flags: AtomicU32::new(0),
        rxq: rcv::PktQueue::default(),
        filter: RwLock::new(None),
        packets: AtomicU32::new(0),
        drops: AtomicU32::new(0),
        freeze_q_cnt: AtomicU32::new(0),
        pg_vec_lock: crate::sync::Mutex::new(()),
        rx: crate::sync::spin::Mutex::new(ring::RxRing::default()),
        tx: crate::sync::spin::Mutex::new(tx::TxRing::default()),
        tx_pending: AtomicU32::new(0),
        tx_done: AtomicU32::new(0),
        tx_wq: crate::sync::waitqueue::WaitQueue::new(),
        me: spin::Once::new(),
        fanout: crate::sync::spin::Mutex::new(None),
        rollover: crate::sync::spin::Mutex::new(None),
        retire: try_arc(v3::Retire::new())?,
        mapped: try_arc(ring::Mapped::default())?,
        tp_version: AtomicU32::new(ring::TPACKET_V1),
        tp_hdrlen: AtomicU32::new(0),
        tp_reserve: AtomicU32::new(0),
        tp_tstamp: AtomicU32::new(0),
        copy_thresh: AtomicU32::new(0),
        vnet_hdr_sz: AtomicU32::new(0),
        mclist: crate::sync::Mutex::new(Vec::new()),
        link: crate::util::list::Link::new(),
        rcu: crate::sync::rcu::RcuHead::new(),
    })?;
    s.retire.attach(&s);
    s.me.call_once(|| Arc::downgrade(&s));
    // Linux packet_create: hooked at once when a protocol is given
    if proto != 0 {
        let g = s.bind_lock.lock();
        s.register_hook(&g);
    }
    net.packet.insert(&s);
    Ok(s)
}

/// Bound to `dev`
fn bound_to(s: &PacketSock, dev: &NetDevice) -> bool {
    let (_, ifindex) = s.bound();
    ifindex > 0 && ifindex as u32 == dev.ifindex()
}

/// `dev` came up (Linux packet_notifier NETDEV_UP, RTNL held): a
/// socket bound to it with a protocol is hooked again
pub fn netdev_up(net: &crate::net::NetNamespace, dev: &NetDevice) {
    net.packet.for_each(|s| {
        if bound_to(s, dev) {
            let g = s.bind_lock.lock();
            if s.bound().0 != 0 {
                s.register_hook(&g);
            }
        }
    });
}

/// `dev` went down (Linux packet_notifier NETDEV_DOWN, RTNL held): a
/// socket hooked on it is unhooked and gets ENETDOWN, reported
/// (sk_error_report: POLLERR, a blocked receive wakes)
pub fn netdev_down(net: &crate::net::NetNamespace, dev: &NetDevice) {
    net.packet.for_each(|s| {
        if bound_to(s, dev) {
            let g = s.bind_lock.lock();
            s.unhook_err(&g);
        }
    });
}

/// `dev` is unregistered (Linux packet_notifier NETDEV_UNREGISTER):
/// its memberships go, and a socket bound to it is unhooked (ENETDOWN)
/// and left bound to no device (ifindex -1), so it receives nothing
/// and sends fail ENXIO
pub fn netdev_unregister(
    r: &crate::net::rtnl::RtnlGuard,
    net: &crate::net::NetNamespace,
    dev: &NetDevice,
) {
    // The device is unlisted already (unregister_netdevice): a bind
    // that found it stored its binding under bind_lock before this
    // visit, one that missed it failed ENODEV
    for s in net.packet.snapshot() {
        opts::mclist_delete(r, &s, dev);
        if bound_to(&s, dev) {
            let g = s.bind_lock.lock();
            s.unhook_err(&g);
            let (num, _) = s.bound();
            s.bind.store(pack(num, -1), Ordering::Release);
        }
    }
}

/// The `bind` word of (protocol, ifindex)
fn pack(proto: u16, ifindex: i32) -> u64 {
    (u64::from(proto) << 32) | u64::from(ifindex as u32)
}

fn unpack(w: u64) -> (u16, i32) {
    ((w >> 32) as u16, w as u32 as i32)
}

/// `PacketSock.bind_lock` held
type BindGuard<'a> = crate::sync::spin::MutexGuard<'a, ()>;

impl PacketSock {
    /// (protocol, ifindex) bound
    fn bound(&self) -> (u16, i32) {
        unpack(self.bind.load(Ordering::Acquire))
    }

    /// Hook the socket on the tap (Linux __register_prot_hook)
    fn register_hook(&self, _g: &BindGuard<'_>) {
        if !self.flag(pf::RUNNING) {
            if let Some(f) = self.fanout.lock().clone() {
                self.fanout_link(&f);
            }
            self.set_flag(pf::RUNNING, true);
        }
    }

    /// Clear RUNNING, out of the fanout group if in one
    fn unhook(&self) {
        if self.flag(pf::RUNNING)
            && let Some(f) = self.fanout.lock().clone()
        {
            self.fanout_unlink(&f);
        }
        self.set_flag(pf::RUNNING, false);
    }

    /// Unhook it (Linux __unregister_prot_hook): with `sync` the lock
    /// is dropped for a grace period, after which no tap still
    /// delivers by the old binding (Linux synchronize_net)
    fn unregister_hook<'a>(&'a self, g: BindGuard<'a>, sync: bool) -> BindGuard<'a> {
        self.unhook();
        if !sync {
            return g;
        }
        drop(g);
        crate::sync::rcu::synchronize();
        self.bind_lock.lock()
    }

    /// The device went: unhooked, ENETDOWN reported (Linux
    /// packet_notifier NETDEV_DOWN / UNREGISTER)
    fn unhook_err(&self, _g: &BindGuard<'_>) {
        if self.flag(pf::RUNNING) {
            self.unhook();
            self.sk.set_err(KernelError::NetworkDown);
        }
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

    /// Bind to the device `ifindex` (0: all) and `proto` (0: keep);
    /// Linux packet_do_bind
    fn do_bind(&self, ifindex: i32, proto: u16) -> Result<(), KernelError> {
        self.do_bind_dev(
            || match ifindex {
                0 => Ok(None),
                i => self.dev(i).map(Some).ok_or(KernelError::NoDevice),
            },
            proto,
        )
    }

    /// Linux packet_do_bind with the device lookup `lookup` (by index,
    /// or by name for SOCK_PACKET): ENODEV for an unknown device. A
    /// changed binding unhooks the socket, waits out the taps, then
    /// hooks it again, or reports ENETDOWN for a down device or one
    /// unregistered meanwhile ("unlisted": bound to no device, -1)
    fn do_bind_dev(
        &self,
        lookup: impl Fn() -> Result<Option<Arc<NetDevice>>, KernelError>,
        proto: u16,
    ) -> Result<(), KernelError> {
        let _sk = self.sk_lock.lock();
        let mut g = self.bind_lock.lock();
        let (cur, cur_if) = self.bound();
        let proto = if proto != 0 { proto } else { cur };
        if self.fanout.lock().is_some() {
            return Err(KernelError::InvalidArgument);
        }
        let dev = lookup()?;
        let new_if = dev.as_ref().map_or(0, |d| d.ifindex() as i32);
        // Linux compares po->prot_hook.dev, none once unlisted
        let need_rehook = cur != proto || cur_if.max(0) != new_if;
        let mut unlisted = false;
        if need_rehook {
            if self.flag(pf::RUNNING) {
                // Linux: po->num 0 keeps packet_notifier from hooking it
                self.bind.store(pack(0, cur_if), Ordering::Release);
                g = self.unregister_hook(g, true);
                unlisted = dev
                    .as_ref()
                    .is_some_and(|d| self.dev(d.ifindex() as i32).is_none());
            }
            let ifindex = if unlisted { -1 } else { new_if };
            self.bind.store(pack(proto, ifindex), Ordering::Release);
        }
        if proto == 0 || !need_rehook {
            return Ok(());
        }
        if !unlisted && dev.as_ref().is_none_or(|d| d.is_up()) {
            self.register_hook(&g);
        } else {
            self.sk.set_err(KernelError::NetworkDown);
        }
        Ok(())
    }

    /// PACKET_VNET_HDR's header size, 0 without
    fn vnet_hdr_len(&self) -> usize {
        self.vnet_hdr_sz.load(Ordering::Acquire) as usize
    }

    /// Identity for skipping our own outgoing frames
    fn id(&self) -> usize {
        core::ptr::from_ref::<Self>(self) as usize
    }

    fn dev(&self, ifindex: i32) -> Option<Arc<NetDevice>> {
        if ifindex <= 0 {
            return None;
        }
        self.sk.net.dev_get_by_index(ifindex as u32)
    }

    /// Destination of a send, from msg_name or the binding (Linux
    /// packet_snd)
    fn dest(&self, m: &SendMsg<'_>) -> Result<Dest, KernelError> {
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
        let mut skb = SkBuff::alloc(NET_SKB_PAD, data.len() + ETH_HLEN, Gfp::KERNEL)
            .ok_or(KernelError::NoBufferSpace)?;
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

/// A frame over the MTU may carry an 802.1Q tag (Linux
/// packet_extra_vlan_len_allowed, Ethernet devices)
fn extra_vlan_allowed(frame: &[u8]) -> bool {
    frame.get(12..14) == Some(&ETH_P_8021Q.to_be_bytes()[..])
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
        {
            // Linux packet_release: unhooked, po->num 0
            let g = self.bind_lock.lock();
            let _g = self.unregister_hook(g, false);
            let (_, ifindex) = self.bound();
            self.bind.store(pack(0, ifindex), Ordering::Release);
        }
        opts::flush_mclist(self);
        {
            // Linux packet_release: the rings go (closing: even mapped)
            let _sk = self.sk_lock.lock();
            if self.rx.lock().ring.is_some() {
                let _ = ring::set_ring(self, &ring::Req::default(), true, false);
            }
            if self.tx.lock().ring.is_some() {
                let _ = ring::set_ring(self, &ring::Req::default(), true, true);
            }
        }
        // Linux fanout_release: the group goes with its last member
        fanout::release(self);
        self.rxq.clear();
        self.sk.purge_err();
        // Linux packet_release's sock_put: the last reference
        self.sk.inuse_end();
    }

    /// Linux packet_bind: a sockaddr_ll
    fn bind(&self, a: &[u8]) -> Result<(), KernelError> {
        if self.spkt() {
            return self.bind_spkt(a);
        }
        if a.len() < SLL_LEN || u16::from_ne_bytes([a[0], a[1]]) != AF_PACKET {
            return Err(KernelError::InvalidArgument);
        }
        let sll = Sll::parse(a);
        self.do_bind(sll.ifindex, sll.protocol)
    }

    /// Linux packet_getname: no peer; the bound device's address
    fn getname(&self, peer: bool) -> Result<Vec<u8>, KernelError> {
        if self.spkt() {
            return self.getname_spkt(peer);
        }
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

    /// Linux packet_poll: datagram_poll, and readable while the ring
    /// has a filled frame
    fn poll(&self) -> u16 {
        fanout::try_clear_pressure(self);
        let mut mask = self.rxq.poll(&self.sk);
        if self.ring_readable() {
            mask |= crate::io::poll::POLLIN | crate::io::poll::POLLRDNORM;
        }
        if tx::tx_writable(self) {
            mask |= crate::io::poll::POLLOUT | crate::io::poll::POLLWRNORM;
        }
        mask
    }

    /// Linux packet_mmap (SOCK_PACKET: sock_no_mmap)
    fn mmap(&self) -> Result<(), KernelError> {
        if self.spkt() {
            return Err(KernelError::NoDevice);
        }
        Ok(())
    }

    /// Linux packet_mmap: from offset 0 only
    fn mmap_offset(&self, off: u64) -> Result<(), KernelError> {
        if off != 0 {
            return Err(KernelError::InvalidArgument);
        }
        Ok(())
    }

    fn mmap_hold(&self, len: u64) -> Result<Option<crate::mm::vma::VmHold>, KernelError> {
        ring::mmap_hold(self, len)
    }

    // SAFETY: ring pages, which hold only frames shared with user
    // space; each handed out with a reference (`PgVec::map_page`)
    unsafe fn map_page(&self, idx: u64) -> Option<u64> {
        ring::map_page(self, idx)
    }

    /// SIOCINQ: length of the next frame; SIOCOUTQ: nothing is queued
    fn ioctl(&self, cmd: u32, arg: u64) -> Result<i64, KernelError> {
        let v = match cmd {
            SIOCINQ => self.rxq.inq(),
            SIOCOUTQ => 0,
            _ => return Err(KernelError::NotTty),
        };
        crate::uaccess::put_user::<i32>(arg, v as i32).map_err(|_| KernelError::BadAddress)?;
        Ok(0)
    }

    fn inq(&self) -> usize {
        self.rxq.inq()
    }

    /// SOCK_PACKET has no setsockopt/getsockopt (Linux: EOPNOTSUPP
    /// past SOL_SOCKET)
    fn setsockopt(&self, level: i32, opt: i32, v: OptIn) -> Option<Result<(), KernelError>> {
        if self.spkt() && level != crate::net::socket::SOL_SOCKET {
            return Some(Err(KernelError::OperationNotSupported));
        }
        opts::set(self, level, opt, v)
    }

    fn getsockopt(&self, level: i32, opt: i32) -> Option<Result<OptOut, KernelError>> {
        if self.spkt() && level != crate::net::socket::SOL_SOCKET {
            return Some(Err(KernelError::OperationNotSupported));
        }
        opts::get(self, level, opt, None)
    }

    fn getsockopt_in(&self, level: i32, opt: i32, v: OptIn) -> Option<Result<OptOut, KernelError>> {
        if self.spkt() && level != crate::net::socket::SOL_SOCKET {
            return Some(Err(KernelError::OperationNotSupported));
        }
        opts::get(self, level, opt, Some(v))
    }

    /// Linux packet_snd
    fn sendmsg(&self, m: &mut SendMsg<'_>, flags: i32) -> Result<usize, KernelError> {
        if self.spkt() {
            return self.sendmsg_spkt(m);
        }
        // Linux packet_sendmsg: a transmit ring sends its frames
        // (checked again under pg_vec_lock)
        if self.tx.lock().ring.is_some() {
            return tx::tpacket_snd(self, m, flags);
        }
        let Dest { dev, proto, addr } = self.dest(m)?;
        if !dev.is_up() {
            return Err(KernelError::NetworkDown);
        }
        let total = m.data.len();
        // Linux packet_snd_vnet_parse: the header first
        let vnet = self.vnet_hdr_len();
        let mut hdr = vnet::VnetHdr::default();
        if vnet != 0 {
            if total < vnet {
                return Err(KernelError::InvalidArgument);
            }
            hdr = vnet::VnetHdr::parse(&m.data.take(vnet::VNET_HDR_LEN)?);
            vnet::snd_parse(&mut hdr, total - vnet)?;
        }
        let len = total - vnet;
        let mtu = dev.mtu() as usize;
        let gso = hdr.gso_type != 0;
        if !gso && len > mtu + ETH_HLEN + VLAN_HLEN {
            return Err(KernelError::MessageTooLong);
        }
        let mut data = m.data.take_at(vnet, len)?;
        if gso {
            if self.sk.stype == SOCK_RAW && data.len() < ETH_HLEN {
                return Err(KernelError::InvalidArgument);
            }
        } else {
            check_len(self.sk.stype, mtu, &data)?;
        }
        if vnet != 0 {
            vnet::to_frame(&hdr, &mut data)?;
        }
        let mut skb = self.build(&dev, proto, addr, &data)?;
        skb.dev = Some(dev);
        skb.owner = self.id();
        crate::net::dev::dev_queue_xmit(skb)?;
        Ok(total)
    }

    /// Linux packet_recvmsg
    fn recvmsg(&self, m: &mut RecvMsg<'_>, flags: i32) -> Result<usize, KernelError> {
        let ok = MSG_PEEK | MSG_DONTWAIT | MSG_TRUNC | MSG_ERRQUEUE;
        if flags & !ok != 0 {
            return Err(KernelError::InvalidArgument);
        }
        if flags & MSG_ERRQUEUE != 0 {
            // Nothing is ever queued (no TX timestamps)
            return Err(KernelError::WouldBlock);
        }
        let f = self.rxq.recv(&self.sk, flags)?;
        fanout::try_clear_pressure(self);
        rcv::deliver(self, m, &f, flags)
    }
}

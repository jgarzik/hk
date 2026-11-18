//! UDP (Linux net/ipv4/udp.c, datagram.c)
//!
//! Sockets live in the UDP table (Linux udp_table: hash slots by
//! namespace and local port, sized from memory at boot), from
//! bind/autobind until close (or disconnect of an autobound port).
//! Binding follows Linux SO_REUSEADDR/SO_REUSEPORT rules
//! (`inet::port::conflict`); ephemeral ports come from
//! `ip_local_port_range` at a keyed-hash offset. Receive lookup scores
//! candidates like Linux compute_score (exact address, connected peer,
//! bound device), spreads a SO_REUSEPORT group by flow hash, and
//! delivers broadcasts to every matching socket. The receive queue is
//! bounded by SO_RCVBUF (drops counted); checksums are verified on
//! receive.
//!
//! ## Locking (thread context only)
//!
//! Order: `UdpSock.op` (sleeping `sync::Mutex`, Linux lock_sock:
//! bind/connect/autobind, socket calls only) -> a hash slot's lock
//! (spin, Linux hslot->lock; one at a time) -> `REUSEPORT_LOCK` ->
//! `Inet.addr` (Mutex leaf); `UdpSock.rxq` is a separate leaf. Receive
//! and ICMP-error lookups walk a slot under RCU (Linux
//! __udp4_lib_lookup, __udp4_lib_mcast_deliver), reading each
//! candidate's `Inet.addr`, and queue under the guard with GFP_ATOMIC.
//! A socket's table reference is released a grace period after it
//! leaves (Linux SOCK_RCU_FREE), possibly in `rcuc/N`: its drop takes
//! no sleeping lock. No lock is held across a sleep or a transmit.

use crate::mm::page_alloc::Gfp;
use crate::net::mib::INUSE_UDP;
use crate::util::kalloc::try_arc_cyclic;
use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::net::sock_reuseport::{self, ReuseCb};
use crate::sync::rcu::RcuPuts;
use crate::util::hlist_nulls::{NullsHead, NullsLink};

use crate::net::af_inet::{
    self, IP_PKTINFO, IP_TOS, IP_TTL, IPPROTO_UDP, Inet, InetAddr, RxInfo, SOL_IP,
};
use crate::net::dgram::{self, RxQueue};
use crate::net::inet::fib::RouteType;
use crate::net::inet::port::{self, BindInfo, Flow, Parity};
use crate::net::inet::route;
use crate::net::ipv4::{self, IpParams, Ipv4Addr};
use crate::net::mib::*;
use crate::net::msg::{MSG_ERRQUEUE, MSG_OOB, MSG_PEEK, RecvMsg, SendMsg, cmsgs};
use crate::net::skb::SkBuff;
use crate::net::sock::{SHUTDOWN_MASK, Sock, sf};
use crate::net::socket::{
    AF_INET, AF_UNSPEC, OptIn, OptOut, ProtoOps, SIOCINQ, SIOCOUTQ, SOCK_DGRAM, SOL_SOCKET,
    shut_bits,
};
use crate::util::error::KernelError;

/// UDP header length
pub const UDP_HLEN: usize = 8;
/// Largest payload (65535 - IP and UDP headers)
pub const UDP_MAX: usize = 65507;
/// Socket level of UDP options
pub const SOL_UDP: i32 = 17;
/// A UDP socket
pub struct UdpSock {
    sk: Sock,
    pub inet: Inet,
    /// Socket lock: bind/connect/disconnect/autobind (Linux lock_sock,
    /// which sleeps)
    op: crate::sync::Mutex<()>,
    /// Connected (Linux TCP_ESTABLISHED state for datagram sockets)
    connected: AtomicBool,
    rxq: RxQueue,
    /// Link on its port's hash slot (Linux sk_node)
    link: NullsLink,
    /// Its SO_REUSEPORT group (Linux sk_reuseport_cb)
    reuse: ReuseCb<UdpSock>,
    /// The table reference's deferred release (Linux SOCK_RCU_FREE)
    rcu: RcuPuts,
    me: Weak<UdpSock>,
}

/// socket(AF_INET, SOCK_DGRAM, 0)
pub fn create() -> Result<Arc<dyn ProtoOps>, KernelError> {
    let net = crate::net::current_net_ns();
    Ok(try_arc_cyclic(|me| UdpSock {
        sk: Sock::new(net, AF_INET, SOCK_DGRAM, IPPROTO_UDP),
        inet: Inet::default(),
        op: crate::sync::Mutex::new(()),
        connected: AtomicBool::new(false),
        rxq: RxQueue::default(),
        link: NullsLink::new(),
        reuse: ReuseCb::new(),
        rcu: RcuPuts::new(),
        me: me.clone(),
    })?)
}

impl UdpSock {
    fn arc(&self) -> Arc<UdpSock> {
        self.me.upgrade().expect("udp socket alive")
    }

    /// How this socket looks to the bind rules (address `addr`)
    fn bind_info(&self, addr: Ipv4Addr) -> BindInfo {
        BindInfo {
            addr,
            dev: self.sk.bound_dev_if(),
            reuse: self.sk.flag(sf::REUSEADDR),
            reuseport: self.sk.flag(sf::REUSEPORT),
            uid: self.sk.cred.euid,
            ..Default::default()
        }
    }

    /// Claim `port` (0 = ephemeral) for receive address `addr`; caller
    /// holds `op`. Returns the port.
    fn get_port(&self, addr: Ipv4Addr, port: u16) -> Result<u16, KernelError> {
        let me = self.arc();
        let info = self.bind_info(addr);
        let flow = Flow {
            proto: IPPROTO_UDP as u8,
            saddr: addr,
            ..Default::default()
        };
        let p = udp_lib_get_port(&me, &info, port, flow)?;
        // Linux udp_lib_get_port
        self.sk.net.mib.inuse_add(INUSE_UDP, true);
        Ok(p)
    }

    /// Linux inet_autobind: an ephemeral port on the bound address
    fn autobind(&self) -> Result<(), KernelError> {
        let _g = self.op.lock();
        self.autobind_locked()
    }

    /// `autobind` with `op` held
    fn autobind_locked(&self) -> Result<(), KernelError> {
        let a = self.inet.get();
        if a.sport != 0 {
            return Ok(());
        }
        let p = self
            .get_port(a.rcv_saddr, 0)
            .map_err(|_| KernelError::WouldBlock)?;
        self.inet.addr.lock().sport = p;
        Ok(())
    }

    /// Linux udp_lib_unhash: off its slot and out of its group; the
    /// table's reference goes after a grace period
    fn unhash(&self) {
        let port = self.inet.get().sport;
        let mut g = slot(&self.sk.net, port).lock();
        self.reuse.detach(self, &mut sock_reuseport::lock());
        if let Some(u) = g.del_rcu(self) {
            drop(g);
            u.defer();
            self.sk.net.mib.inuse_add(INUSE_UDP, false);
        }
    }

    /// Linux __udp_disconnect
    fn disconnect(&self) {
        let _g = self.op.lock();
        self.connected.store(false, Ordering::Release);
        let unhash = {
            let mut a = self.inet.addr.lock();
            a.daddr = Ipv4Addr::default();
            a.dport = 0;
            if !a.addr_lock {
                a.rcv_saddr = Ipv4Addr::default();
                a.saddr = Ipv4Addr::default();
            }
            !a.port_lock
        };
        if unhash {
            self.unhash();
            self.inet.addr.lock().sport = 0;
        }
    }

    // --- send ------------------------------------------------------------

    /// Destination of a send: msg_name or the connected peer
    fn dest(&self, m: &SendMsg<'_>) -> Result<(Ipv4Addr, u16, bool), KernelError> {
        if let Some(a) = &m.addr {
            let (addr, port) = af_inet::sin_parse(a, true)?;
            if port == 0 {
                return Err(KernelError::InvalidArgument);
            }
            return Ok((addr, port, false));
        }
        if !self.connected.load(Ordering::Acquire) {
            return Err(KernelError::DestAddrRequired);
        }
        let a = self.inet.get();
        Ok((a.daddr, a.dport, true))
    }

    /// Output route checked for broadcast permission (EACCES without
    /// SO_BROADCAST)
    fn route(
        &self,
        daddr: Ipv4Addr,
        saddr: Ipv4Addr,
        oif: u32,
    ) -> Result<route::Rtable, KernelError> {
        let rt = route::output(&self.sk.net, daddr, saddr, oif)
            .inspect_err(|e| self.sk.net.mib.route_err(e))?;
        if rt.rtype == RouteType::Broadcast && !self.sk.flag(sf::BROADCAST) {
            return Err(KernelError::PermissionDenied);
        }
        Ok(rt)
    }

    /// IP_MTU: path MTU towards the connected peer (Linux: ENOTCONN
    /// without a cached route)
    fn mtu(&self) -> Result<i32, KernelError> {
        if !self.connected.load(Ordering::Acquire) {
            return Err(KernelError::NotConnected);
        }
        let a = self.inet.get();
        let rt = route::output(&self.sk.net, a.daddr, a.saddr, self.sk.bound_dev_if())
            .map_err(|_| KernelError::NotConnected)?;
        Ok(rt.mtu as i32)
    }

    /// Build and send one datagram: whether it went out, false if the
    /// send's ENOBUFS was swallowed (`send_err`)
    fn xmit(
        &self,
        rt: &route::Rtable,
        sport: u16,
        dport: u16,
        data: &[u8],
        p: IpParams,
    ) -> Result<bool, KernelError> {
        // Linux __ip_append_data's error path counts the discard
        let nobufs = || {
            self.sk.net.mib.out_discard();
            KernelError::NoBufferSpace
        };
        let mut skb = SkBuff::alloc_tx(UDP_HLEN + data.len(), Gfp::KERNEL).ok_or_else(nobufs)?;
        skb.put_slice(data).ok_or_else(nobufs)?;
        let h = skb.push(UDP_HLEN).ok_or_else(nobufs)?;
        h[0..2].copy_from_slice(&sport.to_be_bytes());
        h[2..4].copy_from_slice(&dport.to_be_bytes());
        h[4..6].copy_from_slice(&((UDP_HLEN + data.len()) as u16).to_be_bytes());
        h[6..8].copy_from_slice(&[0, 0]);
        let saddr = rt.saddr;
        let csum = udp_checksum(saddr, rt.daddr, skb.data());
        skb.data_mut()[6..8].copy_from_slice(&csum.to_be_bytes());
        skb.saddr = Some(saddr);
        skb.daddr = Some(rt.daddr);
        // Linux udp_send_skb: what ip_send_skb failed with
        match ipv4::ip_send_rt(&self.sk.net, rt, skb, IPPROTO_UDP as u8, p) {
            Ok(()) => Ok(true),
            // Linux __ip_append_data: no discard counted
            Err(KernelError::MessageTooLong) => Err(KernelError::MessageTooLong),
            Err(e) => {
                let mib = &self.sk.net.mib;
                // ip_send_skb counts the discard either way
                mib.out_discard();
                match send_err(e, self.inet.flag(af_inet::ipf::RECVERR)) {
                    Some(e) => Err(e),
                    None => {
                        mib.udp.inc(UDP_MIB_SNDBUFERRORS);
                        Ok(false)
                    }
                }
            }
        }
    }
}

/// What the sender sees of a send that failed past building the
/// datagram (Linux udp_send_skb): ENOBUFS (a full device queue) is
/// swallowed, None, unless IP_RECVERR asks for errors
fn send_err(e: KernelError, recverr: bool) -> Option<KernelError> {
    (e != KernelError::NoBufferSpace || recverr).then_some(e)
}

/// Per-message IP parameters from sendmsg control data (Linux
/// ip_cmsg_send: IP_PKTINFO, IP_TTL, IP_TOS)
#[derive(Default)]
pub struct TxCmsg {
    pub oif: u32,
    pub saddr: Ipv4Addr,
    pub ttl: Option<u8>,
    pub tos: Option<u8>,
}

pub fn tx_cmsgs(c: &[u8]) -> Result<TxCmsg, KernelError> {
    let mut t = TxCmsg::default();
    for r in cmsgs(c) {
        let (level, ty, d) = r?;
        if level == SOL_SOCKET {
            // Linux __sock_cmsg_send: SCM_RIGHTS/SCM_CREDENTIALS are
            // ignored on non-unix sockets, SO_MARK/SO_PRIORITY/
            // SO_TIMESTAMPING/SCM_TXTIME accepted, anything else EINVAL
            if !matches!(ty, 1 | 2 | 12 | 36 | 37 | 61) {
                return Err(KernelError::InvalidArgument);
            }
            continue;
        }
        if level != SOL_IP {
            continue;
        }
        let int = || -> Result<i32, KernelError> {
            match d.len() {
                4 => Ok(i32::from_ne_bytes([d[0], d[1], d[2], d[3]])),
                1 => Ok(i32::from(d[0])),
                _ => Err(KernelError::InvalidArgument),
            }
        };
        match ty {
            IP_PKTINFO => {
                if d.len() != 12 {
                    return Err(KernelError::InvalidArgument);
                }
                t.oif = u32::from_ne_bytes([d[0], d[1], d[2], d[3]]);
                t.saddr = Ipv4Addr::from_be_bytes([d[4], d[5], d[6], d[7]]);
            }
            IP_TTL => {
                let v = int()?;
                if !(1..=255).contains(&v) {
                    return Err(KernelError::InvalidArgument);
                }
                t.ttl = Some(v as u8);
            }
            IP_TOS => {
                let v = int()?;
                if !(0..=255).contains(&v) {
                    return Err(KernelError::InvalidArgument);
                }
                t.tos = Some(v as u8);
            }
            _ => return Err(KernelError::InvalidArgument),
        }
    }
    Ok(t)
}

impl ProtoOps for UdpSock {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn sk(&self) -> &Sock {
        &self.sk
    }

    fn release(&self) {
        self.unhash();
        self.sk.set_shutdown(SHUTDOWN_MASK);
        self.rxq.clear();
        self.sk.purge_err();
    }

    /// Linux inet_bind for UDP
    fn bind(&self, a: &[u8]) -> Result<(), KernelError> {
        let (addr, port, ty) = af_inet::bind_check(&self.sk, &self.inet, a)?;
        let _g = self.op.lock();
        if self.inet.get().sport != 0 {
            return Err(KernelError::InvalidArgument);
        }
        let no_port = port == 0 && self.inet.flag(af_inet::ipf::BIND_NO_PORT);
        // Like Linux inet_bind: the address is set before the port table
        // entry is published (lookups read it under the table lock) and
        // reset if that fails
        let saddr = if matches!(ty, RouteType::Multicast | RouteType::Broadcast) {
            Ipv4Addr::default()
        } else {
            addr
        };
        self.inet.set_saddrs(addr, saddr);
        let p = if no_port {
            0
        } else {
            match self.get_port(addr, port) {
                Ok(p) => p,
                Err(e) => {
                    self.inet
                        .set_saddrs(Ipv4Addr::default(), Ipv4Addr::default());
                    return Err(e);
                }
            }
        };
        let mut s = self.inet.addr.lock();
        s.sport = p;
        s.addr_lock = !addr.is_unspecified();
        s.port_lock = port != 0;
        Ok(())
    }

    /// Linux inet_dgram_connect + __ip4_datagram_connect
    fn connect(&self, a: &[u8], _nonblock: bool) -> Result<(), KernelError> {
        if af_inet::sa_family(a)? == AF_UNSPEC {
            self.disconnect();
            return Ok(());
        }
        let (daddr, dport) = af_inet::sin_parse(a, false)?;
        // One socket-lock hold for autobind and the connect (Linux
        // lock_sock around both)
        let _g = self.op.lock();
        self.autobind_locked()?;
        let cur = self.inet.get();
        let rt = self.route(daddr, cur.saddr, self.sk.bound_dev_if())?;
        let mut s = self.inet.addr.lock();
        if s.saddr.is_unspecified() {
            s.saddr = rt.saddr;
        }
        if s.rcv_saddr.is_unspecified() {
            s.rcv_saddr = rt.saddr;
        }
        s.daddr = rt.daddr;
        s.dport = dport;
        drop(s);
        self.connected.store(true, Ordering::Release);
        // Linux __ip4_datagram_connect: reuseport_has_conns_set
        self.reuse.set_conns(&sock_reuseport::lock());
        Ok(())
    }

    fn getname(&self, peer: bool) -> Result<Vec<u8>, KernelError> {
        let a = self.inet.get();
        if peer {
            if !self.connected.load(Ordering::Acquire) {
                return Err(KernelError::NotConnected);
            }
            return Ok(af_inet::sin_bytes(a.daddr, a.dport));
        }
        let addr = if a.rcv_saddr.is_unspecified() {
            a.saddr
        } else {
            a.rcv_saddr
        };
        Ok(af_inet::sin_bytes(addr, a.sport))
    }

    /// Linux udp_poll / datagram_poll
    fn poll(&self) -> u16 {
        dgram::poll(&self.sk, &self.rxq)
    }

    fn ioctl(&self, cmd: u32, arg: u64) -> Result<i64, KernelError> {
        let v = match cmd {
            SIOCINQ => self.inq(),
            SIOCOUTQ => 0,
            _ => return Err(KernelError::NotTty),
        };
        crate::uaccess::put_user::<i32>(arg, v as i32).map_err(|_| KernelError::BadAddress)?;
        Ok(0)
    }

    /// Payload length of the first queued datagram (Linux
    /// first_packet_length)
    fn inq(&self) -> usize {
        self.rxq.inq()
    }

    /// Linux inet_shutdown for datagram sockets: ENOTCONN when not
    /// connected (the shutdown bits are still set, waking pollers)
    fn shutdown(&self, how: i32) -> Result<(), KernelError> {
        let bits = shut_bits(how)?;
        self.sk.set_shutdown(bits);
        if !self.connected.load(Ordering::Acquire) {
            return Err(KernelError::NotConnected);
        }
        Ok(())
    }

    fn setsockopt(&self, level: i32, opt: i32, v: OptIn) -> Option<Result<(), KernelError>> {
        match level {
            SOL_SOCKET => None,
            SOL_IP => Some(self.inet.setsockopt(&self.sk, opt, v)),
            _ => Some(Err(KernelError::NoProtocolOption)),
        }
    }

    fn getsockopt(&self, level: i32, opt: i32) -> Option<Result<OptOut, KernelError>> {
        match level {
            SOL_SOCKET => None,
            SOL_IP if opt == af_inet::IP_MTU => Some(self.mtu().map(OptOut::Int)),
            SOL_IP => Some(self.inet.getsockopt(opt)),
            SOL_UDP => Some(Err(KernelError::NoProtocolOption)),
            // Linux do_ip_getsockopt: other levels are EOPNOTSUPP
            _ => Some(Err(KernelError::OperationNotSupported)),
        }
    }

    /// Linux udp_sendmsg
    fn sendmsg(&self, m: &mut SendMsg<'_>, flags: i32) -> Result<usize, KernelError> {
        if flags & MSG_OOB != 0 {
            return Err(KernelError::OperationNotSupported);
        }
        let len = m.data.len();
        if len > UDP_MAX {
            return Err(KernelError::MessageTooLong);
        }
        let (daddr, dport, _connected) = self.dest(m)?;
        let c = tx_cmsgs(&m.control)?;
        let data = m.data.take(len)?;
        self.autobind()?;
        let a: InetAddr = self.inet.get();
        let oif = if c.oif != 0 {
            c.oif
        } else {
            self.sk.bound_dev_if()
        };
        let saddr = if c.saddr.is_unspecified() {
            a.saddr
        } else {
            c.saddr
        };
        let rt = self.route(daddr, saddr, oif)?;
        let mut p = self.inet.params();
        p.tos = c.tos.unwrap_or(p.tos);
        p.ttl = c.ttl.unwrap_or(p.ttl);
        // Linux sock_alloc_send_pskb: a pending (ICMP) error first
        if let Some(e) = self.sk.take_err() {
            return Err(e);
        }
        let mib = &self.sk.net.mib;
        match self.xmit(&rt, a.sport, dport, &data, p) {
            Ok(sent) => {
                // Linux udp_send_skb
                if sent {
                    mib.udp.inc(UDP_MIB_OUTDATAGRAMS);
                }
                Ok(len)
            }
            Err(KernelError::MessageTooLong) => {
                // Linux __ip_append_data: IP_RECVERR also queues it
                // (msg_name port: the connected one)
                let e = KernelError::MessageTooLong;
                af_inet::ip_local_error(&self.sk, &self.inet, e, daddr, a.dport, rt.mtu);
                Err(e)
            }
            Err(e) => {
                // Linux udp_sendmsg's out: no kernel memory (the
                // discard counted where it failed)
                if e == KernelError::NoBufferSpace {
                    mib.udp.inc(UDP_MIB_SNDBUFERRORS);
                }
                Err(e)
            }
        }
    }

    /// Linux udp_recvmsg
    fn recvmsg(&self, m: &mut RecvMsg<'_>, flags: i32) -> Result<usize, KernelError> {
        if flags & MSG_ERRQUEUE != 0 {
            return af_inet::ip_recv_error(&self.sk, &self.inet, m);
        }
        let Some(d) = self.rxq.recv(&self.sk, flags)? else {
            return Ok(0);
        };
        let r = dgram::deliver(&self.sk, &self.inet, m, &d, flags);
        if flags & MSG_PEEK == 0 {
            // Linux udp_recvmsg: a datagram is counted when it is read
            let f = if r.is_ok() {
                UDP_MIB_INDATAGRAMS
            } else {
                UDP_MIB_INERRORS
            };
            self.sk.net.mib.udp.inc(f);
        }
        r
    }
}

// ============================================================================
// Socket table
// ============================================================================

crate::nulls_adapter!(UdpHash, UdpSock, link);
crate::rcu_puts!(UdpSock, rcu);

/// Hash slots of every namespace (Linux udp_table.hash)
static UDP_TABLE: spin::Once<Box<[NullsHead<UdpHash>]>> = spin::Once::new();

/// Size the table from memory (Linux udp_table_init:
/// alloc_large_system_hash with one slot per 2 MiB, a power of two
/// between UDP_HTABLE_SIZE_MIN and 64 Ki slots)
pub fn init() {
    let n = (crate::FRAME_ALLOCATOR.buffer_pages() >> 9)
        .next_power_of_two()
        .clamp(256, 1 << 16);
    UDP_TABLE.call_once(|| NullsHead::table(n).expect("udp: hash table"));
}

fn table() -> &'static [NullsHead<UdpHash>] {
    UDP_TABLE.get().expect("udp table not initialized")
}

/// Linux udp_hashfn: the port plus the namespace's random mix, masked
fn slot_index(net: &crate::net::NetNamespace, port: u16) -> usize {
    (usize::from(port).wrapping_add(net.hash_mix as usize)) & (table().len() - 1)
}

fn slot(net: &crate::net::NetNamespace, port: u16) -> &'static NullsHead<UdpHash> {
    &table()[slot_index(net, port)]
}

/// Address `s` is bound to (for the bind rules), read under the slot
/// lock (order: slot -> Inet.addr)
fn bound_addr(s: &UdpSock) -> Ipv4Addr {
    s.inet.get().rcv_saddr
}

/// Another socket of `net` on `port` conflicts with `info` (Linux
/// udp_lib_lport_inuse), the slot locked
fn inuse(
    g: &crate::util::hlist_nulls::NullsGuard<'_, UdpHash>,
    net: u64,
    port: u16,
    info: &BindInfo,
) -> bool {
    g.find(|o| {
        o.sk.net.id == net
            && o.inet.get().sport == port
            && port::conflict(info, &o.bind_info(bound_addr(o)), false)
    })
    .is_some()
}

/// Hash `s` on `port` (0 = an ephemeral port) and set the port, all
/// under the slot's lock, joining or starting a SO_REUSEPORT group
/// (Linux udp_lib_get_port, udp_reuseport_add_sock): EADDRINUSE on a
/// conflict, when the range is exhausted, or when the group cannot
/// grow
fn udp_lib_get_port(
    s: &Arc<UdpSock>,
    info: &BindInfo,
    port: u16,
    flow: Flow,
) -> Result<u16, KernelError> {
    let net = &*s.sk.net;
    let take = |p: u16| -> Option<Result<u16, KernelError>> {
        let mut g = slot(net, p).lock();
        if inuse(&g, net.id, p, info) {
            return None;
        }
        if s.sk.flag(sf::REUSEPORT) && reuseport_add(&g, s, p, info).is_err() {
            return Some(Err(KernelError::AddressInUse));
        }
        s.inet.addr.lock().sport = p;
        g.add_head_rcu(s.clone());
        Some(Ok(p))
    };
    if port != 0 {
        return take(port).unwrap_or(Err(KernelError::AddressInUse));
    }
    let mut r = None;
    let range = net.port_range.get();
    port::ephemeral(range, flow, Parity::Any, |p| {
        r = take(p);
        r.is_some()
    });
    r.unwrap_or(Err(KernelError::AddressInUse))
}

/// Join the group of a socket on `port` with the same owner, device
/// and address, or start one (Linux udp_reuseport_add_sock)
fn reuseport_add(
    g: &crate::util::hlist_nulls::NullsGuard<'_, UdpHash>,
    s: &Arc<UdpSock>,
    port: u16,
    info: &BindInfo,
) -> Result<(), KernelError> {
    let net = s.sk.net.id;
    let peer = g.find(|o| {
        o.sk.net.id == net
            && o.inet.get().sport == port
            && o.sk.flag(sf::REUSEPORT)
            && o.sk.cred.euid == info.uid
            && o.sk.bound_dev_if() == info.dev
            && bound_addr(o) == info.addr
    });
    let mut o = sock_reuseport::lock();
    match peer {
        Some(p) => s.reuse.add(s, &p.reuse, &mut o),
        None => s.reuse.alloc(s, &mut o),
    }
}

/// A received datagram's addressing
#[derive(Clone, Copy)]
struct Key {
    saddr: Ipv4Addr,
    sport: u16,
    daddr: Ipv4Addr,
    dport: u16,
    dif: u32,
}

/// Linux compute_score: -1 = no match
fn score(s: &UdpSock, k: &Key) -> i32 {
    let a = s.inet.get();
    if a.rcv_saddr != k.daddr && !a.rcv_saddr.is_unspecified() {
        return -1;
    }
    let mut sc = 2;
    if !a.rcv_saddr.is_unspecified() {
        sc += 4;
    }
    if s.connected.load(Ordering::Acquire) {
        if a.daddr != k.saddr || a.dport != k.sport {
            return -1;
        }
        sc += 8;
    }
    let dev = s.sk.bound_dev_if();
    if dev != 0 {
        if dev != k.dif {
            return -1;
        }
        sc += 4;
    }
    sc
}

/// Linux udp_ehashfn: a keyed hash of the flow, for a reuseport pick
fn flow_hash(net: &crate::net::NetNamespace, k: &Key) -> u32 {
    port::secure_hash(
        0x7564_7065_6861,
        &[
            net.id,
            (u64::from(k.saddr.0) << 32) | u64::from(k.daddr.0),
            (u64::from(k.sport) << 16) | u64::from(k.dport),
        ],
    ) as u32
}

/// Best socket for a unicast datagram (Linux udp4_lib_lookup2): each
/// candidate scored once in a single walk under RCU, so a concurrent
/// connect() or SO_BINDTODEVICE cannot make a second look disagree. A
/// new best that is unconnected and in a SO_REUSEPORT group hands over
/// to the member the flow hash picks; with connected members in the
/// group, the pick is scored instead (Linux reuseport_has_conns).
fn lookup(net: &crate::net::NetNamespace, k: &Key) -> Option<Arc<UdpSock>> {
    let head = slot(net, k.dport);
    let h = flow_hash(net, k);
    let g = crate::sync::rcu::read_lock();
    loop {
        let mut best: Option<(i32, &UdpSock)> = None;
        let mut it = head.iter_rcu(&g);
        for e in it.by_ref() {
            let s = e.get();
            if s.sk.net.id != net.id || s.inet.get().sport != k.dport {
                continue;
            }
            let sc = score(s, k);
            if sc < 0 || best.is_some_and(|b| sc <= b.0) {
                continue;
            }
            best = Some((sc, s));
            if s.connected.load(Ordering::Acquire) {
                continue;
            }
            if let Some((r, conns)) = s.reuse.select(h, &g) {
                best = Some((if conns { score(r, k) } else { sc }, r));
            }
        }
        if it.ended_at() == Some(head.nulls()) {
            return best.filter(|b| b.0 >= 0).and_then(|b| b.1.me.upgrade());
        }
    }
}

/// Linux __udp_is_mcast_sock: broadcast receivers
fn bcast_match(s: &UdpSock, k: &Key) -> bool {
    let a = s.inet.get();
    let conn = s.connected.load(Ordering::Acquire);
    let dev = s.sk.bound_dev_if();
    !(conn && (a.daddr != k.saddr || (a.dport != 0 && a.dport != k.sport))
        || (!a.rcv_saddr.is_unspecified() && a.rcv_saddr != k.daddr)
        || (dev != 0 && dev != k.dif))
}

/// Receive a UDP packet (from ip_rcv; thread context; the device's
/// namespace). The skb itself is queued to the socket, trimmed to the
/// datagram and pulled to its payload (Linux __udp4_lib_rcv ->
/// udp_queue_rcv_skb).
pub fn udp_rcv(mut skb: SkBuff) {
    let (Some(net), Some(saddr), Some(daddr)) = (skb.net(), skb.saddr, skb.daddr) else {
        return;
    };
    let udp = &net.mib.udp;
    let b = skb.data();
    if b.len() < UDP_HLEN {
        udp.inc(UDP_MIB_INERRORS);
        return;
    }
    let ulen = u16::from_be_bytes([b[4], b[5]]) as usize;
    if ulen < UDP_HLEN || ulen > b.len() {
        // Linux short_packet
        udp.inc(UDP_MIB_INERRORS);
        return;
    }
    let pkt = &b[..ulen];
    if u16::from_be_bytes([b[6], b[7]]) != 0 && !csum_ok(saddr, daddr, pkt) {
        udp.inc(UDP_MIB_CSUMERRORS);
        udp.inc(UDP_MIB_INERRORS);
        return;
    }
    let dif = skb.dev.as_ref().map_or(0, |d| d.ifindex());
    let k = Key {
        saddr,
        sport: u16::from_be_bytes([b[0], b[1]]),
        daddr,
        dport: u16::from_be_bytes([b[2], b[3]]),
        dif,
    };
    let pad = b.len() - ulen;
    let info = RxInfo::of(&net, &skb);
    if skb.trim(pad).is_none() || skb.pull(UDP_HLEN).is_none() {
        udp.inc(UDP_MIB_INERRORS);
        return;
    }
    dgram::prepare(&mut skb, info, k.sport);
    if skb.ip_bcast || daddr.is_multicast() {
        return mcast_deliver(&net, skb, &k);
    }
    match lookup(&net, &k) {
        Some(s) => queue_rcv(&net, &s, skb),
        None => {
            udp.inc(UDP_MIB_NOPORTS);
            crate::net::icmp::port_unreach(&net, &skb);
        }
    }
}

/// Queue a datagram to `s`, counting a drop (Linux __udp_queue_rcv_skb:
/// a full buffer is RcvbufErrors, no memory MemErrors, both InErrors)
fn queue_rcv(net: &crate::net::NetNamespace, s: &UdpSock, skb: SkBuff) {
    let Err(e) = s.rxq.enqueue(&s.sk, skb) else {
        return;
    };
    let udp = &net.mib.udp;
    udp.inc(match e {
        dgram::QueueErr::RcvBuf => UDP_MIB_RCVBUFERRORS,
        dgram::QueueErr::NoMem => UDP_MIB_MEMERRORS,
    });
    udp.inc(UDP_MIB_INERRORS);
}

/// A broadcast or multicast datagram to every matching socket (Linux
/// __udp4_lib_mcast_deliver): each but the first gets a clone made
/// GFP_ATOMIC (a failed clone counts a drop on that socket), the first
/// the skb itself
fn mcast_deliver(net: &crate::net::NetNamespace, skb: SkBuff, k: &Key) {
    let g = crate::sync::rcu::read_lock();
    let mut first: Option<&UdpSock> = None;
    let socks = slot(net, k.dport).iter_rcu(&g).map(|e| e.get());
    for s in socks
        .filter(|s| s.sk.net.id == net.id && s.inet.get().sport == k.dport && bcast_match(s, k))
    {
        if first.is_none() {
            first = Some(s);
            continue;
        }
        match skb.clone_gfp(Gfp::ATOMIC) {
            Some(c) => queue_rcv(net, s, c),
            None => {
                s.sk.drops.fetch_add(1, Ordering::Relaxed);
                net.mib.udp.inc(UDP_MIB_RCVBUFERRORS);
                net.mib.udp.inc(UDP_MIB_INERRORS);
            }
        }
    }
    match first {
        Some(s) => queue_rcv(net, s, skb),
        None => net.mib.udp.inc(UDP_MIB_IGNOREDMULTI),
    }
}

/// An ICMP error about a datagram we sent (Linux udp_err): the socket
/// that sent it gets the error queued (IP_RECVERR) and/or as its pending
/// error; without IP_RECVERR only hard errors on connected sockets count
pub fn udp_err(net: &crate::net::NetNamespace, e: &crate::net::icmp::IcmpErr<'_>) {
    let l4 = e.l4();
    let (sport, dport) = (
        u16::from_be_bytes([l4[0], l4[1]]),
        u16::from_be_bytes([l4[2], l4[3]]),
    );
    let k = Key {
        saddr: e.inner_daddr(),
        sport: dport,
        daddr: e.inner_saddr(),
        dport: sport,
        dif: e.rx.ifindex,
    };
    let Some(s) = lookup(net, &k) else {
        // Linux __udp4_lib_err: no socket for it
        net.mib.icmp.inc(ICMP_MIB_INERRORS);
        return;
    };
    let Some((err, hard)) = e.errno(s.inet.pmtudisc()) else {
        return;
    };
    if s.inet.flag(af_inet::ipf::RECVERR) {
        af_inet::ip_icmp_error(&s.sk, e, err, dport, &l4[UDP_HLEN..]);
    } else if !hard || !s.connected.load(Ordering::Acquire) {
        return;
    }
    s.sk.set_err(err);
}

/// Verify a received UDP checksum (pseudo header + header + data sum to
/// 0xffff)
fn csum_ok(saddr: Ipv4Addr, daddr: Ipv4Addr, pkt: &[u8]) -> bool {
    let mut sum = ipv4::pseudo_header_checksum(saddr, daddr, IPPROTO_UDP as u8, pkt.len() as u16);
    sum = add_words(sum, pkt);
    fold(sum) == 0xffff
}

fn add_words(mut sum: u32, d: &[u8]) -> u32 {
    let mut i = 0;
    while i + 1 < d.len() {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([d[i], d[i + 1]])));
        // Fold early so long datagrams cannot overflow
        if sum & 0x8000_0000 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        i += 2;
    }
    if i < d.len() {
        sum = sum.wrapping_add(u32::from(d[i]) << 8);
    }
    sum
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// UDP checksum to transmit (0 is sent as 0xffff: 0 means none)
pub fn udp_checksum(saddr: Ipv4Addr, daddr: Ipv4Addr, udp: &[u8]) -> u16 {
    let sum = ipv4::pseudo_header_checksum(saddr, daddr, IPPROTO_UDP as u8, udp.len() as u16);
    let r = !fold(add_words(sum, udp));
    if r == 0 { 0xffff } else { r }
}

/// `/proc/net/udp` (Linux udp4_seq_show): every bound socket of the
/// `net` by hash slot, addresses as raw network-order hex, lines padded
/// to 127 columns; generated under RCU into a buffer that never grows
pub fn proc_net_udp(net: &crate::net::NetNamespace) -> Vec<u8> {
    use core::fmt::Write;
    crate::fs::proc::seq::generate(|m| {
        m.setwidth(127);
        let _ = write!(
            m,
            "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops"
        );
        m.pad('\n');
        let raw = |a: Ipv4Addr| u32::from_ne_bytes(a.to_be_bytes());
        let g = crate::sync::rcu::read_lock();
        for (i, head) in table().iter().enumerate() {
            for e in head.iter_rcu(&g) {
                let s = e.get();
                if s.sk.net.id != net.id {
                    continue;
                }
                let a = s.inet.get();
                // TCP_ESTABLISHED (1) when connected, else TCP_CLOSE (7)
                let st = if s.connected.load(Ordering::Acquire) {
                    1
                } else {
                    7
                };
                m.setwidth(127);
                let _ = write!(
                    m,
                    "{:5}: {:08X}:{:04X} {:08X}:{:04X} {:02X} {:08X}:{:08X} {:02X}:{:08X} {:08X} {:5} {:8} {} {} {:016x} {}",
                    i,
                    raw(a.rcv_saddr),
                    a.sport,
                    raw(a.daddr),
                    a.dport,
                    st,
                    0,
                    s.rxq.rmem(),
                    0,
                    0,
                    0,
                    s.sk.cred.euid,
                    0,
                    s.sk.ino.load(Ordering::Relaxed),
                    2,
                    0,
                    s.sk.drops.load(Ordering::Relaxed)
                );
                m.pad('\n');
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Linux udp_send_skb: a send's ENOBUFS is the sender's only with
    /// IP_RECVERR; other errors always are
    #[test]
    fn enobufs_swallowed() {
        let nb = KernelError::NoBufferSpace;
        assert_eq!(send_err(nb, false), None);
        assert_eq!(send_err(nb, true), Some(nb));
        let u = KernelError::HostUnreachable;
        assert_eq!(send_err(u, false), Some(u));
    }
}

//! UDP (Linux net/ipv4/udp.c, datagram.c)
//!
//! Sockets live in the namespace's `UdpTable`, keyed by local port, from
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
//! Order: `UdpSock.op` (Linux lock_sock: bind/connect/autobind) ->
//! `UdpTable.socks` (RwLock) -> `Inet.addr` (Mutex leaf);
//! `UdpSock.rxq` is a separate leaf. Receive takes the table read lock
//! and then each candidate's `Inet.addr`; it never holds the table lock
//! while queueing. No lock is held across a sleep or a transmit.

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::sync::spin::{Mutex, RwLock};

use crate::error::KernelError;
use crate::net::af_inet::{
    self, IP_PKTINFO, IP_TOS, IP_TTL, IPPROTO_UDP, Inet, InetAddr, RxInfo, SOL_IP,
};
use crate::net::dgram::{self, Dgram, RxQueue};
use crate::net::inet::fib::RouteType;
use crate::net::inet::port::{self, BindInfo, Flow};
use crate::net::inet::route;
use crate::net::ipv4::{self, IpParams, Ipv4Addr};
use crate::net::msg::{MSG_ERRQUEUE, MSG_OOB, RecvMsg, SendMsg, cmsgs};
use crate::net::skb::SkBuff;
use crate::net::sock::{SHUTDOWN_MASK, Sock, sf};
use crate::net::socket::{
    AF_INET, AF_UNSPEC, OptIn, OptOut, ProtoOps, SIOCINQ, SIOCOUTQ, SOCK_DGRAM, SOL_SOCKET,
    shut_bits,
};

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
    /// Socket lock: bind/connect/disconnect/autobind (Linux lock_sock)
    op: Mutex<()>,
    /// Connected (Linux TCP_ESTABLISHED state for datagram sockets)
    connected: AtomicBool,
    /// In the namespace table
    hashed: AtomicBool,
    rxq: RxQueue,
    me: Weak<UdpSock>,
}

/// socket(AF_INET, SOCK_DGRAM, 0)
pub fn create() -> Arc<dyn ProtoOps> {
    let net = crate::net::current_net_ns();
    Arc::new_cyclic(|me| UdpSock {
        sk: Sock::new(net, AF_INET, SOCK_DGRAM, IPPROTO_UDP),
        inet: Inet::default(),
        op: Mutex::new(()),
        connected: AtomicBool::new(false),
        hashed: AtomicBool::new(false),
        rxq: RxQueue::default(),
        me: me.clone(),
    })
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
        let p = self.sk.net.udp.insert(&me, &info, port, flow)?;
        self.hashed.store(true, Ordering::Release);
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

    fn unhash(&self) {
        if self.hashed.swap(false, Ordering::AcqRel) {
            let port = self.inet.get().sport;
            self.sk.net.udp.remove(self, port);
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
    fn dest(&self, m: &SendMsg) -> Result<(Ipv4Addr, u16, bool), KernelError> {
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
        let rt = route::output(&self.sk.net, daddr, saddr, oif)?;
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

    /// Build and send one datagram
    fn xmit(
        &self,
        rt: &route::Rtable,
        sport: u16,
        dport: u16,
        data: &[u8],
        p: IpParams,
    ) -> Result<(), KernelError> {
        let mut skb = SkBuff::alloc_tx(UDP_HLEN + data.len()).ok_or(KernelError::NoBufferSpace)?;
        skb.put_slice(data).ok_or(KernelError::NoBufferSpace)?;
        let h = skb.push(UDP_HLEN).ok_or(KernelError::NoBufferSpace)?;
        h[0..2].copy_from_slice(&sport.to_be_bytes());
        h[2..4].copy_from_slice(&dport.to_be_bytes());
        h[4..6].copy_from_slice(&((UDP_HLEN + data.len()) as u16).to_be_bytes());
        h[6..8].copy_from_slice(&[0, 0]);
        let saddr = rt.saddr;
        let csum = udp_checksum(saddr, rt.daddr, skb.data());
        skb.data_mut()[6..8].copy_from_slice(&csum.to_be_bytes());
        skb.saddr = Some(saddr);
        skb.daddr = Some(rt.daddr);
        ipv4::ip_send_rt(&self.sk.net, rt, skb, IPPROTO_UDP as u8, p)
    }
}

/// Per-message IP parameters from sendmsg control data (Linux
/// ip_cmsg_send: IP_PKTINFO, IP_TTL, IP_TOS)
pub struct TxCmsg {
    pub oif: u32,
    pub saddr: Ipv4Addr,
    pub ttl: Option<u8>,
    pub tos: Option<u8>,
}

pub fn tx_cmsgs(c: &[u8]) -> Result<TxCmsg, KernelError> {
    let mut t = TxCmsg {
        oif: 0,
        saddr: Ipv4Addr::default(),
        ttl: None,
        tos: None,
    };
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
                1 => Ok(d[0] as i32),
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
        crate::uaccess::put_user::<crate::arch::Uaccess, i32>(arg, v as i32)
            .map_err(|_| KernelError::BadAddress)?;
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
    fn sendmsg(&self, m: &mut SendMsg, flags: i32) -> Result<usize, KernelError> {
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
        match self.xmit(&rt, a.sport, dport, &data, p) {
            Err(KernelError::MessageTooLong) => {
                // Linux __ip_append_data: IP_RECVERR also queues it
                // (msg_name port: the connected one)
                let e = KernelError::MessageTooLong;
                af_inet::ip_local_error(&self.sk, &self.inet, e, daddr, a.dport, rt.mtu);
                Err(e)
            }
            r => r.map(|()| len),
        }
    }

    /// Linux udp_recvmsg
    fn recvmsg(&self, m: &mut RecvMsg, flags: i32) -> Result<usize, KernelError> {
        if flags & MSG_ERRQUEUE != 0 {
            return af_inet::ip_recv_error(&self.sk, &self.inet, m);
        }
        let Some(d) = self.rxq.recv(&self.sk, flags)? else {
            return Ok(0);
        };
        dgram::deliver(&self.sk, &self.inet, m, &d, flags)
    }
}

// ============================================================================
// Socket table (per namespace)
// ============================================================================

/// Bound UDP sockets of a namespace by local port
#[derive(Default)]
pub struct UdpTable {
    socks: RwLock<BTreeMap<u16, Vec<Arc<UdpSock>>>>,
}

/// Address `s` is bound to (for the bind rules), read under the table
/// lock (order: table -> Inet.addr)
fn bound_addr(s: &UdpSock) -> Ipv4Addr {
    s.inet.get().rcv_saddr
}

impl UdpTable {
    fn free(map: &BTreeMap<u16, Vec<Arc<UdpSock>>>, port: u16, info: &BindInfo) -> bool {
        map.get(&port).is_none_or(|v| {
            v.iter()
                .all(|o| !port::conflict(info, &o.bind_info(bound_addr(o)), false))
        })
    }

    /// Insert `s` on `port` (0 = pick an ephemeral port): EADDRINUSE on
    /// a conflict or when the range is exhausted
    fn insert(
        &self,
        s: &Arc<UdpSock>,
        info: &BindInfo,
        port: u16,
        flow: Flow,
    ) -> Result<u16, KernelError> {
        let mut map = self.socks.write();
        let port = if port != 0 {
            if !Self::free(&map, port, info) {
                return Err(KernelError::AddressInUse);
            }
            port
        } else {
            let range = s.sk.net.port_range.get();
            port::ephemeral(range, flow, |p| Self::free(&map, p, info))
                .ok_or(KernelError::AddressInUse)?
        };
        map.entry(port).or_default().push(s.clone());
        Ok(port)
    }

    fn remove(&self, s: &UdpSock, port: u16) {
        let mut map = self.socks.write();
        if let Some(v) = map.get_mut(&port) {
            v.retain(|o| !core::ptr::eq(Arc::as_ptr(o), s));
            if v.is_empty() {
                map.remove(&port);
            }
        }
    }

    /// Sockets bound to `port`
    fn on_port(&self, port: u16) -> Vec<Arc<UdpSock>> {
        self.socks.read().get(&port).cloned().unwrap_or_default()
    }

    /// All bound sockets (by port)
    fn all(&self) -> Vec<Arc<UdpSock>> {
        self.socks.read().values().flatten().cloned().collect()
    }

    /// Number of bound sockets
    pub fn len(&self) -> usize {
        self.socks.read().values().map(|v| v.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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

/// Best socket for a unicast datagram; a SO_REUSEPORT group shares by
/// flow hash
fn lookup(t: &UdpTable, k: &Key) -> Option<Arc<UdpSock>> {
    let cands = t.on_port(k.dport);
    let best = cands
        .iter()
        .map(|s| score(s, k))
        .max()
        .filter(|&b| b >= 0)?;
    let top: Vec<&Arc<UdpSock>> = cands.iter().filter(|s| score(s, k) == best).collect();
    let first = top[0];
    if !first.sk.flag(sf::REUSEPORT) || top.len() == 1 {
        return Some(first.clone());
    }
    let group: Vec<&&Arc<UdpSock>> = top.iter().filter(|s| s.sk.flag(sf::REUSEPORT)).collect();
    let h = port::siphash(
        [0x9e37_79b9, 0x7f4a_7c15],
        &[
            ((k.saddr.0 as u64) << 32) | k.daddr.0 as u64,
            ((k.sport as u64) << 16) | k.dport as u64,
        ],
    );
    Some((*group[(h as usize) % group.len()]).clone())
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
/// namespace)
pub fn udp_rcv(skb: SkBuff) {
    let (Some(net), Some(saddr), Some(daddr)) = (skb.net(), skb.saddr, skb.daddr) else {
        return;
    };
    let b = skb.data();
    if b.len() < UDP_HLEN {
        return;
    }
    let ulen = u16::from_be_bytes([b[4], b[5]]) as usize;
    if ulen < UDP_HLEN || ulen > b.len() {
        return;
    }
    let pkt = &b[..ulen];
    if u16::from_be_bytes([b[6], b[7]]) != 0 && !csum_ok(saddr, daddr, pkt) {
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
    let info = RxInfo::of(&net, &skb);
    let d = Dgram::new(saddr, k.sport, pkt[UDP_HLEN..].to_vec(), info);
    if skb.ip_bcast || daddr.is_multicast() {
        for s in net
            .udp
            .on_port(k.dport)
            .iter()
            .filter(|s| bcast_match(s, &k))
        {
            s.rxq.enqueue(&s.sk, d.clone());
        }
        return;
    }
    match lookup(&net.udp, &k) {
        Some(s) => s.rxq.enqueue(&s.sk, d),
        None => crate::net::icmp::port_unreach(&net, &skb),
    }
}

/// An ICMP error about a datagram we sent (Linux udp_err): the socket
/// that sent it gets the error queued (IP_RECVERR) and/or as its pending
/// error; without IP_RECVERR only hard errors on connected sockets count
pub fn udp_err(net: &crate::net::NetNamespace, e: &crate::net::icmp::IcmpErr) {
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
    let Some(s) = lookup(&net.udp, &k) else {
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
        sum = sum.wrapping_add(u16::from_be_bytes([d[i], d[i + 1]]) as u32);
        // Fold early so long datagrams cannot overflow
        if sum & 0x8000_0000 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        i += 2;
    }
    if i < d.len() {
        sum = sum.wrapping_add((d[i] as u32) << 8);
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
/// reader's namespace, addresses as raw network-order hex, lines padded
/// to 127 columns
pub fn proc_net_udp() -> Vec<u8> {
    use core::fmt::Write;
    let mut out = alloc::string::String::new();
    let _ = writeln!(
        out,
        "{:<127}",
        "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops"
    );
    let raw = |a: Ipv4Addr| u32::from_ne_bytes(a.to_be_bytes());
    for s in crate::net::current_net_ns().udp.all() {
        let a = s.inet.get();
        // TCP_ESTABLISHED (1) when connected, else TCP_CLOSE (7)
        let st = if s.connected.load(Ordering::Acquire) {
            1
        } else {
            7
        };
        let line = alloc::format!(
            "{:5}: {:08X}:{:04X} {:08X}:{:04X} {:02X} {:08X}:{:08X} {:02X}:{:08X} {:08X} {:5} {:8} {} {} {:016x} {}",
            a.sport & 127,
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
        let _ = writeln!(out, "{:<127}", line);
    }
    out.into_bytes()
}

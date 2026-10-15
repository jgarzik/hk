//! Raw IPv4 sockets: socket(AF_INET, SOCK_RAW, protocol) (Linux
//! net/ipv4/raw.c)
//!
//! Need CAP_NET_RAW (EPERM). A raw socket is bound to its protocol from
//! creation and receives a copy of every matching packet for us, IP
//! header included (bound/connected addresses and device filter it;
//! ICMP sockets also by ICMP_FILTER). Sends get an IP header built by
//! the kernel, or use the caller's with IP_HDRINCL (implied by
//! IPPROTO_RAW; its source address is taken as given, length, checksum
//! and a zero id are filled in). ICMP errors about the protocol are
//! reported like Linux raw_err.
//!
//! ## Locking (thread context only)
//!
//! `RawTable.socks` (`spin::RwLock`, per namespace) -> `Inet.addr`;
//! delivery clones the matching `Arc`s and queues (`RxQueue`, leaf)
//! after dropping the table lock. `RawSock.filter` is an atomic.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use spin::RwLock;

use crate::error::KernelError;
use crate::net::af_inet::{self, Inet, RxInfo, SOL_IP, ipf};
use crate::net::dgram::{self, Dgram, RxQueue};
use crate::net::icmp::{self, IcmpErr, icmp_type};
use crate::net::inet::fib::RouteType;
use crate::net::inet::route;
use crate::net::ipv4::{self, IP_HLEN_MIN, IPPROTO_ICMP, Ipv4Addr, ip_checksum, pmtu};
use crate::net::msg::{MSG_ERRQUEUE, MSG_OOB, RecvMsg, SendMsg};
use crate::net::skb::SkBuff;
use crate::net::sock::{SHUTDOWN_MASK, Sock, sf};
use crate::net::socket::{
    AF_INET, AF_UNSPEC, OptIn, OptOut, ProtoOps, SIOCINQ, SIOCOUTQ, SOCK_RAW, SOL_SOCKET, shut_bits,
};
use crate::net::{NetNamespace, udp};

/// Socket level of raw options and ICMP_FILTER
pub const SOL_RAW: i32 = 255;
const ICMP_FILTER: i32 = 1;
const IPPROTO_RAW: i32 = 255;
/// Linux IPPROTO_MAX
const IPPROTO_MAX: i32 = 263;

/// A raw socket
pub struct RawSock {
    sk: Sock,
    pub inet: Inet,
    /// Protocol (Linux inet_num)
    num: u16,
    connected: AtomicBool,
    /// ICMP_FILTER: bit n set = drop ICMP type n
    filter: AtomicU32,
    rxq: RxQueue,
}

/// socket(AF_INET, SOCK_RAW, protocol) (Linux inet_create for raw:
/// EINVAL outside 0..IPPROTO_MAX, EPROTONOSUPPORT for 0, then EPERM
/// without CAP_NET_RAW)
pub fn create(protocol: i32) -> Result<Arc<dyn ProtoOps>, KernelError> {
    if !(0..IPPROTO_MAX).contains(&protocol) {
        return Err(KernelError::InvalidArgument);
    }
    if protocol == 0 {
        return Err(KernelError::ProtocolNotSupported);
    }
    if !crate::task::capable(crate::task::CAP_NET_RAW) {
        return Err(KernelError::NotPermitted);
    }
    let net = crate::net::current_net_ns();
    let sk = Sock::new(net.clone(), AF_INET, SOCK_RAW, protocol);
    // INET_PROTOSW_REUSE
    sk.set_flag(sf::REUSEADDR, true);
    let s = Arc::new(RawSock {
        sk,
        inet: Inet::default(),
        num: protocol as u16,
        connected: AtomicBool::new(false),
        filter: AtomicU32::new(0),
        rxq: RxQueue::default(),
    });
    if protocol == IPPROTO_RAW {
        s.inet.set_hdrincl(true);
    }
    // The "port" is the protocol (Linux inet_sport = htons(inet_num))
    s.inet.addr.lock().sport = protocol as u16;
    net.raw.insert(&s);
    Ok(s)
}

impl RawSock {
    /// Linux raw_v4_match
    fn matches(&self, raddr: Ipv4Addr, laddr: Ipv4Addr, dif: u32) -> bool {
        let a = self.inet.get();
        let dev = self.sk.bound_dev_if();
        (a.daddr.is_unspecified() || a.daddr == raddr)
            && (a.rcv_saddr.is_unspecified() || a.rcv_saddr == laddr)
            && (dev == 0 || dev == dif)
    }

    /// ICMP_FILTER drops this ICMP type
    fn filtered(&self, ty: u8) -> bool {
        ty < 32 && self.filter.load(Ordering::Relaxed) & (1 << ty) != 0
    }

    /// Destination (Linux raw_sendmsg: AF_UNSPEC is tolerated)
    fn dest(&self, m: &SendMsg) -> Result<Ipv4Addr, KernelError> {
        let Some(a) = &m.addr else {
            if !self.connected.load(Ordering::Acquire) {
                return Err(KernelError::DestAddrRequired);
            }
            return Ok(self.inet.get().daddr);
        };
        if a.len() < af_inet::SIN_LEN {
            return Err(KernelError::InvalidArgument);
        }
        let fam = af_inet::sa_family(a)?;
        if fam != AF_INET && fam != AF_UNSPEC {
            return Err(KernelError::AddressFamilyNotSupported);
        }
        Ok(Ipv4Addr::from_be_bytes([a[4], a[5], a[6], a[7]]))
    }

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

    /// IP_HDRINCL send (Linux raw_send_hdrinc): at most the device MTU,
    /// a sane header length; source (if 0), total length, id (if 0)
    /// and checksum filled in
    fn send_hdrinc(&self, rt: &route::Rtable, data: &[u8]) -> Result<(), KernelError> {
        let mtu = rt.dev.mtu() as usize;
        if data.len() > mtu {
            let e = KernelError::MessageTooLong;
            af_inet::ip_local_error(
                &self.sk,
                &self.inet,
                e,
                rt.daddr,
                self.inet.get().dport,
                mtu as u32,
            );
            return Err(e);
        }
        if data.len() < IP_HLEN_MIN {
            return Err(KernelError::InvalidArgument);
        }
        let ihl = ((data[0] & 0x0f) as usize) * 4;
        if ihl > data.len() || ihl < IP_HLEN_MIN {
            return Err(KernelError::InvalidArgument);
        }
        let mut skb = SkBuff::alloc_tx(data.len()).ok_or(KernelError::NoBufferSpace)?;
        skb.put_slice(data).ok_or(KernelError::NoBufferSpace)?;
        let h = skb.data_mut();
        if h[12..16] == [0; 4] {
            h[12..16].copy_from_slice(&rt.saddr.to_be_bytes());
        }
        h[2..4].copy_from_slice(&(data.len() as u16).to_be_bytes());
        if h[4..6] == [0, 0] {
            let (s, d) = (
                Ipv4Addr::from_be_bytes([h[12], h[13], h[14], h[15]]),
                Ipv4Addr::from_be_bytes([h[16], h[17], h[18], h[19]]),
            );
            let id = ipv4::select_ident(&self.sk.net, s, d, h[9]);
            h[4..6].copy_from_slice(&id.to_be_bytes());
        }
        h[10] = 0;
        h[11] = 0;
        let c = ip_checksum(&h[..ihl]);
        h[10..12].copy_from_slice(&c.to_be_bytes());
        let saddr = Ipv4Addr::from_be_bytes([h[12], h[13], h[14], h[15]]);
        ipv4::ip_output(&self.sk.net, rt, skb, saddr, mtu)
    }
}

impl ProtoOps for RawSock {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn sk(&self) -> &Sock {
        &self.sk
    }

    fn release(&self) {
        self.sk.net.raw.remove(self);
        self.sk.set_shutdown(SHUTDOWN_MASK);
        self.rxq.clear();
        self.sk.purge_err();
    }

    /// Linux raw_bind: an address only (local, multicast or broadcast)
    fn bind(&self, a: &[u8]) -> Result<(), KernelError> {
        if a.len() < af_inet::SIN_LEN || self.connected.load(Ordering::Acquire) {
            return Err(KernelError::InvalidArgument);
        }
        let addr = Ipv4Addr::from_be_bytes([a[4], a[5], a[6], a[7]]);
        let ty = self.sk.net.fib.addr_type(addr);
        let ok = addr.is_unspecified()
            || matches!(
                ty,
                RouteType::Local | RouteType::Multicast | RouteType::Broadcast
            )
            || self.inet.flag(ipf::FREEBIND);
        if !ok {
            return Err(KernelError::AddressNotAvailable);
        }
        let mut s = self.inet.addr.lock();
        s.rcv_saddr = addr;
        s.saddr = if matches!(ty, RouteType::Multicast | RouteType::Broadcast) {
            Ipv4Addr::default()
        } else {
            addr
        };
        Ok(())
    }

    /// Linux ip4_datagram_connect (no port)
    fn connect(&self, a: &[u8], _nonblock: bool) -> Result<(), KernelError> {
        if af_inet::sa_family(a)? == AF_UNSPEC {
            self.connected.store(false, Ordering::Release);
            let mut s = self.inet.addr.lock();
            s.daddr = Ipv4Addr::default();
            s.dport = 0;
            return Ok(());
        }
        let (daddr, dport) = af_inet::sin_parse(a, false)?;
        let rt = self.route(daddr, self.inet.get().saddr, self.sk.bound_dev_if())?;
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

    fn poll(&self) -> u16 {
        dgram::poll(&self.sk, &self.rxq)
    }

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

    fn shutdown(&self, how: i32) -> Result<(), KernelError> {
        self.sk.set_shutdown(shut_bits(how)?);
        if !self.connected.load(Ordering::Acquire) {
            return Err(KernelError::NotConnected);
        }
        Ok(())
    }

    /// SOL_RAW ICMP_FILTER (EOPNOTSUPP unless IPPROTO_ICMP; a short
    /// value replaces only its leading bytes), else IP options
    fn setsockopt(&self, level: i32, opt: i32, v: OptIn) -> Option<Result<(), KernelError>> {
        match level {
            SOL_SOCKET => None,
            SOL_RAW if opt != ICMP_FILTER => Some(Err(KernelError::NoProtocolOption)),
            SOL_RAW if self.num != IPPROTO_ICMP as u16 => {
                Some(Err(KernelError::OperationNotSupported))
            }
            SOL_RAW => Some(v.bytes(4).map(|b| {
                let mut f = self.filter.load(Ordering::Relaxed).to_ne_bytes();
                f[..b.len()].copy_from_slice(&b);
                self.filter.store(u32::from_ne_bytes(f), Ordering::Relaxed);
            })),
            SOL_IP => Some(self.inet.setsockopt(&self.sk, opt, v)),
            _ => Some(Err(KernelError::NoProtocolOption)),
        }
    }

    fn getsockopt(&self, level: i32, opt: i32) -> Option<Result<OptOut, KernelError>> {
        match level {
            SOL_SOCKET => None,
            SOL_RAW if opt != ICMP_FILTER => Some(Err(KernelError::NoProtocolOption)),
            SOL_RAW if self.num != IPPROTO_ICMP as u16 => {
                Some(Err(KernelError::OperationNotSupported))
            }
            SOL_RAW => Some(Ok(OptOut::Bytes(
                self.filter.load(Ordering::Relaxed).to_ne_bytes().to_vec(),
            ))),
            SOL_IP => Some(self.inet.getsockopt(opt)),
            _ => Some(Err(KernelError::OperationNotSupported)),
        }
    }

    /// Linux raw_sendmsg
    fn sendmsg(&self, m: &mut SendMsg, flags: i32) -> Result<usize, KernelError> {
        let len = m.data.len();
        if len > 0xffff {
            return Err(KernelError::MessageTooLong);
        }
        if flags & MSG_OOB != 0 {
            return Err(KernelError::OperationNotSupported);
        }
        let daddr = self.dest(m)?;
        let c = udp::tx_cmsgs(&m.control)?;
        let a = self.inet.get();
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
        let data = m.data.take(len)?;
        if let Some(e) = self.sk.take_err() {
            return Err(e);
        }
        if self.inet.flag(ipf::HDRINCL) {
            return self.send_hdrinc(&rt, &data).map(|()| len);
        }
        let mut skb = SkBuff::alloc_tx(len).ok_or(KernelError::NoBufferSpace)?;
        skb.put_slice(&data).ok_or(KernelError::NoBufferSpace)?;
        skb.saddr = Some(rt.saddr);
        skb.daddr = Some(rt.daddr);
        let mut p = self.inet.params();
        p.tos = c.tos.unwrap_or(p.tos);
        p.ttl = c.ttl.unwrap_or(p.ttl);
        match ipv4::ip_send_rt(&self.sk.net, &rt, skb, self.num as u8, p) {
            Err(KernelError::MessageTooLong) => {
                let e = KernelError::MessageTooLong;
                af_inet::ip_local_error(&self.sk, &self.inet, e, rt.daddr, a.dport, rt.mtu);
                Err(e)
            }
            r => r.map(|()| len),
        }
    }

    /// Linux raw_recvmsg: the packet from its IP header, source address
    /// with port 0
    fn recvmsg(&self, m: &mut RecvMsg, flags: i32) -> Result<usize, KernelError> {
        if flags & MSG_OOB != 0 {
            return Err(KernelError::OperationNotSupported);
        }
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
// Table (per namespace) and delivery
// ============================================================================

/// Raw sockets of a namespace by protocol
#[derive(Default)]
pub struct RawTable {
    socks: RwLock<BTreeMap<u16, Vec<Arc<RawSock>>>>,
}

impl RawTable {
    fn insert(&self, s: &Arc<RawSock>) {
        self.socks.write().entry(s.num).or_default().push(s.clone());
    }

    fn remove(&self, s: &RawSock) {
        let mut t = self.socks.write();
        if let Some(v) = t.get_mut(&s.num) {
            v.retain(|o| !core::ptr::eq(Arc::as_ptr(o), s));
            if v.is_empty() {
                t.remove(&s.num);
            }
        }
    }

    /// Sockets of `proto` matching the addresses and device
    fn matching(&self, proto: u8, raddr: Ipv4Addr, laddr: Ipv4Addr, dif: u32) -> Vec<Arc<RawSock>> {
        self.socks
            .read()
            .get(&(proto as u16))
            .map(|v| {
                v.iter()
                    .filter(|s| s.matches(raddr, laddr, dif))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Give every matching raw socket a copy of a packet for us (Linux
/// raw_v4_input; `skb.data()` is the transport header, the IP header is
/// marked). Returns whether any socket matched (even if it filtered the
/// packet or its buffer was full): then no protocol unreachable is sent.
pub fn raw_deliver(net: &NetNamespace, skb: &SkBuff) -> bool {
    let Some(pkt) = skb.network_packet() else {
        return false;
    };
    let (saddr, daddr) = (skb.saddr.unwrap_or_default(), skb.daddr.unwrap_or_default());
    let dif = skb.dev.as_ref().map_or(0, |d| d.ifindex());
    let socks = net.raw.matching(skb.ip_protocol, saddr, daddr, dif);
    if socks.is_empty() {
        return false;
    }
    let info = RxInfo::of(net, skb);
    let icmp = skb.ip_protocol == IPPROTO_ICMP;
    for s in socks {
        if icmp && skb.data().first().is_none_or(|&t| s.filtered(t)) {
            continue;
        }
        s.rxq
            .enqueue(&s.sk, Dgram::new(saddr, 0, pkt.to_vec(), info));
    }
    true
}

/// An ICMP error about a packet of a raw socket's protocol (Linux
/// raw_icmp_error + raw_err)
pub fn raw_err(net: &NetNamespace, e: &IcmpErr) {
    for s in net
        .raw
        .matching(e.proto(), e.inner_daddr(), e.inner_saddr(), e.rx.ifindex)
    {
        err_one(&s, e);
    }
}

fn err_one(s: &RawSock, e: &IcmpErr) {
    let recverr = s.inet.flag(ipf::RECVERR);
    if !recverr && !s.connected.load(Ordering::Acquire) {
        return;
    }
    let (err, hard) = match (e.ty, e.code) {
        (icmp_type::SOURCE_QUENCH, _) => return,
        (icmp_type::PARAMETERPROB, _) => (KernelError::ProtocolError, true),
        (icmp_type::DEST_UNREACH, icmp::code::FRAG_NEEDED) => {
            (KernelError::MessageTooLong, s.inet.pmtudisc() != pmtu::DONT)
        }
        (icmp_type::DEST_UNREACH, c) if c <= icmp::code::MAX_UNREACH => icmp::unreach_err(c),
        _ => (KernelError::HostUnreachable, false),
    };
    if recverr {
        let payload = if s.inet.flag(ipf::HDRINCL) {
            e.inner
        } else {
            e.l4()
        };
        af_inet::ip_icmp_error(&s.sk, e, err, 0, payload);
    }
    if recverr || hard {
        s.sk.set_err(err);
    }
}

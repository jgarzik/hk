//! UDP (Linux net/ipv4/udp.c, datagram.c)
//!
//! Sockets live in the UDP table (`table`: Linux udp_table's hash by
//! port and hash2 by address and port), from bind/autobind until close
//! (or disconnect of an autobound port). Binding follows Linux
//! SO_REUSEADDR/SO_REUSEPORT rules (`inet::port::conflict`); ephemeral
//! ports come from `ip_local_port_range` at a keyed-hash offset.
//! Receive lookup scores candidates like Linux compute_score, spreads a
//! SO_REUSEPORT group by flow hash, and delivers broadcasts to every
//! matching socket. The receive queue is bounded by SO_RCVBUF (drops
//! counted); checksums are verified on receive.
//!
//! ## Locking (thread context only)
//!
//! Order: `UdpSock.op` (sleeping `sync::Mutex`, Linux lock_sock:
//! bind/connect/disconnect/autobind, socket calls only) -> the table's
//! slot locks (`table`) -> `Inet.addr` (Mutex leaf); `UdpSock.rxq` is a
//! separate leaf. Receive and ICMP-error lookups walk slots under RCU,
//! reading each candidate's `Inet.addr`, and queue under the guard with
//! GFP_ATOMIC. A socket's table references are released a grace period
//! after it leaves (Linux SOCK_RCU_FREE), possibly in `rcuc/N`: its
//! drop takes no sleeping lock. Only `op` is held across a sleep or a
//! transmit: a corked datagram (UDP_CORK, MSG_MORE) is appended to and
//! sent under it, as Linux under lock_sock.

pub mod mem;
mod rxq;
mod table;
use rxq::UdpRxq;
use table::Key;

/// Size the table and udp_mem (Linux udp_init)
pub fn init() {
    table::init();
    mem::init();
}

use crate::mm::page_alloc::Gfp;
use crate::net::mib::INUSE_UDP;
use crate::util::kalloc::try_arc_cyclic;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};

use crate::net::sock_reuseport::{self, ReuseCb};
use crate::sync::rcu::RcuPuts;
use crate::util::hlist_nulls::NullsLink;

use crate::net::af_inet::{
    self, IP_PKTINFO, IP_TOS, IP_TTL, IPPROTO_UDP, Inet, InetAddr, RxInfo, SOL_IP,
};
use crate::net::dgram;
use crate::net::inet::fib::RouteType;
use crate::net::inet::port::{BindInfo, Flow};
use crate::net::inet::route;
use crate::net::ipv4::{self, IpParams, Ipv4Addr};
use crate::net::mib::*;
use crate::net::msg::{MSG_ERRQUEUE, MSG_MORE, MSG_OOB, MSG_PEEK, RecvMsg, SendMsg, cmsgs};
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
/// SOL_UDP options (Linux include/uapi/linux/udp.h)
const UDP_CORK: i32 = 1;
const UDP_ENCAP: i32 = 100;
const UDP_NO_CHECK6_TX: i32 = 101;
const UDP_NO_CHECK6_RX: i32 = 102;
const UDP_SEGMENT: i32 = 103;
const UDP_GRO: i32 = 104;
/// UDP_ENCAP types taken without XFRM: none, L2TP (Linux
/// udp_lib_setsockopt; UDP_ENCAP_ESPINUDP needs CONFIG_XFRM)
const UDP_ENCAP_L2TPINUDP: i32 = 3;
/// Linux UDP_MAX_SEGMENTS
const UDP_MAX_SEGMENTS: usize = 1 << 7;

/// `UdpSock.uflags` bits (Linux UDP_FLAGS_*)
mod uf {
    pub const CORK: u32 = 1 << 0;
    pub const NO_CHECK6_TX: u32 = 1 << 1;
    pub const NO_CHECK6_RX: u32 = 1 << 2;
    pub const GRO_ENABLED: u32 = 1 << 3;
}

/// A corked datagram (Linux up->pending, up->len, inet->cork and the
/// sk_write_queue it fills): where it goes (the route and destination
/// port of inet->cork.fl), what the cork fixed, and its payload. The
/// source port, TTL without IP_TTL cmsg, PMTU mode and IP ID are the
/// socket's when it is sent, as Linux udp_send_skb and __ip_make_skb
/// read them.
struct Cork {
    rt: route::Rtable,
    dport: u16,
    /// Linux cork->tos (the socket's or the IP_TOS cmsg's)
    tos: u8,
    /// Linux cork->ttl (an IP_TTL cmsg's; None: the socket's at send)
    ttl: Option<u8>,
    /// Linux cork->fragsize: the MTU when corked
    fragsize: usize,
    gso: u16,
    /// Bytes appended, the UDP header counted (Linux up->len)
    len: usize,
    data: Vec<u8>,
}
/// A UDP socket
pub struct UdpSock {
    sk: Sock,
    pub inet: Inet,
    /// Socket lock (Linux lock_sock, which sleeps): bind, connect,
    /// disconnect, autobind, and the datagram being corked (Linux
    /// up->pending with inet->cork and sk_write_queue)
    op: crate::sync::Mutex<Option<Cork>>,
    /// A datagram is corked (Linux up->pending): set and cleared under
    /// `op`, read without it by sends choosing a path
    pending: AtomicBool,
    /// UDP_CORK, UDP_NO_CHECK6_*, UDP_GRO (Linux udp_flags)
    uflags: AtomicU32,
    /// UDP_SEGMENT (Linux gso_size)
    gso_size: AtomicU16,
    /// UDP_ENCAP (Linux encap_type)
    encap_type: AtomicU16,
    /// Connected (Linux TCP_ESTABLISHED state for datagram sockets)
    connected: AtomicBool,
    /// SO_PEEK_OFF is set (Linux peeking_with_offset)
    peeking_with_offset: AtomicBool,
    rxq: UdpRxq,
    /// Link on its port's hash slot (Linux sk_node)
    link: NullsLink,
    /// Link on its (address, port) hash2 slot (Linux udp_portaddr_node)
    link2: NullsLink,
    /// Its hash2 hash (Linux udp_portaddr_hash): set when hashed and
    /// on rehash, under the socket lock
    portaddr_hash: AtomicU32,
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
        op: crate::sync::Mutex::new(None),
        pending: AtomicBool::new(false),
        uflags: AtomicU32::new(0),
        gso_size: AtomicU16::new(0),
        encap_type: AtomicU16::new(0),
        connected: AtomicBool::new(false),
        peeking_with_offset: AtomicBool::new(false),
        rxq: UdpRxq::default(),
        link: NullsLink::new(),
        link2: NullsLink::new(),
        portaddr_hash: AtomicU32::new(0),
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
        let p = table::get_port(&me, &info, port, flow)?;
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

    /// Linux udp_lib_unhash
    fn unhash(&self) {
        if table::unhash(self) {
            self.sk.net.mib.inuse_add(INUSE_UDP, false);
        }
    }

    /// Linux __udp_disconnect: the peer and bound device cleared; an
    /// address bind() did not fix reset (rehashed if the port stays),
    /// a port it did not fix released
    fn disconnect(&self) {
        let _g = self.op.lock();
        self.connected.store(false, Ordering::Release);
        self.sk.set_bound_dev_if(0);
        let (addr_lock, port_lock) = {
            let mut a = self.inet.addr.lock();
            a.daddr = Ipv4Addr::default();
            a.dport = 0;
            if !a.addr_lock {
                a.rcv_saddr = Ipv4Addr::default();
                a.saddr = Ipv4Addr::default();
            }
            (a.addr_lock, a.port_lock)
        };
        if !addr_lock && port_lock {
            table::rehash(self);
        }
        if !port_lock {
            self.unhash();
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

    /// Copy datagram `skb` from offset `off` (Linux udp_recvmsg): data
    /// (MSG_TRUNC when the buffer is shorter than the rest, or is not
    /// past it and shorter than the datagram), source address, SOL_SOCKET
    /// and IP control messages. Returns the length recvmsg reports (the
    /// datagram's with MSG_TRUNC in `flags`).
    fn deliver(
        &self,
        m: &mut RecvMsg<'_>,
        skb: &SkBuff,
        flags: i32,
        off: usize,
    ) -> Result<usize, KernelError> {
        let crate::net::skb::SkbCb::Inet(cb) = skb.cb else {
            return Err(KernelError::InvalidArgument);
        };
        let data = skb.data();
        let ulen = data.len();
        let off = off.min(ulen);
        let mut copied = m.data.len();
        if copied > ulen - off {
            copied = ulen - off;
        } else if copied < ulen {
            m.flags |= crate::net::msg::MSG_TRUNC;
        }
        let n = m.data.put(0, &data[off..off + copied])?;
        if m.want_name {
            m.name = Some(af_inet::sin_bytes(skb.saddr.unwrap_or_default(), cb.sport));
        }
        dgram::sock_cmsgs(&self.sk, m, skb.tstamp, skb.dropcount);
        self.inet.recv_cmsgs(&mut m.cmsg, &cb.info);
        Ok(if flags & crate::net::msg::MSG_TRUNC != 0 {
            ulen
        } else {
            n
        })
    }

    fn uflag(&self, f: u32) -> bool {
        self.uflags.load(Ordering::Relaxed) & f != 0
    }

    fn set_uflag(&self, f: u32, on: bool) {
        if on {
            self.uflags.fetch_or(f, Ordering::Relaxed);
        } else {
            self.uflags.fetch_and(!f, Ordering::Relaxed);
        }
    }

    /// Send `data` as a datagram, or with `gso` as datagrams of `gso`
    /// bytes (Linux udp_send_skb, segmented in software as
    /// __udp_gso_segment: hk has no GSO), counting it once; EMSGSIZE
    /// past the MTU also queued with IP_RECVERR (Linux __ip_append_data)
    fn send_out(
        &self,
        rt: &route::Rtable,
        sport: u16,
        dport: u16,
        data: &[u8],
        p: IpParams,
        gso: u16,
    ) -> Result<(), KernelError> {
        let gso = usize::from(gso);
        if gso != 0 {
            let hlen = ipv4::IP_HLEN_MIN + UDP_HLEN;
            if hlen + data.len().min(gso) > p.mtu(rt) {
                return Err(KernelError::MessageTooLong);
            }
            if data.len() > gso * UDP_MAX_SEGMENTS {
                return Err(KernelError::InvalidArgument);
            }
            // Linux udp_send_skb: segments need their checksums
            if self.sk.flag(sf::NO_CHECK) {
                return Err(KernelError::InvalidArgument);
            }
        }
        let mib = &self.sk.net.mib;
        let r = if gso != 0 && data.len() > gso {
            let mut sent = true;
            let mut r = Ok(true);
            for chunk in data.chunks(gso) {
                match self.xmit(rt, sport, dport, chunk, p) {
                    Ok(s) => sent &= s,
                    Err(e) => {
                        r = Err(e);
                        break;
                    }
                }
            }
            r.map(|_| sent)
        } else {
            self.xmit(rt, sport, dport, data, p)
        };
        match r {
            // Linux udp_send_skb
            Ok(sent) => {
                if sent {
                    mib.udp.inc(UDP_MIB_OUTDATAGRAMS);
                }
                Ok(())
            }
            Err(KernelError::MessageTooLong) => {
                // Linux __ip_append_data: IP_RECVERR also queues it
                // (msg_name port: the connected one)
                let e = KernelError::MessageTooLong;
                let a = self.inet.get();
                af_inet::ip_local_error(&self.sk, &self.inet, e, rt.daddr, a.dport, rt.mtu);
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

    /// Append `data` (`ulen` bytes counted: the header too for the
    /// first) to the corked datagram, sending it unless `more` (Linux
    /// udp_sendmsg's do_append_data with ip_append_data): past the
    /// largest datagram the socket may send, everything corked is
    /// dropped (udp_flush_pending_frames) and EMSGSIZE also queued
    /// with IP_RECVERR
    fn append(
        &self,
        g: &mut Option<Cork>,
        data: &[u8],
        ulen: usize,
        more: bool,
    ) -> Result<(), KernelError> {
        let Some(c) = g.as_mut() else {
            return Err(KernelError::InvalidArgument);
        };
        // Linux __ip_append_data: a GSO cork may reach IP_MAX_MTU, else
        // the MTU unless fragmenting is allowed
        let mtu = if c.gso != 0 { 0xffff } else { c.fragsize };
        let now = IpParams {
            pmtudisc: self.inet.pmtudisc(),
            ..Default::default()
        };
        let max = if now.may_frag() { 0xffff } else { mtu };
        if c.len + ulen > max - ipv4::IP_HLEN_MIN {
            let daddr = c.rt.daddr;
            self.flush(g);
            let e = KernelError::MessageTooLong;
            let dport = self.inet.get().dport;
            af_inet::ip_local_error(&self.sk, &self.inet, e, daddr, dport, mtu as u32);
            return Err(e);
        }
        if c.data.try_reserve(data.len()).is_err() {
            self.sk.net.mib.out_discard();
            self.flush(g);
            return Err(KernelError::NoBufferSpace);
        }
        c.len += ulen;
        c.data.extend_from_slice(data);
        if more {
            return Ok(());
        }
        self.push(g)
    }

    /// Send the corked datagram (Linux udp_push_pending_frames): from
    /// the socket's port now, which a disconnect may have cleared
    fn push(&self, g: &mut Option<Cork>) -> Result<(), KernelError> {
        let Some(c) = g.take() else {
            return Ok(());
        };
        self.pending.store(false, Ordering::Relaxed);
        let mut p = self.inet.params();
        p.tos = c.tos;
        p.ttl = c.ttl.unwrap_or(p.ttl);
        let sport = self.inet.get().sport;
        self.send_out(&c.rt, sport, c.dport, &c.data, p, c.gso)
    }

    /// Drop the corked datagram (Linux udp_flush_pending_frames)
    fn flush(&self, g: &mut Option<Cork>) {
        *g = None;
        self.pending.store(false, Ordering::Relaxed);
    }

    /// The UDP_SEGMENT size of a send (Linux udp_cmsg_send): a SOL_UDP
    /// message may only be UDP_SEGMENT (a u16)
    fn cmsg_gso(&self, control: &[u8]) -> Result<u16, KernelError> {
        let mut gso = self.gso_size.load(Ordering::Relaxed);
        for r in cmsgs(control) {
            let (level, ty, d) = r?;
            if level != SOL_UDP {
                continue;
            }
            if ty != UDP_SEGMENT || d.len() != 2 {
                return Err(KernelError::InvalidArgument);
            }
            gso = u16::from_ne_bytes([d[0], d[1]]);
        }
        Ok(gso)
    }

    /// Linux udp_lib_setsockopt for SOL_UDP
    fn udp_setsockopt(&self, opt: i32, v: OptIn) -> Result<(), KernelError> {
        let val = v.int()?;
        match opt {
            UDP_CORK => {
                self.set_uflag(uf::CORK, val != 0);
                if val == 0 {
                    let mut g = self.op.lock();
                    // Linux ignores udp_push_pending_frames' result here
                    let _ = self.push(&mut g);
                }
            }
            UDP_ENCAP => match val {
                0 | UDP_ENCAP_L2TPINUDP => self.encap_type.store(val as u16, Ordering::Relaxed),
                _ => return Err(KernelError::NoProtocolOption),
            },
            UDP_NO_CHECK6_TX => self.set_uflag(uf::NO_CHECK6_TX, val != 0),
            UDP_NO_CHECK6_RX => self.set_uflag(uf::NO_CHECK6_RX, val != 0),
            UDP_SEGMENT => {
                if !(0..=i32::from(u16::MAX)).contains(&val) {
                    return Err(KernelError::InvalidArgument);
                }
                self.gso_size.store(val as u16, Ordering::Relaxed);
            }
            UDP_GRO => self.set_uflag(uf::GRO_ENABLED, val != 0),
            _ => return Err(KernelError::NoProtocolOption),
        }
        Ok(())
    }

    /// Linux udp_lib_getsockopt
    fn udp_getsockopt(&self, opt: i32) -> Result<OptOut, KernelError> {
        let v = match opt {
            UDP_CORK => i32::from(self.uflag(uf::CORK)),
            UDP_ENCAP => i32::from(self.encap_type.load(Ordering::Relaxed)),
            UDP_NO_CHECK6_TX => i32::from(self.uflag(uf::NO_CHECK6_TX)),
            UDP_NO_CHECK6_RX => i32::from(self.uflag(uf::NO_CHECK6_RX)),
            UDP_SEGMENT => i32::from(self.gso_size.load(Ordering::Relaxed)),
            UDP_GRO => i32::from(self.uflag(uf::GRO_ENABLED)),
            _ => return Err(KernelError::NoProtocolOption),
        };
        Ok(OptOut::Int(v))
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
        // Linux udp_destroy_sock: udp_flush_pending_frames
        self.flush(&mut self.op.lock());
        self.unhash();
        self.sk.set_shutdown(SHUTDOWN_MASK);
        self.rxq.clear();
        self.sk.purge_err();
        // Linux sk_common_release's sock_put: the last reference
        self.sk.inuse_end();
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
        // Linux __ip4_datagram_connect: addresses before the rehash
        let mut s = self.inet.addr.lock();
        s.daddr = rt.daddr;
        s.dport = dport;
        if s.saddr.is_unspecified() {
            s.saddr = rt.saddr;
        }
        let rehash = s.rcv_saddr.is_unspecified();
        if rehash {
            s.rcv_saddr = rt.saddr;
        }
        drop(s);
        if rehash {
            table::rehash(self);
        }
        self.connected.store(true, Ordering::Release);
        // Linux __ip4_datagram_connect: reuseport_has_conns_set
        if !self.reuse.is_none() {
            self.reuse.set_conns(&sock_reuseport::lock());
        }
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
        dgram::poll(&self.sk, self.rxq.readable())
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
            SOL_UDP => Some(self.udp_setsockopt(opt, v)),
            _ => Some(Err(KernelError::NoProtocolOption)),
        }
    }

    fn getsockopt(&self, level: i32, opt: i32) -> Option<Result<OptOut, KernelError>> {
        match level {
            SOL_SOCKET => None,
            SOL_IP if opt == af_inet::IP_MTU => Some(self.mtu().map(OptOut::Int)),
            SOL_IP => Some(self.inet.getsockopt(opt)),
            SOL_UDP => Some(self.udp_getsockopt(opt)),
            // Linux do_ip_getsockopt: other levels are EOPNOTSUPP
            _ => Some(Err(KernelError::OperationNotSupported)),
        }
    }

    /// Linux udp_sendmsg: with UDP_CORK or MSG_MORE the data is corked
    /// (appended to a datagram sent when a send without either comes,
    /// or UDP_CORK is cleared); a send to a corked socket appends,
    /// whatever its address and control messages
    fn sendmsg(&self, m: &mut SendMsg<'_>, flags: i32) -> Result<usize, KernelError> {
        // Linux inet_sendmsg -> inet_send_prepare: an unhashed socket
        // (never bound, or disconnected) gets an ephemeral port before
        // udp_sendmsg runs, a corked one too
        self.autobind()?;
        let len = m.data.len();
        if len > 0xffff {
            return Err(KernelError::MessageTooLong);
        }
        if flags & MSG_OOB != 0 {
            return Err(KernelError::OperationNotSupported);
        }
        let corkreq = self.uflag(uf::CORK) || flags & MSG_MORE != 0;
        if self.pending.load(Ordering::Relaxed) {
            let mut g = self.op.lock();
            if g.is_some() {
                // Linux do_append_data: any ip_append_data error (a
                // fault copying the data included) drops the cork
                let data = match m.data.take(len) {
                    Ok(d) => d,
                    Err(e) => {
                        self.flush(&mut g);
                        return Err(e);
                    }
                };
                self.append(&mut g, &data, len, corkreq)?;
                return Ok(len);
            }
        }
        if len > UDP_MAX {
            return Err(KernelError::MessageTooLong);
        }
        let (daddr, dport, _connected) = self.dest(m)?;
        let gso = self.cmsg_gso(&m.control)?;
        let c = tx_cmsgs(&m.control)?;
        let data = m.data.take(len)?;
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
        // Linux sock_alloc_send_pskb, for the datagram's first skb (a
        // corked one's later appends allocate with no error check,
        // __ip_append_data with transhdrlen 0): a pending error first
        if let Some(e) = self.sk.take_err() {
            return Err(e);
        }
        if !corkreq {
            let mut p = self.inet.params();
            p.tos = c.tos.unwrap_or(p.tos);
            p.ttl = c.ttl.unwrap_or(p.ttl);
            self.send_out(&rt, a.sport, dport, &data, p, gso)?;
            return Ok(len);
        }
        let now = IpParams {
            pmtudisc: self.inet.pmtudisc(),
            ..Default::default()
        };
        let mut g = self.op.lock();
        if g.is_some() {
            // Linux: "socket already corked" by a racing send
            return Err(KernelError::InvalidArgument);
        }
        *g = Some(Cork {
            fragsize: now.mtu(&rt),
            rt,
            dport,
            tos: c.tos.unwrap_or(self.inet.tos()),
            ttl: c.ttl,
            gso,
            len: 0,
            data: Vec::new(),
        });
        self.pending.store(true, Ordering::Relaxed);
        self.append(&mut g, &data, len + UDP_HLEN, corkreq)?;
        Ok(len)
    }

    /// Linux udp_recvmsg
    fn recvmsg(&self, m: &mut RecvMsg<'_>, flags: i32) -> Result<usize, KernelError> {
        if flags & MSG_ERRQUEUE != 0 {
            return af_inet::ip_recv_error(&self.sk, &self.inet, m);
        }
        let mut off = self.sk.peek_offset(flags);
        let Some(d) = self.rxq.recv(&self.sk, flags, &mut off)? else {
            return Ok(0);
        };
        let peeking = flags & MSG_PEEK != 0;
        let r = self.deliver(m, &d, flags, off.max(0) as usize);
        if !peeking {
            // Linux udp_recvmsg: a datagram is counted when it is read
            let f = if r.is_ok() {
                UDP_MIB_INDATAGRAMS
            } else {
                self.sk.drops.fetch_add(1, Ordering::Relaxed);
                UDP_MIB_INERRORS
            };
            self.sk.net.mib.udp.inc(f);
        }
        // Linux skb_consume_udp: the peek offset moves past what a peek
        // returned, back by what a read consumed
        if let Ok(n) = r
            && self.peeking_with_offset.load(Ordering::Relaxed)
        {
            let n = n as i32;
            self.sk.peek_offset_bwd(if peeking { -n } else { n });
        }
        r
    }

    /// Linux sk_set_peek_off via udp_set_peek_off
    fn set_peek_off(&self, val: i32) -> Option<Result<(), KernelError>> {
        self.sk.set_peek_off(val);
        self.peeking_with_offset.store(val >= 0, Ordering::Relaxed);
        Some(Ok(()))
    }

    fn has_set_peek_off(&self) -> bool {
        true
    }
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
        return table::mcast_deliver(&net, skb, &k);
    }
    match table::lookup(&net, &k) {
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
    let rmem_min = net.sysctl.udp_rmem_min.load(Ordering::Relaxed) as usize;
    let Err(e) = s.rxq.enqueue(&s.sk, rmem_min, skb) else {
        return;
    };
    let udp = &net.mib.udp;
    udp.inc(match e {
        dgram::QueueErr::RcvBuf => UDP_MIB_RCVBUFERRORS,
        dgram::QueueErr::NoMem => UDP_MIB_MEMERRORS,
    });
    udp.inc(UDP_MIB_INERRORS);
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
    let Some(s) = table::lookup(net, &k) else {
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
        // A socket moving slots meanwhile may be missed or listed
        // twice, as Linux's seq walk of the slots
        let g = crate::sync::rcu::read_lock();
        for (i, slot) in table::hash_slots().iter().enumerate() {
            for e in slot.head.iter_rcu(&g) {
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

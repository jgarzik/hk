//! ICMP echo ("ping") sockets: socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
//! (Linux net/ipv4/ping.c)
//!
//! Creation is allowed only to tasks whose effective group is in
//! net.ipv4.ping_group_range (default "1 0": nobody, root included; no
//! CAP_NET_RAW bypass). The local "port" is the echo identifier: bind
//! picks it (0 = next free from a rover), the kernel writes it into
//! every request, and echo replies are demultiplexed by it (plus bound
//! address and device). recvmsg returns the ICMP header and payload;
//! ICMP errors about our requests are reported like UDP (IP_RECVERR).
//!
//! ## Locking (thread context only)
//!
//! `PingSock.op` (socket lock, sleeping `sync::Mutex` as Linux lock_sock:
//! bind/connect/autobind, socket calls only) -> `PingTable.lock` (spin,
//! Linux ping_table.lock: identifier search and insert, removal) -> a
//! chain's writer lock -> `Inet.addr`; `RxQueue` and `Sock.errq` are
//! separate leaves. Receive and error lookups walk a chain under RCU,
//! take a reference to the match under the guard and queue after
//! dropping it. A socket's table reference is released a grace period
//! after it leaves (Linux SOCK_RCU_FREE), possibly in `rcuc/N`: its
//! drop takes no sleeping lock.

use crate::mm::page_alloc::Gfp;
use crate::util::kalloc::try_arc_cyclic;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};

use crate::sync::rcu::RcuHead;
use crate::sync::spin::Mutex;
use crate::util::rcuhlist::{self, HNode, RcuHList};

use crate::net::af_inet::{self, Inet, RxInfo, SOL_IP};
use crate::net::dgram::{self, RxQueue};
use crate::net::icmp::{IcmpErr, icmp_type};
use crate::net::inet::fib::RouteType;
use crate::net::inet::route;
use crate::net::ipv4::{self, IPPROTO_ICMP, Ipv4Addr, ip_checksum};
use crate::net::msg::{MSG_ERRQUEUE, MSG_OOB, MSG_TRUNC, RecvMsg, SendMsg};
use crate::net::skb::SkBuff;
use crate::net::sock::{SHUTDOWN_MASK, Sock, sf};
use crate::net::socket::{
    AF_INET, AF_UNSPEC, OptIn, OptOut, ProtoOps, SOCK_DGRAM, SOL_SOCKET, shut_bits,
};
use crate::net::{NetNamespace, udp};
use crate::util::error::KernelError;

/// ICMP header length (struct icmphdr)
const HDR: usize = 8;

/// A ping socket
pub struct PingSock {
    sk: Sock,
    pub inet: Inet,
    /// Socket lock (Linux lock_sock, which sleeps)
    op: crate::sync::Mutex<()>,
    connected: AtomicBool,
    hashed: AtomicBool,
    rxq: RxQueue,
    me: Weak<PingSock>,
    /// Link on its identifier chain (Linux sk_node)
    node: HNode,
    /// Its table reference's release after a grace period (Linux
    /// SOCK_RCU_FREE's rcu head)
    rcu: RcuHead,
}

/// Linux ping_init_sock: the effective group or a supplementary group
/// must be in ping_group_range
fn group_ok(net: &NetNamespace) -> bool {
    let (lo, hi) = net.sysctl.ping_group();
    let c = crate::task::current_cred();
    let ok = |g: u32| lo <= g && g <= hi;
    ok(c.egid) || c.groups.as_slice().iter().any(|&g| ok(g))
}

/// socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
pub fn create() -> Result<Arc<dyn ProtoOps>, KernelError> {
    let net = crate::net::current_net_ns();
    if !group_ok(&net) {
        return Err(KernelError::PermissionDenied);
    }
    // INET_PROTOSW_REUSE: identifiers are shared unless a socket clears
    // SO_REUSEADDR
    let sk = Sock::new(net, AF_INET, SOCK_DGRAM, i32::from(IPPROTO_ICMP));
    sk.set_flag(sf::REUSEADDR, true);
    Ok(try_arc_cyclic(|me| PingSock {
        sk,
        inet: Inet::default(),
        op: crate::sync::Mutex::new(()),
        connected: AtomicBool::new(false),
        hashed: AtomicBool::new(false),
        rxq: RxQueue::default(),
        me: me.clone(),
        node: HNode::new(),
        rcu: RcuHead::new(),
    })?)
}

impl PingSock {
    fn arc(&self) -> Arc<PingSock> {
        self.me.upgrade().expect("ping socket alive")
    }

    /// Claim echo identifier `ident` (0 = pick); caller holds `op`
    fn get_port(&self, ident: u16) -> Result<u16, KernelError> {
        let id = self.sk.net.ping.insert(&self.arc(), ident)?;
        self.hashed.store(true, Ordering::Release);
        Ok(id)
    }

    /// Linux inet_autobind (EAGAIN when no identifier is free)
    fn autobind(&self) -> Result<(), KernelError> {
        let _g = self.op.lock();
        self.autobind_locked()
    }

    /// `autobind` with `op` held
    fn autobind_locked(&self) -> Result<(), KernelError> {
        if self.inet.get().sport != 0 {
            return Ok(());
        }
        let id = self.get_port(0).map_err(|_| KernelError::WouldBlock)?;
        self.inet.addr.lock().sport = id;
        Ok(())
    }

    fn unhash(&self) {
        if self.hashed.swap(false, Ordering::AcqRel) {
            self.sk.net.ping.remove(self, self.inet.get().sport);
        }
    }

    /// Linux __udp_disconnect (ping uses it too)
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

    /// Output route checked for broadcast permission
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

    /// Destination of a send (Linux ping_v4_sendmsg; no port)
    fn dest(&self, m: &SendMsg<'_>) -> Result<Ipv4Addr, KernelError> {
        match &m.addr {
            Some(a) => Ok(af_inet::sin_parse(a, false)?.0),
            None if self.connected.load(Ordering::Acquire) => Ok(self.inet.get().daddr),
            None => Err(KernelError::DestAddrRequired),
        }
    }

    /// The echo request: the user's type/code/sequence, our identifier,
    /// a fresh checksum
    fn build(&self, user: &[u8], ident: u16) -> Result<alloc::boxed::Box<SkBuff>, KernelError> {
        let mut skb =
            SkBuff::alloc_tx(user.len(), Gfp::KERNEL).ok_or(KernelError::NoBufferSpace)?;
        skb.put_slice(user).ok_or(KernelError::NoBufferSpace)?;
        let h = skb.data_mut();
        h[2] = 0;
        h[3] = 0;
        h[4..6].copy_from_slice(&ident.to_be_bytes());
        let c = ip_checksum(h);
        h[2..4].copy_from_slice(&c.to_be_bytes());
        Ok(skb)
    }
}

/// Bind address check (Linux ping_check_bind_addr): EINVAL if short,
/// EAFNOSUPPORT unless AF_INET (or AF_UNSPEC with INADDR_ANY),
/// EADDRNOTAVAIL for multicast, broadcast or non-local addresses
fn check_bind_addr(sk: &Sock, inet: &Inet, a: &[u8]) -> Result<(Ipv4Addr, u16), KernelError> {
    if a.len() < af_inet::SIN_LEN {
        return Err(KernelError::InvalidArgument);
    }
    let fam = af_inet::sa_family(a)?;
    let (addr, port) = af_inet::sin_parse(a, true)?;
    if fam == AF_UNSPEC && !addr.is_unspecified() {
        return Err(KernelError::AddressFamilyNotSupported);
    }
    if addr.is_unspecified() {
        return Ok((addr, port));
    }
    match sk.net.fib.addr_type(addr) {
        RouteType::Multicast | RouteType::Broadcast => Err(KernelError::AddressNotAvailable),
        RouteType::Local => Ok((addr, port)),
        _ if inet.flag(af_inet::ipf::FREEBIND) => Ok((addr, port)),
        _ => Err(KernelError::AddressNotAvailable),
    }
}

impl ProtoOps for PingSock {
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

    /// Linux ping_bind
    fn bind(&self, a: &[u8]) -> Result<(), KernelError> {
        let (addr, ident) = check_bind_addr(&self.sk, &self.inet, a)?;
        let _g = self.op.lock();
        if self.inet.get().sport != 0 {
            return Err(KernelError::InvalidArgument);
        }
        // Address before the identifier table entry (Linux inet_bind)
        self.inet.set_saddrs(addr, addr);
        let id = match self.get_port(ident) {
            Ok(id) => id,
            Err(e) => {
                self.inet
                    .set_saddrs(Ipv4Addr::default(), Ipv4Addr::default());
                return Err(e);
            }
        };
        let mut s = self.inet.addr.lock();
        s.sport = id;
        s.daddr = Ipv4Addr::default();
        s.dport = 0;
        s.addr_lock = !addr.is_unspecified();
        s.port_lock = ident != 0;
        drop(s);
        self.connected.store(false, Ordering::Release);
        Ok(())
    }

    /// Linux inet_dgram_connect + __ip4_datagram_connect
    fn connect(&self, a: &[u8], _nonblock: bool) -> Result<(), KernelError> {
        if af_inet::sa_family(a)? == AF_UNSPEC {
            self.disconnect();
            return Ok(());
        }
        let (daddr, dport) = af_inet::sin_parse(a, false)?;
        let _g = self.op.lock();
        self.autobind_locked()?;
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

    fn shutdown(&self, how: i32) -> Result<(), KernelError> {
        self.sk.set_shutdown(shut_bits(how)?);
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
            SOL_IP => Some(self.inet.getsockopt(opt)),
            _ => Some(Err(KernelError::OperationNotSupported)),
        }
    }

    /// Linux ping_v4_sendmsg (after inet_sendmsg's autobind)
    fn sendmsg(&self, m: &mut SendMsg<'_>, flags: i32) -> Result<usize, KernelError> {
        self.autobind()?;
        let len = m.data.len();
        if len > 0xffff {
            return Err(KernelError::MessageTooLong);
        }
        if len < HDR {
            return Err(KernelError::InvalidArgument);
        }
        if flags & MSG_OOB != 0 {
            return Err(KernelError::OperationNotSupported);
        }
        let user = m.data.take(len)?;
        if user[0] != icmp_type::ECHO || user[1] != 0 {
            return Err(KernelError::InvalidArgument);
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
        if let Some(e) = self.sk.take_err() {
            return Err(e);
        }
        let mut skb = self.build(&user, a.sport)?;
        skb.saddr = Some(rt.saddr);
        skb.daddr = Some(rt.daddr);
        let mut p = self.inet.params();
        p.tos = c.tos.unwrap_or(p.tos);
        p.ttl = c.ttl.unwrap_or(p.ttl);
        match ipv4::ip_send_rt(&self.sk.net, &rt, skb, IPPROTO_ICMP, p) {
            Err(KernelError::MessageTooLong) => {
                let e = KernelError::MessageTooLong;
                af_inet::ip_local_error(&self.sk, &self.inet, e, rt.daddr, a.dport, rt.mtu);
                Err(e)
            }
            r => r.map(|()| len),
        }
    }

    /// Linux ping_recvmsg: ICMP header + payload, source address with
    /// port 0
    fn recvmsg(&self, m: &mut RecvMsg<'_>, flags: i32) -> Result<usize, KernelError> {
        if flags & MSG_OOB != 0 {
            return Err(KernelError::OperationNotSupported);
        }
        if flags & MSG_ERRQUEUE != 0 {
            return af_inet::ip_recv_error(&self.sk, &self.inet, m);
        }
        let Some(d) = self.rxq.recv(&self.sk, flags)? else {
            return Ok(0);
        };
        // Linux ping_recvmsg returns what it copied, MSG_TRUNC or not
        dgram::deliver(&self.sk, &self.inet, m, &d, flags & !MSG_TRUNC)
    }
}

// ============================================================================
// Identifier table (per namespace)
// ============================================================================

/// Chains of the identifier table (Linux PING_HTABLE_SIZE)
const PING_HTABLE_SIZE: usize = 64;

crate::hadapter!(PingNode, PingSock, node);
crate::rcu_head!(PingSock, rcu);

/// Bound ping sockets of a namespace, hashed by echo identifier (Linux
/// struct ping_table: hlist chains read under RCU, changed under the
/// table lock)
pub struct PingTable {
    hash: [RcuHList<PingNode>; PING_HTABLE_SIZE],
    /// Linux ping_table.lock: an identifier search and the insert it
    /// decides are one step; removals too
    lock: Mutex<()>,
    /// Last identifier handed out (Linux ping_port_rover)
    rover: AtomicU16,
}

impl Default for PingTable {
    fn default() -> Self {
        Self {
            hash: [const { RcuHList::new() }; PING_HTABLE_SIZE],
            lock: Mutex::new(()),
            rover: AtomicU16::new(0),
        }
    }
}

impl PingTable {
    /// Linux ping_hashslot (the table is per namespace already)
    fn slot(&self, ident: u16) -> &RcuHList<PingNode> {
        &self.hash[usize::from(ident) % PING_HTABLE_SIZE]
    }

    /// Some socket other than `s` on its chain holds `ident` and they
    /// may not share it (shared only when both set SO_REUSEADDR)
    fn busy(&self, ident: u16, s: Option<&PingSock>) -> bool {
        let mut busy = false;
        self.slot(ident).for_each(|o| {
            let mine = s.is_some_and(|s| core::ptr::eq(o, s));
            let shared = s.is_some_and(|s| s.sk.flag(sf::REUSEADDR) && o.sk.flag(sf::REUSEADDR));
            busy |= !mine && o.inet.get().sport == ident && !shared;
        });
        busy
    }

    /// Hash `s` under `ident` (0 = the next unused one after the rover)
    /// and set it as its identifier, all under the table lock (Linux
    /// ping_get_port); EADDRINUSE if taken or none is free
    fn insert(&self, s: &Arc<PingSock>, ident: u16) -> Result<u16, KernelError> {
        let _t = self.lock.lock();
        let id = if ident == 0 {
            let start = self.rover.load(Ordering::Relaxed);
            let id = (1..=u16::MAX)
                .map(|i| start.wrapping_add(i))
                .find(|&p| p != 0 && !self.busy(p, None))
                .ok_or(KernelError::AddressInUse)?;
            self.rover.store(id, Ordering::Relaxed);
            id
        } else {
            if self.busy(ident, Some(s)) {
                return Err(KernelError::AddressInUse);
            }
            ident
        };
        s.inet.addr.lock().sport = id;
        if !s.node.is_hashed() {
            self.slot(id).add_head(s.clone());
        }
        Ok(id)
    }

    /// Linux ping_unhash: off its chain; the table's reference goes
    /// after a grace period (Linux SOCK_RCU_FREE)
    fn remove(&self, s: &PingSock, ident: u16) {
        let gone = {
            let _t = self.lock.lock();
            self.slot(ident).del_init(s)
        };
        if let Some(g) = gone {
            g.defer();
        }
    }

    /// Socket for identifier `ident` of a packet to `daddr` received on
    /// `dif` (Linux ping_lookup: the first match, under RCU), with a
    /// reference taken under the guard (sock_hold)
    fn lookup(&self, ident: u16, daddr: Ipv4Addr, dif: u32) -> Option<Arc<PingSock>> {
        let g = crate::sync::rcu::read_lock();
        let s = self.slot(ident).iter(&g).find(|s| {
            let a = s.inet.get();
            let dev = s.sk.bound_dev_if();
            a.sport == ident
                && (a.rcv_saddr.is_unspecified() || a.rcv_saddr == daddr)
                && (dev == 0 || dev == dif)
        })?;
        Some(rcuhlist::get::<PingNode>(s, &g))
    }
}

/// An echo reply arrived (Linux ping_rcv; `skb.data()` is the ICMP
/// message)
pub fn ping_rcv(net: &NetNamespace, skb: &SkBuff) {
    let d = skb.data();
    let ident = u16::from_be_bytes([d[4], d[5]]);
    let dif = skb.dev.as_ref().map_or(0, |d| d.ifindex());
    let Some(s) = net.ping.lookup(ident, skb.daddr.unwrap_or_default(), dif) else {
        return;
    };
    let info = RxInfo::of(net, skb);
    // A clone that cannot be allocated drops the reply (Linux ping_rcv:
    // skb_clone(GFP_ATOMIC) failure)
    if let Some(mut c) = skb.clone_gfp(Gfp::ATOMIC) {
        dgram::prepare(&mut c, info, 0);
        s.rxq.enqueue(&s.sk, c);
    }
}

/// An ICMP error about one of our echo requests (Linux ping_err)
pub fn ping_err(net: &NetNamespace, e: &IcmpErr<'_>) {
    let l4 = e.l4();
    if l4[0] != icmp_type::ECHO || l4[1] != 0 {
        return;
    }
    let ident = u16::from_be_bytes([l4[4], l4[5]]);
    let Some(s) = net.ping.lookup(ident, e.rx.daddr, e.rx.ifindex) else {
        return;
    };
    // Source quench is no error, but ping wants to see it
    let r = if e.ty == icmp_type::SOURCE_QUENCH {
        Some((KernelError::RemoteIo, false))
    } else {
        e.errno(s.inet.pmtudisc())
    };
    let Some((err, hard)) = r else {
        return;
    };
    if s.inet.flag(af_inet::ipf::RECVERR) {
        af_inet::ip_icmp_error(&s.sk, e, err, 0, l4);
    } else if !hard || !s.connected.load(Ordering::Acquire) {
        return;
    }
    s.sk.set_err(err);
}

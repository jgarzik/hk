//! AF_INET sockets (Linux net/ipv4/af_inet.c, ip_sockglue.c)
//!
//! `create` dispatches (type, protocol) to the transport (Linux inetsw:
//! TCP and UDP today; raw and ping sockets in P5). `Inet` is the
//! IPv4 part of a transport socket (Linux inet_sock): addresses, ports,
//! IP-level options. IPv6 will add a sibling family reusing the TCP/UDP
//! cores with its own address part.
//!
//! ## Locking
//!
//! `Inet.addr` is a `spin::Mutex` leaf (thread context only); the
//! IP-level options are atomics.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, AtomicU8, AtomicU16, AtomicU32, Ordering};

use spin::Mutex;

use crate::error::KernelError;
use crate::net::inet::fib::RouteType;
use crate::net::ipv4::{IP_DEFAULT_TTL, IpParams, Ipv4Addr};
use crate::net::msg::Cmsg;
use crate::net::sock::Sock;
use crate::net::socket::{AF_INET, AF_UNSPEC, OptIn, OptOut, ProtoOps, SOCK_DGRAM, SOCK_STREAM};

pub const IPPROTO_IP: i32 = 0;
pub const IPPROTO_TCP: i32 = 6;
pub const IPPROTO_UDP: i32 = 17;
pub const SOL_IP: i32 = 0;

/// IP-level options
pub const IP_TOS: i32 = 1;
pub const IP_TTL: i32 = 2;
pub const IP_HDRINCL: i32 = 3;
pub const IP_PKTINFO: i32 = 8;
pub const IP_MTU_DISCOVER: i32 = 10;
pub const IP_RECVERR: i32 = 11;
pub const IP_RECVTTL: i32 = 12;
pub const IP_RECVTOS: i32 = 13;
pub const IP_MTU: i32 = 14;
pub const IP_FREEBIND: i32 = 15;
pub const IP_BIND_ADDRESS_NO_PORT: i32 = 24;
pub const IP_MULTICAST_TTL: i32 = 33;
pub const IP_MULTICAST_LOOP: i32 = 34;

/// sizeof(struct sockaddr_in)
pub const SIN_LEN: usize = 16;

/// socket(AF_INET, type, protocol) (Linux inet_create over inetsw)
pub fn create(stype: i32, protocol: i32) -> Result<Arc<dyn ProtoOps>, KernelError> {
    match stype {
        SOCK_STREAM => match protocol {
            IPPROTO_IP | IPPROTO_TCP => Ok(crate::net::tcp::create()),
            _ => Err(KernelError::ProtocolNotSupported),
        },
        SOCK_DGRAM => match protocol {
            IPPROTO_IP | IPPROTO_UDP => Ok(crate::net::udp::create()),
            _ => Err(KernelError::ProtocolNotSupported),
        },
        _ => Err(KernelError::SocketTypeNotSupported),
    }
}

/// Addresses and ports (network order kept as host values)
#[derive(Clone, Copy, Debug, Default)]
pub struct InetAddr {
    /// Bound receive address (Linux inet_rcv_saddr)
    pub rcv_saddr: Ipv4Addr,
    /// Source address for output (Linux inet_saddr)
    pub saddr: Ipv4Addr,
    /// Local port (0 = unbound)
    pub sport: u16,
    pub daddr: Ipv4Addr,
    /// Remote port (0 = not connected)
    pub dport: u16,
    /// bind() fixed the address / the port (Linux sk_userlocks)
    pub addr_lock: bool,
    pub port_lock: bool,
}

/// IP part of a transport socket (Linux inet_sock)
pub struct Inet {
    pub addr: Mutex<InetAddr>,
    /// Unicast TTL (-1 = sysctl default)
    ttl: AtomicI32,
    tos: AtomicU8,
    /// IP_PKTINFO / IP_RECVTTL / IP_RECVTOS / IP_RECVERR / ... (`ipf`)
    flags: AtomicU32,
    pmtudisc: AtomicU8,
    mc_ttl: AtomicU8,
    /// IP id counter of a connected socket (Linux inet_id)
    id: AtomicU16,
}

/// `Inet.flags` bits
pub mod ipf {
    pub const PKTINFO: u32 = 1 << 0;
    pub const RECVTTL: u32 = 1 << 1;
    pub const RECVTOS: u32 = 1 << 2;
    pub const RECVERR: u32 = 1 << 3;
    pub const FREEBIND: u32 = 1 << 4;
    pub const BIND_NO_PORT: u32 = 1 << 5;
    pub const MC_LOOP: u32 = 1 << 6;
}

impl Default for Inet {
    fn default() -> Self {
        Self {
            addr: Mutex::new(InetAddr::default()),
            ttl: AtomicI32::new(-1),
            tos: AtomicU8::new(0),
            flags: AtomicU32::new(ipf::MC_LOOP),
            pmtudisc: AtomicU8::new(crate::net::ipv4::pmtu::WANT),
            mc_ttl: AtomicU8::new(1),
            id: AtomicU16::new(crate::random::get_random_u32() as u16),
        }
    }
}

impl Inet {
    pub fn get(&self) -> InetAddr {
        *self.addr.lock()
    }

    pub fn flag(&self, f: u32) -> bool {
        self.flags.load(Ordering::Acquire) & f != 0
    }

    fn set_flag(&self, f: u32, on: bool) {
        if on {
            self.flags.fetch_or(f, Ordering::AcqRel);
        } else {
            self.flags.fetch_and(!f, Ordering::AcqRel);
        }
    }

    /// TTL for output
    pub fn ttl(&self) -> u8 {
        match self.ttl.load(Ordering::Acquire) {
            -1 => IP_DEFAULT_TTL,
            t => t as u8,
        }
    }

    pub fn tos(&self) -> u8 {
        self.tos.load(Ordering::Acquire)
    }

    pub fn pmtudisc(&self) -> u8 {
        self.pmtudisc.load(Ordering::Acquire)
    }

    /// IP parameters of the next packet (Linux ip_select_ident_segs:
    /// a connected socket numbers its packets from its own counter)
    pub fn params(&self) -> IpParams {
        let connected = !self.get().daddr.is_unspecified();
        IpParams {
            tos: self.tos(),
            ttl: self.ttl(),
            pmtudisc: self.pmtudisc(),
            id: connected.then(|| self.id.fetch_add(1, Ordering::Relaxed)),
        }
    }

    /// A child (accept) inherits the options of its listener
    pub fn clone_opts(&self, p: &Inet) {
        self.ttl
            .store(p.ttl.load(Ordering::Relaxed), Ordering::Relaxed);
        self.tos.store(p.tos(), Ordering::Relaxed);
        self.flags
            .store(p.flags.load(Ordering::Relaxed), Ordering::Relaxed);
    }

    /// setsockopt(SOL_IP) (Linux do_ip_setsockopt subset)
    pub fn setsockopt(&self, sk: &Sock, opt: i32, v: OptIn) -> Result<(), KernelError> {
        let bool_flag = match opt {
            IP_PKTINFO => Some(ipf::PKTINFO),
            IP_RECVTTL => Some(ipf::RECVTTL),
            IP_RECVTOS => Some(ipf::RECVTOS),
            IP_RECVERR => Some(ipf::RECVERR),
            IP_FREEBIND => Some(ipf::FREEBIND),
            IP_BIND_ADDRESS_NO_PORT => Some(ipf::BIND_NO_PORT),
            IP_MULTICAST_LOOP => Some(ipf::MC_LOOP),
            _ => None,
        };
        if let Some(f) = bool_flag {
            self.set_flag(f, v.int_or_byte()? != 0);
            return Ok(());
        }
        match opt {
            IP_TOS => {
                let mut t = v.int_or_byte()? as u8;
                if sk.stype == SOCK_STREAM {
                    // ECN bits belong to TCP
                    t = (t & !3) | (self.tos() & 3);
                }
                self.tos.store(t, Ordering::Release);
            }
            IP_TTL => {
                let t = v.int_or_byte()?;
                if t != -1 && !(1..=255).contains(&t) {
                    return Err(KernelError::InvalidArgument);
                }
                self.ttl.store(t, Ordering::Release);
            }
            IP_MTU_DISCOVER => {
                let m = v.int_or_byte()?;
                if !(0..=5).contains(&m) {
                    return Err(KernelError::InvalidArgument);
                }
                self.pmtudisc.store(m as u8, Ordering::Release);
            }
            IP_MULTICAST_TTL => {
                let t = v.int_or_byte()?;
                let t = if t == -1 { 1 } else { t };
                if !(0..=255).contains(&t) {
                    return Err(KernelError::InvalidArgument);
                }
                self.mc_ttl.store(t as u8, Ordering::Release);
            }
            _ => return Err(KernelError::NoProtocolOption),
        }
        Ok(())
    }

    /// getsockopt(SOL_IP)
    pub fn getsockopt(&self, opt: i32) -> Result<OptOut, KernelError> {
        let v = match opt {
            IP_TOS => self.tos() as i32,
            IP_TTL => self.ttl() as i32,
            IP_PKTINFO => self.flag(ipf::PKTINFO) as i32,
            IP_RECVTTL => self.flag(ipf::RECVTTL) as i32,
            IP_RECVTOS => self.flag(ipf::RECVTOS) as i32,
            IP_RECVERR => self.flag(ipf::RECVERR) as i32,
            IP_FREEBIND => self.flag(ipf::FREEBIND) as i32,
            IP_BIND_ADDRESS_NO_PORT => self.flag(ipf::BIND_NO_PORT) as i32,
            IP_MTU_DISCOVER => self.pmtudisc.load(Ordering::Acquire) as i32,
            IP_MULTICAST_TTL => self.mc_ttl.load(Ordering::Acquire) as i32,
            IP_MULTICAST_LOOP => self.flag(ipf::MC_LOOP) as i32,
            _ => return Err(KernelError::NoProtocolOption),
        };
        Ok(OptOut::Int(v))
    }

    /// Receive control messages for a datagram (Linux
    /// ip_cmsg_recv_offset): IP_PKTINFO, IP_TTL, IP_TOS
    pub fn recv_cmsgs(&self, c: &mut Cmsg, info: &RxInfo) {
        if self.flag(ipf::PKTINFO) {
            let mut b = [0u8; 12];
            b[..4].copy_from_slice(&info.ifindex.to_ne_bytes());
            b[4..8].copy_from_slice(&info.spec_dst.to_be_bytes());
            b[8..12].copy_from_slice(&info.daddr.to_be_bytes());
            c.put(SOL_IP, IP_PKTINFO, &b);
        }
        if self.flag(ipf::RECVTTL) {
            c.put(SOL_IP, IP_TTL, &(info.ttl as i32).to_ne_bytes());
        }
        if self.flag(ipf::RECVTOS) {
            c.put(SOL_IP, IP_TOS, &[info.tos]);
        }
    }
}

/// Per-datagram receive metadata kept for control messages
#[derive(Clone, Copy, Debug, Default)]
pub struct RxInfo {
    pub ifindex: u32,
    /// Local address the datagram was for (in_pktinfo.ipi_spec_dst)
    pub spec_dst: Ipv4Addr,
    /// Header destination (in_pktinfo.ipi_addr)
    pub daddr: Ipv4Addr,
    pub ttl: u8,
    pub tos: u8,
}

/// A struct sockaddr_in
pub fn sin_bytes(addr: Ipv4Addr, port: u16) -> Vec<u8> {
    let mut b = alloc::vec![0u8; SIN_LEN];
    b[..2].copy_from_slice(&AF_INET.to_ne_bytes());
    b[2..4].copy_from_slice(&port.to_be_bytes());
    b[4..8].copy_from_slice(&addr.to_be_bytes());
    b
}

/// Family field of a socket address (EINVAL if too short for it)
pub fn sa_family(a: &[u8]) -> Result<u16, KernelError> {
    if a.len() < 2 {
        return Err(KernelError::InvalidArgument);
    }
    Ok(u16::from_ne_bytes([a[0], a[1]]))
}

/// Parse a sockaddr_in: EINVAL if short, EAFNOSUPPORT unless AF_INET
/// (or AF_UNSPEC where `unspec_ok`, Linux compatibility games)
pub fn sin_parse(a: &[u8], unspec_ok: bool) -> Result<(Ipv4Addr, u16), KernelError> {
    if a.len() < SIN_LEN {
        return Err(KernelError::InvalidArgument);
    }
    let fam = sa_family(a)?;
    if fam != AF_INET && !(unspec_ok && fam == AF_UNSPEC) {
        return Err(KernelError::AddressFamilyNotSupported);
    }
    let port = u16::from_be_bytes([a[2], a[3]]);
    let addr = Ipv4Addr::from_be_bytes([a[4], a[5], a[6], a[7]]);
    Ok((addr, port))
}

/// Ports below this need CAP_NET_BIND_SERVICE (ip_unprivileged_port_start)
const PROT_SOCK: u16 = 1024;

/// bind() address/port checks shared by UDP and TCP (Linux
/// __inet_bind): AF_UNSPEC only with INADDR_ANY; EADDRNOTAVAIL for an
/// address that is not local (unless IP_FREEBIND); EACCES for a
/// privileged port. Returns (address, port, address type).
pub fn bind_check(
    sk: &Sock,
    inet: &Inet,
    a: &[u8],
) -> Result<(Ipv4Addr, u16, RouteType), KernelError> {
    if a.len() < SIN_LEN {
        return Err(KernelError::InvalidArgument);
    }
    let fam = sa_family(a)?;
    let (addr, port) = sin_parse(a, true)?;
    if fam == AF_UNSPEC && !addr.is_unspecified() {
        return Err(KernelError::AddressFamilyNotSupported);
    }
    let ty = if addr.is_unspecified() {
        RouteType::Unicast
    } else {
        sk.net.fib.addr_type(addr)
    };
    let ok = addr.is_unspecified()
        || matches!(
            ty,
            RouteType::Local | RouteType::Multicast | RouteType::Broadcast
        )
        || inet.flag(ipf::FREEBIND);
    if !ok {
        return Err(KernelError::AddressNotAvailable);
    }
    if port != 0 && port < PROT_SOCK && !crate::task::capable(crate::task::CAP_NET_BIND_SERVICE) {
        return Err(KernelError::PermissionDenied);
    }
    Ok((addr, port, ty))
}

// ============================================================================
// Extended errors (Linux ip_sockglue.c ip_icmp_error / ip_local_error /
// ip_recv_error)
// ============================================================================

/// Queue an ICMP error for a socket with IP_RECVERR (Linux
/// ip_icmp_error): the offending packet's destination and `port` become
/// msg_name, `payload` (its transport payload as quoted) the data
pub fn ip_icmp_error(
    sk: &Sock,
    e: &crate::net::icmp::IcmpErr,
    errno: KernelError,
    port: u16,
    payload: &[u8],
) {
    sk.queue_err(crate::net::sock::ErrSkb {
        errno: errno as u32,
        origin: crate::net::sock::EE_ORIGIN_ICMP,
        ty: e.ty,
        code: e.code,
        info: e.info,
        name: sin_bytes(e.inner_daddr(), port),
        offender: sin_bytes(e.from, 0),
        payload: payload.to_vec(),
        rx: Some(e.rx),
    });
}

/// Queue a locally detected error (EMSGSIZE) if IP_RECVERR is on (Linux
/// ip_local_error)
pub fn ip_local_error(
    sk: &Sock,
    inet: &Inet,
    errno: KernelError,
    daddr: Ipv4Addr,
    port: u16,
    info: u32,
) {
    if !inet.flag(ipf::RECVERR) {
        return;
    }
    sk.queue_err(crate::net::sock::ErrSkb {
        errno: errno as u32,
        origin: crate::net::sock::EE_ORIGIN_LOCAL,
        info,
        name: sin_bytes(daddr, port),
        ..Default::default()
    });
}

/// recvmsg(MSG_ERRQUEUE) (Linux ip_recv_error): EAGAIN when empty; the
/// data is the quoted payload, msg_name the original destination, and
/// an IP_RECVERR control message carries sock_extended_err + offender
pub fn ip_recv_error(
    sk: &Sock,
    inet: &Inet,
    m: &mut crate::net::msg::RecvMsg,
) -> Result<usize, KernelError> {
    use crate::net::msg::{MSG_ERRQUEUE, MSG_TRUNC};
    let e = sk.dequeue_err().ok_or(KernelError::WouldBlock)?;
    let n = m.data.put(0, &e.payload)?;
    if n < e.payload.len() {
        m.flags |= MSG_TRUNC;
    }
    if m.want_name && !e.name.is_empty() {
        m.name = Some(e.name.clone());
    }
    let mut ee = [0u8; 32];
    ee[0..4].copy_from_slice(&e.errno.to_ne_bytes());
    ee[4] = e.origin;
    ee[5] = e.ty;
    ee[6] = e.code;
    ee[8..12].copy_from_slice(&e.info.to_ne_bytes());
    if e.origin == crate::net::sock::EE_ORIGIN_ICMP {
        ee[16..16 + e.offender.len().min(16)]
            .copy_from_slice(&e.offender[..e.offender.len().min(16)]);
        if let Some(rx) = &e.rx {
            inet.recv_cmsgs(&mut m.cmsg, rx);
        }
    }
    m.cmsg.put(SOL_IP, IP_RECVERR, &ee);
    m.flags |= MSG_ERRQUEUE;
    Ok(n)
}

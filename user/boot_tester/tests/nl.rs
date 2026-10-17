//! Minimal NETLINK_ROUTE client for the network tests (no allocator:
//! fixed buffers) and `net_setup_eth0()`, which configures the first
//! Ethernet link like `ip link set up; ip addr add 10.0.2.15/24; ip route
//! add default via 10.0.2.2` on both hk and Linux.

use core::ptr::addr_of_mut;

use hk_syscall::{
    POLLIN, PollFd, SOCK_CLOEXEC, SOCK_RAW, Timespec, sys_bind, sys_close, sys_nanosleep, sys_poll,
    sys_recvfrom, sys_sendto, sys_socket,
};

pub const AF_NETLINK: i32 = 16;
pub const NETLINK_ROUTE: i32 = 0;
pub const SOL_NETLINK: i32 = 270;
pub const NETLINK_ADD_MEMBERSHIP: i32 = 1;
pub const NETLINK_PKTINFO: i32 = 3;
pub const NETLINK_NO_ENOBUFS: i32 = 5;
pub const NETLINK_CAP_ACK: i32 = 10;
pub const NETLINK_EXT_ACK: i32 = 11;
pub const NETLINK_GET_STRICT_CHK: i32 = 12;

pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_MULTI: u16 = 0x02;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_DUMP_FILTERED: u16 = 0x20;
pub const NLM_F_CAPPED: u16 = 0x100;
pub const NLM_F_DUMP: u16 = 0x300;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;

pub const RTM_NEWLINK: u16 = 16;
pub const RTM_GETLINK: u16 = 18;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_DELADDR: u16 = 21;
pub const RTM_GETADDR: u16 = 22;
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;
pub const RTM_GETROUTE: u16 = 26;
pub const RTM_NEWNEIGH: u16 = 28;
pub const RTM_GETNEIGH: u16 = 30;
pub const RTM_NEWRULE: u16 = 32;
pub const RTM_GETRULE: u16 = 34;

pub const RTMGRP_IPV4_IFADDR: u32 = 0x10;
pub const RTNLGRP_LINK: i32 = 1;

pub const IFLA_ADDRESS: u16 = 1;
pub const IFLA_IFNAME: u16 = 3;
pub const IFLA_MTU: u16 = 4;
pub const IFLA_OPERSTATE: u16 = 16;
pub const IFA_ADDRESS: u16 = 1;
pub const IFA_LOCAL: u16 = 2;
pub const IFA_BROADCAST: u16 = 4;
pub const RTA_DST: u16 = 1;
pub const RTA_OIF: u16 = 4;
pub const RTA_GATEWAY: u16 = 5;
pub const RTA_PREFSRC: u16 = 7;

pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;
pub const ARPHRD_ETHER: u16 = 1;
pub const ARPHRD_LOOPBACK: u16 = 772;
pub const IFF_UP: u32 = 0x1;
pub const IFF_LOOPBACK: u32 = 0x8;
pub const IFF_RUNNING: u32 = 0x40;
pub const IFF_LOWER_UP: u32 = 0x10000;
pub const IF_OPER_DOWN: u8 = 2;
pub const IF_OPER_UP: u8 = 6;
pub const RT_TABLE_MAIN: u8 = 254;
pub const RT_TABLE_LOCAL: u8 = 255;
pub const RTPROT_KERNEL: u8 = 2;
pub const RTPROT_BOOT: u8 = 3;
pub const RT_SCOPE_UNIVERSE: u8 = 0;
pub const RT_SCOPE_LINK: u8 = 253;
pub const RTN_UNICAST: u8 = 1;
pub const RTN_LOCAL: u8 = 2;
pub const RTN_BROADCAST: u8 = 3;

const RXBUF_LEN: usize = 32768;
static mut RXBUF: [u8; RXBUF_LEN] = [0; RXBUF_LEN];

/// The shared receive buffer (single-threaded test program)
pub fn rxbuf() -> &'static mut [u8] {
    unsafe { &mut *addr_of_mut!(RXBUF) }
}

/// A request under construction
pub struct Req {
    buf: [u8; 512],
    len: usize,
}

impl Req {
    /// Header + family header `fam`
    pub fn new(ty: u16, flags: u16, fam: &[u8]) -> Self {
        let mut r = Req {
            buf: [0; 512],
            len: 16,
        };
        r.buf[4..6].copy_from_slice(&ty.to_ne_bytes());
        r.buf[6..8].copy_from_slice(&(flags | NLM_F_REQUEST).to_ne_bytes());
        r.put(fam);
        r
    }

    fn put(&mut self, b: &[u8]) -> &mut Self {
        self.buf[self.len..self.len + b.len()].copy_from_slice(b);
        self.len = (self.len + b.len() + 3) & !3;
        self
    }

    pub fn attr(&mut self, ty: u16, data: &[u8]) -> &mut Self {
        let l = (4 + data.len()) as u16;
        let mut h = [0u8; 4];
        h[..2].copy_from_slice(&l.to_ne_bytes());
        h[2..].copy_from_slice(&ty.to_ne_bytes());
        self.put(&h);
        self.put(data)
    }

    pub fn u32(&mut self, ty: u16, v: u32) -> &mut Self {
        self.attr(ty, &v.to_ne_bytes())
    }

    pub fn flags(&self) -> u16 {
        u16::from_ne_bytes([self.buf[6], self.buf[7]])
    }

    pub fn set_flags(&mut self, f: u16) {
        self.buf[6..8].copy_from_slice(&f.to_ne_bytes());
    }

    /// Finalize with `seq`; returns the bytes
    pub fn bytes(&mut self, seq: u32) -> &[u8] {
        let len = self.len as u32;
        self.buf[..4].copy_from_slice(&len.to_ne_bytes());
        self.buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        &self.buf[..self.len]
    }
}

/// struct ifinfomsg
pub fn ifinfo(index: u32, flags: u32, change: u32) -> [u8; 16] {
    let mut h = [0u8; 16];
    h[4..8].copy_from_slice(&index.to_ne_bytes());
    h[8..12].copy_from_slice(&flags.to_ne_bytes());
    h[12..16].copy_from_slice(&change.to_ne_bytes());
    h
}

/// struct ifaddrmsg
pub fn ifaddr(family: u8, prefixlen: u8, index: u32) -> [u8; 8] {
    let mut h = [0u8; 8];
    h[0] = family;
    h[1] = prefixlen;
    h[4..8].copy_from_slice(&index.to_ne_bytes());
    h
}

/// struct rtmsg
pub fn rtmsg(dst_len: u8, table: u8, protocol: u8, scope: u8, rtype: u8) -> [u8; 12] {
    [
        AF_INET, dst_len, 0, 0, table, protocol, scope, rtype, 0, 0, 0, 0,
    ]
}

/// One received message
pub struct Msg<'a> {
    pub ty: u16,
    pub flags: u16,
    pub seq: u32,
    pub pid: u32,
    /// Payload after the 16-byte header
    pub body: &'a [u8],
}

impl<'a> Msg<'a> {
    /// Attribute `ty` after a family header of `hdr` bytes
    pub fn attr(&self, hdr: usize, ty: u16) -> Option<&'a [u8]> {
        let mut b = self.body.get(hdr..)?;
        while b.len() >= 4 {
            let l = u16::from_ne_bytes([b[0], b[1]]) as usize;
            let t = u16::from_ne_bytes([b[2], b[3]]) & 0x3fff;
            if l < 4 || l > b.len() {
                return None;
            }
            if t == ty {
                return Some(&b[4..l]);
            }
            b = &b[((l + 3) & !3).min(b.len())..];
        }
        None
    }

    pub fn attr_u32(&self, hdr: usize, ty: u16) -> Option<u32> {
        self.attr(hdr, ty)
            .filter(|a| a.len() >= 4)
            .map(|a| u32::from_ne_bytes([a[0], a[1], a[2], a[3]]))
    }

    /// IPv4 attribute as [a, b, c, d]
    pub fn attr_ip(&self, hdr: usize, ty: u16) -> Option<[u8; 4]> {
        self.attr(hdr, ty)
            .filter(|a| a.len() >= 4)
            .map(|a| [a[0], a[1], a[2], a[3]])
    }

    /// String attribute without the NUL
    pub fn attr_str(&self, hdr: usize, ty: u16) -> Option<&'a [u8]> {
        self.attr(hdr, ty)
            .map(|a| &a[..a.iter().position(|&c| c == 0).unwrap_or(a.len())])
    }

    pub fn u32_at(&self, off: usize) -> u32 {
        let b = self.body;
        u32::from_ne_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
    }

    /// NLMSG_ERROR code (0 = ACK)
    pub fn error(&self) -> i32 {
        self.u32_at(0) as i32
    }
}

/// Call `f` for each message in a datagram
pub fn each_msg<'a>(mut b: &'a [u8], f: &mut dyn FnMut(&Msg<'a>)) {
    while b.len() >= 16 {
        let len = u32::from_ne_bytes([b[0], b[1], b[2], b[3]]) as usize;
        if len < 16 || len > b.len() {
            return;
        }
        let m = Msg {
            ty: u16::from_ne_bytes([b[4], b[5]]),
            flags: u16::from_ne_bytes([b[6], b[7]]),
            seq: u32::from_ne_bytes([b[8], b[9], b[10], b[11]]),
            pid: u32::from_ne_bytes([b[12], b[13], b[14], b[15]]),
            body: &b[16..len],
        };
        f(&m);
        b = &b[((len + 3) & !3).min(b.len())..];
    }
}

/// A NETLINK_ROUTE socket
pub struct Nl {
    pub fd: i32,
    seq: u32,
}

impl Nl {
    /// Open and autobind
    pub fn open() -> Option<Self> {
        let fd = sys_socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
        if fd < 0 {
            return None;
        }
        let addr = nladdr(0, 0);
        if sys_bind(fd as i32, addr.as_ptr(), 12) != 0 {
            sys_close(fd as u64);
            return None;
        }
        Some(Nl {
            fd: fd as i32,
            seq: 1000,
        })
    }

    /// Wrap an existing socket
    pub fn from_fd(fd: i32) -> Self {
        Nl { fd, seq: 5000 }
    }

    /// Send `req` to the kernel; returns its sequence number
    pub fn send(&mut self, req: &mut Req) -> u32 {
        self.seq += 1;
        let seq = self.seq;
        let b = req.bytes(seq);
        let k = nladdr(0, 0);
        sys_sendto(self.fd, b.as_ptr(), b.len(), 0, k.as_ptr(), 12);
        seq
    }

    /// Receive one datagram into `buf` (waits up to 5 s); <0 on error
    pub fn recv(&self, buf: &mut [u8], flags: i32) -> i64 {
        if !wait_readable(self.fd, 5000) {
            return -11;
        }
        sys_recvfrom(
            self.fd,
            buf.as_mut_ptr(),
            buf.len(),
            flags,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    }

    /// Send with NLM_F_ACK and return the NLMSG_ERROR code (0 = ACK),
    /// or -10000 if no ACK arrived
    pub fn ack(&mut self, req: &mut Req) -> i32 {
        req.set_flags(req.flags() | NLM_F_ACK);
        let seq = self.send(req);
        self.wait_ack(seq)
    }

    /// Read until the NLMSG_ERROR for `seq`
    pub fn wait_ack(&mut self, seq: u32) -> i32 {
        for _ in 0..16 {
            let buf = rxbuf();
            let n = self.recv(buf, 0);
            if n <= 0 {
                return -10000;
            }
            let mut code = None;
            each_msg(&buf[..n as usize], &mut |m| {
                if m.ty == NLMSG_ERROR && m.seq == seq {
                    code = Some(m.error());
                }
            });
            if let Some(c) = code {
                return c;
            }
        }
        -10000
    }

    /// Dump: calls `f` for every reply message of the request; returns
    /// the message count, a negative errno, or -10000 without DONE
    pub fn dump(&mut self, req: &mut Req, f: &mut dyn FnMut(&Msg)) -> i32 {
        req.set_flags(req.flags() | NLM_F_DUMP);
        let seq = self.send(req);
        let mut count = 0;
        for _ in 0..64 {
            let buf = rxbuf();
            let n = self.recv(buf, 0);
            if n <= 0 {
                return -10000;
            }
            let mut end = None;
            each_msg(&buf[..n as usize], &mut |m| {
                if m.seq != seq || end.is_some() {
                    return;
                }
                match m.ty {
                    NLMSG_DONE => {
                        // A dump that failed while running ends with the
                        // error in DONE
                        let e = if m.body.len() >= 4 { m.error() } else { 0 };
                        end = Some(if e < 0 { e } else { count });
                    }
                    NLMSG_ERROR => end = Some(m.error()),
                    _ => {
                        count += 1;
                        f(m);
                    }
                }
            });
            if let Some(r) = end {
                return r;
            }
        }
        -10000
    }
}

impl Drop for Nl {
    fn drop(&mut self) {
        sys_close(self.fd as u64);
    }
}

/// struct sockaddr_nl
pub fn nladdr(pid: u32, groups: u32) -> [u8; 12] {
    let mut a = [0u8; 12];
    a[..2].copy_from_slice(&(AF_NETLINK as u16).to_ne_bytes());
    a[4..8].copy_from_slice(&pid.to_ne_bytes());
    a[8..12].copy_from_slice(&groups.to_ne_bytes());
    a
}

/// Sleep `ms` milliseconds
pub fn msleep(ms: i64) {
    let req = Timespec {
        tv_sec: ms / 1000,
        tv_nsec: (ms % 1000) * 1_000_000,
    };
    sys_nanosleep(&req, core::ptr::null_mut());
}

pub fn wait_readable(fd: i32, ms: i32) -> bool {
    let mut pfd = PollFd::new(fd, POLLIN);
    sys_poll(&mut pfd, 1, ms) == 1 && pfd.revents & POLLIN != 0
}

/// Link facts from an RTM_NEWLINK message
#[derive(Clone, Copy, Default)]
pub struct Link {
    pub index: u32,
    pub ltype: u16,
    pub flags: u32,
    pub operstate: u8,
    pub mtu: u32,
}

pub fn link_of(m: &Msg) -> Link {
    Link {
        ltype: u16::from_ne_bytes([m.body[2], m.body[3]]),
        index: m.u32_at(4),
        flags: m.u32_at(8),
        operstate: m.attr(16, IFLA_OPERSTATE).map_or(255, |a| a[0]),
        mtu: m.attr_u32(16, IFLA_MTU).unwrap_or(0),
    }
}

/// The first Ethernet link (ARPHRD_ETHER) from a link dump
pub fn first_ether(nl: &mut Nl) -> Option<Link> {
    let mut found: Option<Link> = None;
    let mut r = Req::new(RTM_GETLINK, 0, &ifinfo(0, 0, 0));
    nl.dump(&mut r, &mut |m| {
        let l = link_of(m);
        if m.ty == RTM_NEWLINK && l.ltype == ARPHRD_ETHER && found.is_none() {
            found = Some(l);
        }
    });
    found
}

/// Current state of link `index` (RTM_GETLINK)
pub fn get_link(nl: &mut Nl, index: u32) -> Option<Link> {
    let mut r = Req::new(RTM_GETLINK, 0, &ifinfo(index, 0, 0));
    let seq = nl.send(&mut r);
    let buf = rxbuf();
    let n = nl.recv(buf, 0);
    let mut out = None;
    if n > 0 {
        each_msg(&buf[..n as usize], &mut |m| {
            if m.ty == RTM_NEWLINK && m.seq == seq {
                out = Some(link_of(m));
            }
        });
    }
    out
}

/// Set IFF_UP on link `index` (`up`) or clear it; returns the ACK code
pub fn set_link_up(nl: &mut Nl, index: u32, up: bool) -> i32 {
    let f = if up { IFF_UP } else { 0 };
    nl.ack(&mut Req::new(RTM_NEWLINK, 0, &ifinfo(index, f, IFF_UP)))
}

/// Add (`add`) or delete `ip/plen` with broadcast on link `index`
pub fn addr(nl: &mut Nl, add: bool, index: u32, ip: [u8; 4], plen: u8, flags: u16) -> i32 {
    let ty = if add { RTM_NEWADDR } else { RTM_DELADDR };
    let mut r = Req::new(ty, flags, &ifaddr(AF_INET, plen, index));
    r.attr(IFA_LOCAL, &ip).attr(IFA_ADDRESS, &ip);
    if add && plen < 31 {
        let host = u32::MAX >> plen;
        let b = (u32::from_be_bytes(ip) | host).to_be_bytes();
        r.attr(IFA_BROADCAST, &b);
    }
    nl.ack(&mut r)
}

/// Add/delete a main-table route `dst/plen` via `gw` (0 = none) on `oif`
pub fn route(
    nl: &mut Nl,
    add: bool,
    dst: [u8; 4],
    plen: u8,
    gw: [u8; 4],
    oif: u32,
    flags: u16,
) -> i32 {
    let ty = if add { RTM_NEWROUTE } else { RTM_DELROUTE };
    let scope = if gw == [0; 4] {
        RT_SCOPE_LINK
    } else {
        RT_SCOPE_UNIVERSE
    };
    let (proto, rtype, scope) = if add {
        (RTPROT_BOOT, RTN_UNICAST, scope)
    } else {
        (0, 0, 255)
    };
    let mut r = Req::new(ty, flags, &rtmsg(plen, RT_TABLE_MAIN, proto, scope, rtype));
    if plen != 0 {
        r.attr(RTA_DST, &dst);
    }
    if gw != [0; 4] {
        r.attr(RTA_GATEWAY, &gw);
    }
    if oif != 0 {
        r.u32(RTA_OIF, oif);
    }
    nl.ack(&mut r)
}

/// Configure the first Ethernet link for QEMU slirp: up, 10.0.2.15/24,
/// default route via 10.0.2.2 (existing address/route accepted).
/// Returns the link's index.
pub fn net_setup_eth0() -> Result<u32, &'static str> {
    const EEXIST: i32 = -17;
    let mut nl = Nl::open().ok_or("netlink socket")?;
    let eth = first_ether(&mut nl).ok_or("no ethernet link")?;
    if set_link_up(&mut nl, eth.index, true) != 0 {
        return Err("link up");
    }
    let r = addr(
        &mut nl,
        true,
        eth.index,
        [10, 0, 2, 15],
        24,
        NLM_F_CREATE | NLM_F_EXCL,
    );
    if r != 0 && r != EEXIST {
        return Err("address");
    }
    let r = route(
        &mut nl,
        true,
        [0; 4],
        0,
        [10, 0, 2, 2],
        eth.index,
        NLM_F_CREATE | NLM_F_EXCL,
    );
    if r != 0 && r != EEXIST {
        return Err("default route");
    }
    Ok(eth.index)
}

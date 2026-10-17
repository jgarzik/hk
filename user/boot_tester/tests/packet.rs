//! AF_PACKET sockets (hk and Linux): creation rules, sockaddr_ll
//! naming, SOCK_RAW/SOCK_DGRAM receive over lo with packet types
//! (OUTGOING then HOST), frame sends both ways, MSG_TRUNC, the bounded
//! receive queue with PACKET_STATISTICS, classic BPF filters with
//! PACKET_AUXDATA, memberships, /proc/net/packet, and a DHCP exchange
//! on eth0 without an IP address (what busybox udhcpc does).

use hk_syscall::{
    AF_INET, SOCK_DGRAM, SOCK_RAW, SOCK_STREAM, sys_bind, sys_exit, sys_fork, sys_getpeername,
    sys_getsockname, sys_getsockopt, sys_ioctl, sys_recvfrom, sys_sendto, sys_setresuid,
    sys_setsockopt, sys_shutdown, sys_socket, sys_wait4,
};

use super::helpers::{println, skip};
use super::nl::{Nl, addr as nl_addr, msleep, net_setup_eth0};
use super::sk::*;

const AF_PACKET: i32 = 17;
const SOL_PACKET: i32 = 263;
const PACKET_ADD_MEMBERSHIP: i32 = 1;
const PACKET_DROP_MEMBERSHIP: i32 = 2;
const PACKET_STATISTICS: i32 = 6;
const PACKET_AUXDATA: i32 = 8;
const PACKET_MR_PROMISC: u16 = 1;
const SO_ATTACH_FILTER: i32 = 26;
const SO_DETACH_FILTER: i32 = 27;
const SO_LOCK_FILTER: i32 = 44;

const ETH_P_ALL: u16 = 0x0003;
const ETH_P_IP: u16 = 0x0800;
/// IEEE local experimental EtherType: only our test frames use it
const ETH_P_TEST: u16 = 0x88b5;

const PACKET_HOST: u8 = 0;
const PACKET_BROADCAST: u8 = 1;
const PACKET_OUTGOING: u8 = 4;
const ARPHRD_LOOPBACK: u16 = 772;
const ARPHRD_ETHER: u16 = 1;

const ENXIO: i64 = -6;
const ENOENT: i64 = -2;
const ENODEV: i64 = -19;

pub fn run_tests() {
    println(b"=== AF_PACKET Tests ===");
    test_create();
    let lo = ifindex(b"lo");
    test_name(lo);
    test_bind_errors();
    test_lo_all(lo);
    test_lo_dgram(lo);
    test_send(lo);
    test_trunc(lo);
    test_rcvbuf(lo);
    test_filter(lo);
    test_opts(lo);
    test_proc();
    match net_setup_eth0() {
        Ok(eth) => {
            test_eth_errors(eth as i32);
            test_dhcp(eth as i32);
            let _ = net_setup_eth0();
        }
        Err(e) => skip(b"PACKET_DHCP", e.as_bytes()),
    }
}

/// struct sockaddr_ll
#[derive(Clone, Copy, Default)]
struct Sll {
    protocol: u16,
    ifindex: i32,
    hatype: u16,
    pkttype: u8,
    halen: u8,
    addr: [u8; 8],
}

impl Sll {
    fn new(protocol: u16, ifindex: i32) -> Self {
        Self {
            protocol,
            ifindex,
            ..Default::default()
        }
    }

    fn bytes(&self) -> [u8; 20] {
        let mut b = [0u8; 20];
        b[0..2].copy_from_slice(&(AF_PACKET as u16).to_ne_bytes());
        b[2..4].copy_from_slice(&self.protocol.to_be_bytes());
        b[4..8].copy_from_slice(&self.ifindex.to_ne_bytes());
        b[8..10].copy_from_slice(&self.hatype.to_ne_bytes());
        b[10] = self.pkttype;
        b[11] = self.halen;
        b[12..20].copy_from_slice(&self.addr);
        b
    }

    fn parse(b: &[u8; 20]) -> Self {
        let mut addr = [0u8; 8];
        addr.copy_from_slice(&b[12..20]);
        Self {
            protocol: u16::from_be_bytes([b[2], b[3]]),
            ifindex: i32::from_ne_bytes([b[4], b[5], b[6], b[7]]),
            hatype: u16::from_ne_bytes([b[8], b[9]]),
            pkttype: b[10],
            halen: b[11],
            addr,
        }
    }
}

fn psock(ty: i32, proto: u16) -> i32 {
    sys_socket(AF_PACKET, ty, proto.to_be() as i32) as i32
}

fn pbind(fd: i32, proto: u16, ifindex: i32) -> i64 {
    let a = Sll::new(proto, ifindex).bytes();
    sys_bind(fd, a.as_ptr(), 20)
}

/// A socket bound to `proto` on `ifindex`
fn bound(ty: i32, proto: u16, ifindex: i32) -> i32 {
    let fd = psock(ty, proto);
    pbind(fd, proto, ifindex);
    fd
}

fn sendto_ll(fd: i32, data: &[u8], a: &Sll, alen: u32) -> i64 {
    let b = a.bytes();
    sys_sendto(fd, data.as_ptr(), data.len(), 0, b.as_ptr(), alen)
}

/// getsockname: (return, length, address)
fn sockname(fd: i32) -> (i64, u32, Sll) {
    let mut b = [0u8; 20];
    let mut len = 20u32;
    let r = sys_getsockname(fd, b.as_mut_ptr(), &mut len);
    (r, len, Sll::parse(&b))
}

/// Interface index by name (SIOCGIFINDEX)
fn ifindex(name: &[u8]) -> i32 {
    const SIOCGIFINDEX: u64 = 0x8933;
    let mut ifr = [0u8; 40];
    ifr[..name.len()].copy_from_slice(name);
    let fd = udp();
    sys_ioctl(fd, SIOCGIFINDEX, ifr.as_mut_ptr() as u64);
    close(fd);
    i32::from_ne_bytes([ifr[16], ifr[17], ifr[18], ifr[19]])
}

/// Receive one frame within `ms`: (length, source address)
fn recv_ll(fd: i32, buf: &mut [u8], ms: i32, flags: i32) -> (i64, Sll) {
    let (r, _) = poll1(fd, 1, ms);
    if r != 1 {
        return (EAGAIN, Sll::default());
    }
    let mut a = [0u8; 20];
    let mut len = 20u32;
    let n = sys_recvfrom(
        fd,
        buf.as_mut_ptr(),
        buf.len(),
        flags | MSG_DONTWAIT,
        a.as_mut_ptr(),
        &mut len,
    );
    (n, Sll::parse(&a))
}

/// The next frame within `ms` for which `pred(frame, sll)` holds
fn find(
    fd: i32,
    buf: &mut [u8],
    ms: u64,
    pred: &dyn Fn(&[u8], &Sll) -> bool,
) -> Option<(usize, Sll)> {
    let end = now_ms() + ms;
    while now_ms() < end {
        let (n, a) = recv_ll(fd, buf, 200, 0);
        if n > 0 && pred(&buf[..n as usize], &a) {
            return Some((n as usize, a));
        }
    }
    None
}

/// A test frame: zero (lo's) destination and source, ETH_P_TEST, `tag`
/// then zero padding to `len`
fn test_frame(out: &mut [u8], tag: u8, len: usize) -> &[u8] {
    out[..len].fill(0);
    out[12..14].copy_from_slice(&ETH_P_TEST.to_be_bytes());
    out[14] = tag;
    &out[..len]
}

/// Creation: EPERM without CAP_NET_RAW, ESOCKTNOSUPPORT for stream
fn test_create() {
    let mut t = T::new(b"PACKET_CREATE");
    t.eq(
        b"stream",
        psock(SOCK_STREAM, ETH_P_ALL) as i64,
        ESOCKTNOSUPPORT,
    );
    for ty in [SOCK_RAW, SOCK_DGRAM] {
        let fd = psock(ty, ETH_P_ALL);
        t.ok(b"create", fd >= 0, fd as i64);
        t.eq(
            b"SO_DOMAIN",
            getint(fd, SOL_SOCKET, SO_DOMAIN).1 as i64,
            AF_PACKET as i64,
        );
        t.eq(
            b"SO_TYPE",
            getint(fd, SOL_SOCKET, SO_TYPE).1 as i64,
            ty as i64,
        );
        close(fd);
    }
    let pid = sys_fork();
    if pid == 0 {
        if sys_setresuid(65534, 65534, 65534) != 0 {
            sys_exit(90);
        }
        sys_exit(if psock(SOCK_RAW, ETH_P_ALL) as i64 == EPERM {
            0
        } else {
            1
        });
    }
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    t.eq(b"unprivileged", st as i64, 0);
    t.done();
}

/// getsockname: protocol from socket(), the bound device's address
/// after bind (length 12 + halen); no peer
fn test_name(lo: i32) {
    let mut t = T::new(b"PACKET_NAME");
    let fd = psock(SOCK_RAW, ETH_P_ALL);
    let (r, len, a) = sockname(fd);
    t.eq(b"getsockname", r, 0);
    t.eq(b"unbound len", len as i64, 12);
    t.eq(b"protocol", a.protocol as i64, ETH_P_ALL as i64);
    t.eq(b"ifindex", a.ifindex as i64, 0);
    t.eq(b"bind lo", pbind(fd, 0, lo), 0);
    let (_, len, a) = sockname(fd);
    t.eq(b"bound len", len as i64, 18);
    t.eq(b"kept protocol", a.protocol as i64, ETH_P_ALL as i64);
    t.eq(b"bound ifindex", a.ifindex as i64, lo as i64);
    t.eq(b"hatype", a.hatype as i64, ARPHRD_LOOPBACK as i64);
    t.eq(b"halen", a.halen as i64, 6);
    let mut b = [0u8; 20];
    let mut l = 20u32;
    t.eq(
        b"getpeername",
        sys_getpeername(fd, b.as_mut_ptr(), &mut l),
        EOPNOTSUPP,
    );
    t.eq(b"shutdown", sys_shutdown(fd, 2), EOPNOTSUPP);
    close(fd);
    t.done();
}

/// bind: short address and wrong family EINVAL, unknown device ENODEV;
/// sends without a device ENXIO, with a short address EINVAL
fn test_bind_errors() {
    let mut t = T::new(b"PACKET_BIND_ERRORS");
    let fd = psock(SOCK_RAW, 0);
    let a = Sll::new(ETH_P_ALL, 1).bytes();
    t.eq(b"short", sys_bind(fd, a.as_ptr(), 10), EINVAL);
    let mut inet = a;
    inet[0..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
    t.eq(b"family", sys_bind(fd, inet.as_ptr(), 20), EINVAL);
    t.eq(b"no device", pbind(fd, ETH_P_ALL, 9999), ENODEV);
    let mut f = [0u8; 64];
    let frame = test_frame(&mut f, 0, 60);
    t.eq(b"send unbound", send(fd, frame, 0), ENXIO);
    t.eq(
        b"send short addr",
        sendto_ll(fd, frame, &Sll::new(ETH_P_TEST, 1), 10),
        EINVAL,
    );
    t.eq(
        b"send no device",
        sendto_ll(fd, frame, &Sll::new(ETH_P_TEST, 9999), 20),
        ENXIO,
    );
    close(fd);
    t.done();
}

/// SOCK_RAW ETH_P_ALL on lo sees a UDP datagram twice: as
/// PACKET_OUTGOING when sent, as PACKET_HOST when received, both from
/// the Ethernet header
fn test_lo_all(lo: i32) {
    let mut t = T::new(b"PACKET_LO_ALL");
    let fd = bound(SOCK_RAW, ETH_P_ALL, lo);
    let (u, port) = udp_lo();
    t.eq(b"udp send", send_to(u, b"pktlo", LO, port, 0), 5);
    let mut buf = [0u8; 256];
    let is_ours = |f: &[u8], _: &Sll| {
        f.len() >= 47
            && f[12..14] == ETH_P_IP.to_be_bytes()
            && f[23] == 17
            && f[36..38] == port.to_be_bytes()
            && &f[42..47] == b"pktlo"
    };
    match find(fd, &mut buf, 3000, &is_ours) {
        Some((n, a)) => {
            t.eq(b"first outgoing", a.pkttype as i64, PACKET_OUTGOING as i64);
            t.eq(b"len", n as i64, 47);
            t.eq(b"sll_protocol", a.protocol as i64, ETH_P_IP as i64);
            t.eq(b"sll_ifindex", a.ifindex as i64, lo as i64);
            t.eq(b"sll_hatype", a.hatype as i64, ARPHRD_LOOPBACK as i64);
            t.eq(b"sll_halen", a.halen as i64, 6);
        }
        None => {
            t.ok(b"outgoing copy", false, 0);
        }
    }
    match find(fd, &mut buf, 3000, &is_ours) {
        Some((_, a)) => {
            t.eq(b"then host", a.pkttype as i64, PACKET_HOST as i64);
        }
        None => {
            t.ok(b"incoming copy", false, 0);
        }
    }
    close(u);
    close(fd);
    t.done();
}

/// SOCK_DGRAM ETH_P_IP: received frames only, from the IP header
fn test_lo_dgram(lo: i32) {
    let mut t = T::new(b"PACKET_LO_DGRAM");
    let fd = bound(SOCK_DGRAM, ETH_P_IP, lo);
    let (u, port) = udp_lo();
    send_to(u, b"dgram", LO, port, 0);
    let mut buf = [0u8; 256];
    let is_ours =
        |f: &[u8], _: &Sll| f.len() >= 33 && f[0] == 0x45 && f[22..24] == port.to_be_bytes();
    match find(fd, &mut buf, 3000, &is_ours) {
        Some((n, a)) => {
            t.eq(b"len", n as i64, 33);
            t.eq(b"pkttype", a.pkttype as i64, PACKET_HOST as i64);
            t.eq(b"protocol", a.protocol as i64, ETH_P_IP as i64);
            t.ok(b"payload", &buf[28..33] == b"dgram", 0);
        }
        None => {
            t.ok(b"frame", false, 0);
        }
    }
    // Exactly one copy: no PACKET_OUTGOING for a specific protocol
    t.ok(
        b"single copy",
        find(fd, &mut buf, 300, &is_ours).is_none(),
        0,
    );
    close(u);
    close(fd);
    t.done();
}

/// Sends: SOCK_RAW takes a whole frame (the sender does not see its own
/// outgoing copy, other ETH_P_ALL sockets do); SOCK_DGRAM gets an
/// Ethernet header from sll_addr and sll_protocol (lo's zero source)
fn test_send(lo: i32) {
    let mut t = T::new(b"PACKET_SEND");
    let rx = bound(SOCK_RAW, ETH_P_TEST, lo);
    let all = bound(SOCK_RAW, ETH_P_ALL, lo);
    let tx = bound(SOCK_RAW, ETH_P_ALL, lo);
    let mut f = [0u8; 64];
    let frame = test_frame(&mut f, 0x51, 60);
    t.eq(b"raw send", send(tx, frame, 0), 60);
    let mut buf = [0u8; 128];
    let tagged = |tag: u8| {
        move |f: &[u8], _: &Sll| {
            f.len() >= 15 && f[12..14] == ETH_P_TEST.to_be_bytes() && f[14] == tag
        }
    };
    match find(rx, &mut buf, 3000, &tagged(0x51)) {
        Some((n, a)) => {
            t.eq(b"raw len", n as i64, 60);
            t.eq(b"raw pkttype", a.pkttype as i64, PACKET_HOST as i64);
            t.eq(b"raw protocol", a.protocol as i64, ETH_P_TEST as i64);
        }
        None => {
            t.ok(b"raw frame", false, 0);
        }
    }
    let seen = find(all, &mut buf, 3000, &tagged(0x51)).map(|(_, a)| a.pkttype);
    t.eq(
        b"other socket outgoing",
        seen.unwrap_or(99) as i64,
        PACKET_OUTGOING as i64,
    );
    let own = find(tx, &mut buf, 1000, &tagged(0x51)).map(|(_, a)| a.pkttype);
    t.eq(
        b"sender sees incoming only",
        own.unwrap_or(99) as i64,
        PACKET_HOST as i64,
    );

    let d = psock(SOCK_DGRAM, 0);
    let mut to = Sll::new(ETH_P_TEST, lo);
    to.halen = 6;
    to.addr = [2, 0, 0, 0, 0, 1, 0, 0];
    t.eq(b"dgram send", sendto_ll(d, &[0x52, b'h', b'i'], &to, 20), 3);
    match find(rx, &mut buf, 3000, &tagged(0x52)) {
        Some((n, a)) => {
            t.eq(b"dgram frame len", n as i64, 17);
            t.ok(
                b"dest from sll_addr",
                buf[..6] == [2, 0, 0, 0, 0, 1],
                buf[0] as i64,
            );
            t.ok(b"lo zero source", buf[6..12] == [0; 6], buf[6] as i64);
            t.eq(b"not for lo", a.pkttype as i64, 3);
        }
        None => {
            t.ok(b"dgram frame", false, 0);
        }
    }
    let mut short = [0u8; 64];
    t.eq(
        b"raw short",
        send(tx, test_frame(&mut short, 0, 10), 0),
        EINVAL,
    );
    close(d);
    close(tx);
    close(all);
    close(rx);
    t.done();
}

/// MSG_TRUNC: a short buffer gets the head and MSG_TRUNC in msg_flags;
/// the MSG_TRUNC flag returns the real length
fn test_trunc(lo: i32) {
    let mut t = T::new(b"PACKET_TRUNC");
    let rx = bound(SOCK_RAW, ETH_P_TEST, lo);
    let tx = bound(SOCK_RAW, ETH_P_ALL, lo);
    let mut f = [0u8; 64];
    send(tx, test_frame(&mut f, 0x53, 60), 0);
    send(tx, test_frame(&mut f, 0x54, 60), 0);
    poll1(rx, 1, 3000);
    let mut small = [0u8; 16];
    let mut ctl = [0u8; 8];
    let (n, flags, _) = recv_msg(rx, &mut small, &mut ctl, 0);
    t.eq(b"truncated", n, 16);
    t.ok(b"MSG_TRUNC flag", flags & MSG_TRUNC != 0, flags as i64);
    poll1(rx, 1, 3000);
    t.eq(
        b"real length",
        recv(rx, &mut small, MSG_TRUNC | MSG_DONTWAIT),
        60,
    );
    close(tx);
    close(rx);
    t.done();
}

/// A full receive buffer drops frames; PACKET_STATISTICS counts them
/// (packets include drops) and resets on read
fn test_rcvbuf(lo: i32) {
    let mut t = T::new(b"PACKET_RCVBUF");
    let rx = bound(SOCK_RAW, ETH_P_TEST, lo);
    setint(rx, SOL_SOCKET, SO_RCVBUF, 0);
    let tx = bound(SOCK_RAW, ETH_P_ALL, lo);
    let mut f = [0u8; 1100];
    const N: i64 = 20;
    for i in 0..N {
        send(tx, test_frame(&mut f, i as u8, 1000), 0);
    }
    msleep(200);
    let mut got = 0;
    let mut buf = [0u8; 1100];
    while recv(rx, &mut buf, MSG_DONTWAIT) > 0 {
        got += 1;
    }
    let mut st = [0u32; 2];
    let mut len = 8u32;
    let r = sys_getsockopt(
        rx,
        SOL_PACKET,
        PACKET_STATISTICS,
        st.as_mut_ptr() as *mut u8,
        &mut len,
    );
    t.eq(b"PACKET_STATISTICS", r, 0);
    t.eq(b"stats len", len as i64, 8);
    t.ok(b"some queued", got >= 1, got);
    t.ok(b"bounded", got < N, got);
    t.eq(b"drops", st[1] as i64, N - got);
    t.eq(b"packets", st[0] as i64, N);
    let r = sys_getsockopt(
        rx,
        SOL_PACKET,
        PACKET_STATISTICS,
        st.as_mut_ptr() as *mut u8,
        &mut len,
    );
    t.ok(b"reset", r == 0 && st == [0, 0], st[0] as i64);
    close(tx);
    close(rx);
    t.done();
}

/// struct sock_fprog for `insns` (code, jt, jf, k)
fn fprog(insns: &[(u16, u8, u8, u32)], out: &mut [u8; 128]) -> [u8; 16] {
    for (i, &(code, jt, jf, k)) in insns.iter().enumerate() {
        let o = i * 8;
        out[o..o + 2].copy_from_slice(&code.to_ne_bytes());
        out[o + 2] = jt;
        out[o + 3] = jf;
        out[o + 4..o + 8].copy_from_slice(&k.to_ne_bytes());
    }
    let mut p = [0u8; 16];
    p[0..2].copy_from_slice(&(insns.len() as u16).to_ne_bytes());
    p[8..16].copy_from_slice(&(out.as_ptr() as u64).to_ne_bytes());
    p
}

fn attach(fd: i32, p: &[u8; 16]) -> i64 {
    sys_setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, p.as_ptr(), 16)
}

/// Classic BPF: validation errors, drop-all, snap to 20 bytes (the
/// auxdata shows the original length), detach and lock rules
fn test_filter(lo: i32) {
    const RET_K: u16 = 0x06;
    const LD_IMM: u16 = 0x00;
    let mut t = T::new(b"PACKET_FILTER");
    let rx = bound(SOCK_RAW, ETH_P_TEST, lo);
    let tx = bound(SOCK_RAW, ETH_P_ALL, lo);
    let mut ins = [0u8; 128];
    let p = fprog(&[(LD_IMM, 0, 0, 1)], &mut ins);
    t.eq(b"no ret", attach(rx, &p), EINVAL);
    t.eq(
        b"optlen",
        sys_setsockopt(rx, SOL_SOCKET, SO_ATTACH_FILTER, p.as_ptr(), 8),
        EINVAL,
    );
    t.eq(
        b"detach none",
        sys_setsockopt(rx, SOL_SOCKET, SO_DETACH_FILTER, p.as_ptr(), 4),
        ENOENT,
    );

    let p = fprog(&[(RET_K, 0, 0, 0)], &mut ins);
    t.eq(b"drop all", attach(rx, &p), 0);
    let mut f = [0u8; 64];
    send(tx, test_frame(&mut f, 0x55, 60), 0);
    let mut buf = [0u8; 128];
    t.eq(b"dropped", recv_ll(rx, &mut buf, 300, 0).0, EAGAIN);

    let mut ins2 = [0u8; 128];
    let p = fprog(&[(RET_K, 0, 0, 20)], &mut ins2);
    t.eq(b"snap 20", attach(rx, &p), 0);
    t.eq(b"auxdata", setint(rx, SOL_PACKET, PACKET_AUXDATA, 1), 0);
    send(tx, test_frame(&mut f, 0x56, 60), 0);
    poll1(rx, 1, 3000);
    let mut ctl = [0u8; 64];
    let (n, _, clen) = recv_msg(rx, &mut buf, &mut ctl, MSG_DONTWAIT);
    t.eq(b"snapped", n, 20);
    match cmsg_find(&ctl, clen, SOL_PACKET, PACKET_AUXDATA) {
        Some(aux) if aux.len() >= 12 => {
            let w = |o: usize| u32::from_ne_bytes([aux[o], aux[o + 1], aux[o + 2], aux[o + 3]]);
            t.eq(b"tp_len", w(4) as i64, 60);
            t.eq(b"tp_snaplen", w(8) as i64, 20);
            t.ok(b"TP_STATUS_USER", w(0) & 1 != 0, w(0) as i64);
        }
        _ => {
            t.ok(b"auxdata cmsg", false, clen as i64);
        }
    }
    t.eq(
        b"detach",
        sys_setsockopt(rx, SOL_SOCKET, SO_DETACH_FILTER, p.as_ptr(), 4),
        0,
    );
    t.eq(b"lock", setint(rx, SOL_SOCKET, SO_LOCK_FILTER, 1), 0);
    t.eq(b"locked attach", attach(rx, &p), EPERM);
    t.eq(b"unlock", setint(rx, SOL_SOCKET, SO_LOCK_FILTER, 0), EPERM);
    t.eq(
        b"lock get",
        getint(rx, SOL_SOCKET, SO_LOCK_FILTER).1 as i64,
        1,
    );
    close(tx);
    close(rx);
    t.done();
}

/// SOL_PACKET options: memberships (counted, dropping a missing one is
/// fine, ENODEV), unknown options ENOPROTOOPT
fn test_opts(lo: i32) {
    let mut t = T::new(b"PACKET_OPTS");
    let fd = psock(SOCK_RAW, ETH_P_ALL);
    let mut mreq = [0u8; 16];
    mreq[0..4].copy_from_slice(&lo.to_ne_bytes());
    mreq[4..6].copy_from_slice(&PACKET_MR_PROMISC.to_ne_bytes());
    let set = |opt: i32, m: &[u8], len: u32| sys_setsockopt(fd, SOL_PACKET, opt, m.as_ptr(), len);
    t.eq(b"add", set(PACKET_ADD_MEMBERSHIP, &mreq, 16), 0);
    t.eq(b"add again", set(PACKET_ADD_MEMBERSHIP, &mreq, 16), 0);
    t.eq(b"short", set(PACKET_ADD_MEMBERSHIP, &mreq, 8), EINVAL);
    t.eq(b"drop", set(PACKET_DROP_MEMBERSHIP, &mreq, 16), 0);
    t.eq(b"drop 2", set(PACKET_DROP_MEMBERSHIP, &mreq, 16), 0);
    t.eq(b"drop none", set(PACKET_DROP_MEMBERSHIP, &mreq, 16), 0);
    mreq[0..4].copy_from_slice(&9999i32.to_ne_bytes());
    t.eq(b"no device", set(PACKET_ADD_MEMBERSHIP, &mreq, 16), ENODEV);
    t.eq(b"unknown", setint(fd, SOL_PACKET, 999, 1), ENOPROTOOPT);
    t.eq(
        b"auxdata get",
        getint(fd, SOL_PACKET, PACKET_AUXDATA).1 as i64,
        0,
    );
    close(fd);
    t.done();
}

/// /proc/net/packet lists our socket (protocol 0003)
fn test_proc() {
    let mut t = T::new(b"PACKET_PROC");
    let fd = psock(SOCK_RAW, ETH_P_ALL);
    let mut buf = [0u8; 4096];
    let n = super::sysctl::read_file(b"/proc/net/packet\0", &mut buf);
    t.ok(b"read", n > 0, n);
    let s = &buf[..n.max(0) as usize];
    t.ok(
        b"header",
        s.starts_with(b"sk ") && contains(s, b"Proto  Iface"),
        0,
    );
    t.ok(b"our socket", contains(s, b" 0003 "), 0);
    close(fd);
    t.done();
}

fn contains(h: &[u8], n: &[u8]) -> bool {
    h.windows(n.len()).any(|w| w == n)
}

/// eth0 sends: SOCK_DGRAM needs a destination address (EINVAL), frames
/// over the MTU are EMSGSIZE
fn test_eth_errors(eth: i32) {
    let mut t = T::new(b"PACKET_ETH_ERRORS");
    let d = bound(SOCK_DGRAM, ETH_P_TEST, eth);
    t.eq(b"dgram no dest", send(d, b"x", 0), EINVAL);
    close(d);
    let r = bound(SOCK_RAW, ETH_P_TEST, eth);
    let mut f = [0u8; 1600];
    t.eq(
        b"over mtu",
        send(r, test_frame(&mut f, 0, 1515), 0),
        EMSGSIZE,
    );
    t.eq(b"mtu", send(r, test_frame(&mut f, 0, 1514), 0), 1514);
    close(r);
    t.done();
}

/// busybox udhcpc's filter: UDP to port 68, not a fragment
const UDHCPC_FILTER: [(u16, u8, u8, u32); 9] = [
    (0x30, 0, 0, 9),
    (0x15, 0, 6, 17),
    (0x28, 0, 0, 6),
    (0x45, 4, 0, 0x1fff),
    (0xb1, 0, 0, 0),
    (0x48, 0, 0, 2),
    (0x15, 0, 1, 68),
    (0x06, 0, 0, 0x7fff_ffff),
    (0x06, 0, 0, 0),
];

/// A DHCPDISCOVER from 0.0.0.0:68 to 255.255.255.255:67 into `out`
fn discover(out: &mut [u8; 300], mac: &[u8], xid: u32) {
    out.fill(0);
    let ip = &mut out[..20];
    ip.copy_from_slice(&[
        0x45, 0, 0x01, 0x2c, 0, 1, 0, 0, 64, 17, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255,
    ]);
    let mut s: u32 = 0;
    for c in ip.chunks(2) {
        s += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    ip[10..12].copy_from_slice(&(!(s as u16)).to_be_bytes());
    out[20..28].copy_from_slice(&[0, 68, 0, 67, 0x01, 0x18, 0, 0]);
    let b = &mut out[28..];
    b[0..4].copy_from_slice(&[1, 1, 6, 0]);
    b[4..8].copy_from_slice(&xid.to_be_bytes());
    b[10] = 0x80; // broadcast reply
    b[28..34].copy_from_slice(&mac[..6]);
    b[236..240].copy_from_slice(&[99, 130, 83, 99]);
    b[240..244].copy_from_slice(&[53, 1, 1, 255]);
}

/// DHCP over AF_PACKET on eth0 with no IP address: a SOCK_DGRAM
/// ETH_P_IP socket with udhcpc's filter broadcasts a DISCOVER and gets
/// slirp's OFFER of 10.0.2.15; an ETH_P_ALL socket sees the DISCOVER
/// as PACKET_OUTGOING
fn test_dhcp(eth: i32) {
    let mut t = T::new(b"PACKET_DHCP");
    if let Some(mut nl) = Nl::open() {
        nl_addr(&mut nl, false, eth as u32, [10, 0, 2, 15], 24, 0);
    }
    let rx = bound(SOCK_DGRAM, ETH_P_IP, eth);
    let mut prog = [0u8; 128];
    let p = fprog(&UDHCPC_FILTER, &mut prog);
    t.eq(b"udhcpc filter", attach(rx, &p), 0);
    let all = bound(SOCK_RAW, ETH_P_ALL, eth);
    let (_, _, me) = sockname(rx);
    t.eq(b"ether", me.hatype as i64, ARPHRD_ETHER as i64);
    let xid = 0x4b48_0000 | (now_ms() as u32 & 0xffff);
    let mut pkt = [0u8; 300];
    discover(&mut pkt, &me.addr, xid);
    let mut to = Sll::new(ETH_P_IP, eth);
    to.halen = 6;
    to.addr[..6].copy_from_slice(&[0xff; 6]);
    t.eq(b"send", sendto_ll(rx, &pkt, &to, 20), 300);

    let mut buf = [0u8; 1600];
    let out = find(all, &mut buf, 3000, &|f: &[u8], a: &Sll| {
        a.pkttype == PACKET_OUTGOING
            && f.len() >= 50
            && f[36..38] == [0, 67]
            && f[46..50] == xid.to_be_bytes()
    });
    t.ok(
        b"outgoing DISCOVER",
        out.is_some_and(|(_, _)| buf[..6] == [0xff; 6]),
        0,
    );

    let offer = find(rx, &mut buf, 5000, &|f: &[u8], _: &Sll| {
        f.len() >= 244 && f[28] == 2 && f[32..36] == xid.to_be_bytes()
    });
    match offer {
        Some((_, a)) => {
            t.ok(b"yiaddr", buf[44..48] == [10, 0, 2, 15], buf[47] as i64);
            t.ok(
                b"pkttype",
                a.pkttype == PACKET_HOST || a.pkttype == PACKET_BROADCAST,
                a.pkttype as i64,
            );
            t.eq(b"protocol", a.protocol as i64, ETH_P_IP as i64);
            t.eq(b"halen", a.halen as i64, 6);
            t.ok(b"server mac", a.addr[..6] != [0; 6], 0);
        }
        None => {
            t.ok(b"OFFER", false, 0);
        }
    }
    close(all);
    close(rx);
    t.done();
}

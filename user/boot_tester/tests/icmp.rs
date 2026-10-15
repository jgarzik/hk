//! ICMP errors delivered to UDP sockets (hk and Linux): port
//! unreachable over lo (connected ECONNREFUSED, unconnected ignored,
//! IP_RECVERR + MSG_ERRQUEUE with sock_extended_err), host unreachable
//! after neighbour resolution fails on eth0, local EMSGSIZE errors.

use hk_syscall::POLLERR;

use super::helpers::skip;
use super::nl::net_setup_eth0;
use super::sk::*;

pub const EHOSTUNREACH: i64 = -113;
pub const SO_EE_ORIGIN_LOCAL: u8 = 1;
pub const SO_EE_ORIGIN_ICMP: u8 = 2;
const IP_MTU_DISCOVER: i32 = 10;

pub fn run_tests() {
    super::helpers::println(b"=== ICMP Error Tests ===");
    test_refused_connected();
    test_refused_unconnected();
    test_recverr();
    match net_setup_eth0() {
        Ok(_) => {
            test_hostunreach();
            test_local_emsgsize();
        }
        Err(e) => skip(b"ICMP_ETH0", e.as_bytes()),
    }
}

/// A closed lo port (bound then closed)
pub fn closed_port() -> u16 {
    let (fd, p) = udp_lo();
    close(fd);
    p
}

/// sock_extended_err + offender from an IP_RECVERR control message
pub struct Ee {
    pub errno: u32,
    pub origin: u8,
    pub ty: u8,
    pub code: u8,
    pub info: u32,
    pub offender: [u8; 4],
    pub off_family: u16,
}

pub fn ee_of(ctl: &[u8], cl: usize) -> Option<Ee> {
    let d = cmsg_find(ctl, cl, SOL_IP, IP_RECVERR)?;
    if d.len() < 32 {
        return None;
    }
    Some(Ee {
        errno: u32::from_ne_bytes([d[0], d[1], d[2], d[3]]),
        origin: d[4],
        ty: d[5],
        code: d[6],
        info: u32::from_ne_bytes([d[8], d[9], d[10], d[11]]),
        off_family: u16::from_ne_bytes([d[16], d[17]]),
        offender: [d[20], d[21], d[22], d[23]],
    })
}

/// recvmsg(MSG_ERRQUEUE): (return, msg_flags, ee, name addr, name port)
pub fn recv_err(fd: i32, buf: &mut [u8]) -> (i64, i32, Option<Ee>, [u8; 4], u16) {
    use hk_syscall::{sys_recvmsg, IoVec, MsgHdr, SockAddrIn};
    let mut ctl = [0u8; 256];
    let mut name = sin(ANY, 0);
    let mut iov = IoVec { iov_base: buf.as_mut_ptr(), iov_len: buf.len() };
    let mut m = MsgHdr::with_addr(&mut name, &mut iov, 1);
    m.msg_control = ctl.as_mut_ptr();
    m.msg_controllen = ctl.len();
    let r = sys_recvmsg(fd, &mut m, MSG_ERRQUEUE);
    let ee = if r >= 0 { ee_of(&ctl, m.msg_controllen) } else { None };
    let _: &SockAddrIn = &name;
    (r, m.msg_flags, ee, name.sin_addr.to_ne_bytes(), u16::from_be(name.sin_port))
}

/// Connected UDP to a closed port: the port unreachable makes the next
/// send or receive fail with ECONNREFUSED (once); SO_ERROR reports it
fn test_refused_connected() {
    let mut t = T::new(b"ICMP_REFUSED_CONNECTED");
    let p = closed_port();
    let c = udp();
    t.eq(b"connect", connect(c, LO, p), 0);
    t.eq(b"send 1", send(c, b"a", 0), 1);
    t.eq(b"send 2", send(c, b"b", 0), ECONNREFUSED);
    t.eq(b"send 3", send(c, b"c", 0), 1);
    let mut buf = [0u8; 8];
    t.eq(b"recv", recv(c, &mut buf, MSG_DONTWAIT), ECONNREFUSED);
    t.eq(b"recv again", recv(c, &mut buf, MSG_DONTWAIT), EAGAIN);
    send(c, b"d", 0);
    t.eq(b"SO_ERROR", getint(c, SOL_SOCKET, SO_ERROR).1 as i64, 111);
    t.eq(b"SO_ERROR clear", getint(c, SOL_SOCKET, SO_ERROR).1 as i64, 0);
    // Without IP_RECVERR nothing is queued
    t.eq(b"errqueue", recv(c, &mut buf, MSG_ERRQUEUE), EAGAIN);
    close(c);
    t.done();
}

/// Unconnected UDP ignores port unreachable without IP_RECVERR
fn test_refused_unconnected() {
    let mut t = T::new(b"ICMP_REFUSED_UNCONNECTED");
    let p = closed_port();
    let (fd, _) = udp_lo();
    t.eq(b"send 1", send_to(fd, b"a", LO, p, 0), 1);
    t.eq(b"send 2", send_to(fd, b"b", LO, p, 0), 1);
    t.eq(b"SO_ERROR", getint(fd, SOL_SOCKET, SO_ERROR).1 as i64, 0);
    close(fd);
    t.done();
}

/// IP_RECVERR: the error is queued with the original payload and
/// destination; POLLERR until it is read; reading it clears SO_ERROR
fn test_recverr() {
    let mut t = T::new(b"ICMP_RECVERR");
    let p = closed_port();
    let (fd, _) = udp_lo();
    t.eq(b"IP_RECVERR", setint(fd, SOL_IP, IP_RECVERR, 1), 0);
    t.eq(b"sendto", send_to(fd, b"hello", LO, p, 0), 5);
    let (_, rev) = poll1(fd, 0, 1000);
    t.ok(b"POLLERR", rev & POLLERR != 0, rev as i64);
    let mut buf = [0u8; 64];
    let (n, fl, ee, ip, port) = recv_err(fd, &mut buf);
    t.ok(b"payload", n == 5 && &buf[..5] == b"hello", n);
    t.ok(b"MSG_ERRQUEUE", fl & MSG_ERRQUEUE != 0, fl as i64);
    t.ok(b"name", ip == LO && port == p, port as i64);
    match ee {
        Some(e) => {
            t.eq(b"errno", e.errno as i64, 111);
            t.eq(b"origin", e.origin as i64, SO_EE_ORIGIN_ICMP as i64);
            t.ok(b"type/code", e.ty == 3 && e.code == 3, e.ty as i64);
            t.ok(b"offender", e.off_family == 2 && e.offender == LO, e.off_family as i64);
        }
        None => {
            t.ok(b"IP_RECVERR cmsg", false, 0);
        }
    }
    t.eq(b"empty", recv(fd, &mut buf, MSG_ERRQUEUE), EAGAIN);
    t.eq(b"SO_ERROR cleared", getint(fd, SOL_SOCKET, SO_ERROR).1 as i64, 0);
    let (_, rev) = poll1(fd, 0, 0);
    t.ok(b"no POLLERR", rev & POLLERR == 0, rev as i64);
    // Truncated payload
    send_to(fd, b"hello", LO, p, 0);
    let (n, fl, _, _, _) = recv_err(fd, &mut buf[..2]);
    t.ok(b"trunc", n == 2 && fl & MSG_TRUNC != 0, n);
    close(fd);
    t.done();
}

/// Neighbour resolution fails for an unused on-link address: after
/// ~3 s the socket gets EHOSTUNREACH (ICMP host unreachable from our
/// own address, queued with IP_RECVERR)
fn test_hostunreach() {
    let mut t = T::new(b"ICMP_HOSTUNREACH");
    let fd = udp();
    setint(fd, SOL_IP, IP_RECVERR, 1);
    t.eq(b"connect", connect(fd, [10, 0, 2, 78], 9), 0);
    let start = now_ms();
    t.eq(b"send", send(fd, b"x", 0), 1);
    let tv: [i64; 2] = [8, 0];
    hk_syscall::sys_setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, tv.as_ptr() as *const u8, 16);
    let mut buf = [0u8; 16];
    let r = recv(fd, &mut buf, 0);
    let el = (now_ms() - start) as i64;
    t.eq(b"recv", r, EHOSTUNREACH);
    t.ok(b"after ~3 s", (2500..7000).contains(&el), el);
    let (n, _, ee, ip, port) = recv_err(fd, &mut buf);
    t.ok(b"queued", n == 1 && ip == [10, 0, 2, 78] && port == 9, n);
    if let Some(e) = ee {
        t.ok(b"ee", e.errno == 113 && e.ty == 3 && e.code == 1, e.errno as i64);
        t.ok(b"offender", e.offender == [10, 0, 2, 15], e.offender[3] as i64);
    } else {
        t.ok(b"ee", false, 0);
    }
    close(fd);
    t.done();
}

/// IP_PMTUDISC_DO beyond the MTU: EMSGSIZE, queued as a local error
/// with the MTU in ee_info
fn test_local_emsgsize() {
    let mut t = T::new(b"ICMP_LOCAL_EMSGSIZE");
    let fd = udp();
    setint(fd, SOL_IP, IP_RECVERR, 1);
    setint(fd, SOL_IP, IP_MTU_DISCOVER, 2);
    let data = [0u8; 2000];
    t.eq(b"send", send_to(fd, &data, [10, 0, 2, 2], 9, 0), EMSGSIZE);
    let mut buf = [0u8; 16];
    let (n, fl, ee, ip, _) = recv_err(fd, &mut buf);
    t.ok(b"queued", n == 0 && fl & MSG_ERRQUEUE != 0 && ip == [10, 0, 2, 2], n);
    if let Some(e) = ee {
        t.ok(b"ee", e.errno == 90 && e.origin == SO_EE_ORIGIN_LOCAL && e.info == 1500, e.info as i64);
    } else {
        t.ok(b"ee", false, 0);
    }
    close(fd);
    t.done();
}

// ============================================================================
// Ping sockets (SOCK_DGRAM, IPPROTO_ICMP)
// ============================================================================

use super::sysctl::write_file;
use hk_syscall::{sys_exit, sys_fork, sys_setresgid, sys_socket, sys_wait4, AF_INET, SOCK_DGRAM};

const PING_RANGE: &[u8] = b"/proc/sys/net/ipv4/ping_group_range\0";
const IPPROTO_ICMP: i32 = 1;

pub fn ping_socket() -> i32 {
    sys_socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) as i32
}

/// An echo request: type 8, code 0, `id`, `seq`, payload
pub fn echo(id: u16, seq: u16, payload: &[u8], out: &mut [u8]) -> usize {
    out[..8].copy_from_slice(&[8, 0, 0, 0, 0, 0, 0, 0]);
    out[4..6].copy_from_slice(&id.to_be_bytes());
    out[6..8].copy_from_slice(&seq.to_be_bytes());
    out[8..8 + payload.len()].copy_from_slice(payload);
    8 + payload.len()
}

/// Wait up to `ms` for a datagram; (len, source)
pub fn recv_wait(fd: i32, buf: &mut [u8], ms: i32) -> (i64, [u8; 4]) {
    let (r, _) = poll1(fd, 1, ms);
    if r != 1 {
        return (EAGAIN, [0; 4]);
    }
    let (n, ip, _) = recv_from(fd, buf, MSG_DONTWAIT);
    (n, ip)
}

pub fn run_ping_tests() {
    super::helpers::println(b"=== Ping Socket Tests ===");
    test_ping_group();
    if write_file(PING_RANGE, b"0 2147483647") < 0 {
        skip(b"PING", b"cannot set ping_group_range");
        return;
    }
    test_ping_lo();
    test_ping_errors();
    match net_setup_eth0() {
        Ok(_) => {
            test_ping_eth0();
            test_ping_unreach();
        }
        Err(e) => skip(b"PING_ETH0", e.as_bytes()),
    }
    write_file(PING_RANGE, b"1 0");
}

/// ping_group_range gates creation by effective group, root included
fn test_ping_group() {
    let mut t = T::new(b"PING_GROUP");
    t.eq(b"default EACCES", ping_socket() as i64, EACCES);
    t.eq(b"set 0 0", write_file(PING_RANGE, b"0 0"), 3);
    let fd = ping_socket();
    t.ok(b"root gid 0", fd >= 0, fd as i64);
    close(fd);
    fn child(range: &[u8]) -> i32 {
        write_file(PING_RANGE, range);
        let pid = sys_fork();
        if pid == 0 {
            if sys_setresgid(100, 100, 100) != 0 {
                sys_exit(90);
            }
            let fd = ping_socket();
            sys_exit(if fd >= 0 { 0 } else { (-fd) as u64 });
        }
        let mut st = 0;
        sys_wait4(pid, &mut st, 0, 0);
        (st >> 8) & 0xff
    }
    t.eq(b"gid 100 outside", child(b"0 0") as i64, 13);
    t.eq(b"gid 100 inside", child(b"100 100") as i64, 0);
    write_file(PING_RANGE, b"1 0");
    t.done();
}

/// Echo to 127.0.0.1: the kernel sets the identifier to the bound
/// "port" and the reply comes back with it
fn test_ping_lo() {
    let mut t = T::new(b"PING_LO");
    let fd = ping_socket();
    let mut req = [0u8; 64];
    let n = echo(0x1234, 7, b"hkping", &mut req);
    t.eq(b"sendto", send_to(fd, &req[..n], LO, 0, 0), n as i64);
    let ident = port(fd);
    t.ok(b"autobound", ident != 0, 0);
    let mut buf = [0u8; 64];
    let (r, ip) = recv_wait(fd, &mut buf, 2000);
    t.eq(b"reply len", r, n as i64);
    t.ok(b"reply", buf[0] == 0 && buf[1] == 0 && ip == LO, buf[0] as i64);
    t.eq(b"id", u16::from_be_bytes([buf[4], buf[5]]) as i64, ident as i64);
    t.eq(b"seq", u16::from_be_bytes([buf[6], buf[7]]) as i64, 7);
    t.ok(b"payload", &buf[8..14] == b"hkping", 0);
    // connect + send
    t.eq(b"connect", connect(fd, LO, 0), 0);
    t.eq(b"send", send(fd, &req[..n], 0), n as i64);
    t.eq(b"reply 2", recv_wait(fd, &mut buf, 2000).0, n as i64);
    close(fd);
    t.done();
}

/// Argument errors and identifier binding
fn test_ping_errors() {
    let mut t = T::new(b"PING_ERRORS");
    let fd = ping_socket();
    let mut req = [0u8; 16];
    let n = echo(1, 1, b"", &mut req);
    t.eq(b"no dest", send(fd, &req[..n], 0), EDESTADDRREQ);
    t.eq(b"short", send_to(fd, &req[..4], LO, 0, 0), EINVAL);
    req[0] = 13;
    t.eq(b"not echo", send_to(fd, &req[..n], LO, 0, 0), EINVAL);
    close(fd);
    let a = ping_socket();
    t.eq(b"bind", bind(a, LO, 4444), 0);
    t.eq(b"ident", port(a) as i64, 4444);
    let b = ping_socket();
    // Ping sockets start with SO_REUSEADDR (INET_PROTOSW_REUSE)
    t.eq(b"reuse default", getint(b, SOL_SOCKET, SO_REUSEADDR).1 as i64, 1);
    setint(b, SOL_SOCKET, SO_REUSEADDR, 0);
    t.eq(b"busy", bind(b, ANY, 4444), EADDRINUSE);
    let c = ping_socket();
    t.eq(b"shared", bind(c, ANY, 4444), 0);
    close(c);
    t.eq(b"rebind", bind(a, LO, 4445), EINVAL);
    t.eq(b"nonlocal", bind(b, [10, 9, 8, 7], 0), EADDRNOTAVAIL);
    close(a);
    close(b);
    t.done();
}

/// Echo to our eth0 address, and to the slirp gateway (slirp answers
/// only if the host lets it ping: a timeout is a skip, not a failure)
fn test_ping_eth0() {
    let mut t = T::new(b"PING_ETH0");
    let fd = ping_socket();
    let mut req = [0u8; 64];
    let n = echo(0, 1, b"own", &mut req);
    t.eq(b"own send", send_to(fd, &req[..n], [10, 0, 2, 15], 0, 0), n as i64);
    let mut buf = [0u8; 64];
    let (r, ip) = recv_wait(fd, &mut buf, 2000);
    t.ok(b"own reply", r == n as i64 && buf[0] == 0 && ip == [10, 0, 2, 15], r);
    t.done();
    let n = echo(0, 2, b"gw", &mut req);
    send_to(fd, &req[..n], [10, 0, 2, 2], 0, 0);
    let (r, ip) = recv_wait(fd, &mut buf, 3000);
    if r == EAGAIN {
        skip(b"PING_GATEWAY", b"slirp did not answer ICMP echo (host ping not permitted)");
    } else {
        let mut t = T::new(b"PING_GATEWAY");
        t.ok(b"reply", r == n as i64 && buf[0] == 0 && ip == [10, 0, 2, 2], r);
        t.done();
    }
    close(fd);
}

/// An echo to an unused on-link address: host unreachable is queued for
/// the ping socket with IP_RECVERR (data: the echo request)
fn test_ping_unreach() {
    let mut t = T::new(b"PING_UNREACH");
    let fd = ping_socket();
    setint(fd, SOL_IP, IP_RECVERR, 1);
    let mut req = [0u8; 64];
    let n = echo(0, 3, b"lost", &mut req);
    t.eq(b"send", send_to(fd, &req[..n], [10, 0, 2, 79], 0, 0), n as i64);
    let (r, rev) = poll1(fd, 0, 7000);
    t.ok(b"POLLERR", r == 1 && rev & POLLERR != 0, rev as i64);
    let mut buf = [0u8; 64];
    let (m, _, ee, ip, _) = recv_err(fd, &mut buf);
    t.ok(b"queued", m == n as i64 && buf[0] == 8 && ip == [10, 0, 2, 79], m);
    t.ok(b"ee", ee.is_some_and(|e| e.errno == 113 && e.code == 1), 0);
    close(fd);
    t.done();
}

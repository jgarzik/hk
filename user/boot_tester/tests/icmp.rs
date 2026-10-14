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

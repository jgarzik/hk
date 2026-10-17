//! Raw IPv4 sockets over lo (hk and Linux): creation rules, ICMP
//! sockets seeing echo traffic, ICMP_FILTER, IP_HDRINCL sends,
//! protocol unreachable, and reassembly of crafted fragments
//! (duplicates tolerated, overlaps dropped).

use hk_syscall::{
    AF_INET, SOCK_RAW, sys_exit, sys_fork, sys_getsockopt, sys_setresuid, sys_setsockopt,
    sys_socket, sys_wait4,
};

use super::icmp::recv_wait;
use super::sk::*;

const IPPROTO_ICMP: i32 = 1;
const IPPROTO_UDP: i32 = 17;
const IPPROTO_RAW: i32 = 255;
const SOL_RAW: i32 = 255;
const ICMP_FILTER: i32 = 1;
const IP_HDRINCL: i32 = 3;

pub fn run_tests() {
    super::helpers::println(b"=== Raw Socket Tests ===");
    test_create();
    test_icmp_echo();
    test_icmp_filter();
    test_hdrincl();
    test_proto_unreach();
    test_frag_overlap();
}

fn raw(proto: i32) -> i32 {
    sys_socket(AF_INET, SOCK_RAW, proto) as i32
}

/// Internet checksum
fn csum(d: &[u8]) -> u16 {
    let mut s: u32 = 0;
    for c in d.chunks(2) {
        s += u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32;
    }
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

/// An IPv4 header for `proto`, `len` bytes of payload, fragment field
/// `fo`, id `id`, 127.0.0.1 -> 127.0.0.1 (kernel fills length/checksum)
fn iphdr(out: &mut [u8], proto: u8, id: u16, fo: u16) {
    out[..20].copy_from_slice(&[
        0x45, 0, 0, 0, 0, 0, 0, 0, 64, proto, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1,
    ]);
    out[4..6].copy_from_slice(&id.to_be_bytes());
    out[6..8].copy_from_slice(&fo.to_be_bytes());
}

/// Creation: protocol 0 EPROTONOSUPPORT, out of range EINVAL, EPERM
/// without CAP_NET_RAW; the "port" is the protocol
fn test_create() {
    let mut t = T::new(b"RAW_CREATE");
    t.eq(b"proto 0", raw(0) as i64, EPROTONOSUPPORT);
    t.eq(b"proto 300", raw(300) as i64, EINVAL);
    let fd = raw(IPPROTO_ICMP);
    t.ok(b"icmp", fd >= 0, fd as i64);
    t.eq(b"port", port(fd) as i64, IPPROTO_ICMP as i64);
    t.eq(b"hdrincl off", getint(fd, SOL_IP, IP_HDRINCL).1 as i64, 0);
    close(fd);
    let r = raw(IPPROTO_RAW);
    t.eq(
        b"IPPROTO_RAW hdrincl",
        getint(r, SOL_IP, IP_HDRINCL).1 as i64,
        1,
    );
    close(r);
    let u = udp();
    t.eq(
        b"udp hdrincl",
        setint(u, SOL_IP, IP_HDRINCL, 1),
        ENOPROTOOPT,
    );
    close(u);
    let pid = sys_fork();
    if pid == 0 {
        if sys_setresuid(65534, 65534, 65534) != 0 {
            sys_exit(90);
        }
        sys_exit(if raw(IPPROTO_ICMP) as i64 == EPERM {
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

/// An echo request (with checksum) into `out`; returns its length
fn echo_req(out: &mut [u8], id: u16) -> usize {
    out[..12].copy_from_slice(&[8, 0, 0, 0, 0, 0, 0, 1, b'r', b'a', b'w', b'!']);
    out[4..6].copy_from_slice(&id.to_be_bytes());
    let c = csum(&out[..12]);
    out[2..4].copy_from_slice(&c.to_be_bytes());
    12
}

/// Find an ICMP message of `ty` with identifier `id` among datagrams
/// queued on `fd` (each starts with the IP header)
fn find_icmp(fd: i32, ty: u8, id: u16) -> bool {
    let mut buf = [0u8; 256];
    for _ in 0..8 {
        let (n, ip) = recv_wait(fd, &mut buf, 1000);
        if n < 28 {
            return false;
        }
        let ihl = ((buf[0] & 0xf) * 4) as usize;
        let m = &buf[ihl..n as usize];
        if ip == LO && buf[9] == 1 && m[0] == ty && u16::from_be_bytes([m[4], m[5]]) == id {
            return true;
        }
    }
    false
}

/// A raw ICMP socket sends an echo request (kernel IP header) and sees
/// both the request and the reply, IP header included
fn test_icmp_echo() {
    let mut t = T::new(b"RAW_ICMP_ECHO");
    let fd = raw(IPPROTO_ICMP);
    let mut req = [0u8; 32];
    let n = echo_req(&mut req, 0x5151);
    t.eq(b"sendto", send_to(fd, &req[..n], LO, 0, 0), n as i64);
    t.ok(b"request seen", find_icmp(fd, 8, 0x5151), 0);
    t.ok(b"reply seen", find_icmp(fd, 0, 0x5151), 0);
    close(fd);
    t.done();
}

/// ICMP_FILTER drops the types whose bit is set
fn test_icmp_filter() {
    let mut t = T::new(b"RAW_ICMP_FILTER");
    let fd = raw(IPPROTO_ICMP);
    let mask: u32 = !1; // only echo replies (type 0)
    let r = sys_setsockopt(
        fd,
        SOL_RAW,
        ICMP_FILTER,
        &mask as *const u32 as *const u8,
        4,
    );
    t.eq(b"set", r, 0);
    let mut got: u32 = 0;
    let mut len = 4u32;
    let r = sys_getsockopt(
        fd,
        SOL_RAW,
        ICMP_FILTER,
        &mut got as *mut u32 as *mut u8,
        &mut len,
    );
    t.ok(b"get", r == 0 && got == mask && len == 4, got as i64);
    t.eq(b"unknown", setint(fd, SOL_RAW, 2, 0), ENOPROTOOPT);
    let mut req = [0u8; 32];
    let n = echo_req(&mut req, 0x5252);
    send_to(fd, &req[..n], LO, 0, 0);
    let mut buf = [0u8; 256];
    let (r, _) = recv_wait(fd, &mut buf, 1000);
    let ihl = ((buf[0] & 0xf) * 4) as usize;
    t.ok(b"only reply", r > 0 && buf[ihl] == 0, buf[ihl] as i64);
    let u = raw(IPPROTO_UDP);
    t.eq(b"non-icmp", setint(u, SOL_RAW, ICMP_FILTER, 0), EOPNOTSUPP);
    close(u);
    close(fd);
    t.done();
}

/// IP_HDRINCL: our header goes out with length/checksum/id filled in
fn test_hdrincl() {
    let mut t = T::new(b"RAW_HDRINCL");
    let (u, pu) = udp_lo();
    let fd = raw(IPPROTO_RAW);
    let mut pkt = [0u8; 64];
    iphdr(&mut pkt, 17, 0, 0);
    pkt[20..22].copy_from_slice(&4321u16.to_be_bytes());
    pkt[22..24].copy_from_slice(&pu.to_be_bytes());
    pkt[24..26].copy_from_slice(&13u16.to_be_bytes());
    pkt[28..33].copy_from_slice(b"hello");
    t.eq(b"send", send_to(fd, &pkt[..33], LO, 0, 0), 33);
    let mut buf = [0u8; 16];
    let (n, ip, sp) = recv_from(u, &mut buf, 0);
    t.ok(
        b"udp got it",
        n == 5 && &buf[..5] == b"hello" && ip == LO && sp == 4321,
        n,
    );
    // IP options (four NOPs) are skipped on receive
    let mut opt = [0u8; 64];
    opt[..20].copy_from_slice(&pkt[..20]);
    opt[0] = 0x46;
    opt[20..24].copy_from_slice(&[1, 1, 1, 1]);
    opt[24..37].copy_from_slice(&pkt[20..33]);
    t.eq(b"send opts", send_to(fd, &opt[..37], LO, 0, 0), 37);
    let (n, _, _) = recv_from(u, &mut buf, MSG_DONTWAIT);
    t.ok(b"with options", n == 5 && &buf[..5] == b"hello", n);
    t.eq(b"short", send_to(fd, &pkt[..12], LO, 0, 0), EINVAL);
    pkt[0] = 0x4f;
    t.eq(b"bad ihl", send_to(fd, &pkt[..33], LO, 0, 0), EINVAL);
    close(fd);
    close(u);
    t.done();
}

/// A protocol nobody handles: ICMP protocol unreachable
fn test_proto_unreach() {
    let mut t = T::new(b"RAW_PROTO_UNREACH");
    let ic = raw(IPPROTO_ICMP);
    let fd = raw(IPPROTO_RAW);
    let mut pkt = [0u8; 32];
    iphdr(&mut pkt, 254, 0x7777, 0);
    t.eq(b"send", send_to(fd, &pkt[..28], LO, 0, 0), 28);
    let mut buf = [0u8; 256];
    let mut found = false;
    for _ in 0..4 {
        let (n, _) = recv_wait(ic, &mut buf, 1000);
        if n < 48 {
            break;
        }
        let m = &buf[20..];
        if m[0] == 3 && m[1] == 2 && m[8 + 9] == 254 {
            found = true;
            break;
        }
    }
    t.ok(b"prot unreach", found, 0);
    close(fd);
    close(ic);
    t.done();
}

/// Send one UDP fragment (IP payload `data` at byte offset `off`)
fn frag(fd: i32, id: u16, off: usize, more: bool, data: &[u8]) -> i64 {
    let mut pkt = [0u8; 128];
    let fo = (off / 8) as u16 | if more { 0x2000 } else { 0 };
    iphdr(&mut pkt, 17, id, fo);
    pkt[20..20 + data.len()].copy_from_slice(data);
    send_to(fd, &pkt[..20 + data.len()], LO, 0, 0)
}

/// Crafted fragments of a 24-byte UDP datagram: in order and with a
/// duplicate they reassemble; an overlap kills the datagram
fn test_frag_overlap() {
    let mut t = T::new(b"RAW_FRAG");
    let (u, pu) = udp_lo();
    let fd = raw(IPPROTO_RAW);
    let mut d = [0u8; 24];
    d[0..2].copy_from_slice(&1111u16.to_be_bytes());
    d[2..4].copy_from_slice(&pu.to_be_bytes());
    d[4..6].copy_from_slice(&24u16.to_be_bytes());
    d[8..24].copy_from_slice(b"0123456789abcdef");
    let mut buf = [0u8; 32];
    // In order
    frag(fd, 0x1001, 0, true, &d[..16]);
    frag(fd, 0x1001, 16, false, &d[16..]);
    t.eq(b"whole", recv(u, &mut buf, MSG_DONTWAIT), 16);
    t.ok(b"data", &buf[..16] == b"0123456789abcdef", 0);
    // Duplicate first fragment, then the rest
    frag(fd, 0x1002, 0, true, &d[..16]);
    frag(fd, 0x1002, 0, true, &d[..16]);
    frag(fd, 0x1002, 16, false, &d[16..]);
    t.eq(b"dup ok", recv(u, &mut buf, MSG_DONTWAIT), 16);
    // Overlap: [0,16) then [8,24) last
    frag(fd, 0x1003, 0, true, &d[..16]);
    frag(fd, 0x1003, 8, false, &d[8..]);
    t.eq(b"overlap dropped", recv(u, &mut buf, MSG_DONTWAIT), EAGAIN);
    // The queue is gone: the missing piece no longer completes it
    frag(fd, 0x1003, 16, false, &d[16..]);
    t.eq(b"killed", recv(u, &mut buf, MSG_DONTWAIT), EAGAIN);
    close(fd);
    close(u);
    t.done();
}

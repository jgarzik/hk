//! IPv4 header options (hk and Linux): IP_OPTIONS set and read back
//! as given, carried in a datagram's header with our address recorded
//! (ip_options_build), IP_RECVOPTS / IP_RETOPTS control messages on
//! receive, and an ICMP echo reply echoing a record route with its own
//! entry added (ip_options_echo); malformed sets refused.

use hk_syscall::{AF_INET, SOCK_RAW, sys_getsockopt, sys_setsockopt, sys_socket};

use crate::harness::T;
use crate::net::sk::*;

const IP_OPTIONS: i32 = 4;
const IP_RECVOPTS: i32 = 6;
const IP_RETOPTS: i32 = 7;
const IPOPT_RR: u8 = 7;

pub fn run_tests() {
    crate::helpers::println(b"=== IP Options Tests ===");
    test_sockopt();
    test_datagram();
    test_echo();
}

fn set_opts(fd: i32, o: &[u8]) -> i64 {
    sys_setsockopt(fd, SOL_IP, IP_OPTIONS, o.as_ptr(), o.len() as u32)
}

/// (return, bytes) of IP_OPTIONS
fn get_opts(fd: i32, out: &mut [u8; 40]) -> (i64, usize) {
    let mut len = 40u32;
    let r = sys_getsockopt(fd, SOL_IP, IP_OPTIONS, out.as_mut_ptr(), &mut len);
    (r, len as usize)
}

/// Linux do_ip_setsockopt / ip_sock_getsockopt: none at first; a set
/// padded to 4 bytes reads back as given; malformed or too long EINVAL
fn test_sockopt() {
    let mut t = T::new(b"IPOPT_SOCKOPT");
    let u = udp();
    let mut b = [0u8; 40];
    t.eq(b"none", get_opts(u, &mut b).1 as i64, 0);
    t.eq(b"set", set_opts(u, &[IPOPT_RR, 7, 4, 0, 0, 0, 0]), 0);
    let (r, n) = get_opts(u, &mut b);
    t.ok(
        b"get",
        r == 0 && n == 8 && b[..8] == [IPOPT_RR, 7, 4, 0, 0, 0, 0, 0],
        n as i64,
    );
    t.eq(b"short", set_opts(u, &[IPOPT_RR, 1]), EINVAL);
    t.eq(
        b"pointer",
        set_opts(u, &[IPOPT_RR, 7, 2, 0, 0, 0, 0]),
        EINVAL,
    );
    t.eq(b"long", set_opts(u, &[1u8; 41]), EINVAL);
    t.eq(b"clear", set_opts(u, &[]), 0);
    t.eq(b"cleared", get_opts(u, &mut b).1 as i64, 0);
    close(u);
    t.done();
}

/// A datagram carries the socket's record route with the sender's
/// address in the first slot and ours (the receiver's) in the second;
/// the receiver sees them as IP_RECVOPTS and IP_RETOPTS
fn test_datagram() {
    let mut t = T::new(b"IPOPT_DATAGRAM");
    let raw = sys_socket(AF_INET, SOCK_RAW, 17) as i32;
    let (r, rp) = udp_lo();
    t.eq(b"recvopts", setint(r, SOL_IP, IP_RECVOPTS, 1), 0);
    t.eq(b"retopts", setint(r, SOL_IP, IP_RETOPTS, 1), 0);
    let s = udp();
    let rr = [IPOPT_RR, 11, 4, 0, 0, 0, 0, 0, 0, 0, 0];
    t.eq(b"set", set_opts(s, &rr), 0);
    t.eq(b"send", send_to(s, b"opt", LO, rp, 0), 3);
    let want = [IPOPT_RR, 11, 12, 127, 0, 0, 1, 127, 0, 0, 1, 0];
    let mut buf = [0u8; 64];
    let mut seen = false;
    for _ in 0..20 {
        let n = recv(raw, &mut buf, MSG_DONTWAIT);
        if n >= 32 && buf[0] == 0x48 && buf[22..24] == rp.to_be_bytes() {
            seen = buf[20..32] == want;
            break;
        }
        crate::net::nl::msleep(10);
    }
    t.ok(b"header", seen, 0);
    let mut ctl = [0u8; 128];
    let (n, _, cl) = recv_msg(r, &mut buf, &mut ctl, MSG_DONTWAIT);
    t.eq(b"recv", n, 3);
    t.ok(
        b"IP_RECVOPTS",
        cmsg_find(&ctl, cl, SOL_IP, IP_RECVOPTS) == Some(&want[..]),
        0,
    );
    t.ok(
        b"IP_RETOPTS",
        cmsg_find(&ctl, cl, SOL_IP, IP_RETOPTS) == Some(&want[..]),
        0,
    );
    close(s);
    close(r);
    close(raw);
    t.done();
}

/// An echo request with a three-slot record route: we record twice as
/// sender and receiver, and the reply echoes it with the third slot
/// filled (Linux icmp_reply -> ip_options_echo, ip_options_build)
fn test_echo() {
    let mut t = T::new(b"IPOPT_ECHO");
    let fd = sys_socket(AF_INET, SOCK_RAW, 1) as i32;
    let rr = [IPOPT_RR, 15, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    t.eq(b"set", set_opts(fd, &rr), 0);
    let mut req = [8u8, 0, 0, 0, 0x77, 0x77, 0, 1];
    let c = crate::net::raw::csum(&req);
    req[2..4].copy_from_slice(&c.to_be_bytes());
    t.eq(b"send", send_to(fd, &req, LO, 0, 0), 8);
    let mut buf = [0u8; 128];
    let mut got = None;
    for _ in 0..20 {
        let n = recv(fd, &mut buf, MSG_DONTWAIT);
        if n > 0 {
            let ihl = usize::from(buf[0] & 0xf) * 4;
            if (n as usize) > ihl && buf[ihl] == 0 && buf[ihl + 4..ihl + 6] == [0x77, 0x77] {
                got = Some(ihl);
                break;
            }
            continue;
        }
        crate::net::nl::msleep(10);
    }
    let want = [
        IPOPT_RR, 15, 16, 127, 0, 0, 1, 127, 0, 0, 1, 127, 0, 0, 1, 0,
    ];
    t.ok(
        b"reply options",
        got == Some(36) && buf[20..36] == want,
        got.map_or(-1, |i| i as i64),
    );
    close(fd);
    t.done();
}

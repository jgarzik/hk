//! SOCK_PACKET (hk and Linux): the obsolete packet socket addressed by
//! device name (struct sockaddr_pkt), bind/getsockname by name, its
//! send rules, frames received over lo from the link header, no socket
//! options of its own (EOPNOTSUPP) and no mmap (ENODEV).

use hk_syscall::{sys_bind, sys_getsockname, sys_getsockopt, sys_recvfrom, sys_sendto};

use crate::harness::T;
use crate::helpers::println;
use crate::net::packet::{ENODEV, ETH_P_ALL, ETH_P_TEST, SOL_PACKET, psock, test_frame};
use crate::net::packet_ring::map;
use crate::net::sk::*;

const SOCK_PACKET: i32 = 10;
const AF_PACKET: u16 = 17;
const ARPHRD_LOOPBACK: u16 = 772;

pub fn run_tests() {
    println(b"=== SOCK_PACKET Tests ===");
    test_spkt();
}

/// struct sockaddr_pkt for device `dev` and `proto`
fn spkt_addr(dev: &[u8], proto: u16) -> [u8; 18] {
    let mut a = [0u8; 18];
    a[0..2].copy_from_slice(&AF_PACKET.to_ne_bytes());
    a[2..2 + dev.len()].copy_from_slice(dev);
    a[16..18].copy_from_slice(&proto.to_be_bytes());
    a
}

fn test_spkt() {
    let mut t = T::new(b"PACKET_SOCK_PACKET");
    let fd = psock(SOCK_PACKET, ETH_P_ALL);
    t.ok(b"create", fd >= 0, fd as i64);
    t.eq(
        b"SO_TYPE",
        getint(fd, SOL_SOCKET, SO_TYPE).1 as i64,
        SOCK_PACKET as i64,
    );
    let a = spkt_addr(b"lo", 0);
    t.eq(b"bind len", sys_bind(fd, a.as_ptr(), 18), EINVAL);
    let bad = spkt_addr(b"nosuchdev0", 0);
    t.eq(b"bind unknown", sys_bind(fd, bad.as_ptr(), 16), ENODEV);
    t.eq(b"bind lo", sys_bind(fd, a.as_ptr(), 16), 0);
    let mut n = [0u8; 32];
    let mut nl = 32u32;
    t.eq(
        b"getsockname",
        sys_getsockname(fd, n.as_mut_ptr(), &mut nl),
        0,
    );
    t.eq(b"name len", nl as i64, 16);
    t.eq(
        b"name family",
        u16::from_ne_bytes([n[0], n[1]]) as i64,
        AF_PACKET as i64,
    );
    t.ok(b"name device", &n[2..5] == b"lo\0", n[2] as i64);
    t.eq(b"setsockopt", setint(fd, SOL_PACKET, 8, 1), EOPNOTSUPP);
    let mut v = [0u8; 4];
    let mut vl = 4u32;
    t.eq(
        b"getsockopt",
        sys_getsockopt(fd, SOL_PACKET, 8, v.as_mut_ptr(), &mut vl),
        EOPNOTSUPP,
    );
    t.eq(b"mmap", map(fd, 4096, 0), ENODEV);

    let tx = psock(SOCK_PACKET, 0);
    let mut f = [0u8; 64];
    let fr = test_frame(&mut f, 0xc1, 60);
    t.eq(b"no address", send(tx, fr, 0), ENOTCONN);
    let to = spkt_addr(b"lo", ETH_P_TEST);
    t.eq(
        b"short address",
        sys_sendto(tx, fr.as_ptr(), fr.len(), 0, to.as_ptr(), 10),
        EINVAL,
    );
    t.eq(
        b"unknown device",
        sys_sendto(tx, fr.as_ptr(), fr.len(), 0, bad.as_ptr(), 18),
        ENODEV,
    );
    t.eq(
        b"short frame",
        sys_sendto(tx, fr.as_ptr(), 10, 0, to.as_ptr(), 18),
        EINVAL,
    );
    t.eq(
        b"send",
        sys_sendto(tx, fr.as_ptr(), fr.len(), 0, to.as_ptr(), 18),
        60,
    );
    let mut buf = [0u8; 128];
    let end = now_ms() + 3000;
    let mut got = None;
    while now_ms() < end {
        poll1(fd, 1, 200);
        let mut a = [0u8; 32];
        let mut al = 32u32;
        let r = sys_recvfrom(
            fd,
            buf.as_mut_ptr(),
            buf.len(),
            MSG_DONTWAIT,
            a.as_mut_ptr(),
            &mut al,
        );
        if r == 60 && buf[12..14] == ETH_P_TEST.to_be_bytes() && buf[14] == 0xc1 {
            got = Some((al, a));
            break;
        }
    }
    match got {
        Some((al, a)) => {
            t.eq(b"addr len", al as i64, 18);
            t.eq(
                b"spkt_family",
                u16::from_ne_bytes([a[0], a[1]]) as i64,
                ARPHRD_LOOPBACK as i64,
            );
            t.ok(b"spkt_device", &a[2..5] == b"lo\0", a[2] as i64);
            t.eq(
                b"spkt_protocol",
                u16::from_be_bytes([a[16], a[17]]) as i64,
                ETH_P_TEST as i64,
            );
        }
        None => {
            t.ok(b"frame", false, 0);
        }
    }
    close(tx);
    close(fd);
    t.done();
}

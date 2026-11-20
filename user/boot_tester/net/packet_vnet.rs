//! AF_PACKET PACKET_VNET_HDR (hk and Linux), after Linux
//! tools/testing/selftests/net/psock_snd.c: the options (SOCK_RAW
//! only, 10 or 12 bytes, EBUSY with a ring), sends with a struct
//! virtio_net_hdr in front (its validation: short, hdr_len, checksum
//! bounds, GSO types), receives with one (recvmsg and the ring's
//! frame layout), PACKET_QDISC_BYPASS.

use hk_syscall::{SOCK_DGRAM, SOCK_RAW, sys_sendto, sys_setsockopt};

use crate::harness::T;
use crate::helpers::println;
use crate::net::packet::{
    ETH_P_ALL, ETH_P_IP, ETH_P_TEST, PACKET_AUXDATA, SOL_PACKET, Sll, find, ifindex, pbind, psock,
    test_frame,
};
use crate::net::packet_ring::{
    PACKET_RX_RING, PACKET_VERSION, TP_STATUS_USER, TPACKET_V2, map, rd8, rd16, rd32, ring_req,
};
use crate::net::sk::*;

pub const PACKET_VNET_HDR: i32 = 15;
pub const PACKET_QDISC_BYPASS: i32 = 20;
pub const PACKET_VNET_HDR_SZ: i32 = 24;
const EBUSY: i64 = -16;

pub fn run_tests() {
    println(b"=== AF_PACKET vnet Tests ===");
    let lo = ifindex(b"lo");
    test_opts();
    test_snd(lo);
    test_rcv(lo);
    test_csum(lo);
}

/// struct virtio_net_hdr
fn vh(flags: u8, gso: u8, hdr_len: u16, gso_size: u16, start: u16, off: u16) -> [u8; 10] {
    let mut b = [0u8; 10];
    b[0] = flags;
    b[1] = gso;
    b[2..4].copy_from_slice(&hdr_len.to_le_bytes());
    b[4..6].copy_from_slice(&gso_size.to_le_bytes());
    b[6..8].copy_from_slice(&start.to_le_bytes());
    b[8..10].copy_from_slice(&off.to_le_bytes());
    b
}

/// Send `hdr` then `frame` as one datagram to lo
fn snd(fd: i32, lo: i32, hdr: &[u8], frame: &[u8]) -> i64 {
    let mut b = [0u8; 256];
    b[..hdr.len()].copy_from_slice(hdr);
    b[hdr.len()..hdr.len() + frame.len()].copy_from_slice(frame);
    let a = Sll::new(ETH_P_TEST, lo).bytes();
    sys_sendto(fd, b.as_ptr(), hdr.len() + frame.len(), 0, a.as_ptr(), 20)
}

/// An Ethernet + IPv4 + UDP test frame of 60 bytes (EtherType IPv4 is
/// rewritten by the receiver's filter: it listens to ETH_P_TEST, so
/// the frame keeps ETH_P_TEST and carries an IPv4-looking payload)
fn udp_frame(out: &mut [u8; 64], tag: u8) -> &[u8] {
    test_frame(&mut out[..], tag, 60);
    out[14] = 0x45;
    out[15] = tag;
    out[23] = 17;
    &out[..60]
}

/// The options
fn test_opts() {
    let mut t = T::new(b"PACKET_VNET_OPTS");
    let d = psock(SOCK_DGRAM, 0);
    t.eq(b"dgram", setint(d, SOL_PACKET, PACKET_VNET_HDR, 1), EINVAL);
    close(d);
    let fd = psock(SOCK_RAW, 0);
    let v = [1i32];
    t.eq(
        b"optlen",
        sys_setsockopt(fd, SOL_PACKET, PACKET_VNET_HDR, v.as_ptr() as *const u8, 2),
        EINVAL,
    );
    t.eq(b"on", setint(fd, SOL_PACKET, PACKET_VNET_HDR, 1), 0);
    t.eq(b"get", getint(fd, SOL_PACKET, PACKET_VNET_HDR).1 as i64, 1);
    t.eq(
        b"get sz",
        getint(fd, SOL_PACKET, PACKET_VNET_HDR_SZ).1 as i64,
        10,
    );
    t.eq(b"sz 12", setint(fd, SOL_PACKET, PACKET_VNET_HDR_SZ, 12), 0);
    t.eq(
        b"get 12",
        getint(fd, SOL_PACKET, PACKET_VNET_HDR_SZ).1 as i64,
        12,
    );
    t.eq(
        b"sz 11",
        setint(fd, SOL_PACKET, PACKET_VNET_HDR_SZ, 11),
        EINVAL,
    );
    t.eq(b"off", setint(fd, SOL_PACKET, PACKET_VNET_HDR, 0), 0);
    t.eq(
        b"get off",
        getint(fd, SOL_PACKET, PACKET_VNET_HDR_SZ).1 as i64,
        0,
    );
    t.eq(
        b"ring",
        ring_req(fd, PACKET_RX_RING, &[4096, 1, 2048, 2], 16),
        0,
    );
    t.eq(b"busy", setint(fd, SOL_PACKET, PACKET_VNET_HDR, 1), EBUSY);
    t.eq(b"bypass", setint(fd, SOL_PACKET, PACKET_QDISC_BYPASS, 1), 0);
    t.eq(
        b"bypass get",
        getint(fd, SOL_PACKET, PACKET_QDISC_BYPASS).1 as i64,
        1,
    );
    let w = [1i32, 0];
    t.eq(
        b"bypass optlen",
        sys_setsockopt(
            fd,
            SOL_PACKET,
            PACKET_QDISC_BYPASS,
            w.as_ptr() as *const u8,
            8,
        ),
        EINVAL,
    );
    close(fd);
    t.done();
}

/// Sends with a header: what goes out, what Linux refuses
fn test_snd(lo: i32) {
    let mut t = T::new(b"PACKET_VNET_SND");
    let rx = psock(SOCK_RAW, ETH_P_TEST);
    pbind(rx, ETH_P_TEST, lo);
    let tx = psock(SOCK_RAW, 0);
    t.eq(b"vnet", setint(tx, SOL_PACKET, PACKET_VNET_HDR, 1), 0);
    let mut f = [0u8; 64];
    let mut buf = [0u8; 256];
    t.eq(
        b"plain",
        snd(tx, lo, &vh(0, 0, 0, 0, 0, 0), udp_frame(&mut f, 0xa1)),
        70,
    );
    poll1(rx, 1, 2000);
    let n = recv(rx, &mut buf, MSG_DONTWAIT);
    t.eq(b"frame only", n, 60);
    t.eq(b"tag", buf[15] as i64, 0xa1);
    t.eq(b"short", snd(tx, lo, &[0u8; 5], &[]), EINVAL);
    t.eq(
        b"hdr_len past",
        snd(tx, lo, &vh(0, 0, 61, 0, 0, 0), udp_frame(&mut f, 0)),
        EINVAL,
    );
    t.eq(
        b"csum past",
        snd(tx, lo, &vh(1, 0, 0, 0, 34, 40), udp_frame(&mut f, 0)),
        EINVAL,
    );
    t.eq(
        b"gso type",
        snd(tx, lo, &vh(0, 9, 0, 1000, 0, 0), udp_frame(&mut f, 0)),
        EINVAL,
    );
    t.eq(
        b"gso size 0",
        snd(tx, lo, &vh(1, 5, 0, 0, 34, 6), udp_frame(&mut f, 0)),
        EINVAL,
    );
    t.eq(
        b"udp_l4 no csum",
        snd(tx, lo, &vh(0, 5, 0, 1000, 0, 0), udp_frame(&mut f, 0)),
        EINVAL,
    );
    t.eq(
        b"needs csum",
        snd(tx, lo, &vh(1, 0, 0, 0, 34, 6), udp_frame(&mut f, 0xa2)),
        70,
    );
    poll1(rx, 1, 2000);
    let n = recv(rx, &mut buf, MSG_DONTWAIT);
    t.ok(b"csum frame", n == 60 && buf[15] == 0xa2, n);
    t.eq(
        b"12-byte header",
        setint(tx, SOL_PACKET, PACKET_VNET_HDR_SZ, 12),
        0,
    );
    let mut h12 = [0u8; 12];
    h12[..10].copy_from_slice(&vh(0, 0, 0, 0, 0, 0));
    t.eq(
        b"sz 12 send",
        snd(tx, lo, &h12, udp_frame(&mut f, 0xa3)),
        72,
    );
    poll1(rx, 1, 2000);
    let n = recv(rx, &mut buf, MSG_DONTWAIT);
    t.ok(b"sz 12 frame", n == 60 && buf[15] == 0xa3, n);
    close(tx);
    close(rx);
    t.done();
}

/// Receives: the header before the frame (no GSO), a buffer shorter
/// than it EINVAL; a ring frame's MAC header after a header's room
fn test_rcv(lo: i32) {
    let mut t = T::new(b"PACKET_VNET_RCV");
    let rx = psock(SOCK_RAW, ETH_P_TEST);
    pbind(rx, ETH_P_TEST, lo);
    t.eq(b"vnet", setint(rx, SOL_PACKET, PACKET_VNET_HDR, 1), 0);
    let tx = psock(SOCK_RAW, 0);
    let mut f = [0u8; 64];
    let a = Sll::new(ETH_P_TEST, lo).bytes();
    let fr = udp_frame(&mut f, 0xb1);
    sys_sendto(tx, fr.as_ptr(), fr.len(), 0, a.as_ptr(), 20);
    poll1(rx, 1, 2000);
    let mut buf = [0u8; 256];
    let n = recv(rx, &mut buf, MSG_DONTWAIT);
    t.eq(b"header + frame", n, 70);
    t.eq(b"no csum flags", buf[0] as i64, 0);
    t.eq(b"gso none", buf[1] as i64, 0);
    t.eq(b"hdr_len", u16::from_le_bytes([buf[2], buf[3]]) as i64, 0);
    t.eq(b"tag", buf[10 + 15] as i64, 0xb1);
    let fr = udp_frame(&mut f, 0xb2);
    sys_sendto(tx, fr.as_ptr(), fr.len(), 0, a.as_ptr(), 20);
    poll1(rx, 1, 2000);
    let mut small = [0u8; 4];
    t.eq(b"short buffer", recv(rx, &mut small, MSG_DONTWAIT), EINVAL);
    close(rx);

    let rx = psock(SOCK_RAW, ETH_P_TEST);
    pbind(rx, ETH_P_TEST, lo);
    setint(rx, SOL_PACKET, PACKET_VNET_HDR, 1);
    setint(rx, SOL_PACKET, PACKET_VERSION, TPACKET_V2);
    t.eq(
        b"ring",
        ring_req(rx, PACKET_RX_RING, &[4096, 1, 2048, 2], 16),
        0,
    );
    let m = map(rx, 4096, 0);
    t.ok(b"map", m > 0, m);
    if m > 0 {
        let base = m as u64;
        let fr = udp_frame(&mut f, 0xb3);
        sys_sendto(tx, fr.as_ptr(), fr.len(), 0, a.as_ptr(), 20);
        let end = now_ms() + 2000;
        while rd32(base) as u64 & TP_STATUS_USER == 0 && now_ms() < end {
            crate::net::nl::msleep(10);
        }
        // TPACKET_ALIGN(52 + 16) + 10 = 90, the MAC header 14 before
        t.eq(b"tp_net", rd16(base + 14) as i64, 90);
        t.eq(b"tp_mac", rd16(base + 12) as i64, 76);
        t.eq(b"tag", rd8(base + 76 + 15) as i64, 0xb3);
        t.eq(b"gso none", rd8(base + 76 - 10 + 1) as i64, 0);
        hk_syscall::sys_munmap(base, 4096);
    }
    close(tx);
    close(rx);
    t.done();
}

/// tpacket_auxdata.tp_status of the next frame on `fd` within 2 s that
/// `pred` picks
fn aux_status(fd: i32, pred: &dyn Fn(&[u8]) -> bool) -> Option<u32> {
    let end = now_ms() + 2000;
    let mut buf = [0u8; 256];
    let mut ctl = [0u8; 128];
    while now_ms() < end {
        poll1(fd, 1, 200);
        let (n, _, clen) = recv_msg(fd, &mut buf, &mut ctl, MSG_DONTWAIT);
        if n > 0 && pred(&buf[..n as usize]) {
            let aux = cmsg_find(&ctl, clen, SOL_PACKET, PACKET_AUXDATA)?;
            return Some(u32::from_ne_bytes([aux[0], aux[1], aux[2], aux[3]]));
        }
    }
    None
}

/// Checksum state as Linux reports it over lo: a UDP datagram is
/// CHECKSUM_PARTIAL (lo offloads it), TP_STATUS_CSUMNOTREADY both ways
/// and NEEDS_CSUM in a virtio_net_hdr with the UDP checksum's place; a
/// packet socket's frame has neither CSUMNOTREADY nor CSUM_VALID
fn test_csum(lo: i32) {
    let mut t = T::new(b"PACKET_CSUM_STATUS");
    let all = psock(SOCK_RAW, ETH_P_ALL);
    pbind(all, ETH_P_ALL, lo);
    t.eq(b"auxdata", setint(all, SOL_PACKET, PACKET_AUXDATA, 1), 0);
    let v = psock(SOCK_RAW, ETH_P_IP);
    pbind(v, ETH_P_IP, lo);
    t.eq(b"vnet", setint(v, SOL_PACKET, PACKET_VNET_HDR, 1), 0);
    let (u, port) = udp_lo();
    t.eq(b"udp send", send_to(u, b"csum", LO, port, 0), 4);
    let is_udp = |f: &[u8]| {
        f.len() >= 46
            && f[12..14] == ETH_P_IP.to_be_bytes()
            && f[23] == 17
            && f[36..38] == port.to_be_bytes()
    };
    let out = aux_status(all, &is_udp);
    t.ok(
        b"udp outgoing notready",
        out.is_some_and(|s| s & 8 != 0),
        out.unwrap_or(0) as i64,
    );
    let inc = aux_status(all, &is_udp);
    t.ok(
        b"udp incoming notready",
        inc.is_some_and(|s| s & 8 != 0),
        inc.unwrap_or(0) as i64,
    );
    t.ok(
        b"udp not valid",
        inc.is_some_and(|s| s & 0x80 == 0),
        inc.unwrap_or(0) as i64,
    );
    let mut buf = [0u8; 256];
    let hit = find(v, &mut buf, 2000, &|f: &[u8], _: &Sll| {
        f.len() >= 56 && f[10 + 23] == 17 && f[10 + 36..10 + 38] == port.to_be_bytes()
    });
    t.ok(b"vnet udp", hit.is_some(), 0);
    if hit.is_some() {
        t.eq(b"needs csum", buf[0] as i64, 1);
        t.eq(
            b"csum_start",
            u16::from_le_bytes([buf[6], buf[7]]) as i64,
            34,
        );
        t.eq(
            b"csum_offset",
            u16::from_le_bytes([buf[8], buf[9]]) as i64,
            6,
        );
    }
    let tx = psock(SOCK_RAW, 0);
    let mut f = [0u8; 64];
    let fr = test_frame(&mut f, 0xd1, 60);
    let a = Sll::new(ETH_P_TEST, lo).bytes();
    sys_sendto(tx, fr.as_ptr(), fr.len(), 0, a.as_ptr(), 20);
    let st = aux_status(all, &|f: &[u8]| f.len() == 60 && f[14] == 0xd1);
    t.ok(
        b"frame no csum bits",
        st.is_some_and(|s| s & 0x88 == 0),
        st.unwrap_or(0) as i64,
    );
    close(tx);
    close(u);
    close(v);
    close(all);
    t.done();
}

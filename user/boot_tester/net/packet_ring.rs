//! AF_PACKET mmap rings (hk and Linux), after Linux
//! tools/testing/selftests/net/psock_tpacket.c: the ring options
//! (PACKET_VERSION, PACKET_HDRLEN, PACKET_RESERVE, ...) and their
//! EBUSY once a ring exists, PACKET_RX_RING validation, mmap's size,
//! offset and busy rules (mappings counted across fork and split),
//! TPACKET_V1/V2 receive over lo (frame headers, sockaddr_ll, the
//! status handshake, poll), a full ring's drops with TP_STATUS_LOSING
//! and PACKET_COPY_THRESH's queued copy.

use hk_syscall::{
    MAP_SHARED, POLLIN, POLLOUT, PROT_READ, PROT_WRITE, SOCK_DGRAM, SOCK_RAW, sys_exit, sys_fork,
    sys_getsockopt, sys_mmap, sys_munmap, sys_recvfrom, sys_setsockopt, sys_wait4,
};

use crate::harness::T;
use crate::helpers::println;
use crate::net::nl::msleep;
use crate::net::packet::{
    AF_PACKET, ETH_P_ALL, ETH_P_TEST, PACKET_HOST, PACKET_STATISTICS, SOL_PACKET, Sll, ifindex,
    pbind, psock, sendto_ll, test_frame,
};
use crate::net::sk::*;

pub const PACKET_RX_RING: i32 = 5;
pub const PACKET_COPY_THRESH: i32 = 7;
pub const PACKET_VERSION: i32 = 10;
pub const PACKET_HDRLEN: i32 = 11;
pub const PACKET_RESERVE: i32 = 12;
pub const PACKET_TX_RING: i32 = 13;
pub const PACKET_LOSS: i32 = 14;
pub const PACKET_TIMESTAMP: i32 = 17;
pub const PACKET_TX_HAS_OFF: i32 = 19;

pub const TPACKET_V1: i32 = 0;
pub const TPACKET_V2: i32 = 1;
pub const TPACKET_V3: i32 = 2;
pub const TP_STATUS_BLK_TMO: u32 = 1 << 5;

pub const TP_STATUS_USER: u64 = 1;
pub const TP_STATUS_COPY: u64 = 2;
pub const TP_STATUS_LOSING: u64 = 4;
pub const TP_STATUS_SEND_REQUEST: u32 = 1;
pub const TP_STATUS_WRONG_FORMAT: u64 = 4;

pub const EBUSY: i64 = -16;
pub const ENODEV: i64 = -19;
const ARPHRD_LOOPBACK: u16 = 772;

pub fn run_tests() {
    println(b"=== AF_PACKET ring Tests ===");
    let lo = ifindex(b"lo");
    test_opts();
    test_req_errors();
    test_mmap_rules();
    test_rx(lo, TPACKET_V1, SOCK_RAW, b"PACKET_RING_RX_V1");
    test_rx(lo, TPACKET_V2, SOCK_RAW, b"PACKET_RING_RX_V2");
    test_rx(lo, TPACKET_V2, SOCK_DGRAM, b"PACKET_RING_RX_V2_DGRAM");
    test_full(lo);
    test_copy_thresh(lo);
    test_big_block(lo);
    test_tx(lo, TPACKET_V1, b"PACKET_RING_TX_V1");
    test_tx(lo, TPACKET_V2, b"PACKET_RING_TX_V2");
    test_tx_rules(lo);
    test_rx_tx_map(lo);
    test_v3_rx(lo);
    test_v3_full(lo);
    test_v3_tx(lo);
}

/// setsockopt(PACKET_RX_RING etc.) with a tpacket_req
pub fn ring_req(fd: i32, opt: i32, w: &[u32], len: u32) -> i64 {
    let mut b = [0u32; 8];
    b[..w.len()].copy_from_slice(w);
    sys_setsockopt(fd, SOL_PACKET, opt, b.as_ptr() as *const u8, len)
}

/// mmap(fd) shared read-write at offset `off`
pub fn map(fd: i32, len: u64, off: u64) -> i64 {
    sys_mmap(0, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, off)
}

pub fn rd32(a: u64) -> u32 {
    unsafe { core::ptr::read_volatile(a as *const u32) }
}

pub fn rd16(a: u64) -> u16 {
    unsafe { core::ptr::read_volatile(a as *const u16) }
}

pub fn rd8(a: u64) -> u8 {
    unsafe { core::ptr::read_volatile(a as *const u8) }
}

pub fn wr32(a: u64, v: u32) {
    unsafe { core::ptr::write_volatile(a as *mut u32, v) }
}

pub fn wr64(a: u64, v: u64) {
    unsafe { core::ptr::write_volatile(a as *mut u64, v) }
}

/// A frame's status word (V1: unsigned long)
fn status(f: u64, ver: i32) -> u64 {
    if ver == TPACKET_V1 {
        unsafe { core::ptr::read_volatile(f as *const u64) }
    } else {
        rd32(f) as u64
    }
}

/// Give a frame back to the kernel
fn release(f: u64, ver: i32) {
    if ver == TPACKET_V1 {
        wr64(f, 0);
    } else {
        wr32(f, 0);
    }
}

/// Wait up to `ms` for frame `f` to be the user's
fn wait_user(f: u64, ver: i32, ms: u64) -> bool {
    let end = now_ms() + ms;
    while now_ms() < end {
        if status(f, ver) & TP_STATUS_USER != 0 {
            return true;
        }
        msleep(10);
    }
    false
}

/// (tp_len, tp_snaplen, tp_mac, tp_net)
fn hdr(f: u64, ver: i32) -> (u32, u32, u16, u16) {
    if ver == TPACKET_V1 {
        (rd32(f + 8), rd32(f + 12), rd16(f + 16), rd16(f + 18))
    } else {
        (rd32(f + 4), rd32(f + 8), rd16(f + 12), rd16(f + 14))
    }
}

/// The sockaddr_ll after a 32-byte header
fn sll_at(a: u64) -> Sll {
    let mut b = [0u8; 20];
    for (i, x) in b.iter_mut().enumerate() {
        *x = rd8(a + i as u64);
    }
    Sll::parse(&b)
}

/// struct tpacket_stats: (packets, drops)
pub fn stats(fd: i32) -> (u32, u32) {
    let mut st = [0u32; 3];
    let mut len = 12u32;
    sys_getsockopt(
        fd,
        SOL_PACKET,
        PACKET_STATISTICS,
        st.as_mut_ptr() as *mut u8,
        &mut len,
    );
    (st[0], st[1])
}

/// getsockopt(PACKET_HDRLEN) of version `v` with an `len`-byte buffer
fn hdrlen(fd: i32, v: i32, len: u32) -> (i64, i32) {
    let mut b = [v, 0];
    let mut l = len;
    let r = sys_getsockopt(
        fd,
        SOL_PACKET,
        PACKET_HDRLEN,
        b.as_mut_ptr() as *mut u8,
        &mut l,
    );
    (r, b[0])
}

/// The ring options: values and errors, EBUSY with a ring
fn test_opts() {
    let mut t = T::new(b"PACKET_RING_OPTS");
    let fd = psock(SOCK_RAW, 0);
    t.eq(b"hdrlen v1", hdrlen(fd, 0, 4).1 as i64, 32);
    t.eq(b"hdrlen v2", hdrlen(fd, 1, 4).1 as i64, 32);
    t.eq(b"hdrlen v3", hdrlen(fd, 2, 4).1 as i64, 48);
    t.eq(b"hdrlen long buf", hdrlen(fd, 1, 8).1 as i64, 32);
    t.eq(b"hdrlen v4", hdrlen(fd, 3, 4).0, EINVAL);
    t.eq(b"hdrlen short", hdrlen(fd, 1, 2).0, EINVAL);
    t.eq(
        b"version default",
        getint(fd, SOL_PACKET, PACKET_VERSION).1 as i64,
        0,
    );
    t.eq(
        b"version 3",
        setint(fd, SOL_PACKET, PACKET_VERSION, 3),
        EINVAL,
    );
    let v = [1i32, 0];
    t.eq(
        b"version optlen",
        sys_setsockopt(fd, SOL_PACKET, PACKET_VERSION, v.as_ptr() as *const u8, 8),
        EINVAL,
    );
    t.eq(b"version 2", setint(fd, SOL_PACKET, PACKET_VERSION, 1), 0);
    t.eq(
        b"version get",
        getint(fd, SOL_PACKET, PACKET_VERSION).1 as i64,
        1,
    );
    t.eq(
        b"reserve neg",
        setint(fd, SOL_PACKET, PACKET_RESERVE, -1),
        EINVAL,
    );
    t.eq(b"reserve", setint(fd, SOL_PACKET, PACKET_RESERVE, 64), 0);
    t.eq(
        b"reserve get",
        getint(fd, SOL_PACKET, PACKET_RESERVE).1 as i64,
        64,
    );
    t.eq(b"loss", setint(fd, SOL_PACKET, PACKET_LOSS, 1), 0);
    t.eq(b"loss get", getint(fd, SOL_PACKET, PACKET_LOSS).1 as i64, 1);
    t.eq(b"timestamp", setint(fd, SOL_PACKET, PACKET_TIMESTAMP, 3), 0);
    t.eq(
        b"timestamp get",
        getint(fd, SOL_PACKET, PACKET_TIMESTAMP).1 as i64,
        3,
    );
    t.eq(
        b"copy_thresh optlen",
        sys_setsockopt(
            fd,
            SOL_PACKET,
            PACKET_COPY_THRESH,
            v.as_ptr() as *const u8,
            2,
        ),
        EINVAL,
    );
    t.eq(
        b"copy_thresh",
        setint(fd, SOL_PACKET, PACKET_COPY_THRESH, 1),
        0,
    );
    t.eq(
        b"tx_has_off",
        setint(fd, SOL_PACKET, PACKET_TX_HAS_OFF, 1),
        0,
    );
    t.eq(
        b"tx_has_off get",
        getint(fd, SOL_PACKET, PACKET_TX_HAS_OFF).1 as i64,
        1,
    );
    // 64 reserved bytes still fit a 2048-byte frame
    t.eq(
        b"ring",
        ring_req(fd, PACKET_RX_RING, &[4096, 1, 2048, 2], 16),
        0,
    );
    t.eq(
        b"busy version",
        setint(fd, SOL_PACKET, PACKET_VERSION, 0),
        EBUSY,
    );
    t.eq(
        b"busy reserve",
        setint(fd, SOL_PACKET, PACKET_RESERVE, 0),
        EBUSY,
    );
    t.eq(b"busy loss", setint(fd, SOL_PACKET, PACKET_LOSS, 0), EBUSY);
    t.eq(
        b"busy ring",
        ring_req(fd, PACKET_RX_RING, &[4096, 1, 2048, 2], 16),
        EBUSY,
    );
    t.eq(
        b"tx_has_off ignored",
        setint(fd, SOL_PACKET, PACKET_TX_HAS_OFF, 0),
        0,
    );
    t.eq(
        b"tx_has_off kept",
        getint(fd, SOL_PACKET, PACKET_TX_HAS_OFF).1 as i64,
        1,
    );
    t.eq(
        b"teardown",
        ring_req(fd, PACKET_RX_RING, &[0, 0, 0, 0], 16),
        0,
    );
    t.eq(
        b"version again",
        setint(fd, SOL_PACKET, PACKET_VERSION, 0),
        0,
    );
    close(fd);
    t.done();
}

/// PACKET_RX_RING validation (Linux packet_set_ring)
fn test_req_errors() {
    let mut t = T::new(b"PACKET_RING_REQ");
    let fd = psock(SOCK_RAW, 0);
    let r = |w: &[u32], len: u32| ring_req(fd, PACKET_RX_RING, w, len);
    t.eq(b"short", r(&[4096, 1, 2048, 2], 8), EINVAL);
    t.eq(b"block not page", r(&[4000, 1, 2000, 2], 16), EINVAL);
    t.eq(
        b"block negative",
        r(&[0x8000_0000, 1, 4096, 0x8_0000], 16),
        EINVAL,
    );
    t.eq(b"frame small", r(&[4096, 1, 48, 85], 16), EINVAL);
    t.eq(b"frame unaligned", r(&[4096, 1, 1032, 3], 16), EINVAL);
    t.eq(b"frame over block", r(&[4096, 1, 8192, 0], 16), EINVAL);
    t.eq(b"frame_nr", r(&[4096, 2, 2048, 3], 16), EINVAL);
    t.eq(b"frames no blocks", r(&[0, 0, 0, 3], 16), EINVAL);
    t.eq(b"overflow", r(&[4096, 0x8000_0001, 2048, 2], 16), EINVAL);
    t.eq(b"no ring teardown", r(&[0, 0, 0, 0], 16), 0);
    close(fd);
    t.done();
}

/// mmap: no ring EINVAL, the exact size from offset 0 only, the ring
/// busy while mapped (counted per VMA: a fork's copy, a split), UDP
/// has none (ENODEV)
fn test_mmap_rules() {
    let mut t = T::new(b"PACKET_RING_MMAP");
    let fd = psock(SOCK_RAW, 0);
    t.eq(b"no ring", map(fd, 4096, 0), EINVAL);
    t.eq(
        b"ring",
        ring_req(fd, PACKET_RX_RING, &[4096, 2, 2048, 4], 16),
        0,
    );
    t.eq(b"small", map(fd, 4096, 0), EINVAL);
    t.eq(b"large", map(fd, 12288, 0), EINVAL);
    t.eq(b"offset", map(fd, 8192, 4096), EINVAL);
    let m = map(fd, 8192, 0);
    t.ok(b"map", m > 0, m);
    let teardown = |t: &mut T, why: &[u8], want: i64| {
        t.eq(why, ring_req(fd, PACKET_RX_RING, &[0, 0, 0, 0], 16), want);
    };
    teardown(&mut t, b"busy mapped", EBUSY);
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(0);
    }
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    teardown(&mut t, b"busy after fork", EBUSY);
    t.eq(b"split", sys_munmap(m as u64 + 4096, 4096), 0);
    teardown(&mut t, b"busy half", EBUSY);
    t.eq(b"unmap", sys_munmap(m as u64, 4096), 0);
    teardown(&mut t, b"unmapped", 0);
    close(fd);
    let u = udp();
    t.eq(b"udp", map(u, 4096, 0), ENODEV);
    close(u);
    t.done();
}

/// Frame `i` of a ring of `fpb` frames per `bs`-byte block
fn frame_at(base: u64, bs: u64, fs: u64, fpb: u64, i: u64) -> u64 {
    base + (i / fpb) * bs + (i % fpb) * fs
}

/// TPACKET_V1/V2 receive over lo: three frames in order with their
/// headers and addresses, readable until given back
fn test_rx(lo: i32, ver: i32, ty: i32, name: &'static [u8]) {
    let mut t = T::new(name);
    let rx = psock(ty, ETH_P_TEST);
    pbind(rx, ETH_P_TEST, lo);
    t.eq(b"version", setint(rx, SOL_PACKET, PACKET_VERSION, ver), 0);
    t.eq(
        b"ring",
        ring_req(rx, PACKET_RX_RING, &[4096, 2, 2048, 4], 16),
        0,
    );
    let m = map(rx, 8192, 0);
    t.ok(b"map", m > 0, m);
    if m <= 0 {
        close(rx);
        t.done();
        return;
    }
    let base = m as u64;
    let f = |i: u64| frame_at(base, 4096, 2048, 2, i);
    t.eq(b"idle", poll1(rx, POLLIN, 0).0, 0);
    let tx = psock(SOCK_RAW, 0);
    let mut buf = [0u8; 128];
    for i in 0..3u8 {
        let len = 60 + 10 * i as usize;
        sendto_ll(
            tx,
            test_frame(&mut buf, 0x60 + i, len),
            &Sll::new(ETH_P_TEST, lo),
            20,
        );
    }
    t.ok(b"filled", wait_user(f(2), ver, 3000), 0);
    t.eq(b"pollin", poll1(rx, POLLIN, 0).1 as i64 & 1, 1);
    // SOCK_RAW: the frame from the link header, its network header at
    // TPACKET_ALIGN(hdrlen + 16) = 80; SOCK_DGRAM: both at
    // TPACKET_ALIGN(hdrlen) + 16 = 80
    let (mac, net) = if ty == SOCK_RAW { (66, 80) } else { (80, 80) };
    for i in 0..3u64 {
        let a = f(i);
        let len = 60 + 10 * i as u32 - if ty == SOCK_RAW { 0 } else { 14 };
        t.ok(
            b"user",
            status(a, ver) & TP_STATUS_USER != 0,
            status(a, ver) as i64,
        );
        let (l, snap, m, n) = hdr(a, ver);
        t.eq(b"tp_len", l as i64, len as i64);
        t.eq(b"tp_snaplen", snap as i64, len as i64);
        t.eq(b"tp_mac", m as i64, mac);
        t.eq(b"tp_net", n as i64, net);
        let tag = if ty == SOCK_RAW {
            rd8(a + m as u64 + 14)
        } else {
            rd8(a + n as u64)
        };
        t.eq(b"order", tag as i64, 0x60 + i as i64);
        let s = sll_at(a + 32);
        t.eq(b"sll_family", rd16(a + 32) as i64, AF_PACKET as i64);
        t.eq(b"sll_protocol", s.protocol as i64, ETH_P_TEST as i64);
        t.eq(b"sll_ifindex", s.ifindex as i64, lo as i64);
        t.eq(b"sll_hatype", s.hatype as i64, ARPHRD_LOOPBACK as i64);
        t.eq(b"sll_pkttype", s.pkttype as i64, PACKET_HOST as i64);
        t.eq(b"sll_halen", s.halen as i64, 6);
        let sec = if ver == TPACKET_V1 {
            rd32(a + 20)
        } else {
            rd32(a + 16)
        };
        t.ok(b"tp_sec", sec > 0, sec as i64);
        release(a, ver);
    }
    t.eq(b"given back", poll1(rx, POLLIN, 0).0, 0);
    t.eq(b"no copy queued", recv(rx, &mut buf, MSG_DONTWAIT), EAGAIN);
    t.eq(b"stats", stats(rx).0 as i64, 3);
    sys_munmap(base, 8192);
    close(tx);
    close(rx);
    t.done();
}

/// A full ring drops frames (PACKET_STATISTICS counts them); the next
/// frame filled carries TP_STATUS_LOSING until the statistics are read
fn test_full(lo: i32) {
    let mut t = T::new(b"PACKET_RING_FULL");
    let rx = psock(SOCK_RAW, ETH_P_TEST);
    pbind(rx, ETH_P_TEST, lo);
    setint(rx, SOL_PACKET, PACKET_VERSION, TPACKET_V2);
    t.eq(
        b"ring",
        ring_req(rx, PACKET_RX_RING, &[4096, 1, 1024, 4], 16),
        0,
    );
    let m = map(rx, 4096, 0);
    t.ok(b"map", m > 0, m);
    if m <= 0 {
        close(rx);
        t.done();
        return;
    }
    let base = m as u64;
    let f = |i: u64| base + i * 1024;
    let tx = psock(SOCK_RAW, 0);
    let to = Sll::new(ETH_P_TEST, lo);
    let mut buf = [0u8; 128];
    for i in 0..6u8 {
        sendto_ll(tx, test_frame(&mut buf, i, 60), &to, 20);
    }
    t.ok(b"filled", wait_user(f(3), TPACKET_V2, 3000), 0);
    msleep(100);
    for i in 0..4u64 {
        t.eq(
            b"no losing",
            (status(f(i), TPACKET_V2) & TP_STATUS_LOSING) as i64,
            0,
        );
        t.eq(b"first four", rd8(f(i) + 66 + 14) as i64, i as i64);
    }
    release(f(0), TPACKET_V2);
    sendto_ll(tx, test_frame(&mut buf, 0x77, 60), &to, 20);
    t.ok(b"refilled", wait_user(f(0), TPACKET_V2, 3000), 0);
    t.eq(b"next", rd8(f(0) + 66 + 14) as i64, 0x77);
    t.ok(
        b"losing",
        status(f(0), TPACKET_V2) & TP_STATUS_LOSING != 0,
        status(f(0), TPACKET_V2) as i64,
    );
    let (p, d) = stats(rx);
    t.eq(b"drops", d as i64, 2);
    t.eq(b"packets", p as i64, 7);
    release(f(1), TPACKET_V2);
    sendto_ll(tx, test_frame(&mut buf, 0x78, 60), &to, 20);
    t.ok(b"refilled 2", wait_user(f(1), TPACKET_V2, 3000), 0);
    t.eq(
        b"losing cleared",
        (status(f(1), TPACKET_V2) & TP_STATUS_LOSING) as i64,
        0,
    );
    sys_munmap(base, 4096);
    close(tx);
    close(rx);
    t.done();
}

/// PACKET_COPY_THRESH: a frame too big for its slot is cut there
/// (TP_STATUS_COPY) and queued whole for recvmsg, with no device or
/// address in its sockaddr_ll
fn test_copy_thresh(lo: i32) {
    let mut t = T::new(b"PACKET_RING_COPY");
    let rx = psock(SOCK_RAW, ETH_P_TEST);
    pbind(rx, ETH_P_TEST, lo);
    setint(rx, SOL_PACKET, PACKET_VERSION, TPACKET_V2);
    t.eq(b"thresh", setint(rx, SOL_PACKET, PACKET_COPY_THRESH, 1), 0);
    t.eq(
        b"ring",
        ring_req(rx, PACKET_RX_RING, &[4096, 1, 128, 32], 16),
        0,
    );
    let m = map(rx, 4096, 0);
    t.ok(b"map", m > 0, m);
    if m <= 0 {
        close(rx);
        t.done();
        return;
    }
    let base = m as u64;
    let tx = psock(SOCK_RAW, ETH_P_ALL);
    let mut buf = [0u8; 256];
    sendto_ll(
        tx,
        test_frame(&mut buf, 0x79, 200),
        &Sll::new(ETH_P_TEST, lo),
        20,
    );
    t.ok(b"filled", wait_user(base, TPACKET_V2, 3000), 0);
    let st = status(base, TPACKET_V2);
    t.ok(b"copy", st & TP_STATUS_COPY != 0, st as i64);
    let (l, snap, mac, _) = hdr(base, TPACKET_V2);
    t.eq(b"tp_len", l as i64, 200);
    t.eq(b"tp_snaplen", snap as i64, 128 - 66);
    t.eq(b"tp_mac", mac as i64, 66);
    let mut a = [0u8; 20];
    let mut alen = 20u32;
    let n = sys_recvfrom(
        rx,
        buf.as_mut_ptr(),
        buf.len(),
        MSG_DONTWAIT,
        a.as_mut_ptr(),
        &mut alen,
    );
    t.eq(b"whole copy", n, 200);
    t.eq(b"copy tag", buf[14] as i64, 0x79);
    let s = Sll::parse(&a);
    t.eq(b"copy protocol", s.protocol as i64, ETH_P_TEST as i64);
    t.eq(b"copy ifindex", s.ifindex as i64, 0);
    t.eq(b"copy halen", s.halen as i64, 0);
    sys_munmap(base, 4096);
    close(tx);
    close(rx);
    t.done();
}

/// Fill TX frame `f` (data at `off`, tp_len `len`, tag) and request it
fn tx_fill(f: u64, ver: i32, off: u64, len: usize, tag: u8) {
    let mut b = [0u8; 2048];
    let fr = test_frame(&mut b, tag, len);
    for (i, x) in fr.iter().enumerate() {
        unsafe { core::ptr::write_volatile((f + off + i as u64) as *mut u8, *x) };
    }
    if ver == TPACKET_V1 {
        wr32(f + 8, len as u32);
    } else {
        wr32(f + 4, len as u32);
    }
    if ver == TPACKET_V1 {
        wr64(f, TP_STATUS_SEND_REQUEST as u64);
    } else {
        wr32(f, TP_STATUS_SEND_REQUEST);
    }
}

/// A TX ring socket on lo with `opts` set first: (fd, ring base)
fn tx_sock(lo: i32, ver: i32, opts: &[(i32, i32)]) -> (i32, u64) {
    let tx = psock(SOCK_RAW, 0);
    pbind(tx, ETH_P_TEST, lo);
    setint(tx, SOL_PACKET, PACKET_VERSION, ver);
    for &(o, v) in opts {
        setint(tx, SOL_PACKET, o, v);
    }
    ring_req(tx, PACKET_TX_RING, &[4096, 1, 2048, 2], 16);
    let m = map(tx, 4096, 0);
    (tx, if m > 0 { m as u64 } else { 0 })
}

/// The next frame on `rx` with test tag `tag` within 2 s: its length
fn rx_tag(rx: i32, tag: u8) -> i64 {
    let mut buf = [0u8; 2048];
    let end = now_ms() + 2000;
    while now_ms() < end {
        poll1(rx, POLLIN, 200);
        let n = recv(rx, &mut buf, MSG_DONTWAIT);
        if n > 14 && buf[14] == tag {
            return n;
        }
    }
    -1
}

/// TPACKET_V1/V2 transmit: requested frames go out in order and come
/// back available; send returns their bytes; nothing requested is 0
fn test_tx(lo: i32, ver: i32, name: &'static [u8]) {
    let mut t = T::new(name);
    let rx = psock(SOCK_RAW, ETH_P_TEST);
    pbind(rx, ETH_P_TEST, lo);
    let (tx, base) = tx_sock(lo, ver, &[]);
    t.ok(b"map", base != 0, 0);
    if base == 0 {
        close(tx);
        close(rx);
        t.done();
        return;
    }
    // Data right after the header, at tp_hdrlen - sizeof(sockaddr_ll)
    tx_fill(base, ver, 32, 60, 0x81);
    tx_fill(base + 2048, ver, 32, 70, 0x82);
    t.eq(b"send", send(tx, &[], 0), 130);
    t.eq(b"available 0", status(base, ver) as i64, 0);
    t.eq(b"available 1", status(base + 2048, ver) as i64, 0);
    t.eq(b"first", rx_tag(rx, 0x81), 60);
    t.eq(b"second", rx_tag(rx, 0x82), 70);
    t.eq(b"nothing", send(tx, &[], 0), 0);
    t.eq(
        b"pollout",
        poll1(tx, POLLOUT, 0).1 as i64 & POLLOUT as i64,
        POLLOUT as i64,
    );
    sys_munmap(base, 4096);
    close(tx);
    close(rx);
    t.done();
}

/// Malformed TX frames: short of an Ethernet header EINVAL and
/// TP_STATUS_WRONG_FORMAT, over the frame EMSGSIZE; PACKET_LOSS skips
/// them; PACKET_TX_HAS_OFF takes the data offset from tp_mac
fn test_tx_rules(lo: i32) {
    let mut t = T::new(b"PACKET_RING_TX_RULES");
    let rx = psock(SOCK_RAW, ETH_P_TEST);
    pbind(rx, ETH_P_TEST, lo);
    let (tx, base) = tx_sock(lo, TPACKET_V2, &[]);
    if base != 0 {
        tx_fill(base, TPACKET_V2, 32, 60, 0x83);
        wr32(base + 4, 10);
        t.eq(b"short", send(tx, &[], 0), EINVAL);
        t.eq(
            b"wrong format",
            status(base, TPACKET_V2) as i64,
            TP_STATUS_WRONG_FORMAT as i64,
        );
        tx_fill(base, TPACKET_V2, 32, 60, 0x83);
        wr32(base + 4, 2017);
        t.eq(b"over frame", send(tx, &[], 0), EMSGSIZE);
        sys_munmap(base, 4096);
    }
    close(tx);

    let (tx, base) = tx_sock(lo, TPACKET_V2, &[(PACKET_LOSS, 1)]);
    if base != 0 {
        tx_fill(base, TPACKET_V2, 32, 60, 0x84);
        wr32(base + 4, 10);
        tx_fill(base + 2048, TPACKET_V2, 32, 60, 0x85);
        t.eq(b"loss skips", send(tx, &[], 0), 60);
        t.eq(b"skipped available", status(base, TPACKET_V2) as i64, 0);
        t.eq(b"after skip", rx_tag(rx, 0x85), 60);
        sys_munmap(base, 4096);
    }
    close(tx);

    let (tx, base) = tx_sock(lo, TPACKET_V2, &[(PACKET_TX_HAS_OFF, 1)]);
    if base != 0 {
        tx_fill(base, TPACKET_V2, 100, 60, 0x86);
        unsafe { core::ptr::write_volatile((base + 12) as *mut u16, 100) };
        t.eq(b"has_off", send(tx, &[], 0), 60);
        t.eq(b"has_off frame", rx_tag(rx, 0x86), 60);
        tx_fill(base + 2048, TPACKET_V2, 32, 60, 0x87);
        unsafe { core::ptr::write_volatile((base + 2048 + 12) as *mut u16, 16) };
        t.eq(b"has_off low", send(tx, &[], 0), EINVAL);
        sys_munmap(base, 4096);
    }
    close(tx);
    close(rx);
    t.done();
}

/// Both rings mapped at once: the receive ring first, then the
/// transmit ring
fn test_rx_tx_map(lo: i32) {
    let mut t = T::new(b"PACKET_RING_RXTX");
    let fd = psock(SOCK_RAW, ETH_P_TEST);
    pbind(fd, ETH_P_TEST, lo);
    setint(fd, SOL_PACKET, PACKET_VERSION, TPACKET_V2);
    t.eq(
        b"rx",
        ring_req(fd, PACKET_RX_RING, &[4096, 1, 2048, 2], 16),
        0,
    );
    t.eq(
        b"tx",
        ring_req(fd, PACKET_TX_RING, &[4096, 2, 2048, 4], 16),
        0,
    );
    t.eq(b"rx only size", map(fd, 4096, 0), EINVAL);
    let m = map(fd, 12288, 0);
    t.ok(b"map both", m > 0, m);
    if m > 0 {
        let base = m as u64;
        tx_fill(base + 4096, TPACKET_V2, 32, 60, 0x88);
        t.eq(b"send", send(fd, &[], 0), 60);
        // Its own frame comes back in through lo into the receive ring
        t.ok(b"looped", wait_user(base, TPACKET_V2, 2000), 0);
        t.eq(b"tag", rd8(base + 66 + 14) as i64, 0x88);
        sys_munmap(base, 12288);
    }
    close(fd);
    t.done();
}

/// struct tpacket_stats_v3: (len, packets, drops, freeze_q_cnt)
fn stats3(fd: i32) -> (u32, u32, u32, u32) {
    let mut st = [0u32; 3];
    let mut len = 12u32;
    sys_getsockopt(
        fd,
        SOL_PACKET,
        PACKET_STATISTICS,
        st.as_mut_ptr() as *mut u8,
        &mut len,
    );
    (len, st[0], st[1], st[2])
}

/// A V3 receive socket on lo: (fd, base) of `nr` 4096-byte blocks
fn v3_sock(lo: i32, nr: u32, tov: u32) -> (i32, u64) {
    let rx = psock(SOCK_RAW, ETH_P_TEST);
    pbind(rx, ETH_P_TEST, lo);
    setint(rx, SOL_PACKET, PACKET_VERSION, TPACKET_V3);
    ring_req(rx, PACKET_RX_RING, &[4096, nr, 2048, nr * 2, tov, 0, 0], 28);
    let m = map(rx, 4096 * nr as u64, 0);
    (rx, if m > 0 { m as u64 } else { 0 })
}

/// Wait up to `ms` for block `b` to be the user's
fn wait_block(b: u64, ms: u64) -> bool {
    let end = now_ms() + ms;
    while now_ms() < end {
        if rd32(b + 8) & 1 != 0 {
            return true;
        }
        msleep(10);
    }
    false
}

/// TPACKET_V3 receive: packets packed in a block that the retire timer
/// hands over (TP_STATUS_BLK_TMO), block descriptor and packet headers
fn test_v3_rx(lo: i32) {
    let mut t = T::new(b"PACKET_RING_V3_RX");
    let fd = psock(SOCK_RAW, 0);
    setint(fd, SOL_PACKET, PACKET_VERSION, TPACKET_V3);
    t.eq(
        b"req short",
        ring_req(fd, PACKET_RX_RING, &[4096, 1, 2048, 2], 16),
        EINVAL,
    );
    t.eq(
        b"priv too big",
        ring_req(fd, PACKET_RX_RING, &[4096, 1, 2048, 2, 0, 4000, 0], 28),
        EINVAL,
    );
    close(fd);
    let (rx, base) = v3_sock(lo, 4, 500);
    t.ok(b"map", base != 0, 0);
    if base == 0 {
        close(rx);
        t.done();
        return;
    }
    let tx = psock(SOCK_RAW, 0);
    let mut buf = [0u8; 128];
    for i in 0..3u8 {
        sendto_ll(
            tx,
            test_frame(&mut buf, 0x90 + i, 60 + i as usize),
            &Sll::new(ETH_P_TEST, lo),
            20,
        );
    }
    t.ok(b"retired", wait_block(base, 3000), 0);
    t.eq(b"pollin", poll1(rx, POLLIN, 0).1 as i64 & 1, 1);
    let st = rd32(base + 8);
    t.ok(b"BLK_TMO", st & TP_STATUS_BLK_TMO != 0, st as i64);
    t.eq(b"version", rd32(base) as i64, TPACKET_V3 as i64);
    t.eq(b"offset_to_priv", rd32(base + 4) as i64, 48);
    t.eq(b"num_pkts", rd32(base + 12) as i64, 3);
    t.eq(b"offset_to_first_pkt", rd32(base + 16) as i64, 48);
    t.eq(
        b"seq_num",
        unsafe { core::ptr::read_volatile((base + 24) as *const u64) } as i64,
        1,
    );
    let mut p = base + 48;
    for i in 0..3u64 {
        let len = 60 + i as u32;
        t.eq(b"tp_len", rd32(p + 16) as i64, len as i64);
        t.eq(b"tp_snaplen", rd32(p + 12) as i64, len as i64);
        // TPACKET_ALIGN(68 + 16) = 96, the MAC header 14 before
        t.eq(b"tp_mac", rd16(p + 24) as i64, 82);
        t.eq(b"tp_net", rd16(p + 26) as i64, 96);
        t.eq(b"tag", rd8(p + 82 + 14) as i64, 0x90 + i as i64);
        let s = sll_at(p + 48);
        t.eq(b"sll_ifindex", s.ifindex as i64, lo as i64);
        t.eq(b"sll_protocol", s.protocol as i64, ETH_P_TEST as i64);
        let next = rd32(p) as u64;
        if i < 2 {
            t.eq(b"next aligned", next as i64 % 8, 0);
            t.ok(b"next", next >= 82 + len as u64, next as i64);
        } else {
            t.eq(b"last next", next as i64, 0);
        }
        p += next;
    }
    wr32(base + 8, 0);
    let (len, packets, drops, freeze) = stats3(rx);
    t.eq(b"stats v3 len", len as i64, 12);
    t.eq(b"packets", packets as i64, 3);
    t.eq(b"drops", drops as i64, 0);
    t.eq(b"freeze", freeze as i64, 0);
    sys_munmap(base, 4 * 4096);
    close(tx);
    close(rx);
    t.done();
}

/// A packet that does not fit closes the block (no BLK_TMO); with the
/// next block still the user's the queue freezes and drops
/// (tp_freeze_q_cnt), and thaws once the block is given back
fn test_v3_full(lo: i32) {
    let mut t = T::new(b"PACKET_RING_V3_FULL");
    let (rx, base) = v3_sock(lo, 2, 1000);
    t.ok(b"map", base != 0, 0);
    if base == 0 {
        close(rx);
        t.done();
        return;
    }
    let tx = psock(SOCK_RAW, 0);
    let to = Sll::new(ETH_P_TEST, lo);
    let mut buf = [0u8; 1100];
    // 82 + 1000 bytes take 1088: three per block
    for i in 0..7u8 {
        sendto_ll(tx, test_frame(&mut buf, i, 1000), &to, 20);
    }
    t.ok(b"block 0", wait_block(base, 2000), 0);
    t.ok(b"block 1", wait_block(base + 4096, 2000), 0);
    t.eq(b"closed, not timed out", rd32(base + 8) as i64, 1);
    t.eq(b"block 1 status", rd32(base + 4096 + 8) as i64, 1);
    t.eq(b"block 0 pkts", rd32(base + 12) as i64, 3);
    t.eq(b"block 1 pkts", rd32(base + 4096 + 12) as i64, 3);
    t.eq(b"block 1 first", rd8(base + 4096 + 48 + 82 + 14) as i64, 3);
    let (_, packets, drops, freeze) = stats3(rx);
    t.eq(b"packets", packets as i64, 7);
    t.eq(b"drops", drops as i64, 1);
    t.eq(b"freeze", freeze as i64, 1);
    wr32(base + 8, 0);
    sendto_ll(tx, test_frame(&mut buf, 0x55, 100), &to, 20);
    t.ok(b"thawed", wait_block(base, 3000), 0);
    t.eq(b"after thaw", rd8(base + 48 + 82 + 14) as i64, 0x55);
    t.eq(
        b"seq",
        unsafe { core::ptr::read_volatile((base + 24) as *const u64) } as i64,
        3,
    );
    sys_munmap(base, 2 * 4096);
    close(tx);
    close(rx);
    t.done();
}

/// TPACKET_V3 transmit: no block options (EINVAL), frames with the V3
/// header (status at 20, tp_len at 16, data at tp_hdrlen - 20 = 48)
fn test_v3_tx(lo: i32) {
    let mut t = T::new(b"PACKET_RING_V3_TX");
    let rx = psock(SOCK_RAW, ETH_P_TEST);
    pbind(rx, ETH_P_TEST, lo);
    let tx = psock(SOCK_RAW, 0);
    pbind(tx, ETH_P_TEST, lo);
    setint(tx, SOL_PACKET, PACKET_VERSION, TPACKET_V3);
    t.eq(
        b"block options",
        ring_req(tx, PACKET_TX_RING, &[4096, 1, 2048, 2, 10, 0, 0], 28),
        EINVAL,
    );
    t.eq(
        b"ring",
        ring_req(tx, PACKET_TX_RING, &[4096, 1, 2048, 2, 0, 0, 0], 28),
        0,
    );
    let m = map(tx, 4096, 0);
    t.ok(b"map", m > 0, m);
    if m > 0 {
        let f = m as u64;
        let mut b = [0u8; 128];
        let fr = test_frame(&mut b, 0x99, 64);
        for (i, x) in fr.iter().enumerate() {
            unsafe { core::ptr::write_volatile((f + 48 + i as u64) as *mut u8, *x) };
        }
        wr32(f, 0);
        wr32(f + 16, 64);
        wr32(f + 20, TP_STATUS_SEND_REQUEST);
        t.eq(b"send", send(tx, &[], 0), 64);
        t.eq(b"available", rd32(f + 20) as i64, 0);
        t.eq(b"received", rx_tag(rx, 0x99), 64);
        wr32(f + 2048, 8);
        wr32(f + 2048 + 16, 64);
        wr32(f + 2048 + 20, TP_STATUS_SEND_REQUEST);
        t.eq(b"next_offset", send(tx, &[], 0), EINVAL);
        sys_munmap(f, 4096);
    }
    close(tx);
    close(rx);
    t.done();
}

/// An 8 MiB block, past the buddy allocator's largest order: Linux
/// alloc_one_pg_vec_page falls back to vzalloc, and the ring maps and
/// fills as any
fn test_big_block(lo: i32) {
    let mut t = T::new(b"PACKET_RING_BIG_BLOCK");
    const BS: u32 = 8 << 20;
    let rx = psock(SOCK_RAW, ETH_P_TEST);
    pbind(rx, ETH_P_TEST, lo);
    setint(rx, SOL_PACKET, PACKET_VERSION, TPACKET_V2);
    t.eq(
        b"ring",
        ring_req(rx, PACKET_RX_RING, &[BS, 1, 2048, BS / 2048], 16),
        0,
    );
    let m = map(rx, BS as u64, 0);
    t.ok(b"map", m > 0, m);
    if m > 0 {
        let base = m as u64;
        let tx = psock(SOCK_RAW, 0);
        let mut buf = [0u8; 128];
        sendto_ll(
            tx,
            test_frame(&mut buf, 0x6a, 60),
            &Sll::new(ETH_P_TEST, lo),
            20,
        );
        t.ok(b"filled", wait_user(base, TPACKET_V2, 3000), 0);
        t.eq(b"tag", rd8(base + 66 + 14) as i64, 0x6a);
        // The last frame, deep in the block, is the kernel's and zeroed
        t.eq(b"last frame", rd32(base + BS as u64 - 2048) as i64, 0);
        sys_munmap(base, BS as u64);
        close(tx);
    }
    close(rx);
    t.done();
}

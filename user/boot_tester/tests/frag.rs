//! IPv4 fragmentation and reassembly over lo with a 1500-byte MTU (hk
//! and Linux): large UDP datagrams are fragmented and reassembled
//! intact by default (IP_PMTUDISC_WANT), EMSGSIZE with DF modes;
//! IP_MTU of a connected socket.

use hk_syscall::{AF_INET, SOCK_DGRAM, sys_ioctl, sys_socket};

use super::sk::*;

const SIOCSIFMTU: u64 = 0x8922;
const IP_MTU_DISCOVER: i32 = 10;
const IP_MTU: i32 = 14;
const IP_PMTUDISC_DONT: i32 = 0;
const IP_PMTUDISC_WANT: i32 = 1;
const IP_PMTUDISC_DO: i32 = 2;
const IP_PMTUDISC_PROBE: i32 = 3;

pub fn run_tests() {
    super::helpers::println(b"=== Fragmentation Tests ===");
    if set_mtu(b"lo", 1500) != 0 {
        super::helpers::skip(b"FRAG", b"cannot set lo MTU");
        return;
    }
    test_reassembly();
    test_df_modes();
    test_ip_mtu();
    set_mtu(b"lo", 65536);
}

/// SIOCSIFMTU on `name`
pub fn set_mtu(name: &[u8], mtu: i32) -> i64 {
    let mut ifr = [0u8; 40];
    ifr[..name.len()].copy_from_slice(name);
    ifr[16..20].copy_from_slice(&mtu.to_ne_bytes());
    let fd = sys_socket(AF_INET, SOCK_DGRAM, 0);
    let r = sys_ioctl(fd as i32, SIOCSIFMTU, ifr.as_mut_ptr() as u64);
    close(fd as i32);
    r
}

fn pattern(buf: &mut [u8], seed: u8) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(seed);
    }
}

/// 8 KB and the largest datagram (65507) arrive intact through lo
fn test_reassembly() {
    let mut t = T::new(b"FRAG_REASSEMBLY");
    let (a, _) = udp_lo();
    let (b, pb) = udp_lo();
    setint(b, SOL_SOCKET, SO_RCVBUF, 1 << 20);
    let mut out = [0u8; 65507];
    let mut inb = [0u8; 65536];
    for (len, seed) in [(8192usize, 3u8), (1473, 5), (65507, 9)] {
        pattern(&mut out[..len], seed);
        t.eq(b"send", send_to(a, &out[..len], LO, pb, 0), len as i64);
        let n = recv(b, &mut inb, MSG_DONTWAIT);
        t.ok(b"recv len", n == len as i64, n);
        t.ok(b"intact", n > 0 && inb[..len] == out[..len], len as i64);
    }
    close(a);
    close(b);
    t.done();
}

/// IP_MTU_DISCOVER: DO and PROBE refuse datagrams beyond the MTU with
/// EMSGSIZE; WANT (default) and DONT fragment them
fn test_df_modes() {
    let mut t = T::new(b"FRAG_DF");
    let (a, _) = udp_lo();
    let (b, pb) = udp_lo();
    let data = [0x5au8; 2000];
    let mut inb = [0u8; 4096];
    t.eq(
        b"default",
        getint(a, SOL_IP, IP_MTU_DISCOVER).1 as i64,
        IP_PMTUDISC_WANT as i64,
    );
    for (mode, want) in [
        (IP_PMTUDISC_DO, EMSGSIZE),
        (IP_PMTUDISC_PROBE, EMSGSIZE),
        (IP_PMTUDISC_DONT, 2000),
        (IP_PMTUDISC_WANT, 2000),
    ] {
        setint(a, SOL_IP, IP_MTU_DISCOVER, mode);
        t.eq(b"send", send_to(a, &data, LO, pb, 0), want);
        if want > 0 {
            t.eq(b"recv", recv(b, &mut inb, MSG_DONTWAIT), want);
        }
    }
    // A datagram that fits goes out even with DO
    setint(a, SOL_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO);
    t.eq(b"fits", send_to(a, &data[..1400], LO, pb, 0), 1400);
    t.eq(b"recv fits", recv(b, &mut inb, MSG_DONTWAIT), 1400);
    t.eq(b"bad mode", setint(a, SOL_IP, IP_MTU_DISCOVER, 6), EINVAL);
    close(a);
    close(b);
    t.done();
}

/// IP_MTU: the path MTU of a connected socket, ENOTCONN otherwise
fn test_ip_mtu() {
    let mut t = T::new(b"FRAG_IP_MTU");
    let (a, _) = udp_lo();
    t.eq(b"unconnected", getint(a, SOL_IP, IP_MTU).0, ENOTCONN);
    let (b, pb) = udp_lo();
    connect(a, LO, pb);
    let (r, v) = getint(a, SOL_IP, IP_MTU);
    t.ok(b"connected", r == 0 && v == 1500, v as i64);
    close(a);
    close(b);
    t.done();
}

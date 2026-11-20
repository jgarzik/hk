//! UDP memory accounting (hk and Linux: udp_memory_allocated,
//! udp_mem, __udp_enqueue_schedule_skb, udp_rmem_release).
//!
//! - UDP_MEM_SYSCTL: /proc/sys/net/ipv4/udp_mem holds three page counts
//!   sized from RAM as udp_init (min = 3/4 of pressure, max = twice
//!   min) and refuses negative values; udp_rmem_min and udp_wmem_min
//!   are a page.
//! - UDP_MEM_SOCKSTAT: datagrams queued on lo raise /proc/net/sockstat's
//!   "UDP: mem" by about their pages; reading them gives the pages
//!   back. The count lags by each CPU's reserve (net.core.mem_pcpu_rsv,
//!   256 pages), so the margins allow it.

use crate::harness::T;
use crate::helpers::msleep;
use crate::net::sk::*;
use crate::proc::sysctl::{read_file, write_file};

const PATH: &[u8] = b"/proc/sys/net/ipv4/udp_mem\0";
const SOCKS: usize = 4;
const PER_SOCK: usize = 60;
const DGRAM: usize = 60000;
/// Pages the queued datagrams must move the count by (they hold some
/// 3500; each CPU's reserve may hide up to 255)
const MARGIN: i64 = 1024;

pub fn run_tests() {
    crate::helpers::println(b"=== UDP memory Tests ===");
    test_sysctl();
    test_sockstat();
}

/// The numbers of a read, separated by tabs or spaces
fn nums<const N: usize>(b: &[u8]) -> Option<[i64; N]> {
    let mut v = [0i64; N];
    let mut it = b
        .split(|&c| c == b'\t' || c == b' ' || c == b'\n')
        .filter(|w| !w.is_empty());
    for x in v.iter_mut() {
        let f = it.next()?;
        if !f.iter().all(u8::is_ascii_digit) {
            return None;
        }
        *x = f.iter().fold(0, |a, &d| a * 10 + i64::from(d - b'0'));
    }
    it.next().is_none().then_some(v)
}

fn read_nums<const N: usize>(path: &[u8]) -> Option<[i64; N]> {
    let mut buf = [0u8; 96];
    let n = read_file(path, &mut buf);
    nums(&buf[..n.max(0) as usize])
}

fn test_sysctl() {
    let mut t = T::new(b"UDP_MEM_SYSCTL");
    match read_nums::<3>(PATH) {
        Some([a, b, c]) => {
            t.ok(b"min < pressure", a < b, a);
            t.ok(b"max = 2 min", c == 2 * a, c);
            t.ok(b"pressure >= 128", b >= 128, b);
            t.eq(b"negative", write_file(PATH, b"-1 200 300\n"), EINVAL);
            t.ok(b"unchanged", read_nums::<3>(PATH) == Some([a, b, c]), 0);
        }
        None => {
            t.ok(b"format", false, 0);
        }
    }
    let r = read_nums::<1>(b"/proc/sys/net/ipv4/udp_rmem_min\0");
    t.ok(b"udp_rmem_min", r == Some([4096]), r.map_or(-1, |v| v[0]));
    let w = read_nums::<1>(b"/proc/sys/net/ipv4/udp_wmem_min\0");
    t.ok(b"udp_wmem_min", w == Some([4096]), w.map_or(-1, |v| v[0]));
    t.done();
}

/// "UDP: inuse N mem M" of /proc/net/sockstat: M
fn udp_mem() -> i64 {
    let mut buf = [0u8; 1024];
    let n = crate::helpers::read_file(b"/proc/net/sockstat\0", &mut buf);
    let Some(line) = buf[..n.max(0) as usize]
        .split(|&b| b == b'\n')
        .find(|l| l.starts_with(b"UDP: "))
    else {
        return -1;
    };
    let mut w = line.split(|&b| b == b' ').filter(|w| !w.is_empty());
    while let Some(k) = w.next() {
        if k == b"mem" {
            return w.next().and_then(|v| nums::<1>(v)).map_or(-1, |v| v[0]);
        }
    }
    -1
}

/// The count once it is at least `want` (up to ~2 s: lo delivers
/// through the backlog), or as it then is
fn udp_mem_at_least(want: i64) -> i64 {
    for _ in 0..200 {
        let m = udp_mem();
        if m >= want {
            return m;
        }
        msleep(10);
    }
    udp_mem()
}

fn test_sockstat() {
    let mut t = T::new(b"UDP_MEM_SOCKSTAT");
    let before = udp_mem();
    t.ok(b"read", before >= 0, before);
    let mut rx = [-1i32; SOCKS];
    for fd in rx.iter_mut() {
        let (s, _) = udp_lo();
        t.eq(b"rcvbuf", setint(s, SOL_SOCKET, SO_RCVBUFFORCE, 4 << 20), 0);
        *fd = s;
    }
    let tx = udp();
    let data = [0x5au8; DGRAM];
    for &s in &rx {
        let p = port(s);
        for _ in 0..PER_SOCK {
            send_to(tx, &data, LO, p, 0);
        }
    }
    let during = udp_mem_at_least(before + MARGIN);
    t.ok(b"queued raises", during >= before + MARGIN, during - before);
    let mut buf = [0u8; DGRAM];
    let mut got = 0;
    for &s in &rx {
        for _ in 0..PER_SOCK {
            if poll1(s, 1, 1000).0 == 1 && recv(s, &mut buf, MSG_DONTWAIT) == DGRAM as i64 {
                got += 1;
            }
        }
    }
    t.eq(b"all read", got, (SOCKS * PER_SOCK) as i64);
    let after = udp_mem();
    t.ok(b"read releases", after <= during - MARGIN, during - after);
    for s in rx {
        close(s);
    }
    close(tx);
    t.done();
}

//! ICMP timestamp requests (hk and Linux), in a new network namespace
//! with lo up so no other traffic moves the counters:
//!
//! - ICMP_TS: a raw ICMP socket's timestamp request to 127.0.0.1 is
//!   answered with a 20-byte type 14 reply carrying the request's id,
//!   sequence and originate time, and receive == transmit time in ms
//!   since midnight UTC (big-endian), within a clock_gettime window;
//!   data past the originate time is not echoed
//! - ICMP_TS_SHORT: a request with under 4 bytes past the header gets
//!   no reply and counts Icmp InErrors
//! - ICMP_TS_SNMP: Icmp InTimestamps / IcmpMsg InType13 and
//!   OutTimestamps count both requests, InErrors the short one; the
//!   reply counts as Linux counts it, as an echo reply (OutEchoReps,
//!   OutType0; not OutTimestampReps, OutType14)

use hk_syscall::{
    AF_INET, CLOCK_REALTIME, CLONE_NEWNET, SOCK_RAW, Timespec, sys_clock_gettime, sys_exit,
    sys_fork, sys_socket, sys_unshare,
};

use crate::harness::{T, fail_num, pass};
use crate::helpers::{host_mode, loopback_up, println, skip};
use crate::net::icmp::recv_wait;
use crate::net::raw::csum;
use crate::net::sk::*;
use crate::net::snmp::{Mib, SNMP};
use crate::net::tcp_xfer::wait_child;

const IPPROTO_ICMP: i32 = 1;
const TIMESTAMP: u8 = 13;
const TIMESTAMPREPLY: u8 = 14;
const ID: u16 = 0x7473;
const ORIG: u32 = 0x0123_4567;
const DAY_MS: i64 = 86_400_000;

pub fn run_tests() {
    println(b"=== ICMP Timestamp Tests ===");
    let pid = sys_fork();
    if pid < 0 {
        fail_num(b"ICMP_TS_NETNS:FAIL fork", pid);
        return;
    }
    if pid == 0 {
        if sys_unshare(CLONE_NEWNET) != 0 {
            sys_exit(2);
        }
        loopback_up();
        sys_exit(if netns_tests() { 0 } else { 1 });
    }
    let st = wait_child(pid);
    let code = (st >> 8) & 0xff;
    if st & 0x7f == 0 && code == 0 {
        pass(b"ICMP_TS_NETNS");
    } else if code == 2 && host_mode() {
        skip(b"ICMP_TS_NETNS", b"unshare(CLONE_NEWNET) not permitted");
    } else {
        fail_num(b"ICMP_TS_NETNS:FAIL status=", st as i64);
    }
}

/// The tests proper, in the new namespace; do all pass?
fn netns_tests() -> bool {
    let Some(before) = Mib::read(SNMP) else {
        println(b"ICMP_TS_SNMP:FAIL read");
        return false;
    };
    let fd = sys_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) as i32;
    if fd < 0 {
        fail_num(b"ICMP_TS:FAIL socket", fd as i64);
        return false;
    }
    let ok = test_reply(fd) & test_short(fd);
    close(fd);
    ok & test_snmp(&before)
}

/// CLOCK_REALTIME now, in ms since midnight UTC
fn now_ms() -> i64 {
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    sys_clock_gettime(CLOCK_REALTIME, &mut ts);
    (ts.tv_sec * 1000 + ts.tv_nsec / 1_000_000).rem_euclid(DAY_MS)
}

/// A timestamp request of `len` bytes (8-byte header, originate time,
/// zeroed receive/transmit times, extra zeroes), checksummed
fn ts_req(out: &mut [u8], seq: u16, len: usize) -> usize {
    out[..len].fill(0);
    out[0] = TIMESTAMP;
    out[4..6].copy_from_slice(&ID.to_be_bytes());
    out[6..8].copy_from_slice(&seq.to_be_bytes());
    let o = ORIG.to_be_bytes();
    let n = o.len().min(len.saturating_sub(8));
    out[8..8 + n].copy_from_slice(&o[..n]);
    let c = csum(&out[..len]);
    out[2..4].copy_from_slice(&c.to_be_bytes());
    len
}

/// Wait for a timestamp reply to sequence `seq` on `fd`, copying its
/// ICMP part to `out`; its length, or 0 if none came
fn ts_reply(fd: i32, seq: u16, out: &mut [u8]) -> usize {
    let mut buf = [0u8; 256];
    for _ in 0..8 {
        let (n, ip) = recv_wait(fd, &mut buf, 1000);
        if n < 28 {
            return 0;
        }
        let ihl = ((buf[0] & 0xf) * 4) as usize;
        let m = &buf[ihl..n as usize];
        let id = u16::from_be_bytes([m[4], m[5]]);
        let sq = u16::from_be_bytes([m[6], m[7]]);
        if ip == LO && m[0] == TIMESTAMPREPLY && id == ID && sq == seq {
            out[..m.len()].copy_from_slice(m);
            return m.len();
        }
    }
    0
}

/// Field `i` (0 originate, 1 receive, 2 transmit) of a timestamp message
fn field(m: &[u8], i: usize) -> u32 {
    let o = 8 + 4 * i;
    u32::from_be_bytes([m[o], m[o + 1], m[o + 2], m[o + 3]])
}

/// The reply: type 14 code 0, valid checksum, 20 bytes for a longer
/// request, originate echoed, receive == transmit within [t0, t1]
fn test_reply(fd: i32) -> bool {
    let mut t = T::new(b"ICMP_TS");
    let mut req = [0u8; 32];
    let n = ts_req(&mut req, 1, 28);
    let t0 = now_ms();
    t.eq(b"sendto", send_to(fd, &req[..n], LO, 0, 0), n as i64);
    let mut m = [0u8; 256];
    let len = ts_reply(fd, 1, &mut m);
    let t1 = now_ms();
    if !t.ok(b"no reply", len != 0, 0) {
        return false;
    }
    let m = &m[..len];
    t.eq(b"length", len as i64, 20);
    t.eq(b"code", m[1] as i64, 0);
    t.eq(b"checksum", csum(m) as i64, 0);
    t.eq(b"originate", field(m, 0) as i64, ORIG as i64);
    let (rx, tx) = (field(m, 1) as i64, field(m, 2) as i64);
    t.eq(b"transmit != receive", tx, rx);
    t.ok(b"receive out of day", rx < DAY_MS, rx);
    // Within the clock_gettime window (1 s slack each way, midnight
    // wrap allowed)
    let span = (t1 - t0).rem_euclid(DAY_MS);
    let off = (rx - t0 + 1000).rem_euclid(DAY_MS);
    t.ok(b"receive outside window", off <= span + 2000, rx - t0);
    let ok = !t.failed();
    t.done();
    ok
}

/// Under 4 bytes past the header: no reply
fn test_short(fd: i32) -> bool {
    let mut t = T::new(b"ICMP_TS_SHORT");
    let mut req = [0u8; 16];
    let n = ts_req(&mut req, 2, 11);
    t.eq(b"sendto", send_to(fd, &req[..n], LO, 0, 0), n as i64);
    let mut m = [0u8; 256];
    t.eq(b"reply", ts_reply(fd, 2, &mut m) as i64, 0);
    let ok = !t.failed();
    t.done();
    ok
}

/// Both requests in, one reply out, the short one an input error
fn test_snmp(a: &Mib) -> bool {
    let mut t = T::new(b"ICMP_TS_SNMP");
    let Some(b) = Mib::read(SNMP) else {
        t.ok(b"read", false, 0);
        return false;
    };
    let d = |tag: &[u8], f: &[u8]| b.val(tag, f) - a.val(tag, f);
    t.eq(b"InTimestamps", d(b"Icmp", b"InTimestamps"), 2);
    t.eq(b"OutTimestamps", d(b"Icmp", b"OutTimestamps"), 2);
    // Linux icmp_reply counts every reply as an echo reply (BUGS.md)
    t.eq(b"OutEchoReps", d(b"Icmp", b"OutEchoReps"), 1);
    t.eq(b"OutTimestampReps", d(b"Icmp", b"OutTimestampReps"), 0);
    t.eq(b"InTimestampReps", d(b"Icmp", b"InTimestampReps"), 1);
    t.eq(b"InErrors", d(b"Icmp", b"InErrors"), 1);
    t.eq(b"InType13", d(b"IcmpMsg", b"InType13"), 2);
    t.eq(b"OutType0", d(b"IcmpMsg", b"OutType0"), 1);
    t.eq(b"OutType14", d(b"IcmpMsg", b"OutType14"), 0);
    let ok = !t.failed();
    t.done();
    ok
}

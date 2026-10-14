//! /proc/sys/net (hk and Linux): defaults, writes with validation,
//! wiring (ip_local_port_range -> ephemeral ports, somaxconn), and
//! permissions (non-root cannot open for writing).

use hk_syscall::{
    sys_close, sys_exit, sys_fork, sys_open, sys_read, sys_setresuid, sys_wait4, sys_write,
    O_RDONLY, O_WRONLY,
};

use super::sk::*;

pub fn run_tests() {
    super::helpers::println(b"=== Sysctl Tests ===");
    test_defaults();
    test_port_range();
    test_validation();
    test_perm();
}

/// Read a NUL-terminated path into `buf`; returns the length or -errno
pub fn read_file(path: &[u8], buf: &mut [u8]) -> i64 {
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        return fd;
    }
    let mut n = 0usize;
    loop {
        let r = sys_read(fd as u64, buf[n..].as_mut_ptr(), (buf.len() - n) as u64);
        if r <= 0 {
            break;
        }
        n += r as usize;
        if n == buf.len() {
            break;
        }
    }
    sys_close(fd as u64);
    n as i64
}

/// Write `val` to a /proc/sys file; the write's result or open's error
pub fn write_file(path: &[u8], val: &[u8]) -> i64 {
    let fd = sys_open(path.as_ptr(), O_WRONLY, 0);
    if fd < 0 {
        return fd;
    }
    let r = sys_write(fd as u64, val.as_ptr(), val.len() as u64);
    sys_close(fd as u64);
    r
}

/// Does the file read exactly `want`?
pub fn reads(path: &[u8], want: &[u8]) -> bool {
    let mut buf = [0u8; 128];
    let n = read_file(path, &mut buf);
    n >= 0 && &buf[..n as usize] == want
}

const PING: &[u8] = b"/proc/sys/net/ipv4/ping_group_range\0";
const PORTS: &[u8] = b"/proc/sys/net/ipv4/ip_local_port_range\0";
const SYN: &[u8] = b"/proc/sys/net/ipv4/tcp_syn_retries\0";
const SOMAX: &[u8] = b"/proc/sys/net/core/somaxconn\0";

/// Linux defaults
fn test_defaults() {
    let mut t = T::new(b"SYSCTL_DEFAULTS");
    let want: [(&[u8], &[u8]); 12] = [
        (PING, b"1\t0\n"),
        (PORTS, b"32768\t60999\n"),
        (b"/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts\0", b"1\n"),
        (b"/proc/sys/net/ipv4/icmp_echo_ignore_all\0", b"0\n"),
        (b"/proc/sys/net/ipv4/icmp_ratelimit\0", b"1000\n"),
        (b"/proc/sys/net/ipv4/icmp_ratemask\0", b"6168\n"),
        (SYN, b"6\n"),
        (b"/proc/sys/net/ipv4/ip_forward\0", b"0\n"),
        (b"/proc/sys/net/ipv4/ipfrag_high_thresh\0", b"4194304\n"),
        (b"/proc/sys/net/ipv4/ipfrag_low_thresh\0", b"3145728\n"),
        (b"/proc/sys/net/ipv4/ipfrag_time\0", b"30\n"),
        (SOMAX, b"4096\n"),
    ];
    for (i, (p, v)) in want.iter().enumerate() {
        t.ok(b"value", reads(p, v), i as i64);
    }
    t.done();
}

/// ip_local_port_range bounds the ephemeral ports of UDP and TCP
fn test_port_range() {
    let mut t = T::new(b"SYSCTL_PORT_RANGE");
    t.eq(b"write", write_file(PORTS, b"40000 40003\n"), 12);
    t.ok(b"read back", reads(PORTS, b"40000\t40003\n"), 0);
    let mut fds = [-1i32; 4];
    for f in fds.iter_mut() {
        *f = udp();
        let r = bind(*f, LO, 0);
        let p = port(*f);
        t.ok(b"udp port in range", r == 0 && (40000..=40003).contains(&p), p as i64);
    }
    // The range is exhausted for a fifth socket on the same address
    let x = udp();
    t.eq(b"exhausted", bind(x, LO, 0), EADDRINUSE);
    close(x);
    for f in fds {
        close(f);
    }
    let c = tcp();
    t.eq(b"tcp bind", bind(c, LO, 0), 0);
    let p = port(c);
    t.ok(b"tcp port in range", (40000..=40003).contains(&p), p as i64);
    close(c);
    t.eq(b"restore", write_file(PORTS, b"32768 60999"), 11);
    t.done();
}

/// Out-of-range and malformed values are EINVAL; an inverted ping
/// range means nobody
fn test_validation() {
    let mut t = T::new(b"SYSCTL_VALIDATE");
    t.eq(b"privileged low", write_file(PORTS, b"1000 2000"), EINVAL);
    t.eq(b"inverted", write_file(PORTS, b"5000 4000"), EINVAL);
    t.eq(b"too big", write_file(PORTS, b"5000 70000"), EINVAL);
    t.eq(b"garbage", write_file(PORTS, b"abc"), EINVAL);
    t.ok(b"unchanged", reads(PORTS, b"32768\t60999\n"), 0);
    t.eq(b"syn 0", write_file(SYN, b"0"), EINVAL);
    t.eq(b"syn 200", write_file(SYN, b"200"), EINVAL);
    t.eq(b"syn 3", write_file(SYN, b"3"), 1);
    t.ok(b"syn read", reads(SYN, b"3\n"), 0);
    write_file(SYN, b"6");
    t.eq(b"ping inverted", write_file(PING, b"5 2"), 3);
    t.ok(b"ping nobody", reads(PING, b"1\t0\n"), 0);
    t.eq(b"ping range", write_file(PING, b"100 200"), 7);
    t.ok(b"ping read", reads(PING, b"100\t200\n"), 0);
    write_file(PING, b"1 0");
    t.eq(b"somaxconn", write_file(SOMAX, b"16"), 2);
    t.ok(b"somaxconn read", reads(SOMAX, b"16\n"), 0);
    write_file(SOMAX, b"4096");
    t.done();
}

/// Non-root cannot open a sysctl for writing (EACCES) but can read it
fn test_perm() {
    let mut t = T::new(b"SYSCTL_PERM");
    let pid = sys_fork();
    if pid == 0 {
        if sys_setresuid(65534, 65534, 65534) != 0 {
            sys_exit(90);
        }
        let w = sys_open(PORTS.as_ptr(), O_WRONLY, 0);
        if w != EACCES {
            sys_exit(1);
        }
        if !reads(PORTS, b"32768\t60999\n") {
            sys_exit(2);
        }
        sys_exit(0);
    }
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    t.eq(b"child", st as i64, 0);
    t.done();
}

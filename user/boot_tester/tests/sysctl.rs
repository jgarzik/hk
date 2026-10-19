//! /proc/sys/net (hk and Linux): defaults, writes with validation,
//! wiring (ip_local_port_range -> ephemeral ports, somaxconn), and
//! permissions (non-root cannot open for writing).

use hk_syscall::{
    _LINUX_CAPABILITY_VERSION_3, CapUserData, CapUserHeader, O_RDONLY, O_WRONLY, PR_SET_KEEPCAPS,
    sys_capget, sys_capset, sys_close, sys_exit, sys_fork, sys_open, sys_prctl, sys_read,
    sys_setresuid, sys_wait4, sys_write,
};

use super::sk::*;

pub fn run_tests() {
    super::helpers::println(b"=== Sysctl Tests ===");
    test_defaults();
    test_port_range();
    test_validation();
    test_perm();
    test_perm_net_admin();
    test_proc_net_udp();
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
    let want: [(&[u8], &[u8]); 15] = [
        (PING, b"1\t0\n"),
        (PORTS, b"32768\t60999\n"),
        (b"/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts\0", b"1\n"),
        (b"/proc/sys/net/ipv4/icmp_echo_ignore_all\0", b"0\n"),
        (b"/proc/sys/net/ipv4/icmp_ratelimit\0", b"1000\n"),
        (b"/proc/sys/net/ipv4/icmp_ratemask\0", b"6168\n"),
        (SYN, b"6\n"),
        (b"/proc/sys/net/ipv4/tcp_synack_retries\0", b"5\n"),
        (b"/proc/sys/net/ipv4/tcp_retries2\0", b"15\n"),
        (b"/proc/sys/net/ipv4/tcp_fin_timeout\0", b"60\n"),
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
        t.ok(
            b"udp port in range",
            r == 0 && (40000..=40003).contains(&p),
            p as i64,
        );
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

/// Non-root with only CAP_NET_ADMIN may write network sysctls, not vm
/// ones such as min_free_kbytes (Linux net_ctl_permissions vs
/// test_perm)
fn test_perm_net_admin() {
    const MIN_FREE: &[u8] = b"/proc/sys/vm/min_free_kbytes\0";
    const CAP_NET_ADMIN: u32 = 12;
    let mut t = T::new(b"SYSCTL_PERM_NET_ADMIN");
    let pid = sys_fork();
    if pid == 0 {
        if sys_prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0 || sys_setresuid(65534, 65534, 65534) != 0 {
            sys_exit(90);
        }
        let mut h = CapUserHeader {
            version: _LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let mut d: [CapUserData; 2] = unsafe { core::mem::zeroed() };
        if sys_capget(&mut h, d.as_mut_ptr()) != 0 {
            sys_exit(91);
        }
        d[0].effective = 1 << CAP_NET_ADMIN;
        d[1].effective = 0;
        if sys_capset(&h, d.as_ptr()) != 0 {
            sys_exit(92);
        }
        let w = sys_open(MIN_FREE.as_ptr(), O_WRONLY, 0);
        if w != EACCES {
            sys_exit(1);
        }
        let w = sys_open(PORTS.as_ptr(), O_WRONLY, 0);
        if w < 0 {
            sys_exit(2);
        }
        sys_close(w as u64);
        sys_exit(0);
    }
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    t.eq(b"child", st as i64, 0);
    t.done();
}

/// Upper-case hex of `v` in `w` digits
fn hex(v: u64, w: usize, out: &mut [u8]) {
    for i in 0..w {
        let d = ((v >> (4 * (w - 1 - i))) & 0xf) as u8;
        out[i] = if d < 10 { b'0' + d } else { b'A' + d - 10 };
    }
}

/// Decimal text of `v`
fn dec(mut v: u64, out: &mut [u8; 20]) -> usize {
    let mut tmp = [0u8; 20];
    let mut n = 0;
    loop {
        tmp[n] = b'0' + (v % 10) as u8;
        n += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for i in 0..n {
        out[i] = tmp[n - 1 - i];
    }
    n
}

/// /proc/net/udp lists a bound socket: local 127.0.0.1:port, state 07
/// (unconnected) or 01 with the peer, its inode
fn test_proc_net_udp() {
    use hk_syscall::{Stat, sys_fstat};
    let mut t = T::new(b"PROC_NET_UDP");
    let (a, pa) = udp_lo();
    let (b, pb) = udp_lo();
    connect(b, LO, pa);
    let mut st: Stat = unsafe { core::mem::zeroed() };
    sys_fstat(a, &mut st);
    let mut buf = [0u8; 8192];
    let n = read_file(b"/proc/net/udp\0", &mut buf);
    let text = &buf[..n.max(0) as usize];
    t.ok(
        b"header",
        text.starts_with(b"   sl  local_address rem_address   st tx_queue rx_queue"),
        n,
    );
    let find = |port: u16| {
        let mut key = *b"0100007F:0000";
        hex(port as u64, 4, &mut key[9..]);
        text.split(|&c| c == b'\n')
            .find(|l| l.len() > 20 && &l[7..20] == &key[..])
    };
    let la = find(pa);
    t.ok(b"a listed", la.is_some(), pa as i64);
    if let Some(l) = la {
        t.ok(
            b"a unconnected",
            &l[21..34] == b"00000000:0000" && &l[35..37] == b"07",
            0,
        );
        let mut d = [0u8; 20];
        let k = dec(st.st_ino, &mut d);
        let has = l
            .windows(k + 2)
            .any(|w| w[0] == b' ' && &w[1..k + 1] == &d[..k] && w[k + 1] == b' ');
        t.ok(b"inode", has, st.st_ino as i64);
        t.eq(b"width", l.len() as i64, 127);
    }
    let lb = find(pb);
    t.ok(b"b listed", lb.is_some(), pb as i64);
    if let Some(l) = lb {
        let mut rem = *b"0100007F:0000";
        hex(pa as u64, 4, &mut rem[9..]);
        t.ok(
            b"b connected",
            &l[21..34] == &rem[..] && &l[35..37] == b"01",
            0,
        );
    }
    close(a);
    close(b);
    let n = read_file(b"/proc/net/udp\0", &mut buf);
    let text = &buf[..n.max(0) as usize];
    let mut key = *b"0100007F:0000";
    hex(pa as u64, 4, &mut key[9..]);
    let gone = !text.windows(13).any(|w| w == &key[..]);
    t.ok(b"gone after close", gone, 0);
    t.done();
}

//! Per-device network sysctls (hk and Linux): the neighbour parameters
//! of net/ipv4/neigh/{default,<dev>} (Linux neigh_sysctl_register:
//! units, inheritance of "default" until a device's own value is
//! written, unres_qlen in packets, default-only GC knobs) and the
//! IPv4 device configuration of net/ipv4/conf/{all,default,<dev>}
//! (Linux devinet_sysctl: defaults, the same inheritance, forwarding
//! carried from "all" to every device and to ip_forward, attributes
//! "default" does not carry), and what a new namespace has of both.

use hk_syscall::{
    CLONE_NEWNET, O_RDONLY, sys_close, sys_exit, sys_fork, sys_open, sys_unshare, sys_wait4,
};

use crate::harness::T;
use crate::net::sk::EINVAL;
use crate::proc::sysctl::{read_file, reads, write_file};

const ENOENT: i64 = -2;

pub fn run_tests() {
    crate::helpers::println(b"=== Per-device sysctl Tests ===");
    if crate::net::nl::net_setup_eth0().is_err() {
        crate::helpers::skip(b"NEIGH_SYSCTL", b"no eth0");
        return;
    }
    test_neigh_defaults();
    test_neigh_inherit();
    test_neigh_units();
    test_conf_defaults();
    test_conf_inherit();
    test_conf_forwarding();
    test_netns();
}

/// A NUL-terminated /proc/sys/net/ipv4/<sub>/<dir>/<name> path
fn path(buf: &mut [u8; 96], sub: &[u8], dir: &[u8], name: &[u8]) -> usize {
    let mut n = 0;
    for part in [b"/proc/sys/net/ipv4/" as &[u8], sub, b"/", dir, b"/", name] {
        buf[n..n + part.len()].copy_from_slice(part);
        n += part.len();
    }
    buf[n] = 0;
    n + 1
}

fn neigh(dir: &[u8], name: &[u8]) -> [u8; 96] {
    let mut b = [0u8; 96];
    path(&mut b, b"neigh", dir, name);
    b
}

fn conf(dir: &[u8], name: &[u8]) -> [u8; 96] {
    let mut b = [0u8; 96];
    path(&mut b, b"conf", dir, name);
    b
}

/// The integer a sysctl file reads, or the error
fn val(p: &[u8]) -> i64 {
    let mut buf = [0u8; 32];
    let n = read_file(p, &mut buf);
    if n <= 0 {
        return if n < 0 { n } else { -1000 };
    }
    let mut v = 0i64;
    let mut neg = false;
    for &c in &buf[..n as usize] {
        match c {
            b'-' => neg = true,
            b'0'..=b'9' => v = v * 10 + i64::from(c - b'0'),
            _ => break,
        }
    }
    if neg { -v } else { v }
}

/// Write a decimal value; the write's result
fn put(p: &[u8], v: i64) -> i64 {
    let mut b = [0u8; 24];
    let mut n = 0;
    let mut x = v.unsigned_abs();
    let mut digits = [0u8; 20];
    let mut d = 0;
    loop {
        digits[d] = b'0' + (x % 10) as u8;
        d += 1;
        x /= 10;
        if x == 0 {
            break;
        }
    }
    if v < 0 {
        b[n] = b'-';
        n += 1;
    }
    while d > 0 {
        d -= 1;
        b[n] = digits[d];
        n += 1;
    }
    write_file(p, &b[..n])
}

/// Linux arp_tbl defaults, in the handlers' units
fn test_neigh_defaults() {
    let mut t = T::new(b"NEIGH_SYSCTL_DEFAULTS");
    let want: [(&[u8], i64); 15] = [
        (b"mcast_solicit", 3),
        (b"ucast_solicit", 3),
        (b"app_solicit", 0),
        (b"mcast_resolicit", 0),
        (b"retrans_time", 100),
        (b"retrans_time_ms", 1000),
        (b"base_reachable_time", 30),
        (b"base_reachable_time_ms", 30000),
        (b"delay_first_probe_time", 5),
        (b"gc_stale_time", 60),
        (b"proxy_qlen", 64),
        (b"proxy_delay", 80),
        (b"anycast_delay", 100),
        (b"locktime", 100),
        (b"interval_probe_time_ms", 5000),
    ];
    for (name, v) in want {
        t.eq(b"default", val(&neigh(b"default", name)), v);
        t.eq(b"eth0", val(&neigh(b"eth0", name)), v);
        t.eq(b"lo", val(&neigh(b"lo", name)), v);
    }
    for (name, v) in [
        (b"gc_thresh1" as &[u8], 128),
        (b"gc_thresh2", 512),
        (b"gc_thresh3", 1024),
        (b"gc_interval", 30),
    ] {
        t.eq(b"gc", val(&neigh(b"default", name)), v);
        // A device's table stops before them
        t.eq(b"dev gc", val(&neigh(b"eth0", name)), ENOENT);
    }
    t.ok(
        b"no all",
        val(&neigh(b"all", b"ucast_solicit")) == ENOENT,
        0,
    );
    t.done();
}

/// A device inherits "default" until its own value is written (Linux
/// data_state, neigh_copy_dflt_parms)
fn test_neigh_inherit() {
    let mut t = T::new(b"NEIGH_SYSCTL_INHERIT");
    let (d, e, l) = (
        neigh(b"default", b"ucast_solicit"),
        neigh(b"eth0", b"ucast_solicit"),
        neigh(b"lo", b"ucast_solicit"),
    );
    t.eq(b"own", put(&e, 7), 1);
    t.eq(b"own read", val(&e), 7);
    t.eq(b"default kept", val(&d), 3);
    t.eq(b"dflt", put(&d, 5), 1);
    t.eq(b"lo inherits", val(&l), 5);
    t.eq(b"eth0 keeps", val(&e), 7);
    t.eq(b"restore", put(&d, 3), 1);
    t.eq(b"lo back", val(&l), 3);
    t.eq(b"eth0 restore", put(&e, 3), 1);
    t.done();
}

/// Units and bounds: ms and seconds of one value, USER_HZ ticks,
/// unres_qlen in packets of unres_qlen_bytes, EINVAL outside
fn test_neigh_units() {
    let mut t = T::new(b"NEIGH_SYSCTL_UNITS");
    let (s, ms) = (
        neigh(b"eth0", b"base_reachable_time"),
        neigh(b"eth0", b"base_reachable_time_ms"),
    );
    t.eq(b"ms", put(&ms, 12000), 5);
    t.eq(b"secs", val(&s), 12);
    t.eq(b"secs write", put(&s, 30), 2);
    t.eq(b"ms back", val(&ms), 30000);
    let (rt, rtms) = (
        neigh(b"eth0", b"retrans_time"),
        neigh(b"eth0", b"retrans_time_ms"),
    );
    t.eq(b"retrans ms", put(&rtms, 2000), 4);
    t.eq(b"retrans ticks", val(&rt), 200);
    t.eq(b"retrans restore", put(&rt, 100), 3);
    t.eq(b"retrans ms back", val(&rtms), 1000);
    let (q, qb) = (
        neigh(b"eth0", b"unres_qlen"),
        neigh(b"eth0", b"unres_qlen_bytes"),
    );
    let bytes = val(&qb);
    t.ok(b"qlen bytes", bytes > 0, bytes);
    t.eq(b"qlen", put(&q, 5), 1);
    t.eq(b"qlen read", val(&q), 5);
    let b5 = val(&qb);
    t.ok(b"qlen in bytes", b5 > 0 && b5 % 5 == 0, b5);
    t.ok(b"qlen restore", put(&qb, bytes) > 0, 0);
    t.eq(b"qlen bytes back", val(&qb), bytes);
    t.eq(b"neg", put(&neigh(b"eth0", b"ucast_solicit"), -1), EINVAL);
    t.eq(
        b"thresh neg",
        put(&neigh(b"default", b"gc_thresh1"), -1),
        EINVAL,
    );
    t.eq(
        b"interval 0",
        put(&neigh(b"eth0", b"interval_probe_time_ms"), 0),
        EINVAL,
    );
    t.done();
}

/// Linux ipv4_devconf / ipv4_devconf_dflt; a device copies "default"
fn test_conf_defaults() {
    let mut t = T::new(b"CONF_SYSCTL_DEFAULTS");
    let want: [(&[u8], i64, i64); 10] = [
        (b"forwarding", 0, 0),
        (b"accept_redirects", 1, 1),
        (b"send_redirects", 1, 1),
        (b"secure_redirects", 1, 1),
        (b"shared_media", 1, 1),
        (b"accept_source_route", 0, 1),
        (b"rp_filter", 0, 0),
        (b"proxy_arp", 0, 0),
        (b"arp_evict_nocarrier", 1, 1),
        (b"igmpv2_unsolicited_report_interval", 10000, 10000),
    ];
    for (name, all, dflt) in want {
        t.eq(b"all", val(&conf(b"all", name)), all);
        t.eq(b"default", val(&conf(b"default", name)), dflt);
        t.eq(b"eth0", val(&conf(b"eth0", name)), dflt);
    }
    // mc_forwarding is read-only
    let p = conf(b"all", b"mc_forwarding");
    t.eq(b"mc_forwarding", val(&p), 0);
    t.eq(b"mc_forwarding ro", put(&p, 1), -13);
    t.done();
}

/// "default" reaches devices whose value was never written; disable_*
/// and promote_secondaries are not carried (Linux devinet_conf_proc)
fn test_conf_inherit() {
    let mut t = T::new(b"CONF_SYSCTL_INHERIT");
    let (d, e, l) = (
        conf(b"default", b"arp_ignore"),
        conf(b"eth0", b"arp_ignore"),
        conf(b"lo", b"arp_ignore"),
    );
    t.eq(b"own", put(&e, 2), 1);
    t.eq(b"dflt", put(&d, 1), 1);
    t.eq(b"lo inherits", val(&l), 1);
    t.eq(b"eth0 keeps", val(&e), 2);
    t.eq(b"restore", put(&d, 0), 1);
    t.eq(b"lo back", val(&l), 0);
    t.eq(b"eth0 restore", put(&e, 0), 1);
    let (dp, ep) = (
        conf(b"default", b"promote_secondaries"),
        conf(b"eth0", b"promote_secondaries"),
    );
    t.eq(b"promote", put(&dp, 1), 1);
    t.eq(b"promote not carried", val(&ep), 0);
    t.eq(b"promote restore", put(&dp, 0), 1);
    t.done();
}

/// "all"'s forwarding carries to "default", every device and
/// ip_forward, and turns "all"'s accept_redirects off (Linux
/// inet_forward_change); /proc/net/snmp's Forwarding follows
fn test_conf_forwarding() {
    let mut t = T::new(b"CONF_SYSCTL_FORWARDING");
    let ipf = b"/proc/sys/net/ipv4/ip_forward\0";
    let all = conf(b"all", b"forwarding");
    t.eq(b"on", put(&all, 1), 1);
    t.eq(b"ip_forward", val(ipf), 1);
    t.eq(b"default", val(&conf(b"default", b"forwarding")), 1);
    t.eq(b"eth0", val(&conf(b"eth0", b"forwarding")), 1);
    t.eq(b"lo", val(&conf(b"lo", b"forwarding")), 1);
    t.eq(b"redirects", val(&conf(b"all", b"accept_redirects")), 0);
    t.eq(b"off", put(ipf, 0), 1);
    t.eq(b"all off", val(&all), 0);
    t.eq(b"eth0 off", val(&conf(b"eth0", b"forwarding")), 0);
    t.eq(
        b"redirects back",
        val(&conf(b"all", b"accept_redirects")),
        1,
    );
    // A device's own forwarding leaves the others alone
    let e = conf(b"eth0", b"forwarding");
    t.eq(b"dev on", put(&e, 1), 1);
    t.eq(b"all still", val(&all), 0);
    t.eq(b"dev off", put(&e, 0), 1);
    t.ok(
        b"no dev",
        val(&conf(b"nosuchdev0", b"forwarding")) == ENOENT,
        0,
    );
    t.done();
}

/// A new namespace copies the initial one's "all" and "default" (Linux
/// devinet_init_net, devconf_inherit_init_net 0), its lo copies its
/// "default", and it has no neigh/default (registered in init_net only)
fn test_netns() {
    let mut t = T::new(b"CONF_SYSCTL_NETNS");
    let d = conf(b"default", b"arp_announce");
    t.eq(b"set", put(&d, 2), 1);
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(netns_child());
    }
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    t.eq(b"restore", put(&d, 0), 1);
    if st == 2 << 8 && crate::helpers::host_mode() {
        crate::helpers::skip(b"CONF_SYSCTL_NETNS", b"unshare(CLONE_NEWNET) not permitted");
        return;
    }
    t.eq(b"child", st as i64, 0);
    t.done();
}

fn netns_child() -> u64 {
    if sys_unshare(CLONE_NEWNET) != 0 {
        return 2;
    }
    if val(&conf(b"default", b"arp_announce")) != 2 {
        return 10;
    }
    if val(&conf(b"lo", b"arp_announce")) != 2 {
        return 11;
    }
    if val(&conf(b"eth0", b"arp_announce")) != ENOENT {
        return 12;
    }
    if val(&neigh(b"default", b"ucast_solicit")) != ENOENT {
        return 13;
    }
    if val(&neigh(b"lo", b"ucast_solicit")) != 3 {
        return 14;
    }
    let fd = sys_open(b"/proc/sys/net/ipv4/neigh\0".as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        return 15;
    }
    sys_close(fd as u64);
    if !reads(b"/proc/sys/net/ipv4/conf/all/forwarding\0", b"0\n") {
        return 16;
    }
    0
}

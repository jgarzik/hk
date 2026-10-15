//! TCP options and completeness (hk and Linux): 4 MB over lo with
//! window scaling and timestamps (checked through TCP_INFO), 4 MB
//! through the slirp echo peer, IPPROTO_TCP option round-trips,
//! TCP_MAXSEG on a connection, TCP_CORK/MSG_MORE delivery, keepalive
//! against a dead peer (a blackhole route), /proc/net/tcp lines and the
//! TCP sysctls.

use hk_syscall::{sys_exit, sys_fork, sys_getsockopt, sys_setsockopt, sys_shutdown, SHUT_WR};

use super::nl::{self, Nl, Req};
use super::sk::*;
use super::sysctl::read_file;
use super::tcp_xfer::{accept, listener, recv_pat, send_pat, set_timeo, wait_child};

const MB: usize = 1024 * 1024;
/// slirp guestfwd echo service (tools/qemu-net.sh)
const ECHO: [u8; 4] = [10, 0, 2, 100];

const TCP_NODELAY: i32 = 1;
const TCP_MAXSEG: i32 = 2;
const TCP_CORK: i32 = 3;
const TCP_KEEPIDLE: i32 = 4;
const TCP_KEEPINTVL: i32 = 5;
const TCP_KEEPCNT: i32 = 6;
const TCP_SYNCNT: i32 = 7;
const TCP_DEFER_ACCEPT: i32 = 9;
const TCP_INFO: i32 = 11;
const TCP_QUICKACK: i32 = 12;
const TCP_CONGESTION: i32 = 13;
const TCP_USER_TIMEOUT: i32 = 18;
const TCP_FASTOPEN: i32 = 23;
const TCP_NOTSENT_LOWAT: i32 = 25;
const MSG_MORE: i32 = 0x8000;
const ENOENT: i64 = -2;
const ETIMEDOUT: i64 = -110;
/// tcpi_options bits
const TCPI_OPT_TIMESTAMPS: u8 = 1;
const TCPI_OPT_WSCALE: u8 = 4;

pub fn run_tests() {
    super::helpers::println(b"=== TCP Option Tests ===");
    test_opts();
    test_congestion();
    test_lo_4mb_info();
    test_maxseg_conn();
    test_cork_more();
    test_proc_net_tcp();
    test_sysctls();
    test_echo_4mb();
    test_keepalive_dead_peer();
}

/// The fields of struct tcp_info the tests read
struct Info {
    len: u32,
    state: u8,
    options: u8,
    snd_wscale: u8,
    rcv_wscale: u8,
    rto: u32,
    snd_mss: u32,
    rcv_mss: u32,
    rtt: u32,
    snd_cwnd: u32,
    advmss: u32,
}

fn tcp_info(fd: i32) -> Info {
    let mut b = [0u8; 512];
    let mut len = b.len() as u32;
    sys_getsockopt(fd, IPPROTO_TCP, TCP_INFO, b.as_mut_ptr(), &mut len);
    let u32_at = |o: usize| u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
    Info {
        len,
        state: b[0],
        options: b[5],
        snd_wscale: b[6] & 15,
        rcv_wscale: b[6] >> 4,
        rto: u32_at(8),
        snd_mss: u32_at(16),
        rcv_mss: u32_at(20),
        rtt: u32_at(68),
        snd_cwnd: u32_at(80),
        advmss: u32_at(84),
    }
}

/// IPPROTO_TCP options read back what was set (Linux semantics)
fn test_opts() {
    let mut t = T::new(b"TCP_OPT_ROUNDTRIP");
    let fd = tcp();
    let get = |opt| getint(fd, IPPROTO_TCP, opt).1 as i64;
    t.eq(b"nodelay default", get(TCP_NODELAY), 0);
    setint(fd, IPPROTO_TCP, TCP_NODELAY, 1);
    t.eq(b"nodelay", get(TCP_NODELAY), 1);
    setint(fd, IPPROTO_TCP, TCP_CORK, 1);
    t.eq(b"cork", get(TCP_CORK), 1);
    setint(fd, IPPROTO_TCP, TCP_CORK, 0);
    t.eq(b"uncork", get(TCP_CORK), 0);
    t.eq(b"quickack default", get(TCP_QUICKACK), 1);
    setint(fd, IPPROTO_TCP, TCP_QUICKACK, 0);
    t.eq(b"quickack off", get(TCP_QUICKACK), 0);
    setint(fd, IPPROTO_TCP, TCP_QUICKACK, 1);
    t.eq(b"quickack on", get(TCP_QUICKACK), 1);
    t.eq(b"keepidle default", get(TCP_KEEPIDLE), 7200);
    t.eq(b"keepintvl default", get(TCP_KEEPINTVL), 75);
    t.eq(b"keepcnt default", get(TCP_KEEPCNT), 9);
    t.eq(b"keepintvl set", setint(fd, IPPROTO_TCP, TCP_KEEPINTVL, 3), 0);
    t.eq(b"keepintvl", get(TCP_KEEPINTVL), 3);
    t.eq(b"keepintvl 0", setint(fd, IPPROTO_TCP, TCP_KEEPINTVL, 0), EINVAL);
    setint(fd, IPPROTO_TCP, TCP_KEEPCNT, 4);
    t.eq(b"keepcnt", get(TCP_KEEPCNT), 4);
    setint(fd, IPPROTO_TCP, TCP_KEEPIDLE, 33);
    t.eq(b"keepidle", get(TCP_KEEPIDLE), 33);
    t.eq(b"keepidle max", setint(fd, IPPROTO_TCP, TCP_KEEPIDLE, 32768), EINVAL);
    t.eq(b"user_timeout", setint(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, 1234), 0);
    t.eq(b"user_timeout get", get(TCP_USER_TIMEOUT), 1234);
    t.eq(b"user_timeout neg", setint(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, -1), EINVAL);
    t.eq(b"maxseg default", get(TCP_MAXSEG), 536);
    t.eq(b"maxseg small", setint(fd, IPPROTO_TCP, TCP_MAXSEG, 87), EINVAL);
    setint(fd, IPPROTO_TCP, TCP_MAXSEG, 1000);
    t.eq(b"maxseg", get(TCP_MAXSEG), 1000);
    setint(fd, IPPROTO_TCP, TCP_SYNCNT, 3);
    t.eq(b"syncnt", get(TCP_SYNCNT), 3);
    // Seconds -> retransmissions -> seconds (1 + 2 + 4)
    setint(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, 5);
    t.eq(b"defer_accept", get(TCP_DEFER_ACCEPT), 7);
    t.eq(b"fastopen", setint(fd, IPPROTO_TCP, TCP_FASTOPEN, 5), 0);
    t.eq(b"fastopen get", get(TCP_FASTOPEN), 5);
    setint(fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, 16384);
    t.eq(b"notsent_lowat", get(TCP_NOTSENT_LOWAT), 16384);
    t.eq(b"so_keepalive", setint(fd, SOL_SOCKET, SO_KEEPALIVE, 1), 0);
    t.eq(b"so_keepalive get", getint(fd, SOL_SOCKET, SO_KEEPALIVE).1 as i64, 1);
    // TCP_INFO of an unconnected socket: TCP_CLOSE, Linux's size
    let i = tcp_info(fd);
    t.ok(b"info len", i.len >= 104, i.len as i64);
    t.eq(b"info state", i.state as i64, 7);
    close(fd);
    t.done();
}

/// TCP_CONGESTION: "reno" is always there; unknown names are ENOENT
fn test_congestion() {
    let mut t = T::new(b"TCP_CONGESTION");
    let fd = tcp();
    let mut b = [0xffu8; 16];
    let mut len = 16u32;
    let r = sys_getsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, b.as_mut_ptr(), &mut len);
    t.eq(b"get", r, 0);
    t.eq(b"len", len as i64, 16);
    t.ok(b"has a name", b[0].is_ascii_lowercase(), b[0] as i64);
    let set = |name: &[u8]| sys_setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, name.as_ptr(), name.len() as u32);
    t.eq(b"reno", set(b"reno"), 0);
    let mut b = [0xffu8; 16];
    let mut len = 16u32;
    sys_getsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, b.as_mut_ptr(), &mut len);
    t.ok(b"reno back", &b[..5] == b"reno\0", 0);
    t.eq(b"unknown", set(b"nosuchcc"), ENOENT);
    close(fd);
    t.done();
}

/// 4 MB client -> server over lo; TCP_INFO shows an established
/// connection with window scaling and timestamps negotiated
fn test_lo_4mb_info() {
    let mut t = T::new(b"TCP_LO_4MB_WSCALE");
    let (l, p) = listener(4);
    let pid = sys_fork();
    if pid == 0 {
        let c = tcp();
        set_timeo(c, 60_000);
        if connect(c, LO, p) != 0 {
            sys_exit(1);
        }
        let i = tcp_info(c);
        if i.state != 1 || i.snd_wscale == 0 || i.options & TCPI_OPT_WSCALE == 0 {
            sys_exit(2);
        }
        if send_pat(c, 6, 4 * MB) != (4 * MB) as i64 {
            sys_exit(3);
        }
        // Wait for the server's EOF so the info is read while connected
        let mut b = [0u8; 1];
        recv(c, &mut b, 0);
        sys_exit(0);
    }
    let s = accept(l);
    set_timeo(s, 60_000);
    let (n, bad, _) = recv_pat(s, 6, 4 * MB, 16384);
    t.eq(b"got", n as i64, (4 * MB) as i64);
    t.eq(b"data", bad, -1);
    let i = tcp_info(s);
    t.eq(b"state", i.state as i64, 1);
    t.ok(b"wscale opt", i.options & TCPI_OPT_WSCALE != 0, i.options as i64);
    t.ok(b"ts opt", i.options & TCPI_OPT_TIMESTAMPS != 0, i.options as i64);
    t.ok(b"snd_wscale", i.snd_wscale > 0, i.snd_wscale as i64);
    t.ok(b"rcv_wscale", i.rcv_wscale > 0, i.rcv_wscale as i64);
    t.ok(b"snd_mss", i.snd_mss > 0 && i.snd_mss <= 65535, i.snd_mss as i64);
    t.ok(b"rcv_mss", i.rcv_mss > 0, i.rcv_mss as i64);
    t.ok(b"advmss", i.advmss >= i.snd_mss, i.advmss as i64);
    t.ok(b"rto", i.rto >= 200_000 && i.rto <= 120_000_000, i.rto as i64);
    t.ok(b"rtt", i.rtt < 5_000_000, i.rtt as i64);
    t.ok(b"cwnd", i.snd_cwnd > 0, i.snd_cwnd as i64);
    sys_shutdown(s, SHUT_WR);
    t.eq(b"client", wait_child(pid) as i64, 0);
    close(s);
    close(l);
    t.done();
}

/// TCP_MAXSEG before connect caps both directions; it reads back as the
/// payload size (less the 12 timestamp option bytes)
fn test_maxseg_conn() {
    let mut t = T::new(b"TCP_MAXSEG_CONN");
    let (l, p) = listener(4);
    let c = tcp();
    setint(c, IPPROTO_TCP, TCP_MAXSEG, 1000);
    t.eq(b"connect", connect(c, LO, p), 0);
    let s = accept(l);
    t.eq(b"client mss", getint(c, IPPROTO_TCP, TCP_MAXSEG).1 as i64, 988);
    t.eq(b"server mss", getint(s, IPPROTO_TCP, TCP_MAXSEG).1 as i64, 988);
    t.eq(b"info snd_mss", tcp_info(s).snd_mss as i64, 988);
    // Data still flows in 988-byte pieces
    set_timeo(s, 10_000);
    set_timeo(c, 10_000);
    t.eq(b"send", send_pat(c, 7, 50_000), 50_000);
    let (n, bad, _) = recv_pat(s, 7, 50_000, 16384);
    t.eq(b"recv", n as i64, 50_000);
    t.eq(b"data", bad, -1);
    close(c);
    close(s);
    close(l);
    t.done();
}

/// Corked and MSG_MORE data arrives once uncorked / pushed
fn test_cork_more() {
    let mut t = T::new(b"TCP_CORK_MORE");
    let (l, p) = listener(4);
    let c = tcp();
    t.eq(b"connect", connect(c, LO, p), 0);
    let s = accept(l);
    set_timeo(s, 10_000);
    setint(c, IPPROTO_TCP, TCP_CORK, 1);
    t.eq(b"send corked", send(c, b"hello ", 0), 6);
    t.eq(b"send more", send(c, b"wor", MSG_MORE), 3);
    t.eq(b"send", send(c, b"ld", 0), 2);
    setint(c, IPPROTO_TCP, TCP_CORK, 0);
    let mut b = [0u8; 11];
    t.eq(b"recv", recv(s, &mut b, MSG_WAITALL), 11);
    t.ok(b"bytes", &b == b"hello world", 0);
    // A corked partial segment still goes out (200 ms ceiling)
    setint(c, IPPROTO_TCP, TCP_CORK, 1);
    send(c, b"late", 0);
    t.eq(b"recv late", recv(s, &mut b[..4], MSG_WAITALL), 4);
    close(c);
    close(s);
    close(l);
    t.done();
}

static mut PROC: [u8; 512 * 1024] = [0; 512 * 1024];

/// Hex digits of `v` (`w` wide) into `out`
fn hex(v: u32, w: usize, out: &mut [u8]) {
    for i in 0..w {
        let d = ((v >> (4 * (w - 1 - i))) & 15) as u8;
        out[i] = if d < 10 { b'0' + d } else { b'A' + d - 10 };
    }
}

/// A line of `text` containing all of `parts`
fn has_line(text: &[u8], parts: &[&[u8]]) -> bool {
    text.split(|&c| c == b'\n')
        .any(|l| parts.iter().all(|p| l.windows(p.len()).any(|w| w == *p)))
}

/// /proc/net/tcp lists a listener (st 0A) and both ends of a connection
/// (st 01), addresses as raw network-order hex and ports in hex
fn test_proc_net_tcp() {
    let mut t = T::new(b"TCP_PROC_NET");
    let (l, p) = listener(4);
    let c = tcp();
    t.eq(b"connect", connect(c, LO, p), 0);
    let s = accept(l);
    let cp = port(c);
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(PROC) };
    let n = read_file(b"/proc/net/tcp\0", buf);
    t.ok(b"read", n > 0, n);
    let text = &buf[..n.max(0) as usize];
    t.ok(b"header", text.starts_with(b"  sl  local_address rem_address   st tx_queue rx_queue"), 0);
    let mut lo = *b"0100007F:0000";
    hex(p as u32, 4, &mut lo[9..]);
    let mut lc = *b"0100007F:0000";
    hex(cp as u32, 4, &mut lc[9..]);
    let mut lst = *b"0100007F:0000 00000000:0000 0A ";
    lst[..13].copy_from_slice(&lo);
    t.ok(b"listener", has_line(text, &[&lst]), 0);
    let mut est = [0u8; 27];
    est[..13].copy_from_slice(&lc);
    est[13] = b' ';
    est[14..].copy_from_slice(&lo);
    t.ok(b"client line", has_line(text, &[&est, b" 01 "]), 0);
    est[..13].copy_from_slice(&lo);
    est[14..].copy_from_slice(&lc);
    t.ok(b"server line", has_line(text, &[&est, b" 01 "]), 0);
    close(c);
    close(s);
    close(l);
    t.done();
}

/// TCP sysctls exist with Linux's defaults
fn test_sysctls() {
    let mut t = T::new(b"TCP_SYSCTLS");
    let mut b = [0u8; 128];
    let n = read_file(b"/proc/sys/net/ipv4/tcp_available_congestion_control\0", &mut b);
    t.ok(b"available has reno", n > 0 && has_line(&b[..n as usize], &[b"reno"]), n);
    let n = read_file(b"/proc/sys/net/ipv4/tcp_congestion_control\0", &mut b);
    t.ok(b"default", n > 1 && b[0].is_ascii_lowercase() && b[n as usize - 1] == b'\n', n);
    for (path, want) in [
        (&b"/proc/sys/net/ipv4/tcp_window_scaling\0"[..], &b"1\n"[..]),
        (b"/proc/sys/net/ipv4/tcp_timestamps\0", b"1\n"),
        (b"/proc/sys/net/ipv4/tcp_keepalive_time\0", b"7200\n"),
        (b"/proc/sys/net/ipv4/tcp_keepalive_intvl\0", b"75\n"),
        (b"/proc/sys/net/ipv4/tcp_keepalive_probes\0", b"9\n"),
    ] {
        let n = read_file(path, &mut b);
        t.ok(&path[..path.len() - 1], n > 0 && &b[..n as usize] == want, n);
    }
    let n = read_file(b"/proc/sys/net/ipv4/tcp_rmem\0", &mut b);
    t.ok(b"tcp_rmem 3 values", n > 0 && b[..n as usize].iter().filter(|&&c| c == b'\t').count() == 2, n);
    t.done();
}

/// 4 MB through the echo peer: a child sends and half-closes, the
/// parent reads the echo until EOF
fn test_echo_4mb() {
    let mut t = T::new(b"TCP_ECHO_4MB");
    if let Err(e) = nl::net_setup_eth0() {
        t.ok(e.as_bytes(), false, 0);
        return t.done();
    }
    let fd = tcp();
    set_timeo(fd, 60_000);
    if !t.eq(b"connect", connect(fd, ECHO, 7), 0) {
        close(fd);
        return t.done();
    }
    let pid = sys_fork();
    if pid == 0 {
        let r = send_pat(fd, 8, 4 * MB);
        sys_shutdown(fd, SHUT_WR);
        sys_exit(if r == (4 * MB) as i64 { 0 } else { 1 });
    }
    let (n, bad, last) = recv_pat(fd, 8, 4 * MB + 1, 16384);
    t.eq(b"echoed", n as i64, (4 * MB) as i64);
    t.eq(b"data", bad, -1);
    t.eq(b"eof", last, 0);
    t.eq(b"sender", wait_child(pid) as i64, 0);
    close(fd);
    t.done();
}

const RTN_BLACKHOLE: u8 = 6;

/// Add or delete a blackhole route for `dst`/32 in the main table
fn blackhole(nl: &mut Nl, add: bool, dst: [u8; 4]) -> i32 {
    let (ty, flags, proto, scope, rtype) = if add {
        (nl::RTM_NEWROUTE, nl::NLM_F_CREATE | nl::NLM_F_EXCL, nl::RTPROT_BOOT, nl::RT_SCOPE_UNIVERSE, RTN_BLACKHOLE)
    } else {
        (nl::RTM_DELROUTE, 0, 0, 255, 0)
    };
    let mut r = Req::new(ty, flags, &nl::rtmsg(32, nl::RT_TABLE_MAIN, proto, scope, rtype));
    r.attr(nl::RTA_DST, &dst);
    nl.ack(&mut r)
}

/// Keepalive with tiny intervals against a peer that went away (its
/// route became a blackhole): the connection fails with ETIMEDOUT
fn test_keepalive_dead_peer() {
    let mut t = T::new(b"TCP_KEEPALIVE_DEAD");
    if let Err(e) = nl::net_setup_eth0() {
        t.ok(e.as_bytes(), false, 0);
        return t.done();
    }
    let Some(mut nl) = Nl::open() else {
        t.ok(b"netlink", false, 0);
        return t.done();
    };
    let fd = tcp();
    set_timeo(fd, 30_000);
    if !t.eq(b"connect", connect(fd, ECHO, 7), 0) {
        close(fd);
        return t.done();
    }
    // The peer is alive: an echo round trip
    send(fd, b"ping", 0);
    let mut b = [0u8; 4];
    t.eq(b"echo", recv(fd, &mut b, MSG_WAITALL), 4);
    t.eq(b"keepalive", setint(fd, SOL_SOCKET, SO_KEEPALIVE, 1), 0);
    setint(fd, IPPROTO_TCP, TCP_KEEPIDLE, 1);
    setint(fd, IPPROTO_TCP, TCP_KEEPINTVL, 1);
    setint(fd, IPPROTO_TCP, TCP_KEEPCNT, 2);
    t.eq(b"blackhole", blackhole(&mut nl, true, ECHO) as i64, 0);
    let t0 = now_ms();
    let r = recv(fd, &mut b, 0);
    let dt = now_ms() - t0;
    t.eq(b"recv", r, ETIMEDOUT);
    t.ok(b"took idle + probes", (1500..20_000).contains(&dt), dt as i64);
    t.eq(b"unblackhole", blackhole(&mut nl, false, ECHO) as i64, 0);
    close(fd);
    t.done();
}

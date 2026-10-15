//! TCP connection management (hk and Linux): listen backlog, half-close,
//! resets (close with unread data, SO_LINGER 0), the TIME_WAIT bind rule,
//! refused and unanswered connects on eth0.

use hk_syscall::{
    sys_exit, sys_fork, sys_listen, sys_nanosleep, sys_setsockopt, sys_shutdown, sys_socket,
    Timespec, AF_INET, SHUT_WR, SOCK_NONBLOCK, SOCK_STREAM,
};

use super::sk::*;
use super::sysctl::{read_file, write_file};
use super::tcp_xfer::{accept, listener, set_timeo, wait_child};

const ECONNRESET: i64 = -104;
const ETIMEDOUT: i64 = -110;
const EHOSTUNREACH: i64 = -113;
const POLLIN: i16 = 1;
const POLLOUT: i16 = 4;
const POLLRDHUP: i16 = 0x2000;
const SYN_RETRIES: &[u8] = b"/proc/sys/net/ipv4/tcp_syn_retries\0";

pub fn run_tests() {
    super::helpers::println(b"=== TCP Connection Tests ===");
    test_backlog();
    test_half_close();
    test_rst_unread();
    test_linger0();
    test_time_wait_bind();
    test_eth0_refused();
    test_connect_timeout();
}

fn msleep(ms: u64) {
    let ts = Timespec {
        tv_sec: (ms / 1000) as i64,
        tv_nsec: ((ms % 1000) * 1_000_000) as i64,
    };
    sys_nanosleep(&ts, core::ptr::null_mut());
}

fn nb_tcp() -> i32 {
    sys_socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0) as i32
}

/// Connected per poll + SO_ERROR (non-blocking connect finished well)
fn connected(fd: i32) -> bool {
    let (n, ev) = poll1(fd, POLLOUT, 0);
    n == 1 && ev & POLLOUT != 0 && getint(fd, SOL_SOCKET, SO_ERROR).1 == 0
}

/// listen(fd, 1) queues at most backlog + 1 completed connections; the
/// other SYNs are dropped and retried, so every client gets accepted
/// once the queue drains
fn test_backlog() {
    let mut t = T::new(b"TCP_BACKLOG");
    let (l, p) = listener(1);
    let mut c = [-1i32; 4];
    for fd in c.iter_mut() {
        *fd = nb_tcp();
        let r = connect(*fd, LO, p);
        t.ok(b"connect", r == EINPROGRESS || r == 0, r);
    }
    msleep(300);
    let up = c.iter().filter(|&&fd| connected(fd)).count();
    t.ok(b"queued", (1..=2).contains(&up), up as i64);
    set_timeo(l, 10_000);
    let mut acc = 0;
    for _ in 0..4 {
        let s = accept(l);
        if s < 0 {
            break;
        }
        acc += 1;
        close(s);
    }
    t.eq(b"all accepted", acc, 4);
    for fd in c {
        close(fd);
    }
    close(l);
    t.done();
}

/// SHUT_WR sends a FIN only: the peer reads EOF (POLLRDHUP) and can
/// still answer; the half-closed side reads the answer, then EOF
fn test_half_close() {
    let mut t = T::new(b"TCP_HALF_CLOSE");
    let (l, p) = listener(4);
    let c = tcp();
    set_timeo(c, 10_000);
    t.eq(b"connect", connect(c, LO, p), 0);
    let s = accept(l);
    set_timeo(s, 10_000);
    send(c, b"request", 0);
    t.eq(b"shutdown", sys_shutdown(c, SHUT_WR), 0);
    let mut b = [0u8; 16];
    t.eq(b"request", recv(s, &mut b[..7], MSG_WAITALL), 7);
    let (n, ev) = poll1(s, POLLIN | POLLRDHUP, 2000);
    t.ok(b"rdhup", n == 1 && ev & POLLRDHUP != 0, ev as i64);
    t.eq(b"server eof", recv(s, &mut b, 0), 0);
    t.eq(b"send after shut", send(c, b"x", MSG_NOSIGNAL), EPIPE);
    t.eq(b"answer", send(s, b"response", 0), 8);
    close(s);
    t.eq(b"client reads", recv(c, &mut b[..8], MSG_WAITALL), 8);
    t.ok(b"answer data", &b[..8] == b"response", 0);
    t.eq(b"client eof", recv(c, &mut b, 0), 0);
    close(c);
    close(l);
    t.done();
}

/// Closing with unread data resets the connection: the peer's next
/// read fails with ECONNRESET
fn test_rst_unread() {
    let mut t = T::new(b"TCP_RST_UNREAD");
    let (l, p) = listener(4);
    let c = tcp();
    set_timeo(c, 10_000);
    connect(c, LO, p);
    let s = accept(l);
    send(c, b"never read", 0);
    let (n, _) = poll1(s, POLLIN, 2000);
    t.eq(b"arrived", n, 1);
    close(s);
    let mut b = [0u8; 16];
    t.eq(b"reset", recv(c, &mut b, 0), ECONNRESET);
    t.eq(b"then eof", recv(c, &mut b, 0), 0);
    t.eq(b"send", send(c, b"x", MSG_NOSIGNAL), EPIPE);
    close(c);
    close(l);
    t.done();
}

/// SO_LINGER {1, 0}: close aborts with RST
fn test_linger0() {
    let mut t = T::new(b"TCP_LINGER0");
    let (l, p) = listener(4);
    let c = tcp();
    set_timeo(c, 10_000);
    connect(c, LO, p);
    let s = accept(l);
    let lg = [1i32, 0];
    t.eq(b"setsockopt", sys_setsockopt(s, SOL_SOCKET, SO_LINGER, lg.as_ptr() as *const u8, 8), 0);
    close(s);
    let mut b = [0u8; 4];
    t.eq(b"reset", recv(c, &mut b, 0), ECONNRESET);
    close(c);
    close(l);
    t.done();
}

/// The side that closes first keeps the port in TIME_WAIT: binding it
/// needs SO_REUSEADDR (which the closed listener had), and listening
/// there works again
fn test_time_wait_bind() {
    let mut t = T::new(b"TCP_TIME_WAIT_BIND");
    let l = tcp();
    setint(l, SOL_SOCKET, SO_REUSEADDR, 1);
    bind(l, LO, 0);
    sys_listen(l, 4);
    let p = port(l);
    let c = tcp();
    set_timeo(c, 10_000);
    connect(c, LO, p);
    let s = accept(l);
    close(s);
    let mut b = [0u8; 4];
    t.eq(b"client eof", recv(c, &mut b, 0), 0);
    close(c);
    close(l);
    msleep(100);
    let n = tcp();
    t.eq(b"bind without REUSEADDR", bind(n, LO, p), EADDRINUSE);
    close(n);
    let r = tcp();
    setint(r, SOL_SOCKET, SO_REUSEADDR, 1);
    t.eq(b"bind with REUSEADDR", bind(r, LO, p), 0);
    t.eq(b"listen", sys_listen(r, 4), 0);
    // And it takes connections
    let c2 = tcp();
    t.eq(b"reconnect", connect(c2, LO, p), 0);
    let s2 = accept(r);
    t.ok(b"accept", s2 >= 0, s2 as i64);
    for f in [c2, s2, r] {
        close(f);
    }
    t.done();
}

/// A closed port behind the slirp gateway: refused (slirp answers RST
/// when the host refuses) or no answer yet; never a success
fn test_eth0_refused() {
    let mut t = T::new(b"TCP_ETH0_REFUSED");
    if super::nl::net_setup_eth0().is_err() {
        t.ok(b"eth0", false, 0);
        return t.done();
    }
    let fd = nb_tcp();
    let r = connect(fd, [10, 0, 2, 2], 1);
    t.ok(b"connect", r == EINPROGRESS || r == ECONNREFUSED, r);
    if r == EINPROGRESS {
        let (n, ev) = poll1(fd, POLLOUT, 5000);
        if n == 1 {
            let e = getint(fd, SOL_SOCKET, SO_ERROR).1 as i64;
            t.ok(b"refused", e == -ECONNREFUSED || e == -ETIMEDOUT, e);
            let _ = ev;
        }
    }
    close(fd);
    t.done();
}

/// A connect to an address nobody answers (no ARP reply on eth0) fails
/// with EHOSTUNREACH (neighbour failure) or ETIMEDOUT (SYN retries,
/// lowered to 1 here) within seconds
fn test_connect_timeout() {
    let mut t = T::new(b"TCP_CONNECT_TIMEOUT");
    if super::nl::net_setup_eth0().is_err() {
        t.ok(b"eth0", false, 0);
        return t.done();
    }
    let mut old = [0u8; 8];
    let n = read_file(SYN_RETRIES, &mut old);
    t.ok(b"read sysctl", n > 0, n);
    t.eq(b"set sysctl", write_file(SYN_RETRIES, b"1\n"), 2);
    let pid = sys_fork();
    if pid == 0 {
        let fd = tcp();
        let t0 = now_ms();
        let r = connect(fd, [10, 0, 2, 77], 80);
        let dt = now_ms() - t0;
        let code = match r {
            EHOSTUNREACH => 0,
            ETIMEDOUT => 0,
            _ => 1,
        };
        sys_exit(if dt > 20_000 { 2 } else { code });
    }
    let st = wait_child(pid);
    if n > 0 {
        write_file(SYN_RETRIES, &old[..n as usize]);
    }
    t.eq(b"connect failed in time", st as i64, 0);
    t.done();
}

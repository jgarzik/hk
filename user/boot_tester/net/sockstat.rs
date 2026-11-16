//! /proc/net/sockstat (hk and Linux), in a new network namespace so
//! nothing else moves its counts
//!
//! - SOCKSTAT_FORMAT: the sockets, TCP, UDP, RAW and FRAG lines with
//!   their fields (Linux 6.8 also has a UDPLITE line, read past)
//! - SOCKSTAT_COUNTS: a fresh namespace's protocols start at zero; a
//!   socket counts in "sockets: used" while open, a UDP socket in UDP
//!   inuse once bound, a raw socket in RAW inuse at once, a TCP
//!   listener, its connection and the accepted one in TCP inuse; the
//!   side that closes first ends in TIME_WAIT (tw); closing everything
//!   brings the counts back

use hk_syscall::{AF_INET, CLONE_NEWNET, SOCK_RAW, sys_exit, sys_fork, sys_socket, sys_unshare};

use crate::harness::{T, fail_num, pass};
use crate::helpers::{host_mode, loopback_up, msleep, println, read_file, skip};
use crate::net::sk::*;
use crate::net::tcp_xfer::{accept, listener, wait_child};

const IPPROTO_ICMP: i32 = 1;

/// The file's text
struct Stat {
    buf: [u8; 1024],
    len: usize,
}

impl Stat {
    fn read() -> Option<Stat> {
        let mut s = Stat {
            buf: [0; 1024],
            len: 0,
        };
        let n = read_file(b"/proc/net/sockstat\0", &mut s.buf);
        if n <= 0 || n as usize == s.buf.len() {
            return None;
        }
        s.len = n as usize;
        Some(s)
    }

    /// Field `name` of the line tagged `tag` ("TCP:"): the number after
    /// the name
    fn get(&self, tag: &[u8], name: &[u8]) -> Option<i64> {
        let line = self.buf[..self.len]
            .split(|&b| b == b'\n')
            .find(|l| l.starts_with(tag))?;
        let mut w = line[tag.len()..]
            .split(|&b| b == b' ')
            .filter(|w| !w.is_empty());
        while let Some(k) = w.next() {
            if k == name {
                return w.next().and_then(num);
            }
        }
        None
    }

    fn val(&self, tag: &[u8], name: &[u8]) -> i64 {
        self.get(tag, name).unwrap_or(-1)
    }
}

fn num(w: &[u8]) -> Option<i64> {
    if w.is_empty() || !w.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(w.iter().fold(0i64, |n, &c| n * 10 + i64::from(c - b'0')))
}

pub fn run_tests() {
    println(b"=== sockstat Tests ===");
    let pid = sys_fork();
    if pid < 0 {
        println(b"SOCKSTAT:FAIL fork");
        return;
    }
    if pid == 0 {
        if sys_unshare(CLONE_NEWNET) != 0 {
            sys_exit(2);
        }
        loopback_up();
        format();
        counts();
        sys_exit(0);
    }
    let st = wait_child(pid);
    let code = (st >> 8) & 0xff;
    if st & 0x7f == 0 && code == 0 {
        pass(b"SOCKSTAT");
    } else if code == 2 && host_mode() {
        skip(b"SOCKSTAT", b"unshare(CLONE_NEWNET) not permitted");
    } else {
        fail_num(b"SOCKSTAT:FAIL status=", st as i64);
    }
}

fn format() {
    let mut t = T::new(b"SOCKSTAT_FORMAT");
    let Some(s) = Stat::read() else {
        t.ok(b"read", false, 0);
        t.done();
        return;
    };
    let fields: [(&[u8], &[&[u8]]); 5] = [
        (b"sockets:", &[b"used"]),
        (b"TCP:", &[b"inuse", b"orphan", b"tw", b"alloc", b"mem"]),
        (b"UDP:", &[b"inuse", b"mem"]),
        (b"RAW:", &[b"inuse"]),
        (b"FRAG:", &[b"inuse", b"memory"]),
    ];
    for (i, (tag, names)) in fields.iter().enumerate() {
        for (j, name) in names.iter().enumerate() {
            t.ok(name, s.get(tag, name).is_some(), (i * 10 + j) as i64);
        }
    }
    t.done();
}

/// Read until `f` holds of the counts (up to ~2 s: TIME_WAIT is
/// entered after the peer's FIN arrives)
fn settle(f: impl Fn(&Stat) -> bool) -> Option<Stat> {
    for _ in 0..200 {
        let s = Stat::read()?;
        if f(&s) {
            return Some(s);
        }
        msleep(10);
    }
    Stat::read()
}

fn counts() {
    let mut t = T::new(b"SOCKSTAT_COUNTS");
    let Some(s0) = Stat::read() else {
        t.ok(b"read", false, 0);
        t.done();
        return;
    };
    for (tag, name) in [
        (b"TCP:" as &[u8], b"inuse" as &[u8]),
        (b"TCP:", b"tw"),
        (b"UDP:", b"inuse"),
        (b"RAW:", b"inuse"),
        (b"FRAG:", b"inuse"),
    ] {
        t.eq(name, s0.val(tag, name), 0);
    }
    let used = |s: &Stat| s.val(b"sockets:", b"used");
    let base = used(&s0);

    // UDP: a socket, bound
    let u = udp();
    let s = Stat::read().unwrap_or(Stat {
        buf: [0; 1024],
        len: 0,
    });
    t.eq(b"udp used", used(&s) - base, 1);
    t.eq(b"udp unbound", s.val(b"UDP:", b"inuse"), 0);
    bind(u, LO, 0);
    t.eq(
        b"udp bound",
        Stat::read().map_or(-1, |s| s.val(b"UDP:", b"inuse")),
        1,
    );
    close(u);
    let s = Stat::read().unwrap_or(Stat {
        buf: [0; 1024],
        len: 0,
    });
    t.eq(b"udp closed", s.val(b"UDP:", b"inuse"), 0);
    t.eq(b"udp closed used", used(&s) - base, 0);

    // RAW: hashed when made
    let r = sys_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) as i32;
    t.ok(b"raw socket", r >= 0, i64::from(r));
    t.eq(
        b"raw",
        Stat::read().map_or(-1, |s| s.val(b"RAW:", b"inuse")),
        1,
    );
    close(r);
    t.eq(
        b"raw closed",
        Stat::read().map_or(-1, |s| s.val(b"RAW:", b"inuse")),
        0,
    );

    // TCP: listener, connection, accepted; the client closes first
    let (l, p) = listener(1);
    t.eq(
        b"listen",
        Stat::read().map_or(-1, |s| s.val(b"TCP:", b"inuse")),
        1,
    );
    let c = tcp();
    t.eq(b"connect", connect(c, LO, p), 0);
    let a = accept(l);
    let s = Stat::read().unwrap_or(Stat {
        buf: [0; 1024],
        len: 0,
    });
    t.eq(b"established", s.val(b"TCP:", b"inuse"), 3);
    t.eq(b"tcp used", used(&s) - base, 3);
    close(c);
    close(a);
    let s = settle(|s| s.val(b"TCP:", b"tw") == 1).unwrap_or(Stat {
        buf: [0; 1024],
        len: 0,
    });
    t.eq(b"time wait", s.val(b"TCP:", b"tw"), 1);
    close(l);
    let s = settle(|s| s.val(b"TCP:", b"inuse") == 0).unwrap_or(Stat {
        buf: [0; 1024],
        len: 0,
    });
    t.eq(b"tcp closed", s.val(b"TCP:", b"inuse"), 0);
    t.done();
}

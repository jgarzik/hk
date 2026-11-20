//! AF_UNIX garbage collection (hk and Linux): sockets reachable only
//! through their own in-flight descriptors are freed after close
//! (Linux selftests af_unix/scm_rights.c: self_ref, triangle,
//! cross_edge, backtrack_from_scc, mixed_lowpoint, over socketpairs of
//! both types, unaccepted connections and out-of-band bytes), counted
//! through /proc/net/unix of a fresh network namespace; a MSG_PEEK copy
//! keeps its cycle alive.

use hk_syscall::{
    AF_UNIX, CLONE_NEWNET, O_RDONLY, SOCK_DGRAM, SOCK_STREAM, sys_bind, sys_connect, sys_exit,
    sys_fork, sys_getsockname, sys_listen, sys_open, sys_read, sys_socket, sys_unshare, sys_wait4,
};

use crate::harness::T;
use crate::helpers::{host_mode, skip};
use crate::net::sk::*;
use crate::net::unix::{got_fds, pair, send_cmsg};

const SCM_RIGHTS: i32 = 1;

pub fn run_tests() {
    crate::helpers::println(b"=== AF_UNIX GC Tests ===");
    let pid = sys_fork();
    if pid == 0 {
        if sys_unshare(CLONE_NEWNET) != 0 {
            sys_exit(2);
        }
        for v in &VARIANTS {
            graphs(v);
        }
        test_peek();
        sys_exit(0);
    }
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    let code = (st >> 8) & 0xff;
    if code == 2 && host_mode() {
        skip(b"UNIX_GC", b"unshare(CLONE_NEWNET) not permitted");
    } else if st != 0 {
        let mut t = T::new(b"UNIX_GC");
        t.eq(b"child status", st as i64, 0);
        t.done();
    }
}

/// How the sockets are made and sent (scm_rights.c variants)
struct Variant {
    name: &'static [u8],
    ty: i32,
    flags: i32,
    listener: bool,
}

const VARIANTS: [Variant; 4] = [
    Variant {
        name: b"UNIX_GC_STREAM",
        ty: SOCK_STREAM,
        flags: 0,
        listener: false,
    },
    Variant {
        name: b"UNIX_GC_DGRAM",
        ty: SOCK_DGRAM,
        flags: 0,
        listener: false,
    },
    Variant {
        name: b"UNIX_GC_STREAM_OOB",
        ty: SOCK_STREAM,
        flags: MSG_OOB,
        listener: false,
    },
    Variant {
        name: b"UNIX_GC_LISTENER",
        ty: SOCK_STREAM,
        flags: 0,
        listener: true,
    },
];

/// Sockets of this namespace (/proc/net/unix lines past the header)
fn count() -> i64 {
    let f = sys_open(b"/proc/net/unix\0".as_ptr(), O_RDONLY, 0) as i32;
    if f < 0 {
        return f as i64;
    }
    let mut buf = [0u8; 16384];
    let mut n = 0;
    loop {
        let r = sys_read(f as u64, buf[n..].as_mut_ptr(), (buf.len() - n) as u64);
        if r <= 0 {
            break;
        }
        n += r as usize;
    }
    close(f);
    buf[..n].iter().filter(|&&c| c == b'\n').count() as i64 - 1
}

/// The count once it reached `want`, waiting up to 3 s for the
/// collector (scm_rights.c sleeps 1 s)
fn settle(want: i64) -> i64 {
    let mut c = count();
    for _ in 0..60 {
        if c == want {
            break;
        }
        let ts = hk_syscall::Timespec {
            tv_sec: 0,
            tv_nsec: 50_000_000,
        };
        hk_syscall::sys_nanosleep(&ts, core::ptr::null_mut());
        c = count();
    }
    c
}

/// `n` units: socketpairs, or an autobound listener and a connected,
/// unaccepted client (fd[2i], fd[2i + 1])
fn create(v: &Variant, n: usize, fd: &mut [i32; 32]) {
    for i in 0..n {
        if !v.listener {
            let (a, b) = pair(v.ty);
            fd[2 * i] = a;
            fd[2 * i + 1] = b;
            continue;
        }
        let l = sys_socket(AF_UNIX, SOCK_STREAM, 0) as i32;
        let fam = (AF_UNIX as u16).to_ne_bytes();
        sys_bind(l, fam.as_ptr(), 2);
        sys_listen(l, -1);
        let mut addr = [0u8; 110];
        let mut len = 110u32;
        sys_getsockname(l, addr.as_mut_ptr(), &mut len);
        let c = sys_socket(AF_UNIX, SOCK_STREAM, 0) as i32;
        sys_connect(c, addr.as_ptr(), len);
        fd[2 * i] = l;
        fd[2 * i + 1] = c;
    }
}

/// Send unit `inflight`'s first socket, twice, to unit `receiver`'s
/// first socket (through its peer)
fn send_fd(t: &mut T, v: &Variant, fd: &[i32; 32], inflight: usize, receiver: usize) {
    let f = fd[inflight * 2];
    let mut p = [0u8; 8];
    p[..4].copy_from_slice(&f.to_ne_bytes());
    p[4..].copy_from_slice(&f.to_ne_bytes());
    let r = send_cmsg(
        fd[receiver * 2 + 1],
        b"x",
        SOL_SOCKET,
        SCM_RIGHTS,
        &p,
        v.flags,
    );
    t.eq(b"send", r, 1);
}

/// One graph of scm_rights.c: `n` units, the sends, all closed, then
/// every socket freed (back to the count before; unless `host_bug`
/// on the reference Linux, which then keeps them)
fn graph(t: &mut T, v: &Variant, n: usize, sends: &[(usize, usize)], host_bug: bool) {
    let before = count();
    let mut fd = [-1i32; 32];
    create(v, n, &mut fd);
    for &(a, b) in sends {
        send_fd(t, v, &fd, a, b);
    }
    for &f in &fd[..2 * n] {
        close(f);
    }
    if host_bug && host_mode() {
        return;
    }
    t.eq(b"all freed", settle(before), before);
}

fn graphs(v: &Variant) {
    let mut t = T::new(v.name);
    // self_ref
    graph(&mut t, v, 2, &[(0, 0), (1, 1)], false);
    // triangle
    graph(
        &mut t,
        v,
        6,
        &[(0, 1), (1, 2), (2, 0), (3, 4), (4, 5), (5, 3)],
        false,
    );
    // cross_edge
    let cross = [(0, 1), (1, 2), (2, 0), (1, 3), (3, 2)];
    let mut s = [(0, 0); 10];
    for (i, &(a, b)) in cross.iter().enumerate() {
        s[i] = (a, b);
        s[i + 5] = (a + 4, b + 4);
    }
    graph(&mut t, v, 8, &s, false);
    // backtrack_from_scc
    let back = [(0, 1), (0, 4), (1, 2), (2, 3), (3, 1)];
    for (i, &(a, b)) in back.iter().enumerate() {
        s[i] = (a, b);
        s[i + 5] = (a + 5, b + 5);
    }
    graph(&mut t, v, 10, &s, false);
    // mixed_lowpoint: two back edges in one component. The reference
    // Linux (Ubuntu 6.8.0-149 backports the graph collector,
    // 4090fa373f0e) lacks 4a4263dfeaba ("af_unix: Unify scc_index when
    // finalising SCC in __unix_walk_scc()"), so it keeps these sockets
    graph(
        &mut t,
        v,
        6,
        &[
            (0, 1),
            (1, 2),
            (2, 1),
            (1, 0),
            (3, 4),
            (4, 5),
            (5, 4),
            (4, 3),
        ],
        true,
    );
    t.done();
}

/// A socket peeked out of its own queue (a MSG_PEEK copy of the
/// in-flight descriptor) is alive: its message can still be read
/// through the copy; once that is closed too, both go
fn test_peek() {
    let mut t = T::new(b"UNIX_GC_PEEK");
    let before = count();
    let (a, b) = pair(SOCK_STREAM);
    let p = a.to_ne_bytes();
    t.eq(
        b"send self",
        send_cmsg(b, b"x", SOL_SOCKET, SCM_RIGHTS, &p, 0),
        1,
    );
    let mut buf = [0u8; 8];
    let mut ctl = [0u8; 64];
    let (r, _, clen) = recv_msg(a, &mut buf, &mut ctl, MSG_PEEK);
    let (pk, _) = got_fds(&ctl, clen);
    t.ok(b"peeked", r == 1 && pk >= 0, r);
    close(a);
    close(b);
    // A run of the collector (b's release) must leave a's socket
    t.eq(b"kept", settle(before + 1), before + 1);
    let (r, _, clen) = recv_msg(pk, &mut buf, &mut ctl, MSG_DONTWAIT);
    let (rd, _) = got_fds(&ctl, clen);
    t.ok(b"read through copy", r == 1 && rd >= 0, r);
    close(pk);
    close(rd);
    t.eq(b"all freed", settle(before), before);
    t.done();
}

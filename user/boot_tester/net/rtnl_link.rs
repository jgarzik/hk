//! RTM_SETLINK / RTM_NEWLINK attributes beyond MTU and flags (hk and
//! Linux): each is applied or refused with Linux's errno, never
//! silently ignored.
//!
//! - RTNL_LINK_NETNS: moving lo into another namespace (IFLA_NET_NS_PID
//!   of a task there, or IFLA_NET_NS_FD of its namespace file) is
//!   EINVAL, lo being netns-local (Linux __dev_change_net_namespace);
//!   both attributes at once EINVAL (rtnl_ensure_unique_netns); a pid
//!   naming no task ESRCH, a bad fd EBADF, a file other than a network
//!   namespace EINVAL (get_net_ns_by_pid / get_net_ns_by_fd)
//! - RTNL_LINK_UNSUPPORTED: lo refuses IFLA_CARRIER and IFLA_PROTO_DOWN
//!   (EOPNOTSUPP: no ndo_change_carrier, no proto_down), IFLA_MASTER of
//!   a missing device is EINVAL, IFLA_MASTER 0 and IFLA_GROUP 0 are
//!   no-ops, IFLA_PERM_ADDRESS is rejected (EINVAL)

use hk_syscall::{
    CLONE_NEWNET, O_RDONLY, sys_close, sys_exit, sys_fork, sys_open, sys_pipe2, sys_read,
    sys_unshare, sys_wait4, sys_write,
};

use crate::harness::T;
use crate::net::nl::*;

const RTM_SETLINK: u16 = 19;
const IFLA_MASTER: u16 = 10;
const IFLA_NET_NS_PID: u16 = 19;
const IFLA_GROUP: u16 = 27;
const IFLA_NET_NS_FD: u16 = 28;
const IFLA_CARRIER: u16 = 33;
const IFLA_PROTO_DOWN: u16 = 39;
const IFLA_PERM_ADDRESS: u16 = 54;
const IFLA_XDP: u16 = 43;
const IFLA_XDP_FD: u16 = 1;

const EBADF: i64 = -9;
const ESRCH: i64 = -3;
const EINVAL: i64 = -22;
const EOPNOTSUPP: i64 = -95;

pub fn run_tests() {
    crate::helpers::println(b"=== RTNL Link Attribute Tests ===");
    test_netns();
    test_unsupported();
}

/// The ACK code of a request of type `ty` on lo carrying the
/// attributes `attrs` adds
fn lo_req(nl: &mut Nl, ty: u16, attrs: &dyn Fn(&mut Req)) -> i64 {
    let mut r = Req::new(ty, 0, &ifinfo(1, 0, 0));
    attrs(&mut r);
    i64::from(nl.ack(&mut r))
}

/// "/proc/<pid>/ns/net", NUL-terminated, into `buf`
fn ns_path(buf: &mut [u8; 32], pid: i64) -> &[u8] {
    let mut digits = [0u8; 20];
    let mut n = 0;
    let mut v = pid as u64;
    loop {
        digits[n] = b'0' + (v % 10) as u8;
        n += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let mut len = 0;
    for &b in b"/proc/" {
        buf[len] = b;
        len += 1;
    }
    for i in (0..n).rev() {
        buf[len] = digits[i];
        len += 1;
    }
    for &b in b"/ns/net\0" {
        buf[len] = b;
        len += 1;
    }
    &buf[..len]
}

fn test_netns() {
    let mut t = T::new(b"RTNL_LINK_NETNS");
    let Some(mut nl) = Nl::open() else {
        t.ok(b"open", false, 0);
        return t.done();
    };
    let mut ready = [0i32; 2];
    let mut stop = [0i32; 2];
    if sys_pipe2(ready.as_mut_ptr(), 0) != 0 || sys_pipe2(stop.as_mut_ptr(), 0) != 0 {
        t.ok(b"pipe", false, 0);
        return t.done();
    }
    // A child in a namespace of its own, until told to go
    let pid = sys_fork();
    if pid == 0 {
        let ok = sys_unshare(CLONE_NEWNET) == 0;
        sys_write(ready[1] as u64, [u8::from(ok)].as_ptr(), 1);
        let mut b = [0u8; 1];
        sys_read(stop[0] as u64, b.as_mut_ptr(), 1);
        sys_exit(0);
    }
    let mut b = [0u8; 1];
    let n = sys_read(ready[0] as u64, b.as_mut_ptr(), 1);
    t.ok(b"child in new netns", n == 1 && b[0] == 1, n);
    let p = pid as u32;
    for ty in [RTM_SETLINK, RTM_NEWLINK] {
        t.eq(
            b"lo to pid's netns",
            lo_req(&mut nl, ty, &|r| {
                r.u32(IFLA_NET_NS_PID, p);
            }),
            EINVAL,
        );
    }
    let mut buf = [0u8; 32];
    let nsfd = sys_open(ns_path(&mut buf, pid).as_ptr(), O_RDONLY, 0) as i32;
    t.ok(b"open ns file", nsfd >= 0, nsfd as i64);
    t.eq(
        b"lo to fd's netns",
        lo_req(&mut nl, RTM_SETLINK, &|r| {
            r.u32(IFLA_NET_NS_FD, nsfd as u32);
        }),
        EINVAL,
    );
    t.eq(
        b"pid and fd",
        lo_req(&mut nl, RTM_SETLINK, &|r| {
            r.u32(IFLA_NET_NS_PID, p).u32(IFLA_NET_NS_FD, nsfd as u32);
        }),
        EINVAL,
    );
    t.eq(
        b"no such pid",
        lo_req(&mut nl, RTM_SETLINK, &|r| {
            r.u32(IFLA_NET_NS_PID, 0x3fff_fff0);
        }),
        ESRCH,
    );
    t.eq(
        b"bad fd",
        lo_req(&mut nl, RTM_SETLINK, &|r| {
            r.u32(IFLA_NET_NS_FD, 9999);
        }),
        EBADF,
    );
    t.eq(
        b"not a netns fd",
        lo_req(&mut nl, RTM_SETLINK, &|r| {
            r.u32(IFLA_NET_NS_FD, ready[0] as u32);
        }),
        EINVAL,
    );
    sys_write(stop[1] as u64, b"x".as_ptr(), 1);
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    for f in [ready[0], ready[1], stop[0], stop[1], nsfd] {
        if f >= 0 {
            sys_close(f as u64);
        }
    }
    t.done();
}

fn test_unsupported() {
    let mut t = T::new(b"RTNL_LINK_UNSUPPORTED");
    let Some(mut nl) = Nl::open() else {
        t.ok(b"open", false, 0);
        return t.done();
    };
    t.eq(
        b"carrier",
        lo_req(&mut nl, RTM_SETLINK, &|r| {
            r.attr(IFLA_CARRIER, &[1]);
        }),
        EOPNOTSUPP,
    );
    t.eq(
        b"proto_down",
        lo_req(&mut nl, RTM_SETLINK, &|r| {
            r.attr(IFLA_PROTO_DOWN, &[0]);
        }),
        EOPNOTSUPP,
    );
    // `ip link set dev lo xdp off` with nothing attached: a no-op, 0
    // (Linux dev_xdp_attach with no old or new program)
    let mut xdp = [0u8; 8];
    xdp[..2].copy_from_slice(&8u16.to_ne_bytes());
    xdp[2..4].copy_from_slice(&IFLA_XDP_FD.to_ne_bytes());
    xdp[4..].copy_from_slice(&(-1i32).to_ne_bytes());
    t.eq(
        b"xdp off",
        lo_req(&mut nl, RTM_SETLINK, &|r| {
            r.attr(IFLA_XDP, &xdp);
        }),
        0,
    );
    t.eq(
        b"missing master",
        lo_req(&mut nl, RTM_SETLINK, &|r| {
            r.u32(IFLA_MASTER, 0x7fff_0000);
        }),
        EINVAL,
    );
    t.eq(
        b"master 0",
        lo_req(&mut nl, RTM_SETLINK, &|r| {
            r.u32(IFLA_MASTER, 0);
        }),
        0,
    );
    t.eq(
        b"group 0",
        lo_req(&mut nl, RTM_NEWLINK, &|r| {
            r.u32(IFLA_GROUP, 0);
        }),
        0,
    );
    t.eq(
        b"perm address",
        lo_req(&mut nl, RTM_SETLINK, &|r| {
            r.attr(IFLA_PERM_ADDRESS, &[0; 6]);
        }),
        EINVAL,
    );
    t.done();
}

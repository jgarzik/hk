//! NETLINK_ROUTE NLM_F_ECHO and extended ACKs (hk and Linux), each in a
//! new network namespace (only lo):
//!
//! - NL_ECHO: RTM_NEWADDR / RTM_NEWROUTE / RTM_DELADDR with NLM_F_ECHO
//!   send the notification back to the requester (Linux rtnl_notify ->
//!   nlmsg_notify with report), before its ACK, with the request's
//!   sequence and port; a requester subscribed to the group gets one
//!   copy, not two (excluded from the multicast); without NLM_F_ECHO an
//!   unsubscribed requester gets only the ACK; another subscriber gets
//!   the notification either way
//! - NL_EXT_ACK: with NETLINK_EXT_ACK, an error carries NLM_F_ACK_TLVS
//!   and NLMSGERR_ATTR_MSG (devinet's "ipv4: Invalid prefix length",
//!   "ipv4: Device not found", "ipv4: Address already assigned"); an
//!   attribute failing its policy (a 2-byte IFA_LOCAL) is ERANGE with
//!   "Attribute failed policy validation" and NLMSGERR_ATTR_OFFS at the
//!   attribute's offset in the request; with NETLINK_CAP_ACK the
//!   request is not echoed but the TLVs are; a strict dump refused for
//!   its header ends with NLMSG_DONE carrying the error and the
//!   message; without NETLINK_EXT_ACK no TLVs

use hk_syscall::{CLONE_NEWNET, sys_exit, sys_fork, sys_setsockopt, sys_unshare};

use crate::harness::{T, fail_num, pass};
use crate::helpers::{host_mode, println, skip};
use crate::net::nl::*;
use crate::net::tcp_xfer::wait_child;

const NLM_F_ECHO: u16 = 0x08;
const NLM_F_ACK_TLVS: u16 = 0x200;
const NETLINK_ADD: i32 = NETLINK_ADD_MEMBERSHIP;
const RTNLGRP_IPV4_IFADDR: i32 = 5;
const NLMSGERR_ATTR_MSG: u16 = 1;
const NLMSGERR_ATTR_OFFS: u16 = 2;
const EINVAL: i64 = -22;
const ENODEV: i64 = -19;
const EEXIST: i64 = -17;
const ERANGE: i64 = -34;

pub fn run_tests() {
    println(b"=== RTNL echo / extended ACK Tests ===");
    in_netns(b"NL_ECHO", echo);
    in_netns(b"NL_EXT_ACK", ext_ack);
}

/// Run `f` in a child in a new network namespace; the child prints its
/// own FAIL lines (exit 2: no unshare)
pub fn in_netns(name: &'static [u8], f: fn(&'static [u8]) -> bool) {
    let pid = sys_fork();
    if pid < 0 {
        fail_num(b"NETNS:FAIL fork ", pid);
        return;
    }
    if pid == 0 {
        if sys_unshare(CLONE_NEWNET) != 0 {
            sys_exit(2);
        }
        sys_exit(if f(name) { 0 } else { 1 });
    }
    let st = wait_child(pid);
    let code = (st >> 8) & 0xff;
    if st & 0x7f == 0 && code == 0 {
        pass(name);
    } else if code == 2 && host_mode() {
        skip(name, b"unshare(CLONE_NEWNET) not permitted");
    } else if code != 1 {
        crate::harness::fail_why(name, b"status", i64::from(st));
    }
}

fn setsockopt_int(fd: i32, opt: i32, v: i32) -> i64 {
    sys_setsockopt(fd, SOL_NETLINK, opt, &v as *const i32 as *const u8, 4)
}

/// What one request brought back up to its ACK
#[derive(Default)]
struct Reply {
    /// Messages of type `want` with the request's sequence
    copies: u32,
    /// Their port id
    pid: u32,
    /// The ACK's error, flags and port id (-10000: none)
    err: i32,
    flags: u16,
    ack_pid: u32,
    /// A copy came after the ACK
    late: bool,
}

/// Read up to the NLMSG_ERROR for `seq`, counting messages of type
/// `want` with that sequence
fn collect(nl: &Nl, seq: u32, want: u16) -> Reply {
    let mut r = Reply {
        err: -10000,
        ..Default::default()
    };
    let mut acked = false;
    for _ in 0..8 {
        let buf = rxbuf();
        let n = nl.recv(buf, 0);
        if n <= 0 {
            break;
        }
        each_msg(&buf[..n as usize], &mut |m| {
            if m.seq != seq {
                return;
            }
            if m.ty == NLMSG_ERROR {
                r.err = m.error();
                r.flags = m.flags;
                r.ack_pid = m.pid;
                acked = true;
            } else if m.ty == want {
                r.copies += 1;
                r.pid = m.pid;
                r.late |= acked;
            }
        });
        if acked {
            break;
        }
    }
    r
}

/// Messages waiting on `nl` (within 100 ms) of type `want` and `seq`
fn pending(nl: &Nl, seq: u32, want: u16) -> u32 {
    let mut n = 0;
    while wait_readable(nl.fd, 100) {
        let buf = rxbuf();
        let len = nl.recv(buf, 0);
        if len <= 0 {
            break;
        }
        each_msg(&buf[..len as usize], &mut |m| {
            if m.seq == seq && m.ty == want {
                n += 1;
            }
        });
    }
    n
}

/// RTM_NEWADDR / RTM_DELADDR of `ip`/32 on lo
fn lo_addr(ty: u16, flags: u16, ip: [u8; 4]) -> Req {
    let mut r = Req::new(ty, flags, &ifaddr(AF_INET, 32, 1));
    r.attr(IFA_LOCAL, &ip).attr(IFA_ADDRESS, &ip);
    r
}

fn echo(name: &'static [u8]) -> bool {
    let mut t = T::new(name);
    let (Some(mut a), Some(b)) = (Nl::open(), Nl::open()) else {
        t.ok(b"open", false, 0);
        return false;
    };
    t.eq(
        b"subscribe",
        setsockopt_int(b.fd, NETLINK_ADD, RTNLGRP_IPV4_IFADDR),
        0,
    );
    t.eq(b"lo up", i64::from(set_link_up(&mut a, 1, true)), 0);
    let ip = [10, 9, 0, 1];
    // Echoed to the unsubscribed requester before its ACK
    let mut r = lo_addr(
        RTM_NEWADDR,
        NLM_F_CREATE | NLM_F_EXCL | NLM_F_ECHO | NLM_F_ACK,
        ip,
    );
    let seq = a.send(&mut r);
    let got = collect(&a, seq, RTM_NEWADDR);
    t.eq(b"newaddr ack", i64::from(got.err), 0);
    t.eq(b"newaddr echo", i64::from(got.copies), 1);
    t.ok(b"newaddr echo first", !got.late, 1);
    t.eq(b"echo pid", i64::from(got.pid), i64::from(got.ack_pid));
    t.ok(b"echo pid set", got.pid != 0, 0);
    t.eq(b"subscriber", i64::from(pending(&b, seq, RTM_NEWADDR)), 1);
    // A route
    let mut r = Req::new(
        RTM_NEWROUTE,
        NLM_F_CREATE | NLM_F_EXCL | NLM_F_ECHO | NLM_F_ACK,
        &rtmsg(24, RT_TABLE_MAIN, RTPROT_BOOT, RT_SCOPE_LINK, RTN_UNICAST),
    );
    r.attr(RTA_DST, &[10, 9, 1, 0]).u32(RTA_OIF, 1);
    let seq = a.send(&mut r);
    let got = collect(&a, seq, RTM_NEWROUTE);
    t.eq(b"newroute ack", i64::from(got.err), 0);
    t.eq(b"newroute echo", i64::from(got.copies), 1);
    // A subscribed requester: one copy (the echo), not the multicast
    t.eq(
        b"subscribe a",
        setsockopt_int(a.fd, NETLINK_ADD, RTNLGRP_IPV4_IFADDR),
        0,
    );
    let mut r = lo_addr(RTM_DELADDR, NLM_F_ECHO | NLM_F_ACK, ip);
    let seq = a.send(&mut r);
    let got = collect(&a, seq, RTM_DELADDR);
    t.eq(b"deladdr ack", i64::from(got.err), 0);
    t.eq(b"deladdr echo", i64::from(got.copies), 1);
    t.eq(
        b"deladdr extra",
        i64::from(pending(&a, seq, RTM_DELADDR)),
        0,
    );
    t.eq(
        b"deladdr subscriber",
        i64::from(pending(&b, seq, RTM_DELADDR)),
        1,
    );
    // No NLM_F_ECHO, a fresh unsubscribed requester: the ACK only
    let Some(mut c) = Nl::open() else {
        t.ok(b"open c", false, 0);
        return false;
    };
    let mut r = lo_addr(RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK, ip);
    let seq = c.send(&mut r);
    let got = collect(&c, seq, RTM_NEWADDR);
    t.eq(b"plain ack", i64::from(got.err), 0);
    t.eq(b"plain copies", i64::from(got.copies), 0);
    t.eq(
        b"plain subscriber",
        i64::from(pending(&b, seq, RTM_NEWADDR)),
        1,
    );
    !t.failed()
}

/// The NLMSG_ERROR for request `r` on `nl`: (error, flags, message
/// TLV, offset TLV, message length)
struct ErrMsg {
    err: i64,
    flags: u16,
    msg: [u8; 64],
    msg_len: usize,
    offs: Option<u32>,
    len: usize,
}

impl ErrMsg {
    fn msg(&self) -> &[u8] {
        &self.msg[..self.msg_len]
    }
}

/// The TLVs after an NLMSG_ERROR body of `hdr` bytes
fn err_tlvs(m: &Msg, hdr: usize, e: &mut ErrMsg) {
    if let Some(s) = m.attr_str(hdr, NLMSGERR_ATTR_MSG) {
        let n = s.len().min(e.msg.len());
        e.msg[..n].copy_from_slice(&s[..n]);
        e.msg_len = n;
    }
    e.offs = m.attr_u32(hdr, NLMSGERR_ATTR_OFFS);
}

fn send_err(nl: &mut Nl, r: &mut Req) -> ErrMsg {
    r.set_flags(r.flags() | NLM_F_ACK);
    let seq = nl.send(r);
    let mut e = ErrMsg {
        err: -10000,
        flags: 0,
        msg: [0; 64],
        msg_len: 0,
        offs: None,
        len: 0,
    };
    let buf = rxbuf();
    let n = nl.recv(buf, 0);
    if n <= 0 {
        return e;
    }
    each_msg(&buf[..n as usize], &mut |m| {
        if m.ty != NLMSG_ERROR || m.seq != seq {
            return;
        }
        e.err = i64::from(m.error());
        e.flags = m.flags;
        e.len = m.body.len() + 16;
        // struct nlmsgerr: error, then the request (whole, or its
        // header when capped)
        let inner = if m.body.len() >= 8 {
            u32::from_ne_bytes([m.body[4], m.body[5], m.body[6], m.body[7]]) as usize
        } else {
            0
        };
        let hdr = if m.flags & NLM_F_CAPPED != 0 {
            4 + 16
        } else {
            4 + ((inner + 3) & !3)
        };
        err_tlvs(m, hdr, &mut e);
    });
    e
}

/// A strict RTM_GETADDR dump with a prefix length set: (DONE's error,
/// flags, message)
fn bad_dump(nl: &mut Nl) -> (i64, u16, [u8; 64], usize) {
    let mut r = Req::new(RTM_GETADDR, NLM_F_DUMP, &ifaddr(AF_INET, 8, 0));
    let seq = nl.send(&mut r);
    let mut out = (-10000i64, 0u16, [0u8; 64], 0usize);
    let buf = rxbuf();
    let n = nl.recv(buf, 0);
    if n <= 0 {
        return out;
    }
    each_msg(&buf[..n as usize], &mut |m| {
        if m.seq != seq || m.ty != NLMSG_DONE {
            return;
        }
        out.0 = i64::from(m.error());
        out.1 = m.flags;
        if let Some(s) = m.attr_str(4, NLMSGERR_ATTR_MSG) {
            let k = s.len().min(64);
            out.2[..k].copy_from_slice(&s[..k]);
            out.3 = k;
        }
    });
    out
}

fn ext_ack(name: &'static [u8]) -> bool {
    let mut t = T::new(name);
    let Some(mut nl) = Nl::open() else {
        t.ok(b"open", false, 0);
        return false;
    };
    // Without NETLINK_EXT_ACK: a plain error
    let mut r = Req::new(RTM_NEWADDR, 0, &ifaddr(AF_INET, 33, 1));
    r.attr(IFA_LOCAL, &[10, 9, 0, 2]);
    let e = send_err(&mut nl, &mut r);
    t.eq(b"plain err", e.err, EINVAL);
    t.eq(b"plain tlvs", i64::from(e.flags & NLM_F_ACK_TLVS), 0);
    t.eq(b"plain msg", e.msg_len as i64, 0);
    t.eq(b"ext_ack on", setsockopt_int(nl.fd, NETLINK_EXT_ACK, 1), 0);
    let e = send_err(&mut nl, &mut r);
    t.eq(b"prefix err", e.err, EINVAL);
    t.eq(
        b"prefix tlvs",
        i64::from(e.flags & NLM_F_ACK_TLVS),
        i64::from(NLM_F_ACK_TLVS),
    );
    t.ok(
        b"prefix msg",
        e.msg() == b"ipv4: Invalid prefix length",
        e.msg_len as i64,
    );
    // A device that does not exist
    let mut r = Req::new(RTM_NEWADDR, 0, &ifaddr(AF_INET, 32, 9999));
    r.attr(IFA_LOCAL, &[10, 9, 0, 2]);
    let e = send_err(&mut nl, &mut r);
    t.eq(b"nodev err", e.err, ENODEV);
    t.ok(
        b"nodev msg",
        e.msg() == b"ipv4: Device not found",
        e.msg_len as i64,
    );
    // An address already there
    let mut r = lo_addr(RTM_NEWADDR, NLM_F_CREATE, [10, 9, 0, 3]);
    t.eq(b"add", send_err(&mut nl, &mut r).err, 0);
    let mut r = lo_addr(RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, [10, 9, 0, 3]);
    let e = send_err(&mut nl, &mut r);
    t.eq(b"exists err", e.err, EEXIST);
    t.ok(
        b"exists msg",
        e.msg() == b"ipv4: Address already assigned",
        e.msg_len as i64,
    );
    // An attribute failing its policy: offset from the request's start
    // (nlmsghdr 16 + ifaddrmsg 8)
    let mut r = Req::new(RTM_NEWADDR, 0, &ifaddr(AF_INET, 32, 1));
    r.attr(IFA_LOCAL, &[10, 9]);
    let e = send_err(&mut nl, &mut r);
    t.eq(b"policy err", e.err, ERANGE);
    t.ok(
        b"policy msg",
        e.msg() == b"Attribute failed policy validation",
        e.msg_len as i64,
    );
    t.eq(b"policy offs", i64::from(e.offs.unwrap_or(0)), 24);
    // NETLINK_CAP_ACK: the request header only, the TLVs still
    t.eq(b"cap_ack on", setsockopt_int(nl.fd, NETLINK_CAP_ACK, 1), 0);
    let e = send_err(&mut nl, &mut r);
    t.eq(b"capped err", e.err, ERANGE);
    t.eq(
        b"capped flags",
        i64::from(e.flags),
        i64::from(NLM_F_CAPPED | NLM_F_ACK_TLVS),
    );
    t.eq(b"capped offs", i64::from(e.offs.unwrap_or(0)), 24);
    t.ok(
        b"capped msg",
        e.msg() == b"Attribute failed policy validation",
        e.msg_len as i64,
    );
    // A success has no TLVs
    let mut r = lo_addr(RTM_DELADDR, 0, [10, 9, 0, 3]);
    let e = send_err(&mut nl, &mut r);
    t.eq(b"ack err", e.err, 0);
    t.eq(b"ack flags", i64::from(e.flags), i64::from(NLM_F_CAPPED));
    t.eq(b"ack len", e.len as i64, 36);
    // A strict dump refused for its header
    t.eq(
        b"strict on",
        setsockopt_int(nl.fd, NETLINK_GET_STRICT_CHK, 1),
        0,
    );
    let (err, flags, msg, len) = bad_dump(&mut nl);
    t.eq(b"dump err", err, EINVAL);
    t.eq(
        b"dump flags",
        i64::from(flags),
        i64::from(NLM_F_MULTI | NLM_F_ACK_TLVS),
    );
    t.ok(
        b"dump msg",
        &msg[..len] == b"ipv4: Invalid values in header for address dump request",
        len as i64,
    );
    !t.failed()
}

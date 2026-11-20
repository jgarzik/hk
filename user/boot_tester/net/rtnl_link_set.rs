//! Link settings Linux always applies (hk and Linux), on lo of a new
//! network namespace:
//!
//! - RTNL_LINK_SETTINGS: IFLA_GROUP is kept and a group-wide
//!   RTM_NEWLINK (no index, no name) changes its members
//!   (rtnl_group_changelink); IFLA_IFALIAS is kept and an empty one
//!   clears it, one of IFALIASZ bytes is EINVAL (dev_set_alias);
//!   IFLA_TXQLEN is kept (dev_change_tx_queue_len); IFLA_BROADCAST is
//!   copied; GSO/GRO limits are kept up to the device's TSO limits and
//!   GRO_MAX_SIZE, beyond them EINVAL ("too big ...", validate_linkmsg)

use crate::harness::T;
use crate::net::nl::*;
use crate::net::rtnl_ack::in_netns;

const RTM_SETLINK: u16 = 19;
const IFLA_BROADCAST: u16 = 2;
const IFLA_TXQLEN: u16 = 13;
const IFLA_IFALIAS: u16 = 20;
const IFLA_GROUP: u16 = 27;
const IFLA_GSO_MAX_SEGS: u16 = 40;
const IFLA_GSO_MAX_SIZE: u16 = 41;
const IFLA_GRO_MAX_SIZE: u16 = 58;
const EINVAL: i64 = -22;

pub fn run_tests() {
    crate::helpers::println(b"=== RTNL Link Settings Tests ===");
    in_netns(b"RTNL_LINK_SETTINGS", settings);
}

/// RTM_SETLINK on lo with the attributes `f` adds
fn set(nl: &mut Nl, f: &dyn Fn(&mut Req)) -> i64 {
    let mut r = Req::new(RTM_SETLINK, 0, &ifinfo(1, 0, 0));
    f(&mut r);
    i64::from(nl.ack(&mut r))
}

/// Attribute `ty` of lo's RTM_GETLINK answer, into `out`: its length,
/// or -1 if absent
fn get_attr(nl: &mut Nl, ty: u16, out: &mut [u8; 32]) -> i64 {
    let mut r = Req::new(RTM_GETLINK, 0, &ifinfo(1, 0, 0));
    let seq = nl.send(&mut r);
    let buf = rxbuf();
    let n = nl.recv(buf, 0);
    let mut len = -1;
    if n > 0 {
        each_msg(&buf[..n as usize], &mut |m| {
            if m.seq == seq && m.ty == RTM_NEWLINK {
                if let Some(a) = m.attr(16, ty) {
                    let k = a.len().min(out.len());
                    out[..k].copy_from_slice(&a[..k]);
                    len = a.len() as i64;
                }
            }
        });
    }
    len
}

fn get_u32(nl: &mut Nl, ty: u16) -> i64 {
    let mut b = [0u8; 32];
    if get_attr(nl, ty, &mut b) < 4 {
        return -1;
    }
    i64::from(u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
}

fn settings(name: &'static [u8]) -> bool {
    let mut t = T::new(name);
    let Some(mut nl) = Nl::open() else {
        t.ok(b"open", false, 0);
        return false;
    };
    // Group, and a change to the whole group
    t.eq(
        b"group",
        set(&mut nl, &|r| {
            r.u32(IFLA_GROUP, 5);
        }),
        0,
    );
    t.eq(b"group kept", get_u32(&mut nl, IFLA_GROUP), 5);
    let mut r = Req::new(RTM_NEWLINK, 0, &ifinfo(0, 0, 0));
    r.u32(IFLA_GROUP, 5).u32(IFLA_MTU, 1500);
    t.eq(b"group change", i64::from(nl.ack(&mut r)), 0);
    t.eq(b"group mtu", get_u32(&mut nl, IFLA_MTU), 1500);
    // Alias
    t.eq(
        b"alias",
        set(&mut nl, &|r| {
            r.attr(IFLA_IFALIAS, b"uplink");
        }),
        0,
    );
    let mut b = [0u8; 32];
    let n = get_attr(&mut nl, IFLA_IFALIAS, &mut b);
    let len = b.iter().position(|&c| c == 0).unwrap_or(0);
    t.ok(b"alias kept", n > 0 && &b[..len] == b"uplink", n);
    t.eq(
        b"alias clear",
        set(&mut nl, &|r| {
            r.attr(IFLA_IFALIAS, b"");
        }),
        0,
    );
    t.eq(b"alias gone", get_attr(&mut nl, IFLA_IFALIAS, &mut b), -1);
    t.eq(
        b"alias long",
        set(&mut nl, &|r| {
            r.attr(IFLA_IFALIAS, &[b'a'; 256]);
        }),
        EINVAL,
    );
    // Transmit queue length
    t.eq(
        b"txqlen",
        set(&mut nl, &|r| {
            r.u32(IFLA_TXQLEN, 500);
        }),
        0,
    );
    t.eq(b"txqlen kept", get_u32(&mut nl, IFLA_TXQLEN), 500);
    // Broadcast address
    let bc = [0x02, 1, 2, 3, 4, 5];
    t.eq(
        b"broadcast",
        set(&mut nl, &|r| {
            r.attr(IFLA_BROADCAST, &bc);
        }),
        0,
    );
    let n = get_attr(&mut nl, IFLA_BROADCAST, &mut b);
    t.ok(b"broadcast kept", n == 6 && b[..6] == bc, n);
    // GSO / GRO limits
    t.eq(
        b"gso size",
        set(&mut nl, &|r| {
            r.u32(IFLA_GSO_MAX_SIZE, 32768);
        }),
        0,
    );
    t.eq(b"gso size kept", get_u32(&mut nl, IFLA_GSO_MAX_SIZE), 32768);
    t.eq(
        b"gso segs",
        set(&mut nl, &|r| {
            r.u32(IFLA_GSO_MAX_SEGS, 100);
        }),
        0,
    );
    t.eq(b"gso segs kept", get_u32(&mut nl, IFLA_GSO_MAX_SEGS), 100);
    t.eq(
        b"gro size",
        set(&mut nl, &|r| {
            r.u32(IFLA_GRO_MAX_SIZE, 32768);
        }),
        0,
    );
    t.eq(b"gro size kept", get_u32(&mut nl, IFLA_GRO_MAX_SIZE), 32768);
    t.eq(
        b"gso too big",
        set(&mut nl, &|r| {
            r.u32(IFLA_GSO_MAX_SIZE, 0x7fff_0000);
        }),
        EINVAL,
    );
    t.eq(
        b"segs too big",
        set(&mut nl, &|r| {
            r.u32(IFLA_GSO_MAX_SEGS, 70000);
        }),
        EINVAL,
    );
    t.eq(
        b"gro too big",
        set(&mut nl, &|r| {
            r.u32(IFLA_GRO_MAX_SIZE, 0x7fff_0000);
        }),
        EINVAL,
    );
    !t.failed()
}

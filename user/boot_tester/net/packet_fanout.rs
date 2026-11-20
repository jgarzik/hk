//! AF_PACKET fanout (hk and Linux), after Linux
//! tools/testing/selftests/net/psock_fanout.c: PACKET_FANOUT's rules
//! (types, flags, binding, EALREADY, ENOSPC, unique ids), the modes'
//! distribution of frames sent over lo (LB alternates, HASH keeps a
//! flow together, QM and CBPF pick by queue and program, ROLLOVER
//! passes on what a full member cannot take), PACKET_FANOUT_DATA and
//! PACKET_ROLLOVER_STATS, and a member leaving.

use hk_syscall::{SOCK_RAW, sys_getsockopt, sys_setsockopt};

use crate::harness::T;
use crate::helpers::println;
use crate::net::nl::msleep;
use crate::net::packet::{
    ETH_P_TEST, SOL_PACKET, Sll, fprog, ifindex, pbind, psock, sendto_ll, test_frame,
};
use crate::net::sk::*;

const PACKET_FANOUT: i32 = 18;
const PACKET_ROLLOVER_STATS: i32 = 21;
const PACKET_FANOUT_DATA: i32 = 22;

const HASH: u16 = 0;
const LB: u16 = 1;
const ROLLOVER: u16 = 3;
const QM: u16 = 5;
const CBPF: u16 = 6;
const EBPF: u16 = 7;
const FLAG_ROLLOVER: u16 = 0x1000;
const FLAG_UNIQUEID: u16 = 0x2000;

const EBUSY_NOSPC: i64 = -28;
const SO_ATTACH_FILTER: i32 = 26;
const SO_LOCK_FILTER: i32 = 44;

pub fn run_tests() {
    println(b"=== AF_PACKET fanout Tests ===");
    let lo = ifindex(b"lo");
    test_rules(lo);
    test_mode(lo, LB, 0x4b10, b"PACKET_FANOUT_LB");
    test_mode(lo, HASH, 0x4b11, b"PACKET_FANOUT_HASH");
    test_mode(lo, QM, 0x4b12, b"PACKET_FANOUT_QM");
    test_cbpf(lo);
    test_rollover(lo);
}

/// A member: SOCK_RAW for ETH_P_TEST on lo
fn member(lo: i32) -> i32 {
    let fd = psock(SOCK_RAW, ETH_P_TEST);
    pbind(fd, ETH_P_TEST, lo);
    fd
}

/// setsockopt(PACKET_FANOUT) as an int
fn join(fd: i32, id: u16, type_flags: u16) -> i64 {
    setint(
        fd,
        SOL_PACKET,
        PACKET_FANOUT,
        (id as u32 | (type_flags as u32) << 16) as i32,
    )
}

/// setsockopt(PACKET_FANOUT) with struct fanout_args
fn join_max(fd: i32, id: u16, type_flags: u16, max: u32) -> i64 {
    let a = [(id as u32 | (type_flags as u32) << 16), max];
    sys_setsockopt(fd, SOL_PACKET, PACKET_FANOUT, a.as_ptr() as *const u8, 8)
}

/// Send `n` test frames of `len` bytes to lo
fn burst(lo: i32, n: usize, len: usize) {
    let tx = psock(SOCK_RAW, 0);
    let mut b = [0u8; 1100];
    for i in 0..n {
        sendto_ll(
            tx,
            test_frame(&mut b, i as u8, len),
            &Sll::new(ETH_P_TEST, lo),
            20,
        );
    }
    close(tx);
    msleep(200);
}

/// Frames queued on `fd`, drained
fn count(fd: i32) -> i64 {
    let mut b = [0u8; 1100];
    let mut n = 0;
    while recv(fd, &mut b, MSG_DONTWAIT) > 0 {
        n += 1;
    }
    n
}

/// PACKET_FANOUT's argument rules (Linux fanout_add)
fn test_rules(lo: i32) {
    let mut t = T::new(b"PACKET_FANOUT_RULES");
    let a = member(lo);
    let v = [0u8; 4];
    t.eq(
        b"optlen",
        sys_setsockopt(a, SOL_PACKET, PACKET_FANOUT, v.as_ptr(), 2),
        EINVAL,
    );
    t.eq(b"bad type", join(a, 0x4b00, 8), EINVAL);
    t.eq(
        b"rollover flag",
        join(a, 0x4b00, ROLLOVER | FLAG_ROLLOVER),
        EINVAL,
    );
    t.eq(b"max too big", join_max(a, 0x4b00, LB, 0x10001), EINVAL);
    t.eq(
        b"data no group",
        setint(a, SOL_PACKET, PACKET_FANOUT_DATA, 0),
        EINVAL,
    );
    t.eq(
        b"stats no rollover",
        getint(a, SOL_PACKET, PACKET_ROLLOVER_STATS).0,
        EINVAL,
    );
    let idle = psock(SOCK_RAW, 0);
    t.eq(b"no protocol", join(idle, 0x4b00, LB), EINVAL);
    close(idle);
    t.eq(b"join", join_max(a, 0x4b00, LB, 1), 0);
    t.eq(
        b"get",
        getint(a, SOL_PACKET, PACKET_FANOUT).1 as i64,
        0x4b00 | (LB as i64) << 16,
    );
    t.eq(b"again", join(a, 0x4b00, LB), EALREADY);
    t.eq(b"bind in group", pbind(a, ETH_P_TEST, 0), EINVAL);
    let b = member(lo);
    t.eq(b"other type", join(b, 0x4b00, HASH), EINVAL);
    t.eq(b"other flags", join(b, 0x4b00, LB | FLAG_ROLLOVER), EINVAL);
    t.eq(b"other max", join_max(b, 0x4b00, LB, 2), EINVAL);
    t.eq(b"full", join(b, 0x4b00, LB), EBUSY_NOSPC);
    let c = psock(SOCK_RAW, ETH_P_TEST);
    t.eq(b"other device", join(c, 0x4b00, LB), EINVAL);
    close(c);
    t.eq(b"unique with id", join(b, 1, LB | FLAG_UNIQUEID), EINVAL);
    t.eq(b"unique", join(b, 0, LB | FLAG_UNIQUEID), 0);
    let g = getint(b, SOL_PACKET, PACKET_FANOUT).1 as u32;
    t.eq(b"unique type, no flag", (g >> 16) as i64, LB as i64);
    t.ok(b"unique id", g & 0xffff != 0x4b00, g as i64);
    let r = member(lo);
    t.eq(b"rollover", join(r, 0x4b01, LB | FLAG_ROLLOVER), 0);
    let mut st = [0u64; 3];
    let mut len = 24u32;
    let n = sys_getsockopt(
        r,
        SOL_PACKET,
        PACKET_ROLLOVER_STATS,
        st.as_mut_ptr() as *mut u8,
        &mut len,
    );
    t.eq(b"rollover stats", n, 0);
    t.eq(b"rollover stats len", len as i64, 24);
    // PACKET_FANOUT_EBPF: an fd that is no BPF program
    let e = member(lo);
    t.eq(b"ebpf", join(e, 0x4b02, EBPF), 0);
    let u = udp();
    let v = [u as u32, 0];
    let set = |len: u32| {
        sys_setsockopt(
            e,
            SOL_PACKET,
            PACKET_FANOUT_DATA,
            v.as_ptr() as *const u8,
            len,
        )
    };
    t.eq(b"ebpf len", set(8), EINVAL);
    t.eq(b"ebpf not bpf", set(4), EINVAL);
    let bad = [9999u32];
    t.eq(
        b"ebpf bad fd",
        sys_setsockopt(
            e,
            SOL_PACKET,
            PACKET_FANOUT_DATA,
            bad.as_ptr() as *const u8,
            4,
        ),
        EBADF,
    );
    close(u);
    close(e);
    close(r);
    close(b);
    close(a);
    t.done();
}

/// Two members of a group of `mode`: LB alternates, HASH and QM send
/// everything to one (one flow; queue 0, the first member)
fn test_mode(lo: i32, mode: u16, id: u16, name: &'static [u8]) {
    let mut t = T::new(name);
    let a = member(lo);
    let b = member(lo);
    t.eq(b"join a", join(a, id, mode), 0);
    t.eq(b"join b", join(b, id, mode), 0);
    burst(lo, 10, 60);
    let (na, nb) = (count(a), count(b));
    t.eq(b"all", na + nb, 10);
    match mode {
        LB => {
            t.eq(b"a half", na, 5);
            t.eq(b"b half", nb, 5);
        }
        QM => {
            t.eq(b"first member", na, 10);
        }
        _ => {
            t.ok(b"one flow, one member", na == 10 || nb == 10, na);
        }
    };
    if mode == LB {
        close(a);
        burst(lo, 4, 60);
        t.eq(b"after leave", count(b), 4);
    } else {
        close(a);
    }
    close(b);
    t.done();
}

/// PACKET_FANOUT_CBPF: the program's return picks the member
/// (modulo the members); a locked filter is EPERM
fn test_cbpf(lo: i32) {
    let mut t = T::new(b"PACKET_FANOUT_CBPF");
    let a = member(lo);
    let b = member(lo);
    t.eq(b"join a", join(a, 0x4b13, CBPF), 0);
    t.eq(b"join b", join(b, 0x4b13, CBPF), 0);
    // No program yet: member 0
    burst(lo, 3, 60);
    t.eq(b"no program", count(a), 3);
    let mut ins = [0u8; 128];
    let p = fprog(&[(0x06, 0, 0, 3)], &mut ins);
    t.eq(
        b"data",
        sys_setsockopt(a, SOL_PACKET, PACKET_FANOUT_DATA, p.as_ptr(), 16),
        0,
    );
    burst(lo, 4, 60);
    t.eq(b"ret 3 -> b", count(b), 4);
    t.eq(b"none to a", count(a), 0);
    t.eq(
        b"short",
        sys_setsockopt(a, SOL_PACKET, PACKET_FANOUT_DATA, p.as_ptr(), 8),
        EINVAL,
    );
    let _ = SO_ATTACH_FILTER;
    t.eq(b"lock", setint(b, SOL_SOCKET, SO_LOCK_FILTER, 1), 0);
    t.eq(
        b"locked",
        sys_setsockopt(b, SOL_PACKET, PACKET_FANOUT_DATA, p.as_ptr(), 16),
        EPERM,
    );
    close(a);
    close(b);
    t.done();
}

/// PACKET_FANOUT_ROLLOVER: a member with a tiny receive buffer passes
/// frames on to the next; PACKET_ROLLOVER_STATS counts them
fn test_rollover(lo: i32) {
    let mut t = T::new(b"PACKET_FANOUT_ROLLOVER");
    let a = member(lo);
    setint(a, SOL_SOCKET, SO_RCVBUF, 0);
    let b = member(lo);
    t.eq(b"join a", join(a, 0x4b14, ROLLOVER), 0);
    t.eq(b"join b", join(b, 0x4b14, ROLLOVER), 0);
    burst(lo, 20, 1000);
    let (na, nb) = (count(a), count(b));
    t.eq(b"all", na + nb, 20);
    t.ok(b"rolled over", nb > 0, nb);
    let mut st = [0u64; 3];
    let mut len = 24u32;
    sys_getsockopt(
        a,
        SOL_PACKET,
        PACKET_ROLLOVER_STATS,
        st.as_mut_ptr() as *mut u8,
        &mut len,
    );
    t.ok(b"tp_all", st[0] > 0, st[0] as i64);
    close(a);
    close(b);
    t.done();
}

//! Pid numbers in procfs (Linux fs/proc/root.c, base.c, array.c: a
//! procfs belongs to the pid namespace of whoever mounted it) and in a
//! pidfd's fdinfo (fs/pidfs.c)
//!
//! As in `pidns`, each test runs in a forked process X whose child Y
//! is pid 1 of a new namespace, here with a new mount namespace too and
//! that namespace's procfs mounted at MP.
//! - PIDNS_PROC_MOUNT: MP lists only the namespace's processes (1 and
//!   Y's child 2), MP/self is 1, MP/1 is Y, a number outside is ENOENT,
//!   MP/1/task holds 1;
//! - PIDNS_PROC_STATUS_NSPID: status read through /proc (root
//!   namespace) gives Y's outer Pid and NSpid/NStgid with both numbers,
//!   NSpgid X then 0 (X's group is outside); through MP one number,
//!   PPid 0 for Y, 1 for its child;
//! - PIDNS_PROC_STAT: MP/1/stat names pid 1, ppid, pgrp and session 0;
//!   MP/2/stat ppid 1; /proc/self/stat Y's outer pid, ppid and pgrp X;
//! - PIDNS_PIDFD_FDINFO: a pidfd's fdinfo gives Pid: and NSpid: from
//!   the reading procfs's namespace down (outer: two numbers; MP: 1).

use super::pidns::{child, first_fail, outer, status};
use crate::helpers::{msleep, println, read_file};
use hk_syscall::{
    CLONE_NEWNS, CLONE_NEWPID, O_DIRECTORY, O_RDONLY, SIGKILL, sys_clone, sys_close, sys_exit,
    sys_getdents64, sys_getpid, sys_kill, sys_mkdir, sys_mount, sys_open, sys_pidfd_open,
    sys_readlink, sys_rmdir, sys_setsid, sys_umount2,
};

const SIGCHLD: u64 = 17;
const ENOENT: i64 = -2;
const MS_REC: u64 = 0x4000;
const MS_PRIVATE: u64 = 1 << 18;
const MNT_DETACH: u64 = 2;
/// Where Y mounts its namespace's procfs
const MP: &[u8] = b"/tmp/pnsp\0";

pub fn run_tests() {
    println(b"[PIDNS PROC TESTS]");
    sys_mkdir(MP.as_ptr(), 0o755);
    outer(b"PIDNS_PROC_MOUNT", || in_ns(proc_mount));
    outer(b"PIDNS_PROC_STATUS_NSPID", || in_ns(status_nspid));
    outer(b"PIDNS_PROC_STAT", || in_ns(stat));
    outer(b"PIDNS_PIDFD_FDINFO", || in_ns(pidfd_fdinfo));
    sys_rmdir(MP.as_ptr());
}

/// X's pid, for Y to check (set by X before Y exists)
static mut X_PID: i64 = 0;

fn x_pid() -> i64 {
    // SAFETY: written by X before Y is made
    unsafe { core::ptr::read_volatile(&raw const X_PID) }
}

/// X: Y in new pid and mount namespaces runs `f` with the namespace's
/// procfs at MP and a child (2) that waits to be killed; Y's status
fn in_ns(f: fn(i64) -> i32) -> i32 {
    // X's own group and session, numbered outside Y's namespace
    if sys_setsid() < 0 {
        return 60;
    }
    // SAFETY: X is single-threaded and Y does not exist yet
    unsafe { core::ptr::write_volatile(&raw mut X_PID, sys_getpid()) };
    // SAFETY: F is read by Y only, set before the clone
    unsafe { core::ptr::write_volatile(&raw mut F, Some(f)) };
    let y = sys_clone(CLONE_NEWPID | CLONE_NEWNS | SIGCHLD, 0, 0, 0, 0);
    if y == 0 {
        sys_exit(ns_init() as u64);
    }
    status(y) as i32
}

/// The test Y runs
static mut F: Option<fn(i64) -> i32> = None;

/// Y: private mounts, procfs at MP, a child; the test's result (50+ if
/// the setup failed)
fn ns_init() -> i32 {
    let none = core::ptr::null();
    if sys_mount(
        b"none\0".as_ptr(),
        b"/\0".as_ptr(),
        none,
        MS_REC | MS_PRIVATE,
        0,
    ) != 0
    {
        return 50;
    }
    if sys_mount(b"proc\0".as_ptr(), MP.as_ptr(), b"proc\0".as_ptr(), 0, 0) != 0 {
        return 51;
    }
    let z = child(|| {
        loop {
            msleep(1000);
        }
    });
    // SAFETY: set by X before the clone
    let f = unsafe { core::ptr::read_volatile(&raw const F) };
    let r = f.map_or(52, |f| f(z));
    sys_kill(z, SIGKILL);
    status(z);
    sys_umount2(MP.as_ptr(), MNT_DETACH);
    r
}

/// `MP` joined with `rest` (NUL-terminated)
fn mp(rest: &[u8], out: &mut [u8; 96]) -> usize {
    let base = &MP[..MP.len() - 1];
    out[..base.len()].copy_from_slice(base);
    out[base.len()..base.len() + rest.len()].copy_from_slice(rest);
    base.len() + rest.len()
}

/// The contents of file `path` (empty if it cannot be read)
fn read(path: &[u8], buf: &mut [u8]) -> usize {
    read_file(path, buf).max(0) as usize
}

/// The contents of `MP` + `rest`
fn read_mp(rest: &[u8], buf: &mut [u8]) -> usize {
    let mut p = [0u8; 96];
    mp(rest, &mut p);
    read(&p, buf)
}

/// The text after `key` on its line (e.g. "NSpid:")
fn line<'a>(buf: &'a [u8], key: &[u8]) -> &'a [u8] {
    buf.split(|&c| c == b'\n')
        .find(|l| l.starts_with(key))
        .map_or(&[][..], |l| &l[key.len()..])
}

/// Tab-separated numbers (up to 4; -1 for an unparsable one) and how
/// many there were
fn nums(s: &[u8]) -> ([i64; 4], usize) {
    let mut out = [-1i64; 4];
    let mut n = 0;
    for f in s.split(|&c| c == b'\t').filter(|f| !f.is_empty()) {
        if n < 4 {
            out[n] = num(f);
        }
        n += 1;
    }
    (out, n)
}

/// A decimal (with an optional '-'), -1000 if not one
fn num(f: &[u8]) -> i64 {
    let (neg, d) = match f.split_first() {
        Some((b'-', r)) => (true, r),
        _ => (false, f),
    };
    if d.is_empty() || !d.iter().all(u8::is_ascii_digit) {
        return -1000;
    }
    let v = d.iter().fold(0i64, |a, &c| a * 10 + i64::from(c - b'0'));
    if neg { -v } else { v }
}

/// The numeric entries of directory `path`: how many, and a bit for
/// each below 64
fn pid_entries(path: &[u8]) -> (u32, u64) {
    let fd = sys_open(path.as_ptr(), O_RDONLY | O_DIRECTORY, 0);
    if fd < 0 {
        return (0, 0);
    }
    let (mut count, mut bits) = (0, 0u64);
    let mut buf = [0u8; 4096];
    loop {
        let n = sys_getdents64(fd as u64, buf.as_mut_ptr(), buf.len() as u64);
        if n <= 0 {
            break;
        }
        let mut off = 0;
        while off < n as usize {
            let reclen = u16::from_ne_bytes([buf[off + 16], buf[off + 17]]) as usize;
            let nm = &buf[off + 19..off + reclen];
            let end = nm.iter().position(|&c| c == 0).unwrap_or(nm.len());
            let v = num(&nm[..end]);
            if v >= 0 {
                count += 1;
                if v < 64 {
                    bits |= 1 << v;
                }
            }
            off += reclen;
        }
    }
    sys_close(fd as u64);
    (count, bits)
}

/// readlink of `MP` + `rest` as a number
fn link_mp(rest: &[u8]) -> i64 {
    let mut p = [0u8; 96];
    mp(rest, &mut p);
    let mut b = [0u8; 32];
    let n = sys_readlink(p.as_ptr(), b.as_mut_ptr(), b.len() as u64);
    if n < 0 { n } else { num(&b[..n as usize]) }
}

fn exists_mp(rest: &[u8]) -> i64 {
    let mut p = [0u8; 96];
    mp(rest, &mut p);
    let fd = sys_open(p.as_ptr(), O_RDONLY, 0);
    if fd >= 0 {
        sys_close(fd as u64);
        0
    } else {
        fd
    }
}

fn proc_mount(z: i64) -> i32 {
    let mut p = [0u8; 96];
    mp(b"\0", &mut p);
    let (count, bits) = pid_entries(&p);
    let mut b = [0u8; 4096];
    let n = read_mp(b"/1/status\0", &mut b);
    let pid1 = nums(line(&b[..n], b"Pid:"));
    first_fail(&[
        z == 2,
        count == 2,
        bits == 0b110,
        link_mp(b"/self\0") == 1,
        pid1.1 == 1 && pid1.0[0] == 1,
        exists_mp(b"/2/stat\0") == 0,
        exists_mp(b"/3\0") == ENOENT,
        exists_mp(b"/1/task/1/stat\0") == 0,
        exists_mp(b"/1/task/2\0") == ENOENT,
    ])
}

fn status_nspid(_z: i64) -> i32 {
    let mut b = [0u8; 4096];
    let n = read(b"/proc/self/status\0", &mut b);
    let o = &b[..n];
    let (pid, np) = nums(line(o, b"Pid:"));
    let (nspid, nn) = nums(line(o, b"NSpid:"));
    let (nstgid, nt) = nums(line(o, b"NStgid:"));
    let (nspgid, ng) = nums(line(o, b"NSpgid:"));
    let outer_ok = np == 1
        && pid[0] > 1
        && nn == 2
        && nspid[0] == pid[0]
        && nspid[1] == 1
        && nt == 2
        && nstgid == nspid
        && ng == 2
        && nspgid[0] == x_pid()
        && nspgid[1] == 0;
    let mut c = [0u8; 4096];
    let n = read_mp(b"/self/status\0", &mut c);
    let i = &c[..n];
    let inner_ok = nums(line(i, b"NSpid:")) == ([1, -1, -1, -1], 1)
        && nums(line(i, b"NStgid:")) == ([1, -1, -1, -1], 1)
        && nums(line(i, b"NSpgid:")) == ([0, -1, -1, -1], 1)
        && nums(line(i, b"PPid:")) == ([0, -1, -1, -1], 1);
    let n = read_mp(b"/2/status\0", &mut c);
    let z = &c[..n];
    let child_ok = nums(line(z, b"PPid:")) == ([1, -1, -1, -1], 1)
        && nums(line(z, b"NSpid:")) == ([2, -1, -1, -1], 1);
    first_fail(&[outer_ok, inner_ok, child_ok])
}

/// Fields 1, 4, 5, 6 of a stat line (pid, ppid, pgrp, session)
fn stat_ids(b: &[u8]) -> [i64; 4] {
    let pid = b.split(|&c| c == b' ').next().map_or(-1, num);
    // Past the comm's closing paren: state, ppid, pgrp, session
    let rest = b
        .iter()
        .rposition(|&c| c == b')')
        .map_or(&[][..], |i| &b[i + 2..]);
    let mut f = rest.split(|&c| c == b' ').skip(1).map(num);
    let mut next = || f.next().unwrap_or(-1);
    [pid, next(), next(), next()]
}

fn stat(_z: i64) -> i32 {
    let mut b = [0u8; 1024];
    let n = read_mp(b"/1/stat\0", &mut b);
    let inner = stat_ids(&b[..n]);
    let n = read_mp(b"/2/stat\0", &mut b);
    let kid = stat_ids(&b[..n]);
    let n = read(b"/proc/self/stat\0", &mut b);
    let outer = stat_ids(&b[..n]);
    first_fail(&[
        inner == [1, 0, 0, 0],
        kid[0] == 2 && kid[1] == 1,
        outer[0] > 1 && outer[1] == x_pid() && outer[2] == x_pid(),
    ])
}

fn pidfd_fdinfo(_z: i64) -> i32 {
    let fd = sys_pidfd_open(1, 0);
    if fd < 0 {
        return 20;
    }
    // "/self/fdinfo/<fd>"
    let mut rest = [0u8; 32];
    let pre = b"/self/fdinfo/";
    rest[..pre.len()].copy_from_slice(pre);
    let mut k = pre.len();
    let mut d = [0u8; 4];
    let (mut v, mut m) = (fd as u32, 0);
    loop {
        d[m] = b'0' + (v % 10) as u8;
        m += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for i in 0..m {
        rest[k] = d[m - 1 - i];
        k += 1;
    }
    let mut outer = [0u8; 40];
    outer[..5].copy_from_slice(b"/proc");
    outer[5..5 + k].copy_from_slice(&rest[..k]);
    let mut b = [0u8; 1024];
    let n = read(&outer[..6 + k], &mut b);
    let o = &b[..n];
    let (pid, _) = nums(line(o, b"Pid:"));
    let (nspid, nn) = nums(line(o, b"NSpid:"));
    let outer_ok = pid[0] > 1 && nn == 2 && nspid[0] == pid[0] && nspid[1] == 1;
    let mut c = [0u8; 1024];
    let n = read_mp(&rest[..k + 1], &mut c);
    let i = &c[..n];
    let inner_ok = nums(line(i, b"Pid:")) == ([1, -1, -1, -1], 1)
        && nums(line(i, b"NSpid:")) == ([1, -1, -1, -1], 1);
    sys_close(fd as u64);
    first_fail(&[outer_ok, inner_ok])
}

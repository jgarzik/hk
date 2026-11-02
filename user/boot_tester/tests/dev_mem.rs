//! The memory character devices beyond null and zero (Linux
//! drivers/char/mem.c and random.c)
//!
//! Tests:
//! - DEV_MEM_NODES: /dev/full, /dev/random and /dev/urandom are
//!   character devices 1:7, 1:8 and 1:9
//! - DEV_FULL: reads zeros; a write fails with ENOSPC
//! - DEV_URANDOM: a 4KB read is whole, two reads differ, writes are
//!   accepted whole
//! - DEV_RANDOM: a read does not block (the CRNG is ready) and returns
//!   the bytes asked for

use super::helpers::{print, println};
use hk_syscall::{O_RDONLY, O_RDWR, Stat, sys_close, sys_open, sys_read, sys_stat, sys_write};

const ENOSPC: i64 = -28;
const S_IFMT: u32 = 0o170000;
const S_IFCHR: u32 = 0o020000;

pub fn run_tests() {
    nodes();
    full();
    urandom();
    random();
}

fn report(name: &[u8], why: &[u8]) {
    print(name);
    if why.is_empty() {
        println(b":OK");
    } else {
        print(b":FAIL ");
        println(why);
    }
}

/// Linux new_encode_dev's major and minor of st_rdev
fn dev(rdev: u64) -> (u64, u64) {
    ((rdev >> 8) & 0xfff, (rdev & 0xff) | ((rdev >> 12) & 0xfff00))
}

fn nodes() {
    for (path, minor) in [
        (&b"/dev/full\0"[..], 7),
        (b"/dev/random\0", 8),
        (b"/dev/urandom\0", 9),
    ] {
        // SAFETY: plain integers
        let mut st: Stat = unsafe { core::mem::zeroed() };
        if sys_stat(path.as_ptr(), &mut st) != 0 {
            return report(b"DEV_MEM_NODES", b"stat");
        }
        if st.st_mode & S_IFMT != S_IFCHR || dev(st.st_rdev) != (1, minor) {
            return report(b"DEV_MEM_NODES", b"wrong node");
        }
    }
    report(b"DEV_MEM_NODES", b"");
}

fn full() {
    let fd = sys_open(b"/dev/full\0".as_ptr(), O_RDWR, 0);
    if fd < 0 {
        return report(b"DEV_FULL", b"open");
    }
    let mut buf = [0x5au8; 64];
    let n = sys_read(fd as u64, buf.as_mut_ptr(), 64);
    let w = sys_write(fd as u64, buf.as_ptr(), 64);
    sys_close(fd as u64);
    let why: &[u8] = if n != 64 || buf.iter().any(|&b| b != 0) {
        b"read not zeros"
    } else if w != ENOSPC {
        b"write not ENOSPC"
    } else {
        b""
    };
    report(b"DEV_FULL", why);
}

fn urandom() {
    let fd = sys_open(b"/dev/urandom\0".as_ptr(), O_RDWR, 0);
    if fd < 0 {
        return report(b"DEV_URANDOM", b"open");
    }
    let mut a = [0u8; 4096];
    let mut b = [0u8; 4096];
    let na = sys_read(fd as u64, a.as_mut_ptr(), a.len() as u64);
    let nb = sys_read(fd as u64, b.as_mut_ptr(), b.len() as u64);
    let w = sys_write(fd as u64, b"seed".as_ptr(), 4);
    sys_close(fd as u64);
    let why: &[u8] = if na != 4096 || nb != 4096 {
        b"short read"
    } else if a == b || a.iter().all(|&x| x == 0) {
        b"not random"
    } else if w != 4 {
        b"write"
    } else {
        b""
    };
    report(b"DEV_URANDOM", why);
}

fn random() {
    let fd = sys_open(b"/dev/random\0".as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        return report(b"DEV_RANDOM", b"open");
    }
    let mut a = [0u8; 32];
    let n = sys_read(fd as u64, a.as_mut_ptr(), 32);
    sys_close(fd as u64);
    report(
        b"DEV_RANDOM",
        if n == 32 && a.iter().any(|&x| x != 0) {
            b""
        } else {
            b"read"
        },
    );
}

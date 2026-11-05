//! TCP memory limits (Linux tcp_mem, __sk_mem_raise_allocated).
//!
//! - TCP_MEM_SYSCTL: /proc/sys/net/ipv4/tcp_mem holds three page counts
//!   sized from RAM as tcp_init_mem (min = 3/4 of pressure, max = twice
//!   min); it takes writes back as written and refuses negative values.
//! - TCP_MEM_NETNS: from another network namespace tcp_mem cannot be
//!   changed (Linux: no such file there; hk: EPERM), nor is it.
//! - MEM_PCPU_RSV: net.core.mem_pcpu_rsv, the per-CPU reserve batching
//!   the count (1 MiB in pages), refuses less than that.
//! - TCP_MEM_PRESSURE: with every limit at 4 pages, 8 loopback pairs each
//!   move 128 KiB intact (charges forced for empty queues keep every
//!   connection progressing), and the limits restore. Senders stay open
//!   until their reader is done: an orphan holding send data past the
//!   hard limit is reset (tcp_out_of_resources).

use hk_syscall::{sys_exit, sys_fork};

use super::sk::*;
use super::sysctl::{read_file, write_file};
use super::tcp_xfer::{accept, listener, recv_pat, send_pat, set_timeo, wait_child};

const PATH: &[u8] = b"/proc/sys/net/ipv4/tcp_mem\0";
const EINVAL: i64 = -22;
const PAIRS: usize = 8;
const LEN: usize = 128 * 1024;

pub fn run_tests() {
    let mut old = [0u8; 96];
    let n = read_file(PATH, &mut old);
    test_sysctl(&old[..n.max(0) as usize]);
    test_pcpu_rsv();
    test_netns();
    test_pressure();
    if n > 0 {
        write_file(PATH, &old[..n as usize]);
    }
}

/// The three tab-separated values of a read, if well-formed
fn parse(b: &[u8]) -> Option<[u64; 3]> {
    let b = b.strip_suffix(b"\n")?;
    let mut v = [0u64; 3];
    let mut it = b.split(|&c| c == b'\t');
    for x in v.iter_mut() {
        let f = it.next()?;
        if f.is_empty() || !f.iter().all(u8::is_ascii_digit) {
            return None;
        }
        *x = f.iter().fold(0, |a, &d| a * 10 + (d - b'0') as u64);
    }
    it.next().is_none().then_some(v)
}

fn test_sysctl(old: &[u8]) {
    let mut t = T::new(b"TCP_MEM_SYSCTL");
    match parse(old) {
        Some([a, b, c]) => {
            t.ok(b"min < pressure", a < b, a as i64);
            t.ok(b"max = 2 min", c == 2 * a, c as i64);
            t.ok(b"pressure >= 128", b >= 128, b as i64);
        }
        None => {
            t.ok(b"format", false, old.len() as i64);
        }
    }
    t.eq(b"write", write_file(PATH, b"100 200 300\n"), 12);
    let mut buf = [0u8; 96];
    let n = read_file(PATH, &mut buf);
    t.ok(
        b"read back",
        parse(&buf[..n.max(0) as usize]) == Some([100, 200, 300]),
        n,
    );
    t.eq(b"negative", write_file(PATH, b"-1 200 300\n"), EINVAL);
    let n = read_file(PATH, &mut buf);
    t.ok(
        b"unchanged",
        parse(&buf[..n.max(0) as usize]) == Some([100, 200, 300]),
        n,
    );
    t.done();
}

fn test_netns() {
    let mut t = T::new(b"TCP_MEM_NETNS");
    let mut before = [0u8; 96];
    let n = read_file(PATH, &mut before);
    let pid = sys_fork();
    if pid == 0 {
        if hk_syscall::sys_unshare(hk_syscall::CLONE_NEWNET) != 0 {
            sys_exit(1);
        }
        sys_exit(if write_file(PATH, b"1 1 1\n") < 0 {
            0
        } else {
            2
        });
    }
    t.eq(b"child", wait_child(pid) as i64, 0);
    let mut after = [0u8; 96];
    let m = read_file(PATH, &mut after);
    t.ok(
        b"unchanged",
        n > 0 && before[..n as usize] == after[..m.max(0) as usize],
        m,
    );
    t.done();
}

fn test_pcpu_rsv() {
    const RSV: &[u8] = b"/proc/sys/net/core/mem_pcpu_rsv\0";
    let mut t = T::new(b"MEM_PCPU_RSV");
    let mut buf = [0u8; 32];
    let n = read_file(RSV, &mut buf);
    t.ok(b"default", n > 0 && &buf[..n as usize] == b"256\n", n);
    t.eq(b"below", write_file(RSV, b"255\n"), EINVAL);
    t.eq(b"raise", write_file(RSV, b"512\n"), 4);
    let n = read_file(RSV, &mut buf);
    t.ok(b"read back", n > 0 && &buf[..n as usize] == b"512\n", n);
    write_file(RSV, b"256\n");
    t.done();
}

fn test_pressure() {
    let mut t = T::new(b"TCP_MEM_PRESSURE");
    t.eq(b"limits", write_file(PATH, b"4 4 4\n"), 6);
    let mut pids = [0i64; PAIRS];
    for (i, pid) in pids.iter_mut().enumerate() {
        *pid = sys_fork();
        if *pid == 0 {
            sys_exit(pair(i));
        }
    }
    for (i, &pid) in pids.iter().enumerate() {
        let st = wait_child(pid);
        if !t.eq(b"pair status", st as i64, 0) {
            t.eq(b"pair", i as i64, -1);
        }
    }
    t.done();
}

/// One loopback pair: a child sends LEN pattern bytes, this process
/// checks them: the exit code, 0 if all arrived intact
fn pair(seed: usize) -> u64 {
    let (l, p) = listener(1);
    let c = tcp();
    set_timeo(c, 20_000);
    if connect(c, LO, p) != 0 {
        return 1;
    }
    let s = accept(l);
    if s < 0 {
        return 2;
    }
    set_timeo(s, 20_000);
    let pid = sys_fork();
    if pid == 0 {
        close(s);
        let r = send_pat(c, seed, LEN);
        // Stay open until the reader is done: an orphan holding data
        // past the hard limit is reset (Linux tcp_out_of_resources)
        let mut b = [0u8; 1];
        let eof = recv(c, &mut b, 0);
        sys_exit(if r != LEN as i64 {
            3
        } else if eof != 0 {
            7
        } else {
            0
        });
    }
    close(c);
    let (n, bad, _) = recv_pat(s, seed, LEN, 16384);
    close(s);
    let st = wait_child(pid);
    if n != LEN {
        4
    } else if bad >= 0 {
        5
    } else if st != 0 {
        6
    } else {
        0
    }
}

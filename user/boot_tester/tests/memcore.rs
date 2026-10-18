//! Memory core (page allocator, slab): what /proc/meminfo reports for
//! RAM and the kernel heap
//!
//! Tests:
//! - MEM_TOTAL: MemTotal is the QEMU RAM (512MB) less what boot keeps
//!   (kernel image, memory map): between 400MB and 512MB
//! - MEM_TOUCH_FREE: a child touching 300MB of anonymous memory takes
//!   about that much MemFree, and it all comes back when the child exits
//!   (within 8MB on hk, 32MB on Linux)
//! - MEM_SLAB_TIME_WAIT: 2000 connections closed into TIME_WAIT are all
//!   listed in /proc/net/tcp; on hk each entry costs at most 1KB of
//!   Slab with its table and timer entries (about 600 bytes, 860 with
//!   LOCKDEP's lock tracking: a compact timewait entry, not a whole
//!   control block, which was over 1.3KB;
//!   Linux's tw_sock slab varies with its other caches, so there only
//!   the entries are checked)

use super::helpers::{host_mode, print, print_num, println};
use super::mm_life::meminfo;
use super::sk::{bind, close, connect, port, tcp};
use super::sysctl::{read_file, write_file};
use super::tcp_xfer::accept;
use hk_syscall::{
    MAP_ANONYMOUS, MAP_PRIVATE, O_RDONLY, PROT_READ, PROT_WRITE, Timespec, sys_bind, sys_close,
    sys_exit, sys_fork, sys_listen, sys_mmap, sys_nanosleep, sys_open, sys_read, sys_wait4,
};

const MB: i64 = 1024;
const TOUCH: u64 = 300 << 20;
const MAX_TW: &[u8] = b"/proc/sys/net/ipv4/tcp_max_tw_buckets\0";

pub fn run_tests() {
    mem_total();
    touch_free();
    slab_time_wait();
}

fn report(name: &[u8], ok: bool, detail: i64) {
    print(name);
    if ok {
        println(b":OK");
    } else {
        print(b":FAIL ");
        print_num(detail);
        println(b"");
    }
}

fn sleep_ms(ms: i64) {
    let ts = Timespec {
        tv_sec: ms / 1000,
        tv_nsec: (ms % 1000) * 1_000_000,
    };
    sys_nanosleep(&ts, core::ptr::null_mut());
}

fn mem_total() {
    let t = meminfo(b"MemTotal:");
    print(b"MEM_TOTAL: ");
    print_num(t);
    println(b" kB");
    report(b"MEM_TOTAL", (400 * MB..=512 * MB).contains(&t), t);
}

/// Child: touch TOUCH bytes; exit 0 if MemFree dropped by at least 90%
/// of it meanwhile
fn toucher(before: i64) -> u64 {
    let p = sys_mmap(
        0,
        TOUCH,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if p < 0 {
        return 2;
    }
    let mut a = p as u64;
    while a < p as u64 + TOUCH {
        unsafe { core::ptr::write_volatile(a as *mut u8, 1) };
        a += 4096;
    }
    let used = before - meminfo(b"MemFree:");
    if used < (TOUCH as i64 >> 10) * 9 / 10 {
        print(b"MEM_TOUCH_FREE: MemFree dropped by only ");
        print_num(used);
        println(b" kB");
        return 3;
    }
    0
}

/// MemFree once it stops moving (within 1MB over 100ms, at most 3 s):
/// frees an earlier test left in flight (Linux swap-cache and
/// writeback, per-CPU lists) land before the baseline is taken
fn settled_free() -> i64 {
    let mut last = meminfo(b"MemFree:");
    for _ in 0..30 {
        sleep_ms(100);
        let now = meminfo(b"MemFree:");
        if (now - last).abs() < 1024 {
            return now;
        }
        last = now;
    }
    last
}

fn touch_free() {
    let before = settled_free();
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(toucher(before));
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    // Everything comes back (within 8MB on hk: other activity, per-CPU
    // lists; Linux also keeps more on its per-CPU lists and caches)
    let slack = if host_mode() { 32 * MB } else { 8 * MB };
    let mut after = 0;
    for _ in 0..50 {
        sleep_ms(20);
        after = meminfo(b"MemFree:");
        if before - after <= slack {
            break;
        }
    }
    if before - after > slack {
        print(b"MEM_TOUCH_FREE: MemFree before ");
        print_num(before);
        print(b" kB, after ");
        print_num(after);
        println(b" kB");
    }
    report(
        b"MEM_TOUCH_FREE",
        st == 0 && before - after <= slack,
        st as i64,
    );
}

/// TIME_WAIT lines (state 06) of /proc/net/tcp
fn time_wait_count() -> i64 {
    let fd = sys_open(b"/proc/net/tcp\0".as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        return -1;
    }
    let mut buf = [0u8; 4096];
    let mut line = [0u8; 64];
    let (mut ll, mut n) = (0usize, 0i64);
    loop {
        let r = sys_read(fd as u64, buf.as_mut_ptr(), buf.len() as u64);
        if r <= 0 {
            break;
        }
        for &b in &buf[..r as usize] {
            if b == b'\n' {
                // "  sl  local_address rem_address   st": the state
                // follows the second address
                let l = &line[..ll];
                if l.windows(4).any(|w| w == b" 06 ") {
                    n += 1;
                }
                ll = 0;
            } else if ll < line.len() {
                line[ll] = b;
                ll += 1;
            }
        }
    }
    sys_close(fd as u64);
    n
}

/// A listener on 127.0.0.1, any port
fn listener() -> i32 {
    let l = tcp();
    let a = super::sk::sin([127, 0, 0, 1], 0);
    sys_bind(l, super::sk::sa(&a), 16);
    sys_listen(l, 64);
    l
}

/// One connection from client port `cp`, closed client first: the
/// client end goes to TIME_WAIT (a fixed port each, so no connect
/// reuses a TIME_WAIT tuple: Linux tcp_tw_reuse on loopback)
fn cycle(l: i32, p: u16, cp: u16) -> bool {
    let c = tcp();
    if bind(c, [127, 0, 0, 1], cp) != 0 || connect(c, [127, 0, 0, 1], p) != 0 {
        close(c);
        return false;
    }
    let s = accept(l);
    close(c);
    if s >= 0 {
        close(s);
    }
    s >= 0
}

fn slab_time_wait() {
    const N: i64 = 2000;
    const BASE: u16 = 20000;
    // Linux sizes tcp_max_tw_buckets from RAM (about 1024 here); past
    // it a closing socket skips TIME_WAIT. hk has no such limit.
    let mut buf = [0u8; 32];
    if read_file(MAX_TW, &mut buf) > 0 {
        write_file(MAX_TW, b"65536\n");
    }
    let l = listener();
    let p = port(l);
    for i in 0..32 {
        cycle(l, p, BASE - 100 + i);
    }
    sleep_ms(100);
    let tw0 = time_wait_count();
    let before = meminfo(b"Slab:");
    for i in 0..N {
        if !cycle(l, p, BASE + i as u16) {
            report(b"MEM_SLAB_TIME_WAIT", false, -1000 - i);
            close(l);
            return;
        }
    }
    sleep_ms(200);
    let tw = time_wait_count() - tw0;
    let grew = meminfo(b"Slab:") - before;
    close(l);
    print(b"MEM_SLAB_TIME_WAIT: ");
    print_num(tw);
    print(b" entries, Slab +");
    print_num(grew);
    println(b" kB");
    if tw < N {
        report(b"MEM_SLAB_TIME_WAIT", false, tw);
        return;
    }
    if host_mode() {
        report(b"MEM_SLAB_TIME_WAIT", true, 0);
        return;
    }
    report(b"MEM_SLAB_TIME_WAIT", grew * 1024 <= N * 1024, grew);
}

//! Direct vs buffered read throughput on vda3, printed only (never a
//! verdict): 1 MiB sequential and 4 KiB random reads, the cache dropped
//! (BLKFLSBUF) before each buffered run. At queue depth 1: buffered,
//! direct, and direct with RWF_HIPRI (polled completion where the
//! queue polls). At depth > 1 (no async I/O: several processes, each
//! with its own buffer, read in parallel): direct only. O_DSYNC
//! direct 1 MiB writes put back what they overwrite (each chunk is read
//! first, untimed). `DIO_BENCH:` lines, to compare hk with Linux on the
//! same QEMU. Only when the kernel command line has `hk.bench` (`make
//! check BENCH=1`).

use crate::helpers::{find_blkdev, print, print_num, println, read_file};
use hk_syscall::{
    IoVec, MAP_ANONYMOUS, MAP_PRIVATE, O_RDONLY, O_RDWR, PROT_READ, PROT_WRITE, Timespec,
    sys_clock_gettime, sys_close, sys_exit, sys_fork, sys_ioctl, sys_mmap, sys_munmap, sys_open,
    sys_pipe2, sys_pread64, sys_preadv2, sys_pwritev2, sys_read, sys_wait4, sys_write,
};

const O_DIRECT: u32 = hk_syscall::O_DIRECT;
const RWF_HIPRI: i32 = 0x01;
const RWF_DSYNC: i32 = 0x02;
const CLOCK_MONOTONIC: i32 = 1;
const BLKFLSBUF: u64 = 0x1261;
const MIB: u64 = 1 << 20;
/// Bytes read sequentially per run (vda3 is 16 MiB)
const SEQ: u64 = 8 * MIB;
/// Random 4 KiB reads per run at depth 1
const RAND: u64 = 512;
/// Random 4 KiB reads per run at depth > 1
const RAND_QD: u64 = 2048;
/// Depths of the parallel runs
const SEQ_QD: u64 = 4;
const RAND_QDN: u64 = 8;

/// One process's reads: `n` of `len` bytes, sequential (1 MiB chunks
/// interleaved by process) or random, with RWF_* `flags`
#[derive(Clone, Copy)]
struct Run {
    len: u64,
    n: u64,
    random: bool,
    flags: i32,
}

/// The kernel command line asks for benchmarks
fn wanted() -> bool {
    let mut b = [0u8; 2048];
    let n = read_file(b"/proc/cmdline\0", &mut b);
    let line = &b[..n.max(0) as usize];
    line.split(|c| c.is_ascii_whitespace())
        .any(|w| w == b"hk.bench")
}

pub fn run_tests() {
    if !wanted() {
        return;
    }
    let Some(p3) = find_blkdev(b"vd", 16384) else {
        println(b"DIO_BENCH: no vda3");
        return;
    };
    let mut p = [0u8; 48];
    let path = p3.path(&mut p);
    let d = sys_open(path.as_ptr(), O_RDONLY | O_DIRECT, 0) as i32;
    let b = sys_open(path.as_ptr(), O_RDONLY, 0) as i32;
    let buf = sys_mmap(
        0,
        MIB,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if d < 0 || b < 0 || buf <= 0 {
        println(b"DIO_BENCH: setup error");
    } else {
        bench(b, d, buf as u64);
    }
    if buf > 0 {
        sys_munmap(buf as u64, MIB);
    }
    sys_close(d as u64);
    sys_close(b as u64);
}

fn bench(b: i32, d: i32, buf: u64) {
    let seq = Run {
        len: MIB,
        n: SEQ / MIB,
        random: false,
        flags: 0,
    };
    let rnd = Run {
        len: 4096,
        n: RAND,
        random: true,
        flags: 0,
    };
    let hipri = |r: Run| Run {
        flags: RWF_HIPRI,
        ..r
    };
    let row = [
        (&b" buffered "[..], timed(b, buf, seq, true)),
        (b" direct ", timed(d, buf, seq, false)),
        (b" hipri ", timed(d, buf, hipri(seq), false)),
    ];
    line(b"seq 1M QD1", &row, SEQ, 0);
    let row = [
        (&b" buffered "[..], timed(b, buf, rnd, true)),
        (b" direct ", timed(d, buf, rnd, false)),
        (b" hipri ", timed(d, buf, hipri(rnd), false)),
    ];
    line(b"rand 4K QD1", &row, RAND * 4096, RAND);
    let s = Run {
        n: SEQ / MIB / SEQ_QD,
        ..seq
    };
    let row = [(&b" direct "[..], parallel(d, s, SEQ_QD))];
    line(b"seq 1M QD4", &row, SEQ, 0);
    let r = Run {
        n: RAND_QD / RAND_QDN,
        ..rnd
    };
    let row = [(&b" direct "[..], parallel(d, r, RAND_QDN))];
    line(b"rand 4K QD8", &row, RAND_QD * 4096, RAND_QD);
    line(b"dsync 1M write", &[(b" direct ", dsync(d, buf))], DSYNC, 0);
}

/// Bytes written by the O_DSYNC run (vda3 from 8 MiB)
const DSYNC: u64 = 4 * MIB;

/// Nanoseconds for O_DSYNC direct 1 MiB writes of `DSYNC` bytes, each
/// writing back the chunk just read (only the writes are timed); or
/// the first error. `ro` is the read-only direct fd: a writable one is
/// opened here
fn dsync(ro: i32, buf: u64) -> i64 {
    let mut p = [0u8; 48];
    let Some(p3) = find_blkdev(b"vd", 16384) else {
        return -1;
    };
    let fd = sys_open(p3.path(&mut p).as_ptr(), O_RDWR | O_DIRECT, 0) as i32;
    if fd < 0 {
        return fd as i64;
    }
    let mut ns = 0;
    let mut off = 8 * MIB;
    while off < 8 * MIB + DSYNC {
        if sys_pread64(ro, buf as *mut u8, MIB, off as i64) != MIB as i64 {
            ns = -1;
            break;
        }
        let iov = IoVec {
            iov_base: buf as *const u8,
            iov_len: MIB as usize,
        };
        let t = now_ns();
        let n = sys_pwritev2(fd, &iov, 1, off as i64, RWF_DSYNC);
        if n != MIB as i64 {
            ns = n.min(-1);
            break;
        }
        ns += now_ns() - t;
        off += MIB;
    }
    sys_close(fd as u64);
    ns
}

fn now_ns() -> i64 {
    let mut t = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    sys_clock_gettime(CLOCK_MONOTONIC, &mut t);
    t.tv_sec * 1_000_000_000 + t.tv_nsec
}

/// Nanoseconds for one process's run, or the first error
fn timed(fd: i32, buf: u64, r: Run, cold: bool) -> i64 {
    if cold {
        sys_ioctl(fd, BLKFLSBUF, 0);
    }
    let t = now_ns();
    match reads(fd, buf, r, 0, 1) {
        0 => now_ns() - t,
        e => e,
    }
}

/// Process `k` of `procs`: its reads of `r`, 0 or the first error.
/// Sequential: 1 MiB chunks k, k + procs, ...; random: 4 KiB-aligned
/// offsets in vda3's 16 MiB from a seed of its own
fn reads(fd: i32, buf: u64, r: Run, k: u64, procs: u64) -> i64 {
    let mut x: u32 = 12345u32.wrapping_add(k as u32 * 7919);
    for i in 0..r.n {
        let off = if r.random {
            x = x.wrapping_mul(1103515245).wrapping_add(12345);
            u64::from(x >> 8) % 4096 * 4096
        } else {
            (i * procs + k) * r.len
        };
        let iov = IoVec {
            iov_base: buf as *const u8,
            iov_len: r.len as usize,
        };
        let n = sys_preadv2(fd, &iov, 1, off as i64, r.flags);
        if n != r.len as i64 {
            return n.min(-1);
        }
    }
    0
}

/// Nanoseconds for `procs` processes (at most 8) running `r` at once,
/// each with its own buffer, started together through a pipe; or an
/// error
fn parallel(fd: i32, r: Run, procs: u64) -> i64 {
    let mut pfd = [0i32; 2];
    if sys_pipe2(pfd.as_mut_ptr(), 0) < 0 {
        return -1;
    }
    let mut pids = [0i64; 8];
    for (k, pid) in pids.iter_mut().enumerate().take(procs as usize) {
        *pid = sys_fork();
        if *pid == 0 {
            sys_close(pfd[1] as u64);
            let mut go = 0u8;
            sys_read(pfd[0] as u64, &mut go, 1);
            sys_exit(child(fd, r, k as u64, procs));
        }
    }
    sys_close(pfd[0] as u64);
    let t = now_ns();
    let go = [0u8; 8];
    sys_write(pfd[1] as u64, go.as_ptr(), procs);
    let mut ok = true;
    for &pid in pids.iter().take(procs as usize) {
        let mut st = 0i32;
        ok &= pid > 0 && sys_wait4(pid, &mut st, 0, 0) == pid && st == 0;
    }
    let ns = now_ns() - t;
    sys_close(pfd[1] as u64);
    if ok { ns } else { -1 }
}

/// A parallel run's process: exit status 0 if every read was whole
fn child(fd: i32, r: Run, k: u64, procs: u64) -> u64 {
    let buf = sys_mmap(
        0,
        r.len,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if buf <= 0 {
        return 1;
    }
    u64::from(reads(fd, buf as u64, r, k, procs) != 0)
}

/// DIO_BENCH: <what> <name> <MB/s> MB/s [<IOPS> IOPS] ...
fn line(what: &[u8], row: &[(&[u8], i64)], bytes: u64, ios: u64) {
    print(b"DIO_BENCH: ");
    print(what);
    for &(name, ns) in row {
        print(name);
        if ns <= 0 {
            print(b"error ");
            print_num(ns);
            continue;
        }
        print_num(bytes as i64 * 1000 / ns);
        print(b" MB/s");
        if ios > 0 {
            print(b" ");
            print_num(ios as i64 * 1_000_000_000 / ns);
            print(b" IOPS");
        }
    }
    println(b"");
}

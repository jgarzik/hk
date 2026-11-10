//! Direct vs buffered read throughput on vda3, printed only (never a
//! verdict): 1 MiB sequential reads and 4 KiB random reads at queue
//! depth 1, the cache dropped (BLKFLSBUF) before each buffered run.
//! `DIO_BENCH:` lines, to compare hk with Linux on the same QEMU.

use crate::helpers::{find_blkdev, print, print_num, println};
use hk_syscall::{
    MAP_ANONYMOUS, MAP_PRIVATE, O_RDONLY, PROT_READ, PROT_WRITE, Timespec, sys_clock_gettime,
    sys_close, sys_ioctl, sys_mmap, sys_munmap, sys_open, sys_pread64,
};

const O_DIRECT: u32 = hk_syscall::O_DIRECT;
const CLOCK_MONOTONIC: i32 = 1;
const BLKFLSBUF: u64 = 0x1261;
const MIB: u64 = 1 << 20;
/// Bytes read sequentially per run (vda3 is 16 MiB)
const SEQ: u64 = 8 * MIB;
/// Random 4 KiB reads per run
const RAND: u64 = 512;

pub fn run_tests() {
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
        let buf = buf as u64;
        let sb = seq(b, buf, true);
        let sd = seq(d, buf, false);
        line(b"seq 1M", sb, sd, SEQ);
        let rb = rand(b, buf, true);
        let rd = rand(d, buf, false);
        line(b"rand 4K", rb, rd, RAND * 4096);
    }
    if buf > 0 {
        sys_munmap(buf as u64, MIB);
    }
    sys_close(d as u64);
    sys_close(b as u64);
}

fn now_ns() -> i64 {
    let mut t = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    sys_clock_gettime(CLOCK_MONOTONIC, &mut t);
    t.tv_sec * 1_000_000_000 + t.tv_nsec
}

/// Nanoseconds for `SEQ` bytes in 1 MiB reads from offset 0, or the
/// first error
fn seq(fd: i32, buf: u64, cold: bool) -> i64 {
    if cold {
        sys_ioctl(fd, BLKFLSBUF, 0);
    }
    let t = now_ns();
    let mut off = 0;
    while off < SEQ {
        let n = sys_pread64(fd, buf as *mut u8, MIB, off as i64);
        if n != MIB as i64 {
            return n.min(-1);
        }
        off += MIB;
    }
    now_ns() - t
}

/// Nanoseconds for `RAND` 4 KiB reads at 4 KiB-aligned pseudo-random
/// offsets in vda3's 16 MiB, or the first error
fn rand(fd: i32, buf: u64, cold: bool) -> i64 {
    if cold {
        sys_ioctl(fd, BLKFLSBUF, 0);
    }
    let mut x: u32 = 12345;
    let t = now_ns();
    for _ in 0..RAND {
        x = x.wrapping_mul(1103515245).wrapping_add(12345);
        let off = u64::from(x >> 8) % 4096 * 4096;
        let n = sys_pread64(fd, buf as *mut u8, 4096, off as i64);
        if n != 4096 {
            return n.min(-1);
        }
    }
    now_ns() - t
}

/// DIO_BENCH: <what> buffered <MB/s> MB/s direct <MB/s> MB/s
/// (<IOPS> / <IOPS> IOPS for 4K)
fn line(what: &[u8], buffered: i64, direct: i64, bytes: u64) {
    print(b"DIO_BENCH: ");
    print(what);
    for (name, ns) in [(&b" buffered "[..], buffered), (b" direct ", direct)] {
        print(name);
        if ns <= 0 {
            print(b"error ");
            print_num(ns);
            continue;
        }
        print_num(bytes as i64 * 1000 / ns);
        print(b" MB/s");
        if bytes == RAND * 4096 {
            print(b" ");
            print_num(RAND as i64 * 1_000_000_000 / ns);
            print(b" IOPS");
        }
    }
    println(b"");
}

//! Direct vs buffered read throughput on vda3, printed only (never a
//! verdict): 1 MiB sequential and 4 KiB random reads, the cache dropped
//! (BLKFLSBUF) before each buffered run. At queue depth 1: buffered,
//! direct, and direct with RWF_HIPRI (polled completion where the
//! queue polls). At depth > 1 (no async I/O: several processes, each
//! with its own buffer, read in parallel): direct only. O_DSYNC
//! direct 1 MiB writes put back what they overwrite (each chunk is read
//! first, untimed). `DIO_BENCH:` lines, to compare hk with Linux on the
//! same QEMU. vfat rows: a 16 MiB file on vda1, 1 MiB sequential and
//! 4 KiB random reads, buffered (page cache dropped first) and direct.
//! Only when the kernel command line has `hk.bench` (`make check
//! BENCH=1`).

use crate::helpers::{find_blkdev, print, print_num, println, read_file};
use hk_syscall::{
    IoVec, MAP_ANONYMOUS, MAP_PRIVATE, MAP_SHARED, O_CREAT, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY,
    PROT_READ, PROT_WRITE, Timespec, sys_clock_gettime, sys_close, sys_exit, sys_fork, sys_fsync,
    sys_ioctl, sys_mkdir, sys_mmap, sys_mount, sys_munmap, sys_open, sys_pipe2, sys_pread64,
    sys_preadv2, sys_pwrite64, sys_pwritev2, sys_read, sys_rmdir, sys_umount2, sys_unlink,
    sys_wait4, sys_write,
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
        vfat(buf as u64);
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
/// each with its own buffer faulted in beforehand, started together
/// through a pipe: from the start to the last one's last read (each
/// stores its end time in a shared page; exits are not timed); or an
/// error
fn parallel(fd: i32, r: Run, procs: u64) -> i64 {
    let ends = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0,
    );
    let mut pfd = [0i32; 2];
    if ends <= 0 || sys_pipe2(pfd.as_mut_ptr(), 0) < 0 {
        return -1;
    }
    let ends = ends as u64;
    let mut pids = [0i64; 8];
    for (k, pid) in pids.iter_mut().enumerate().take(procs as usize) {
        *pid = sys_fork();
        if *pid == 0 {
            sys_close(pfd[1] as u64);
            sys_exit(child(fd, r, k as u64, procs, pfd[0], ends));
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
    sys_close(pfd[1] as u64);
    let mut last = 0;
    for k in 0..procs {
        // SAFETY: the shared page, one slot per process, all exited
        last = last.max(unsafe { core::ptr::read_volatile((ends as *const i64).add(k as usize)) });
    }
    sys_munmap(ends, 4096);
    if ok { last - t } else { -1 }
}

/// A parallel run's process `k`: buffer faulted in, then the start
/// (a byte on `go`), the reads, its end time in slot `k` of `ends`;
/// exit status 0 if every read was whole
fn child(fd: i32, r: Run, k: u64, procs: u64, go: i32, ends: u64) -> u64 {
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
    // SAFETY: the mapping just made, `r.len` bytes
    unsafe { core::ptr::write_bytes(buf as *mut u8, 0, r.len as usize) };
    let mut b = 0u8;
    sys_read(go as u64, &mut b, 1);
    let e = reads(fd, buf as u64, r, k, procs);
    // SAFETY: slot `k` of the shared page (k < 8)
    unsafe { core::ptr::write_volatile((ends as *mut i64).add(k as usize), now_ns()) };
    u64::from(e != 0)
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

/// The vfat file the vfat rows read (16 MiB on vda1, 512-byte clusters)
const VFAT_FILE: &[u8] = b"/tmp/vfat_bench/BENCH.BIN\0";
const VFAT_MNT: &[u8] = b"/tmp/vfat_bench\0";
const VFAT_SIZE: u64 = 16 * MIB;

/// Drop the clean page cache (vm.drop_caches 1): a cold buffered run
fn drop_caches() {
    let fd = sys_open(b"/proc/sys/vm/drop_caches\0".as_ptr(), O_WRONLY, 0);
    if fd >= 0 {
        sys_write(fd as u64, b"1\n".as_ptr(), 2);
        sys_close(fd as u64);
    }
}

/// vfat rows: a 16 MiB file on vda1, buffered (cold) and direct, 1 MiB
/// sequential and 4 KiB random reads at depth 1
fn vfat(buf: u64) {
    let Some(p1) = find_blkdev(b"vd", 32768) else {
        println(b"DIO_BENCH: no vda1");
        return;
    };
    let mut p = [0u8; 48];
    sys_mkdir(VFAT_MNT.as_ptr(), 0o755);
    let m = sys_mount(
        p1.path(&mut p).as_ptr(),
        VFAT_MNT.as_ptr(),
        b"vfat\0".as_ptr(),
        0,
        b"iocharset=cp437\0".as_ptr() as u64,
    );
    if m != 0 {
        println(b"DIO_BENCH: vfat mount error");
        return;
    }
    if vfat_fill(buf) {
        let b = sys_open(VFAT_FILE.as_ptr(), O_RDONLY, 0) as i32;
        let d = sys_open(VFAT_FILE.as_ptr(), O_RDONLY | O_DIRECT, 0) as i32;
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
        let cold = |fd, r| {
            drop_caches();
            timed(fd, buf, r, false)
        };
        let row = [
            (&b" buffered "[..], cold(b, seq)),
            (b" direct ", timed(d, buf, seq, false)),
        ];
        line(b"vfat seq 1M QD1", &row, SEQ, 0);
        let row = [
            (&b" buffered "[..], cold(b, rnd)),
            (b" direct ", timed(d, buf, rnd, false)),
        ];
        line(b"vfat rand 4K QD1", &row, RAND * 4096, RAND);
        sys_close(b as u64);
        sys_close(d as u64);
    } else {
        println(b"DIO_BENCH: vfat file error");
    }
    sys_unlink(VFAT_FILE.as_ptr());
    sys_umount2(VFAT_MNT.as_ptr(), 0);
    sys_rmdir(VFAT_MNT.as_ptr());
}

/// Write the vfat file, 1 MiB at a time through `buf`, and fsync it
fn vfat_fill(buf: u64) -> bool {
    let fd = sys_open(VFAT_FILE.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644) as i32;
    if fd < 0 {
        return false;
    }
    // SAFETY: the 1 MiB benchmark buffer
    unsafe { core::ptr::write_bytes(buf as *mut u8, 0x5a, MIB as usize) };
    let mut ok = true;
    let mut off = 0;
    while ok && off < VFAT_SIZE {
        ok = sys_pwrite64(fd, buf as *const u8, MIB, off as i64) == MIB as i64;
        off += MIB;
    }
    ok &= sys_fsync(fd) == 0;
    sys_close(fd as u64);
    ok
}

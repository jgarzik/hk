//! Positioned I/O and lseek on files without a page cache (Linux
//! FMODE_PREAD/PWRITE unless the driver opens a stream):
//!
//! - PREAD_MEMDEV: pread/pwrite on /dev/null, /dev/zero, /dev/urandom
//!   work (the offset is ignored); lseek on null and zero is always 0
//!   (null_lseek), on urandom the position stays (noop_llseek)
//! - PREAD_PROCSYS: pread of a numeric /proc/sys file at 0 reads it,
//!   at any other offset nothing (do_proc_dointvec); pwrite at 0
//!   stores
//! - PREAD_CGROUP: pread of a cgroup file reads from the offset and
//!   leaves the position

use crate::helpers::{print, print_num, println};
use hk_syscall::{
    O_RDONLY, O_RDWR, SEEK_END, SEEK_SET, sys_close, sys_lseek, sys_mkdir, sys_mount, sys_open,
    sys_pread64, sys_pwrite64, sys_read, sys_rmdir, sys_umount2,
};

pub fn run_tests() {
    memdev();
    procsys();
    cgroup();
}

fn report(name: &[u8], cases: &[(&[u8], i64, bool)]) {
    let mut ok = true;
    for (what, v, good) in cases {
        if !good {
            print(name);
            print(b":FAIL ");
            print(what);
            print(b" got ");
            print_num(*v);
            println(b"");
            ok = false;
        }
    }
    if ok {
        print(name);
        println(b":OK");
    }
}

fn open(p: &[u8], flags: u32) -> i32 {
    sys_open(p.as_ptr(), flags, 0) as i32
}

fn memdev() {
    let null = open(b"/dev/null\0", O_RDWR);
    let zero = open(b"/dev/zero\0", O_RDWR);
    let rnd = open(b"/dev/urandom\0", O_RDONLY);
    let mut b = [0xffu8; 16];
    let z = sys_pread64(zero, b.as_mut_ptr(), 16, 100);
    let zeros = b.iter().all(|&c| c == 0);
    let zw = sys_pwrite64(zero, b"abc".as_ptr(), 3, 9);
    let nr = sys_pread64(null, b.as_mut_ptr(), 16, 5);
    let nw = sys_pwrite64(null, b"hello".as_ptr(), 5, 7);
    let rr = sys_pread64(rnd, b.as_mut_ptr(), 8, 0);
    let ns = sys_lseek(null, 100, SEEK_SET);
    let zs = sys_lseek(zero, 0, SEEK_END);
    let rs = sys_lseek(rnd, 5, SEEK_SET);
    for fd in [null, zero, rnd] {
        sys_close(fd as u64);
    }
    report(
        b"PREAD_MEMDEV",
        &[
            (b"pread zero", z, z == 16 && zeros),
            (b"pwrite zero", zw, zw == 3),
            (b"pread null", nr, nr == 0),
            (b"pwrite null", nw, nw == 5),
            (b"pread urandom", rr, rr == 8),
            (b"lseek null", ns, ns == 0),
            (b"lseek zero end", zs, zs == 0),
            (b"lseek urandom", rs, rs == 0),
        ],
    );
}

/// read() of `fd` from the start, then pread at `off`: the pread
/// returns read()'s bytes from `off` on, and leaves the position
fn pread_matches(fd: i32, off: usize) -> (i64, bool) {
    let mut whole = [0u8; 4096];
    let m = sys_read(fd as u64, whole.as_mut_ptr(), 4096);
    let mut part = [0u8; 4096];
    let n = sys_pread64(fd, part.as_mut_ptr(), 4096, off as i64);
    let mut again = [0u8; 8];
    let after = sys_read(fd as u64, again.as_mut_ptr(), 8);
    let ok = m > off as i64
        && n == m - off as i64
        && part[..n as usize] == whole[off..m as usize]
        && after == 0;
    (n, ok)
}

fn procsys() {
    let p = b"/proc/sys/vm/max_map_count\0";
    let fd = open(p, O_RDWR);
    // A number reads only from offset 0 (Linux do_proc_dointvec)
    let mut b = [0u8; 24];
    let n = sys_pread64(fd, b.as_mut_ptr(), 24, 2);
    let r0 = sys_pread64(fd, b.as_mut_ptr(), 24, 0);
    let matches = n == 0 && r0 > 2;
    // pwrite at 0 stores: the value read back
    let mut old = [0u8; 24];
    let on = sys_pread64(fd, old.as_mut_ptr(), 24, 0);
    let w = sys_pwrite64(fd, b"70000\n".as_ptr(), 6, 0);
    let mut now = [0u8; 24];
    let nn = sys_pread64(fd, now.as_mut_ptr(), 24, 0);
    let stored = nn == 6 && &now[..6] == b"70000\n";
    if on > 0 {
        sys_pwrite64(fd, old.as_ptr(), on as u64, 0);
    }
    sys_close(fd as u64);
    report(
        b"PREAD_PROCSYS",
        &[
            (b"pread offset", n, matches),
            (b"pwrite", w, w == 6),
            (b"pwrite stored", nn, stored),
        ],
    );
}

fn cgroup() {
    let mp = b"/tmp/cgp\0";
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777);
    sys_mkdir(mp.as_ptr(), 0o755);
    sys_mount(b"none\0".as_ptr(), mp.as_ptr(), b"cgroup2\0".as_ptr(), 0, 0);
    let fd = open(b"/tmp/cgp/cgroup.stat\0", O_RDONLY);
    let r = cgroup_pread(fd);
    sys_umount2(mp.as_ptr(), 0);
    sys_rmdir(mp.as_ptr());
    report(b"PREAD_CGROUP", &[r]);
}

/// pread at 3 of cgroup.stat (open as `fd`) is read()'s from 3 on
fn cgroup_pread(fd: i32) -> (&'static [u8], i64, bool) {
    if fd < 0 {
        return (b"open", i64::from(fd), false);
    }
    let (n, ok) = pread_matches(fd, 3);
    sys_close(fd as u64);
    (b"pread", n, ok)
}

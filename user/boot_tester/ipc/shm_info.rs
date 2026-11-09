//! SysV shm on tmpfs files (Linux ipc/shm.c)
//!
//! - SHM_RMID_ATTACHED: IPC_RMID of an attached segment hides its key
//!   (shmget ENOENT) but keeps the id until the last detach: IPC_STAT
//!   shows SHM_DEST and key 0, shmat by id still attaches the same
//!   memory; after the last shmdt the id is gone (EINVAL)
//! - SHM_INFO: IPC_INFO limits (shmmin 1, shmseg = shmmni), SHM_INFO
//!   counts (used ids, pages, resident pages), SHM_STAT / SHM_STAT_ANY
//!   by index return the full id, /proc/sysvipc/shm lists the segment,
//!   /proc/meminfo Shmem counts its pages

use crate::harness::T;
use crate::helpers::read_file;
use crate::mm::mm_life::meminfo;
use hk_syscall::{IPC_CREAT, IPC_RMID, IPC_STAT, sys_shmat, sys_shmctl, sys_shmdt, sys_shmget};

const ENOENT: i64 = -2;
const EINVAL: i64 = -22;
const IPC_INFO: i32 = 3;
const SHM_STAT: i32 = 13;
const SHM_INFO: i32 = 14;
const SHM_STAT_ANY: i32 = 15;
const SHM_DEST: u64 = 0o1000;

pub fn run_tests() {
    rmid_attached();
    info();
}

/// shmid64_ds as 14 words (key: low half of word 0, mode: high half
/// of word 2, nattch: word 11), and the shmctl result
fn stat(id: i32, cmd: i32) -> ([u64; 14], i64) {
    let mut ds = [0u64; 14];
    let r = sys_shmctl(id, cmd, ds.as_mut_ptr() as u64);
    (ds, r)
}

fn rmid_attached() {
    let mut t = T::new(b"SHM_RMID_ATTACHED");
    let key = 0x1234_abcd;
    let id = sys_shmget(key, 4096, IPC_CREAT | 0o600) as i32;
    let a = sys_shmat(id, 0, 0);
    if !t.ok(b"attach", id >= 0 && a > 0, a) {
        return t.done();
    }
    // SAFETY: the 4096-byte attachment made above
    unsafe { (a as *mut u64).write_volatile(42) };
    t.eq(b"rmid", sys_shmctl(id, IPC_RMID, 0), 0);
    t.eq(b"key gone", sys_shmget(key, 4096, 0), ENOENT);
    let (ds, r) = stat(id, IPC_STAT);
    t.eq(b"stat", r, 0);
    t.ok(
        b"SHM_DEST",
        (ds[2] >> 32) & SHM_DEST != 0,
        (ds[2] >> 32) as i64,
    );
    t.eq(b"key 0", (ds[0] & 0xffff_ffff) as i64, 0);
    t.eq(b"nattch", ds[11] as i64, 1);
    let b = sys_shmat(id, 0, 0);
    t.ok(b"attach destroyed", b > 0, b);
    if b > 0 {
        // SAFETY: the 4096-byte attachment made above
        let v = unsafe { (b as *const u64).read_volatile() };
        t.eq(b"same memory", v as i64, 42);
        sys_shmdt(b as u64);
    }
    t.eq(b"detach", sys_shmdt(a as u64), 0);
    t.eq(b"id gone", stat(id, IPC_STAT).1, EINVAL);
    t.done();
}

/// `v` right-aligned in `w` columns after `out[at..]`; the new end
fn put_num(out: &mut [u8], at: usize, v: i64, w: usize) -> usize {
    let mut d = [0u8; 24];
    let (mut n, mut x, neg) = (0, v.unsigned_abs(), v < 0);
    loop {
        d[n] = b'0' + (x % 10) as u8;
        n += 1;
        x /= 10;
        if x == 0 {
            break;
        }
    }
    let len = n + usize::from(neg);
    let mut i = at;
    for _ in len..w {
        out[i] = b' ';
        i += 1;
    }
    if neg {
        out[i] = b'-';
        i += 1;
    }
    for k in (0..n).rev() {
        out[i] = d[k];
        i += 1;
    }
    i
}

fn info() {
    let mut t = T::new(b"SHM_INFO");
    let key = 0x2345_bcde;
    let id = sys_shmget(key, 8192, IPC_CREAT | 0o640) as i32;
    let a = sys_shmat(id, 0, 0);
    if !t.ok(b"attach", id >= 0 && a > 0, a) {
        return t.done();
    }
    // Two resident pages
    // SAFETY: the 8192-byte attachment made above
    unsafe {
        (a as *mut u8).write_volatile(1);
        ((a + 4096) as *mut u8).write_volatile(1);
    }
    let mut lim = [0u64; 9];
    let maxidx = sys_shmctl(0, IPC_INFO, lim.as_mut_ptr() as u64);
    t.ok(b"IPC_INFO", maxidx >= 0, maxidx);
    t.eq(b"shmmin", lim[1] as i64, 1);
    t.ok(b"shmseg", lim[3] == lim[2] && lim[2] > 0, lim[3] as i64);
    let mut si = [0u64; 6];
    let r = sys_shmctl(0, SHM_INFO, si.as_mut_ptr() as u64);
    t.eq(b"SHM_INFO idx", r, maxidx);
    t.ok(b"used_ids", si[0] as u32 >= 1, si[0] as i64);
    t.ok(b"shm_tot", si[1] >= 2, si[1] as i64);
    t.ok(b"shm_rss", si[2] >= 2, si[2] as i64);
    // SHM_STAT / SHM_STAT_ANY take an index and return the id
    let mut found = (false, false);
    for i in 0..=maxidx.max(0) as i32 {
        found.0 |= stat(i, SHM_STAT).1 == i64::from(id);
        found.1 |= stat(i, SHM_STAT_ANY).1 == i64::from(id);
    }
    t.ok(b"SHM_STAT", found.0, 0);
    t.ok(b"SHM_STAT_ANY", found.1, 0);
    // /proc/sysvipc/shm: "%10d %10d  %4o %21lu ..."
    let mut buf = [0u8; 8192];
    let n = read_file(b"/proc/sysvipc/shm\0", &mut buf).max(0) as usize;
    let head = b"       key      shmid perms                  size  cpid  lpid nattch";
    t.ok(b"sysvipc header", buf[..n].starts_with(head), n as i64);
    let mut want = [0u8; 64];
    let mut e = put_num(&mut want, 0, key as i64, 10);
    want[e] = b' ';
    e = put_num(&mut want, e + 1, i64::from(id), 10);
    want[e..e + 2].copy_from_slice(b"  ");
    e = put_num(&mut want, e + 2, 640, 4);
    want[e] = b' ';
    e = put_num(&mut want, e + 1, 8192, 21);
    t.ok(
        b"sysvipc line",
        crate::exec::busybox::contains(&buf[..n], &want[..e]),
        n as i64,
    );
    t.ok(
        b"meminfo Shmem",
        meminfo(b"Shmem:") >= 8,
        meminfo(b"Shmem:"),
    );
    sys_shmdt(a as u64);
    sys_shmctl(id, IPC_RMID, 0);
    t.done();
}

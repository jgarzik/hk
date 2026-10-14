//! O_APPEND and shared file positions (Linux generic_file_write_iter
//! under i_rwsem, f_pos_lock / FMODE_ATOMIC_POS):
//! - writers appending through separate O_APPEND descriptors never
//!   overwrite or tear each other's records
//! - pwrite on an O_APPEND file appends (Linux quirk)
//! - processes sharing one open file (fork) never read the same data

use super::helpers::{print, print_num, println};
use hk_syscall::{
    sys_close, sys_exit, sys_fork, sys_fstat, sys_lseek, sys_open, sys_pipe, sys_pread64,
    sys_pwrite64, sys_read, sys_unlink, sys_wait4, sys_write, Stat, O_APPEND, O_CREAT, O_RDONLY,
    O_RDWR, O_TRUNC, O_WRONLY, SEEK_CUR,
};

const REC: usize = 32;
const NREC: usize = 1000;

pub fn run_tests() {
    test_append_race();
    test_append_pwrite();
    test_shared_pos();
}

fn verdict(name: &[u8], ok: bool, got: i64) {
    print(name);
    if ok {
        println(b":OK");
    } else {
        print(b":FAIL got ");
        print_num(got);
        println(b"");
    }
}

fn size_of(fd: i64) -> i64 {
    let mut st: Stat = unsafe { core::mem::zeroed() };
    if sys_fstat(fd as i32, &mut st) != 0 {
        return -1;
    }
    st.st_size
}

/// Child: append NREC records of `tag` through its own O_APPEND fd
fn appender(path: &[u8], tag: u8) -> ! {
    let fd = sys_open(path.as_ptr(), O_WRONLY | O_APPEND, 0);
    if fd < 0 {
        sys_exit(2);
    }
    let mut rec = [tag; REC];
    rec[REC - 1] = b'\n';
    for _ in 0..NREC {
        if sys_write(fd as u64, rec.as_ptr(), REC as u64) != REC as i64 {
            sys_exit(3);
        }
    }
    sys_exit(0);
}

/// Two processes append 1000 fixed-size records each: the size is exact
/// and every record is intact
fn test_append_race() {
    let path = b"/tmp/append_race\0";
    let fd = sys_open(path.as_ptr(), O_CREAT | O_RDWR | O_TRUNC, 0o644);
    if fd < 0 {
        return verdict(b"APPEND_RACE", false, fd);
    }
    let a = sys_fork();
    if a == 0 {
        appender(path, b'A');
    }
    let b = sys_fork();
    if b == 0 {
        appender(path, b'B');
    }
    let (mut sa, mut sb) = (0, 0);
    sys_wait4(a, &mut sa, 0, 0);
    sys_wait4(b, &mut sb, 0, 0);
    let size = size_of(fd);
    let mut bad = 0i64;
    let mut count = [0usize; 2];
    let mut rec = [0u8; REC];
    for i in 0..2 * NREC {
        if sys_pread64(fd as i32, rec.as_mut_ptr(), REC as u64, (i * REC) as i64) != REC as i64 {
            bad += 1;
            continue;
        }
        let t = rec[0];
        if (t != b'A' && t != b'B') || rec[REC - 1] != b'\n' || rec[..REC - 1].iter().any(|&c| c != t)
        {
            bad += 1;
            continue;
        }
        count[(t - b'A') as usize] += 1;
    }
    sys_close(fd as u64);
    sys_unlink(path.as_ptr());
    let ok = sa == 0 && sb == 0 && size == (2 * NREC * REC) as i64 && bad == 0;
    verdict(b"APPEND_RACE", ok && count == [NREC, NREC], if ok { bad } else { size });
}

/// O_APPEND: write() leaves the position at the end, pwrite() appends
/// regardless of its offset
fn test_append_pwrite() {
    let path = b"/tmp/append_pw\0";
    let fd = sys_open(path.as_ptr(), O_CREAT | O_RDWR | O_TRUNC | O_APPEND, 0o644);
    if fd < 0 {
        return verdict(b"APPEND_PWRITE", false, fd);
    }
    sys_write(fd as u64, b"abc".as_ptr(), 3);
    let pos = sys_lseek(fd as i32, 0, SEEK_CUR);
    let w = sys_pwrite64(fd as i32, b"XY".as_ptr(), 2, 0);
    let mut buf = [0u8; 8];
    let n = sys_pread64(fd as i32, buf.as_mut_ptr(), buf.len() as u64, 0);
    sys_close(fd as u64);
    sys_unlink(path.as_ptr());
    let ok = pos == 3 && w == 2 && n == 5 && &buf[..5] == b"abcXY";
    verdict(b"APPEND_PWRITE", ok, n * 100 + pos);
}

const SREC: usize = 256;
const SNREC: usize = 2000;

/// Read records through a shared fd until EOF: (count, index sum)
fn reader(fd: i64) -> (u64, u64) {
    let mut rec = [0u8; SREC];
    let (mut n, mut sum) = (0u64, 0u64);
    while sys_read(fd as u64, rec.as_mut_ptr(), SREC as u64) == SREC as i64 {
        n += 1;
        sum += u64::from_ne_bytes(rec[..8].try_into().unwrap());
    }
    (n, sum)
}

/// Parent and child read one shared open file concurrently: together
/// they see every record exactly once
fn test_shared_pos() {
    let path = b"/tmp/shared_pos\0";
    let fd = sys_open(path.as_ptr(), O_CREAT | O_RDWR | O_TRUNC, 0o644);
    if fd < 0 {
        return verdict(b"SHARED_FPOS", false, fd);
    }
    let mut rec = [0u8; SREC];
    for i in 0..SNREC {
        rec[..8].copy_from_slice(&(i as u64).to_ne_bytes());
        sys_write(fd as u64, rec.as_ptr(), SREC as u64);
    }
    sys_close(fd as u64);
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    let mut p = [0i32; 2];
    sys_pipe(p.as_mut_ptr());
    let pid = sys_fork();
    if pid == 0 {
        let r = reader(fd);
        let out = [r.0.to_ne_bytes(), r.1.to_ne_bytes()];
        sys_write(p[1] as u64, out.as_ptr() as *const u8, 16);
        sys_exit(0);
    }
    let mine = reader(fd);
    let mut out = [0u8; 16];
    sys_read(p[0] as u64, out.as_mut_ptr(), 16);
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    sys_close(p[0] as u64);
    sys_close(p[1] as u64);
    sys_close(fd as u64);
    sys_unlink(path.as_ptr());
    let n = mine.0 + u64::from_ne_bytes(out[..8].try_into().unwrap());
    let sum = mine.1 + u64::from_ne_bytes(out[8..].try_into().unwrap());
    let want = (SNREC * (SNREC - 1) / 2) as u64;
    verdict(b"SHARED_FPOS", n == SNREC as u64 && sum == want, n as i64);
}

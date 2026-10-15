//! Large read/write calls: full transfers beyond any kernel bounce
//! buffer (Linux MAX_RW_COUNT is INT_MAX & PAGE_MASK), and many tasks
//! blocked in big reads at once must not exhaust kernel memory.

use super::helpers::{print, print_num, println};
use hk_syscall::{
    sys_close, sys_exit, sys_fork, sys_mmap, sys_nanosleep, sys_open, sys_pipe,
    sys_pread64, sys_read, sys_unlink, sys_wait4, sys_write, Timespec, MAP_ANONYMOUS,
    MAP_PRIVATE, O_CREAT, O_RDWR, O_TRUNC, PROT_READ, PROT_WRITE,
};

const MB: usize = 1024 * 1024;

pub fn run_tests() {
    // Big mappings live in a child: hk's munmap of part of a merged
    // mapping drops the rest of it (BUGS.md), which would hit init
    in_child(test_file);
    in_child(test_null);
    test_ramfs_pages();
    test_ramfs_unlink();
    test_ramfs_full();
    test_pipe();
    test_blocked_reads();
}

fn verdict(name: &[u8], why: &[u8], got: i64) {
    print(name);
    if why.is_empty() {
        println(b":OK");
        return;
    }
    print(b":FAIL ");
    print(why);
    print(b" got ");
    print_num(got);
    println(b"");
}

/// More ramfs data than the page cache keeps of evictable pages (hk
/// caps those at 4MB): ramfs pages can never be evicted, so they must
/// not count against that cap, and other files keep working
fn test_ramfs_pages() {
    const N: &[u8] = b"BIGIO_RAMFS_PAGES";
    let fd = sys_open(b"/ramfs_big\0".as_ptr(), O_CREAT | O_RDWR | O_TRUNC, 0o644);
    if fd < 0 {
        return verdict(N, b"open", fd);
    }
    let n = write_mb(fd, 8);
    let small = sys_open(b"/ramfs_small\0".as_ptr(), O_CREAT | O_RDWR | O_TRUNC, 0o644);
    let w = sys_write(small as u64, b"ok".as_ptr(), 2);
    let mut b = [0u8; 2];
    let r = sys_pread64(small as i32, b.as_mut_ptr(), 2, 0);
    let mut last = [0u8; 1];
    let tail = sys_pread64(fd as i32, last.as_mut_ptr(), 1, (8 * MB - 1) as i64);
    sys_close(fd as u64);
    sys_close(small as u64);
    sys_unlink(b"/ramfs_big\0".as_ptr());
    sys_unlink(b"/ramfs_small\0".as_ptr());
    if n != 8 * MB as i64 {
        return verdict(N, b"big write", n);
    }
    if w != 2 || r != 2 || &b != b"ok" {
        return verdict(N, b"small file", w * 10 + r);
    }
    if tail != 1 || last[0] != 0x5a {
        return verdict(N, b"big file tail", tail);
    }
    verdict(N, b"", 0);
}

/// Write `mb` MB of 0x5a in 16KB chunks: bytes written, or the first
/// error if nothing was written by that call
fn write_mb(fd: i64, mb: usize) -> i64 {
    let chunk = [0x5au8; 16384];
    let mut done = 0;
    while done < mb * MB {
        let n = sys_write(fd as u64, chunk.as_ptr(), chunk.len() as u64);
        if n < 0 {
            return if done == 0 { n } else { done as i64 };
        }
        done += n as usize;
        if n < chunk.len() as i64 {
            break;
        }
    }
    done as i64
}

/// Free RAM in bytes (sysinfo)
fn free_ram() -> u64 {
    let mut si = [0u8; 112];
    if hk_syscall::sys_sysinfo(si.as_mut_ptr()) != 0 {
        return 0;
    }
    let free = u64::from_ne_bytes(si[40..48].try_into().unwrap());
    let unit = u32::from_ne_bytes(si[104..108].try_into().unwrap()).max(1);
    free * unit as u64
}

/// Directory every user may write in
const RDIR: &[u8] = b"/ramfs_t\0";
const RFILE: &[u8] = b"/ramfs_t/f\0";

/// Run `f` as an unprivileged user (nobody) in a child; its exit status
fn as_nobody(f: fn() -> i32) -> i32 {
    hk_syscall::sys_mkdir(RDIR.as_ptr(), 0o777);
    hk_syscall::sys_chmod(RDIR.as_ptr(), 0o777);
    let pid = sys_fork();
    if pid == 0 {
        if hk_syscall::sys_setresuid(65534, 65534, 65534) != 0 {
            sys_exit(90);
        }
        sys_exit(f() as u64);
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    hk_syscall::sys_rmdir(RDIR.as_ptr());
    st
}

/// Unlinking the last name of a closed ramfs file frees its memory: an
/// unprivileged user writing and deleting a 4MB file 50 times neither
/// fails nor grows memory use (Linux evict_inode)
fn test_ramfs_unlink() {
    fn body() -> i32 {
        let mut base = 0;
        for i in 0..50 {
            let fd = sys_open(RFILE.as_ptr(), O_CREAT | O_RDWR | O_TRUNC, 0o644);
            if fd < 0 {
                return 1;
            }
            let n = write_mb(fd, 4);
            sys_close(fd as u64);
            sys_unlink(RFILE.as_ptr());
            if n != 4 * MB as i64 {
                return 2;
            }
            if i == 0 {
                base = free_ram();
            }
        }
        // Allow some slack for unrelated allocations
        if base > free_ram() + (8 * MB) as u64 {
            return 3;
        }
        0
    }
    let st = as_nobody(body);
    let why: &[u8] = match st >> 8 {
        0 => b"",
        1 => b"open",
        2 => b"write (EIO/short)",
        3 => b"memory grew",
        _ => b"child",
    };
    verdict(b"BIGIO_RAMFS_UNLINK", why, st as i64);
}

/// Filling ramfs fails cleanly with ENOSPC (hk keeps a reserve for the
/// kernel; Linux's rootfs tmpfs is limited to half of RAM), the kernel
/// keeps working, and deleting the file makes the space usable again
fn test_ramfs_full() {
    fn body() -> i32 {
        const ENOSPC: i64 = -28;
        let fd = sys_open(RFILE.as_ptr(), O_CREAT | O_RDWR | O_TRUNC, 0o644);
        if fd < 0 {
            return 1;
        }
        let chunk = [0x5au8; 65536];
        let mut total = 0u64;
        let err = loop {
            let n = sys_write(fd as u64, chunk.as_ptr(), chunk.len() as u64);
            if n <= 0 {
                break n;
            }
            total += n as u64;
            if total > 1024 * MB as u64 {
                break 0;
            }
        };
        sys_close(fd as u64);
        sys_unlink(RFILE.as_ptr());
        if err != ENOSPC {
            return 2;
        }
        if total < 16 * MB as u64 {
            return 3;
        }
        // The kernel still works (fork needs page tables and a stack)
        let pid = sys_fork();
        if pid == 0 {
            sys_exit(7);
        }
        let mut st = 0i32;
        sys_wait4(pid, &mut st, 0, 0);
        if pid < 0 || st != 7 << 8 {
            return 4;
        }
        let fd = sys_open(RFILE.as_ptr(), O_CREAT | O_RDWR | O_TRUNC, 0o644);
        let n = write_mb(fd, 4);
        sys_close(fd as u64);
        sys_unlink(RFILE.as_ptr());
        if n != 4 * MB as i64 {
            return 5;
        }
        0
    }
    let st = as_nobody(body);
    let why: &[u8] = match st >> 8 {
        0 => b"",
        1 => b"open",
        2 => b"not ENOSPC when full",
        3 => b"full too early",
        4 => b"fork when full",
        5 => b"space not reusable",
        _ => b"child",
    };
    verdict(b"BIGIO_RAMFS_FULL", why, st as i64);
}

/// Run `f` in a child process and wait for it
fn in_child(f: fn()) {
    let pid = sys_fork();
    if pid == 0 {
        f();
        sys_exit(0);
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
}

fn msleep(ms: u64) {
    let ts = Timespec {
        tv_sec: (ms / 1000) as i64,
        tv_nsec: ((ms % 1000) * 1_000_000) as i64,
    };
    sys_nanosleep(&ts, core::ptr::null_mut());
}

/// Anonymous read-write mapping of `len` bytes (None on failure)
fn map(len: usize) -> Option<&'static mut [u8]> {
    let a = sys_mmap(0, len as u64, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if a < 0 {
        return None;
    }
    // SAFETY: a fresh private mapping of `len` bytes
    Some(unsafe { core::slice::from_raw_parts_mut(a as *mut u8, len) })
}

fn pattern(i: usize) -> u8 {
    (i as u32).wrapping_mul(2_654_435_761).rotate_left(7) as u8
}

/// One 768 KB write and one 768 KB read of a regular file transfer all
/// of it
fn test_file() {
    const NAME: &[u8] = b"BIGIO_FILE";
    let len = 768 * 1024;
    let (Some(w), Some(r)) = (map(len), map(len)) else {
        return verdict(NAME, b"mmap", -1);
    };
    for (i, b) in w.iter_mut().enumerate() {
        *b = pattern(i);
    }
    let path = b"/tmp/bigio\0";
    let fd = sys_open(path.as_ptr(), O_CREAT | O_RDWR | O_TRUNC, 0o600);
    let why = file_check(fd, w, r);
    sys_close(fd as u64);
    sys_unlink(path.as_ptr());
    match why {
        Ok(()) => verdict(NAME, b"", 0),
        Err((w, got)) => verdict(NAME, w, got),
    }
}

fn file_check(fd: i64, w: &[u8], r: &mut [u8]) -> Result<(), (&'static [u8], i64)> {
    if fd < 0 {
        return Err((b"open", fd));
    }
    let n = sys_write(fd as u64, w.as_ptr(), w.len() as u64);
    if n != w.len() as i64 {
        return Err((b"write", n));
    }
    let n = sys_pread64(fd as i32, r.as_mut_ptr(), r.len() as u64, 0);
    if n != r.len() as i64 {
        return Err((b"pread", n));
    }
    if let Some(i) = (0..r.len()).find(|&i| r[i] != w[i]) {
        return Err((b"data", i as i64));
    }
    // A read at an offset stops at end of file
    let off = 100_000;
    let n = sys_pread64(fd as i32, r.as_mut_ptr(), r.len() as u64, off as i64);
    if n != (w.len() - off) as i64 || r[0] != w[off] {
        return Err((b"pread tail", n));
    }
    let n = sys_read(fd as u64, r.as_mut_ptr(), r.len() as u64);
    if n != 0 {
        return Err((b"read at eof", n));
    }
    Ok(())
}

/// A 1.5 MB write to /dev/null is accepted whole (beyond the old 1 MB
/// cap; Linux MAX_RW_COUNT)
fn test_null() {
    const NAME: &[u8] = b"BIGIO_NULL";
    let len = 3 * MB / 2;
    let Some(w) = map(len) else {
        return verdict(NAME, b"mmap", -1);
    };
    let fd = sys_open(b"/dev/null\0".as_ptr(), O_RDWR, 0);
    let n = sys_write(fd as u64, w.as_ptr(), len as u64);
    sys_close(fd as u64);
    if n == len as i64 {
        verdict(NAME, b"", 0)
    } else {
        verdict(NAME, b"write", n)
    }
}

/// A blocking 300 KB pipe write completes in one call while the reader
/// drains it
fn test_pipe() {
    const NAME: &[u8] = b"BIGIO_PIPE";
    const LEN: usize = 300 * 1024;
    let mut fds = [0i32; 2];
    if sys_pipe(fds.as_mut_ptr()) != 0 {
        return verdict(NAME, b"pipe", -1);
    }
    let pid = sys_fork();
    if pid == 0 {
        sys_close(fds[0] as u64);
        let Some(w) = map(LEN) else { sys_exit(2) };
        for (i, b) in w.iter_mut().enumerate() {
            *b = pattern(i);
        }
        let n = sys_write(fds[1] as u64, w.as_ptr(), LEN as u64);
        sys_exit(if n == LEN as i64 { 0 } else { 1 });
    }
    sys_close(fds[1] as u64);
    let mut buf = [0u8; 4096];
    let (mut got, mut bad) = (0usize, None);
    loop {
        let n = sys_read(fds[0] as u64, buf.as_mut_ptr(), buf.len() as u64);
        if n <= 0 {
            break;
        }
        for (k, &b) in buf[..n as usize].iter().enumerate() {
            if bad.is_none() && b != pattern(got + k) {
                bad = Some(got + k);
            }
        }
        got += n as usize;
    }
    sys_close(fds[0] as u64);
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    if got != LEN {
        verdict(NAME, b"bytes", got as i64)
    } else if let Some(i) = bad {
        verdict(NAME, b"data", i as i64)
    } else if st != 0 {
        verdict(NAME, b"writer status", st as i64)
    } else {
        verdict(NAME, b"", 0)
    }
}

/// 24 tasks blocked in 1 MB pipe reads at once (more than the hk kernel
/// heap if each pinned a full-size buffer); all complete
fn test_blocked_reads() {
    const NAME: &[u8] = b"BIGIO_BLOCKED_READS";
    const N: usize = 24;
    let mut pipes = [[0i32; 2]; N];
    let mut pids = [0i64; N];
    for i in 0..N {
        if sys_pipe(pipes[i].as_mut_ptr()) != 0 {
            return verdict(NAME, b"pipe", i as i64);
        }
        let pid = sys_fork();
        if pid == 0 {
            let Some(b) = map(MB) else { sys_exit(2) };
            let n = sys_read(pipes[i][0] as u64, b.as_mut_ptr(), MB as u64);
            sys_exit(if n == 1 && b[0] == b'x' { 0 } else { 1 });
        }
        pids[i] = pid;
        sys_close(pipes[i][0] as u64);
    }
    msleep(200);
    for p in &pipes {
        sys_write(p[1] as u64, b"x".as_ptr(), 1);
        sys_close(p[1] as u64);
    }
    let mut failed = 0;
    for &pid in &pids {
        let mut st = 0i32;
        if sys_wait4(pid, &mut st, 0, 0) != pid || st != 0 {
            failed += 1;
        }
    }
    if failed == 0 {
        verdict(NAME, b"", 0)
    } else {
        verdict(NAME, b"readers failed", failed)
    }
}

//! getdents64 position semantics (Linux iterate_dir): the directory
//! position lives in the open file, each call resumes after the last
//! returned entry and returns 0 at the end; d_off cookies work with
//! lseek (telldir/seekdir), lseek(0) rewinds, and a buffer too small for
//! one entry is EINVAL

use super::helpers::{print, print_num, println};
use hk_syscall::{
    sys_close, sys_getdents64, sys_lseek, sys_mkdir, sys_open, sys_rmdir, sys_unlink, O_CREAT,
    O_DIRECTORY, O_RDONLY, O_WRONLY, SEEK_SET,
};

const EINVAL: i64 = -22;
/// Bail out of a walk that never ends (getdents restarting at 0)
const MAX_ENTRIES: usize = 4000;

pub fn run_tests() {
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777); // hk boots without /tmp
    check_dir(b"/tmp", b"GETDENTS_RAMFS", 300);
    check_proc();
    #[cfg(target_arch = "x86_64")]
    check_legacy();
}

/// Legacy getdents (x86-64): struct linux_dirent records (d_ino, d_off,
/// d_reclen, d_name, d_type in the last byte), 8-byte aligned
#[cfg(target_arch = "x86_64")]
fn check_legacy() {
    const NAME: &[u8] = b"GETDENTS_LEGACY";
    const N: usize = 40;
    let mut p = [0u8; 64];
    let dir: &[u8] = b"/tmp/gdl";
    if sys_mkdir(join(&mut p, dir, b"").as_ptr(), 0o755) != 0 {
        return verdict(NAME, b"mkdir", -1);
    }
    for i in 0..N {
        let fd = sys_open(join(&mut p, dir, &fname(i)).as_ptr(), O_CREAT | O_WRONLY, 0o644);
        sys_close(fd as u64);
    }
    let why = legacy_walk(dir, N);
    for i in 0..N {
        sys_unlink(join(&mut p, dir, &fname(i)).as_ptr());
    }
    sys_rmdir(join(&mut p, dir, b"").as_ptr());
    match why {
        Ok(()) => verdict(NAME, b"", 0),
        Err((w, got)) => verdict(NAME, w, got),
    }
}

#[cfg(target_arch = "x86_64")]
fn legacy_walk(dir: &[u8], n: usize) -> Result<(), (&'static [u8], i64)> {
    const DT_DIR: u8 = 4;
    const DT_REG: u8 = 8;
    let mut p = [0u8; 64];
    let fd = sys_open(join(&mut p, dir, b"").as_ptr(), O_RDONLY | O_DIRECTORY, 0);
    if fd < 0 {
        return Err((b"open", fd));
    }
    let mut seen = [0u8; 64];
    let (mut dots, mut bad) = (0i64, 0i64);
    let mut buf = [0u8; 200];
    let r = loop {
        let r = hk_syscall::sys_getdents(fd as u64, buf.as_mut_ptr(), buf.len() as u64);
        if r <= 0 {
            break r;
        }
        let mut off = 0usize;
        while off < r as usize {
            let reclen = u16::from_ne_bytes([buf[off + 16], buf[off + 17]]) as usize;
            if reclen < 24 || reclen % 8 != 0 || off + reclen > r as usize {
                sys_close(fd as u64);
                return Err((b"reclen", reclen as i64));
            }
            let rec = &buf[off..off + reclen];
            let name = &rec[18..reclen - 1];
            let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())];
            let ty = rec[reclen - 1];
            match idx(name) {
                Some(i) if i < n && ty == DT_REG => seen[i] += 1,
                _ if (name == b"." || name == b"..") && ty == DT_DIR => dots += 1,
                _ => bad += 1,
            }
            off += reclen;
        }
    };
    sys_close(fd as u64);
    if r < 0 {
        return Err((b"getdents", r));
    }
    if let Some(i) = seen[..n].iter().position(|&c| c != 1) {
        return Err((b"entry count", i as i64));
    }
    if dots != 2 || bad != 0 {
        return Err((b"dots/bad", dots * 1000 + bad));
    }
    Ok(())
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

/// Read all entries of `fd` with `bufsz`-byte calls, `f(name, d_off)`
/// per entry. Returns the number of entries, or the failing errno.
fn walk(fd: i64, bufsz: usize, f: &mut dyn FnMut(&[u8], i64)) -> i64 {
    let mut buf = [0u8; 512];
    let mut total = 0usize;
    loop {
        let n = sys_getdents64(fd as u64, buf.as_mut_ptr(), bufsz as u64);
        if n <= 0 {
            return if n < 0 { n } else { total as i64 };
        }
        let mut off = 0usize;
        while off < n as usize {
            let d_off = i64::from_ne_bytes(buf[off + 8..off + 16].try_into().unwrap());
            let reclen = u16::from_ne_bytes([buf[off + 16], buf[off + 17]]) as usize;
            if reclen < 20 || off + reclen > n as usize {
                return -1000;
            }
            let name = &buf[off + 19..off + reclen];
            let len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
            f(&name[..len], d_off);
            total += 1;
            off += reclen;
        }
        if total > MAX_ENTRIES {
            return -1001;
        }
    }
}

/// Index of a "fNNN" name, if it is one
fn idx(name: &[u8]) -> Option<usize> {
    if name.len() != 4 || (name[0] != b'f' && name[0] != b'F') {
        return None;
    }
    let mut v = 0usize;
    for &c in &name[1..] {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (c - b'0') as usize;
    }
    Some(v)
}

/// `dir/name` NUL-terminated into `buf`
fn join<'a>(buf: &'a mut [u8; 64], dir: &[u8], name: &[u8]) -> &'a [u8] {
    let sep: &[u8] = if name.is_empty() { b"" } else { b"/" };
    let mut i = 0;
    for &b in dir.iter().chain(sep).chain(name) {
        buf[i] = b;
        i += 1;
    }
    buf[i] = 0;
    &buf[..=i]
}

fn fname(i: usize) -> [u8; 4] {
    [
        b'f',
        b'0' + (i / 100) as u8,
        b'0' + (i / 10 % 10) as u8,
        b'0' + (i % 10) as u8,
    ]
}

/// One full pass: every fNNN (< n) once, "." and ".." once, nothing else
fn full_pass(fd: i64, n: usize, seen: &mut [u8; 512]) -> Result<(), (&'static [u8], i64)> {
    seen.fill(0);
    let mut dots = 0;
    let mut other = 0;
    let r = walk(fd, 128, &mut |name, _| match idx(name) {
        Some(i) if i < n => seen[i] += 1,
        _ if name == b"." || name == b".." => dots += 1,
        _ => other += 1,
    });
    if r < 0 {
        return Err((b"walk", r));
    }
    if let Some(i) = seen[..n].iter().position(|&c| c != 1) {
        return Err((b"entry count", seen[i] as i64 * 1000 + i as i64));
    }
    if dots != 2 || other != 0 {
        return Err((b"dots/other", dots * 1000 + other));
    }
    Ok(())
}

/// Create `n` files under `prefix/gdt`, then check iteration, rewind,
/// seekdir and unlink-while-iterating; `n` <= 512
pub fn check_dir(prefix: &[u8], name: &[u8], n: usize) {
    let mut dbuf = [0u8; 64];
    let dlen = join(&mut dbuf, prefix, b"gdt").len() - 1;
    let dir = &dbuf[..dlen];
    let mut p = [0u8; 64];
    let r = sys_mkdir(join(&mut p, dir, b"").as_ptr(), 0o755);
    if r != 0 {
        return verdict(name, b"mkdir", r);
    }
    for i in 0..n {
        let fd = sys_open(join(&mut p, dir, &fname(i)).as_ptr(), O_CREAT | O_WRONLY, 0o644);
        if fd < 0 {
            return verdict(name, b"create", fd);
        }
        sys_close(fd as u64);
    }
    let why = check_open_dir(&mut p, dir, n);
    // Remove whatever the checks left behind
    for i in 0..n {
        sys_unlink(join(&mut p, dir, &fname(i)).as_ptr());
    }
    sys_rmdir(join(&mut p, dir, b"").as_ptr());
    match why {
        Ok(()) => verdict(name, b"", 0),
        Err((w, got)) => verdict(name, w, got),
    }
}

fn check_open_dir(p: &mut [u8; 64], dir: &[u8], n: usize) -> Result<(), (&'static [u8], i64)> {
    let fd = sys_open(join(p, dir, b"").as_ptr(), O_RDONLY | O_DIRECTORY, 0);
    if fd < 0 {
        return Err((b"open", fd));
    }
    let r = check_fd(fd, dir, n);
    sys_close(fd as u64);
    r
}

fn check_fd(fd: i64, dir: &[u8], n: usize) -> Result<(), (&'static [u8], i64)> {
    let mut buf = [0u8; 64];
    let r = sys_getdents64(fd as u64, buf.as_mut_ptr(), 8);
    if r != EINVAL {
        return Err((b"tiny buffer", r));
    }
    let mut seen = [0u8; 512];
    full_pass(fd, n, &mut seen)?;
    // At the end: stays at the end
    let r = sys_getdents64(fd as u64, buf.as_mut_ptr(), buf.len() as u64);
    if r != 0 {
        return Err((b"after end", r));
    }

    // rewinddir, then a full pass again; remember the cookie of entry
    // 100 and the name that follows it
    let r = sys_lseek(fd as i32, 0, SEEK_SET);
    if r != 0 {
        return Err((b"rewind", r));
    }
    let mut k = 0usize;
    let mut cookie = -1i64;
    let mut next = [0u8; 8];
    let mut next_len = 0;
    let r = walk(fd, 128, &mut |name, d_off| {
        if k == n / 3 {
            cookie = d_off;
        }
        if k == n / 3 + 1 {
            next_len = name.len().min(8);
            next[..next_len].copy_from_slice(&name[..next_len]);
        }
        k += 1;
    });
    if r != (n + 2) as i64 {
        return Err((b"second pass", r));
    }

    // seekdir(telldir()) resumes right after that entry
    let r = sys_lseek(fd as i32, cookie, SEEK_SET);
    if r != cookie {
        return Err((b"seekdir", r));
    }
    let mut first = [0u8; 8];
    let mut first_len = 0;
    let mut got_one = false;
    let mut b2 = [0u8; 64];
    let r = sys_getdents64(fd as u64, b2.as_mut_ptr(), b2.len() as u64);
    if r > 0 {
        let reclen = u16::from_ne_bytes([b2[16], b2[17]]) as usize;
        let name = &b2[19..reclen];
        first_len = name.iter().position(|&b| b == 0).unwrap_or(name.len()).min(8);
        first[..first_len].copy_from_slice(&name[..first_len]);
        got_one = true;
    }
    if !got_one || first[..first_len] != next[..next_len] {
        return Err((b"seekdir resume", r));
    }

    // rm -r pattern: unlink each entry as it is returned; every file is
    // still returned exactly once
    sys_lseek(fd as i32, 0, SEEK_SET);
    seen.fill(0);
    let r = walk(fd, 128, &mut |name, _| {
        if let Some(i) = idx(name).filter(|&i| i < n) {
            seen[i] += 1;
            let mut q = [0u8; 64];
            sys_unlink(join(&mut q, dir, name).as_ptr());
        }
    });
    if r < 0 {
        return Err((b"unlink walk", r));
    }
    if let Some(i) = seen[..n].iter().position(|&c| c != 1) {
        return Err((b"unlink walk count", seen[i] as i64 * 1000 + i as i64));
    }
    Ok(())
}

/// /proc read in small chunks: no name twice, "self" and "1" present
fn check_proc() {
    let fd = sys_open(b"/proc\0".as_ptr(), O_RDONLY | O_DIRECTORY, 0);
    if fd < 0 {
        return verdict(b"GETDENTS_PROC", b"open", fd);
    }
    let mut names = [[0u8; 16]; 256];
    let mut lens = [0usize; 256];
    let mut cnt = 0usize;
    let mut dup = 0i64;
    let r = walk(fd, 128, &mut |name, _| {
        let l = name.len().min(16);
        if (0..cnt).any(|j| lens[j] == l && names[j][..l] == name[..l]) {
            dup += 1;
        }
        if cnt < 256 {
            names[cnt][..l].copy_from_slice(&name[..l]);
            lens[cnt] = l;
            cnt += 1;
        }
    });
    sys_close(fd as u64);
    let has = |s: &[u8]| (0..cnt).any(|j| lens[j] == s.len() && names[j][..s.len()] == *s);
    if r < 0 {
        verdict(b"GETDENTS_PROC", b"walk", r);
    } else if dup != 0 {
        verdict(b"GETDENTS_PROC", b"duplicates", dup);
    } else if !has(b"self") || !has(b"1") {
        print(b"/proc:");
        for j in 0..cnt {
            print(b" ");
            print(&names[j][..lens[j]]);
        }
        println(b"");
        verdict(b"GETDENTS_PROC", b"missing self/1", cnt as i64);
    } else {
        verdict(b"GETDENTS_PROC", b"", 0);
    }
}

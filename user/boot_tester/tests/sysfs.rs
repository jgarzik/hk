//! sysfs tests (hk and Linux): the mount, attribute files (seq_file
//! read semantics, open permission, lseek), directory link counts.
//! Paths below /sys/devices differ between the kernels; tests use only
//! what both have.

use hk_syscall::{
    LinuxStatFs, O_DIRECTORY, O_RDONLY, O_WRONLY, Stat, sys_close, sys_getdents64, sys_lseek,
    sys_open, sys_read, sys_stat, sys_statfs,
};

use super::helpers::{print, print_num, println};

const EACCES: i64 = -13;
const SYSFS_MAGIC: i64 = 0x6265_6572;
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const DT_DIR: u8 = 4;

pub fn run_tests() {
    println(b"=== sysfs Tests ===");
    test_basic();
}

fn fail(name: &[u8], why: &[u8], v: i64) {
    print(name);
    print(b":FAIL ");
    print(why);
    print(b" ");
    print_num(v);
    println(b"");
}

fn ok(name: &[u8]) {
    print(name);
    println(b":OK");
}

fn stat(path: &[u8]) -> Result<Stat, i64> {
    // SAFETY: Stat is plain data
    let mut st: Stat = unsafe { core::mem::zeroed() };
    let r = sys_stat(path.as_ptr(), &mut st);
    if r < 0 { Err(r) } else { Ok(st) }
}

/// Calls `f(name, d_type)` for each entry of directory `path`; entry
/// count or a negative errno
pub fn each_entry(path: &[u8], f: &mut dyn FnMut(&[u8], u8)) -> i64 {
    let fd = sys_open(path.as_ptr(), O_RDONLY | O_DIRECTORY, 0);
    if fd < 0 {
        return fd;
    }
    let mut buf = [0u8; 2048];
    let mut n = 0;
    loop {
        let r = sys_getdents64(fd as u64, buf.as_mut_ptr(), buf.len() as u64);
        if r <= 0 {
            sys_close(fd as u64);
            return if r < 0 { r } else { n };
        }
        let mut off = 0;
        while off < r as usize {
            let reclen = u16::from_ne_bytes([buf[off + 16], buf[off + 17]]) as usize;
            let ty = buf[off + 18];
            let name = &buf[off + 19..off + reclen];
            let len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
            let name = &name[..len];
            if name != b"." && name != b".." {
                f(name, ty);
                n += 1;
            }
            off += reclen;
        }
    }
}

/// Mount, attribute stat/read/lseek/open, directory nlink
fn test_basic() {
    const N: &[u8] = b"SYSFS_BASIC";
    // SAFETY: LinuxStatFs is plain data
    let mut sf: LinuxStatFs = unsafe { core::mem::zeroed() };
    let r = sys_statfs(b"/sys\0".as_ptr(), &mut sf);
    if r != 0 || sf.f_type != SYSFS_MAGIC {
        return fail(N, b"statfs magic", if r != 0 { r } else { sf.f_type });
    }
    let mut kernel = false;
    let mut fs = false;
    each_entry(b"/sys\0", &mut |name, ty| {
        kernel |= name == b"kernel" && ty == DT_DIR;
        fs |= name == b"fs" && ty == DT_DIR;
    });
    if !kernel || !fs {
        return fail(N, b"/sys lacks kernel or fs", 0);
    }
    match stat(b"/sys/fs/cgroup\0") {
        Ok(st) if st.st_mode & S_IFMT == S_IFDIR => {}
        _ => return fail(N, b"/sys/fs/cgroup", 0),
    }
    // Directory link count: subdirectories + 2
    let mut subdirs = 0;
    each_entry(b"/sys/kernel\0", &mut |_, ty| subdirs += (ty == DT_DIR) as i64);
    match stat(b"/sys/kernel\0") {
        Ok(st) if st.st_nlink as i64 == subdirs + 2 => {}
        Ok(st) => return fail(N, b"nlink", st.st_nlink as i64),
        Err(e) => return fail(N, b"stat /sys/kernel", e),
    }
    // Attributes: regular, mode 0444, size 4096
    let path = b"/sys/kernel/uevent_seqnum\0";
    match stat(path) {
        Ok(st) if st.st_mode == S_IFREG | 0o444 && st.st_size == 4096 => {}
        Ok(st) => return fail(N, b"attr mode", st.st_mode as i64),
        Err(e) => return fail(N, b"stat attr", e),
    }
    if let Err((why, v)) = attr_reads(path) {
        return fail(N, why, v);
    }
    // A read-only attribute refuses write opens, even to root
    let w = sys_open(path.as_ptr(), O_WRONLY, 0);
    if w >= 0 {
        sys_close(w as u64);
    }
    if w != EACCES {
        return fail(N, b"write open", w);
    }
    ok(N);
}

/// Split reads, re-read after lseek(0), SEEK_END from the 4096 size
fn attr_reads(path: &[u8]) -> Result<(), (&'static [u8], i64)> {
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        return Err((b"open attr", fd));
    }
    let r = (|| {
        let mut a = [0u8; 64];
        let n1 = sys_read(fd as u64, a.as_mut_ptr(), 1);
        let n2 = sys_read(fd as u64, a[1..].as_mut_ptr(), 63);
        let n3 = sys_read(fd as u64, a.as_mut_ptr(), 8);
        if n1 != 1 || n2 < 1 || n3 != 0 {
            return Err((&b"split read"[..], n2));
        }
        let len = (1 + n2) as usize;
        if a[len - 1] != b'\n' || !a[..len - 1].iter().all(u8::is_ascii_digit) {
            return Err((&b"format"[..], len as i64));
        }
        if sys_lseek(fd as i32, 0, 0) != 0 {
            return Err((&b"lseek 0"[..], -1));
        }
        let mut b = [0u8; 64];
        let m = sys_read(fd as u64, b.as_mut_ptr(), 64);
        if m < 2 || b[m as usize - 1] != b'\n' {
            return Err((&b"re-read"[..], m));
        }
        let e = sys_lseek(fd as i32, 0, 2);
        if e != 4096 {
            return Err((&b"SEEK_END"[..], e));
        }
        Ok(())
    })();
    sys_close(fd as u64);
    r
}

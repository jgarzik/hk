//! What /proc and statx say about mounts (Linux fs/proc_namespace.c,
//! fs/proc/fd.c, vfs_getattr): mountinfo lines, the mount id statx and
//! fdinfo report, /proc/self/{cwd,root}, /proc/mounts -> self/mounts

use super::helpers::{print, print_num, println};
use hk_syscall::{
    O_CLOEXEC, O_CREAT, O_RDONLY, O_RDWR, Statx, sys_chdir, sys_close, sys_mkdir, sys_mount,
    sys_open, sys_read, sys_readlink, sys_rmdir, sys_statx, sys_umount2, sys_unlink, sys_write,
};

const AT_FDCWD: i32 = -100;
const STATX_INO: u32 = 0x100;
const STATX_MNT_ID: u32 = 0x1000;
const STATX_MNT_ID_UNIQUE: u32 = 0x4000;

pub fn run_tests() {
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777); // hk boots without /tmp
    let mi = b"/tmp/mi\0";
    sys_mkdir(mi.as_ptr(), 0o755);
    if sys_mount(b"none\0".as_ptr(), mi.as_ptr(), b"ramfs\0".as_ptr(), 0, 0) != 0 {
        println(b"MOUNTINFO:FAIL mount");
        sys_rmdir(mi.as_ptr());
        return;
    }
    let id = mountinfo_id(b"/tmp/mi");
    report(b"MOUNTINFO", check_mountinfo(id));
    report(b"STATX_MNT_ID", check_statx(id));
    report(b"FDINFO_FIELDS", check_fdinfo(id));
    report(b"PROC_CWD_ROOT", check_cwd_root());
    sys_chdir(b"/\0".as_ptr());
    sys_unlink(b"/tmp/mi/f\0".as_ptr());
    sys_umount2(mi.as_ptr(), 0);
    sys_rmdir(mi.as_ptr());
}

type R = Result<(), (&'static [u8], i64)>;

fn report(name: &[u8], r: R) {
    print(name);
    match r {
        Ok(()) => println(b":OK"),
        Err((why, got)) => {
            print(b":FAIL ");
            print(why);
            print(b" got ");
            print_num(got);
            println(b"");
        }
    }
}

fn check(what: &'static [u8], ok: bool, got: i64) -> R {
    if ok { Ok(()) } else { Err((what, got)) }
}

/// Read a whole (small) file
pub fn slurp_pub(path: &[u8], buf: &mut [u8]) -> usize {
    slurp(path, buf)
}

fn slurp(path: &[u8], buf: &mut [u8]) -> usize {
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        return 0;
    }
    let mut n = 0;
    while n < buf.len() {
        let r = sys_read(fd as u64, buf[n..].as_mut_ptr(), (buf.len() - n) as u64);
        if r <= 0 {
            break;
        }
        n += r as usize;
    }
    sys_close(fd as u64);
    n
}

fn num(s: &[u8]) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut v = 0u64;
    for &c in s {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (c - b'0') as u64;
    }
    Some(v)
}

/// The mountinfo line whose mountpoint (field 5) is `mp`
fn line_for<'a>(text: &'a [u8], mp: &[u8]) -> Option<&'a [u8]> {
    text.split(|&c| c == b'\n')
        .find(|l| l.split(|&c| c == b' ').nth(4) == Some(mp))
}

fn mountinfo_id(mp: &[u8]) -> u64 {
    let mut buf = [0u8; 8192];
    let n = slurp(b"/proc/self/mountinfo\0", &mut buf);
    line_for(&buf[..n], mp)
        .and_then(|l| l.split(|&c| c == b' ').next())
        .and_then(num)
        .unwrap_or(0)
}

/// The line of /tmp/mi: id, a parent id that is another line's id,
/// major:minor, root "/", options from "rw", then "- ramfs none rw"
fn check_mountinfo(id: u64) -> R {
    let mut buf = [0u8; 8192];
    let n = slurp(b"/proc/self/mountinfo\0", &mut buf);
    let text = &buf[..n];
    check(b"read", n > 0, 0)?;
    let line = line_for(text, b"/tmp/mi").ok_or((&b"no line"[..], 0))?;
    let f: [&[u8]; 6] = {
        let mut it = line.split(|&c| c == b' ');
        core::array::from_fn(|_| it.next().unwrap_or(b""))
    };
    check(b"id", id != 0, 0)?;
    let parent = num(f[1]).ok_or((&b"parent"[..], 0))?;
    let parent_listed = text
        .split(|&c| c == b'\n')
        .any(|l| l.split(|&c| c == b' ').next().and_then(num) == Some(parent));
    check(
        b"parent listed",
        parent_listed && parent != id,
        parent as i64,
    )?;
    check(b"major:minor", f[2].contains(&b':'), 0)?;
    check(b"root", f[3] == b"/", 0)?;
    check(b"options", f[5].starts_with(b"rw"), 0)?;
    let tail = line
        .windows(3)
        .position(|w| w == b" - ")
        .map(|i| &line[i + 3..])
        .ok_or((&b"separator"[..], 0))?;
    check(b"type source", tail.starts_with(b"ramfs none rw"), 0)?;
    // /proc/mounts is a link to self/mounts, which lists it too
    let mut l = [0u8; 32];
    let r = sys_readlink(b"/proc/mounts\0".as_ptr(), l.as_mut_ptr(), l.len() as u64);
    check(
        b"/proc/mounts link",
        r == 11 && l[..11] == *b"self/mounts",
        r,
    )?;
    let n = slurp(b"/proc/self/mounts\0", &mut buf);
    let listed = buf[..n]
        .split(|&c| c == b'\n')
        .any(|l| l.starts_with(b"none /tmp/mi ramfs rw"));
    check(b"self/mounts", listed, n as i64)
}

fn statx(path: &[u8], mask: u32) -> Result<Statx, i64> {
    // SAFETY: Statx is plain integers
    let mut st: Statx = unsafe { core::mem::zeroed() };
    match sys_statx(AT_FDCWD, path.as_ptr(), 0, mask, &mut st) {
        0 => Ok(st),
        e => Err(e),
    }
}

/// statx always reports the mount id; the unique one (from 2^31) when
/// asked for it
fn check_statx(id: u64) -> R {
    let st = statx(b"/tmp/mi\0", STATX_INO).map_err(|e| (&b"statx"[..], e))?;
    check(b"mask", st.stx_mask & STATX_MNT_ID != 0, st.stx_mask as i64)?;
    check(b"mnt_id", st.stx_mnt_id == id, st.stx_mnt_id as i64)?;
    let u = statx(b"/tmp/mi\0", STATX_MNT_ID_UNIQUE).map_err(|e| (&b"statx unique"[..], e))?;
    check(
        b"unique mask",
        u.stx_mask & STATX_MNT_ID_UNIQUE != 0,
        u.stx_mask as i64,
    )?;
    // Above 2^31 (Linux 6.11+, hk) or 2^32 (older): never a reused id
    check(
        b"unique id",
        u.stx_mnt_id > i32::MAX as u64,
        u.stx_mnt_id as i64,
    )
}

/// The value of `key:\t` in fdinfo text
fn field<'a>(text: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    text.split(|&c| c == b'\n')
        .find(|l| l.starts_with(key) && l.get(key.len()) == Some(&b':'))
        .map(|l| &l[key.len() + 2..])
}

fn octal(s: &[u8]) -> Option<u64> {
    let mut v = 0u64;
    for &c in s {
        if !(b'0'..=b'7').contains(&c) {
            return None;
        }
        v = v * 8 + (c - b'0') as u64;
    }
    Some(v)
}

/// fdinfo: pos, flags (octal with a leading 0, O_CLOEXEC included),
/// mnt_id, ino
fn check_fdinfo(id: u64) -> R {
    let fd = sys_open(b"/tmp/mi/f\0".as_ptr(), O_CREAT | O_RDWR | O_CLOEXEC, 0o644);
    check(b"open", fd >= 0, fd)?;
    sys_write(fd as u64, b"hello".as_ptr(), 5);
    let mut path = *b"/proc/self/fdinfo/\0\0\0\0";
    let mut d = [0u8; 4];
    let (mut v, mut k) = (fd as u32, 0);
    loop {
        d[k] = b'0' + (v % 10) as u8;
        k += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for i in 0..k {
        path[18 + i] = d[k - 1 - i];
    }
    let mut buf = [0u8; 512];
    let n = slurp(&path, &mut buf);
    sys_close(fd as u64);
    let t = &buf[..n];
    let st = statx(b"/tmp/mi/f\0", STATX_INO).map_err(|e| (&b"statx"[..], e))?;
    check(b"pos", field(t, b"pos") == Some(b"5"), n as i64)?;
    let flags = field(t, b"flags").ok_or((&b"flags"[..], 0))?;
    check(b"flags leading 0", flags.first() == Some(&b'0'), 0)?;
    let f = octal(flags).ok_or((&b"flags octal"[..], 0))?;
    check(b"flags cloexec", f & O_CLOEXEC as u64 != 0, f as i64)?;
    check(b"flags rdwr", f & 3 == O_RDWR as u64, f as i64)?;
    check(b"mnt_id", field(t, b"mnt_id").and_then(num) == Some(id), 0)?;
    check(
        b"ino",
        field(t, b"ino").and_then(num) == Some(st.stx_ino),
        0,
    )
}

/// /proc/self/cwd and root name the cwd and root
fn check_cwd_root() -> R {
    check(b"chdir", sys_chdir(b"/tmp/mi\0".as_ptr()) == 0, -1)?;
    let mut b = [0u8; 64];
    let r = sys_readlink(b"/proc/self/cwd\0".as_ptr(), b.as_mut_ptr(), b.len() as u64);
    check(b"cwd", r == 7 && b[..7] == *b"/tmp/mi", r)?;
    let r = sys_readlink(
        b"/proc/self/root\0".as_ptr(),
        b.as_mut_ptr(),
        b.len() as u64,
    );
    check(b"root", r == 1 && b[0] == b'/', r)
}

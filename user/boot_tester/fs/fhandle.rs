//! File handles (Linux fs/fhandle.c, fs/exportfs/expfs.c, mm/shmem.c
//! shmem_export_ops), on a fresh tmpfs and ramfs:
//!
//! - FHANDLE_ENCODE: a tmpfs handle is 12 bytes of type 1 (generation,
//!   inode number low, high); the mount id is statx's; AT_HANDLE_FID
//!   gives the same handle
//! - FHANDLE_OVERFLOW: too small a buffer is EOVERFLOW with 12 bytes and
//!   type 255 written back, the mount id too; more than 128 is EINVAL
//! - FHANDLE_FLAGS: unknown flags and AT_HANDLE_CONNECTABLE with
//!   AT_HANDLE_FID or AT_EMPTY_PATH are EINVAL; a connectable handle is
//!   EOPNOTSUPP on tmpfs (6.13+; before, an unknown flag)
//! - FHANDLE_PATHS: a symlink's own handle, its target's with
//!   AT_SYMLINK_FOLLOW; AT_EMPTY_PATH on a descriptor; an empty name
//!   without it is ENOENT
//! - FHANDLE_OPEN: the handle opens the file (its data, inode, and path
//!   under the mount fd: a descriptor of the mount, of a file on it, or
//!   AT_FDCWD); a directory's opens O_DIRECTORY; a file's with
//!   O_DIRECTORY is ENOTDIR; a symlink's is ELOOP unless O_PATH
//! - FHANDLE_OPEN_FLAGS: O_CLOEXEC sets FD_CLOEXEC, O_CREAT|O_EXCL is
//!   EEXIST, O_CREAT of a directory EISDIR, O_TMPFILE makes a file in
//!   the directory
//! - FHANDLE_BIND: through a bind mount's descriptor the path is the
//!   bind mount's
//! - FHANDLE_STALE: an unlinked file's handle opens while it is open
//!   ("(deleted)") and is ESTALE once it is gone; a wrong generation or
//!   a short handle is ESTALE, 0 or 129 bytes EINVAL, a negative type or
//!   unknown user flags EINVAL (6.13+); a handle stays valid across
//!   drop_caches
//! - FHANDLE_MOUNT_FD: a bad mount fd is EBADF, one on a filesystem
//!   without export operations (procfs) ESTALE
//! - FHANDLE_FID: ramfs and pipes have no export operations: EOPNOTSUPP,
//!   but AT_HANDLE_FID gives a file id (type 0x81: inode number low,
//!   high, generation 0) that does not open (ESTALE)
//! - FHANDLE_MNT_ID_UNIQUE (6.12+): the u64 unique mount id, statx's
//!   STATX_MNT_ID_UNIQUE
//! - FHANDLE_PERM: without CAP_DAC_READ_SEARCH open_by_handle_at is
//!   EPERM, O_DIRECTORY too; name_to_handle_at needs nothing

use crate::harness::{R, check, report_r};
use crate::helpers::linux_at_least;
use hk_syscall::{
    _LINUX_CAPABILITY_VERSION_3, CapUserData, CapUserHeader, O_CREAT, O_DIRECTORY, O_EXCL, O_PATH,
    O_RDONLY, O_RDWR, O_WRONLY, Stat, Statx, sys_capget, sys_capset, sys_chdir, sys_close,
    sys_exit, sys_fcntl, sys_fork, sys_fstat, sys_mkdir, sys_mount, sys_name_to_handle_at,
    sys_open, sys_open_by_handle_at, sys_pipe2, sys_read, sys_readlink, sys_rmdir, sys_statx,
    sys_symlink, sys_umount2, sys_unlink, sys_wait4, sys_write,
};

const ENOENT: i64 = -2;
const EBADF: i64 = -9;
const EEXIST: i64 = -17;
const ENOTDIR: i64 = -20;
const EISDIR: i64 = -21;
const EINVAL: i64 = -22;
const ELOOP: i64 = -40;
const EPERM: i64 = -1;
const EOVERFLOW: i64 = -75;
const EOPNOTSUPP: i64 = -95;
const ESTALE: i64 = -116;

const AT_FDCWD: i32 = -100;
const AT_EMPTY_PATH: i32 = 0x1000;
const AT_SYMLINK_FOLLOW: i32 = 0x400;
const AT_RECURSIVE: i32 = 0x8000;
const AT_HANDLE_FID: i32 = 0x200;
const AT_HANDLE_MNT_ID_UNIQUE: i32 = 0x001;
const AT_HANDLE_CONNECTABLE: i32 = 0x002;
const STATX_INO: u32 = 0x100;
const STATX_MNT_ID: u32 = 0x1000;
const STATX_MNT_ID_UNIQUE: u32 = 0x4000;
const O_CLOEXEC: u32 = 0o2000000;
const O_TMPFILE: u32 = 0o20000000 | O_DIRECTORY;
const F_GETFD: i32 = 1;
const MS_BIND: u64 = 4096;
const CAP_DAC_READ_SEARCH: u32 = 2;
const MAX_HANDLE_SZ: u32 = 128;

const MP: &[u8] = b"/tmp/fh\0";
const F: &[u8] = b"/tmp/fh/f\0";
const D: &[u8] = b"/tmp/fh/d\0";
const X: &[u8] = b"/tmp/fh/d/x\0";
const S: &[u8] = b"/tmp/fh/s\0";
const G: &[u8] = b"/tmp/fh/g\0";
const RAM: &[u8] = b"/tmp/fhr\0";
const RAMF: &[u8] = b"/tmp/fhr/f\0";
const BIND: &[u8] = b"/tmp/fhb\0";

/// struct file_handle with room for MAX_HANDLE_SZ bytes
#[repr(C)]
#[derive(Clone, Copy)]
struct Fh {
    bytes: u32,
    ty: i32,
    f: [u32; 32],
}

impl Fh {
    fn new(room: u32) -> Self {
        Self {
            bytes: room,
            ty: 0,
            f: [0; 32],
        }
    }

    fn ptr(&mut self) -> *mut u8 {
        (self as *mut Self).cast()
    }

    /// Same type and bytes
    fn same(&self, o: &Fh) -> bool {
        let n = (self.bytes / 4) as usize;
        self.bytes == o.bytes && self.ty == o.ty && self.f[..n] == o.f[..n]
    }
}

pub fn run_tests() {
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777);
    sys_mkdir(MP.as_ptr(), 0o755);
    let m = sys_mount(b"tmpfs\0".as_ptr(), MP.as_ptr(), b"tmpfs\0".as_ptr(), 0, 0);
    if m != 0 {
        report_r(b"FHANDLE_SETUP", Err((b"mount", m)));
        sys_rmdir(MP.as_ptr());
        return;
    }
    let fd = sys_open(F.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    sys_write(fd as u64, b"hello".as_ptr(), 5);
    sys_close(fd as u64);
    sys_mkdir(D.as_ptr(), 0o755);
    sys_close(sys_open(X.as_ptr(), O_CREAT | O_WRONLY, 0o644) as u64);
    sys_symlink(b"f\0".as_ptr(), S.as_ptr());
    report_r(b"FHANDLE_ENCODE", encode());
    report_r(b"FHANDLE_OVERFLOW", overflow());
    report_r(b"FHANDLE_FLAGS", flags());
    report_r(b"FHANDLE_PATHS", paths());
    report_r(b"FHANDLE_OPEN", open());
    report_r(b"FHANDLE_OPEN_FLAGS", open_flags());
    report_r(b"FHANDLE_BIND", bind());
    report_r(b"FHANDLE_STALE", stale());
    report_r(b"FHANDLE_MOUNT_FD", mount_fd());
    report_r(b"FHANDLE_FID", fid());
    if linux_at_least(6, 12) {
        report_r(b"FHANDLE_MNT_ID_UNIQUE", mnt_id_unique());
    }
    report_r(b"FHANDLE_PERM", perm());
    sys_umount2(MP.as_ptr(), 0);
    sys_rmdir(MP.as_ptr());
}

/// name_to_handle_at into `fh`, the int mount id into `id`
fn n2h(dfd: i32, p: &[u8], fh: &mut Fh, id: &mut i64, flag: i32) -> i64 {
    sys_name_to_handle_at(dfd, p.as_ptr(), fh.ptr(), (id as *mut i64).cast(), flag)
}

/// The handle of `p` (0 flags), or the error
fn handle(p: &[u8], flag: i32) -> Result<Fh, (&'static [u8], i64)> {
    let mut fh = Fh::new(MAX_HANDLE_SZ);
    let mut id = 0;
    let r = n2h(AT_FDCWD, p, &mut fh, &mut id, flag);
    check(b"name_to_handle_at", r == 0, r)?;
    Ok(fh)
}

/// open_by_handle_at, closing nothing
fn obh(mfd: i32, fh: &Fh, flags: u32) -> i64 {
    sys_open_by_handle_at(mfd, (fh as *const Fh).cast(), flags)
}

/// open_by_handle_at's result, the descriptor closed
fn obh_ret(mfd: i32, fh: &Fh, flags: u32) -> i64 {
    let r = obh(mfd, fh, flags);
    if r >= 0 {
        sys_close(r as u64);
        return 0;
    }
    r
}

/// An O_RDONLY descriptor of `p` (O_DIRECTORY if `dir`)
fn open_fd(p: &[u8], dir: bool) -> Result<i32, (&'static [u8], i64)> {
    let fd = sys_open(p.as_ptr(), O_RDONLY | if dir { O_DIRECTORY } else { 0 }, 0);
    check(b"open", fd >= 0, fd)?;
    Ok(fd as i32)
}

fn statx(p: &[u8], mask: u32) -> Statx {
    let mut st = Statx::default();
    sys_statx(AT_FDCWD, p.as_ptr(), 0, mask, &mut st);
    st
}

/// The path /proc/self/fd/<fd> links to, in `b`
fn fd_link(fd: i32, b: &mut [u8; 64]) -> usize {
    let mut p = *b"/proc/self/fd/\0\0\0\0\0";
    let mut d = [0u8; 4];
    let (mut v, mut k) = (fd as u32, 0);
    loop {
        d[k] = b'0' + (v % 10) as u8;
        k += 1;
        v /= 10;
        if v == 0 || k == d.len() {
            break;
        }
    }
    for i in 0..k {
        p[14 + i] = d[k - 1 - i];
    }
    sys_readlink(p.as_ptr(), b.as_mut_ptr(), 64).max(0) as usize
}

/// open_by_handle_at opens a descriptor linking to `want`
fn opens_at(mfd: i32, fh: &Fh, flags: u32, want: &[u8]) -> R {
    let fd = obh(mfd, fh, flags);
    check(b"open_by_handle_at", fd >= 0, fd)?;
    let mut b = [0u8; 64];
    let n = fd_link(fd as i32, &mut b);
    sys_close(fd as u64);
    check(b"path", &b[..n] == want, n as i64)
}

/// A tmpfs handle is the generation, then the inode number's halves;
/// AT_HANDLE_FID makes the same; the mount id is statx's
fn encode() -> R {
    let mut fh = Fh::new(MAX_HANDLE_SZ);
    let mut id = -1i64;
    let r = n2h(AT_FDCWD, F, &mut fh, &mut id, 0);
    check(b"name_to_handle_at", r == 0, r)?;
    check(b"handle_bytes", fh.bytes == 12, i64::from(fh.bytes))?;
    check(b"handle_type", fh.ty == 1, i64::from(fh.ty))?;
    let st = statx(F, STATX_INO | STATX_MNT_ID);
    let ino = u64::from(fh.f[2]) << 32 | u64::from(fh.f[1]);
    check(b"inode number", ino == st.stx_ino, ino as i64)?;
    // An int: the high half of the u64 stays as it was
    let got = id & 0xffff_ffff;
    check(b"mount id", got as u64 == st.stx_mnt_id, got)?;
    check(b"mount id is an int", id >> 32 == -1, id)?;
    let fid = handle(F, AT_HANDLE_FID)?;
    check(b"fid same", fid.same(&fh), i64::from(fid.ty))
}

/// Too small: EOVERFLOW with the size needed and type 255, mount id
/// written; past MAX_HANDLE_SZ: EINVAL
fn overflow() -> R {
    let st = statx(F, STATX_MNT_ID);
    for room in [0u32, 11] {
        let mut fh = Fh::new(room);
        let mut id = -1i64;
        let r = n2h(AT_FDCWD, F, &mut fh, &mut id, 0);
        check(b"too small", r == EOVERFLOW, r)?;
        check(b"bytes needed", fh.bytes == 12, i64::from(fh.bytes))?;
        check(b"type invalid", fh.ty == 255, i64::from(fh.ty))?;
        check(b"body untouched", fh.f[0] == 0, i64::from(fh.f[0]))?;
        check(b"mount id", (id & 0xffff_ffff) as u64 == st.stx_mnt_id, id)?;
    }
    let mut fh = Fh::new(MAX_HANDLE_SZ + 1);
    let mut id = 0;
    let r = n2h(AT_FDCWD, F, &mut fh, &mut id, 0);
    check(b"past MAX_HANDLE_SZ", r == EINVAL, r)?;
    // 13 bytes of room: three words fit
    let mut fh = Fh::new(13);
    let r = n2h(AT_FDCWD, F, &mut fh, &mut id, 0);
    check(b"13 bytes", r == 0 && fh.bytes == 12, r)
}

/// Flag checks
fn flags() -> R {
    let mut fh = Fh::new(MAX_HANDLE_SZ);
    let mut id = 0;
    let r = n2h(AT_FDCWD, F, &mut fh, &mut id, AT_RECURSIVE);
    check(b"unknown flag", r == EINVAL, r)?;
    let both = AT_HANDLE_CONNECTABLE | AT_HANDLE_FID;
    let r = n2h(AT_FDCWD, F, &mut fh, &mut id, both);
    check(b"connectable fid", r == EINVAL, r)?;
    let fd = open_fd(F, false)?;
    let r = n2h(
        fd,
        b"\0",
        &mut fh,
        &mut id,
        AT_HANDLE_CONNECTABLE | AT_EMPTY_PATH,
    );
    sys_close(fd as u64);
    check(b"connectable empty path", r == EINVAL, r)?;
    // tmpfs decodes no parent (shmem_export_ops has no fh_to_parent)
    let want = if linux_at_least(6, 13) {
        EOPNOTSUPP
    } else {
        EINVAL
    };
    let r = n2h(AT_FDCWD, F, &mut fh, &mut id, AT_HANDLE_CONNECTABLE);
    check(b"connectable", r == want, r)
}

/// A symlink's own handle unless AT_SYMLINK_FOLLOW; AT_EMPTY_PATH
fn paths() -> R {
    let f = handle(F, 0)?;
    let s = handle(S, 0)?;
    check(b"symlink's own", !s.same(&f), 0)?;
    let t = handle(S, AT_SYMLINK_FOLLOW)?;
    check(b"followed", t.same(&f), 0)?;
    let fd = open_fd(F, false)?;
    let mut e = Fh::new(MAX_HANDLE_SZ);
    let mut id = 0;
    let r1 = n2h(fd, b"\0", &mut e, &mut id, AT_EMPTY_PATH);
    let r2 = n2h(fd, b"\0", &mut e, &mut id, 0);
    sys_close(fd as u64);
    check(b"empty path", r1 == 0 && e.same(&f), r1)?;
    check(b"empty without flag", r2 == ENOENT, r2)
}

/// The handle opens the file and directory under the mount fd
fn open() -> R {
    let f = handle(F, 0)?;
    let mfd = open_fd(MP, true)?;
    let r = (|| {
        let fd = obh(mfd, &f, O_RDONLY);
        check(b"open file", fd >= 0, fd)?;
        let mut b = [0u8; 8];
        let n = sys_read(fd as u64, b.as_mut_ptr(), 8);
        let mut st = Stat::default();
        sys_fstat(fd as i32, &mut st);
        sys_close(fd as u64);
        check(b"data", n == 5 && &b[..5] == b"hello", n)?;
        let ino = u64::from(f.f[2]) << 32 | u64::from(f.f[1]);
        check(b"inode", st.st_ino == ino, st.st_ino as i64)?;
        opens_at(mfd, &f, O_RDONLY, b"/tmp/fh/f")?;
        let d = handle(D, 0)?;
        opens_at(mfd, &d, O_RDONLY | O_DIRECTORY, b"/tmp/fh/d")?;
        let r = obh_ret(mfd, &f, O_RDONLY | O_DIRECTORY);
        check(b"file O_DIRECTORY", r == ENOTDIR, r)?;
        let s = handle(S, 0)?;
        let r = obh_ret(mfd, &s, O_RDONLY);
        check(b"symlink", r == ELOOP, r)?;
        opens_at(mfd, &s, O_PATH, b"/tmp/fh/s")?;
        // A descriptor of a file on the mount serves as well
        let ffd = open_fd(F, false)?;
        let r = opens_at(ffd, &f, O_RDONLY, b"/tmp/fh/f");
        sys_close(ffd as u64);
        r?;
        // And the cwd
        sys_chdir(D.as_ptr());
        let r = opens_at(AT_FDCWD, &f, O_RDWR, b"/tmp/fh/f");
        sys_chdir(b"/\0".as_ptr());
        r
    })();
    sys_close(mfd as u64);
    r
}

/// Open flags go through open(2)'s rules
fn open_flags() -> R {
    let f = handle(F, 0)?;
    let d = handle(D, 0)?;
    let mfd = open_fd(MP, true)?;
    let r = (|| {
        let fd = obh(mfd, &f, O_RDONLY | O_CLOEXEC);
        check(b"O_CLOEXEC", fd >= 0, fd)?;
        let fl = sys_fcntl(fd as i32, F_GETFD, 0);
        sys_close(fd as u64);
        check(b"FD_CLOEXEC", fl == 1, fl)?;
        let r = obh_ret(mfd, &f, O_RDWR | O_CREAT | O_EXCL);
        check(b"O_CREAT|O_EXCL", r == EEXIST, r)?;
        let r = obh_ret(mfd, &d, O_RDONLY | O_CREAT);
        check(b"O_CREAT dir", r == EISDIR, r)?;
        let fd = obh(mfd, &d, O_RDWR | O_TMPFILE);
        check(b"O_TMPFILE", fd >= 0, fd)?;
        let mut b = [0u8; 64];
        let n = fd_link(fd as i32, &mut b);
        sys_close(fd as u64);
        check(
            b"tmpfile path",
            b[..n].starts_with(b"/tmp/fh/d/#"),
            n as i64,
        )
    })();
    sys_close(mfd as u64);
    r
}

/// The path is the mount fd's mount's: a bind mount of d
fn bind() -> R {
    sys_mkdir(BIND.as_ptr(), 0o755);
    let m = sys_mount(D.as_ptr(), BIND.as_ptr(), core::ptr::null(), MS_BIND, 0);
    if m != 0 {
        sys_rmdir(BIND.as_ptr());
        return check(b"bind mount", false, m);
    }
    let r = (|| {
        let x = handle(X, 0)?;
        let bfd = open_fd(BIND, true)?;
        let r = opens_at(bfd, &x, O_RDONLY, b"/tmp/fhb/x");
        sys_close(bfd as u64);
        r
    })();
    sys_umount2(BIND.as_ptr(), 0);
    sys_rmdir(BIND.as_ptr());
    r
}

/// Write "2" to /proc/sys/vm/drop_caches (dentries and inodes)
fn drop_caches() {
    let fd = sys_open(b"/proc/sys/vm/drop_caches\0".as_ptr(), O_WRONLY, 0);
    if fd >= 0 {
        sys_write(fd as u64, b"2".as_ptr(), 1);
        sys_close(fd as u64);
    }
}

/// Stale and malformed handles
fn stale() -> R {
    let mfd = open_fd(MP, true)?;
    let r = (|| {
        let f = handle(F, 0)?;
        drop_caches();
        check(b"after drop_caches", obh_ret(mfd, &f, O_RDONLY) == 0, 0)?;
        // Unlinked while open: still there, then gone
        sys_close(sys_open(G.as_ptr(), O_CREAT | O_WRONLY, 0o644) as u64);
        let g = handle(G, 0)?;
        let keep = open_fd(G, false)?;
        sys_unlink(G.as_ptr());
        let r = opens_at(mfd, &g, O_RDONLY, b"/tmp/fh/g (deleted)");
        sys_close(keep as u64);
        r?;
        let r = obh_ret(mfd, &g, O_RDONLY);
        check(b"unlinked", r == ESTALE, r)?;
        let mut bad = f;
        bad.f[0] ^= 1;
        let r = obh_ret(mfd, &bad, O_RDONLY);
        check(b"generation", r == ESTALE, r)?;
        let mut short = f;
        short.bytes = 8;
        let r = obh_ret(mfd, &short, O_RDONLY);
        check(b"short", r == ESTALE, r)?;
        for n in [0, MAX_HANDLE_SZ + 1] {
            let mut h = f;
            h.bytes = n;
            let r = obh_ret(mfd, &h, O_RDONLY);
            check(b"size", r == EINVAL, r)?;
        }
        if linux_at_least(6, 13) {
            for ty in [-1, 0x4_0001] {
                let mut h = f;
                h.ty = ty;
                let r = obh_ret(mfd, &h, O_RDONLY);
                check(b"type", r == EINVAL, r)?;
            }
        }
        Ok(())
    })();
    sys_close(mfd as u64);
    r
}

/// The mount fd: EBADF (an O_PATH one too: Linux fdget), or a
/// filesystem that does not decode
fn mount_fd() -> R {
    let f = handle(F, 0)?;
    for bad in [-1, 9999] {
        let r = obh_ret(bad, &f, O_RDONLY);
        check(b"bad fd", r == EBADF, r)?;
    }
    const O_PATH: u32 = 0o10000000;
    let opath = sys_open(b"/tmp\0".as_ptr(), O_PATH, 0);
    let r = obh_ret(opath as i32, &f, O_RDONLY);
    sys_close(opath as u64);
    check(b"O_PATH fd", r == EBADF, r)?;
    let pfd = open_fd(b"/proc\0", true)?;
    let r = obh_ret(pfd, &f, O_RDONLY);
    sys_close(pfd as u64);
    check(b"procfs", r == ESTALE, r)
}

/// No export operations: only a file id, which does not open
fn fid() -> R {
    sys_mkdir(RAM.as_ptr(), 0o755);
    let m = sys_mount(b"none\0".as_ptr(), RAM.as_ptr(), b"ramfs\0".as_ptr(), 0, 0);
    if m != 0 {
        sys_rmdir(RAM.as_ptr());
        return check(b"ramfs mount", false, m);
    }
    sys_close(sys_open(RAMF.as_ptr(), O_CREAT | O_WRONLY, 0o644) as u64);
    let r = (|| {
        let mut fh = Fh::new(MAX_HANDLE_SZ);
        let mut id = 0;
        let r = n2h(AT_FDCWD, RAMF, &mut fh, &mut id, 0);
        check(b"ramfs handle", r == EOPNOTSUPP, r)?;
        let h = handle(RAMF, AT_HANDLE_FID)?;
        check(b"fid type", h.ty == 0x81 && h.bytes == 12, i64::from(h.ty))?;
        let st = statx(RAMF, STATX_INO);
        let ino = u64::from(h.f[1]) << 32 | u64::from(h.f[0]);
        check(b"fid inode", ino == st.stx_ino && h.f[2] == 0, ino as i64)?;
        let rfd = open_fd(RAM, true)?;
        let r = obh_ret(rfd, &h, O_RDONLY);
        sys_close(rfd as u64);
        check(b"fid open", r == ESTALE, r)?;
        // A pipe (pipefs has no export operations either)
        let mut p = [0i32; 2];
        check(b"pipe", sys_pipe2(p.as_mut_ptr(), 0) == 0, 0)?;
        let mut ph = Fh::new(MAX_HANDLE_SZ);
        let r1 = n2h(p[0], b"\0", &mut ph, &mut id, AT_EMPTY_PATH);
        let r2 = n2h(p[0], b"\0", &mut ph, &mut id, AT_EMPTY_PATH | AT_HANDLE_FID);
        sys_close(p[0] as u64);
        sys_close(p[1] as u64);
        check(b"pipe handle", r1 == EOPNOTSUPP, r1)?;
        check(b"pipe fid", r2 == 0 && ph.ty == 0x81, r2)
    })();
    sys_unlink(RAMF.as_ptr());
    sys_umount2(RAM.as_ptr(), 0);
    sys_rmdir(RAM.as_ptr());
    r
}

/// AT_HANDLE_MNT_ID_UNIQUE writes the u64 unique id
fn mnt_id_unique() -> R {
    let mut fh = Fh::new(MAX_HANDLE_SZ);
    let mut id = 0i64;
    let r = n2h(AT_FDCWD, F, &mut fh, &mut id, AT_HANDLE_MNT_ID_UNIQUE);
    check(b"name_to_handle_at", r == 0, r)?;
    let st = statx(F, STATX_MNT_ID_UNIQUE);
    check(b"unique id", id as u64 == st.stx_mnt_id, id)?;
    let old = statx(F, STATX_MNT_ID);
    check(b"not the old id", id as u64 != old.stx_mnt_id, id)
}

/// Drop CAP_DAC_READ_SEARCH from the effective set
fn drop_dac_read_search() -> bool {
    let mut h = CapUserHeader {
        version: _LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut d = [CapUserData::default(); 2];
    if sys_capget(&mut h, d.as_mut_ptr()) != 0 {
        return false;
    }
    d[0].effective &= !(1 << CAP_DAC_READ_SEARCH);
    sys_capset(&h, d.as_ptr()) == 0
}

/// Without CAP_DAC_READ_SEARCH: EPERM (in a child)
fn perm() -> R {
    let f = handle(F, 0)?;
    let d = handle(D, 0)?;
    let pid = sys_fork();
    if pid == 0 {
        let code = (|| {
            if !drop_dac_read_search() {
                return 1;
            }
            let mfd = sys_open(MP.as_ptr(), O_RDONLY | O_DIRECTORY, 0) as i32;
            let mut h = Fh::new(MAX_HANDLE_SZ);
            let mut id = 0;
            if n2h(AT_FDCWD, F, &mut h, &mut id, 0) != 0 || !h.same(&f) {
                return 2;
            }
            if obh_ret(mfd, &f, O_RDONLY) != EPERM {
                return 3;
            }
            if obh_ret(mfd, &d, O_RDONLY | O_DIRECTORY) != EPERM {
                return 4;
            }
            0
        })();
        sys_exit(code);
    }
    let mut status = 0i32;
    sys_wait4(pid, &mut status, 0, 0);
    let code = (status >> 8) & 0xff;
    check(b"child", status & 0x7f == 0 && code == 0, i64::from(status))
}

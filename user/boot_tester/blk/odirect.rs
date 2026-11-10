//! Who accepts O_DIRECT (Linux do_dentry_open, fs/fcntl.c setfl): a
//! file whose mapping has ->direct_IO or whose ->open sets
//! FMODE_CAN_ODIRECT (tmpfs regular files, block devices, vfat regular
//! files). Opening anything else O_DIRECT is EINVAL after ->open (an
//! O_CREAT file stays created); F_SETFL O_DIRECT has the same rule
//! (pipes aside: packet mode). A memfd is made without ->open, so it
//! cannot take O_DIRECT, but a reopen of it through /proc can.

use crate::harness::{R, check, report_r};
use crate::helpers::find_blkdev;
use hk_syscall::{
    AF_UNIX, O_CREAT, O_DIRECT, O_DIRECTORY, O_NONBLOCK, O_RDONLY, O_RDWR, SOCK_STREAM, Stat,
    sys_close, sys_fcntl, sys_memfd_create, sys_mkdir, sys_mknod, sys_mount, sys_open, sys_rmdir,
    sys_socket, sys_stat, sys_umount2, sys_unlink,
};

const EINVAL: i64 = -22;
const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;
const S_IFIFO: u32 = 0o010000;
const O_TMPFILE: u32 = 0o20000000 | O_DIRECTORY;

const RAMFS: &[u8] = b"/tmp/odir_ram\0";
const TMPFS: &[u8] = b"/tmp/odir_tmp\0";
const VFAT: &[u8] = b"/tmp/odir_fat\0";

pub fn run_tests() {
    sys_mkdir(RAMFS.as_ptr(), 0o755);
    sys_mkdir(TMPFS.as_ptr(), 0o755);
    let r = mnt(RAMFS, b"ramfs\0");
    let t = mnt(TMPFS, b"tmpfs\0");
    report_r(b"ODIRECT_OPEN", open_rules(r, t));
    report_r(b"ODIRECT_SETFL", setfl_rules(r, t));
    report_r(b"ODIRECT_DEV", dev_rules());
    report_r(b"ODIRECT_VFAT", vfat_rules());
    sys_umount2(RAMFS.as_ptr(), 0);
    sys_umount2(TMPFS.as_ptr(), 0);
    sys_rmdir(RAMFS.as_ptr());
    sys_rmdir(TMPFS.as_ptr());
}

fn mnt(dir: &[u8], fstype: &[u8]) -> i64 {
    sys_mount(fstype.as_ptr(), dir.as_ptr(), fstype.as_ptr(), 0, 0)
}

/// open(path, flags) closed again: 0 or the errno
fn try_open(path: &[u8], flags: u32) -> i64 {
    let fd = sys_open(path.as_ptr(), flags, 0o644);
    if fd < 0 {
        return fd;
    }
    sys_close(fd as u64);
    0
}

fn exists(path: &[u8]) -> bool {
    let mut st = Stat::default();
    sys_stat(path.as_ptr(), &mut st) == 0
}

/// ramfs refuses, also after creating the file; tmpfs regular files and
/// tmpfiles accept, tmpfs directories and FIFOs refuse
fn open_rules(ram: i64, tmp: i64) -> R {
    check(b"mount ramfs", ram == 0, ram)?;
    check(b"mount tmpfs", tmp == 0, tmp)?;
    let rf = b"/tmp/odir_ram/f\0";
    let r = try_open(rf, O_RDWR | O_CREAT | O_DIRECT);
    check(b"ramfs create", r == EINVAL, r)?;
    check(b"ramfs created", exists(rf), 0)?;
    let r = try_open(rf, O_RDONLY | O_DIRECT);
    check(b"ramfs open", r == EINVAL, r)?;
    sys_unlink(rf.as_ptr());
    let tf = b"/tmp/odir_tmp/f\0";
    let r = try_open(tf, O_RDWR | O_CREAT | O_DIRECT);
    check(b"tmpfs create", r == 0, r)?;
    let fd = sys_open(tf.as_ptr(), O_RDONLY | O_DIRECT, 0);
    check(b"tmpfs open", fd >= 0, fd)?;
    let fl = sys_fcntl(fd as i32, F_GETFL, 0);
    sys_close(fd as u64);
    check(b"tmpfs GETFL", fl >= 0 && fl & i64::from(O_DIRECT) != 0, fl)?;
    sys_unlink(tf.as_ptr());
    let r = try_open(TMPFS, O_RDONLY | O_DIRECTORY | O_DIRECT);
    check(b"tmpfs dir", r == EINVAL, r)?;
    let r = try_open(TMPFS, O_RDWR | O_TMPFILE | O_DIRECT);
    check(b"tmpfs tmpfile", r == 0, r)?;
    let ff = b"/tmp/odir_tmp/fifo\0";
    let m = sys_mknod(ff.as_ptr(), S_IFIFO | 0o644, 0);
    check(b"mkfifo", m == 0, m)?;
    let r = try_open(ff, O_RDONLY | O_NONBLOCK | O_DIRECT);
    sys_unlink(ff.as_ptr());
    check(b"fifo", r == EINVAL, r)
}

/// F_SETFL O_DIRECT, then F_GETFL: Ok(flags) or the setfl errno
fn setfl_direct(fd: i64) -> Result<i64, i64> {
    let fl = sys_fcntl(fd as i32, F_GETFL, 0);
    let r = sys_fcntl(fd as i32, F_SETFL, (fl as u64) | u64::from(O_DIRECT));
    if r < 0 {
        return Err(r);
    }
    Ok(sys_fcntl(fd as i32, F_GETFL, 0))
}

/// F_SETFL turns O_DIRECT on and off where open could have, and
/// refuses it (EINVAL) elsewhere, leaving the flags unchanged
fn setfl_rules(ram: i64, tmp: i64) -> R {
    check(b"mounts", ram == 0 && tmp == 0, ram | tmp)?;
    let tf = b"/tmp/odir_tmp/s\0";
    let fd = sys_open(tf.as_ptr(), O_RDWR | O_CREAT, 0o644);
    check(b"tmpfs open", fd >= 0, fd)?;
    let on = setfl_direct(fd);
    let off = sys_fcntl(fd as i32, F_SETFL, 0);
    let fl = sys_fcntl(fd as i32, F_GETFL, 0);
    sys_close(fd as u64);
    sys_unlink(tf.as_ptr());
    let on = on.unwrap_or_else(|e| e);
    check(b"tmpfs on", on >= 0 && on & i64::from(O_DIRECT) != 0, on)?;
    check(b"tmpfs off", off == 0 && fl & i64::from(O_DIRECT) == 0, fl)?;
    for (what, path) in [
        (&b"ramfs"[..], &b"/tmp/odir_ram/s\0"[..]),
        (b"devnull", b"/dev/null\0"),
    ] {
        let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT, 0o644);
        check(b"open", fd >= 0, fd)?;
        let r = setfl_direct(fd);
        let fl = sys_fcntl(fd as i32, F_GETFL, 0);
        sys_close(fd as u64);
        check(what, r == Err(EINVAL), r.unwrap_or_else(|e| e))?;
        check(b"flags kept", fl & i64::from(O_DIRECT) == 0, fl)?;
    }
    sys_unlink(b"/tmp/odir_ram/s\0".as_ptr());
    let s = sys_socket(AF_UNIX, SOCK_STREAM, 0);
    check(b"socket", s >= 0, s)?;
    let r = setfl_direct(s);
    sys_close(s as u64);
    check(b"socket setfl", r == Err(EINVAL), r.unwrap_or_else(|e| e))?;
    memfd_rules()
}

/// A memfd has no FMODE_CAN_ODIRECT; its /proc reopen (shmem ->open)
/// has
fn memfd_rules() -> R {
    let m = sys_memfd_create(b"odir\0".as_ptr(), 0);
    check(b"memfd", m >= 0, m)?;
    let r = setfl_direct(m);
    let mut p = *b"/proc/self/fd/\0\0\0\0\0\0";
    let mut n = m as u32;
    let mut d = [0u8; 6];
    let mut k = 0;
    loop {
        d[k] = b'0' + (n % 10) as u8;
        k += 1;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    for i in 0..k {
        p[14 + i] = d[k - 1 - i];
    }
    let re = try_open(&p, O_RDWR | O_DIRECT);
    sys_close(m as u64);
    check(b"memfd setfl", r == Err(EINVAL), r.unwrap_or_else(|e| e))?;
    check(b"memfd reopen", re == 0, re)
}

/// Block devices accept O_DIRECT; character devices, procfs and sysfs
/// refuse it
fn dev_rules() -> R {
    let Some(d) = find_blkdev(b"vd", 131072) else {
        return check(b"no vda", false, 0);
    };
    let mut p = [0u8; 48];
    let r = try_open(d.path(&mut p), O_RDONLY | O_DIRECT);
    check(b"blkdev", r == 0, r)?;
    let r = try_open(b"/dev/null\0", O_RDWR | O_DIRECT);
    check(b"chrdev", r == EINVAL, r)?;
    let r = try_open(b"/proc/self/status\0", O_RDONLY | O_DIRECT);
    check(b"procfs", r == EINVAL, r)?;
    let r = try_open(b"/sys/class\0", O_RDONLY | O_DIRECTORY | O_DIRECT);
    check(b"sysfs", r == EINVAL, r)
}

/// vfat: regular files have fat_aops' ->direct_IO, directories none
fn vfat_rules() -> R {
    let Some(p1) = find_blkdev(b"vd", 32768) else {
        return check(b"no vda1", false, 0);
    };
    let mut p = [0u8; 48];
    sys_mkdir(VFAT.as_ptr(), 0o755);
    let m = sys_mount(
        p1.path(&mut p).as_ptr(),
        VFAT.as_ptr(),
        b"vfat\0".as_ptr(),
        0,
        b"iocharset=cp437\0".as_ptr() as u64,
    );
    check(b"mount", m == 0, m)?;
    let f = try_open(b"/tmp/odir_fat/HKDISK.TXT\0", O_RDONLY | O_DIRECT);
    let d = try_open(VFAT, O_RDONLY | O_DIRECTORY | O_DIRECT);
    sys_umount2(VFAT.as_ptr(), 0);
    sys_rmdir(VFAT.as_ptr());
    check(b"file", f == 0, f)?;
    check(b"dir", d == EINVAL, d)
}

//! Exclusive claims of a block device (Linux block/bdev.c
//! bd_prepare_to_claim, block/ioctl.c blkdev_bszset): a mounted
//! filesystem claims its device, so opening it O_EXCL and BLKBSZSET
//! (which claims it for the call) are EBUSY; a device opened O_EXCL
//! refuses a mount and another file's BLKBSZSET, while its own
//! BLKBSZSET works. On vda1 (vfat).

use crate::harness::{R, check, report_r};
use crate::helpers::{BlkDev, find_blkdev};
use hk_syscall::{
    O_EXCL, O_RDONLY, O_RDWR, sys_close, sys_ioctl, sys_mkdir, sys_mount, sys_open, sys_rmdir,
    sys_umount2,
};

const BLKBSZGET: u64 = 0x8008_1270;
const BLKBSZSET: u64 = 0x4008_1271;
const EBUSY: i64 = -16;
const MNT: &[u8] = b"/tmp/bdev_excl\0";

pub fn run_tests() {
    let Some(p1) = find_blkdev(b"vd", 32768) else {
        report_r(b"BLK_EXCL", check(b"no vda1", false, 0));
        return;
    };
    sys_mkdir(MNT.as_ptr(), 0o755);
    report_r(b"BLK_EXCL_MOUNTED", mounted(&p1));
    report_r(b"BLK_EXCL_OPEN", excl_open(&p1));
    sys_rmdir(MNT.as_ptr());
}

fn open_dev(d: &BlkDev, flags: u32) -> i64 {
    let mut p = [0u8; 48];
    sys_open(d.path(&mut p).as_ptr(), flags, 0)
}

fn mount(d: &BlkDev) -> i64 {
    let mut p = [0u8; 48];
    sys_mount(
        d.path(&mut p).as_ptr(),
        MNT.as_ptr(),
        b"vfat\0".as_ptr(),
        0,
        b"iocharset=cp437\0".as_ptr() as u64,
    )
}

fn bsz(fd: i64) -> i32 {
    let mut v = 0i32;
    sys_ioctl(fd as i32, BLKBSZGET, &mut v as *mut i32 as u64);
    v
}

fn set_bsz(fd: i64, v: i32) -> i64 {
    sys_ioctl(fd as i32, BLKBSZSET, &v as *const i32 as u64)
}

/// While mounted: BLKBSZSET and an O_EXCL open are EBUSY
fn mounted(d: &BlkDev) -> R {
    let m = mount(d);
    check(b"mount", m == 0, m)?;
    let r = mounted_checks(d);
    let u = sys_umount2(MNT.as_ptr(), 0);
    r?;
    check(b"umount", u == 0, u)
}

fn mounted_checks(d: &BlkDev) -> R {
    let fd = open_dev(d, O_RDWR);
    check(b"open", fd >= 0, fd)?;
    // Another size than the mount's, and the same one: both refused
    let cur = bsz(fd);
    let a = set_bsz(fd, if cur == 4096 { 1024 } else { 4096 });
    let b = set_bsz(fd, cur);
    let after = bsz(fd);
    sys_close(fd as u64);
    check(b"BLKBSZSET mounted", a == EBUSY, a)?;
    check(b"BLKBSZSET same size", b == EBUSY, b)?;
    check(b"size kept", after == cur, i64::from(after))?;
    let x = open_dev(d, O_RDONLY | O_EXCL);
    if x >= 0 {
        sys_close(x as u64);
    }
    check(b"O_EXCL open mounted", x == EBUSY, x)
}

/// Opened O_EXCL: a mount and another file's BLKBSZSET are EBUSY, its
/// own BLKBSZSET works; after it closes, BLKBSZSET works again
fn excl_open(d: &BlkDev) -> R {
    let x = open_dev(d, O_RDONLY | O_EXCL);
    check(b"O_EXCL open", x >= 0, x)?;
    let fd = open_dev(d, O_RDWR);
    if fd < 0 {
        sys_close(x as u64);
        return check(b"open", false, fd);
    }
    let cur = bsz(fd);
    let m = mount(d);
    if m == 0 {
        sys_umount2(MNT.as_ptr(), 0);
    }
    let other = set_bsz(fd, cur);
    let own = set_bsz(x, cur);
    sys_close(x as u64);
    let after = set_bsz(fd, cur);
    sys_close(fd as u64);
    check(b"mount while O_EXCL", m == EBUSY, m)?;
    check(b"BLKBSZSET other file", other == EBUSY, other)?;
    check(b"BLKBSZSET O_EXCL file", own == 0, own)?;
    check(b"BLKBSZSET after close", after == 0, after)
}

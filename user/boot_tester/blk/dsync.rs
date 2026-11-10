//! Synchronous block-device writes (Linux blkdev_write_iter ->
//! generic_write_sync): a write through a file opened O_DSYNC or O_SYNC,
//! or with RWF_DSYNC / RWF_SYNC, is on the disk when it returns. Seen
//! through the whole disk, whose page cache is separate from the
//! partition's: it reads what the disk holds while the partition stays
//! open (its last close would write it back anyway).

use crate::harness::{R, check, report_r};
use crate::helpers::{BlkDev, find_blkdev, read_file};
use hk_syscall::{
    IoVec, O_RDONLY, O_RDWR, sys_close, sys_ioctl, sys_open, sys_pread64, sys_pwrite64,
    sys_pwritev2,
};

const O_DSYNC: u32 = 0o10000;
const __O_SYNC: u32 = 0o4000000;
const RWF_DSYNC: i32 = 2;
const RWF_SYNC: i32 = 4;
const BLKFLSBUF: u64 = 0x1261;
/// Offsets in vda3 (16 MiB) no other test touches
const OFF: [i64; 4] = [
    12 << 20,
    (12 << 20) + 65536,
    (12 << 20) + 131072,
    (12 << 20) + 196608,
];
const MSG: [&[u8; 8]; 4] = [b"O_DSYNC!", b"O_SYNC!!", b"RWFDSYNC", b"RWF_SYNC"];

pub fn run_tests() {
    report_r(b"BLK_DSYNC", dsync());
    report_r(b"BLK_DSYNC_RANGE", dsync_range());
}

/// A synchronous write syncs its own bytes only (Linux
/// generic_write_sync -> blkdev_fsync over the written range): a page
/// dirtied elsewhere on the device stays in the cache
fn dsync_range() -> R {
    let (Some(vda), Some(p3), Some(start)) = (
        find_blkdev(b"vd", 131072),
        find_blkdev(b"vd", 16384),
        p3_start(),
    ) else {
        return check(b"no vda3", false, 0);
    };
    const A: i64 = (12 << 20) + 262144;
    const B: i64 = (12 << 20) + 327680;
    let plain = open_dev(&p3, O_RDWR);
    let ds = open_dev(&p3, O_RDWR | O_DSYNC);
    check(b"open", plain >= 0 && ds >= 0, plain.min(ds))?;
    let wa = sys_pwrite64(plain as i32, MSG[0].as_ptr(), 8, A);
    let wb = sys_pwrite64(ds as i32, MSG[1].as_ptr(), 8, B);
    let disk = open_dev(&vda, O_RDONLY);
    let (mut a, mut b) = ([0u8; 8], [0u8; 8]);
    sys_pread64(disk as i32, a.as_mut_ptr(), 8, start * 512 + A);
    sys_pread64(disk as i32, b.as_mut_ptr(), 8, start * 512 + B);
    sys_close(disk as u64);
    for off in [A, B] {
        sys_pwrite64(ds as i32, pat(off).as_ptr(), 8, off);
    }
    let disk = open_dev(&vda, O_RDONLY);
    sys_ioctl(disk as i32, BLKFLSBUF, 0);
    sys_close(disk as u64);
    sys_close(plain as u64);
    sys_close(ds as u64);
    check(b"writes", wa == 8 && wb == 8, wa.min(wb))?;
    check(b"synced write on disk", &b == MSG[1], i64::from(b[0]))?;
    check(b"other page not synced", a == pat(A), i64::from(a[0]))
}

fn open_dev(d: &BlkDev, flags: u32) -> i64 {
    let mut p = [0u8; 48];
    sys_open(d.path(&mut p).as_ptr(), flags, 0)
}

/// vda3's first sector on vda (sysfs)
pub fn p3_start() -> Option<i64> {
    let mut b = [0u8; 32];
    let n = read_file(b"/sys/class/block/vda3/start\0", &mut b);
    let s = b.get(..usize::try_from(n).ok()?)?;
    let mut v = 0i64;
    for &c in s.iter().take_while(|c| c.is_ascii_digit()) {
        v = v * 10 + i64::from(c - b'0');
    }
    (v > 0).then_some(v)
}

/// The pattern word bytes of vda3 at `off` (tools/mkdisk.sh)
pub fn pat(off: i64) -> [u8; 8] {
    let mut b = [0u8; 8];
    for (i, x) in b.iter_mut().enumerate() {
        let o = off as u64 + i as u64;
        let w = ((o / 4) as u32)
            .wrapping_mul(1103515245)
            .wrapping_add(12345);
        *x = w.to_le_bytes()[(o % 4) as usize];
    }
    b
}

fn dsync() -> R {
    let (Some(vda), Some(p3), Some(start)) = (
        find_blkdev(b"vd", 131072),
        find_blkdev(b"vd", 16384),
        p3_start(),
    ) else {
        return check(b"no vda3", false, 0);
    };
    let plain = open_dev(&p3, O_RDWR);
    let ds = open_dev(&p3, O_RDWR | O_DSYNC);
    let sy = open_dev(&p3, O_RDWR | __O_SYNC);
    check(
        b"open",
        plain >= 0 && ds >= 0 && sy >= 0,
        plain.min(ds).min(sy),
    )?;
    let w = |fd: i64, i: usize| sys_pwrite64(fd as i32, MSG[i].as_ptr(), 8, OFF[i]);
    let v = |i: usize, flags: i32| {
        let iov = IoVec {
            iov_base: MSG[i].as_ptr(),
            iov_len: 8,
        };
        sys_pwritev2(plain as i32, &iov, 1, OFF[i], flags)
    };
    // The RWF writes first: a sync writes back every dirty page of the
    // device, the earlier writes' too
    let (r2, r3) = (v(2, RWF_DSYNC), v(3, RWF_SYNC));
    let r = [w(ds, 0), w(sy, 1), r2, r3];
    // The disk, read while vda3 is still open
    let disk = open_dev(&vda, O_RDONLY);
    let mut got = [[0u8; 8]; 4];
    for (i, g) in got.iter_mut().enumerate() {
        sys_pread64(disk as i32, g.as_mut_ptr(), 8, start * 512 + OFF[i]);
    }
    sys_close(disk as u64);
    // Put the pattern back, and drop the disk's now stale cache
    for &off in &OFF {
        sys_pwrite64(ds as i32, pat(off).as_ptr(), 8, off);
    }
    let disk = open_dev(&vda, O_RDONLY);
    sys_ioctl(disk as i32, BLKFLSBUF, 0);
    sys_close(disk as u64);
    for fd in [plain, ds, sy] {
        sys_close(fd as u64);
    }
    for (i, why) in [&b"O_DSYNC"[..], b"O_SYNC", b"RWF_DSYNC", b"RWF_SYNC"]
        .into_iter()
        .enumerate()
    {
        check(why, r[i] == 8, r[i])?;
        check(why, &got[i] == MSG[i], i as i64)?;
    }
    Ok(())
}

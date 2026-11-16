//! Queue limit, geometry and read-only ioctls on the virtio test disk
//! (Linux block/ioctl.c blkdev_common_ioctl, blkdev_getgeo,
//! blkdev_roset; drivers/block/virtio_blk.c virtblk_getgeo): the
//! values agree with sysfs and with the disk's size, BLKSECTGET writes
//! a short, HDIO_GETGEO's start is the partition's first sector, and
//! BLKROSET makes writes fail until it is cleared again

use crate::blk::dsync::p3_start;
use crate::harness::verdict;
use crate::helpers::{BlkDev, find_blkdev, print, print_num, println, read_file};
use hk_syscall::{
    O_RDONLY, O_RDWR, sys_close, sys_exit, sys_fork, sys_ioctl, sys_open, sys_pread64,
    sys_pwrite64, sys_setuid, sys_wait4,
};

const HDIO_GETGEO: u64 = 0x0301;
const BLKROSET: u64 = 0x125d;
const BLKROGET: u64 = 0x125e;
const BLKSECTGET: u64 = 0x1267;
const BLKIOMIN: u64 = 0x1278;
const BLKIOOPT: u64 = 0x1279;
const BLKALIGNOFF: u64 = 0x127a;
const BLKPBSZGET: u64 = 0x127b;

const EPERM: i64 = -1;
const EACCES: i64 = -13;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;

/// vda: 128 MiB in sectors (tools/mkdisk.sh)
const DISK_SECTORS: u64 = 128 * 2048;

fn open_dev(d: &BlkDev, flags: u32) -> i32 {
    let mut p = [0u8; 48];
    sys_open(d.path(&mut p).as_ptr(), flags, 0) as i32
}

fn get_int(fd: i32, cmd: u64) -> (i64, i32) {
    let mut v = 0i32;
    (sys_ioctl(fd, cmd, &mut v as *mut i32 as u64), v)
}

fn set_int(fd: i32, cmd: u64, v: i32) -> i64 {
    sys_ioctl(fd, cmd, &v as *const i32 as u64)
}

/// A decimal sysfs value; -1 if unreadable
fn sys_num(path: &[u8]) -> i64 {
    let mut b = [0u8; 32];
    let n = read_file(path, &mut b);
    if n <= 0 {
        return -1;
    }
    b[..n as usize]
        .iter()
        .take_while(|c| c.is_ascii_digit())
        .fold(0, |v, &c| v * 10 + i64::from(c - b'0'))
}

pub fn run_tests() {
    let (Some(whole), Some(p3)) = (find_blkdev(b"vd", 131072), find_blkdev(b"vd", 16384)) else {
        println(b"BLK_LIMITS_FIND:FAIL no virtio disk");
        return;
    };
    let w = open_dev(&whole, O_RDONLY);
    let p = open_dev(&p3, O_RDWR);
    if w < 0 || p < 0 {
        verdict(b"BLK_LIMITS_OPEN", false, i64::from(w.min(p)));
        return;
    }
    io_sizes(w, p);
    alignment(w, p);
    sectget(w);
    geometry(w, p);
    roset(w, p);
    sys_close(w as u64);
    sys_close(p as u64);
}

/// BLKIOMIN and BLKIOOPT: the queue's minimum_io_size and
/// optimal_io_size, whole disk and partition alike; the minimum at
/// least the physical block, both multiples of it
fn io_sizes(w: i32, p: i32) {
    let (r0, pbs) = get_int(w, BLKPBSZGET);
    let (r1, min) = get_int(w, BLKIOMIN);
    let (r2, pmin) = get_int(p, BLKIOMIN);
    let sys = sys_num(b"/sys/block/vda/queue/minimum_io_size\0");
    let ok = r0 == 0
        && r1 == 0
        && r2 == 0
        && pbs > 0
        && min == pmin
        && i64::from(min) == sys
        && min >= pbs
        && min % pbs == 0;
    verdict(b"BLK_IOMIN", ok, if r1 != 0 { r1 } else { i64::from(min) });
    let (r1, opt) = get_int(w, BLKIOOPT);
    let (r2, popt) = get_int(p, BLKIOOPT);
    let sys = sys_num(b"/sys/block/vda/queue/optimal_io_size\0");
    let ok = r1 == 0 && r2 == 0 && opt == popt && i64::from(opt) == sys && opt % pbs.max(1) == 0;
    verdict(b"BLK_IOOPT", ok, if r1 != 0 { r1 } else { i64::from(opt) });
}

/// BLKALIGNOFF: the disk's and the partition's alignment_offset in
/// sysfs (0: QEMU reports none, and vda3 starts on a 1 MiB boundary)
fn alignment(w: i32, p: i32) {
    let (r1, wa) = get_int(w, BLKALIGNOFF);
    let (r2, pa) = get_int(p, BLKALIGNOFF);
    let ok = r1 == 0
        && r2 == 0
        && i64::from(wa) == sys_num(b"/sys/block/vda/alignment_offset\0")
        && i64::from(pa) == sys_num(b"/sys/class/block/vda3/alignment_offset\0")
        && wa == 0
        && pa == 0;
    verdict(
        b"BLK_ALIGNOFF",
        ok,
        if r1 != 0 { r1 } else { i64::from(wa) },
    );
}

/// BLKSECTGET: the largest request in sectors (max_sectors_kb * 2,
/// capped at 65535), written as an unsigned short: the next two bytes
/// keep their value
fn sectget(w: i32) {
    let mut v = [0xffu8; 4];
    let r = sys_ioctl(w, BLKSECTGET, v.as_mut_ptr() as u64);
    let got = u16::from_ne_bytes([v[0], v[1]]);
    let kb = sys_num(b"/sys/block/vda/queue/max_sectors_kb\0");
    let ok = r == 0 && kb > 0 && i64::from(got) == (kb * 2).min(65535) && v[2..] == [0xff; 2];
    verdict(b"BLK_SECTGET", ok, if r != 0 { r } else { i64::from(got) });
}

/// struct hd_geometry: heads, sectors, cylinders, padding, start
struct Geo {
    r: i64,
    heads: u64,
    sectors: u64,
    cyls: u64,
    pad: [u8; 4],
    start: u64,
}

fn getgeo(fd: i32) -> Geo {
    let mut b = [0xaau8; 16];
    let r = sys_ioctl(fd, HDIO_GETGEO, b.as_mut_ptr() as u64);
    let mut s = [0u8; 8];
    s.copy_from_slice(&b[8..]);
    Geo {
        r,
        heads: u64::from(b[0]),
        sectors: u64::from(b[1]),
        cyls: u64::from(u16::from_ne_bytes([b[2], b[3]])),
        pad: [b[4], b[5], b[6], b[7]],
        start: u64::from_ne_bytes(s),
    }
}

/// HDIO_GETGEO: the device's CHS geometry (QEMU's, or 64 heads and 32
/// sectors without one) whose cylinders cover the disk, the same for a
/// partition, whose start is its first sector; padding zeroed; a NULL
/// argument is EINVAL
fn geometry(w: i32, p: i32) {
    let g = getgeo(w);
    let track = g.heads * g.sectors;
    let ok = g.r == 0
        && track > 0
        && g.cyls * track <= DISK_SECTORS
        && DISK_SECTORS < (g.cyls + 1) * track
        && g.pad == [0; 4]
        && g.start == 0;
    print(b"  geometry c/h/s ");
    print_num(g.cyls as i64);
    print(b"/");
    print_num(g.heads as i64);
    print(b"/");
    print_num(g.sectors as i64);
    println(b"");
    verdict(
        b"BLK_GETGEO",
        ok,
        if g.r != 0 { g.r } else { g.cyls as i64 },
    );
    let pg = getgeo(p);
    let ok = pg.r == 0
        && (pg.heads, pg.sectors, pg.cyls) == (g.heads, g.sectors, g.cyls)
        && Some(pg.start as i64) == p3_start();
    verdict(
        b"BLK_GETGEO_PART",
        ok,
        if pg.r != 0 { pg.r } else { pg.start as i64 },
    );
    let r = sys_ioctl(w, HDIO_GETGEO, 0);
    verdict(b"BLK_GETGEO_NULL", r == EINVAL, r);
}

/// Rewrite vda3's first sector with what it holds: ok when writes are
/// allowed, EPERM when the device is read-only
fn rewrite(p: i32) -> i64 {
    let mut s = [0u8; 512];
    let n = sys_pread64(p, s.as_mut_ptr(), 512, 0);
    if n != 512 {
        return n.min(-1000);
    }
    sys_pwrite64(p, s.as_ptr(), 512, 0)
}

/// BLKROSET without CAP_SYS_ADMIN is EACCES: a child that set its
/// uid to nobody tries it on the inherited descriptor
fn roset_unprivileged(p: i32) -> i64 {
    let pid = sys_fork();
    if pid == 0 {
        let r = if sys_setuid(65534) == 0 {
            set_int(p, BLKROSET, 1)
        } else {
            -1000
        };
        sys_exit((-r).clamp(0, 255) as u64);
    }
    let mut st = 0i32;
    if pid < 0 || sys_wait4(pid, &mut st, 0, 0) != pid {
        return pid.min(-1000);
    }
    -i64::from((st >> 8) & 0xff)
}

/// BLKROSET (root): a partition's flag makes its writes EPERM (sysfs
/// ro 1) and leaves the disk writable; the whole disk's makes its
/// partitions read-only too (Linux bdev_read_only -> get_disk_ro);
/// cleared, writes go through again. A NULL argument is EFAULT, and
/// without CAP_SYS_ADMIN it is EACCES
fn roset(w: i32, p: i32) {
    let r = set_int(p, BLKROSET, 1);
    let (_, ro) = get_int(p, BLKROGET);
    let (_, wro) = get_int(w, BLKROGET);
    let sys = sys_num(b"/sys/class/block/vda3/ro\0");
    let wr = rewrite(p);
    let ok = r == 0 && ro == 1 && wro == 0 && sys == 1 && wr == EPERM;
    verdict(b"BLK_ROSET_PART", ok, if r != 0 { r } else { wr });
    let c = set_int(p, BLKROSET, 0);
    let (_, ro) = get_int(p, BLKROGET);
    let wr = rewrite(p);
    let ok = c == 0 && ro == 0 && wr == 512;
    verdict(b"BLK_ROSET_CLEAR", ok, if c != 0 { c } else { wr });
    let r = set_int(w, BLKROSET, 1);
    let (_, ro) = get_int(p, BLKROGET);
    let wr = rewrite(p);
    let c = set_int(w, BLKROSET, 0);
    let (_, back) = get_int(p, BLKROGET);
    let ok = r == 0 && ro == 1 && wr == EPERM && c == 0 && back == 0;
    verdict(b"BLK_ROSET_DISK", ok, if r != 0 { r } else { wr });
    let r = sys_ioctl(p, BLKROSET, 0);
    verdict(b"BLK_ROSET_NULL", r == EFAULT, r);
    let r = roset_unprivileged(p);
    let (_, ro) = get_int(p, BLKROGET);
    // Writable again for the tests after, whatever the child did
    set_int(p, BLKROSET, 0);
    verdict(b"BLK_ROSET_EACCES", r == EACCES && ro == 0, r);
}

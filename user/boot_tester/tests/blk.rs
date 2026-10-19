//! Block devices on the virtio test disk (tools/mkdisk.sh): naming and
//! dev_t in /proc/partitions and devtmpfs, GPT/MBR on-disk signatures,
//! block ioctls (Linux block/ioctl.c), reads and writes through the
//! device file with Linux's end-of-device rules (block/fops.c), fsync,
//! BLKRRPART, a vfat mount of vda1 and swapon of vda2
//!
//! Layout: vda 128 MiB GPT; vda1 32 MiB vfat (HKDISK.TXT), vda2 64 MiB
//! swap, vda3 16 MiB of 32-bit LE words w(i) = i * 1103515245 + 12345.
//! The disk is attached with snapshot=on: each boot sees it pristine.

use super::helpers::{
    BlkDev, dev_major, dev_minor, find_blkdev, print, print_num, println, read_file,
};
use hk_syscall::{
    O_CREAT, O_RDONLY, O_RDWR, Stat, sys_close, sys_fstat, sys_fsync, sys_ioctl, sys_lseek,
    sys_mkdir, sys_mount, sys_open, sys_pread64, sys_pwrite64, sys_read, sys_stat, sys_swapoff,
    sys_swapon, sys_umount2,
};

const BLKROGET: u64 = 0x125e;
const BLKRRPART: u64 = 0x125f;
const BLKGETSIZE: u64 = 0x1260;
const BLKSSZGET: u64 = 0x1268;
const BLKBSZGET: u64 = 0x8008_1270;
const BLKBSZSET: u64 = 0x4008_1271;
const BLKGETSIZE64: u64 = 0x8008_1272;
const BLKPBSZGET: u64 = 0x127b;

const EINVAL: i64 = -22;
const EBUSY: i64 = -16;
const ENOSPC: i64 = -28;
const S_IFMT: u32 = 0o170000;
const S_IFBLK: u32 = 0o060000;
const SEEK_SET: i32 = 0;
const SEEK_END: i32 = 2;

const MIB: u64 = 1024 * 1024;
const P3_SIZE: u64 = 16 * MIB;

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

/// Pattern byte at offset `off` of vda3
fn pat(off: u64) -> u8 {
    let w = ((off / 4) as u32)
        .wrapping_mul(1103515245)
        .wrapping_add(12345);
    w.to_le_bytes()[(off % 4) as usize]
}

/// Index of the first byte of `buf` (read at `off`) not matching the
/// pattern
fn pat_mismatch(buf: &[u8], off: u64) -> Option<usize> {
    buf.iter()
        .enumerate()
        .position(|(i, &b)| b != pat(off + i as u64))
}

/// Open a /proc/partitions device
fn open_dev(d: &BlkDev, flags: u32) -> i32 {
    let mut p = [0u8; 48];
    sys_open(d.path(&mut p).as_ptr(), flags, 0) as i32
}

/// The disk and its partitions, by size (vda on both kernels)
struct Disk {
    whole: BlkDev,
    p1: BlkDev,
    p2: BlkDev,
    p3: BlkDev,
}

fn find_disk() -> Option<Disk> {
    Some(Disk {
        whole: find_blkdev(b"vd", 131072)?,
        p1: find_blkdev(b"vd", 32768)?,
        p2: find_blkdev(b"vd", 65536)?,
        p3: find_blkdev(b"vd", 16384)?,
    })
}

pub fn run_tests() {
    let Some(d) = find_disk() else {
        let mut b = [0u8; 1024];
        let n = read_file(b"/proc/partitions\0", &mut b);
        println(b"BLK_FIND:FAIL no virtio disk in /proc/partitions:");
        if n > 0 {
            print(&b[..n as usize]);
        }
        return;
    };
    names(&d);
    nodes(&d);
    gpt(&d.whole);
    fat_boot(&d.p1);
    ioctls(&d.p3);
    pattern_read(&d.p3);
    pattern_write(&d.p3);
    eof(&d.p3);
    rrpart(&d);
    vfat(&d.p1);
    swap(&d.p2);
}

/// vda1..3 are partitions 1..3 of vda: same major, minors follow
fn names(d: &Disk) {
    let ok = d.whole.name() == b"vda"
        && d.p1.name() == b"vda1"
        && d.p2.name() == b"vda2"
        && d.p3.name() == b"vda3"
        && [d.p1, d.p2, d.p3]
            .iter()
            .enumerate()
            .all(|(i, p)| p.major == d.whole.major && p.minor == d.whole.minor + 1 + i as u32);
    verdict(b"BLK_PARTITIONS", ok, d.p3.minor as i64);
}

/// devtmpfs nodes are block devices whose st_rdev is the dev_t of
/// /proc/partitions
fn nodes(d: &Disk) {
    for b in [d.whole, d.p1, d.p2, d.p3] {
        let mut p = [0u8; 48];
        let mut st: Stat = unsafe { core::mem::zeroed() };
        let r = sys_stat(b.path(&mut p).as_ptr(), &mut st);
        let ok = r == 0
            && st.st_mode & S_IFMT == S_IFBLK
            && dev_major(st.st_rdev) == b.major
            && dev_minor(st.st_rdev) == b.minor;
        print(b"BLK_RDEV_");
        print(b.name());
        verdict(b"", ok, if r != 0 { r } else { st.st_rdev as i64 });
    }
}

/// Protective MBR (0x55AA, one 0xEE record from LBA 1) and the primary
/// GPT header at LBA 1
fn gpt(whole: &BlkDev) {
    let fd = open_dev(whole, O_RDONLY);
    let mut s = [0u8; 1024];
    let n = sys_read(fd as u64, s.as_mut_ptr(), 1024);
    sys_close(fd as u64);
    let rec = &s[0x1be..0x1ce];
    let ok = n == 1024
        && s[510] == 0x55
        && s[511] == 0xaa
        && rec[4] == 0xee
        && rec[8..12] == 1u32.to_le_bytes()
        && &s[512..520] == b"EFI PART";
    verdict(b"BLK_GPT_SIGNATURE", ok, n);
}

/// vda1's first sector is a FAT32 boot sector: 0x55AA, "FAT32   "
fn fat_boot(p1: &BlkDev) {
    let fd = open_dev(p1, O_RDONLY);
    let mut s = [0u8; 512];
    let n = sys_pread64(fd, s.as_mut_ptr(), 512, 0);
    sys_close(fd as u64);
    let ok = n == 512 && s[510] == 0x55 && s[511] == 0xaa && &s[82..90] == b"FAT32   ";
    verdict(b"BLK_FAT_SIGNATURE", ok, n);
}

fn get_u64(fd: i32, cmd: u64) -> (i64, u64) {
    let mut v = 0u64;
    (sys_ioctl(fd, cmd, &mut v as *mut u64 as u64), v)
}

fn get_int(fd: i32, cmd: u64) -> (i64, i32) {
    let mut v = 0i32;
    (sys_ioctl(fd, cmd, &mut v as *mut i32 as u64), v)
}

fn set_int(fd: i32, cmd: u64, v: i32) -> i64 {
    sys_ioctl(fd, cmd, &v as *const i32 as u64)
}

/// Sizes, block sizes, read-only flag; BLKBSZSET within 512..4096
fn ioctls(p3: &BlkDev) {
    let fd = open_dev(p3, O_RDWR);
    let (r, sz64) = get_u64(fd, BLKGETSIZE64);
    verdict(b"BLK_GETSIZE64", r == 0 && sz64 == P3_SIZE, sz64 as i64);
    let (r, secs) = get_u64(fd, BLKGETSIZE);
    verdict(b"BLK_GETSIZE", r == 0 && secs == P3_SIZE / 512, secs as i64);
    let (r1, ssz) = get_int(fd, BLKSSZGET);
    let (r2, psz) = get_int(fd, BLKPBSZGET);
    let (r3, ro) = get_int(fd, BLKROGET);
    let ok = r1 == 0 && r2 == 0 && r3 == 0 && ssz == 512 && psz == 512 && ro == 0;
    verdict(b"BLK_SSZ_PBSZ_RO", ok, (ssz + psz + ro) as i64);
    // Initial soft block size: largest power of two <= 4096 dividing the size
    let (r, bsz) = get_int(fd, BLKBSZGET);
    verdict(b"BLK_BSZGET", r == 0 && bsz == 4096, bsz as i64);
    let a = set_int(fd, BLKBSZSET, 1024);
    let (_, now) = get_int(fd, BLKBSZGET);
    let b = set_int(fd, BLKBSZSET, 3000);
    let c = set_int(fd, BLKBSZSET, 8192);
    let e = set_int(fd, BLKBSZSET, 256);
    let ok = a == 0 && now == 1024 && b == EINVAL && c == EINVAL && e == EINVAL;
    verdict(b"BLK_BSZSET", ok, if a != 0 { a } else { now as i64 });
    // BLKRRPART is for whole disks
    let r = sys_ioctl(fd, BLKRRPART, 0);
    verdict(b"BLK_RRPART_PART", r == EINVAL, r);
    sys_close(fd as u64);
}

/// Aligned, unaligned and last-sector reads of the pattern
fn pattern_read(p3: &BlkDev) {
    let fd = open_dev(p3, O_RDONLY);
    let mut buf = [0u8; 8192];
    let checks: [(u64, usize); 4] = [
        (0, 8192),
        (5_000_003, 1000),
        (P3_SIZE / 2 - 7, 8192),
        (P3_SIZE - 512, 512),
    ];
    for (i, &(off, len)) in checks.iter().enumerate() {
        let n = sys_pread64(fd, buf.as_mut_ptr(), len as u64, off as i64);
        let bad = pat_mismatch(&buf[..len], off);
        print(b"BLK_PATTERN_READ_");
        print_num(i as i64);
        verdict(
            b"",
            n == len as i64 && bad.is_none(),
            bad.map_or(n, |b| b as i64),
        );
    }
    // read() advances the position
    let p = sys_lseek(fd, 4096, SEEK_SET);
    let n = sys_read(fd as u64, buf.as_mut_ptr(), 4096);
    let pos = sys_lseek(fd, 0, 1);
    let ok = p == 4096 && n == 4096 && pos == 8192 && pat_mismatch(&buf[..4096], 4096).is_none();
    verdict(b"BLK_PATTERN_READ_POS", ok, pos);
    sys_close(fd as u64);
}

/// Unaligned write, fsync, read back from a new descriptor; the bytes
/// around it keep the pattern
fn pattern_write(p3: &BlkDev) {
    let off = 15 * MIB + 123;
    let mut data = [0u8; 3000];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i * 7 + 1) as u8;
    }
    let fd = open_dev(p3, O_RDWR);
    let w = sys_pwrite64(fd, data.as_ptr(), data.len() as u64, off as i64);
    let f = sys_fsync(fd);
    sys_close(fd as u64);
    verdict(b"BLK_WRITE", w == data.len() as i64, w);
    verdict(b"BLK_FSYNC", f == 0, f);
    let fd = open_dev(p3, O_RDONLY);
    let mut back = [0u8; 3000 + 2 * 512];
    let start = off - 512;
    let n = sys_pread64(fd, back.as_mut_ptr(), back.len() as u64, start as i64);
    sys_close(fd as u64);
    let ok = n == back.len() as i64
        && back[512..3512] == data
        && pat_mismatch(&back[..512], start).is_none()
        && pat_mismatch(&back[3512..], off + 3000).is_none();
    verdict(b"BLK_WRITE_READBACK", ok, n);
}

/// End of device (Linux blkdev_read_iter / blkdev_write_iter /
/// fixed_size_llseek): reads stop short or return 0, writes are cut
/// short or ENOSPC, seeks stay within the device
fn eof(p3: &BlkDev) {
    let fd = open_dev(p3, O_RDWR);
    let s = P3_SIZE as i64;
    let mut buf = [0u8; 4096];
    let at_end = sys_pread64(fd, buf.as_mut_ptr(), 4096, s);
    let short = sys_pread64(fd, buf.as_mut_ptr(), 4096, s - 100);
    let short_ok = short == 100 && pat_mismatch(&buf[..100], P3_SIZE - 100).is_none();
    verdict(
        b"BLK_EOF_READ",
        at_end == 0 && short_ok,
        at_end * 10000 + short,
    );
    let end = sys_lseek(fd, 0, SEEK_END);
    let past = sys_lseek(fd, s + 1, SEEK_SET);
    let n = sys_read(fd as u64, buf.as_mut_ptr(), 4096);
    verdict(b"BLK_EOF_SEEK", end == s && past == EINVAL && n == 0, end);
    let w_end = sys_pwrite64(fd, buf.as_ptr(), 16, s);
    let w_short = sys_pwrite64(fd, buf.as_ptr(), 100, s - 10);
    verdict(
        b"BLK_EOF_WRITE",
        w_end == ENOSPC && w_short == 10,
        w_end * 1000 + w_short,
    );
    sys_close(fd as u64);
}

/// BLKRRPART: EBUSY while a partition is open, then a rescan that finds
/// the same partitions again
fn rrpart(d: &Disk) {
    let disk = open_dev(&d.whole, O_RDONLY);
    let part = open_dev(&d.p3, O_RDONLY);
    let busy = sys_ioctl(disk, BLKRRPART, 0);
    sys_close(part as u64);
    let r = sys_ioctl(disk, BLKRRPART, 0);
    sys_close(disk as u64);
    let again = find_disk().is_some_and(|n| n.p3.minor == d.p3.minor);
    let mut p = [0u8; 48];
    let mut st: Stat = unsafe { core::mem::zeroed() };
    let node = sys_stat(d.p3.path(&mut p).as_ptr(), &mut st) == 0;
    let ok = busy == EBUSY && r == 0 && again && node;
    verdict(b"BLK_RRPART", ok, busy * 1000 + r);
}

/// Mount vda1 (vfat) and read the file mkdisk.sh put there; write one
fn vfat(p1: &BlkDev) {
    let mut p = [0u8; 48];
    sys_mkdir(b"/mnt\0".as_ptr(), 0o755);
    sys_mkdir(b"/mnt/vd1\0".as_ptr(), 0o755);
    // Ubuntu's kernel has only cp437 built in (iocharset defaults to
    // iso8859-1, a module); hk ignores mount data
    let r = sys_mount(
        p1.path(&mut p).as_ptr(),
        b"/mnt/vd1\0".as_ptr(),
        b"vfat\0".as_ptr(),
        0,
        b"iocharset=cp437\0".as_ptr() as u64,
    );
    verdict(b"BLK_VFAT_MOUNT", r == 0, r);
    if r != 0 {
        return;
    }
    let mut b = [0u8; 64];
    let n = read_file(b"/mnt/vd1/HKDISK.TXT\0", &mut b);
    verdict(
        b"BLK_VFAT_READ",
        n == 15 && &b[..15] == b"hk virtio disk\n",
        n,
    );
    let fd = sys_open(b"/mnt/vd1/NEW.TXT\0".as_ptr(), O_RDWR | O_CREAT, 0o644) as i32;
    let w = sys_pwrite64(fd, b"written".as_ptr(), 7, 0);
    let f = sys_fsync(fd);
    let mut st: Stat = unsafe { core::mem::zeroed() };
    let s = sys_fstat(fd, &mut st);
    sys_close(fd as u64);
    let n = read_file(b"/mnt/vd1/NEW.TXT\0", &mut b);
    let ok = fd >= 0 && w == 7 && f == 0 && s == 0 && st.st_size == 7 && &b[..7] == b"written";
    verdict(
        b"BLK_VFAT_WRITE",
        ok && n == 7,
        if fd < 0 { fd as i64 } else { n },
    );
    let u = sys_umount2(b"/mnt/vd1\0".as_ptr(), 0);
    verdict(b"BLK_VFAT_UMOUNT", u == 0, u);
}

/// swapon reads vda2's swap header through the block layer
fn swap(p2: &BlkDev) {
    let mut p = [0u8; 48];
    let path = p2.path(&mut p);
    let on = sys_swapon(path.as_ptr(), 0);
    let again = sys_swapon(path.as_ptr(), 0);
    let off = sys_swapoff(path.as_ptr());
    let ok = on == 0 && again == EBUSY && off == 0;
    verdict(b"BLK_SWAPON", ok, on * 1000 + again);
}

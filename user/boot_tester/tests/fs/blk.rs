//! Block devices on the virtio test disk (tools/mkdisk.sh): naming and
//! dev_t in /proc/partitions and devtmpfs, GPT/MBR on-disk signatures,
//! block ioctls (Linux block/ioctl.c), reads and writes through the
//! device file with Linux's end-of-device rules (block/fops.c), fsync,
//! BLKRRPART, a vfat mount of vda1 and swapon of vda2
//!
//! Layout: vda 128 MiB GPT; vda1 32 MiB vfat (HKDISK.TXT), vda2 64 MiB
//! swap, vda3 16 MiB of 32-bit LE words w(i) = i * 1103515245 + 12345.
//! The disk is attached with snapshot=on: each boot sees it pristine.

use crate::tests::helpers::{
    BlkDev, dev_major, dev_minor, find_blkdev, linux_at_least, print, print_num, println, read_file,
};
use hk_syscall::{
    O_CREAT, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY, Stat, sys_close, sys_fstat, sys_fsync, sys_ioctl,
    sys_lseek, sys_mkdir, sys_mount, sys_open, sys_pread64, sys_pwrite64, sys_read, sys_rename,
    sys_stat, sys_swapoff, sys_swapon, sys_umount2, sys_unlink,
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
const EIO: i64 = -5;
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
    vfat(&d);
    swap(&d.p2);
    cache(&d.p3);
}

/// A block device's page cache (Linux bd_mapping): pwrite, pread and a
/// MAP_SHARED mapping of the node see one copy; the last close writes
/// it to the disk (a new open reads it back from there)
fn cache(p3: &BlkDev) {
    use hk_syscall::{MAP_SHARED, PROT_READ, PROT_WRITE, sys_mmap, sys_munmap};
    const OFF: u64 = 8 << 20;
    let a = open_dev(p3, O_RDWR);
    let b = open_dev(p3, O_RDWR);
    let w = sys_pwrite64(a, b"coherent".as_ptr(), 8, OFF as i64);
    let p = sys_mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, b, OFF);
    let mut ok = w == 8 && p > 0;
    if p > 0 {
        let m = unsafe { core::slice::from_raw_parts_mut(p as *mut u8, 4096) };
        ok &= &m[..8] == b"coherent";
        m[100..104].copy_from_slice(b"mmap");
        sys_munmap(p as u64, 4096);
    }
    let mut got = [0u8; 4];
    sys_pread64(a, got.as_mut_ptr(), 4, OFF as i64 + 100);
    ok &= &got == b"mmap";
    verdict(b"BLK_CACHE_COHERENT", ok, w);
    let w2 = sys_pwrite64(a, b"on disk!".as_ptr(), 8, OFF as i64 + 512);
    sys_close(a as u64);
    sys_close(b as u64);
    let c = open_dev(p3, O_RDONLY);
    let mut back = [0u8; 8];
    let n = sys_pread64(c, back.as_mut_ptr(), 8, OFF as i64 + 512);
    sys_close(c as u64);
    verdict(
        b"BLK_WRITEBACK_CLOSE",
        w2 == 8 && n == 8 && &back == b"on disk!",
        n,
    );
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

/// Sizes, block sizes, read-only flag; BLKBSZSET within 512..64K (the
/// page size before Linux 6.15)
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
    let big = if linux_at_least(6, 15) { 0 } else { EINVAL };
    let d = set_int(fd, BLKBSZSET, 128 * 1024);
    let e = set_int(fd, BLKBSZSET, 256);
    let ok = a == 0 && now == 1024 && b == EINVAL && c == big && d == EINVAL && e == EINVAL;
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
fn vfat(d: &Disk) {
    let p1 = &d.p1;
    let mut p = [0u8; 48];
    sys_mkdir(b"/mnt\0".as_ptr(), 0o755);
    sys_mkdir(b"/mnt/vd1\0".as_ptr(), 0o755);
    // Ubuntu's kernel has only cp437 built in (iocharset defaults to
    // iso8859-1, a module)
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
    // A mounted partition is open (Linux: the mount opens the device):
    // a rescan of its disk is EBUSY
    let disk = open_dev(&d.whole, O_RDONLY);
    let busy = sys_ioctl(disk, BLKRRPART, 0);
    sys_close(disk as u64);
    verdict(b"BLK_RRPART_MOUNTED", busy == EBUSY, busy);
    vfat_mmap_write();
    vfat_swapfile();
    drop_caches();
    vfat_rename_ino();
    vfat_unlink_open();
    vfat_unlink_reuse();
    let u = sys_umount2(b"/mnt/vd1\0".as_ptr(), 0);
    verdict(b"BLK_VFAT_UMOUNT", u == 0, u);
    vfat_remount(p1);
    vfat_names(p1);
    vfat_opts(p1);
    vfat_neg_case(p1);
    vfat_mount_alias(p1);
    vfat_sync(p1);
    vfat_corrupt_chain(p1);
}

/// What was written through the page cache (write() and a shared
/// mapping) reached the disk at umount: a new mount reads it
fn vfat_remount(p1: &BlkDev) {
    let mut p = [0u8; 48];
    let r = sys_mount(
        p1.path(&mut p).as_ptr(),
        b"/mnt/vd1\0".as_ptr(),
        b"vfat\0".as_ptr(),
        0,
        b"iocharset=cp437\0".as_ptr() as u64,
    );
    let mut b = [0u8; 9000];
    let n = read_file(b"/mnt/vd1/M.TXT\0", &mut b);
    let ok = r == 0
        && n == 8192
        && b[..4096].iter().all(|&c| c == b'w')
        && &b[4096..4100] == b"MMAP"
        && &b[4196..4200] == b"MPRO"
        && b[4100..4196].iter().all(|&c| c == 0)
        && b[4200..8192].iter().all(|&c| c == 0);
    sys_unlink(b"/mnt/vd1/M.TXT\0".as_ptr());
    let u = sys_umount2(b"/mnt/vd1\0".as_ptr(), 0);
    if !ok {
        // Where the data differs: first bad offset and its byte
        let bad = (0..n.max(0) as usize).find(|&i| {
            b[i] != if i < 4096 {
                b'w'
            } else if i < 4100 {
                b"MMAP"[i - 4096]
            } else if (4196..4200).contains(&i) {
                b"MPRO"[i - 4196]
            } else {
                0
            }
        });
        print(b"VFAT_REMOUNT_DATA: bad at ");
        print_num(bad.map_or(-1, |i| i as i64));
        print(b" byte ");
        print_num(bad.map_or(-1, |i| b[i] as i64));
        println(b"");
    }
    verdict(b"VFAT_REMOUNT_DATA", ok && u == 0, n);
}

/// Mount vda1 on /mnt/vd1 with mount data `opts` (NUL-terminated)
fn mount_vd1(p1: &BlkDev, opts: &[u8]) -> i64 {
    let mut p = [0u8; 48];
    let path = p1.path(&mut p).as_ptr();
    sys_mount(
        path,
        b"/mnt/vd1\0".as_ptr(),
        b"vfat\0".as_ptr(),
        0,
        opts.as_ptr() as u64,
    )
}

/// `name` is an entry of /mnt/vd1, byte for byte
fn vd1_lists(name: &[u8]) -> bool {
    let fd = sys_open(b"/mnt/vd1\0".as_ptr(), O_RDONLY, 0);
    let mut buf = [0u8; 2048];
    let mut found = false;
    loop {
        let n = hk_syscall::sys_getdents64(fd as u64, buf.as_mut_ptr(), buf.len() as u64);
        if n <= 0 {
            break;
        }
        let mut off = 0usize;
        while off < n as usize {
            let reclen = u16::from_ne_bytes([buf[off + 16], buf[off + 17]]) as usize;
            let nm = &buf[off + 19..off + reclen];
            let len = nm.iter().position(|&b| b == 0).unwrap_or(nm.len());
            found |= &nm[..len] == name;
            off += reclen;
        }
    }
    sys_close(fd as u64);
    found
}

/// Long names are UTF-16 on disk, read by the mount's charset (Linux
/// vfat with the utf8 option, then cp437): a UTF-8 name round-trips,
/// shows as cp437 bytes on a cp437 mount; FAT's forbidden characters
/// and undecodable names are EINVAL; trailing dots are dropped
fn vfat_names(p1: &BlkDev) {
    let n = b"VFAT_UTF8_NAME";
    let r = mount_vd1(p1, b"iocharset=cp437,utf8\0");
    if r != 0 {
        return verdict(n, false, r);
    }
    let utf: &[u8] = b"/mnt/vd1/\xc3\xa9t\xc3\xa9.txt\0";
    let fd = sys_open(utf.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    sys_close(fd as u64);
    let listed = vd1_lists(b"\xc3\xa9t\xc3\xa9.txt");
    let bad = sys_open(b"/mnt/vd1/a:b\0".as_ptr(), O_CREAT | O_WRONLY, 0o644);
    let undec = sys_open(b"/mnt/vd1/q\xff\0".as_ptr(), O_CREAT | O_WRONLY, 0o644);
    let dot = sys_open(b"/mnt/vd1/dot.\0".as_ptr(), O_CREAT | O_WRONLY, 0o644);
    sys_close(dot as u64);
    // SAFETY: Stat is plain integers
    let mut st: Stat = unsafe { core::mem::zeroed() };
    let undotted = sys_stat(b"/mnt/vd1/dot\0".as_ptr(), &mut st);
    sys_unlink(b"/mnt/vd1/dot\0".as_ptr());
    sys_umount2(b"/mnt/vd1\0".as_ptr(), 0);
    // The same name through cp437: \x82 is e-acute there
    let r2 = mount_vd1(p1, b"iocharset=cp437\0");
    let cp = vd1_lists(b"\x82t\x82.txt");
    sys_unlink(b"/mnt/vd1/\x82t\x82.txt\0".as_ptr());
    sys_umount2(b"/mnt/vd1\0".as_ptr(), 0);
    let ok = fd >= 0 && listed && bad == -22 && undec == -22 && dot >= 0 && undotted == 0;
    if !ok || r2 != 0 || !cp {
        print(b"VFAT_UTF8_NAME: fd/listed/bad/undec/dot/undotted/cp ");
        for v in [fd, listed as i64, bad, undec, dot, undotted, r2, cp as i64] {
            print_num(v);
            print(b" ");
        }
        println(b"");
    }
    verdict(n, ok && r2 == 0 && cp, fd);
}

/// uid/gid/fmask/dmask set every inode's owner and mode (Linux
/// fat_make_mode: 0777 minus the mask); an unknown option or a bad
/// value is EINVAL (MOUNT_BAD_OPT)
fn vfat_opts(p1: &BlkDev) {
    let r = mount_vd1(
        p1,
        b"iocharset=cp437,uid=1000,gid=1001,fmask=0133,dmask=0022\0",
    );
    // SAFETY: Stat is plain integers
    let mut f: Stat = unsafe { core::mem::zeroed() };
    // SAFETY: as above
    let mut d: Stat = unsafe { core::mem::zeroed() };
    let rf = sys_stat(b"/mnt/vd1/HKDISK.TXT\0".as_ptr(), &mut f);
    let rd = sys_stat(b"/mnt/vd1\0".as_ptr(), &mut d);
    sys_umount2(b"/mnt/vd1\0".as_ptr(), 0);
    let ok = r == 0
        && rf == 0
        && rd == 0
        && (f.st_uid, f.st_gid, f.st_mode) == (1000, 1001, 0o100644)
        && (d.st_uid, d.st_mode) == (1000, 0o40755);
    if !ok {
        print(b"VFAT_MOUNT_OPTS: r/uid/gid/fmode/dmode ");
        for v in [
            r,
            f.st_uid as i64,
            f.st_gid as i64,
            f.st_mode as i64,
            d.st_mode as i64,
        ] {
            print_num(v);
            print(b" ");
        }
        println(b"");
    }
    verdict(b"VFAT_MOUNT_OPTS", ok, r);
    let bogus = mount_vd1(p1, b"iocharset=cp437,bogus\0");
    let badval = mount_vd1(p1, b"iocharset=cp437,uid=abc\0");
    if bogus == 0 || badval == 0 {
        sys_umount2(b"/mnt/vd1\0".as_ptr(), 0);
    }
    verdict(
        b"MOUNT_BAD_OPT",
        bogus == -22 && badval == -22,
        bogus * 100 + badval,
    );
}

/// Write `v` to /proc/sys/vm/drop_caches
fn drop_caches_write(v: &[u8]) -> i64 {
    let fd = sys_open(b"/proc/sys/vm/drop_caches\0".as_ptr(), O_WRONLY, 0) as i32;
    let r = hk_syscall::sys_write(fd as u64, v.as_ptr(), v.len() as u64);
    sys_close(fd as u64);
    r
}

/// vm.drop_caches 1 frees the clean page cache of a vfat file (Linux
/// drop_pagecache_sb): Cached falls by at least half its size (other
/// activity moves Cached on Linux); ramfs data
/// (only in the cache) survives it
fn drop_caches() {
    use crate::tests::helpers::proc_kb;
    let fd = sys_open(b"/mnt/vd1/DC.BIN\0".as_ptr(), O_RDWR | O_CREAT, 0o644) as i32;
    let buf = [b'd'; 4096];
    for i in 0..256 {
        sys_pwrite64(fd, buf.as_ptr(), 4096, i * 4096);
    }
    sys_fsync(fd);
    let before = proc_kb(b"/proc/meminfo\0", b"Cached:");
    let w = drop_caches_write(b"1\n");
    let after = proc_kb(b"/proc/meminfo\0", b"Cached:");
    let mut back = [0u8; 4096];
    let n = sys_pread64(fd, back.as_mut_ptr(), 4096, 255 * 4096);
    sys_close(fd as u64);
    sys_unlink(b"/mnt/vd1/DC.BIN\0".as_ptr());
    verdict(
        b"DROP_CACHES",
        w == 2 && before - after >= 512 && n == 4096 && back == buf,
        before - after,
    );
    let t = sys_open(b"/tmp/dc_ramfs\0".as_ptr(), O_RDWR | O_CREAT, 0o644) as i32;
    sys_pwrite64(t, b"ramfs keeps it".as_ptr(), 14, 0);
    let w = drop_caches_write(b"3\n");
    let mut r = [0u8; 14];
    let n = sys_pread64(t, r.as_mut_ptr(), 14, 0);
    sys_close(t as u64);
    sys_unlink(b"/tmp/dc_ramfs\0".as_ptr());
    verdict(
        b"DROP_CACHES_RAMFS",
        w == 2 && n == 14 && &r == b"ramfs keeps it",
        n,
    );
}

/// A vfat file can be a swap area (Linux: bmap, generic swapfile
/// activation): swapon checks its header against the file (last_page
/// 0 and an area past the file are EINVAL); one that fits works
fn vfat_swapfile() {
    use hk_syscall::sys_ftruncate;
    let path = b"/mnt/vd1/SWAP.BIN\0";
    let mut got = [0i64; 3];
    let mut busy = [0i64; 4];
    let mut map = [0i64; 5];
    for (i, last) in [0u32, 0x7fff_ffff, 255].into_iter().enumerate() {
        let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT, 0o600) as i32;
        let mut hdr = [0u8; 4096];
        hdr[1024..1028].copy_from_slice(&1u32.to_ne_bytes());
        hdr[1028..1032].copy_from_slice(&last.to_ne_bytes());
        hdr[4086..].copy_from_slice(b"SWAPSPACE2");
        let ok =
            sys_pwrite64(fd, hdr.as_ptr(), 4096, 0) == 4096 && sys_ftruncate(fd, 256 * 4096) == 0;
        sys_fsync(fd);
        sys_close(fd as u64);
        // A shared writable mapping made before swapon
        let rw = sys_open(path.as_ptr(), O_RDWR, 0) as i32;
        let early = hk_syscall::sys_mmap(
            0,
            4096,
            hk_syscall::PROT_READ | hk_syscall::PROT_WRITE,
            hk_syscall::MAP_SHARED,
            rw,
            4096,
        );
        let early_ro = hk_syscall::sys_mmap(
            0,
            4096,
            hk_syscall::PROT_READ,
            hk_syscall::MAP_SHARED,
            rw,
            0,
        );
        got[i] = if ok {
            sys_swapon(path.as_ptr(), 0)
        } else {
            -1000
        };
        if got[i] == 0 {
            map = swapfile_map(rw, early, early_ro);
        }
        for m in [early, early_ro] {
            if m > 0 {
                hk_syscall::sys_munmap(m as u64, 4096);
            }
        }
        sys_close(rw as u64);
        if got[i] == 0 {
            // Active: no write, truncate (also by O_TRUNC) or unlink
            // (Linux IS_SWAPFILE: ETXTBSY, EPERM for unlink)
            let fd = sys_open(path.as_ptr(), O_WRONLY, 0) as i32;
            let w = sys_pwrite64(fd, b"x".as_ptr(), 1, 8192);
            let t = sys_ftruncate(fd, 4096);
            sys_close(fd as u64);
            let ot = sys_open(path.as_ptr(), O_WRONLY | O_TRUNC, 0);
            let un = hk_syscall::sys_unlink(path.as_ptr());
            busy = [w, t, ot, un];
            got[i] = sys_swapoff(path.as_ptr()) * 100;
        }
    }
    sys_unlink(path.as_ptr());
    verdict(
        b"VFAT_SWAPFILE",
        got[0] == EINVAL && got[1] == EINVAL && got[2] == 0,
        got[0] * 10000 + got[1] * 100 + got[2],
    );
    verdict(
        b"VFAT_SWAPFILE_BUSY",
        busy == [-26, -26, -26, -1],
        busy[0] * 1000 + busy[1] * 100 + busy[2] * 10 + busy[3],
    );
    // mmap shared writable and copy_file_range into it are ETXTBSY; a
    // write through a mapping made before swapon is SIGBUS (Linux
    // do_mmap, generic_copy_file_checks, do_page_mkwrite), and mprotect
    // may still make such a mapping writable (VM_MAYWRITE was decided
    // at mmap)
    verdict(
        b"VFAT_SWAPFILE_MAP",
        map == [-26, -26, 0x100 + 7, 0, -26],
        map[0] * 1_000_000 + map[1] * 1000 + map[2] + map[3] * 10_000_000 + map[4] * 100_000_000,
    );
}

/// How a child writing a byte at `p` (after reading it first with
/// `read_first`) ends: 0x100 + signal, or its exit status
fn writer_ends(p: i64, read_first: bool) -> i64 {
    let pid = hk_syscall::sys_fork();
    if pid == 0 {
        if read_first {
            unsafe { core::ptr::read_volatile(p as *const u8) };
        }
        unsafe { core::ptr::write_volatile(p as *mut u8, 1) };
        hk_syscall::sys_exit(0);
    }
    let mut st = 0i32;
    hk_syscall::sys_wait4(pid, &mut st, 0, 0);
    if st & 0x7f != 0 {
        0x100 + i64::from(st & 0x7f)
    } else {
        i64::from(st >> 8)
    }
}

/// On an active swap file open read-write as `rw` with `early` mapped
/// shared writable and `early_ro` shared read-only before swapon:
/// [mmap shared writable, copy_file_range into it, how a child writing
/// `early` ends (0x100 + signal), mprotect of `early_ro` writable,
/// mmap shared writable through a write-only descriptor (the swap file
/// is checked before readability, Linux do_mmap: ETXTBSY)]
fn swapfile_map(rw: i32, early: i64, early_ro: i64) -> [i64; 5] {
    use hk_syscall::{MAP_SHARED, PROT_READ, PROT_WRITE};
    let m = hk_syscall::sys_mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, rw, 0);
    if m > 0 {
        hk_syscall::sys_munmap(m as u64, 4096);
    }
    let src = sys_open(b"/mnt/vd1/CFR.SRC\0".as_ptr(), O_RDWR | O_CREAT, 0o600) as i32;
    sys_pwrite64(src, b"y".as_ptr(), 1, 0);
    let mut off: u64 = 8192;
    let c = hk_syscall::sys_copy_file_range(src, core::ptr::null_mut(), rw, &mut off, 1, 0);
    sys_close(src as u64);
    sys_unlink(b"/mnt/vd1/CFR.SRC\0".as_ptr());
    let mut child = -1;
    if early > 0 {
        // A plain write, then a write after a read (the read maps the
        // page read-only; the write-protect fault must refuse it too)
        let w = writer_ends(early, false);
        let rw = writer_ends(early, true);
        child = if w == rw { w } else { w * 1000 + rw };
    }
    let mp = if early_ro > 0 {
        hk_syscall::sys_mprotect(
            early_ro as u64,
            4096,
            hk_syscall::PROT_READ | hk_syscall::PROT_WRITE,
        )
    } else {
        -1000
    };
    let wo = sys_open(b"/mnt/vd1/SWAP.BIN\0".as_ptr(), O_WRONLY, 0) as i32;
    let mw = hk_syscall::sys_mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, wo, 0);
    if mw > 0 {
        hk_syscall::sys_munmap(mw as u64, 4096);
    }
    sys_close(wo as u64);
    [
        if m > 0 { 0 } else { m },
        c,
        child,
        mp,
        if mw > 0 { 0 } else { mw },
    ]
}

/// A shared mapping of a vfat file is its page cache (Linux
/// fat_file_mmap): read() sees a write through it, and it sees write()
fn vfat_mmap_write() {
    use hk_syscall::{MAP_SHARED, PROT_READ, PROT_WRITE, sys_ftruncate, sys_mmap, sys_munmap};
    let fd = sys_open(b"/mnt/vd1/M.TXT\0".as_ptr(), O_RDWR | O_CREAT, 0o644) as i32;
    let page = [b'w'; 4096];
    let w = sys_pwrite64(fd, page.as_ptr(), 4096, 0);
    let t = sys_ftruncate(fd, 8192);
    let m = sys_mmap(0, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    let mut ok = fd >= 0 && w == 4096 && t == 0 && m > 0;
    if m > 0 {
        let v = unsafe { core::slice::from_raw_parts_mut(m as *mut u8, 8192) };
        ok &= v[10] == b'w' && v[5000] == 0;
        v[4096..4100].copy_from_slice(b"mmap");
        sys_pwrite64(fd, b"W".as_ptr(), 1, 11);
        ok &= v[11] == b'W';
        // Written back (and write-protected): a write through the
        // mapping now must dirty the page again (Linux folio_mkclean)
        ok &= sys_fsync(fd) == 0;
        v[4096..4100].copy_from_slice(b"MMAP");
        sys_munmap(m as u64, 8192);
        // Read-only, read, then made writable by mprotect: the store
        // must still dirty the page (Linux vma_wants_writenotify keeps
        // the entry read-only until a write fault). Written back first,
        // so the page is clean.
        ok &= sys_fsync(fd) == 0;
        let r = sys_mmap(0, 4096, PROT_READ, MAP_SHARED, fd, 4096);
        if r > 0 {
            let w = unsafe { core::slice::from_raw_parts_mut(r as *mut u8, 4096) };
            ok &= w[0] == b'M';
            ok &= hk_syscall::sys_mprotect(r as u64, 4096, PROT_READ | PROT_WRITE) == 0;
            w[100..104].copy_from_slice(b"MPRO");
            sys_munmap(r as u64, 4096);
        } else {
            ok = false;
        }
    }
    let mut got = [0u8; 4];
    sys_pread64(fd, got.as_mut_ptr(), 4, 4096);
    sys_pwrite64(fd, b"w".as_ptr(), 1, 11);
    sys_close(fd as u64);
    verdict(b"VFAT_MAP_SHARED", ok && &got == b"MMAP", w);
}

/// An open file renamed is still the same inode under its new name
/// (one inode per FAT entry, moved with it: Linux fat_iget/fat_attach)
fn vfat_rename_ino() {
    let fd = sys_open(b"/mnt/vd1/A.TXT\0".as_ptr(), O_RDWR | O_CREAT, 0o644) as i32;
    let r = sys_rename(b"/mnt/vd1/A.TXT\0".as_ptr(), b"/mnt/vd1/B.TXT\0".as_ptr());
    let mut a: Stat = unsafe { core::mem::zeroed() };
    let mut b: Stat = unsafe { core::mem::zeroed() };
    sys_fstat(fd, &mut a);
    let s = sys_stat(b"/mnt/vd1/B.TXT\0".as_ptr(), &mut b);
    sys_close(fd as u64);
    sys_unlink(b"/mnt/vd1/B.TXT\0".as_ptr());
    verdict(
        b"VFAT_RENAME_INO",
        fd >= 0 && r == 0 && s == 0 && a.st_ino == b.st_ino,
        r * 1000 + s,
    );
}

/// Growing an unlinked, still open file never touches the directory
/// entry of a new file that took its name (Linux fat_detach)
fn vfat_unlink_reuse() {
    let p = b"/mnt/vd1/R.TXT\0";
    let old = sys_open(p.as_ptr(), O_RDWR | O_CREAT, 0o644) as i32;
    let un = sys_unlink(p.as_ptr());
    let new = sys_open(p.as_ptr(), O_RDWR | O_CREAT, 0o644) as i32;
    let wn = sys_pwrite64(new, b"new".as_ptr(), 3, 0);
    sys_close(new as u64);
    let big = [b'o'; 8192];
    let wo = sys_pwrite64(old, big.as_ptr(), big.len() as u64, 0);
    sys_fsync(old);
    let mut b = [0u8; 16];
    let n = read_file(p, &mut b);
    sys_close(old as u64);
    sys_unlink(p.as_ptr());
    verdict(
        b"VFAT_UNLINK_REUSE",
        un == 0 && wn == 3 && wo == 8192 && n == 3 && &b[..3] == b"new",
        n,
    );
}

/// An unlinked file still open keeps its data: its clusters are not
/// reused by a new file until the last close (Linux fat_evict_inode)
fn vfat_unlink_open() {
    let mut buf = [0u8; 16384];
    buf.fill(b'u');
    let fd = sys_open(b"/mnt/vd1/U.TXT\0".as_ptr(), O_RDWR | O_CREAT, 0o644) as i32;
    let w = sys_pwrite64(fd, buf.as_ptr(), buf.len() as u64, 0);
    sys_fsync(fd);
    let un = sys_unlink(b"/mnt/vd1/U.TXT\0".as_ptr());
    buf.fill(b'v');
    let v = sys_open(b"/mnt/vd1/V.TXT\0".as_ptr(), O_RDWR | O_CREAT, 0o644) as i32;
    let wv = sys_pwrite64(v, buf.as_ptr(), buf.len() as u64, 0);
    sys_fsync(v);
    sys_close(v as u64);
    buf.fill(0);
    let n = sys_pread64(fd, buf.as_mut_ptr(), buf.len() as u64, 0);
    let mut st: Stat = unsafe { core::mem::zeroed() };
    sys_fstat(fd, &mut st);
    sys_close(fd as u64);
    sys_unlink(b"/mnt/vd1/V.TXT\0".as_ptr());
    let kept = buf.iter().all(|&c| c == b'u');
    verdict(
        b"VFAT_UNLINK_OPEN",
        w == 16384 && un == 0 && wv == 16384 && n == 16384 && kept && st.st_nlink == 0,
        n,
    );
}

/// swapon reads vda2's swap header through the block layer
fn swap(p2: &BlkDev) {
    let mut p = [0u8; 48];
    let path = p2.path(&mut p);
    let on = sys_swapon(path.as_ptr(), 0);
    let again = sys_swapon(path.as_ptr(), 0);
    // An active swap partition cannot be written (Linux
    // blkdev_write_iter: IS_SWAPFILE -> ETXTBSY)
    let fd = sys_open(path.as_ptr(), O_WRONLY, 0) as i32;
    let w = sys_pwrite64(fd, b"x".as_ptr(), 1, 8192);
    sys_close(fd as u64);
    let off = sys_swapoff(path.as_ptr());
    let ok = on == 0 && again == EBUSY && off == 0;
    verdict(b"BLK_SWAPON", ok, on * 1000 + again);
    verdict(b"SWAP_ETXTBSY", on == 0 && fd >= 0 && w == -26, w);
}

/// A name vfat matches without regard to case or trailing dots is found
/// after a failed lookup of another spelling (Linux vfat_revalidate_ci:
/// no stale negative dentry)
fn vfat_neg_case(p1: &BlkDev) {
    let r = mount_vd1(p1, b"iocharset=cp437\0");
    // SAFETY: Stat is plain integers
    let mut st: Stat = unsafe { core::mem::zeroed() };
    let miss = sys_stat(b"/mnt/vd1/NEGCASE.TXT\0".as_ptr(), &mut st);
    let miss2 = sys_stat(b"/mnt/vd1/td.\0".as_ptr(), &mut st);
    let fd = sys_open(
        b"/mnt/vd1/negcase.txt\0".as_ptr(),
        O_CREAT | O_WRONLY,
        0o644,
    );
    sys_close(fd as u64);
    let fd2 = sys_open(b"/mnt/vd1/td\0".as_ptr(), O_CREAT | O_WRONLY, 0o644);
    sys_close(fd2 as u64);
    let hit = sys_stat(b"/mnt/vd1/NEGCASE.TXT\0".as_ptr(), &mut st);
    let hit2 = sys_stat(b"/mnt/vd1/td.\0".as_ptr(), &mut st);
    sys_unlink(b"/mnt/vd1/negcase.txt\0".as_ptr());
    sys_unlink(b"/mnt/vd1/td\0".as_ptr());
    sys_umount2(b"/mnt/vd1\0".as_ptr(), 0);
    let ok = r == 0 && miss == -2 && miss2 == -2 && fd >= 0 && fd2 >= 0 && hit == 0 && hit2 == 0;
    verdict(b"VFAT_NEG_CASE", ok, hit * 100 + hit2);
}

/// A mount on a vfat directory covers every spelling of it: "AL" and
/// "al" are one directory, and what is under the mount stays hidden
/// (Linux: one dentry through vfat's d_hash/d_compare)
fn vfat_mount_alias(p1: &BlkDev) {
    let r = mount_vd1(p1, b"iocharset=cp437\0");
    sys_mkdir(b"/mnt/vd1/al\0".as_ptr(), 0o755);
    let fd = sys_open(b"/mnt/vd1/al/under\0".as_ptr(), O_CREAT | O_WRONLY, 0o644);
    sys_close(fd as u64);
    let m = sys_mount(
        b"none\0".as_ptr(),
        b"/mnt/vd1/al\0".as_ptr(),
        b"ramfs\0".as_ptr(),
        0,
        0,
    );
    // SAFETY: Stat is plain integers
    let mut st: Stat = unsafe { core::mem::zeroed() };
    let lower = sys_stat(b"/mnt/vd1/al/under\0".as_ptr(), &mut st);
    let upper = sys_stat(b"/mnt/vd1/AL/under\0".as_ptr(), &mut st);
    sys_umount2(b"/mnt/vd1/al\0".as_ptr(), 0);
    sys_unlink(b"/mnt/vd1/al/under\0".as_ptr());
    hk_syscall::sys_rmdir(b"/mnt/vd1/al\0".as_ptr());
    sys_umount2(b"/mnt/vd1\0".as_ptr(), 0);
    let ok = r == 0 && fd >= 0 && m == 0 && lower == -2 && upper == -2;
    verdict(b"VFAT_MOUNT_ALIAS", ok, lower * 100 + upper);
}

/// Dirty kB after writing 2 MiB to a new file on vda1 mounted with
/// `flags`, opened with `oflags` (Linux generic_write_sync)
fn dirty_after_write(p1: &BlkDev, flags: u64, oflags: u32) -> i64 {
    use crate::tests::helpers::proc_kb;
    let mut p = [0u8; 48];
    let r = sys_mount(
        p1.path(&mut p).as_ptr(),
        b"/mnt/vd1\0".as_ptr(),
        b"vfat\0".as_ptr(),
        flags,
        b"iocharset=cp437\0".as_ptr() as u64,
    );
    if r != 0 {
        return r * 1_000_000;
    }
    let f = b"/mnt/vd1/SYNC.BIN\0";
    let fd = sys_open(f.as_ptr(), O_CREAT | O_WRONLY | oflags, 0o644) as i32;
    let buf = [b's'; 4096];
    let before = proc_kb(b"/proc/meminfo\0", b"Dirty:");
    for i in 0..512 {
        sys_pwrite64(fd, buf.as_ptr(), 4096, i * 4096);
    }
    let after = proc_kb(b"/proc/meminfo\0", b"Dirty:");
    sys_close(fd as u64);
    sys_unlink(f.as_ptr());
    sys_umount2(b"/mnt/vd1\0".as_ptr(), 0);
    after - before
}

/// A write on an MS_SYNCHRONOUS mount, or through an O_SYNC descriptor,
/// reaches the disk before it returns: 2 MiB written leaves (almost)
/// nothing dirty, where a plain write leaves it dirty
fn vfat_sync(p1: &BlkDev) {
    const MS_SYNCHRONOUS: u64 = 16;
    const O_SYNC: u32 = 0o4010000;
    let plain = dirty_after_write(p1, 0, 0);
    let sync = dirty_after_write(p1, MS_SYNCHRONOUS, 0);
    let osync = dirty_after_write(p1, 0, O_SYNC);
    verdict(
        b"VFAT_SYNC_WRITE",
        plain >= 1024 && sync < 512 && osync < 512,
        plain * 1_000_000 + sync * 1000 + osync,
    );
}

/// A corrupt cluster chain is EIO (Linux fat_get_cluster / fat_ent_read):
/// the root directory's FAT entry set free, then pointing at itself
/// (a loop), fails the mount; the entry put back, it mounts again
fn vfat_corrupt_chain(p1: &BlkDev) {
    let fd = open_dev(p1, O_RDWR);
    let mut bpb = [0u8; 512];
    sys_pread64(fd, bpb.as_mut_ptr(), 512, 0);
    let bps = u64::from(u16::from_le_bytes([bpb[11], bpb[12]]));
    let reserved = u64::from(u16::from_le_bytes([bpb[14], bpb[15]]));
    let root = u32::from_le_bytes([bpb[44], bpb[45], bpb[46], bpb[47]]);
    let at = (reserved * bps + u64::from(root) * 4) as i64;
    let mut old = [0u8; 4];
    sys_pread64(fd, old.as_mut_ptr(), 4, at);
    let put = |v: &[u8; 4]| {
        sys_pwrite64(fd, v.as_ptr(), 4, at);
        sys_fsync(fd);
        mount_vd1(p1, b"iocharset=cp437\0")
    };
    let free = put(&[0; 4]);
    if free == 0 {
        sys_umount2(b"/mnt/vd1\0".as_ptr(), 0);
    }
    let lp = put(&root.to_le_bytes());
    if lp == 0 {
        sys_umount2(b"/mnt/vd1\0".as_ptr(), 0);
    }
    let back = put(&old);
    if back == 0 {
        sys_umount2(b"/mnt/vd1\0".as_ptr(), 0);
    }
    sys_close(fd as u64);
    verdict(
        b"VFAT_CORRUPT_CHAIN",
        free == EIO && lp == EIO && back == 0,
        free * 10000 + lp * 100 + back,
    );
}

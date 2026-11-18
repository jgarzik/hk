//! The block device cache in buffer heads (Linux fs/buffer.c,
//! block/fops.c def_blk_aops, block/bdev.c set_blocksize): sub-page
//! writes through the device file at several offsets, with BLKBSZSET
//! changing the soft block size between them (each change writes the
//! cache back and drops it), read back through the cache and with
//! O_DIRECT, which sees the disk. vda3 holds the pattern of
//! tools/mkdisk.sh; the range is put back afterwards.

use crate::blk::dsync::pat;
use crate::harness::{R, check, report_r};
use crate::helpers::{BlkDev, find_blkdev};
use hk_syscall::{
    MAP_ANONYMOUS, MAP_PRIVATE, O_DIRECT, O_RDONLY, O_RDWR, PROT_READ, PROT_WRITE, sys_close,
    sys_fsync, sys_ioctl, sys_mmap, sys_munmap, sys_open, sys_pread64, sys_pwrite64,
};

const BLKBSZGET: u64 = 0x8008_1270;
const BLKBSZSET: u64 = 0x4008_1271;
const BLKFLSBUF: u64 = 0x1261;

/// A range of vda3 (16 MiB) no other test touches
const BASE: i64 = (13 << 20) + 262144;
const LEN: usize = 6 * 4096;

/// (soft block size set first, offset from BASE, length, fill byte)
const WRITES: [(i32, usize, usize, u8); 6] = [
    (512, 100, 8, 0xa1),
    // Across a sector boundary
    (512, 4096 + 1000, 512, 0xb2),
    // Across a page boundary
    (1024, 8192 + 3000, 2000, 0xc3),
    (1024, 12288 + 700, 100, 0xd4),
    // Across a page boundary, with a 4 KiB block on each side
    (4096, 16384 + 4090, 12, 0xe5),
    (2048, 20480 + 1536, 1024, 0xf6),
];

pub fn run_tests() {
    report_r(b"BLK_BUFHEAD_RW", rw());
}

fn open_dev(d: &BlkDev, flags: u32) -> i64 {
    let mut p = [0u8; 48];
    sys_open(d.path(&mut p).as_ptr(), flags, 0)
}

fn bsz(fd: i64) -> i32 {
    let mut v = 0i32;
    sys_ioctl(fd as i32, BLKBSZGET, &mut v as *mut i32 as u64);
    v
}

fn set_bsz(fd: i64, v: i32) -> i64 {
    sys_ioctl(fd as i32, BLKBSZSET, &v as *const i32 as u64)
}

/// What the range holds after `WRITES`
fn expected() -> [u8; LEN] {
    let mut e = [0u8; LEN];
    for (i, b) in e.iter_mut().enumerate() {
        *b = pat(BASE + i as i64)[0];
    }
    for &(_, off, n, v) in &WRITES {
        e[off..off + n].fill(v);
    }
    e
}

/// The first offset where `got` differs from `want`, as the failure's
/// number (-1: none)
fn first_diff(got: &[u8], want: &[u8]) -> i64 {
    got.iter()
        .zip(want)
        .position(|(a, b)| a != b)
        .map_or(-1, |i| i as i64)
}

fn rw() -> R {
    let Some(p3) = find_blkdev(b"vd", 16384) else {
        return check(b"no vda3", false, 0);
    };
    let fd = open_dev(&p3, O_RDWR);
    check(b"open", fd >= 0, fd)?;
    let init = bsz(fd);
    let r = writes(fd);
    let r = r.and_then(|()| verify(&p3, fd));
    restore(fd, init);
    sys_close(fd as u64);
    r
}

/// Each write after its block size was set
fn writes(fd: i64) -> R {
    for &(size, off, n, v) in &WRITES {
        let r = set_bsz(fd, size);
        check(b"BLKBSZSET", r == 0, r)?;
        let got = bsz(fd);
        check(b"BLKBSZGET", got == size, i64::from(got))?;
        let buf = [v; 2048];
        let w = sys_pwrite64(fd as i32, buf.as_ptr(), n as u64, BASE + off as i64);
        check(b"pwrite", w == n as i64, w)?;
    }
    Ok(())
}

/// The range read through the cache (block size 512: the change wrote
/// the cache back and dropped it), then from the disk with O_DIRECT
/// after fsync
fn verify(p3: &BlkDev, fd: i64) -> R {
    let want = expected();
    let mut got = [0u8; LEN];
    let n = sys_pread64(fd as i32, got.as_mut_ptr(), LEN as u64, BASE);
    check(b"cached read", n == LEN as i64, n)?;
    check(b"cached data", got == want, first_diff(&got, &want))?;
    // Again after a block size change: from the disk through new buffers
    let r = set_bsz(fd, 512);
    check(b"BLKBSZSET 512", r == 0, r)?;
    let n = sys_pread64(fd as i32, got.as_mut_ptr(), LEN as u64, BASE);
    check(b"reread", n == LEN as i64, n)?;
    check(b"reread data", got == want, first_diff(&got, &want))?;
    // A sub-block write into the 512-byte buffers of a cached page
    let w = sys_pwrite64(fd as i32, want[300..].as_ptr(), 40, BASE + 300);
    check(b"rewrite", w == 40, w)?;
    let r = sys_fsync(fd as i32);
    check(b"fsync", r == 0, r)?;
    let dfd = open_dev(p3, O_RDONLY | O_DIRECT);
    check(b"open O_DIRECT", dfd >= 0, dfd)?;
    let m = sys_mmap(
        0,
        LEN as u64,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if m <= 0 {
        sys_close(dfd as u64);
        return check(b"mmap", false, m);
    }
    let n = sys_pread64(dfd as i32, m as *mut u8, LEN as u64, BASE);
    // SAFETY: the mapping just made, LEN bytes
    let disk = unsafe { core::slice::from_raw_parts(m as *const u8, LEN) };
    let d = first_diff(disk, &want);
    sys_munmap(m as u64, LEN as u64);
    sys_close(dfd as u64);
    check(b"O_DIRECT read", n == LEN as i64, n)?;
    check(b"disk data", d == -1, d)
}

/// The pattern back over the range, on the disk, the cache dropped and
/// the block size as it was
fn restore(fd: i64, init: i32) {
    let mut p = [0u8; LEN];
    for (i, b) in p.iter_mut().enumerate() {
        *b = pat(BASE + i as i64)[0];
    }
    sys_pwrite64(fd as i32, p.as_ptr(), LEN as u64, BASE);
    sys_fsync(fd as i32);
    sys_ioctl(fd as i32, BLKFLSBUF, 0);
    set_bsz(fd, init);
}

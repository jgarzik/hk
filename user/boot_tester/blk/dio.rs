//! Block-device direct I/O (Linux block/fops.c: blkdev_direct_IO,
//! blkdev_read_iter, blkdev_write_iter, direct_write_fallback) on vda3's
//! pattern words (tools/mkdisk.sh): bios straight between the device and
//! the caller's pinned pages. Position and length must be multiples of
//! the logical block size, every segment's address and length of the DMA
//! alignment (512 here: EINVAL); a read stops at the end of the device;
//! the cache is written back before and invalidated after (buffered
//! I/O and mappings of the device see a direct write, a direct read sees
//! a buffered write); a buffer that cannot be pinned all the way shortens
//! the I/O (EFAULT if nothing could be); RWF_NOWAIT is EAGAIN where the
//! I/O would wait (cache to write back or drop, more than one bio).
//!
//! Reads use vda3's untouched first 7 MiB; writes go to 9..11 MiB, put
//! back afterwards.

use crate::blk::dsync::p3_start;
use crate::harness::{R, check, report_r};
use crate::helpers::{BlkDev, find_blkdev};
use hk_syscall::{
    IoVec, MAP_ANONYMOUS, MAP_PRIVATE, MAP_SHARED, O_RDONLY, O_RDWR, PROT_READ, PROT_WRITE,
    sys_close, sys_mmap, sys_munmap, sys_open, sys_pread64, sys_preadv, sys_preadv2, sys_pwrite64,
    sys_pwritev, sys_pwritev2,
};

const O_DIRECT: u32 = hk_syscall::O_DIRECT;
const O_DSYNC: u32 = 0o10000;
const EAGAIN: i64 = -11;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const ENOSPC: i64 = -28;
const EOPNOTSUPP: i64 = -95;
const RWF_DSYNC: i32 = 2;
const RWF_NOWAIT: i32 = 8;

const PAGE: u64 = 4096;
const MIB: u64 = 1 << 20;
const SIZE: u64 = 16 * MIB;
/// Pattern only read (no test writes vda3's first 7 MiB)
const RD: u64 = 2 * MIB;
/// Written and put back (9..11 MiB)
const WR: u64 = 9 * MIB;

pub fn run_tests() {
    let Some(p3) = find_blkdev(b"vd", 16384) else {
        report_r(b"BLK_DIO", check(b"no vda3", false, 0));
        return;
    };
    let d = open(&p3, O_RDWR | O_DIRECT);
    let b = open(&p3, O_RDWR);
    let f = Fds { d, b };
    let cases: [(&[u8], fn(&Fds) -> R); 9] = [
        (b"BLK_DIO_RW", rw),
        (b"BLK_DIO_ALIGN", align),
        (b"BLK_DIO_EOF", eof),
        (b"BLK_DIO_COHERENT", coherent),
        (b"BLK_DIO_READV", readv),
        (b"BLK_DIO_FAULT", fault),
        (b"BLK_DIO_NOWAIT", nowait),
        (b"BLK_DIO_LARGE", large),
        (b"BLK_DIO_RESTORED", restored),
    ];
    for (name, t) in cases {
        let r = if d < 0 || b < 0 {
            check(b"open", false, d.min(b) as i64)
        } else {
            t(&f)
        };
        report_r(name, r);
    }
    report_r(b"BLK_DIO_DSYNC", dsync(&p3, &f));
    sys_close(d as u64);
    sys_close(b as u64);
}

/// vda3 opened twice: O_DIRECT and buffered
struct Fds {
    d: i32,
    b: i32,
}

fn open(d: &BlkDev, flags: u32) -> i32 {
    let mut p = [0u8; 48];
    sys_open(d.path(&mut p).as_ptr(), flags, 0) as i32
}

/// Pattern byte of vda3 at `off`
fn pat(off: u64) -> u8 {
    let w = ((off / 4) as u32)
        .wrapping_mul(1103515245)
        .wrapping_add(12345);
    w.to_le_bytes()[(off % 4) as usize]
}

/// Anonymous memory, unmapped when dropped
struct Buf {
    at: u64,
    len: u64,
}

impl Buf {
    fn new(len: u64) -> Result<Self, (&'static [u8], i64)> {
        let p = sys_mmap(
            0,
            len,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );
        check(b"mmap", p > 0, p)?;
        Ok(Self { at: p as u64, len })
    }

    fn ptr(&self, off: u64) -> *mut u8 {
        (self.at + off) as *mut u8
    }

    fn bytes(&self, off: u64, n: u64) -> &mut [u8] {
        // SAFETY: inside the mapping, which lives as long as `self`
        unsafe { core::slice::from_raw_parts_mut(self.ptr(off), n as usize) }
    }
}

impl Drop for Buf {
    fn drop(&mut self) {
        sys_munmap(self.at, self.len);
    }
}

/// Fill with the pattern of device offset `dev`..
fn fill_pat(s: &mut [u8], dev: u64) {
    for (i, b) in s.iter_mut().enumerate() {
        *b = pat(dev + i as u64);
    }
}

/// Fill with data no device offset has: `seed` mixed with the index
fn fill_data(s: &mut [u8], seed: u8) {
    for (i, b) in s.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(31) ^ seed ^ (i >> 9) as u8;
    }
}

/// Ok if `s` holds the pattern of `dev`..; else the first wrong index
fn is_pat(what: &'static [u8], s: &[u8], dev: u64) -> R {
    let bad = s
        .iter()
        .enumerate()
        .position(|(i, &b)| b != pat(dev + i as u64));
    check(what, bad.is_none(), bad.map_or(0, |i| i as i64))
}

fn same(what: &'static [u8], a: &[u8], b: &[u8]) -> R {
    let bad = a.iter().zip(b).position(|(x, y)| x != y);
    check(what, bad.is_none(), bad.map_or(0, |i| i as i64))
}

fn pread(fd: i32, p: *mut u8, n: u64, off: u64) -> i64 {
    sys_pread64(fd, p, n, off as i64)
}

fn pwrite(fd: i32, p: *const u8, n: u64, off: u64) -> i64 {
    sys_pwrite64(fd, p, n, off as i64)
}

fn rw2(fd: i32, p: *const u8, n: u64, off: u64, flags: i32, write: bool) -> i64 {
    let iov = IoVec {
        iov_base: p,
        iov_len: n as usize,
    };
    if write {
        sys_pwritev2(fd, &iov, 1, off as i64, flags)
    } else {
        sys_preadv2(fd, &iov, 1, off as i64, flags)
    }
}

/// Put the pattern back at `off`.. with direct writes (which also drop
/// what the cache held there)
fn restore(f: &Fds, off: u64, len: u64) -> R {
    let b = Buf::new(len)?;
    fill_pat(b.bytes(0, len), off);
    let w = pwrite(f.d, b.ptr(0), len, off);
    check(b"restore", w == len as i64, w)
}

/// Aligned direct reads and writes round trip; the pattern is intact
fn rw(f: &Fds) -> R {
    const N: u64 = 65536;
    let a = Buf::new(N)?;
    let n = pread(f.d, a.ptr(0), N, RD);
    check(b"read", n == N as i64, n)?;
    is_pat(b"read data", a.bytes(0, N), RD)?;
    fill_data(a.bytes(0, N), 0x5a);
    let w = pwrite(f.d, a.ptr(0), N, WR);
    check(b"write", w == N as i64, w)?;
    let c = Buf::new(N)?;
    let n = pread(f.d, c.ptr(0), N, WR);
    check(b"read back", n == N as i64, n)?;
    same(b"data back", c.bytes(0, N), a.bytes(0, N))?;
    restore(f, WR, N)?;
    let n = pread(f.d, c.ptr(0), N, WR);
    check(b"read restored", n == N as i64, n)?;
    is_pat(b"restored", c.bytes(0, N), WR)
}

/// Position and length in logical blocks, segment memory 512-aligned:
/// EINVAL otherwise, with nothing written; a 512-aligned buffer that is
/// not page-aligned is fine
fn align(f: &Fds) -> R {
    let a = Buf::new(3 * PAGE)?;
    let p = |o: u64| a.ptr(o);
    let r = pread(f.d, p(0), PAGE, RD + 1);
    check(b"read pos", r == EINVAL, r)?;
    let r = pread(f.d, p(0), PAGE + 1, RD);
    check(b"read len", r == EINVAL, r)?;
    let r = pread(f.d, p(0), 100, RD);
    check(b"read short len", r == EINVAL, r)?;
    let r = pread(f.d, p(1), PAGE, RD);
    check(b"read buf", r == EINVAL, r)?;
    let r = pread(f.d, p(256), 512, RD);
    check(b"read buf 256", r == EINVAL, r)?;
    let r = pread(f.d, p(512), PAGE, RD);
    check(b"read buf 512", r == PAGE as i64, r)?;
    is_pat(b"read buf 512 data", a.bytes(512, PAGE), RD)?;
    fill_data(a.bytes(0, 3 * PAGE), 0x33);
    let r = pwrite(f.d, p(0), PAGE, WR + 1);
    check(b"write pos", r == EINVAL, r)?;
    let r = pwrite(f.d, p(0), 100, WR);
    check(b"write len", r == EINVAL, r)?;
    let r = pwrite(f.d, p(1), PAGE, WR);
    check(b"write buf", r == EINVAL, r)?;
    let c = Buf::new(2 * PAGE)?;
    let n = pread(f.d, c.ptr(0), 2 * PAGE, WR);
    check(b"read after", n == 2 * PAGE as i64, n)?;
    is_pat(b"nothing written", c.bytes(0, 2 * PAGE), WR)?;
    fill_pat(a.bytes(512, PAGE), WR);
    let r = pwrite(f.d, p(512), PAGE, WR);
    check(b"write buf 512", r == PAGE as i64, r)?;
    let n = pread(f.d, c.ptr(0), PAGE, WR);
    check(b"read back", n == PAGE as i64, n)?;
    is_pat(b"back", c.bytes(0, PAGE), WR)
}

/// The end of the device: a read there or past it is 0, one across it
/// stops there (its own length truncated before the alignment check), a
/// write there ENOSPC, one across it short; no bytes is 0 whatever the
/// alignment
fn eof(f: &Fds) -> R {
    let a = Buf::new(2 * PAGE)?;
    let r = pread(f.d, a.ptr(0), PAGE, SIZE);
    check(b"read at end", r == 0, r)?;
    let r = pread(f.d, a.ptr(0), PAGE, SIZE + PAGE);
    check(b"read past end", r == 0, r)?;
    let r = pread(f.d, a.ptr(0), PAGE, SIZE - 1024);
    check(b"read across", r == 1024, r)?;
    // The disk tests changed the last bytes; the first 512 are the pattern
    is_pat(b"read across data", a.bytes(0, 512), SIZE - 1024)?;
    for (what, p, off) in [
        (&b"zero"[..], a.ptr(0), RD),
        (b"zero pos", a.ptr(0), RD + 1),
        (b"zero buf", a.ptr(1), RD),
    ] {
        let r = pread(f.d, p, 0, off);
        check(what, r == 0, r)?;
    }
    let r = pwrite(f.d, a.ptr(0), 0, WR + 1);
    check(b"write zero", r == 0, r)?;
    let r = pwrite(f.d, a.ptr(0), PAGE, SIZE);
    check(b"write at end", r == ENOSPC, r)?;
    let save = Buf::new(PAGE)?;
    let r = pread(f.d, save.ptr(0), 1024, SIZE - 1024);
    check(b"save", r == 1024, r)?;
    fill_data(a.bytes(0, PAGE), 0x77);
    let w = pwrite(f.d, a.ptr(0), PAGE, SIZE - 1024);
    let c = Buf::new(PAGE)?;
    let n = pread(f.d, c.ptr(0), 1024, SIZE - 1024);
    let back = pwrite(f.d, save.ptr(0), 1024, SIZE - 1024);
    check(b"write across", w == 1024, w)?;
    check(b"read across back", n == 1024, n)?;
    same(b"across data", c.bytes(0, 1024), a.bytes(0, 1024))?;
    check(b"put back", back == 1024, back)
}

/// The cache and direct I/O see each other: a buffered write is read
/// back directly; a direct write replaces a cached page (a buffered read
/// after sees it) and a mapped one (the mapping sees it)
fn coherent(f: &Fds) -> R {
    let a = Buf::new(PAGE)?;
    let c = Buf::new(PAGE)?;
    // A buffered write, still dirty in the cache, read directly
    fill_data(a.bytes(0, PAGE), 0xa5);
    let w = pwrite(f.b, a.ptr(0), PAGE, WR);
    check(b"buffered write", w == PAGE as i64, w)?;
    let n = pread(f.d, c.ptr(0), PAGE, WR);
    check(b"direct read", n == PAGE as i64, n)?;
    same(b"direct sees buffered", c.bytes(0, PAGE), a.bytes(0, PAGE))?;
    // A cached page, then a direct write over it
    let off = WR + 65536;
    let n = pread(f.b, c.ptr(0), PAGE, off);
    check(b"cache it", n == PAGE as i64, n)?;
    fill_data(a.bytes(0, PAGE), 0x3c);
    let w = pwrite(f.d, a.ptr(0), PAGE, off);
    check(b"direct write", w == PAGE as i64, w)?;
    let n = pread(f.b, c.ptr(0), PAGE, off);
    check(b"buffered read", n == PAGE as i64, n)?;
    same(b"buffered sees direct", c.bytes(0, PAGE), a.bytes(0, PAGE))?;
    // A mapped page, then a direct write over it
    let off2 = WR + 131072;
    let m = sys_mmap(0, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, f.b, off2);
    check(b"mmap", m > 0, m)?;
    // SAFETY: inside the mapping
    let first = unsafe { core::ptr::read_volatile(m as *const u8) };
    fill_data(a.bytes(0, PAGE), 0xc3);
    let w = pwrite(f.d, a.ptr(0), PAGE, off2);
    // SAFETY: the mapping, until the munmap below
    let mm = unsafe { core::slice::from_raw_parts(m as *const u8, PAGE as usize) };
    let r = same(b"mapping sees direct", mm, a.bytes(0, PAGE));
    sys_munmap(m as u64, PAGE);
    check(b"mapped before", first == pat(off2), i64::from(first))?;
    check(b"direct write mapped", w == PAGE as i64, w)?;
    r?;
    restore(f, WR, 3 * 65536)
}

/// Mixed segment sizes and offsets (each 512-aligned, some across a page
/// boundary) for readv and writev; a segment whose length or address is
/// not 512-aligned is EINVAL even when the total is
fn readv(f: &Fds) -> R {
    const SEGS: [(u64, u64); 5] = [
        (512, 512),
        (2048, 1024),
        (8192, 4096),
        (13824, 1536),
        (19456, 3072),
    ];
    const TOTAL: u64 = 10240;
    let a = Buf::new(8 * PAGE)?;
    let iov = SEGS.map(|(o, n)| IoVec {
        iov_base: a.ptr(o),
        iov_len: n as usize,
    });
    let n = sys_preadv(f.d, iov.as_ptr(), 5, (RD + PAGE) as i64);
    check(b"preadv", n == TOTAL as i64, n)?;
    let mut at = RD + PAGE;
    for (o, len) in SEGS {
        is_pat(b"preadv data", a.bytes(o, len), at)?;
        at += len;
    }
    let bad = [
        IoVec {
            iov_base: a.ptr(0),
            iov_len: 600,
        },
        IoVec {
            iov_base: a.ptr(PAGE),
            iov_len: 424,
        },
    ];
    let n = sys_preadv(f.d, bad.as_ptr(), 2, RD as i64);
    check(b"segment len", n == EINVAL, n)?;
    let bad = [
        IoVec {
            iov_base: a.ptr(0),
            iov_len: 512,
        },
        IoVec {
            iov_base: a.ptr(PAGE + 256),
            iov_len: 512,
        },
    ];
    let n = sys_preadv(f.d, bad.as_ptr(), 2, RD as i64);
    check(b"segment address", n == EINVAL, n)?;
    // writev of the same layout, read back in one piece
    for (i, (o, len)) in SEGS.into_iter().enumerate() {
        fill_data(a.bytes(o, len), i as u8 * 17 + 1);
    }
    let w = sys_pwritev(f.d, iov.as_ptr(), 5, WR as i64);
    check(b"pwritev", w == TOTAL as i64, w)?;
    let c = Buf::new(3 * PAGE)?;
    let n = pread(f.d, c.ptr(0), TOTAL, WR);
    check(b"read back", n == TOTAL as i64, n)?;
    let mut at = 0;
    for (o, len) in SEGS {
        same(b"pwritev data", c.bytes(at, len), a.bytes(o, len))?;
        at += len;
    }
    restore(f, WR, 3 * PAGE)
}

/// A buffer whose second page is not mapped: the direct I/O does the
/// first page, the rest falls back to the cache and faults, so the count
/// is the first page's; a buffer whose first page is not mapped is EFAULT
fn fault(f: &Fds) -> R {
    let a = Buf::new(2 * PAGE)?;
    sys_munmap(a.at + PAGE, PAGE);
    let n = pread(f.d, a.ptr(0), 2 * PAGE, RD);
    check(b"read", n == PAGE as i64, n)?;
    is_pat(b"read data", a.bytes(0, PAGE), RD)?;
    fill_data(a.bytes(0, PAGE), 0x99);
    let w = pwrite(f.d, a.ptr(0), 2 * PAGE, WR);
    let c = Buf::new(2 * PAGE)?;
    let n = pread(f.d, c.ptr(0), 2 * PAGE, WR);
    check(b"write", w == PAGE as i64, w)?;
    check(b"read back", n == 2 * PAGE as i64, n)?;
    same(b"written", c.bytes(0, PAGE), a.bytes(0, PAGE))?;
    is_pat(b"rest kept", c.bytes(PAGE, PAGE), WR + PAGE)?;
    restore(f, WR, PAGE)?;
    let e = Buf::new(2 * PAGE)?;
    sys_munmap(e.at, PAGE);
    let r = pread(f.d, e.ptr(0), 2 * PAGE, RD);
    check(b"read unmapped", r == EFAULT, r)?;
    let r = pwrite(f.d, e.ptr(0), 2 * PAGE, WR);
    check(b"write unmapped", r == EFAULT, r)
}

/// RWF_NOWAIT: a direct read with nothing to write back and a direct
/// write with nothing cached go ahead; a dirty page in a read's range,
/// any cached page in a write's, or an I/O needing more than one bio is
/// EAGAIN. Buffered: a write is EOPNOTSUPP, a read of cached data goes
/// ahead and of uncached data is EAGAIN.
fn nowait(f: &Fds) -> R {
    let a = Buf::new(PAGE)?;
    let r = rw2(f.d, a.ptr(0), PAGE, RD + MIB, RWF_NOWAIT, false);
    check(b"clean read", r == PAGE as i64, r)?;
    is_pat(b"clean read data", a.bytes(0, PAGE), RD + MIB)?;
    // Dirty in the cache: the read would write it back first
    let off = WR + 4 * 65536;
    fill_data(a.bytes(0, PAGE), 0x42);
    let w = pwrite(f.b, a.ptr(0), PAGE, off);
    check(b"dirty it", w == PAGE as i64, w)?;
    let c = Buf::new(PAGE)?;
    let r = rw2(f.d, c.ptr(0), PAGE, off, RWF_NOWAIT, false);
    check(b"dirty read", r == EAGAIN, r)?;
    let r = rw2(f.d, c.ptr(0), PAGE, off, 0, false);
    check(b"read", r == PAGE as i64, r)?;
    same(b"read data", c.bytes(0, PAGE), a.bytes(0, PAGE))?;
    // Cached (clean): the write would drop it first
    let off2 = WR + 5 * 65536;
    let n = pread(f.b, c.ptr(0), PAGE, off2);
    check(b"cache it", n == PAGE as i64, n)?;
    let r = rw2(f.d, a.ptr(0), PAGE, off2, RWF_NOWAIT, true);
    check(b"cached write", r == EAGAIN, r)?;
    restore(f, off, 2 * 65536)?;
    // Nothing cached any more: a direct write goes ahead
    fill_pat(a.bytes(0, PAGE), off2);
    let r = rw2(f.d, a.ptr(0), PAGE, off2, RWF_NOWAIT, true);
    check(b"uncached write", r == PAGE as i64, r)?;
    // More than one bio's worth
    let big = Buf::new(4 * MIB)?;
    let r = rw2(f.d, big.ptr(0), 4 * MIB, 0, RWF_NOWAIT, false);
    check(b"large read", r == EAGAIN, r)?;
    // Buffered
    let r = rw2(f.b, a.ptr(0), PAGE, off2, RWF_NOWAIT, true);
    check(b"buffered write", r == EOPNOTSUPP, r)?;
    let n = pread(f.b, c.ptr(0), PAGE, 3 * MIB);
    check(b"cache read", n == PAGE as i64, n)?;
    let r = rw2(f.b, c.ptr(0), PAGE, 3 * MIB, RWF_NOWAIT, false);
    check(b"buffered cached read", r == PAGE as i64, r)?;
    is_pat(b"buffered cached data", c.bytes(0, PAGE), 3 * MIB)?;
    let r = rw2(f.b, c.ptr(0), PAGE, 6 * MIB + MIB / 2, RWF_NOWAIT, false);
    check(b"buffered uncached read", r == EAGAIN, r)
}

/// Direct I/O over many bios: 1 MiB and 3 MiB reads, a 1.5 MiB write
/// read back
fn large(f: &Fds) -> R {
    let a = Buf::new(3 * MIB)?;
    let n = pread(f.d, a.ptr(0), MIB, RD);
    check(b"1M read", n == MIB as i64, n)?;
    is_pat(b"1M data", a.bytes(0, MIB), RD)?;
    let n = pread(f.d, a.ptr(0), 3 * MIB, 3 * MIB);
    check(b"3M read", n == 3 * MIB as i64, n)?;
    is_pat(b"3M data", a.bytes(0, 3 * MIB), 3 * MIB)?;
    let len = 3 * MIB / 2;
    fill_data(a.bytes(0, len), 0x1f);
    let w = pwrite(f.d, a.ptr(0), len, WR);
    check(b"write", w == len as i64, w)?;
    let c = Buf::new(len)?;
    let n = pread(f.d, c.ptr(0), len, WR);
    check(b"read back", n == len as i64, n)?;
    same(b"data back", c.bytes(0, len), a.bytes(0, len))?;
    restore(f, WR, len)
}

/// The written range holds the pattern again, read through the cache
fn restored(f: &Fds) -> R {
    let a = Buf::new(2 * MIB)?;
    let n = pread(f.b, a.ptr(0), 2 * MIB, WR);
    check(b"read", n == 2 * MIB as i64, n)?;
    is_pat(b"pattern", a.bytes(0, 2 * MIB), WR)
}

/// O_DSYNC and RWF_DSYNC direct writes, read back from the whole disk
/// (whose cache is not vda3's) directly
fn dsync(p3: &BlkDev, f: &Fds) -> R {
    let (Some(vda), Some(start)) = (find_blkdev(b"vd", 131072), p3_start()) else {
        return check(b"no vda", false, 0);
    };
    let ds = open(p3, O_RDWR | O_DIRECT | O_DSYNC);
    let disk = open(&vda, O_RDONLY | O_DIRECT);
    let r = sync_writes(f, ds, disk, start as u64 * 512);
    sys_close(ds as u64);
    sys_close(disk as u64);
    r?;
    restore(f, WR + 6 * 65536, 2 * PAGE)
}

fn sync_writes(f: &Fds, ds: i32, disk: i32, base: u64) -> R {
    check(b"open", ds >= 0 && disk >= 0, i64::from(ds.min(disk)))?;
    let off = WR + 6 * 65536;
    let a = Buf::new(2 * PAGE)?;
    fill_data(a.bytes(0, 2 * PAGE), 0x6d);
    let w = pwrite(ds, a.ptr(0), PAGE, off);
    check(b"O_DSYNC", w == PAGE as i64, w)?;
    let r = rw2(f.d, a.ptr(PAGE), PAGE, off + PAGE, RWF_DSYNC, true);
    check(b"RWF_DSYNC", r == PAGE as i64, r)?;
    let c = Buf::new(2 * PAGE)?;
    let n = pread(disk, c.ptr(0), 2 * PAGE, base + off);
    check(b"disk read", n == 2 * PAGE as i64, n)?;
    same(b"on disk", c.bytes(0, 2 * PAGE), a.bytes(0, 2 * PAGE))
}

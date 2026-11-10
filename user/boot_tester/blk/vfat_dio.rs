//! vfat O_DIRECT (Linux fat_direct_IO over __blockdev_direct_IO with
//! DIO_LOCKING) on vda1 (512-byte clusters): position, length and
//! memory in whole logical blocks (EINVAL), except a write past the
//! initialized bytes (mmu_private), which goes through the page cache
//! whole and so succeeds unaligned; a read at or past the end is 0
//! (before any alignment check), one across it is cut at the size.
//! Direct I/O bypasses the file's page cache: a direct write is on the
//! disk at return, a direct read sees the disk even with stale pages
//! cached, and both stay coherent with buffered I/O (written back
//! before, dropped after). A fragmented file maps cluster by cluster.
//!
//! The file data is found on the raw partition by tags: every 512-byte
//! unit starts with "HKD6TAG", a kind byte and its index.

use crate::harness::{R, check, report_r};
use crate::helpers::{BlkDev, find_blkdev};
use hk_syscall::{
    MAP_ANONYMOUS, MAP_PRIVATE, O_CREAT, O_RDWR, O_TRUNC, PROT_READ, PROT_WRITE, Stat, sys_close,
    sys_fallocate, sys_fstat, sys_fsync, sys_ftruncate, sys_mkdir, sys_mmap, sys_mount, sys_munmap,
    sys_open, sys_pread64, sys_pwrite64, sys_rmdir, sys_umount2, sys_unlink,
};

const O_DIRECT: u32 = hk_syscall::O_DIRECT;
const EINVAL: i64 = -22;
const MNT: &[u8] = b"/tmp/vfat_dio\0";
const UNIT: usize = 512;
const MIB: usize = 1 << 20;
/// vda1's size
const PART: usize = 32 * MIB;

pub fn run_tests() {
    let Some(p1) = find_blkdev(b"vd", 32768) else {
        report_r(b"VFAT_DIO", check(b"no vda1", false, 0));
        return;
    };
    let mut p = [0u8; 48];
    sys_mkdir(MNT.as_ptr(), 0o755);
    let m = sys_mount(
        p1.path(&mut p).as_ptr(),
        MNT.as_ptr(),
        b"vfat\0".as_ptr(),
        0,
        b"iocharset=cp437\0".as_ptr() as u64,
    );
    if m != 0 {
        report_r(b"VFAT_DIO", check(b"mount", false, m));
        return;
    }
    report_r(b"VFAT_DIO_ALIGN", align());
    report_r(b"VFAT_DIO_EOF", eof());
    report_r(b"VFAT_DIO_WRITE_DISK", write_disk(&p1));
    report_r(b"VFAT_DIO_READ_DISK", read_disk(&p1));
    report_r(b"VFAT_DIO_FRAG", frag(&p1));
    report_r(b"VFAT_DIO_EOF_TAIL", eof_tail());
    report_r(b"VFAT_WRITE_SHORT", write_short());
    sys_umount2(MNT.as_ptr(), 0);
    sys_rmdir(MNT.as_ptr());
}

/// Anonymous memory (page aligned), unmapped when dropped
struct Buf {
    at: u64,
    len: usize,
}

impl Buf {
    fn new(len: usize) -> Result<Self, (&'static [u8], i64)> {
        let p = sys_mmap(
            0,
            len as u64,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );
        check(b"mmap", p > 0, p)?;
        Ok(Self { at: p as u64, len })
    }

    fn ptr(&self, off: usize) -> *mut u8 {
        (self.at + off as u64) as *mut u8
    }

    fn bytes(&self, off: usize, n: usize) -> &mut [u8] {
        // SAFETY: inside the mapping, which lives as long as `self`
        unsafe { core::slice::from_raw_parts_mut(self.ptr(off), n) }
    }
}

impl Drop for Buf {
    fn drop(&mut self) {
        sys_munmap(self.at, self.len as u64);
    }
}

/// /tmp/vfat_dio/<name>
fn path(name: &[u8], out: &mut [u8; 64]) -> *const u8 {
    let n = MNT.len() - 1;
    out[..n].copy_from_slice(&MNT[..n]);
    out[n] = b'/';
    out[n + 1..n + 1 + name.len()].copy_from_slice(name);
    out[n + 1 + name.len()] = 0;
    out.as_ptr()
}

fn open(name: &[u8], flags: u32) -> i32 {
    let mut p = [0u8; 64];
    sys_open(path(name, &mut p), flags, 0o644) as i32
}

/// Fill one unit with its tag and contents of its own
fn tag(u: &mut [u8], kind: u8, idx: u32) {
    for (i, b) in u.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(13) ^ kind ^ (idx as u8).wrapping_mul(7) ^ (idx >> 8) as u8;
    }
    u[..7].copy_from_slice(b"HKD6TAG");
    u[7] = kind;
    u[8..12].copy_from_slice(&idx.to_le_bytes());
}

/// Tag units `first..` of `b` with `kind`
fn tag_all(b: &mut [u8], kind: u8, first: u32) {
    for (i, u) in b.chunks_mut(UNIT).enumerate() {
        tag(u, kind, first + i as u32);
    }
}

/// `b` holds units `first..` of `kind`
fn tagged(b: &[u8], kind: u8, first: u32) -> bool {
    let mut u = [0u8; UNIT];
    b.chunks(UNIT).enumerate().all(|(i, c)| {
        tag(&mut u, kind, first + i as u32);
        c == &u[..c.len()]
    })
}

/// A new file `name` of `data`, written through the cache and fsynced
fn put(name: &[u8], data: &[u8]) -> R {
    let fd = open(name, O_RDWR | O_CREAT | O_TRUNC);
    check(b"create", fd >= 0, fd as i64)?;
    let w = sys_pwrite64(fd, data.as_ptr(), data.len() as u64, 0);
    let s = sys_fsync(fd);
    sys_close(fd as u64);
    check(b"put write", w == data.len() as i64, w)?;
    check(b"put fsync", s == 0, s)
}

fn size_of(fd: i32) -> i64 {
    let mut st = Stat::default();
    sys_fstat(fd, &mut st);
    st.st_size
}

/// Where on vda1 the units of `kind` are, read with O_DIRECT through
/// `buf` (1 MiB): out[i] = the byte offset of unit i, -1 if not found
fn scan(p1: &BlkDev, buf: &Buf, kind: u8, out: &mut [i64]) -> R {
    out.fill(-1);
    let mut p = [0u8; 48];
    let fd = sys_open(p1.path(&mut p).as_ptr(), O_RDWR | O_DIRECT, 0) as i32;
    check(b"open vda1", fd >= 0, fd as i64)?;
    let mut off = 0;
    while off < PART {
        let n = sys_pread64(fd, buf.ptr(0), MIB as u64, off as i64);
        if n != MIB as i64 {
            sys_close(fd as u64);
            return check(b"scan read", false, n);
        }
        for (k, u) in buf.bytes(0, MIB).chunks(UNIT).enumerate() {
            if &u[..7] == b"HKD6TAG" && u[7] == kind {
                let i = u32::from_le_bytes([u[8], u[9], u[10], u[11]]) as usize;
                if let Some(o) = out.get_mut(i) {
                    *o = (off + k * UNIT) as i64;
                }
            }
        }
        off += MIB;
    }
    sys_close(fd as u64);
    Ok(())
}

/// Overwrite the unit at byte `off` of vda1 with unit `idx` of `kind`,
/// straight to the disk
fn poke(p1: &BlkDev, buf: &Buf, off: i64, kind: u8, idx: u32) -> R {
    tag(buf.bytes(0, UNIT), kind, idx);
    let mut p = [0u8; 48];
    let fd = sys_open(p1.path(&mut p).as_ptr(), O_RDWR | O_DIRECT, 0) as i32;
    check(b"open vda1", fd >= 0, fd as i64)?;
    let w = sys_pwrite64(fd, buf.ptr(0), UNIT as u64, off);
    sys_close(fd as u64);
    check(b"poke", w == UNIT as i64, w)
}

/// Misaligned position, length or memory is EINVAL inside the file;
/// a write past the initialized bytes goes through the cache (any
/// alignment) and is read back; at or past the end a read is 0 first
fn align() -> R {
    let b = Buf::new(4 * 4096)?;
    tag_all(b.bytes(0, 8192), b'A', 0);
    put(b"ALIGN.BIN", b.bytes(0, 8192))?;
    let fd = open(b"ALIGN.BIN", O_RDWR | O_DIRECT);
    check(b"open", fd >= 0, fd as i64)?;
    let r = align_fd(fd, &b);
    sys_close(fd as u64);
    sys_unlink(path(b"ALIGN.BIN", &mut [0; 64]));
    r
}

fn align_fd(fd: i32, b: &Buf) -> R {
    let (p, q) = (b.ptr(0), b.ptr(1));
    for (what, r) in [
        (&b"write pos"[..], sys_pwrite64(fd, p, 512, 100)),
        (b"write len", sys_pwrite64(fd, p, 100, 0)),
        (b"write mem", sys_pwrite64(fd, q, 512, 0)),
        (b"read pos", sys_pread64(fd, p, 512, 100)),
        (b"read len", sys_pread64(fd, p, 100, 0)),
        (b"read mem", sys_pread64(fd, q, 512, 0)),
    ] {
        check(what, r == EINVAL, r)?;
    }
    let r = sys_pread64(fd, q, 100, 8192);
    check(b"read at end", r == 0, r)?;
    let r = sys_pread64(fd, q, 100, 20000);
    check(b"read past end", r == 0, r)?;
    // Past the end, misaligned: through the cache
    tag(b.bytes(8192, UNIT), b'B', 0);
    let w = sys_pwrite64(fd, b.ptr(8193), 100, 8192);
    check(b"extend unaligned", w == 100, w)?;
    check(b"size", size_of(fd) == 8292, size_of(fd))?;
    // Inside the block that write initialized (Linux mmu_private is its
    // end): direct, so EINVAL misaligned; that drops mmu_private back
    // to the size, and the same write then goes through the cache
    let w = sys_pwrite64(fd, b.ptr(8193), 512, 8192);
    check(b"in last block", w == EINVAL, w)?;
    let w = sys_pwrite64(fd, b.ptr(8193), 512, 8192);
    check(b"past size again", w == 512, w)?;
    check(b"size 2", size_of(fd) == 8704, size_of(fd))?;
    // Aligned, past the end
    tag_all(b.bytes(4096, 4096), b'C', 0);
    let w = sys_pwrite64(fd, b.ptr(4096), 4096, 8704);
    check(b"extend aligned", w == 4096, w)?;
    // All of it read back through the cache
    let bf = open(b"ALIGN.BIN", O_RDWR);
    let back = Buf::new(4 * 4096)?;
    let n = sys_pread64(bf, back.ptr(0), 16384, 0);
    sys_close(bf as u64);
    check(b"read back", n == 12800, n)?;
    let got = back.bytes(0, 12800);
    check(b"old data", tagged(&got[..8192], b'A', 0), 0)?;
    check(
        b"unaligned data",
        got[8192..8704] == b.bytes(8193, 512)[..],
        1,
    )?;
    check(b"aligned data", tagged(&got[8704..], b'C', 0), 2)
}

/// At or past the end a read is 0; across it, cut at the size (the
/// last block read whole); misaligned across it: EINVAL
fn eof() -> R {
    let b = Buf::new(8192)?;
    tag_all(b.bytes(0, 1024), b'E', 0);
    put(b"EOF.BIN", b.bytes(0, 1000))?;
    let fd = open(b"EOF.BIN", O_RDWR | O_DIRECT);
    check(b"open", fd >= 0, fd as i64)?;
    let r = (|| {
        let got = Buf::new(8192)?;
        let n = sys_pread64(fd, got.ptr(0), 4096, 0);
        check(b"from 0", n == 1000, n)?;
        check(b"data", got.bytes(0, 1000) == b.bytes(0, 1000), 0)?;
        let n = sys_pread64(fd, got.ptr(0), 1024, 512);
        check(b"from 512", n == 488, n)?;
        check(b"data 512", got.bytes(0, 488) == b.bytes(512, 488), 1)?;
        for at in [1024, 1536, 4096] {
            let n = sys_pread64(fd, got.ptr(0), 512, at);
            check(b"past end", n == 0, n)?;
        }
        let n = sys_pread64(fd, got.ptr(1), 1024, 0);
        check(b"misaligned across", n == EINVAL, n)
    })();
    sys_close(fd as u64);
    sys_unlink(path(b"EOF.BIN", &mut [0; 64]));
    r
}

/// A direct write inside the file is on the disk when it returns, and
/// a buffered reader with the old pages cached sees it
fn write_disk(p1: &BlkDev) -> R {
    const N: usize = 16;
    let b = Buf::new(MIB)?;
    tag_all(b.bytes(0, N * UNIT), b'V', 0);
    put(b"WDISK.BIN", b.bytes(0, N * UNIT))?;
    let bf = open(b"WDISK.BIN", O_RDWR);
    let df = open(b"WDISK.BIN", O_RDWR | O_DIRECT);
    let r = (|| {
        check(b"open", bf >= 0 && df >= 0, bf.min(df) as i64)?;
        let got = Buf::new(N * UNIT)?;
        let n = sys_pread64(bf, got.ptr(0), (N * UNIT) as u64, 0);
        check(b"cache it", n == (N * UNIT) as i64, n)?;
        tag_all(b.bytes(0, N * UNIT), b'W', 0);
        let w = sys_pwrite64(df, b.ptr(0), (N * UNIT) as u64, 0);
        check(b"direct write", w == (N * UNIT) as i64, w)?;
        let mut at = [0i64; N];
        scan(p1, &b, b'W', &mut at)?;
        let missing = at.iter().filter(|&&o| o < 0).count();
        check(b"on disk", missing == 0, missing as i64)?;
        let n = sys_pread64(bf, got.ptr(0), (N * UNIT) as u64, 0);
        check(b"buffered", n == (N * UNIT) as i64, n)?;
        check(b"buffered data", tagged(got.bytes(0, N * UNIT), b'W', 0), 0)
    })();
    sys_close(bf as u64);
    sys_close(df as u64);
    sys_unlink(path(b"WDISK.BIN", &mut [0; 64]));
    r
}

/// A direct read of a file larger than one bio's pages sees the disk,
/// not the stale pages cached over it, and sees a buffered write not
/// yet written back
fn read_disk(p1: &BlkDev) -> R {
    const N: usize = 3072;
    const LEN: usize = N * UNIT;
    let b = Buf::new(2 * MIB)?;
    tag_all(b.bytes(0, LEN), b'R', 0);
    put(b"RDISK.BIN", b.bytes(0, LEN))?;
    let bf = open(b"RDISK.BIN", O_RDWR);
    let df = open(b"RDISK.BIN", O_RDWR | O_DIRECT);
    let r = (|| {
        check(b"open", bf >= 0 && df >= 0, bf.min(df) as i64)?;
        let n = sys_pread64(bf, b.ptr(0), LEN as u64, 0);
        check(b"cache it", n == LEN as i64, n)?;
        let offs = Buf::new(N * 8)?;
        // SAFETY: the mapping holds N i64s, page aligned
        let at = unsafe { core::slice::from_raw_parts_mut(offs.ptr(0) as *mut i64, N) };
        scan(p1, &b, b'R', at)?;
        let missing = at.iter().filter(|&&o| o < 0).count();
        check(b"found", missing == 0, missing as i64)?;
        poke(p1, &b, at[5], b'X', 5)?;
        poke(p1, &b, at[3000], b'X', 3000)?;
        // Buffered, not written back: the direct read writes it back
        // (another page than the units changed on disk: hk writes a
        // file page back whole, Linux only its dirty blocks)
        tag(b.bytes(0, UNIT), b'Y', 20);
        let w = sys_pwrite64(bf, b.ptr(0), UNIT as u64, 20 * UNIT as i64);
        check(b"buffered write", w == UNIT as i64, w)?;
        b.bytes(0, LEN).fill(0);
        let n = sys_pread64(df, b.ptr(0), LEN as u64, 0);
        check(b"direct read", n == LEN as i64, n)?;
        let got = b.bytes(0, LEN);
        for i in 0..N {
            let kind = match i {
                5 | 3000 => b'X',
                20 => b'Y',
                _ => b'R',
            };
            let u = &got[i * UNIT..(i + 1) * UNIT];
            check(b"unit", tagged(u, kind, i as u32), i as i64)?;
        }
        Ok(())
    })();
    sys_close(bf as u64);
    sys_close(df as u64);
    sys_unlink(path(b"RDISK.BIN", &mut [0; 64]));
    r
}

/// Two files grown a cluster at a time in turn leave one fragmented
/// once the other goes: direct reads map it cluster by cluster, from
/// the start and from the middle, and see a cluster changed on disk
fn frag(p1: &BlkDev) -> R {
    const N: usize = 64;
    let b = Buf::new(MIB)?;
    let fa = open(b"FRAGA.BIN", O_RDWR | O_CREAT | O_TRUNC);
    let fb = open(b"FRAGB.BIN", O_RDWR | O_CREAT | O_TRUNC);
    check(b"create", fa >= 0 && fb >= 0, fa.min(fb) as i64)?;
    let mut ok = true;
    for i in 0..N {
        tag(b.bytes(0, UNIT), b'F', i as u32);
        tag(b.bytes(UNIT, UNIT), b'G', i as u32);
        let at = (i * UNIT) as i64;
        ok &= sys_pwrite64(fa, b.ptr(0), UNIT as u64, at) == UNIT as i64;
        ok &= sys_pwrite64(fb, b.ptr(UNIT), UNIT as u64, at) == UNIT as i64;
    }
    ok &= sys_fsync(fa) == 0 && sys_fsync(fb) == 0;
    sys_close(fa as u64);
    sys_close(fb as u64);
    sys_unlink(path(b"FRAGB.BIN", &mut [0; 64]));
    let r = (|| {
        check(b"grow", ok, 0)?;
        let mut at = [0i64; N];
        scan(p1, &b, b'F', &mut at)?;
        let missing = at.iter().filter(|&&o| o < 0).count();
        check(b"found", missing == 0, missing as i64)?;
        let breaks = at.windows(2).filter(|w| w[1] != w[0] + UNIT as i64).count();
        check(b"fragmented", breaks >= N / 2, breaks as i64)?;
        let bf = open(b"FRAGA.BIN", O_RDWR);
        let n = sys_pread64(bf, b.ptr(0), (N * UNIT) as u64, 0);
        sys_close(bf as u64);
        check(b"cache it", n == (N * UNIT) as i64, n)?;
        poke(p1, &b, at[9], b'Z', 9)?;
        let df = open(b"FRAGA.BIN", O_RDWR | O_DIRECT);
        check(b"open", df >= 0, df as i64)?;
        b.bytes(0, N * UNIT).fill(0);
        let n = sys_pread64(df, b.ptr(0), (N * UNIT) as u64, 0);
        let m = sys_pread64(df, b.ptr(N * UNIT), 4096, 7 * UNIT as i64);
        sys_close(df as u64);
        check(b"direct read", n == (N * UNIT) as i64, n)?;
        check(b"from the middle", m == 4096, m)?;
        let got = b.bytes(0, N * UNIT + 4096);
        for i in 0..N {
            let kind = if i == 9 { b'Z' } else { b'F' };
            check(
                b"unit",
                tagged(&got[i * UNIT..(i + 1) * UNIT], kind, i as u32),
                i as i64,
            )?;
        }
        let mid = &got[N * UNIT..];
        check(b"middle 7", tagged(&mid[..1024], b'F', 7), 7)?;
        check(b"middle 9", tagged(&mid[1024..1536], b'Z', 9), 9)?;
        check(b"middle 10", tagged(&mid[1536..], b'F', 10), 10)
    })();
    sys_unlink(path(b"FRAGA.BIN", &mut [0; 64]));
    r
}

/// The block holding the end of a file is written back whole, zeroed
/// past the size (Linux block_write_full_folio): a direct read across
/// the end, which reads that block from the disk, finds zeros past the
/// size, not what a truncate left there
fn eof_tail() -> R {
    let b = Buf::new(8192)?;
    b.bytes(0, 2048).fill(b'X');
    put(b"TAIL.BIN", b.bytes(0, 2048))?;
    let fd = open(b"TAIL.BIN", O_RDWR);
    check(b"open", fd >= 0, fd as i64)?;
    // The last block keeps its cluster and the old bytes past 1100
    let t = sys_ftruncate(fd, 1100);
    b.bytes(0, 50).fill(b'Y');
    let w = sys_pwrite64(fd, b.ptr(0), 50, 1050);
    sys_close(fd as u64);
    let r = (|| {
        check(b"truncate", t == 0, t)?;
        check(b"write", w == 50, w)?;
        let df = open(b"TAIL.BIN", O_RDWR | O_DIRECT);
        check(b"open direct", df >= 0, df as i64)?;
        b.bytes(0, 4096).fill(0xEE);
        let n = sys_pread64(df, b.ptr(0), 1536, 0);
        sys_close(df as u64);
        check(b"read", n == 1100, n)?;
        let got = b.bytes(0, 1536);
        check(b"data", got[..1050].iter().all(|&c| c == b'X'), 0)?;
        check(b"written", got[1050..1100].iter().all(|&c| c == b'Y'), 1)?;
        let bad = got[1100..].iter().position(|&c| c != 0);
        check(
            b"tail zero",
            bad.is_none(),
            bad.map_or(0, |i| i as i64 + 1100),
        )
    })();
    sys_unlink(path(b"TAIL.BIN", &mut [0; 64]));
    r
}

/// A write that faults partway inside the file keeps the clusters
/// fallocate gave past the end (Linux fat_write_failed acts only for a
/// write past the size)
fn write_short() -> R {
    const KEEP_SIZE: i32 = 1;
    let b = Buf::new(2 * 4096)?;
    b.bytes(0, 8192).fill(b'S');
    put(b"SHORT.BIN", b.bytes(0, 8192))?;
    let fd = open(b"SHORT.BIN", O_RDWR);
    check(b"open", fd >= 0, fd as i64)?;
    let blocks = |fd| {
        let mut st = Stat::default();
        sys_fstat(fd, &mut st);
        (st.st_blocks, st.st_size)
    };
    let f = sys_fallocate(fd, KEEP_SIZE, 0, 65536);
    let before = blocks(fd);
    // The second page of the source is gone: the write stops there
    sys_munmap(b.at + 4096, 4096);
    let w = sys_pwrite64(fd, b.ptr(0), 8192, 0);
    let after = blocks(fd);
    sys_close(fd as u64);
    sys_unlink(path(b"SHORT.BIN", &mut [0; 64]));
    check(b"fallocate", f == 0, f)?;
    check(b"blocks before", before == (128, 8192), before.0)?;
    check(b"short write", w == 4096, w)?;
    check(b"size", after.1 == 8192, after.1)?;
    check(b"blocks kept", after.0 == 128, after.0)
}

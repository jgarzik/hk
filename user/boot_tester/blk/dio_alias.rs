//! O_DIRECT I/O whose buffer maps the very device range it reads or
//! writes (a MAP_SHARED mmap of vda3): the pinned buffer pages are the
//! device's page-cache pages, so source and destination may be the same
//! memory, whole or overlapping. The data stays right: a read leaves the
//! mapping holding what the device has at the offsets read, a write
//! stores what the mapping held.

use crate::harness::{R, check, report_r};
use crate::helpers::find_blkdev;
use hk_syscall::{
    MAP_ANONYMOUS, MAP_PRIVATE, MAP_SHARED, O_RDWR, PROT_READ, PROT_WRITE, sys_close, sys_fsync,
    sys_mmap, sys_munmap, sys_open, sys_pread64, sys_pwrite64,
};

const O_DIRECT: u32 = hk_syscall::O_DIRECT;
const LEN: usize = 8192;
/// A page-aligned stretch of vda3's untouched first 8 MiB
const X: u64 = (7 << 20) + (512 << 10);

pub fn run_tests() {
    report_r(b"DIO_ALIAS", alias());
}

/// Pattern byte of vda3 at `off` (tools/mkdisk.sh)
fn pat(off: u64) -> u8 {
    let w = ((off / 4) as u32)
        .wrapping_mul(1103515245)
        .wrapping_add(12345);
    w.to_le_bytes()[(off % 4) as usize]
}

/// The first byte of the mapping's [at, at + n) that is not the pattern
/// of the device at `dev`.., as an error code
fn same(m: u64, at: usize, n: usize, dev: u64) -> Result<(), i64> {
    for i in 0..n {
        // SAFETY: inside the mapping
        let b = unsafe { core::ptr::read_volatile((m + (at + i) as u64) as *const u8) };
        if b != pat(dev + i as u64) {
            return Err(i as i64);
        }
    }
    Ok(())
}

fn alias() -> R {
    let Some(p3) = find_blkdev(b"vd", 16384) else {
        return check(b"no vda3", false, 0);
    };
    let mut p = [0u8; 48];
    let path = p3.path(&mut p);
    let dio = sys_open(path.as_ptr(), O_RDWR | O_DIRECT, 0);
    let buf = sys_open(path.as_ptr(), O_RDWR, 0);
    check(b"open", dio >= 0 && buf >= 0, dio.min(buf))?;
    let m = sys_mmap(
        0,
        LEN as u64,
        PROT_READ | PROT_WRITE,
        MAP_SHARED,
        buf as i32,
        X,
    );
    let r = if m < 0 {
        check(b"mmap", false, m)
    } else {
        aliased(dio as i32, m as u64)
    };
    if m >= 0 {
        sys_munmap(m as u64, LEN as u64);
    }
    // Put the pattern back through the cache, and on the disk
    let mut pg = [0u8; LEN];
    for (i, b) in pg.iter_mut().enumerate() {
        *b = pat(X + i as u64);
    }
    let w = sys_pwrite64(buf as i32, pg.as_ptr(), LEN as u64, X as i64);
    let f = sys_fsync(buf as i32);
    sys_close(dio as u64);
    sys_close(buf as u64);
    r?;
    check(b"restore", w == LEN as i64 && f == 0, w)
}

fn aliased(dio: i32, m: u64) -> R {
    // Read the range into its own mapping: the same bytes
    let n = sys_pread64(dio, m as *mut u8, LEN as u64, X as i64);
    check(b"read same", n == LEN as i64, n)?;
    same(m, 0, LEN, X).map_err(|i| (&b"data same"[..], i))?;
    // Read 1 KiB at X + 512 into the mapping's start: overlapping bytes
    // of one page
    let n = sys_pread64(dio, m as *mut u8, 1024, X as i64 + 512);
    check(b"read overlap", n == 1024, n)?;
    same(m, 0, 1024, X + 512).map_err(|i| (&b"data overlap"[..], i))?;
    // Write the mapping's start back where it came from: overlapping again
    let n = sys_pwrite64(dio, m as *const u8, 1024, X as i64 + 512);
    check(b"write overlap", n == 1024, n)?;
    // Into a buffer of its own (O_DIRECT memory alignment)
    let a = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    check(b"mmap anon", a >= 0, a)?;
    let r = sys_pread64(dio, a as *mut u8, 1024, X as i64 + 512);
    let ok = same(a as u64, 0, 1024, X + 512);
    sys_munmap(a as u64, 4096);
    check(b"read back", r == 1024, r)?;
    ok.map_err(|i| (&b"data back"[..], i))?;
    // And the second page written from its own mapping
    let n = sys_pwrite64(dio, (m + 4096) as *const u8, 4096, X as i64 + 4096);
    check(b"write same", n == 4096, n)?;
    same(m, 4096, 4096, X + 4096).map_err(|i| (&b"data write same"[..], i))
}

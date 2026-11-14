//! O_DIRECT reads into the caller's own stack (Linux
//! iov_iter_extract_pages / pin_user_pages_fast on the stack VMA): the
//! device writes exactly the buffer's bytes, in the pages the stack maps
//! there, whether the page was touched, never faulted in (zapped by
//! MADV_DONTNEED) or mapped read-only to the zero page. The bytes
//! around the buffer, the caller's frame and the return path stay
//! intact. Run on the USB mass-storage disk (sda: a bio driver that
//! copies through the direct map) and on virtio-blk (vda3: DMA).

use crate::harness::{R, check, report_r};
use crate::helpers::{BlkDev, find_blkdev, host_mode, skip};
use hk_syscall::{
    MAP_ANONYMOUS, MAP_PRIVATE, O_DIRECT, O_RDONLY, PROT_READ, PROT_WRITE, sys_close, sys_madvise,
    sys_mincore, sys_mmap, sys_munmap, sys_open, sys_pread64,
};

const PAGE: usize = 4096;
/// Bytes read: four pages, each its own bio segment
const LEN: usize = 4 * PAGE;
const CANARY: u8 = 0xc3;
const FILL: u8 = 0x5a;
const MADV_DONTNEED: i32 = 4;
/// What `frame_read` returns when its own frame survived
const MAGIC: u64 = 0x5eed_f00d_cafe_b0b0;

/// The stack page states a read lands in
#[derive(Clone, Copy, PartialEq)]
enum Page {
    /// Written before the read
    Touched,
    /// Zapped: no entry until the pin faults it in
    Unfaulted,
    /// Zapped, then read: the zero page, read-only
    Zero,
}

pub fn run_tests() {
    match find_blkdev(b"sd", 0) {
        Some(d) => report_r(b"DIO_STACK_USB", dev(&d, 0)),
        // Real Linux boots with the virtio disk only
        None if host_mode() => skip(b"DIO_STACK_USB", b"no USB disk"),
        None => report_r(b"DIO_STACK_USB", check(b"no sda", false, 0)),
    }
    match find_blkdev(b"vd", 16384) {
        // vda3's untouched pattern region
        Some(d) => report_r(b"DIO_STACK_VIRTIO", dev(&d, 3 << 20)),
        None => report_r(b"DIO_STACK_VIRTIO", check(b"no vda3", false, 0)),
    }
}

/// Every page state on `d` at byte `off`, checked against a buffered
/// read of the same bytes
fn dev(d: &BlkDev, off: i64) -> R {
    let mut p = [0u8; 48];
    let path = d.path(&mut p);
    let want = sys_mmap(
        0,
        LEN as u64,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    check(b"mmap", want > 0, want)?;
    let r = with_want(path, off, want as *mut u8);
    sys_munmap(want as u64, LEN as u64);
    r
}

fn with_want(path: &[u8], off: i64, want: *mut u8) -> R {
    let b = sys_open(path.as_ptr(), O_RDONLY, 0);
    check(b"open buffered", b >= 0, b)?;
    let n = sys_pread64(b as i32, want, LEN as u64, off);
    sys_close(b as u64);
    check(b"buffered read", n == LEN as i64, n)?;
    // SAFETY: the mapping holds LEN bytes and lives across the call
    let want = unsafe { core::slice::from_raw_parts(want, LEN) };
    let fd = sys_open(path.as_ptr(), O_RDONLY | O_DIRECT, 0);
    check(b"open direct", fd >= 0, fd)?;
    let mut r = Ok(());
    for p in [Page::Touched, Page::Unfaulted, Page::Zero] {
        r = caller(fd as i32, off, want, p);
        if r.is_err() {
            break;
        }
    }
    sys_close(fd as u64);
    r
}

/// The caller's frame: a sentinel kept across the read, and the return
/// value of the frame that did it
#[inline(never)]
fn caller(fd: i32, off: i64, want: &[u8], p: Page) -> R {
    let mut guard = [0u8; 256];
    fill(&mut guard, CANARY);
    let got = frame_read(fd, off, want, p);
    check(b"caller frame", intact(&guard, CANARY), p as i64)?;
    let (r, magic) = got;
    check(b"return value", magic == MAGIC, p as i64)?;
    r
}

/// The buffer on this frame, a canary page either side
#[repr(C, align(4096))]
struct Frame {
    lo: [u8; PAGE],
    buf: [u8; LEN],
    hi: [u8; PAGE],
}

/// Read into a buffer on this frame in page state `p`; the result and
/// MAGIC from a local that must survive the read
#[inline(never)]
fn frame_read(fd: i32, off: i64, want: &[u8], p: Page) -> (R, u64) {
    let mut f = Frame {
        lo: [0; PAGE],
        buf: [0; LEN],
        hi: [0; PAGE],
    };
    let magic = core::hint::black_box(MAGIC);
    fill(&mut f.lo, CANARY);
    fill(&mut f.hi, CANARY);
    fill(&mut f.buf, FILL);
    let r = read_into(fd, off, want, &mut f, p);
    (r, core::hint::black_box(magic))
}

fn read_into(fd: i32, off: i64, want: &[u8], f: &mut Frame, p: Page) -> R {
    let buf = f.buf.as_mut_ptr();
    if p != Page::Touched {
        let m = sys_madvise(buf as u64, LEN as u64, MADV_DONTNEED);
        check(b"madvise", m == 0, m)?;
        let mut v = [0u8; LEN / PAGE];
        let m = sys_mincore(buf as u64, LEN as u64, v.as_mut_ptr());
        check(b"mincore", m == 0, m)?;
        check(b"zapped", v.iter().all(|&b| b & 1 == 0), i64::from(v[0]))?;
    }
    if p == Page::Zero {
        for i in (0..LEN).step_by(PAGE) {
            // SAFETY: inside the buffer
            let b = unsafe { core::ptr::read_volatile(buf.add(i)) };
            check(b"zero page", b == 0, i64::from(b))?;
        }
    }
    let n = sys_pread64(fd, buf, LEN as u64, off);
    check(b"direct read", n == LEN as i64, n)?;
    check(b"canary below", intact(&f.lo, CANARY), p as i64)?;
    check(b"canary above", intact(&f.hi, CANARY), p as i64)?;
    let bad = (0..LEN).find(|&i| {
        // SAFETY: inside the buffer
        unsafe { core::ptr::read_volatile(buf.add(i)) != want[i] }
    });
    check(b"data", bad.is_none(), bad.map_or(0, |i| i as i64))
}

fn fill(b: &mut [u8], v: u8) {
    for x in b.iter_mut() {
        // SAFETY: a byte of `b`; volatile so the fill is not elided
        unsafe { core::ptr::write_volatile(x, v) };
    }
}

fn intact(b: &[u8], v: u8) -> bool {
    b.iter().all(|x| {
        // SAFETY: a byte of `b`; volatile: the device wrote behind the
        // compiler's back if anything did
        unsafe { core::ptr::read_volatile(x) == v }
    })
}

//! Pinned direct-I/O buffers (Linux mm/gup.c FOLL_PIN): O_DIRECT reads
//! of vda3 (its pattern words, tools/mkdisk.sh) into a buffer whose pages
//! another thread forks over, pages out or unmaps meanwhile. The read
//! lands in the reader's pages whatever happens: fork gives the child a
//! copy of a pinned page instead of sharing it copy-on-write (Linux
//! page_needs_cow_for_dma), so the parent's own writes into the same
//! pages during the I/O do not move it to another page; reclaim keeps a
//! pinned page; an unmapped one stays allocated until the read is done.

use core::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use crate::harness::{R, check, report_r};
use crate::helpers::{find_blkdev, swap_off, swap_on};
use crate::mm::fork_mm::{join, spawn_thread};
use hk_syscall::{
    IoVec, MAP_ANONYMOUS, MAP_FIXED, MAP_PRIVATE, O_RDONLY, PROT_READ, PROT_WRITE, sys_close,
    sys_exit, sys_fork, sys_madvise, sys_mmap, sys_munmap, sys_open, sys_preadv, sys_sched_yield,
    sys_wait4,
};

const O_DIRECT: u32 = hk_syscall::O_DIRECT;
const PAGE: usize = 4096;
const PAGES: usize = 16;
const LEN: usize = PAGES * PAGE;
/// Read into all but the last 512 bytes of each page: the rest is the
/// owner's to write during the I/O
const PART: usize = PAGE - 512;
const ROUNDS: u64 = 120;
const EFAULT: i64 = -14;
const MADV_PAGEOUT: i32 = 21;

pub fn run_tests() {
    let Some(p3) = find_blkdev(b"vd", 16384) else {
        report_r(b"DIO_PIN_FORK", check(b"no vda3", false, 0));
        return;
    };
    let mut p = [0u8; 48];
    let fd = sys_open(p3.path(&mut p).as_ptr(), O_RDONLY | O_DIRECT, 0);
    report_r(b"DIO_PIN_FORK", with_fd(fd, fork_race));
    report_r(b"DIO_PIN_RECLAIM", with_fd(fd, reclaim_race));
    report_r(b"DIO_PIN_MUNMAP", with_fd(fd, munmap_race));
    if fd >= 0 {
        sys_close(fd as u64);
    }
}

fn with_fd(fd: i64, f: fn(i32) -> R) -> R {
    check(b"open", fd >= 0, fd)?;
    f(fd as i32)
}

/// Pattern byte of vda3 at `off`
fn pat(off: u64) -> u8 {
    let w = ((off / 4) as u32)
        .wrapping_mul(1103515245)
        .wrapping_add(12345);
    w.to_le_bytes()[(off % 4) as usize]
}

/// The disk offset of round `k`: 512-aligned, in vda3's untouched first
/// 8 MiB
fn off_of(k: u64) -> u64 {
    (1 << 20) + (k * (PAGES * PART) as u64) % (6 << 20)
}

fn anon(len: usize) -> u64 {
    let p = sys_mmap(
        0,
        len as u64,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if p < 0 { 0 } else { p as u64 }
}

/// The iovecs of the pages of `buf`, `PART` bytes each
fn iovs(buf: u64) -> [IoVec; PAGES] {
    core::array::from_fn(|i| IoVec {
        iov_base: (buf + (i * PAGE) as u64) as *const u8,
        iov_len: PART,
    })
}

/// Index of the first byte of a round's read in `buf` that is not the
/// pattern
fn mismatch(buf: u64, off: u64) -> Option<usize> {
    (0..PAGES * PART).find(|&i| {
        let at = buf + ((i / PART) * PAGE + i % PART) as u64;
        // SAFETY: inside the buffer's mapping
        let b = unsafe { core::ptr::read_volatile(at as *const u8) };
        b != pat(off + i as u64)
    })
}

static FD: AtomicI64 = AtomicI64::new(-1);
static BUF: AtomicU64 = AtomicU64::new(0);
static DONE: AtomicU64 = AtomicU64::new(0);
/// Reader verdict: 0, or what went wrong (-errno, or round * 1000000 +
/// offset of the first wrong byte + 1)
static BAD: AtomicI64 = AtomicI64::new(0);
/// For the munmap race: reads may fail with EFAULT
static MAY_FAULT: AtomicU64 = AtomicU64::new(0);

#[repr(C, align(16))]
struct Stack([u8; 32768]);
static mut STACK: Stack = Stack([0; 32768]);
static mut CTID: u32 = 0;

/// The reader thread: ROUNDS O_DIRECT reads, each checked
extern "C" fn reader(_: u64) -> ! {
    let fd = FD.load(Ordering::Relaxed) as i32;
    for k in 0..ROUNDS {
        let buf = BUF.load(Ordering::Acquire);
        let off = off_of(k);
        let v = iovs(buf);
        let n = sys_preadv(fd, v.as_ptr(), PAGES as i32, off as i64);
        let faulted = MAY_FAULT.load(Ordering::Relaxed) != 0;
        // Unmapped under it: EFAULT, or as much as was read (Linux may
        // count part of a sector)
        if faulted && (n == EFAULT || (n > 0 && n <= (PAGES * PART) as i64)) {
            continue;
        }
        if n != (PAGES * PART) as i64 {
            BAD.store(if n < 0 { n } else { -1000 - n }, Ordering::Relaxed);
            break;
        }
        if !faulted && let Some(i) = mismatch(buf, off) {
            BAD.store((k as i64) * 1_000_000 + i as i64 + 1, Ordering::Relaxed);
            break;
        }
    }
    DONE.store(1, Ordering::Release);
    sys_exit(0)
}

/// Run the reader over `buf` while `step` runs in this thread until it
/// is done; the reader's verdict
fn race(fd: i32, buf: u64, may_fault: bool, step: &mut dyn FnMut(u64)) -> R {
    FD.store(i64::from(fd), Ordering::Relaxed);
    BUF.store(buf, Ordering::Release);
    BAD.store(0, Ordering::Relaxed);
    DONE.store(0, Ordering::Relaxed);
    MAY_FAULT.store(u64::from(may_fault), Ordering::Relaxed);
    let ctid = &raw mut CTID;
    // SAFETY: one reader at a time; it is joined before the next race
    let top = unsafe { (&raw mut STACK).cast::<u8>().add(32768) } as u64;
    // SAFETY: a stack and tid word no other thread uses
    let tid = unsafe {
        ctid.write_volatile(1);
        spawn_thread(top, reader, 0, ctid)
    };
    check(b"thread", tid > 0, tid)?;
    let mut i = 0u64;
    while DONE.load(Ordering::Acquire) == 0 {
        step(i);
        i += 1;
        sys_sched_yield();
    }
    check(b"join", join(ctid), 0)?;
    let bad = BAD.load(Ordering::Relaxed);
    check(b"read", bad == 0, bad)
}

/// Fork while the reader reads; the parent writes the pages' tails, a
/// child its own copy of everything
fn fork_race(fd: i32) -> R {
    let buf = anon(LEN);
    check(b"mmap", buf != 0, 0)?;
    // SAFETY: the fresh mapping
    unsafe { core::ptr::write_bytes(buf as *mut u8, 0, LEN) };
    let mut child_bad = 0i64;
    let r = race(fd, buf, false, &mut |i| {
        let pid = sys_fork();
        if pid == 0 {
            // SAFETY: the child's copy of the mapping
            unsafe { core::ptr::write_bytes(buf as *mut u8, 0x5a, LEN) };
            sys_exit(0);
        }
        for pg in 0..PAGES {
            let at = buf + (pg * PAGE + PART) as u64;
            // SAFETY: the page's tail, outside every read
            unsafe { core::ptr::write_volatile(at as *mut u64, i) };
        }
        let mut st = 0i32;
        if pid < 0 || sys_wait4(pid, &mut st, 0, 0) != pid || st != 0 {
            child_bad = if pid < 0 {
                pid
            } else {
                i64::from(st) | 1 << 32
            };
        }
    });
    sys_munmap(buf, LEN as u64);
    r?;
    check(b"child", child_bad == 0, child_bad)
}

/// Page the buffer out (MADV_PAGEOUT, swap on vda2) while the reader
/// reads into it
fn reclaim_race(fd: i32) -> R {
    let on = swap_on(b"/dev/vda2\0");
    check(b"swapon", on == 0, on)?;
    let buf = anon(LEN);
    let r = if buf == 0 {
        check(b"mmap", false, 0)
    } else {
        // SAFETY: the fresh mapping
        unsafe { core::ptr::write_bytes(buf as *mut u8, 0, LEN) };
        race(fd, buf, false, &mut |_| {
            sys_madvise(buf, LEN as u64, MADV_PAGEOUT);
        })
    };
    if buf != 0 {
        sys_munmap(buf, LEN as u64);
    }
    let off = swap_off(b"/dev/vda2\0");
    r?;
    check(b"swapoff", off == 0, off)
}

/// Unmap and map the buffer again while the reader reads into it: a read
/// fails with EFAULT or comes up short, and one after the race reads the
/// pattern
fn munmap_race(fd: i32) -> R {
    let buf = anon(LEN);
    check(b"mmap", buf != 0, 0)?;
    let r = race(fd, buf, true, &mut |_| {
        sys_munmap(buf, LEN as u64);
        sys_mmap(
            buf,
            LEN as u64,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
            -1,
            0,
        );
    });
    let v = iovs(buf);
    let n = sys_preadv(fd, v.as_ptr(), PAGES as i32, off_of(0) as i64);
    let bad = mismatch(buf, off_of(0));
    sys_munmap(buf, LEN as u64);
    r?;
    check(b"read after", n == (PAGES * PART) as i64, n)?;
    check(b"data after", bad.is_none(), bad.map_or(0, |i| i as i64))
}

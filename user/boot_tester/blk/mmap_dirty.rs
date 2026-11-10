//! Writes through a shared mapping of a block device reach the disk:
//! the page they land in is dirty, however the mapping got writable
//! (Linux tracks dirtying with write-protected PTEs: vma_wants_writenotify)
//! or the write got there. A page first mapped by a read is clean and
//! read-only; then a store after mprotect PROT_READ and back to
//! PROT_READ|PROT_WRITE, and a write by process_vm_writev (Linux
//! pins the page for writing, which faults and dirties it), must each
//! leave it dirty. A direct read of the range writes dirty pages
//! back first, so it shows whether the data got there. vda3's 9 MiB
//! region, put back after.

use crate::harness::{R, check, report_r};
use crate::helpers::{BlkDev, find_blkdev};
use hk_syscall::{
    IoVec, MAP_ANONYMOUS, MAP_PRIVATE, MAP_SHARED, O_RDWR, PROT_READ, PROT_WRITE, sys_close,
    sys_getpid, sys_mmap, sys_mprotect, sys_munmap, sys_open, sys_pread64, sys_process_vm_writev,
    sys_pwrite64,
};

const O_DIRECT: u32 = hk_syscall::O_DIRECT;
const PAGE: u64 = 4096;
/// Pages of vda3 these tests write (9 MiB + 448 KiB on), put back after
const OFF: u64 = (9 << 20) + 7 * 65536;

pub fn run_tests() {
    let Some(p3) = find_blkdev(b"vd", 16384) else {
        report_r(b"BLK_MMAP_DIRTY", check(b"no vda3", false, 0));
        return;
    };
    let b = open(&p3, O_RDWR);
    let d = open(&p3, O_RDWR | O_DIRECT);
    let cases: [(&[u8], fn(u64) -> R); 2] = [
        (b"BLK_MMAP_MPROTECT", mprotect_rw),
        (b"BLK_MMAP_PROCESS_VM", process_vm),
    ];
    for (i, (name, t)) in cases.into_iter().enumerate() {
        let off = OFF + i as u64 * PAGE;
        let r = if b < 0 || d < 0 {
            check(b"open", false, i64::from(b.min(d)))
        } else {
            mapped(b, d, off, t)
        };
        report_r(name, r);
    }
    sys_close(b as u64);
    sys_close(d as u64);
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

const MSG: &[u8; 8] = b"dirty!!!";

/// Map page `off` of vda3 shared and writable, fault it in by a read,
/// run `t` on it (which writes MSG at its start), unmap, then check
/// with a direct read that MSG reached the disk; the pattern goes back
fn mapped(b: i32, d: i32, off: u64, t: fn(u64) -> R) -> R {
    let m = sys_mmap(0, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, b, off);
    check(b"mmap", m > 0, m)?;
    let m = m as u64;
    // SAFETY: inside the mapping
    let first = unsafe { core::ptr::read_volatile(m as *const u8) };
    let r = t(m);
    sys_munmap(m, PAGE);
    check(b"read fault", first == pat(off), i64::from(first))?;
    r?;
    let buf = sys_mmap(
        0,
        PAGE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    check(b"buffer", buf > 0, buf)?;
    let p = buf as *mut u8;
    let n = sys_pread64(d, p, PAGE, off as i64);
    // SAFETY: the buffer's mapping
    let got = unsafe { core::slice::from_raw_parts_mut(p, PAGE as usize) };
    let (ok, first_got) = (got[..8] == *MSG, got[0]);
    for (i, x) in got.iter_mut().enumerate() {
        *x = pat(off + i as u64);
    }
    let w = sys_pwrite64(d, p, PAGE, off as i64);
    sys_munmap(buf as u64, PAGE);
    check(b"direct read", n == PAGE as i64, n)?;
    check(b"on disk", ok, i64::from(first_got))?;
    check(b"restore", w == PAGE as i64, w)
}

/// mprotect PROT_READ, then PROT_READ|PROT_WRITE, then a store
fn mprotect_rw(m: u64) -> R {
    let r = sys_mprotect(m, PAGE, PROT_READ);
    check(b"mprotect R", r == 0, r)?;
    let r = sys_mprotect(m, PAGE, PROT_READ | PROT_WRITE);
    check(b"mprotect RW", r == 0, r)?;
    for (i, &c) in MSG.iter().enumerate() {
        // SAFETY: inside the writable mapping
        unsafe { core::ptr::write_volatile((m + i as u64) as *mut u8, c) };
    }
    Ok(())
}

/// process_vm_writev into this very process
fn process_vm(m: u64) -> R {
    let local = IoVec {
        iov_base: MSG.as_ptr(),
        iov_len: 8,
    };
    let remote = IoVec {
        iov_base: m as *const u8,
        iov_len: 8,
    };
    let w = sys_process_vm_writev(sys_getpid() as i32, &local, 1, &remote, 1, 0);
    check(b"process_vm_writev", w == 8, w)
}

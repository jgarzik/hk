//! RWF_NOWAIT direct I/O to a driver that would block: EAGAIN, never a
//! wait (Linux REQ_NOWAIT, bio_wouldblock_error). hk's sd driver does
//! each request synchronously in the submitter (it stands in for a
//! blk-mq SCSI queue whose tags are all taken), so a NOWAIT direct read
//! of sda is EAGAIN, and the same read without RWF_NOWAIT returns the
//! data. Linux references have no sda (no USB disk): skipped there.

use crate::harness::{R, check, report_r};
use crate::helpers::{host_mode, skip};
use hk_syscall::{
    IoVec, MAP_ANONYMOUS, MAP_PRIVATE, O_RDONLY, PROT_READ, PROT_WRITE, sys_close, sys_mmap,
    sys_munmap, sys_open, sys_preadv2,
};

const O_DIRECT: u32 = hk_syscall::O_DIRECT;
const RWF_NOWAIT: i32 = 8;
const EAGAIN: i64 = -11;
const PAGE: u64 = 4096;

pub fn run_tests() {
    if host_mode() {
        skip(b"BLK_DIO_NOWAIT_SYNC", b"no USB disk (/dev/sda) on host");
        return;
    }
    report_r(b"BLK_DIO_NOWAIT_SYNC", nowait_sync());
}

fn nowait_sync() -> R {
    let fd = sys_open(b"/dev/sda\0".as_ptr(), O_RDONLY | O_DIRECT, 0);
    check(b"open sda", fd >= 0, fd)?;
    let buf = sys_mmap(
        0,
        PAGE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    let r = if buf <= 0 {
        check(b"mmap", false, buf)
    } else {
        reads(fd as i32, buf as u64)
    };
    if buf > 0 {
        sys_munmap(buf as u64, PAGE);
    }
    sys_close(fd as u64);
    r
}

fn reads(fd: i32, buf: u64) -> R {
    let iov = IoVec {
        iov_base: buf as *const u8,
        iov_len: PAGE as usize,
    };
    let n = sys_preadv2(fd, &iov, 1, 0, RWF_NOWAIT);
    check(b"nowait read", n == EAGAIN, n)?;
    let n = sys_preadv2(fd, &iov, 1, 0, 0);
    check(b"blocking read", n == PAGE as i64, n)
}

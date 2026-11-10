//! RWF_NOWAIT on a block device whose queue cannot honor it (Linux
//! BLK_FEAT_NOWAIT unset: bdev_open leaves FMODE_NOWAIT off, so
//! kiocb_set_rw_flags refuses RWF_NOWAIT): EOPNOTSUPP, direct or
//! buffered, and the same read without RWF_NOWAIT returns the data. An
//! empty read is 0 whatever the flags (Linux vfs_readv returns before
//! kiocb_set_rw_flags).
//! hk's sd driver is bio-based and does each request in the submitter,
//! so sda is such a device. Linux references have no sda (no USB disk)
//! and no such device: skipped there.

use crate::harness::{R, check, report_r};
use crate::helpers::{host_mode, skip};
use hk_syscall::{
    IoVec, MAP_ANONYMOUS, MAP_PRIVATE, O_RDONLY, PROT_READ, PROT_WRITE, sys_close, sys_mmap,
    sys_munmap, sys_open, sys_preadv2,
};

const O_DIRECT: u32 = hk_syscall::O_DIRECT;
const RWF_NOWAIT: i32 = 8;
const EOPNOTSUPP: i64 = -95;
const PAGE: u64 = 4096;

pub fn run_tests() {
    if host_mode() {
        skip(b"BLK_DIO_NOWAIT_SYNC", b"no USB disk (/dev/sda) on host");
        return;
    }
    report_r(b"BLK_DIO_NOWAIT_SYNC", nowait_sync());
}

fn nowait_sync() -> R {
    let buf = sys_mmap(
        0,
        PAGE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    check(b"mmap", buf > 0, buf)?;
    let r = reads(buf as u64);
    sys_munmap(buf as u64, PAGE);
    r
}

/// (what, open flags, length, RWF flags, expected result)
type Case = (&'static [u8], u32, u64, i32, i64);

fn reads(buf: u64) -> R {
    let cases: [Case; 5] = [
        (
            b"nowait direct read",
            O_RDONLY | O_DIRECT,
            PAGE,
            RWF_NOWAIT,
            EOPNOTSUPP,
        ),
        (
            b"nowait buffered read",
            O_RDONLY,
            PAGE,
            RWF_NOWAIT,
            EOPNOTSUPP,
        ),
        // Linux vfs_readv: nothing to read is 0 before the flags are
        // looked at (kiocb_set_rw_flags)
        (
            b"empty nowait direct read",
            O_RDONLY | O_DIRECT,
            0,
            RWF_NOWAIT,
            0,
        ),
        (b"empty nowait buffered read", O_RDONLY, 0, RWF_NOWAIT, 0),
        (b"direct read", O_RDONLY | O_DIRECT, PAGE, 0, PAGE as i64),
    ];
    for (what, flags, len, rwf, want) in cases {
        let fd = sys_open(b"/dev/sda\0".as_ptr(), flags, 0);
        check(b"open sda", fd >= 0, fd)?;
        let iov = IoVec {
            iov_base: buf as *const u8,
            iov_len: len as usize,
        };
        let n = sys_preadv2(fd as i32, &iov, 1, 0, rwf);
        sys_close(fd as u64);
        check(what, n == want, n)?;
    }
    Ok(())
}

//! RWF_NOWAIT on a block device whose queue cannot honor it (Linux
//! BLK_FEAT_NOWAIT unset: bdev_open leaves FMODE_NOWAIT off, so
//! kiocb_set_rw_flags refuses RWF_NOWAIT): EOPNOTSUPP, direct or
//! buffered, and the same read without RWF_NOWAIT returns the data.
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

fn reads(buf: u64) -> R {
    for (what, flags, ok) in [
        (&b"nowait direct read"[..], O_RDONLY | O_DIRECT, false),
        (b"nowait buffered read", O_RDONLY, false),
        (b"direct read", O_RDONLY | O_DIRECT, true),
    ] {
        let fd = sys_open(b"/dev/sda\0".as_ptr(), flags, 0);
        check(b"open sda", fd >= 0, fd)?;
        let iov = IoVec {
            iov_base: buf as *const u8,
            iov_len: PAGE as usize,
        };
        let rwf = if ok { 0 } else { RWF_NOWAIT };
        let n = sys_preadv2(fd as i32, &iov, 1, 0, rwf);
        sys_close(fd as u64);
        let want = if ok { PAGE as i64 } else { EOPNOTSUPP };
        check(what, n == want, n)?;
    }
    Ok(())
}

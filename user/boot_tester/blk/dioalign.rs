//! statx STATX_DIOALIGN of block devices (Linux bdev_statx): memory
//! alignment dma_alignment + 1 (512 for virtio-blk), offset alignment
//! the logical block size; stx_blksize (and st_blksize) is the device's
//! io_min since Linux 6.15 (the physical block size here). Files of
//! tmpfs and vfat do not report it.

use crate::harness::{R, check, report_r};
use crate::helpers::{find_blkdev, linux_at_least};
use hk_syscall::{
    AT_FDCWD, O_CREAT, O_RDWR, Stat, Statx, sys_close, sys_open, sys_stat, sys_statx, sys_unlink,
};

const STATX_DIOALIGN: u32 = 0x2000;

pub fn run_tests() {
    report_r(b"STATX_DIOALIGN", dioalign());
}

fn statx(path: &[u8], st: &mut Statx) -> i64 {
    sys_statx(AT_FDCWD, path.as_ptr(), 0, STATX_DIOALIGN, st)
}

fn dioalign() -> R {
    let blksize = if linux_at_least(6, 15) { 512 } else { 4096 };
    for blocks in [131072, 16384] {
        let Some(d) = find_blkdev(b"vd", blocks) else {
            return check(b"no vda", false, 0);
        };
        let mut p = [0u8; 48];
        let path = d.path(&mut p);
        let mut st = Statx::default();
        let r = statx(path, &mut st);
        check(b"statx", r == 0, r)?;
        let m = st.stx_mask & STATX_DIOALIGN;
        check(b"mask", m != 0, i64::from(st.stx_mask))?;
        check(
            b"mem",
            st.stx_dio_mem_align == 512,
            i64::from(st.stx_dio_mem_align),
        )?;
        let off = i64::from(st.stx_dio_offset_align);
        check(b"offset", off == 512, off)?;
        let bs = i64::from(st.stx_blksize);
        check(b"stx_blksize", bs == blksize, bs)?;
        let mut s = Stat::default();
        let r = sys_stat(path.as_ptr(), &mut s);
        check(
            b"st_blksize",
            r == 0 && s.st_blksize as i64 == blksize,
            s.st_blksize as i64,
        )?;
    }
    let f = b"/tmp/dioalign\0";
    let fd = sys_open(f.as_ptr(), O_RDWR | O_CREAT, 0o644);
    sys_close(fd as u64);
    let mut st = Statx::default();
    let r = statx(f, &mut st);
    sys_unlink(f.as_ptr());
    check(b"file statx", r == 0, r)?;
    let m = st.stx_mask & STATX_DIOALIGN;
    check(b"file mask", m == 0, i64::from(st.stx_mask))
}

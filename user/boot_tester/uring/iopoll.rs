//! IORING_SETUP_IOPOLL (Linux io_uring/rw.c io_do_iopoll, io_uring.c
//! io_iopoll_check; block/fops.c REQ_POLLED bios on a poll queue: every
//! boot gives virtio-blk one, virtio_blk.poll_queues=1):
//! - IO_URING_IOPOLL_READ: 32 O_DIRECT reads of vda3 on an IOPOLL ring
//!   are reaped by GETEVENTS polling, with the pattern
//! - IO_URING_IOPOLL_OPS: on an IOPOLL ring a NOP completes, a read of a
//!   file without O_DIRECT is EOPNOTSUPP, an operation that cannot be
//!   polled (FSYNC) fails with EINVAL

use super::dio::{Buf, is_pat, open};
use super::{Ring, sqe};
use crate::harness::{R, check, report_r};
use crate::helpers::{BlkDev, find_blkdev};
use hk_syscall::{
    IORING_OP_FSYNC, IORING_OP_NOP, IORING_OP_READ, IORING_SETUP_IOPOLL, IoUringParams, O_RDONLY,
    sys_close, sys_memfd_create,
};

const O_DIRECT: u32 = hk_syscall::O_DIRECT;
const EINVAL: i32 = -22;
const EOPNOTSUPP: i32 = -95;

pub fn run_tests() {
    match find_blkdev(b"vd", 16384) {
        Some(p3) => report_r(b"IO_URING_IOPOLL_READ", iopoll_read(&p3)),
        None => report_r(b"IO_URING_IOPOLL_READ", check(b"no vda3", false, 0)),
    }
    report_r(b"IO_URING_IOPOLL_OPS", iopoll_ops());
}

fn ring(entries: u32) -> Result<Ring, (&'static [u8], i64)> {
    let p = IoUringParams {
        flags: IORING_SETUP_IOPOLL,
        ..IoUringParams::default()
    };
    Ring::new(entries, p).map_err(|e| (&b"iopoll ring"[..], e))
}

fn iopoll_read(d: &BlkDev) -> R {
    let fd = open(d, O_RDONLY | O_DIRECT)?;
    let r = iopoll_read_in(fd);
    sys_close(fd as u64);
    r
}

fn iopoll_read_in(fd: i32) -> R {
    const N: u32 = 32;
    let mut r = ring(N)?;
    let b = Buf::new(N as usize * 4096)?;
    for i in 0..N {
        let off = 3 * (1 << 20) + u64::from(i) * 12288;
        r.push(sqe(
            IORING_OP_READ,
            fd,
            b.addr(i as usize * 4096),
            4096,
            off,
            u64::from(i),
        ));
    }
    let n = r.enter(N, 0, 0);
    check(b"submit", n == i64::from(N), n)?;
    let mut got = 0;
    // GETEVENTS may return early (the task should yield): poll again
    for _ in 0..100_000 {
        let w = r.submit_wait(0, N - got);
        check(b"getevents", w == 0, w)?;
        while let Some(c) = r.pop() {
            check(b"res", c.res == 4096, i64::from(c.res))?;
            let off = 3 * (1 << 20) + c.user_data * 12288;
            let data = is_pat(b.bytes(c.user_data as usize * 4096, 4096), off);
            check(b"data", data, c.user_data as i64)?;
            got += 1;
        }
        if got == N {
            return Ok(());
        }
    }
    check(b"reaped", false, i64::from(got))
}

fn iopoll_ops() -> R {
    let mut r = ring(4)?;
    r.push(sqe(IORING_OP_NOP, -1, 0, 0, 0, 1));
    let n = r.submit_wait(1, 1);
    check(b"nop enter", n == 1, n)?;
    let c = r.pop().ok_or((&b"no nop cqe"[..], 0))?;
    check(b"nop res", c.res == 0, i64::from(c.res))?;
    let m = sys_memfd_create(b"p\0".as_ptr(), 0);
    check(b"memfd", m >= 0, m)?;
    let mut buf = [0u8; 16];
    r.push(sqe(
        IORING_OP_READ,
        m as i32,
        buf.as_mut_ptr() as u64,
        16,
        0,
        2,
    ));
    let n = r.submit_wait(1, 1);
    let c = r.pop();
    r.push(sqe(IORING_OP_FSYNC, m as i32, 0, 0, 0, 3));
    let n2 = r.submit_wait(1, 1);
    let c2 = r.pop();
    sys_close(m as u64);
    check(b"read enter", n == 1, n)?;
    let c = c.ok_or((&b"no read cqe"[..], 0))?;
    check(b"buffered read", c.res == EOPNOTSUPP, i64::from(c.res))?;
    check(b"fsync enter", n2 == 1, n2)?;
    let c2 = c2.ok_or((&b"no fsync cqe"[..], 0))?;
    check(b"fsync", c2.res == EINVAL, i64::from(c2.res))
}

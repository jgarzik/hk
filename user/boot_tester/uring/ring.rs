//! The shared rings (Linux io_uring.c io_submit_sqes, io_get_sqe,
//! io_cqring_event_overflow, memmap.c io_uring_mmap):
//! - IO_URING_MMAP: the SQ ring, CQ ring and SQEs map; the rings show
//!   their sizes and masks, and the CQ ring offset maps the same region
//!   as the SQ ring (IORING_FEAT_SINGLE_MMAP); another offset is EINVAL
//! - IO_URING_NOP: NOPs from the SQ come back as CQEs with their
//!   user_data, the SQ head moves past them
//! - IO_URING_READ: IORING_OP_READ and READV read a file at an offset
//! - IO_URING_CUR_POS: offset -1 reads at, and moves, the file position
//!   (IORING_FEAT_RW_CUR_POS)
//! - IO_URING_OVERFLOW: CQEs past a full CQ wait (IORING_SQ_CQ_OVERFLOW,
//!   none lost: IORING_FEAT_NODROP) until GETEVENTS finds room
//! - IO_URING_DROPPED: an SQ array slot naming no SQE is dropped
//!   (sq_dropped) and ends the batch
//! - IO_URING_BADOP: an unknown opcode completes with EINVAL
//! - IO_URING_NOT_RING: io_uring_enter on another fd is EOPNOTSUPP
//! - IO_URING_MMAP_SPLIT: a CQ ring mapping split by munmap of its first
//!   page still shows the right pages after it (Linux inserts the pages
//!   at mmap)
//! - IO_URING_FILES_UPDATE: IORING_REGISTER_FILES_UPDATE leaves an
//!   IORING_REGISTER_FILES_SKIP slot as it is and stops at a bad fd: the
//!   count done before it, EBADF if that is the first (Linux
//!   __io_sqe_files_update)
//! - IO_URING_REG_RING: an io_uring cannot be a registered file, its
//!   own or another ring's (EBADF: Linux io_is_uring_fops; it would keep
//!   the rings alive forever)
//! - IO_URING_OVERFLOW_BOUND (hk only: Linux bounds the overflow list
//!   by the memory cgroup, hk by the CQ size): a CQE past a full
//!   overflow list is lost, counted in cq_overflow, and the next wait
//!   on an empty CQ is EBADR, once

use super::{EINVAL, EOPNOTSUPP, Ring, sqe};
use crate::harness::{R, check, report_r};
use crate::helpers::{host_mode, linux_at_least, skip};

const ENOMEM: i64 = -12;
const EBADF: i64 = -9;
const EBADR: i64 = -53;
const ETIME: i64 = -62;
use hk_syscall::{
    IORING_ENTER_EXT_ARG, IORING_ENTER_GETEVENTS, IORING_FEAT_NODROP, IORING_FEAT_RW_CUR_POS,
    IORING_FEAT_SINGLE_MMAP, IORING_OFF_CQ_RING, IORING_OP_NOP, IORING_OP_READ, IORING_OP_READV,
    IORING_REGISTER_FILES, IORING_SETUP_CQSIZE, IORING_SQ_CQ_OVERFLOW, IoUringParams, IoVec,
    MAP_SHARED, PROT_READ, SEEK_CUR, Timespec, sys_close, sys_io_uring_enter,
    sys_io_uring_register, sys_lseek, sys_memfd_create, sys_mmap, sys_munmap, sys_write,
};

pub fn run_tests() {
    let cases: [(&[u8], fn() -> R); 11] = [
        (b"IO_URING_MMAP", mmap),
        (b"IO_URING_NOP", nop),
        (b"IO_URING_READ", read),
        (b"IO_URING_CUR_POS", cur_pos),
        (b"IO_URING_OVERFLOW", overflow),
        (b"IO_URING_DROPPED", dropped),
        (b"IO_URING_BADOP", badop),
        (b"IO_URING_NOT_RING", not_ring),
        (b"IO_URING_REG_RING", reg_ring),
        (b"IO_URING_MMAP_SPLIT", mmap_split),
        (b"IO_URING_FILES_UPDATE", files_update),
    ];
    for (name, t) in cases {
        report_r(name, t());
    }
    if host_mode() {
        skip(
            b"IO_URING_OVERFLOW_BOUND",
            b"hk bounds the CQ overflow list, Linux charges memcg",
        );
    } else {
        report_r(b"IO_URING_OVERFLOW_BOUND", overflow_bound());
    }
}

fn ring(entries: u32) -> Result<Ring, (&'static [u8], i64)> {
    Ring::simple(entries).map_err(|e| (&b"ring setup/mmap"[..], e))
}

fn mmap() -> R {
    let r = ring(8)?;
    let f = r.p.features;
    check(b"features", f & IORING_FEAT_SINGLE_MMAP != 0, i64::from(f))?;
    let (sq, cq) = (r.p.sq_off, r.p.cq_off);
    check(b"sq entries", r.ring_word(sq.ring_entries) == 8, 0)?;
    check(b"sq mask", r.ring_word(sq.ring_mask) == 7, 0)?;
    check(b"cq entries", r.ring_word(cq.ring_entries) == 16, 0)?;
    check(b"cq mask", r.ring_word(cq.ring_mask) == 15, 0)?;
    // The CQ ring offset maps the same region
    let len = u64::from(cq.cqes) + 16 * 16;
    let p = sys_mmap(0, len, PROT_READ, MAP_SHARED, r.fd, IORING_OFF_CQ_RING);
    check(b"mmap cq ring", p > 0, p)?;
    // SAFETY: the word at the CQ entries offset of the new mapping
    let n = unsafe { ((p as u64 + u64::from(cq.ring_entries)) as *const u32).read_volatile() };
    sys_munmap(p as u64, len);
    check(b"cq ring view", n == 16, i64::from(n))?;
    // EINVAL since Linux 7.2 (df645b745941: before, get_unmapped_area
    // turned the error into ENOMEM)
    let bad = sys_mmap(0, 4096, PROT_READ, MAP_SHARED, r.fd, 0x2000_0000);
    let want = if linux_at_least(7, 2) { EINVAL } else { ENOMEM };
    check(b"bad offset", bad == want, bad)
}

fn nop() -> R {
    let mut r = ring(8)?;
    for i in 0..4 {
        r.push(sqe(IORING_OP_NOP, -1, 0, 0, 0, 100 + i));
    }
    let n = r.submit_wait(4, 4);
    check(b"enter", n == 4, n)?;
    check(b"sq head", r.sq_head() == 4, i64::from(r.sq_head()))?;
    for i in 0..4 {
        let c = r.pop().ok_or((&b"missing cqe"[..], i as i64))?;
        check(b"user_data", c.user_data == 100 + i, c.user_data as i64)?;
        check(b"res", c.res == 0, i64::from(c.res))?;
    }
    check(b"extra cqe", r.pop().is_none(), 0)
}

/// A memfd holding bytes 0, 1, 2, ... (mod 251) for 8 KiB
fn data_file() -> Result<i32, (&'static [u8], i64)> {
    let fd = sys_memfd_create(b"uring\0".as_ptr(), 0);
    check(b"memfd", fd >= 0, fd)?;
    let mut buf = [0u8; 8192];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let n = sys_write(fd as u64, buf.as_ptr(), buf.len() as u64);
    if n != buf.len() as i64 {
        sys_close(fd as u64);
        return Err((b"write", n));
    }
    Ok(fd as i32)
}

/// `buf` holds the file's bytes from `off`
fn is_data(buf: &[u8], off: usize) -> bool {
    buf.iter()
        .enumerate()
        .all(|(i, &b)| b == ((off + i) % 251) as u8)
}

fn read() -> R {
    let fd = data_file()?;
    let r = read_in(fd);
    sys_close(fd as u64);
    r
}

fn read_in(fd: i32) -> R {
    let mut r = ring(4)?;
    let mut a = [0u8; 100];
    let mut b = [0u8; 50];
    let iov = [
        IoVec {
            iov_base: b.as_mut_ptr(),
            iov_len: b.len(),
        },
        IoVec {
            iov_base: a.as_mut_ptr(),
            iov_len: 10,
        },
    ];
    r.push(sqe(IORING_OP_READ, fd, a.as_mut_ptr() as u64, 100, 4000, 1));
    let n = r.submit_wait(1, 1);
    check(b"enter read", n == 1, n)?;
    let c = r.pop().ok_or((&b"no read cqe"[..], 0))?;
    check(b"read res", c.res == 100, i64::from(c.res))?;
    check(b"read data", is_data(&a, 4000), 0)?;
    // 8192 - 8160 = 32 bytes left: short
    r.push(sqe(IORING_OP_READV, fd, iov.as_ptr() as u64, 2, 8160, 2));
    let n = r.submit_wait(1, 1);
    check(b"enter readv", n == 1, n)?;
    let c = r.pop().ok_or((&b"no readv cqe"[..], 0))?;
    check(b"readv res", c.res == 32, i64::from(c.res))?;
    check(b"readv data", is_data(&b[..32], 8160), 0)
}

fn cur_pos() -> R {
    let fd = data_file()?;
    let r = cur_pos_in(fd);
    sys_close(fd as u64);
    r
}

fn cur_pos_in(fd: i32) -> R {
    let mut r = ring(4)?;
    let f = r.p.features;
    check(b"feature", f & IORING_FEAT_RW_CUR_POS != 0, i64::from(f))?;
    let p = sys_lseek(fd, 1000, 0);
    check(b"lseek", p == 1000, p)?;
    let mut a = [0u8; 64];
    for (i, at) in [1000usize, 1064].into_iter().enumerate() {
        r.push(sqe(
            IORING_OP_READ,
            fd,
            a.as_mut_ptr() as u64,
            64,
            u64::MAX,
            1,
        ));
        let n = r.submit_wait(1, 1);
        check(b"enter", n == 1, n)?;
        let c = r.pop().ok_or((&b"no cqe"[..], i as i64))?;
        check(b"res", c.res == 64, i64::from(c.res))?;
        check(b"data", is_data(&a, at), at as i64)?;
    }
    let p = sys_lseek(fd, 0, SEEK_CUR);
    check(b"position", p == 1128, p)
}

fn overflow() -> R {
    let p = IoUringParams {
        flags: IORING_SETUP_CQSIZE,
        cq_entries: 2,
        ..IoUringParams::default()
    };
    let mut r = Ring::new(2, p).map_err(|e| (&b"setup"[..], e))?;
    let f = r.p.features;
    check(b"nodrop", f & IORING_FEAT_NODROP != 0, i64::from(f))?;
    for i in 1..=4 {
        r.push(sqe(IORING_OP_NOP, -1, 0, 0, 0, i));
        let n = r.enter(1, 0, 0);
        check(b"enter", n == 1, n)?;
    }
    check(b"cq tail", r.cq_tail() == 2, i64::from(r.cq_tail()))?;
    let fl = r.sq_flags();
    check(
        b"overflow flag",
        fl & IORING_SQ_CQ_OVERFLOW != 0,
        i64::from(fl),
    )?;
    check(
        b"none lost",
        r.cq_overflow() == 0,
        i64::from(r.cq_overflow()),
    )?;
    for i in 1..=2 {
        let c = r.pop().ok_or((&b"missing"[..], i))?;
        check(b"first cqes", c.user_data == i as u64, c.user_data as i64)?;
    }
    let n = r.enter(0, 0, IORING_ENTER_GETEVENTS);
    check(b"getevents", n == 0, n)?;
    for i in 3..=4 {
        let c = r.pop().ok_or((&b"flushed missing"[..], i))?;
        check(
            b"flushed order",
            c.user_data == i as u64,
            c.user_data as i64,
        )?;
    }
    let fl = r.sq_flags();
    check(
        b"flag cleared",
        fl & IORING_SQ_CQ_OVERFLOW == 0,
        i64::from(fl),
    )
}

fn dropped() -> R {
    let mut r = ring(4)?;
    r.push_at(sqe(IORING_OP_NOP, -1, 0, 0, 0, 1), 99);
    r.push(sqe(IORING_OP_NOP, -1, 0, 0, 0, 2));
    let n = r.enter(2, 0, 0);
    check(b"enter stops", n == 0, n)?;
    check(b"dropped", r.sq_dropped() == 1, i64::from(r.sq_dropped()))?;
    check(b"head past it", r.sq_head() == 1, i64::from(r.sq_head()))?;
    let n = r.submit_wait(1, 1);
    check(b"enter rest", n == 1, n)?;
    let c = r.pop().ok_or((&b"no cqe"[..], 0))?;
    check(b"user_data", c.user_data == 2, c.user_data as i64)
}

fn badop() -> R {
    let mut r = ring(4)?;
    r.push(sqe(0xff, -1, 0, 0, 0, 7));
    let n = r.submit_wait(1, 1);
    check(b"enter", n == 1, n)?;
    let c = r.pop().ok_or((&b"no cqe"[..], 0))?;
    check(b"user_data", c.user_data == 7, c.user_data as i64)?;
    check(b"res", i64::from(c.res) == EINVAL, i64::from(c.res))
}

fn not_ring() -> R {
    let fd = sys_memfd_create(b"x\0".as_ptr(), 0);
    check(b"memfd", fd >= 0, fd)?;
    let n = sys_io_uring_enter(fd as u32, 0, 0, 0, 0, 0);
    sys_close(fd as u64);
    check(b"enter", n == EOPNOTSUPP, n)
}

fn reg_ring() -> R {
    let r = ring(4)?;
    let other = ring(4)?;
    for fd in [r.fd, other.fd] {
        let n = sys_io_uring_register(
            r.fd as u32,
            IORING_REGISTER_FILES,
            &fd as *const i32 as u64,
            1,
        );
        check(b"register ring", n == EBADF, n)?;
    }
    Ok(())
}

fn overflow_bound() -> R {
    let p = IoUringParams {
        flags: IORING_SETUP_CQSIZE,
        cq_entries: 2,
        ..IoUringParams::default()
    };
    let mut r = Ring::new(2, p).map_err(|e| (&b"setup"[..], e))?;
    // 2 in the CQ, 2 on the overflow list, the fifth lost
    for i in 1..=5 {
        r.push(sqe(IORING_OP_NOP, -1, 0, 0, 0, i));
        let n = r.enter(1, 0, 0);
        check(b"enter", n == 1, n)?;
    }
    check(b"lost", r.cq_overflow() == 1, i64::from(r.cq_overflow()))?;
    for _ in 0..2 {
        r.pop().ok_or((&b"missing"[..], 0))?;
    }
    let n = r.enter(0, 0, IORING_ENTER_GETEVENTS);
    check(b"flush", n == 0, n)?;
    for i in 3..=4 {
        let c = r.pop().ok_or((&b"flushed missing"[..], i))?;
        check(b"flushed", c.user_data == i as u64, c.user_data as i64)?;
    }
    let ts = Timespec {
        tv_sec: 0,
        tv_nsec: 10_000_000,
    };
    let arg = [0u64, 0, &ts as *const Timespec as u64];
    let wait = || {
        sys_io_uring_enter(
            r.fd as u32,
            0,
            1,
            IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG,
            arg.as_ptr() as u64,
            24,
        )
    };
    let n = wait();
    check(b"first wait", n == EBADR, n)?;
    let n = wait();
    check(b"second wait", n == ETIME, n)
}

fn mmap_split() -> R {
    let mut r = ring(256)?;
    let cq = r.p.cq_off;
    let len = u64::from(cq.cqes) + u64::from(r.p.cq_entries) * 16;
    // Not populated: every page of this view is reached after the split
    let p = sys_mmap(0, len, PROT_READ, MAP_SHARED, r.fd, IORING_OFF_CQ_RING);
    check(b"mmap", p > 0, p)?;
    let n = sys_munmap(p as u64, 4096);
    let res = (|| {
        check(b"munmap first page", n == 0, n)?;
        // CQE 300 lies in the mapping's second page or later
        for i in 0..301u64 {
            r.push(sqe(IORING_OP_NOP, -1, 0, 0, 0, 1000 + i));
            let k = r.enter(1, 0, 0);
            check(b"enter", k == 1, k)?;
            r.pop().ok_or((&b"no cqe"[..], i as i64))?;
        }
        let off = u64::from(cq.cqes) + 300 * 16;
        // SAFETY: inside the part of the mapping left after the munmap
        let ud = unsafe { ((p as u64 + off) as *const u64).read_volatile() };
        check(b"cqe 300 user_data", ud == 1300, ud as i64)
    })();
    sys_munmap(p as u64 + 4096, len - 4096);
    res
}

fn files_update() -> R {
    let fd = data_file()?;
    let r = files_update_in(fd);
    sys_close(fd as u64);
    r
}

fn files_update_in(fd: i32) -> R {
    let mut r = ring(4)?;
    let fds = [fd, -1];
    let n = sys_io_uring_register(r.fd as u32, IORING_REGISTER_FILES, fds.as_ptr() as u64, 2);
    check(b"register", n == 0, n)?;
    let rfd = r.fd as u32;
    let update = |fds: &[i32]| {
        // struct io_uring_files_update { u32 offset; u32 resv; u64 fds; }
        let up = [0u64, fds.as_ptr() as u64];
        sys_io_uring_register(rfd, 6, up.as_ptr() as u64, fds.len() as u32)
    };
    let n = update(&[-2, 999]);
    check(b"skip then bad fd", n == 1, n)?;
    // Slot 0 still holds the file
    let mut a = [0u8; 16];
    let mut s = sqe(IORING_OP_READ, 0, a.as_mut_ptr() as u64, 16, 100, 1);
    s.flags = 1; // IOSQE_FIXED_FILE
    r.push(s);
    let k = r.submit_wait(1, 1);
    check(b"enter", k == 1, k)?;
    let c = r.pop().ok_or((&b"no cqe"[..], 0))?;
    check(b"fixed read", c.res == 16, i64::from(c.res))?;
    check(b"data", is_data(&a, 100), 0)?;
    // A bad fd first: EBADF, and its slot is left empty
    let n = update(&[999]);
    check(b"bad fd first", n == EBADF, n)?;
    r.push(s);
    let k = r.submit_wait(1, 1);
    check(b"enter again", k == 1, k)?;
    let c = r.pop().ok_or((&b"no second cqe"[..], 0))?;
    check(b"emptied slot", i64::from(c.res) == EBADF, i64::from(c.res))
}

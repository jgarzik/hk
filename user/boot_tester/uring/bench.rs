//! io_uring rows of DIO_BENCH (`make check BENCH=1`; printed only): 4
//! KiB random O_DIRECT reads of vda3 from one task, kept `qd` in flight
//! (QD1, QD32, QD128), with plain buffers, registered buffers and, on an
//! IOPOLL ring, polled completion

use super::{Ring, sqe};
use crate::blk::dio_bench::{line, now_ns};
use crate::uring::dio::Buf;
use hk_syscall::{
    IORING_OP_READ, IORING_OP_READ_FIXED, IORING_REGISTER_BUFFERS, IORING_SETUP_IOPOLL,
    IoUringParams, IoVec, sys_io_uring_register,
};

/// Reads per run
const N: u64 = 4096;

/// Queue depths
const QDS: [u32; 3] = [1, 32, 128];

/// The next random 4 KiB-aligned offset in vda3's 16 MiB
fn next_off(x: &mut u32) -> u64 {
    *x = x.wrapping_mul(1103515245).wrapping_add(12345);
    u64::from(*x >> 8) % 4096 * 4096
}

/// A run's setup: IOPOLL ring, registered buffers
#[derive(Clone, Copy)]
struct Mode {
    iopoll: bool,
    fixed: bool,
}

/// Nanoseconds for N reads at depth `qd`, or the first error
fn run(fd: i32, qd: u32, m: Mode) -> i64 {
    let p = IoUringParams {
        flags: if m.iopoll { IORING_SETUP_IOPOLL } else { 0 },
        ..IoUringParams::default()
    };
    let Ok(mut r) = Ring::new(qd, p) else {
        return -1;
    };
    let Ok(b) = Buf::new(qd as usize * 4096) else {
        return -2;
    };
    if m.fixed {
        let iov = IoVec {
            iov_base: b.p,
            iov_len: b.len,
        };
        let n = sys_io_uring_register(
            r.fd as u32,
            IORING_REGISTER_BUFFERS,
            &iov as *const _ as u64,
            1,
        );
        if n != 0 {
            return n;
        }
    }
    let op = if m.fixed {
        IORING_OP_READ_FIXED
    } else {
        IORING_OP_READ
    };
    let mut x = 777u32;
    let mut issue = |r: &mut Ring, slot: u64| {
        let s = sqe(
            op,
            fd,
            b.addr(slot as usize * 4096),
            4096,
            next_off(&mut x),
            slot,
        );
        r.push(s);
    };
    let t = now_ns();
    let (mut sent, mut done) = (0u64, 0u64);
    for slot in 0..u64::from(qd).min(N) {
        issue(&mut r, slot);
        sent += 1;
    }
    let mut pending = sent as u32;
    while done < N {
        let w = r.submit_wait(pending, 1);
        if w < 0 {
            return w;
        }
        pending = 0;
        while let Some(c) = r.pop() {
            if c.res != 4096 {
                return i64::from(c.res).min(-3);
            }
            done += 1;
            if sent < N {
                issue(&mut r, c.user_data);
                sent += 1;
                pending += 1;
            }
        }
    }
    now_ns() - t
}

/// Print the rows
pub fn bench(fd: i32) {
    let modes = [
        (
            &b" plain "[..],
            Mode {
                iopoll: false,
                fixed: false,
            },
        ),
        (
            b" fixed ",
            Mode {
                iopoll: false,
                fixed: true,
            },
        ),
        (
            b" iopoll ",
            Mode {
                iopoll: true,
                fixed: false,
            },
        ),
        (
            b" iopoll+fixed ",
            Mode {
                iopoll: true,
                fixed: true,
            },
        ),
    ];
    for qd in QDS {
        let row = modes.map(|(name, m)| (name, run(fd, qd, m)));
        let what: &[u8] = match qd {
            1 => b"uring rand 4K QD1",
            32 => b"uring rand 4K QD32",
            _ => b"uring rand 4K QD128",
        };
        line(what, &row, N * 4096, N);
    }
}

//! Linux AIO rows of DIO_BENCH (`make check BENCH=1`; printed only): 4
//! KiB random O_DIRECT reads of vda3 from one task, kept `qd` in flight
//! (QD1, QD32), events reaped by io_getevents (libaio) or straight from
//! the mapped ring (the user-space fast path, io_getevents only to
//! sleep)

use super::{Ctx, IOCB_CMD_PREAD, IoEvent, Iocb, iocb};
use crate::blk::dio_bench::{line, now_ns};
use crate::uring::dio::Buf;

/// Reads per run
const N: u64 = 4096;

/// Queue depths
const QDS: [usize; 2] = [1, 32];
const MAXQD: usize = 32;

/// The next random 4 KiB-aligned offset in vda3's 16 MiB
fn next_off(x: &mut u32) -> u64 {
    *x = x.wrapping_mul(1103515245).wrapping_add(12345);
    u64::from(*x >> 8) % 4096 * 4096
}

/// Nanoseconds for N reads at depth `qd`, or the first error; `ring`:
/// reap from the ring, sleeping in io_getevents only when it is empty
fn run(fd: i32, qd: usize, ring: bool) -> i64 {
    let Ok(c) = Ctx::new(qd as u32 * 2) else {
        return -1;
    };
    let Ok(b) = Buf::new(qd * 4096) else {
        return -2;
    };
    let mut cbs = [Iocb::default(); MAXQD];
    let mut x = 777u32;
    let mut issue = |c: &Ctx, slot: usize, cbs: &mut [Iocb; MAXQD]| {
        cbs[slot] = iocb(
            IOCB_CMD_PREAD,
            fd,
            b.addr(slot * 4096),
            4096,
            next_off(&mut x) as i64,
            slot as u64,
        );
        c.submit(&[&cbs[slot] as *const Iocb])
    };
    let t = now_ns();
    let (mut sent, mut done) = (0u64, 0u64);
    for slot in 0..qd {
        let n = issue(&c, slot, &mut cbs);
        if n != 1 {
            return n.min(-3);
        }
        sent += 1;
    }
    let mut ev = [IoEvent::default(); MAXQD];
    while done < N {
        let mut got = if ring {
            c.ring_pop(&mut ev[..qd]) as i64
        } else {
            0
        };
        while got == 0 || got == super::EINTR {
            // A signal (an earlier run's SIGCHLD) may end the wait: again
            got = c.get(1, &mut ev[..qd], None);
        }
        if got < 0 {
            return got.min(-4);
        }
        for e in &ev[..got as usize] {
            if e.res != 4096 {
                return e.res.min(-5);
            }
            done += 1;
            if sent < N {
                if issue(&c, e.data as usize, &mut cbs) != 1 {
                    return -6;
                }
                sent += 1;
            }
        }
    }
    now_ns() - t
}

/// Print the rows
pub fn bench(fd: i32) {
    for qd in QDS {
        let row = [
            (&b" getevents "[..], run(fd, qd, false)),
            (b" ring ", run(fd, qd, true)),
        ];
        let what: &[u8] = if qd == 1 {
            b"aio rand 4K QD1"
        } else {
            b"aio rand 4K QD32"
        };
        line(what, &row, N * 4096, N);
    }
}

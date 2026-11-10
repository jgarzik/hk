//! AIO operations other than block O_DIRECT:
//! - AIO_BUFFERED: reads and writes of a tmpfs file without O_DIRECT
//!   complete within io_submit (their events are in the ring when it
//!   returns), PREADV/PWRITEV included; aio_key is set to 0; a bad fd is
//!   EBADF, a negative offset, IOCB_CMD_NOOP and aio_reserved2 EINVAL
//! - AIO_FSYNC: FSYNC and FDSYNC events report 0; a buffer or length on
//!   one is EINVAL
//! - AIO_CANCEL: io_cancel of an O_DIRECT read is EINVAL (Linux only
//!   cancels requests with ki_cancel); its event still comes; an iocb
//!   address whose aio_key wraps past the top of memory is EFAULT
//! - AIO_POLL: IOCB_CMD_POLL of a pipe completes when data comes, at once
//!   when ready; io_cancel of a waiting one is EINPROGRESS and its event
//!   reports 0
//! - AIO_PGETEVENTS: a timeout returns 0 no sooner; a zero one at once;
//!   the sigmask blocks a timer's signal through the wait (delivered
//!   after), an empty one lets it end the wait (EINTR); a bad sigset
//!   size is EINVAL

use core::sync::atomic::{AtomicU32, Ordering};

use super::*;
use crate::harness::{R, check, report_r};
use crate::helpers::find_blkdev;
use crate::signal::signals::restorer_addr;
use crate::uring::dio::{Buf, open};
use crate::uring::wait::now_ms;
use hk_syscall::{
    ITIMER_REAL, ITimerVal, IoVec, O_RDONLY, SA_RESTORER, SA_SIGINFO, SIG_DFL, SIGALRM, Timeval,
    sys_io_cancel, sys_io_pgetevents, sys_pipe2, sys_read, sys_rt_sigaction, sys_setitimer,
    sys_unlink, sys_write,
};

const O_DIRECT: u32 = hk_syscall::O_DIRECT;
const EINPROGRESS: i64 = -115;
const POLLIN: u64 = 1;
const POLLOUT: u64 = 4;

pub fn run_tests() {
    report_r(b"AIO_BUFFERED", buffered());
    report_r(b"AIO_FSYNC", fsync());
    report_r(b"AIO_CANCEL", cancel());
    report_r(b"AIO_POLL", poll());
    report_r(b"AIO_PGETEVENTS", pgetevents());
}

const BUFFILE: &[u8] = b"/tmp/aio_buffered\0";

/// One event, which must be in the ring already
fn ready_event(c: &Ctx) -> Result<IoEvent, (&'static [u8], i64)> {
    check(
        b"event in ring at return",
        c.ready() == 1,
        i64::from(c.ready()),
    )?;
    let mut ev = [IoEvent::default(); 1];
    let n = c.get(1, &mut ev, Some(0));
    check(b"io_getevents", n == 1, n)?;
    Ok(ev[0])
}

fn buffered() -> R {
    let fd = tmp_file(BUFFILE)?;
    let r = (|| {
        let c = Ctx::new(8)?;
        let msg = b"hello aio";
        let mut w = iocb(IOCB_CMD_PWRITE, fd, msg.as_ptr() as u64, 9, 100, 7);
        w.key = 0xdead;
        let wp = &raw mut w;
        let n = c.submit(&[wp.cast_const()]);
        check(b"io_submit", n == 1, n)?;
        // SAFETY: the iocb, which io_submit wrote through the pointer
        let key = unsafe { (&raw const (*wp).key).read_volatile() };
        check(b"aio_key", key == 0, i64::from(key))?;
        let e = ready_event(&c)?;
        check(b"write res", e.res == 9 && e.data == 7, e.res)?;
        let mut buf = [0u8; 16];
        c.submit1(&iocb(
            IOCB_CMD_PREAD,
            fd,
            buf.as_mut_ptr() as u64,
            9,
            100,
            8,
        ))?;
        let e = ready_event(&c)?;
        check(b"read res", e.res == 9, e.res)?;
        check(b"read data", &buf[..9] == msg, 0)?;
        // Vectored
        let (mut a, mut b) = ([0u8; 4], [0u8; 5]);
        let iov = [
            IoVec {
                iov_base: a.as_mut_ptr(),
                iov_len: 4,
            },
            IoVec {
                iov_base: b.as_mut_ptr(),
                iov_len: 5,
            },
        ];
        c.submit1(&iocb(IOCB_CMD_PREADV, fd, iov.as_ptr() as u64, 2, 100, 9))?;
        let e = ready_event(&c)?;
        check(
            b"readv",
            e.res == 9 && &a == b"hell" && &b == b"o aio",
            e.res,
        )?;
        let wiov = [IoVec {
            iov_base: msg.as_ptr() as *mut u8,
            iov_len: 5,
        }];
        c.submit1(&iocb(IOCB_CMD_PWRITEV, fd, wiov.as_ptr() as u64, 1, 0, 10))?;
        let e = ready_event(&c)?;
        check(b"writev", e.res == 5, e.res)?;
        // Errors of io_submit itself
        let one = |cb: Iocb| c.submit(&[&cb as *const Iocb]);
        let n = one(iocb(IOCB_CMD_PREAD, 9999, buf.as_mut_ptr() as u64, 1, 0, 0));
        check(b"bad fd", n == EBADF, n)?;
        let n = one(iocb(IOCB_CMD_PREAD, fd, buf.as_mut_ptr() as u64, 1, -1, 0));
        check(b"negative offset", n == EINVAL, n)?;
        let n = one(iocb(IOCB_CMD_NOOP, fd, 0, 0, 0, 0));
        check(b"noop", n == EINVAL, n)?;
        let n = one(Iocb {
            reserved2: 1,
            ..iocb(IOCB_CMD_PREAD, fd, buf.as_mut_ptr() as u64, 1, 0, 0)
        });
        check(b"reserved2", n == EINVAL, n)?;
        check(b"no stray events", c.ready() == 0, i64::from(c.ready()))
    })();
    sys_close(fd as u64);
    sys_unlink(BUFFILE.as_ptr());
    r
}

fn fsync() -> R {
    let fd = tmp_file(BUFFILE)?;
    let r = (|| {
        let c = Ctx::new(8)?;
        sys_write(fd as u64, b"data".as_ptr(), 4);
        for (op, d) in [(IOCB_CMD_FSYNC, 1u64), (IOCB_CMD_FDSYNC, 2)] {
            c.submit1(&iocb(op, fd, 0, 0, 0, d))?;
            let mut ev = [IoEvent::default(); 1];
            c.get_all(&mut ev)?;
            check(b"fsync res", ev[0].res == 0 && ev[0].data == d, ev[0].res)?;
        }
        let bad = iocb(IOCB_CMD_FSYNC, fd, 0, 1, 0, 3);
        let n = c.submit(&[&bad as *const Iocb]);
        check(b"fsync with length", n == EINVAL, n)
    })();
    sys_close(fd as u64);
    sys_unlink(BUFFILE.as_ptr());
    r
}

fn cancel() -> R {
    let Some(p3) = find_blkdev(b"vd", 16384) else {
        return check(b"no vda3", false, 0);
    };
    let fd = open(&p3, O_RDONLY | O_DIRECT)?;
    let r = (|| {
        let c = Ctx::new(8)?;
        let b = Buf::new(1 << 20)?;
        let cb = iocb(IOCB_CMD_PREAD, fd, b.addr(0), 1 << 20, 0, 5);
        c.submit1(&cb)?;
        let mut res = IoEvent::default();
        let n = sys_io_cancel(
            c.0,
            &cb as *const Iocb as u64,
            &mut res as *mut IoEvent as u64,
        );
        check(b"cancel dio", n == EINVAL, n)?;
        // An iocb whose aio_key would be past the top of memory
        let n = sys_io_cancel(c.0, u64::MAX - 1, 0);
        check(b"cancel wrapping iocb", n == EFAULT, n)?;
        let mut ev = [IoEvent::default(); 1];
        c.get_all(&mut ev)?;
        check(b"event", ev[0].res == 1 << 20 && ev[0].data == 5, ev[0].res)
    })();
    sys_close(fd as u64);
    r
}

fn poll() -> R {
    let mut p = [0i32; 2];
    let n = sys_pipe2(p.as_mut_ptr(), 0);
    check(b"pipe", n == 0, n)?;
    let r = (|| {
        let c = Ctx::new(8)?;
        let rd = iocb(IOCB_CMD_POLL, p[0], POLLIN, 0, 0, 1);
        c.submit1(&rd)?;
        crate::helpers::msleep(50);
        check(b"not ready", c.ready() == 0, i64::from(c.ready()))?;
        sys_write(p[1] as u64, b"x".as_ptr(), 1);
        let mut ev = [IoEvent::default(); 1];
        c.get_all(&mut ev)?;
        check(
            b"pollin",
            ev[0].data == 1 && ev[0].res as u64 & POLLIN != 0,
            ev[0].res,
        )?;
        // Ready at once
        c.submit1(&iocb(IOCB_CMD_POLL, p[1], POLLOUT, 0, 0, 2))?;
        let e = ready_event(&c)?;
        check(b"pollout", e.res as u64 & POLLOUT != 0, e.res)?;
        // Drained; the finished one cannot be cancelled
        let mut x = [0u8; 1];
        sys_read(p[0] as u64, x.as_mut_ptr(), 1);
        let n = sys_io_cancel(c.0, &rd as *const Iocb as u64, 0);
        check(b"cancel finished", n == EINVAL, n)
    })();
    let r = r.and_then(|()| poll_cancel(&p));
    sys_close(p[0] as u64);
    sys_close(p[1] as u64);
    r
}

/// io_cancel of a waiting poll
fn poll_cancel(p: &[i32; 2]) -> R {
    let c = Ctx::new(8)?;
    let cb = iocb(IOCB_CMD_POLL, p[0], POLLIN, 0, 0, 4);
    c.submit1(&cb)?;
    let n = sys_io_cancel(c.0, &cb as *const Iocb as u64, 0);
    check(b"cancel poll", n == EINPROGRESS, n)?;
    let mut ev = [IoEvent::default(); 1];
    c.get_all(&mut ev)?;
    check(
        b"cancelled event",
        ev[0].data == 4 && ev[0].res == 0,
        ev[0].res,
    )?;
    let bad = iocb(IOCB_CMD_POLL, p[0], POLLIN, 1, 0, 5);
    let n = c.submit(&[&bad as *const Iocb]);
    check(b"poll with length", n == EINVAL, n)
}

static CAUGHT: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_alrm(_s: i32, _i: *const u8, _u: *const u8) {
    CAUGHT.store(CAUGHT.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
}

#[repr(C)]
struct SigAct {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

fn catch(on: bool) {
    CAUGHT.store(0, Ordering::Relaxed);
    let act = SigAct {
        handler: if on {
            on_alrm as *const () as u64
        } else {
            SIG_DFL
        },
        flags: SA_SIGINFO | SA_RESTORER,
        restorer: restorer_addr(),
        mask: 0,
    };
    sys_rt_sigaction(SIGALRM, &act as *const SigAct as u64, 0, 8);
}

/// `struct __aio_sigset`
#[repr(C)]
struct AioSigset {
    sigmask: u64,
    sigsetsize: u64,
}

/// io_pgetevents for one event, `ms` timeout, signal mask `mask` (size
/// `sz`), while a timer sends SIGALRM after 50 ms: the result, the
/// handler runs right after
fn timed(c: &Ctx, ms: i64, mask: u64, sz: u64) -> (i64, u32) {
    catch(true);
    let it = ITimerVal {
        it_interval: Timeval::default(),
        it_value: Timeval {
            tv_sec: 0,
            tv_usec: 50_000,
        },
    };
    sys_setitimer(ITIMER_REAL, &it, core::ptr::null_mut());
    let ts = Timespec {
        tv_sec: ms / 1000,
        tv_nsec: (ms % 1000) * 1_000_000,
    };
    let sig = AioSigset {
        sigmask: &mask as *const u64 as u64,
        sigsetsize: sz,
    };
    let mut ev = [IoEvent::default(); 1];
    let n = sys_io_pgetevents(
        c.0,
        1,
        1,
        ev.as_mut_ptr() as u64,
        &ts as *const Timespec as u64,
        &sig as *const AioSigset as u64,
    );
    let off = ITimerVal::default();
    sys_setitimer(ITIMER_REAL, &off, core::ptr::null_mut());
    let caught = CAUGHT.load(Ordering::Relaxed);
    catch(false);
    (n, caught)
}

fn pgetevents() -> R {
    let c = Ctx::new(8)?;
    let mut ev = [IoEvent::default(); 1];
    let t = now_ms();
    let ts = Timespec {
        tv_sec: 0,
        tv_nsec: 100_000_000,
    };
    let n = sys_io_pgetevents(
        c.0,
        1,
        1,
        ev.as_mut_ptr() as u64,
        &ts as *const Timespec as u64,
        0,
    );
    let dt = now_ms() - t;
    check(b"timeout result", n == 0, n)?;
    check(b"timeout not early (ms)", dt >= 95, dt)?;
    let t = now_ms();
    let n = c.get(1, &mut ev, Some(0));
    let dt = now_ms() - t;
    check(b"zero timeout", n == 0 && dt < 50, n)?;
    let (n, caught) = timed(&c, 300, 1 << (SIGALRM - 1), 8);
    check(b"masked result", n == 0, n)?;
    check(b"masked handler after", caught == 1, i64::from(caught))?;
    let (n, caught) = timed(&c, 5000, 0, 8);
    check(b"signal result", n == EINTR, n)?;
    check(b"signal handler", caught == 1, i64::from(caught))?;
    let (n, _) = timed(&c, 0, 0, 4);
    check(b"bad sigsetsize", n == EINVAL, n)
}

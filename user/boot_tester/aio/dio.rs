//! AIO O_DIRECT (Linux aio_read/aio_write with an async kiocb: block/fops.c
//! __blkdev_direct_IO_async; fs/direct-io.c for vfat):
//! - AIO_DIO_RW: 32 4 KiB reads of vda3 in one io_submit, half reaped by
//!   io_getevents and half straight from the mapped ring, each event's
//!   data, obj and res right and the pattern read; 32 writes at 12 MiB
//!   read back by AIO, then the pattern put back (PWRITEV) and checked
//! - AIO_RESFD: an eventfd named by IOCB_FLAG_RESFD counts the
//!   completions
//! - AIO_DIO_REDIRTY: O_DIRECT writes of a page another process keeps
//!   writing through a shared mapping of the device: a page that cannot
//!   be dropped from the cache sends the write through it (Linux
//!   kiocb_invalidate_pages EBUSY -> direct_write_fallback), so every
//!   event reports the whole write
//! - AIO_VFAT_DIO: on a vda1 vfat file, an extending O_DIRECT write
//!   (synchronous, as Linux), overwrites within the size and reads back
//!   by AIO match a buffered read; a read at the end is 0; misaligned
//!   memory is an EINVAL event
//! - AIO_VFAT_APPEND: on a vda1 vfat file opened
//!   O_DIRECT, RWF_APPEND sends a write within the size to the end
//!   (Linux kiocb_set_rw_flags: IOCB_APPEND), and RWF_NOAPPEND on an
//!   O_APPEND one writes at the offset (Linux 6.9 on)
//! - AIO_VFAT_DIO_CACHE: a buffered read of the range of an async
//!   O_DIRECT write in flight caches what it finds; once the write's
//!   event is in, a buffered read sees the written data (Linux
//!   dio_complete -> kiocb_invalidate_post_direct_write)

use super::*;
use crate::harness::{R, check, report_r};
use crate::helpers::{BlkDev, find_blkdev};
use crate::uring::dio::{Buf, is_pat, open, pat};
use hk_syscall::{
    IoVec, O_CREAT, O_RDONLY, O_TRUNC, sys_eventfd2, sys_mkdir, sys_mount, sys_pread64, sys_read,
    sys_rmdir, sys_umount2, sys_unlink,
};
use hk_syscall::{
    MAP_SHARED, PROT_READ, PROT_WRITE, sys_exit, sys_fork, sys_kill, sys_mmap, sys_pwrite64,
    sys_wait4,
};

const O_DIRECT: u32 = hk_syscall::O_DIRECT;
const PAGE: usize = 4096;
const MIB: u64 = 1 << 20;
/// vda3's AIO write area
const WR: u64 = 12 * MIB;
const QD: usize = 32;

pub fn run_tests() {
    let Some(p3) = find_blkdev(b"vd", 16384) else {
        report_r(b"AIO_DIO", check(b"no vda3", false, 0));
        return;
    };
    report_r(b"AIO_DIO_RW", rw(&p3));
    report_r(b"AIO_RESFD", resfd(&p3));
    report_r(b"AIO_DIO_REDIRTY", redirty(&p3));
    let Some(p1) = find_blkdev(b"vd", 32768) else {
        report_r(b"AIO_VFAT_DIO", check(b"no vda1", false, 0));
        return;
    };
    report_r(b"AIO_VFAT_DIO", vfat(&p1));
}

/// Read offset of request `i` (scattered over the first 7 MiB)
fn rd_off(i: usize) -> u64 {
    (i as u64 * 7919 % 1792) * PAGE as u64
}

/// Check `ev` against `cbs`: every request once, its res `want`
fn check_events(ev: &[IoEvent], cbs: &[Iocb], want: i64, seen: &mut [bool]) -> R {
    for e in ev {
        let i = e.data as usize;
        check(b"event data", i < cbs.len() && !seen[i], e.data as i64)?;
        seen[i] = true;
        check(
            b"event obj",
            e.obj == &cbs[i] as *const Iocb as u64,
            i as i64,
        )?;
        check(b"event res", e.res == want, e.res)?;
    }
    Ok(())
}

/// Submit `cbs` at once, reap half by io_getevents and half from the
/// ring, all with res `want`
fn run_all(c: &Ctx, cbs: &[Iocb], want: i64) -> R {
    let ptrs: [*const Iocb; QD] = core::array::from_fn(|i| &cbs[i] as *const Iocb);
    let n = c.submit(&ptrs[..cbs.len()]);
    check(b"io_submit", n == cbs.len() as i64, n)?;
    let mut ev = [IoEvent::default(); QD];
    let half = cbs.len() / 2;
    let got = c.get(half, &mut ev[..half], Some(5000));
    check(b"io_getevents", got == half as i64, got)?;
    c.ring_pop_all(&mut ev[half..cbs.len()])?;
    let mut seen = [false; QD];
    check_events(&ev[..cbs.len()], cbs, want, &mut seen)
}

fn rw(d: &BlkDev) -> R {
    let fd = open(d, hk_syscall::O_RDWR | O_DIRECT)?;
    let r = (|| {
        let c = Ctx::new(64)?;
        let b = Buf::new(QD * PAGE)?;
        let cbs: [Iocb; QD] = core::array::from_fn(|i| {
            iocb(
                IOCB_CMD_PREAD,
                fd,
                b.addr(i * PAGE),
                PAGE as u64,
                rd_off(i) as i64,
                i as u64,
            )
        });
        run_all(&c, &cbs, PAGE as i64)?;
        for i in 0..QD {
            check(
                b"read pattern",
                is_pat(b.bytes(i * PAGE, PAGE), rd_off(i)),
                i as i64,
            )?;
        }
        // Writes of a fill unlike the pattern, read back by AIO
        for i in 0..QD {
            b.bytes(i * PAGE, PAGE).fill(0xa5 ^ i as u8);
        }
        let at = |i: usize| (WR + (i * PAGE) as u64) as i64;
        let cbs: [Iocb; QD] = core::array::from_fn(|i| {
            iocb(
                IOCB_CMD_PWRITE,
                fd,
                b.addr(i * PAGE),
                PAGE as u64,
                at(i),
                i as u64,
            )
        });
        run_all(&c, &cbs, PAGE as i64)?;
        let back = Buf::new(QD * PAGE)?;
        let cbs: [Iocb; QD] = core::array::from_fn(|i| {
            iocb(
                IOCB_CMD_PREAD,
                fd,
                back.addr(i * PAGE),
                PAGE as u64,
                at(i),
                i as u64,
            )
        });
        run_all(&c, &cbs, PAGE as i64)?;
        for i in 0..QD {
            let ok = back
                .bytes(i * PAGE, PAGE)
                .iter()
                .all(|&x| x == 0xa5 ^ i as u8);
            check(b"written data", ok, i as i64)?;
        }
        // The pattern back, two iovecs per request
        for (k, v) in b.bytes(0, QD * PAGE).iter_mut().enumerate() {
            *v = pat(WR + k as u64);
        }
        let iov: [[IoVec; 2]; QD] = core::array::from_fn(|i| {
            [
                IoVec {
                    iov_base: b.p.wrapping_add(i * PAGE),
                    iov_len: 1024,
                },
                IoVec {
                    iov_base: b.p.wrapping_add(i * PAGE + 1024),
                    iov_len: 3072,
                },
            ]
        });
        let cbs: [Iocb; QD] = core::array::from_fn(|i| {
            iocb(
                IOCB_CMD_PWRITEV,
                fd,
                iov[i].as_ptr() as u64,
                2,
                at(i),
                i as u64,
            )
        });
        run_all(&c, &cbs, PAGE as i64)?;
        let n = sys_pread64(fd, back.p, (QD * PAGE) as u64, WR as i64);
        check(b"pread", n == (QD * PAGE) as i64, n)?;
        check(b"pattern back", is_pat(back.bytes(0, QD * PAGE), WR), 0)
    })();
    sys_close(fd as u64);
    r
}

fn resfd(d: &BlkDev) -> R {
    let fd = open(d, O_RDONLY | O_DIRECT)?;
    let efd = sys_eventfd2(0, 0);
    let r = (|| {
        check(b"eventfd", efd >= 0, efd)?;
        let c = Ctx::new(16)?;
        let b = Buf::new(8 * PAGE)?;
        let cbs: [Iocb; 8] = core::array::from_fn(|i| Iocb {
            flags: IOCB_FLAG_RESFD,
            resfd: efd as u32,
            ..iocb(
                IOCB_CMD_PREAD,
                fd,
                b.addr(i * PAGE),
                PAGE as u64,
                rd_off(i) as i64,
                i as u64,
            )
        });
        let ptrs: [*const Iocb; 8] = core::array::from_fn(|i| &cbs[i] as *const Iocb);
        let n = c.submit(&ptrs);
        check(b"io_submit", n == 8, n)?;
        let mut ev = [IoEvent::default(); 8];
        c.get_all(&mut ev)?;
        let mut v = 0u64;
        let r = sys_read(efd as u64, &mut v as *mut u64 as *mut u8, 8);
        check(b"eventfd read", r == 8, r)?;
        check(b"eventfd count", v == 8, v as i64)?;
        // RESFD naming no eventfd
        let bad = Iocb {
            flags: IOCB_FLAG_RESFD,
            resfd: fd as u32,
            ..cbs[0]
        };
        let n = c.submit(&[&bad as *const Iocb]);
        check(b"resfd not eventfd", n == EINVAL, n)
    })();
    if efd >= 0 {
        sys_close(efd as u64);
    }
    sys_close(fd as u64);
    r
}

/// The page the redirty test writes
const RD_PAGE: u64 = WR + 512 * 1024;
/// Writes it makes
const REDIRTY_N: usize = 200;

/// In a child: write vda3's page at `page` through a shared mapping
/// until killed
pub fn dirtier(d: &BlkDev, page: u64) -> ! {
    let Ok(fd) = open(d, hk_syscall::O_RDWR) else {
        sys_exit(1)
    };
    let m = sys_mmap(0, PAGE as u64, PROT_READ | PROT_WRITE, MAP_SHARED, fd, page);
    if m <= 0 {
        sys_exit(2);
    }
    let mut i = 0u8;
    loop {
        // SAFETY: inside the mapping
        unsafe { core::ptr::write_volatile((m as *mut u8).add(usize::from(i) * 16), i) };
        i = i.wrapping_add(1);
    }
}

fn redirty(d: &BlkDev) -> R {
    let pid = sys_fork();
    if pid == 0 {
        dirtier(d, RD_PAGE);
    }
    check(b"fork", pid > 0, pid)?;
    let fd = open(d, hk_syscall::O_RDWR | O_DIRECT);
    let r = fd.and_then(|fd| {
        let r = (|| {
            let c = Ctx::new(8)?;
            let b = Buf::new(PAGE)?;
            b.bytes(0, PAGE).fill(0x5a);
            let cb = iocb(
                IOCB_CMD_PWRITE,
                fd,
                b.addr(0),
                PAGE as u64,
                RD_PAGE as i64,
                1,
            );
            let mut ev = [IoEvent::default(); 1];
            for _ in 0..REDIRTY_N {
                c.submit1(&cb)?;
                c.get_all(&mut ev)?;
                check(b"write res", ev[0].res == PAGE as i64, ev[0].res)?;
            }
            Ok(())
        })();
        sys_close(fd as u64);
        r
    });
    sys_kill(pid, 9);
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    // The pattern back
    let fd = open(d, hk_syscall::O_RDWR | O_DIRECT)?;
    let b = Buf::new(PAGE)?;
    for (k, v) in b.bytes(0, PAGE).iter_mut().enumerate() {
        *v = pat(RD_PAGE + k as u64);
    }
    let w = sys_pwrite64(fd, b.p, PAGE as u64, RD_PAGE as i64);
    sys_close(fd as u64);
    r?;
    check(b"restore", w == PAGE as i64, w)
}

const MNT: &[u8] = b"/tmp/aio_vfat\0";
const FILE: &[u8] = b"/tmp/aio_vfat/aio.dat\0";

fn vfat(p1: &BlkDev) -> R {
    let mut p = [0u8; 48];
    sys_mkdir(MNT.as_ptr(), 0o755);
    let m = sys_mount(
        p1.path(&mut p).as_ptr(),
        MNT.as_ptr(),
        b"vfat\0".as_ptr(),
        0,
        b"iocharset=cp437\0".as_ptr() as u64,
    );
    check(b"mount", m == 0, m)?;
    let r = vfat_io();
    sys_unlink(FILE.as_ptr());
    report_r(b"AIO_VFAT_APPEND", append(false));
    sys_unlink(FILE.as_ptr());
    report_r(b"AIO_VFAT_DIO_CACHE", dio_cache());
    sys_unlink(FILE.as_ptr());

    sys_umount2(MNT.as_ptr(), 0);
    sys_rmdir(MNT.as_ptr());
    r
}

fn vfat_io() -> R {
    const LEN: usize = 16 * PAGE;
    let fd = sys_open(
        FILE.as_ptr(),
        hk_syscall::O_RDWR | O_CREAT | O_TRUNC | O_DIRECT,
        0o644,
    );
    check(b"open", fd >= 0, fd)?;
    let fd = fd as i32;
    let r = (|| {
        let c = Ctx::new(32)?;
        let b = Buf::new(LEN + PAGE)?;
        for (k, v) in b.bytes(0, LEN).iter_mut().enumerate() {
            *v = (k / PAGE) as u8 ^ 0x3c;
        }
        // Extending: done at once (Linux: no async extending write)
        c.submit1(&iocb(IOCB_CMD_PWRITE, fd, b.addr(0), LEN as u64, 0, 1))?;
        let mut ev = [IoEvent::default(); 16];
        c.get_all(&mut ev[..1])?;
        check(b"extending write", ev[0].res == LEN as i64, ev[0].res)?;
        // Overwrites within the size, page by page
        for i in 0..16 {
            b.bytes(i * PAGE, PAGE).fill(0x80 | i as u8);
        }
        let cbs: [Iocb; 16] = core::array::from_fn(|i| {
            iocb(
                IOCB_CMD_PWRITE,
                fd,
                b.addr(i * PAGE),
                PAGE as u64,
                (i * PAGE) as i64,
                i as u64,
            )
        });
        let ptrs: [*const Iocb; 16] = core::array::from_fn(|i| &cbs[i] as *const Iocb);
        let n = c.submit(&ptrs);
        check(b"overwrites", n == 16, n)?;
        c.get_all(&mut ev)?;
        let mut seen = [false; 16];
        check_events(&ev, &cbs, PAGE as i64, &mut seen)?;
        // Read back by AIO
        let back = Buf::new(LEN + PAGE)?;
        c.submit1(&iocb(IOCB_CMD_PREAD, fd, back.addr(0), LEN as u64, 0, 2))?;
        c.get_all(&mut ev[..1])?;
        check(b"read", ev[0].res == LEN as i64, ev[0].res)?;
        for i in 0..16 {
            let ok = back
                .bytes(i * PAGE, PAGE)
                .iter()
                .all(|&x| x == 0x80 | i as u8);
            check(b"read data", ok, i as i64)?;
        }
        // A buffered reader sees the same
        let bfd = sys_open(FILE.as_ptr(), O_RDONLY, 0);
        check(b"open buffered", bfd >= 0, bfd)?;
        back.bytes(0, LEN).fill(0);
        let n = sys_pread64(bfd as i32, back.p, LEN as u64, 0);
        sys_close(bfd as u64);
        check(b"buffered read", n == LEN as i64, n)?;
        let ok = (0..16).all(|i| {
            back.bytes(i * PAGE, PAGE)
                .iter()
                .all(|&x| x == 0x80 | i as u8)
        });
        check(b"buffered data", ok, 0)?;
        // At the end: 0; misaligned memory: EINVAL
        c.submit1(&iocb(
            IOCB_CMD_PREAD,
            fd,
            back.addr(0),
            PAGE as u64,
            LEN as i64,
            3,
        ))?;
        c.get_all(&mut ev[..1])?;
        check(b"read at end", ev[0].res == 0, ev[0].res)?;
        c.submit1(&iocb(IOCB_CMD_PREAD, fd, back.addr(1), PAGE as u64, 0, 4))?;
        c.get_all(&mut ev[..1])?;
        check(b"misaligned", ev[0].res == EINVAL, ev[0].res)
    })();
    sys_close(fd as u64);
    r
}

const RWF_APPEND: i32 = 0x10;
const RWF_NOAPPEND: i32 = 0x20;
const APPEND_PAGES: usize = 16;

/// One page of `b` written at `off` of `fd` with RWF_* `rwf`, by AIO or
/// io_uring (`uring`): its result
fn write_rwf(
    fd: i32,
    b: &Buf,
    off: u64,
    rwf: i32,
    uring: bool,
) -> Result<i64, (&'static [u8], i64)> {
    if uring {
        let mut r = crate::uring::Ring::simple(4).map_err(|e| (&b"ring"[..], e))?;
        let mut q = crate::uring::sqe(
            hk_syscall::IORING_OP_WRITE,
            fd,
            b.addr(0),
            PAGE as u32,
            off,
            1,
        );
        q.op_flags = rwf as u32;
        r.push(q);
        let n = r.submit_wait(1, 1);
        check(b"io_uring_enter", n == 1, n)?;
        let c = r.pop().ok_or((&b"no cqe"[..], 0))?;
        return Ok(i64::from(c.res));
    }
    let c = Ctx::new(4)?;
    let mut cb = iocb(IOCB_CMD_PWRITE, fd, b.addr(0), PAGE as u64, off as i64, 1);
    cb.rw_flags = rwf;
    c.submit1(&cb)?;
    let mut ev = [IoEvent::default(); 1];
    c.get_all(&mut ev)?;
    Ok(ev[0].res)
}

/// The file's size
fn size_of(fd: i32) -> i64 {
    let off = hk_syscall::sys_lseek(fd, 0, hk_syscall::SEEK_END);
    hk_syscall::sys_lseek(fd, 0, hk_syscall::SEEK_SET);
    off
}

/// Page `i` of FILE holds `v` (a buffered read)
fn page_is(i: usize, v: u8) -> Result<bool, (&'static [u8], i64)> {
    let b = Buf::new(PAGE)?;
    let fd = sys_open(FILE.as_ptr(), O_RDONLY, 0);
    check(b"open buffered", fd >= 0, fd)?;
    let n = sys_pread64(fd as i32, b.p, PAGE as u64, (i * PAGE) as i64);
    sys_close(fd as u64);
    check(b"pread", n == PAGE as i64, n)?;
    Ok(b.bytes(0, PAGE).iter().all(|&x| x == v))
}

fn append(uring: bool) -> R {
    let fl = hk_syscall::O_RDWR | O_CREAT | O_TRUNC | O_DIRECT;
    let fd = sys_open(FILE.as_ptr(), fl, 0o644);
    check(b"open", fd >= 0, fd)?;
    let fd = fd as i32;
    let r = (|| {
        let b = Buf::new(APPEND_PAGES * PAGE)?;
        b.bytes(0, APPEND_PAGES * PAGE).fill(0x11);
        let n = hk_syscall::sys_pwrite64(fd, b.p, (APPEND_PAGES * PAGE) as u64, 0);
        check(b"fill", n == (APPEND_PAGES * PAGE) as i64, n)?;
        // RWF_APPEND at offset 0: to the end
        b.bytes(0, PAGE).fill(0x22);
        let n = write_rwf(fd, &b, 0, RWF_APPEND, uring)?;
        check(b"RWF_APPEND res", n == PAGE as i64, n)?;
        let sz = size_of(fd);
        check(
            b"RWF_APPEND size",
            sz == ((APPEND_PAGES + 1) * PAGE) as i64,
            sz,
        )?;
        check(b"page 0 kept", page_is(0, 0x11)?, 0)?;
        check(b"appended page", page_is(APPEND_PAGES, 0x22)?, 0)?;
        // RWF_NOAPPEND on an O_APPEND file: at the offset (Linux 6.9
        // on: the 6.8 references have no RWF_NOAPPEND, EOPNOTSUPP)
        if !crate::helpers::linux_at_least(6, 9) {
            return Ok(());
        }
        let afd = sys_open(
            FILE.as_ptr(),
            fl & !(O_CREAT | O_TRUNC) | hk_syscall::O_APPEND,
            0,
        );
        check(b"open O_APPEND", afd >= 0, afd)?;
        b.bytes(0, PAGE).fill(0x33);
        let n = write_rwf(afd as i32, &b, PAGE as u64, RWF_NOAPPEND, uring);
        let sz = size_of(afd as i32);
        sys_close(afd as u64);
        let n = n?;
        check(b"RWF_NOAPPEND res", n == PAGE as i64, n)?;
        check(
            b"RWF_NOAPPEND size",
            sz == ((APPEND_PAGES + 1) * PAGE) as i64,
            sz,
        )?;
        check(b"page 1 written", page_is(1, 0x33)?, 0)
    })();
    sys_close(fd as u64);
    r
}

/// Pages of the cache test's file and async write
const CACHE_PAGES: usize = 1024;
/// Most rounds of the race
const CACHE_ROUNDS: usize = 64;

/// One round: the file all `old`, an async O_DIRECT write of all `new`
/// raced by a buffered read of its last page; after the event, a
/// buffered read finds `new`. True if the racing read came while the
/// write was in flight and cached the old data.
fn cache_round(fd: i32, c: &Ctx, b: &Buf, old: u8, new: u8) -> Result<bool, (&'static [u8], i64)> {
    let len = CACHE_PAGES * PAGE;
    b.bytes(0, len).fill(old);
    let n = hk_syscall::sys_pwrite64(fd, b.p, len as u64, 0);
    check(b"fill", n == len as i64, n)?;
    b.bytes(0, len).fill(new);
    let bfd = sys_open(FILE.as_ptr(), O_RDONLY, 0);
    check(b"open buffered", bfd >= 0, bfd)?;
    let one = Buf::new(PAGE)?;
    let r = (|| {
        c.submit1(&iocb(IOCB_CMD_PWRITE, fd, b.addr(0), len as u64, 0, 1))?;
        // Often while the write is in flight: caches the old data
        sys_pread64(bfd as i32, one.p, PAGE as u64, (len - PAGE) as i64);
        // The race won: read before the write's event, the old data
        let raced = c.ready() == 0 && one.bytes(0, 1)[0] == old;
        let mut ev = [IoEvent::default(); 1];
        c.get_all(&mut ev)?;
        check(b"write res", ev[0].res == len as i64, ev[0].res)?;
        let n = sys_pread64(bfd as i32, one.p, PAGE as u64, (len - PAGE) as i64);
        check(b"buffered read", n == PAGE as i64, n)?;
        let ok = one.bytes(0, PAGE).iter().all(|&x| x == new);
        check(
            b"stale cache after the write",
            ok,
            i64::from(one.bytes(0, 1)[0]),
        )?;
        Ok(raced)
    })();
    sys_close(bfd as u64);
    r
}

fn dio_cache() -> R {
    let fd = sys_open(
        FILE.as_ptr(),
        hk_syscall::O_RDWR | O_CREAT | O_TRUNC | O_DIRECT,
        0o644,
    );
    check(b"open", fd >= 0, fd)?;
    let fd = fd as i32;
    let r = (|| {
        let c = Ctx::new(4)?;
        let b = Buf::new(CACHE_PAGES * PAGE)?;
        // Until the race is won once (a few rounds on KVM), at most
        // CACHE_ROUNDS
        for i in 0..CACHE_ROUNDS {
            let i = i as u8;
            if cache_round(fd, &c, &b, 0x40 | i, 0x80 | i)? {
                break;
            }
        }
        Ok(())
    })();
    sys_close(fd as u64);
    r
}

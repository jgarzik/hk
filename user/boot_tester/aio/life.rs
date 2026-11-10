//! An AIO context's end and inheritance:
//! - AIO_DESTROY_INFLIGHT: io_destroy with 32 1 MiB O_DIRECT reads in
//!   flight returns once they ended (the buffers hold the data at its
//!   return: Linux waits so the kernel is off user memory), and aio-nr
//!   drops
//! - AIO_EXIT_INFLIGHT: a child exiting with reads in flight is reaped
//!   (Linux exit_aio waits for them), and its context leaves aio-nr
//! - AIO_CLOSE_INFLIGHT: the descriptor closed with 32 O_DIRECT reads
//!   in flight (the requests hold the file's last references, dropped
//!   where the bios end): every event comes, with the data, and the
//!   file is released soon after (its flock lock goes: Linux
//!   delayed_fput)
//! - AIO_FORK: MADV_DOFORK of the ring is EINVAL (VM_DONTEXPAND is
//!   VM_SPECIAL, Linux 7.0 on); a fork child has no ring at the context's address
//!   (VM_DONTCOPY, Linux 7.1 on) and no context there (EINVAL); where
//!   it inherits the ring (older Linux) mremap of it is EINVAL (the
//!   ring is no context of the child's); the parent's still works at
//!   the same address

use super::*;
use crate::harness::{R, check, report_r};
use crate::helpers::{BlkDev, find_blkdev, linux_at_least, msleep};
use crate::uring::dio::{Buf, is_pat, open};
use hk_syscall::{
    MADV_DOFORK, MAP_ANONYMOUS, MAP_PRIVATE, MREMAP_FIXED, MREMAP_MAYMOVE, O_RDONLY, PROT_READ,
    sys_exit, sys_flock, sys_fork, sys_kill, sys_madvise, sys_mincore, sys_mmap, sys_mremap,
    sys_unlink, sys_wait4,
};

const O_DIRECT: u32 = hk_syscall::O_DIRECT;
const ENOMEM: i64 = -12;
const MIB: usize = 1 << 20;
const N: usize = 32;

pub fn run_tests() {
    let Some(p3) = find_blkdev(b"vd", 16384) else {
        report_r(b"AIO_LIFE", check(b"no vda3", false, 0));
        return;
    };
    report_r(b"AIO_DESTROY_INFLIGHT", destroy(&p3));
    report_r(b"AIO_EXIT_INFLIGHT", exit(&p3));
    report_r(b"AIO_CLOSE_INFLIGHT", close_inflight(&p3));
    report_r(b"AIO_FORK", fork());
}

/// Submit `N` 1 MiB reads of vda3's first `N` MiB... wrapped at 7 MiB,
/// into `b`
fn reads(c: &Ctx, fd: i32, b: &Buf, cbs: &mut [Iocb; N]) -> R {
    for (i, cb) in cbs.iter_mut().enumerate() {
        *cb = iocb(
            IOCB_CMD_PREAD,
            fd,
            b.addr(i * MIB),
            MIB as u64,
            ((i % 7) * MIB) as i64,
            i as u64,
        );
    }
    let ptrs: [*const Iocb; N] = core::array::from_fn(|i| &cbs[i] as *const Iocb);
    let n = c.submit(&ptrs);
    check(b"io_submit", n == N as i64, n)
}

fn destroy(d: &BlkDev) -> R {
    let fd = open(d, O_RDONLY | O_DIRECT)?;
    let r = (|| {
        let base = sysctl(b"aio-nr\0");
        let c = Ctx::new(64)?;
        let b = Buf::new(N * MIB)?;
        let mut cbs = [Iocb::default(); N];
        reads(&c, fd, &b, &mut cbs)?;
        let r = sys_io_destroy(c.0);
        c.forget();
        check(b"io_destroy", r == 0, r)?;
        for i in 0..N {
            let ok = is_pat(b.bytes(i * MIB, MIB), ((i % 7) * MIB) as u64);
            check(b"data at return", ok, i as i64)?;
        }
        let nr = sysctl(b"aio-nr\0");
        check(b"aio-nr back", nr == base, nr)
    })();
    sys_close(fd as u64);
    r
}

const LOCK_EX: i32 = 2;
const LOCK_NB: i32 = 4;

fn close_inflight(d: &BlkDev) -> R {
    let fd = open(d, O_RDONLY | O_DIRECT)?;
    let l = sys_flock(fd, LOCK_EX);
    if l != 0 {
        sys_close(fd as u64);
        return check(b"flock", false, l);
    }
    let c = Ctx::new(64)?;
    let b = Buf::new(N * MIB)?;
    let mut cbs = [Iocb::default(); N];
    let r = reads(&c, fd, &b, &mut cbs);
    sys_close(fd as u64);
    r?;
    let mut ev = [IoEvent::default(); N];
    c.get_all(&mut ev)?;
    for e in &ev {
        check(b"event res", e.res == MIB as i64, e.res)?;
        let i = e.data as usize;
        let ok = is_pat(b.bytes(i * MIB, MIB), ((i % 7) * MIB) as u64);
        check(b"data", ok, i as i64)?;
    }
    // The last reference's release comes a tick or so later
    let fd2 = open(d, O_RDONLY)?;
    let mut got = -1;
    for _ in 0..200 {
        got = sys_flock(fd2, LOCK_EX | LOCK_NB);
        if got == 0 {
            break;
        }
        msleep(5);
    }
    sys_close(fd2 as u64);
    check(b"file released (flock free)", got == 0, got)
}

/// In a child: reads in flight, then exit without io_destroy
fn exit_child(d: &BlkDev) -> u64 {
    let Ok(fd) = open(d, O_RDONLY | O_DIRECT) else {
        return 1;
    };
    let Ok(c) = Ctx::new(64) else { return 2 };
    let Ok(b) = Buf::new(N * MIB) else { return 3 };
    let mut cbs = [Iocb::default(); N];
    if reads(&c, fd, &b, &mut cbs).is_err() {
        return 4;
    }
    c.forget();
    core::mem::forget(b);
    0
}

fn exit(d: &BlkDev) -> R {
    let base = sysctl(b"aio-nr\0");
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(exit_child(d));
    }
    check(b"fork", pid > 0, pid)?;
    let mut st = 0;
    for _ in 0..500 {
        if sys_wait4(pid, &mut st, 1, 0) == pid {
            check(b"child status", st >> 8 == 0, i64::from(st >> 8))?;
            let nr = sysctl(b"aio-nr\0");
            return check(b"aio-nr back", nr == base, nr);
        }
        msleep(10);
    }
    sys_kill(pid, 9);
    sys_wait4(pid, &mut st, 0, 0);
    check(b"child never reaped", false, 0)
}

const FORKFILE: &[u8] = b"/tmp/aio_fork\0";

/// In the fork child: nothing mapped at `id` (unless `inherit`), no
/// context there; an inherited `len`-byte ring there cannot be moved
fn fork_child(id: u64, len: u64, inherit: bool) -> u64 {
    let mut v = [0u8; 1];
    let m = sys_mincore(id, 4096, v.as_mut_ptr());
    if !inherit && m != ENOMEM {
        return 1;
    }
    if sys_io_submit(id, 0, core::ptr::null()) != EINVAL {
        return 2;
    }
    if sys_io_destroy(id) != EINVAL {
        return 3;
    }
    // An inherited ring: moving it is no move of a context (Linux
    // aio_ring_mremap finds none in the child's table)
    if inherit {
        let to = sys_mmap(0, len, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if to < 0 {
            return 4;
        }
        let m = sys_mremap(id, len, len, MREMAP_MAYMOVE | MREMAP_FIXED, to as u64);
        if m != EINVAL {
            return 5;
        }
    }
    0
}

fn fork() -> R {
    let c = Ctx::new(8)?;
    // The ring VMA is VM_DONTCOPY since Linux 7.1 (c03ce4173c7b); the
    // 6.8 references still copy it to the child (with no context there)
    let dontcopy = linux_at_least(7, 1);
    // The ring's bytes: its header and events, whole pages
    let len = (32 + u64::from(c.nr()) * 32).next_multiple_of(4096);
    // Not handed down by MADV_DOFORK either: the ring is VM_SPECIAL
    // (Linux 7.0 on, 0b2758f48f22; the 6.8 references refuse VM_IO only,
    // and hand the ring down anyway)
    let d = sys_madvise(c.0, len, MADV_DOFORK);
    if linux_at_least(7, 0) {
        check(b"MADV_DOFORK of the ring", d == EINVAL, d)?;
    }
    let inherit = !dontcopy || d == 0;
    let pid = sys_fork();
    if pid == 0 {
        let code = fork_child(c.0, len, inherit);
        c.forget();
        sys_exit(code);
    }
    check(b"fork", pid > 0, pid)?;
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    check(b"child", st >> 8 == 0, i64::from(st >> 8))?;
    let fd = tmp_file(FORKFILE)?;
    let r = (|| {
        c.submit1(&iocb(IOCB_CMD_PWRITE, fd, b"ab".as_ptr() as u64, 2, 0, 1))?;
        let mut ev = [IoEvent::default(); 1];
        c.get_all(&mut ev)?;
        check(b"parent's context", ev[0].res == 2, ev[0].res)
    })();
    sys_close(fd as u64);
    sys_unlink(FORKFILE.as_ptr());
    r
}

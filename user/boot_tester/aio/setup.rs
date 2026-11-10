//! AIO_SETUP: io_setup's errnos and limits (Linux ioctx_alloc,
//! aio_setup_ring), the ring's header read from user space (magic,
//! features, header length, size), aio-nr accounting and aio-max-nr
//! (EAGAIN past it), and the errnos of the other calls on bad contexts
//! and arguments
//! AIO_MREMAP: mremap moves the ring and with it the context id (Linux
//! aio_ring_mremap); growing it is EFAULT (VM_DONTEXPAND)

use super::*;
use crate::harness::{R, check, report_r};
use hk_syscall::{
    MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE, sys_io_cancel, sys_mmap, sys_mremap,
    sys_munmap,
};

const MREMAP_MAYMOVE: u32 = 1;
const MREMAP_FIXED: u32 = 2;

pub fn run_tests() {
    report_r(b"AIO_SETUP", setup());
    report_r(b"AIO_MREMAP", mremap());
}

fn errnos() -> R {
    let mut id = 0u64;
    let r = sys_io_setup(0, &mut id);
    check(b"0 events", r == EINVAL, r)?;
    let mut id = 1u64;
    let r = sys_io_setup(8, &mut id);
    check(b"ctx not 0", r == EINVAL, r)?;
    let r = sys_io_setup(8, 8 as *mut u64);
    check(b"bad ctxp", r == EFAULT, r)?;
    let mut id = 0u64;
    let r = sys_io_setup(0x1000_0000, &mut id);
    check(b"too many", r == EINVAL, r)?;
    // Doubled, it wraps to 0 (Linux's unsigned arithmetic)
    let r = sys_io_setup(0x8000_0000, &mut id);
    check(b"wrapping", r == EAGAIN, r)?;
    let r = sys_io_destroy(0);
    check(b"destroy 0", r == EINVAL, r)?;
    let mut ev = [IoEvent::default(); 1];
    let r = sys_io_getevents(12345, 0, 1, ev.as_mut_ptr() as u64, 0);
    check(b"getevents bad", r == EINVAL, r)?;
    Ok(())
}

fn header(c: &Ctx, n: u32) -> R {
    check(b"aligned", c.0 % 4096 == 0, c.0 as i64)?;
    let w = |i| i64::from(c.word(i).load(core::sync::atomic::Ordering::Relaxed));
    check(b"magic", w(4) == i64::from(AIO_RING_MAGIC), w(4))?;
    check(b"compat", w(5) == 1, w(5))?;
    check(b"incompat", w(6) == 0, w(6))?;
    check(b"header_length", w(7) == 32, w(7))?;
    check(b"head", w(2) == 0, w(2))?;
    check(b"tail", w(3) == 0, w(3))?;
    let nr = w(1);
    // At least twice what was asked, and whole pages of header + events
    check(b"nr", nr >= 2 * i64::from(n), nr)?;
    check(b"whole pages", (nr + 1) * 32 % 4096 == 0, nr)
}

fn calls(c: &Ctx) -> R {
    let r = sys_io_submit(c.0, -1, core::ptr::null());
    check(b"submit nr<0", r == EINVAL, r)?;
    let r = sys_io_submit(c.0, 0, core::ptr::null());
    check(b"submit 0", r == 0, r)?;
    let mut ev = [IoEvent::default(); 2];
    let r = sys_io_getevents(c.0, 2, 1, ev.as_mut_ptr() as u64, 0);
    check(b"min > nr", r == EINVAL, r)?;
    let r = sys_io_getevents(c.0, -1, 1, ev.as_mut_ptr() as u64, 0);
    check(b"min < 0", r == EINVAL, r)?;
    let cb = Iocb {
        key: 1,
        ..Iocb::default()
    };
    let r = sys_io_cancel(c.0, &cb as *const Iocb as u64, 0);
    check(b"cancel key", r == EINVAL, r)
}

fn setup() -> R {
    errnos()?;
    let base = sysctl(b"aio-nr\0");
    let c = Ctx::new(128)?;
    header(&c, 128)?;
    calls(&c)?;
    let nr = sysctl(b"aio-nr\0");
    check(b"aio-nr counts", nr == base + 128, nr)?;
    // aio-max-nr: one more context of 128 no longer fits
    let max = sysctl(b"aio-max-nr\0");
    check(b"aio-max-nr", max == 0x10000, max)?;
    let w = set_sysctl(b"aio-max-nr\0", nr + 64);
    check(b"set aio-max-nr", w > 0, w)?;
    let mut id = 0u64;
    let r = sys_io_setup(128, &mut id);
    set_sysctl(b"aio-max-nr\0", max);
    check(b"past aio-max-nr", r == EAGAIN, r)?;
    let r = sys_io_destroy(c.0);
    check(b"destroy", r == 0, r)?;
    let again = sys_io_destroy(c.0);
    c.forget();
    check(b"destroy twice", again == EINVAL, again)?;
    let nr = sysctl(b"aio-nr\0");
    check(b"aio-nr back", nr == base, nr)
}

fn mremap() -> R {
    let c = Ctx::new(8)?;
    let len = (u64::from(c.nr()) + 1) * 32;
    let grow = sys_mremap(c.0, len, len + 4096, MREMAP_MAYMOVE, 0);
    check(b"grow", grow == EFAULT, grow)?;
    // A free range to move it onto
    let dst = sys_mmap(
        0,
        len,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    check(b"mmap", dst > 0, dst)?;
    let old = c.0;
    c.forget();
    let m = sys_mremap(old, len, len, MREMAP_MAYMOVE | MREMAP_FIXED, dst as u64);
    if m != dst {
        sys_munmap(dst as u64, len);
    }
    check(b"move", m == dst, m)?;
    let c = Ctx(dst as u64);
    let r = sys_io_submit(old, 0, core::ptr::null());
    check(b"old id", r == EINVAL, r)?;
    let r = sys_io_submit(c.0, 0, core::ptr::null());
    check(b"new id", r == 0, r)?;
    check(
        b"magic moved",
        c.word(4).load(core::sync::atomic::Ordering::Relaxed) == AIO_RING_MAGIC,
        0,
    )?;
    let r = sys_io_destroy(c.0);
    c.forget();
    check(b"destroy", r == 0, r)
}

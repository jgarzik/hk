//! tracefs (Linux fs/tracefs, kernel/trace/trace.c)
//!
//! - TRACEFS_TRACE: /sys/kernel/tracing is the directory to mount
//!   tracefs on; mounted, statfs shows TRACEFS_MAGIC and the `trace`
//!   file starts with the nop tracer's header
//! - TRACEFS_TRUNC: `trace` opens for writing; with O_TRUNC it empties
//!   the buffer (entries 0/0), a write is accepted (Linux tracing_open,
//!   tracing_write_stub)
//! - TRACEFS_EVENTS: events/enable reads 0/1/X; an event's enable file
//!   reads back what was written (1, then 0), its system's enable then
//!   shows X (mixed) and 0, anything but 0/1 is EINVAL (Linux
//!   event_enable_write). On hk, xHCI transfers (a USB disk read,
//!   console output to the USB serial port) record xhci_urb_enqueue
//!   events while it is on, none once it is off

use crate::harness::{R, check, report_r};
use crate::helpers::{host_mode, msleep, read_file, skip};
use hk_syscall::{
    LinuxStatFs, O_DIRECT, O_RDONLY, O_TRUNC, O_WRONLY, sys_close, sys_mount, sys_open,
    sys_pread64, sys_statfs, sys_umount2, sys_write,
};

const MP: &[u8] = b"/sys/kernel/tracing\0";
const TRACE: &[u8] = b"/sys/kernel/tracing/trace\0";
const TRACEFS_MAGIC: i64 = 0x7472_6163;
const ENODEV: i64 = -19;
const ENOENT: i64 = -2;
const HEADER: &[u8] = b"# tracer: nop\n#\n# entries-in-buffer/entries-written: ";

pub fn run_tests() {
    let r = sys_mount(
        b"nodev\0".as_ptr(),
        MP.as_ptr(),
        b"tracefs\0".as_ptr(),
        0,
        0,
    );
    if (r == ENODEV || r == ENOENT) && host_mode() {
        skip(b"TRACEFS_TRACE", b"host kernel without tracefs");
        skip(b"TRACEFS_TRUNC", b"host kernel without tracefs");
        skip(b"TRACEFS_EVENTS", b"host kernel without tracefs");
        return;
    }
    report_r(b"TRACEFS_TRACE", mounted(r));
    if r == 0 {
        report_r(b"TRACEFS_TRUNC", trunc());
        let r = events();
        write_str(EV, b"0");
        report_r(b"TRACEFS_EVENTS", r);
        sys_umount2(MP.as_ptr(), 0);
    }
}

fn mounted(r: i64) -> R {
    check(b"mount", r == 0, r)?;
    let mut st = LinuxStatFs::default();
    let s = sys_statfs(MP.as_ptr(), &mut st);
    check(b"statfs", s == 0, s)?;
    check(b"f_type", st.f_type == TRACEFS_MAGIC, st.f_type)?;
    let mut buf = [0u8; 256];
    let n = read_file(TRACE, &mut buf);
    check(b"read", n >= HEADER.len() as i64, n)?;
    check(b"header", buf.starts_with(HEADER), n)
}

/// The `trace` file's entries-in-buffer/entries-written pair
pub fn entries() -> Option<(u64, u64)> {
    let mut buf = [0u8; 256];
    let n = read_file(TRACE, &mut buf);
    if n < HEADER.len() as i64 || !buf.starts_with(HEADER) {
        return None;
    }
    let rest = &buf[HEADER.len()..n as usize];
    let num = |s: &[u8]| -> (u64, usize) {
        let d = s.iter().take_while(|c| c.is_ascii_digit()).count();
        (
            s[..d].iter().fold(0, |v, c| v * 10 + u64::from(c - b'0')),
            d,
        )
    };
    let (a, d) = num(rest);
    if rest.get(d) != Some(&b'/') {
        return None;
    }
    let (b, _) = num(&rest[d + 1..]);
    Some((a, b))
}

/// Empty the buffer as `echo > trace` does: an O_TRUNC open for writing
pub fn truncate() -> i64 {
    let fd = sys_open(TRACE.as_ptr(), O_WRONLY | O_TRUNC, 0);
    if fd < 0 {
        return fd;
    }
    let w = sys_write(fd as u64, b"\n".as_ptr(), 1);
    sys_close(fd as u64);
    if w == 1 { 0 } else { w - 1000 }
}

fn trunc() -> R {
    let r = truncate();
    check(b"open-trunc+write", r == 0, r)?;
    let e = entries();
    check(
        b"entries",
        e == Some((0, 0)),
        e.map_or(-1, |(a, _)| a as i64),
    )
}

const EINVAL: i64 = -22;
const ALL: &[u8] = b"/sys/kernel/tracing/events/enable\0";
const SYS: &[u8] = b"/sys/kernel/tracing/events/xhci-hcd/enable\0";
const EV: &[u8] = b"/sys/kernel/tracing/events/xhci-hcd/xhci_urb_enqueue/enable\0";

/// Write `data` to `path` in one write(2): its result, or the open's
fn write_str(path: &[u8], data: &[u8]) -> i64 {
    let fd = sys_open(path.as_ptr(), O_WRONLY, 0);
    if fd < 0 {
        return fd;
    }
    let r = sys_write(fd as u64, data.as_ptr(), data.len() as u64);
    sys_close(fd as u64);
    r
}

/// `path` reads exactly `want`
fn reads(path: &[u8], want: &[u8]) -> bool {
    let mut b = [0u8; 8];
    let n = read_file(path, &mut b);
    n == want.len() as i64 && &b[..want.len()] == want
}

/// Make the xHCI work: console output (the USB serial console's bulk
/// OUT) and an O_DIRECT read of the USB disk (bulk IN)
fn xhci_work() {
    write_str(b"/dev/kmsg\0", b"tracefs: xhci work\n");
    let fd = sys_open(b"/dev/sda\0".as_ptr(), O_RDONLY | O_DIRECT, 0);
    if fd < 0 {
        return;
    }
    if let Ok(b) = crate::uring::dio::Buf::new(4096) {
        sys_pread64(fd as i32, b.p, 4096, 0);
    }
    sys_close(fd as u64);
}

/// Entries recorded within about a second
fn entries_soon() -> u64 {
    for _ in 0..20 {
        if let Some((n, _)) = entries()
            && n > 0
        {
            return n;
        }
        msleep(50);
    }
    0
}

fn events() -> R {
    let mut b = [0u8; 8];
    let n = read_file(ALL, &mut b);
    check(
        b"events/enable",
        n == 2 && b"01X".contains(&b[0]) && b[1] == b'\n',
        n,
    )?;
    let mut probe = [0u8; 8];
    if read_file(EV, &mut probe) < 0 && host_mode() {
        // A host kernel without xHCI tracepoints: nothing more to check
        return Ok(());
    }
    check(b"event reads 0", reads(EV, b"0\n"), 0)?;
    let w = write_str(EV, b"1");
    check(b"write 1", w == 1, w)?;
    check(b"event reads 1", reads(EV, b"1\n"), 1)?;
    check(b"system mixed", reads(SYS, b"X\n"), 0)?;
    let w = write_str(EV, b"2");
    check(b"write 2", w == EINVAL, w)?;
    if !host_mode() {
        truncate();
        xhci_work();
        let n = entries_soon();
        check(b"recorded", n > 0, n as i64)?;
    }
    let w = write_str(EV, b"0\n");
    check(b"write 0", w == 2, w)?;
    check(b"event reads 0 again", reads(EV, b"0\n"), 0)?;
    check(b"system off", reads(SYS, b"0\n"), 0)?;
    if !host_mode() {
        msleep(100);
        truncate();
        xhci_work();
        msleep(300);
        let e = entries();
        check(
            b"none once off",
            e == Some((0, 0)),
            e.map_or(-1, |(a, _)| a as i64),
        )?;
    }
    Ok(())
}

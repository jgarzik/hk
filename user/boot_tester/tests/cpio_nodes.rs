//! What the initramfs unpacker makes (Linux init/initramfs.c), from the
//! entries tools/cpio-test.sh puts in the boot archive
//!
//! Tests:
//! - CPIO_EMPTY: an empty file is unpacked (size 0)
//! - CPIO_HARDLINK: two hard links are one inode (same st_ino, nlink 2)
//!   with the body, which cpio stores with the last name
//! - CPIO_FIFO: a FIFO entry is a FIFO
//! - CPIO_CONCAT: a character device from a second, concatenated archive
//!   is unpacked (1:3, usable like /dev/null)
//! - CPIO_OVERLAY: a file in the second archive replaces the same name
//!   from the first (Linux opens it O_TRUNC)

use super::helpers::{print, println};
use hk_syscall::{O_RDONLY, O_WRONLY, Stat, sys_close, sys_open, sys_read, sys_stat, sys_write};

const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFIFO: u32 = 0o010000;
const S_IFCHR: u32 = 0o020000;

pub fn run_tests() {
    empty();
    hardlink();
    fifo();
    concat();
    overlay();
}

fn overlay() {
    let mut b = [0u8; 32];
    let n = read_all(b"/cpio_test/overlay\0", &mut b);
    report(
        b"CPIO_OVERLAY",
        if n == 8 && &b[..8] == b"overlay\n" {
            b""
        } else {
            b"not replaced"
        },
    );
}

fn report(name: &[u8], why: &[u8]) {
    print(name);
    if why.is_empty() {
        println(b":OK");
    } else {
        print(b":FAIL ");
        println(why);
    }
}

fn stat(path: &[u8]) -> Option<Stat> {
    // SAFETY: plain integers
    let mut st: Stat = unsafe { core::mem::zeroed() };
    (sys_stat(path.as_ptr(), &mut st) == 0).then_some(st)
}

fn read_all(path: &[u8], buf: &mut [u8]) -> i64 {
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        return fd;
    }
    let n = sys_read(fd as u64, buf.as_mut_ptr(), buf.len() as u64);
    sys_close(fd as u64);
    n
}

fn empty() {
    let why: &[u8] = match stat(b"/cpio_test/empty\0") {
        None => b"missing",
        Some(st) if st.st_mode & S_IFMT != S_IFREG || st.st_size != 0 => b"not an empty file",
        Some(_) => b"",
    };
    report(b"CPIO_EMPTY", why);
}

fn hardlink() {
    let (Some(a), Some(b)) = (stat(b"/cpio_test/link1\0"), stat(b"/cpio_test/link2\0")) else {
        return report(b"CPIO_HARDLINK", b"missing");
    };
    if a.st_ino != b.st_ino || a.st_nlink != 2 {
        return report(b"CPIO_HARDLINK", b"not one inode");
    }
    let mut x = [0u8; 16];
    let mut y = [0u8; 16];
    let nx = read_all(b"/cpio_test/link1\0", &mut x);
    let ny = read_all(b"/cpio_test/link2\0", &mut y);
    let ok = nx == 7 && ny == 7 && &x[..7] == b"linked\n" && x == y;
    report(b"CPIO_HARDLINK", if ok { b"" } else { b"body" });
}

fn fifo() {
    let why: &[u8] = match stat(b"/cpio_test/fifo\0") {
        Some(st) if st.st_mode & S_IFMT == S_IFIFO => b"",
        Some(_) => b"not a fifo",
        None => b"missing",
    };
    report(b"CPIO_FIFO", why);
}

fn concat() {
    let Some(st) = stat(b"/cpio_test/null\0") else {
        return report(b"CPIO_CONCAT", b"missing");
    };
    let major = (st.st_rdev >> 8) & 0xfff;
    let minor = (st.st_rdev & 0xff) | ((st.st_rdev >> 12) & 0xfff00);
    if st.st_mode & S_IFMT != S_IFCHR || (major, minor) != (1, 3) {
        return report(b"CPIO_CONCAT", b"not char 1:3");
    }
    let fd = sys_open(b"/cpio_test/null\0".as_ptr(), O_WRONLY, 0);
    let w = sys_write(fd as u64, b"x".as_ptr(), 1);
    sys_close(fd as u64);
    report(b"CPIO_CONCAT", if fd >= 0 && w == 1 { b"" } else { b"write" });
}

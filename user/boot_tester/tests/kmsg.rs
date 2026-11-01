//! /dev/kmsg and syslog(2) reads (Linux kernel/printk/printk.c)
//!
//! Tests:
//! - KMSG_WRITE_READ: after SEEK_END, a written `<5>text\n` comes back as
//!   one record `13,seq,usec,...;text\n` (facility 0 becomes LOG_USER),
//!   then a nonblocking read is EAGAIN
//! - KMSG_FACILITY: `<256>` is facility 32 (pri 256), not wrapped into
//!   facility 0 (a kernel message)
//! - KMSG_SEEK: a read into a buffer smaller than the first record is
//!   EINVAL; lseek with a nonzero offset is ESPIPE, SEEK_CUR is EINVAL
//! - KMSG_SYSLOG: syslog READ_ALL returns `<pri>[` lines including the
//!   record written; SIZE_BUFFER is positive
//! - KMSG_RESTRICT: without CAP_SYSLOG (dmesg_restrict = 1, Ubuntu's
//!   kernel default) opening /dev/kmsg to read and every syslog action
//!   (READ_ALL, SIZE_UNREAD, SIZE_BUFFER) are EPERM (a write-only open
//!   is EACCES only by the node's 0644 mode)

use super::helpers::{print, print_num, println};
use hk_syscall::{
    O_NONBLOCK, O_RDONLY, O_RDWR, O_WRONLY, sys_close, sys_exit, sys_fork, sys_lseek, sys_open,
    sys_read, sys_setresuid, sys_syslog, sys_wait4, sys_write,
};

const EAGAIN: i64 = -11;
const EINVAL: i64 = -22;
const ESPIPE: i64 = -29;
const SEEK_SET: i32 = 0;
const SEEK_CUR: i32 = 1;
const SEEK_END: i32 = 2;
const SYSLOG_ACTION_READ_ALL: i32 = 3;
const SYSLOG_ACTION_SIZE_UNREAD: i32 = 9;
const SYSLOG_ACTION_SIZE_BUFFER: i32 = 10;
const EPERM: i64 = -1;
const EACCES: i64 = -13;
const TEXT: &[u8] = b"hk kmsg test record 4711";

pub fn run_tests() {
    let fd = sys_open(b"/dev/kmsg\0".as_ptr(), O_RDWR | O_NONBLOCK, 0) as i32;
    if fd < 0 {
        report(b"KMSG_WRITE_READ", b"open", fd as i64);
        return;
    }
    write_read(fd);
    facility(fd);
    seek(fd);
    sys_close(fd as u64);
    syslog();
    restrict();
}

/// As nobody, in a child: exit status is the first failed step
fn restrict() {
    let pid = sys_fork();
    if pid == 0 {
        if sys_setresuid(65534, 65534, 65534) != 0 {
            sys_exit(1);
        }
        let r = sys_open(b"/dev/kmsg\0".as_ptr(), O_RDONLY, 0);
        if r != EPERM {
            sys_exit(2);
        }
        // Write-only is not restricted, but the node is 0644 root
        let w = sys_open(b"/dev/kmsg\0".as_ptr(), O_WRONLY, 0);
        if w != EACCES {
            sys_exit(3);
        }
        let mut b = [0u8; 64];
        if sys_syslog(SYSLOG_ACTION_READ_ALL, b.as_mut_ptr(), 64) != EPERM {
            sys_exit(4);
        }
        if sys_syslog(SYSLOG_ACTION_SIZE_UNREAD, core::ptr::null_mut(), 0) != EPERM {
            sys_exit(5);
        }
        if sys_syslog(SYSLOG_ACTION_SIZE_BUFFER, core::ptr::null_mut(), 0) != EPERM {
            sys_exit(6);
        }
        sys_exit(0);
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    let step = if st & 0x7f == 0 { (st >> 8) & 0xff } else { 100 };
    report(b"KMSG_RESTRICT", if step == 0 { b"" } else { b"step" }, step as i64);
}

fn report(name: &[u8], why: &[u8], detail: i64) {
    print(name);
    if why.is_empty() {
        println(b":OK");
    } else {
        print(b":FAIL ");
        print(why);
        print(b" ");
        print_num(detail);
        println(b"");
    }
}

fn find(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn write_read(fd: i32) {
    let n = b"KMSG_WRITE_READ";
    if sys_lseek(fd, 0, SEEK_END) != 0 {
        return report(n, b"seek end", 0);
    }
    let mut msg = [0u8; 64];
    msg[..3].copy_from_slice(b"<5>");
    msg[3..3 + TEXT.len()].copy_from_slice(TEXT);
    // A newline ends the record (Linux keeps a record without one open
    // for continuation, unseen by readers)
    msg[3 + TEXT.len()] = b'\n';
    let len = 4 + TEXT.len();
    let w = sys_write(fd as u64, msg.as_ptr(), len as u64);
    if w != len as i64 {
        return report(n, b"write", w);
    }
    let mut buf = [0u8; 512];
    let r = sys_read(fd as u64, buf.as_mut_ptr(), buf.len() as u64);
    if r <= 0 {
        return report(n, b"read", r);
    }
    let rec = &buf[..r as usize];
    let mut tail = [0u8; 64];
    tail[0] = b';';
    tail[1..1 + TEXT.len()].copy_from_slice(TEXT);
    tail[1 + TEXT.len()] = b'\n';
    if !rec.starts_with(b"13,") || !rec.ends_with(&tail[..TEXT.len() + 2]) {
        return report(n, b"record", r);
    }
    let again = sys_read(fd as u64, buf.as_mut_ptr(), buf.len() as u64);
    if again != EAGAIN {
        return report(n, b"not EAGAIN at end", again);
    }
    report(n, b"", 0);
}

fn facility(fd: i32) {
    let n = b"KMSG_FACILITY";
    sys_lseek(fd, 0, SEEK_END);
    let msg = b"<256>hk kmsg facility\n";
    if sys_write(fd as u64, msg.as_ptr(), msg.len() as u64) != msg.len() as i64 {
        return report(n, b"write", 0);
    }
    let mut buf = [0u8; 256];
    let r = sys_read(fd as u64, buf.as_mut_ptr(), buf.len() as u64);
    if r <= 0 || !buf.starts_with(b"256,") {
        return report(n, b"pri", r);
    }
    report(n, b"", 0);
}

fn seek(fd: i32) {
    let n = b"KMSG_SEEK";
    if sys_lseek(fd, 0, SEEK_SET) != 0 {
        return report(n, b"seek set", 0);
    }
    let mut small = [0u8; 4];
    let r = sys_read(fd as u64, small.as_mut_ptr(), 4);
    if r != EINVAL {
        return report(n, b"small read not EINVAL", r);
    }
    let r = sys_lseek(fd, 1, SEEK_SET);
    if r != ESPIPE {
        return report(n, b"offset not ESPIPE", r);
    }
    let r = sys_lseek(fd, 0, SEEK_CUR);
    if r != EINVAL {
        return report(n, b"SEEK_CUR not EINVAL", r);
    }
    report(n, b"", 0);
}

fn syslog() {
    let n = b"KMSG_SYSLOG";
    static mut BUF: [u8; 1 << 17] = [0; 1 << 17];
    // SAFETY: the boot tester is single-threaded here
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
    let size = sys_syslog(SYSLOG_ACTION_SIZE_BUFFER, core::ptr::null_mut(), 0);
    if size <= 0 {
        return report(n, b"size buffer", size);
    }
    let r = sys_syslog(SYSLOG_ACTION_READ_ALL, buf.as_mut_ptr(), buf.len() as i32);
    if r <= 0 {
        return report(n, b"read all", r);
    }
    let all = &buf[..r as usize];
    if !all.starts_with(b"<") || !find(all, b">[") || !find(all, TEXT) {
        return report(n, b"content", r);
    }
    report(n, b"", 0);
}

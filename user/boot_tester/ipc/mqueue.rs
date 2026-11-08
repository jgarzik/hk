//! POSIX Message Queue tests
//!
//! Tests:
//! - Test mq_open creates a new queue
//! - Test mq_open opens existing queue
//! - Test mq_open with O_CREAT|O_EXCL returns EEXIST
//! - Test mq_open without O_CREAT returns ENOENT
//! - Test mq_unlink removes queue
//! - Test mq_send and mq_receive
//! - Test mq_priority ordering
//! - Test mq_nonblock returns EAGAIN
//! - Test mq_getsetattr
//! - Test mq_close fd
//! - Test mq_emsgsize
//! - MQ_NOTIFY_OWNER_EXIT: a child's registration on an inherited
//!   descriptor ends when it exits (Linux mqueue_flush_file on its
//!   close), so the parent may register (no EBUSY)
//! - MQ_LEN_UNSIGNED: message lengths compare as size_t: a send of
//!   SIZE_MAX bytes is EMSGSIZE, a receive into SIZE_MAX bytes is not
//! - MQ_RLIMIT: a queue charges its creator's real uid maxmsg * (msgsize
//!   + overhead) bytes against RLIMIT_MSGQUEUE (EMFILE past it), and an
//!   unprivileged user meets queues_max (ENOSPC) (Linux
//!   mqueue_get_inode, mqueue_create_attr)

use crate::harness::{fail_num, pass};
use crate::helpers::{print, print_num, println};
use hk_syscall::{
    MqAttr, O_CREAT, O_EXCL, O_NONBLOCK, O_RDWR, sys_close, sys_mq_getsetattr, sys_mq_open,
    sys_mq_timedreceive, sys_mq_timedsend, sys_mq_unlink, sys_read, sys_write,
};

// Error codes
const ENOENT: i64 = -2;
const EBADF: i64 = -9;
const EAGAIN: i64 = -11;
const EEXIST: i64 = -17;
const EINVAL: i64 = -22;
const EACCES: i64 = -13;
const EMSGSIZE: i64 = -90;

// Access modes for future tests
#[allow(dead_code)]
const O_RDONLY: i32 = 0;
#[allow(dead_code)]
const O_WRONLY: i32 = 1;

/// Run all mqueue tests
pub fn run_tests() {
    test_mq_open_create();
    test_mq_open_existing();
    test_mq_open_excl();
    test_mq_open_enoent();
    test_mq_unlink();
    test_mq_send_receive();
    test_mq_priority_ordering();
    test_mq_nonblock_eagain();
    test_mq_getsetattr();
    test_mq_close_fd();
    test_mq_emsgsize();
    test_mq_name_slash();
    test_mq_name_toolong();
    test_mq_attr_limits();
    test_mq_notify_owner_exit();
    test_mq_read_status();
    test_mq_len_unsigned();
    test_mq_rlimit();
}

fn test_mq_len_unsigned() {
    let name = b"mq_len_unsigned\0";
    let attr = MqAttr::new(4, 64);
    let flags = O_RDWR as i32 | O_CREAT as i32 | O_NONBLOCK as i32;
    let fd = sys_mq_open(name.as_ptr(), flags, 0o600, &attr) as i32;
    let b = [0u8; 8];
    let s = sys_mq_timedsend(fd, b.as_ptr(), usize::MAX, 0, core::ptr::null());
    let mut rb = [0u8; 64];
    let r = sys_mq_timedreceive(
        fd,
        rb.as_mut_ptr(),
        usize::MAX,
        core::ptr::null_mut(),
        core::ptr::null(),
    );
    sys_close(fd as u64);
    sys_mq_unlink(name.as_ptr());
    crate::harness::verdict(
        b"MQ_LEN_UNSIGNED",
        fd >= 0 && s == EMSGSIZE && r == EAGAIN,
        s * 1000 + r,
    );
}

/// In a child as uid 4242: [the 1st and 2nd default queue under a
/// 100000-byte RLIMIT_MSGQUEUE, the first refusal among 300 tiny
/// queues, how many came before it]
fn mq_rlimit_child() -> i64 {
    use hk_syscall::{RLIMIT_MSGQUEUE, RLimit, sys_setresuid, sys_setrlimit};
    let lim = RLimit {
        rlim_cur: 100_000,
        rlim_max: 100_000,
    };
    if sys_setrlimit(RLIMIT_MSGQUEUE, &lim) != 0 || sys_setresuid(4242, 4242, 4242) != 0 {
        return 1;
    }
    let flags = O_RDWR as i32 | O_CREAT as i32;
    // One default queue (10 * (8192 + 96) = 82880 bytes) fits, two not
    let a = sys_mq_open(b"mq_rl_a\0".as_ptr(), flags, 0o600, core::ptr::null());
    let b = sys_mq_open(b"mq_rl_b\0".as_ptr(), flags, 0o600, core::ptr::null());
    sys_mq_unlink(b"mq_rl_a\0".as_ptr());
    sys_mq_unlink(b"mq_rl_b\0".as_ptr());
    if a < 0 || b != -24 {
        return 2;
    }
    sys_close(a as u64);
    // queues_max (256 in the namespace): tiny queues until refused
    let attr = MqAttr::new(1, 1);
    let mut name = *b"mq_rl_000\0";
    let mut first_err = 0;
    let mut made = 0;
    for i in 0..300u32 {
        name[6] = b'0' + (i / 100) as u8;
        name[7] = b'0' + (i / 10 % 10) as u8;
        name[8] = b'0' + (i % 10) as u8;
        let fd = sys_mq_open(name.as_ptr(), flags, 0o600, &attr);
        if fd < 0 {
            first_err = fd;
            break;
        }
        sys_close(fd as u64);
        made += 1;
    }
    for i in 0..made {
        name[6] = b'0' + (i / 100) as u8;
        name[7] = b'0' + (i / 10 % 10) as u8;
        name[8] = b'0' + (i % 10) as u8;
        sys_mq_unlink(name.as_ptr());
    }
    const ENOSPC: i64 = -28;
    if first_err != ENOSPC || made == 0 || made > 256 {
        return 3;
    }
    0
}

fn test_mq_rlimit() {
    let pid = hk_syscall::sys_fork();
    if pid == 0 {
        hk_syscall::sys_exit(mq_rlimit_child() as u64);
    }
    let mut st = 0i32;
    hk_syscall::sys_wait4(pid, &mut st, 0, 0);
    crate::harness::report_step(
        b"MQ_RLIMIT",
        i64::from(st >> 8) + i64::from(st & 0x7f) * 100,
    );
}

/// SIGEV_NONE on `fd`: mq_notify's result
fn notify_none(fd: i32) -> i64 {
    let sev = hk_syscall::SigEvent {
        sigev_notify: 1, // SIGEV_NONE
        ..hk_syscall::SigEvent::default()
    };
    hk_syscall::sys_mq_notify(fd, &sev)
}

fn test_mq_notify_owner_exit() {
    let name = b"test_mq_notify_exit\0";
    let attr = MqAttr::new(4, 64);
    let fd = sys_mq_open(name.as_ptr(), O_RDWR as i32 | O_CREAT as i32, 0o600, &attr) as i32;
    if fd < 0 {
        println(b"MQ_NOTIFY_OWNER_EXIT:FAIL open");
        return;
    }
    let pid = hk_syscall::sys_fork();
    if pid == 0 {
        hk_syscall::sys_exit(if notify_none(fd) == 0 { 0 } else { 1 });
    }
    let mut st = 0i32;
    hk_syscall::sys_wait4(pid, &mut st, 0, 0);
    let r = notify_none(fd);
    if st == 0 && r == 0 {
        pass(b"MQ_NOTIFY_OWNER_EXIT");
    } else {
        print(b"MQ_NOTIFY_OWNER_EXIT:FAIL child status ");
        print_num(st as i64);
        print(b" parent ");
        print_num(r);
        println(b"");
    }
    sys_close(fd as u64);
    sys_mq_unlink(name.as_ptr());
}

/// A message size above the hard maximum is rejected before any
/// allocation (Linux mq_attr_ok), so a huge msgsize can never drive a
/// giant kernel allocation. The hard cap applies to everyone, so this
/// runs as root and agrees with Linux.
fn test_mq_attr_limits() {
    let name = b"mq_attr_lim\0";
    let huge = MqAttr {
        mq_flags: 0,
        mq_maxmsg: 10,
        mq_msgsize: (16 * 1024 * 1024) + 1, // one past HARD_MSGSIZEMAX
        mq_curmsgs: 0,
        __reserved: [0; 4],
    };
    let r = sys_mq_open(name.as_ptr(), O_RDWR as i32 | O_CREAT as i32, 0o644, &huge);
    if r >= 0 {
        sys_close(r as u64);
        sys_mq_unlink(name.as_ptr());
    }
    if r == EINVAL as i64 {
        pass(b"MQ_MSGSIZE_LIMIT");
    } else {
        fail_num(b"MQ_MSGSIZE_LIMIT:FAIL r=", r);
    }
}

/// Test mq_open creates a new queue
fn test_mq_open_create() {
    let name = b"test_mq_create\0";

    // Create a new queue
    let attr = MqAttr::new(10, 256);
    let fd = sys_mq_open(name.as_ptr(), O_RDWR as i32 | O_CREAT as i32, 0o644, &attr);

    if fd < 0 {
        print(b"MQ_OPEN_CREATE:FAIL: returned ");
        print_num(fd);
        return;
    }

    // Clean up
    sys_close(fd as u64);
    sys_mq_unlink(name.as_ptr());

    pass(b"MQ_OPEN_CREATE");
}

/// Test mq_open opens existing queue
fn test_mq_open_existing() {
    let name = b"test_mq_existing\0";

    // Create the queue first
    let attr = MqAttr::new(10, 256);
    let fd1 = sys_mq_open(name.as_ptr(), O_RDWR as i32 | O_CREAT as i32, 0o644, &attr);
    if fd1 < 0 {
        print(b"MQ_OPEN_EXISTING:FAIL: create returned ");
        print_num(fd1);
        return;
    }

    // Open the same queue again (without O_CREAT)
    let fd2 = sys_mq_open(name.as_ptr(), O_RDWR as i32, 0, core::ptr::null());
    if fd2 < 0 {
        print(b"MQ_OPEN_EXISTING:FAIL: reopen returned ");
        print_num(fd2);
        sys_close(fd1 as u64);
        sys_mq_unlink(name.as_ptr());
        return;
    }

    // Both should be valid (different fds)
    if fd1 != fd2 && fd2 >= 0 {
        pass(b"MQ_OPEN_EXISTING");
    } else {
        print(b"MQ_OPEN_EXISTING:FAIL: fd1=");
        print_num(fd1);
        print(b" fd2=");
        print_num(fd2);
    }

    sys_close(fd1 as u64);
    sys_close(fd2 as u64);
    sys_mq_unlink(name.as_ptr());
}

/// Test mq_open with O_CREAT|O_EXCL returns EEXIST if queue exists
fn test_mq_open_excl() {
    let name = b"test_mq_excl\0";

    // Create the queue first
    let attr = MqAttr::new(10, 256);
    let fd1 = sys_mq_open(name.as_ptr(), O_RDWR as i32 | O_CREAT as i32, 0o644, &attr);
    if fd1 < 0 {
        print(b"MQ_OPEN_EXCL:FAIL: first create returned ");
        print_num(fd1);
        return;
    }

    // Try to create again with O_EXCL - should fail
    let fd2 = sys_mq_open(
        name.as_ptr(),
        O_RDWR as i32 | O_CREAT as i32 | O_EXCL as i32,
        0o644,
        &attr,
    );
    if fd2 == EEXIST {
        pass(b"MQ_OPEN_EXCL");
    } else {
        print(b"MQ_OPEN_EXCL:FAIL: expected -17, got ");
        print_num(fd2);
    }

    sys_close(fd1 as u64);
    sys_mq_unlink(name.as_ptr());
}

/// Test mq_open without O_CREAT returns ENOENT for non-existent queue
fn test_mq_open_enoent() {
    let name = b"test_mq_nonexistent\0";

    // Try to open non-existent queue without O_CREAT
    let fd = sys_mq_open(name.as_ptr(), O_RDWR as i32, 0, core::ptr::null());
    if fd == ENOENT {
        pass(b"MQ_OPEN_ENOENT");
    } else {
        print(b"MQ_OPEN_ENOENT:FAIL: expected -2, got ");
        print_num(fd);
        if fd >= 0 {
            sys_close(fd as u64);
            sys_mq_unlink(name.as_ptr());
        }
    }
}

/// Test mq_unlink removes queue
fn test_mq_unlink() {
    let name = b"test_mq_unlink\0";

    // Create queue
    let attr = MqAttr::new(10, 256);
    let fd = sys_mq_open(name.as_ptr(), O_RDWR as i32 | O_CREAT as i32, 0o644, &attr);
    if fd < 0 {
        print(b"MQ_UNLINK:FAIL: create returned ");
        print_num(fd);
        return;
    }
    sys_close(fd as u64);

    // Unlink it
    let ret = sys_mq_unlink(name.as_ptr());
    if ret != 0 {
        print(b"MQ_UNLINK:FAIL: unlink returned ");
        print_num(ret);
        return;
    }

    // Try to open again - should fail with ENOENT
    let fd2 = sys_mq_open(name.as_ptr(), O_RDWR as i32, 0, core::ptr::null());
    if fd2 == ENOENT {
        pass(b"MQ_UNLINK");
    } else {
        print(b"MQ_UNLINK:FAIL: reopen expected -2, got ");
        print_num(fd2);
        if fd2 >= 0 {
            sys_close(fd2 as u64);
            sys_mq_unlink(name.as_ptr());
        }
    }
}

/// Test mq_send and mq_receive
fn test_mq_send_receive() {
    let name = b"test_mq_sendrecv\0";
    let msg = b"Hello, mqueue!";

    // Create queue
    let attr = MqAttr::new(10, 256);
    let fd = sys_mq_open(name.as_ptr(), O_RDWR as i32 | O_CREAT as i32, 0o644, &attr);
    if fd < 0 {
        print(b"MQ_SEND_RECEIVE:FAIL: create returned ");
        print_num(fd);
        return;
    }

    // Send message
    let ret = sys_mq_timedsend(fd as i32, msg.as_ptr(), msg.len(), 0, core::ptr::null());
    if ret != 0 {
        print(b"MQ_SEND_RECEIVE:FAIL: send returned ");
        print_num(ret);
        sys_close(fd as u64);
        sys_mq_unlink(name.as_ptr());
        return;
    }

    // Receive message
    let mut buf = [0u8; 256];
    let mut prio: u32 = 0;
    let ret = sys_mq_timedreceive(
        fd as i32,
        buf.as_mut_ptr(),
        buf.len(),
        &mut prio,
        core::ptr::null(),
    );
    if ret < 0 {
        print(b"MQ_SEND_RECEIVE:FAIL: receive returned ");
        print_num(ret);
        sys_close(fd as u64);
        sys_mq_unlink(name.as_ptr());
        return;
    }

    // Verify message
    if ret as usize == msg.len() && &buf[..msg.len()] == msg {
        pass(b"MQ_SEND_RECEIVE");
    } else {
        print(b"MQ_SEND_RECEIVE:FAIL: message mismatch, len=");
        print_num(ret);
    }

    sys_close(fd as u64);
    sys_mq_unlink(name.as_ptr());
}

/// Test mq_priority ordering (higher priority received first)
fn test_mq_priority_ordering() {
    let name = b"test_mq_priority\0";
    let msg_lo = b"low priority";
    let msg_hi = b"high priority";

    // Create queue
    let attr = MqAttr::new(10, 256);
    let fd = sys_mq_open(name.as_ptr(), O_RDWR as i32 | O_CREAT as i32, 0o644, &attr);
    if fd < 0 {
        print(b"MQ_PRIORITY:FAIL: create returned ");
        print_num(fd);
        return;
    }

    // Send low priority first
    let ret = sys_mq_timedsend(
        fd as i32,
        msg_lo.as_ptr(),
        msg_lo.len(),
        1,
        core::ptr::null(),
    );
    if ret != 0 {
        print(b"MQ_PRIORITY:FAIL: send low returned ");
        print_num(ret);
        sys_close(fd as u64);
        sys_mq_unlink(name.as_ptr());
        return;
    }

    // Send high priority second
    let ret = sys_mq_timedsend(
        fd as i32,
        msg_hi.as_ptr(),
        msg_hi.len(),
        10,
        core::ptr::null(),
    );
    if ret != 0 {
        print(b"MQ_PRIORITY:FAIL: send high returned ");
        print_num(ret);
        sys_close(fd as u64);
        sys_mq_unlink(name.as_ptr());
        return;
    }

    // Receive - should get high priority first
    let mut buf = [0u8; 256];
    let mut prio: u32 = 0;
    let ret = sys_mq_timedreceive(
        fd as i32,
        buf.as_mut_ptr(),
        buf.len(),
        &mut prio,
        core::ptr::null(),
    );
    if ret < 0 {
        print(b"MQ_PRIORITY:FAIL: receive returned ");
        print_num(ret);
        sys_close(fd as u64);
        sys_mq_unlink(name.as_ptr());
        return;
    }

    // Should be high priority message (prio=10)
    if prio == 10 && ret as usize == msg_hi.len() && &buf[..msg_hi.len()] == msg_hi {
        pass(b"MQ_PRIORITY");
    } else {
        print(b"MQ_PRIORITY:FAIL: expected prio=10, got ");
        print_num(prio as i64);
    }

    sys_close(fd as u64);
    sys_mq_unlink(name.as_ptr());
}

/// Test mq_nonblock returns EAGAIN on empty queue
fn test_mq_nonblock_eagain() {
    let name = b"test_mq_nonblock\0";

    // Create queue with O_NONBLOCK
    let attr = MqAttr::new(10, 256);
    let fd = sys_mq_open(
        name.as_ptr(),
        O_RDWR as i32 | O_CREAT as i32 | O_NONBLOCK as i32,
        0o644,
        &attr,
    );
    if fd < 0 {
        print(b"MQ_NONBLOCK:FAIL: create returned ");
        print_num(fd);
        return;
    }

    // Try to receive from empty queue - should return EAGAIN
    let mut buf = [0u8; 256];
    let mut prio: u32 = 0;
    let ret = sys_mq_timedreceive(
        fd as i32,
        buf.as_mut_ptr(),
        buf.len(),
        &mut prio,
        core::ptr::null(),
    );
    if ret == EAGAIN {
        pass(b"MQ_NONBLOCK");
    } else {
        print(b"MQ_NONBLOCK:FAIL: expected -11, got ");
        print_num(ret);
    }

    sys_close(fd as u64);
    sys_mq_unlink(name.as_ptr());
}

/// Test mq_getsetattr
fn test_mq_getsetattr() {
    let name = b"test_mq_attr\0";

    // Create queue
    let attr = MqAttr::new(10, 256);
    let fd = sys_mq_open(name.as_ptr(), O_RDWR as i32 | O_CREAT as i32, 0o644, &attr);
    if fd < 0 {
        print(b"MQ_GETSETATTR:FAIL: create returned ");
        print_num(fd);
        return;
    }

    // Get current attributes
    let mut old_attr = MqAttr::default();
    let ret = sys_mq_getsetattr(fd as i32, core::ptr::null(), &mut old_attr);
    if ret != 0 {
        print(b"MQ_GETSETATTR:FAIL: getattr returned ");
        print_num(ret);
        sys_close(fd as u64);
        sys_mq_unlink(name.as_ptr());
        return;
    }

    // Verify attributes match what we set
    if old_attr.mq_maxmsg == 10 && old_attr.mq_msgsize == 256 {
        pass(b"MQ_GETSETATTR");
    } else {
        print(b"MQ_GETSETATTR:FAIL: maxmsg=");
        print_num(old_attr.mq_maxmsg);
        print(b" msgsize=");
        print_num(old_attr.mq_msgsize);
    }

    sys_close(fd as u64);
    sys_mq_unlink(name.as_ptr());
}

/// Test mq operations on closed fd returns EBADF
fn test_mq_close_fd() {
    let name = b"test_mq_close\0";

    // Create and immediately close
    let attr = MqAttr::new(10, 256);
    let fd = sys_mq_open(name.as_ptr(), O_RDWR as i32 | O_CREAT as i32, 0o644, &attr);
    if fd < 0 {
        print(b"MQ_CLOSE_FD:FAIL: create returned ");
        print_num(fd);
        return;
    }
    sys_close(fd as u64);

    // Try to use closed fd - should return EBADF
    let mut buf = [0u8; 256];
    let mut prio: u32 = 0;
    let ret = sys_mq_timedreceive(
        fd as i32,
        buf.as_mut_ptr(),
        buf.len(),
        &mut prio,
        core::ptr::null(),
    );
    if ret == EBADF {
        pass(b"MQ_CLOSE_FD");
    } else {
        print(b"MQ_CLOSE_FD:FAIL: expected -9, got ");
        print_num(ret);
    }

    sys_mq_unlink(name.as_ptr());
}

/// Test mq_send with message too large returns EMSGSIZE
fn test_mq_emsgsize() {
    let name = b"test_mq_msgsize\0";

    // Create queue with small message size
    let attr = MqAttr::new(10, 16); // Only 16 bytes max
    let fd = sys_mq_open(name.as_ptr(), O_RDWR as i32 | O_CREAT as i32, 0o644, &attr);
    if fd < 0 {
        print(b"MQ_EMSGSIZE:FAIL: create returned ");
        print_num(fd);
        return;
    }

    // Try to send message larger than max
    let msg = b"This message is way too long for the queue!";
    let ret = sys_mq_timedsend(fd as i32, msg.as_ptr(), msg.len(), 0, core::ptr::null());
    if ret == EMSGSIZE {
        pass(b"MQ_EMSGSIZE");
    } else {
        print(b"MQ_EMSGSIZE:FAIL: expected -90, got ");
        print_num(ret);
    }

    sys_close(fd as u64);
    sys_mq_unlink(name.as_ptr());
}

/// Test raw mq_open/mq_unlink reject names containing '/'
///
/// The raw syscall takes the name without the leading '/' (libc strips it).
/// A '/' anywhere in the name is rejected with EACCES (ipc/mqueue.c ->
/// lookup_noperm_common() in fs/namei.c).
fn test_mq_name_slash() {
    let names: [&[u8]; 3] = [b"/test_mq_slash\0", b"test/mq_slash\0", b"..\0"];
    for name in names {
        let fd = sys_mq_open(
            name.as_ptr(),
            O_RDWR as i32 | O_CREAT as i32,
            0o600,
            core::ptr::null(),
        );
        if fd != EACCES {
            fail_num(b"MQ_NAME_SLASH:FAIL: mq_open expected -13, got ", fd);
            if fd >= 0 {
                sys_close(fd as u64);
                sys_mq_unlink(name.as_ptr());
            }
            return;
        }
    }
    let ret = sys_mq_unlink(b"/test_mq_slash\0".as_ptr());
    if ret != EACCES {
        fail_num(b"MQ_NAME_SLASH:FAIL: mq_unlink expected -13, got ", ret);
        return;
    }
    pass(b"MQ_NAME_SLASH");
}

/// A name longer than NAME_MAX is ENAMETOOLONG for mq_open and
/// mq_unlink (Linux: getname, then the lookup in the mqueue root)
fn test_mq_name_toolong() {
    let mut name = [b'q'; 301];
    name[300] = 0;
    let attr = MqAttr {
        mq_flags: 0,
        mq_maxmsg: 4,
        mq_msgsize: 64,
        mq_curmsgs: 0,
        __reserved: [0; 4],
    };
    let o = sys_mq_open(name.as_ptr(), O_RDWR as i32 | O_CREAT as i32, 0o644, &attr);
    let u = sys_mq_unlink(name.as_ptr());
    if o >= 0 {
        sys_close(o as u64);
    }
    if o == -36 && u == -36 {
        pass(b"MQ_NAME_TOOLONG");
    } else {
        print(b"MQ_NAME_TOOLONG:FAIL open=");
        print_num(o);
        print(b" unlink=");
        print_num(u);
        println(b"");
    }
}

/// read() on a queue descriptor returns its status line (Linux
/// mqueue_read_file: "QSIZE:<bytes queued> NOTIFY:..."), leaving the
/// messages queued; write() is EINVAL
fn test_mq_read_status() {
    let name = b"hk_mq_status\0";
    let fd = sys_mq_open(
        name.as_ptr(),
        (O_CREAT | O_RDWR) as i32,
        0o600,
        core::ptr::null(),
    ) as i32;
    let msg = *b"hello";
    sys_mq_timedsend(fd, msg.as_ptr(), msg.len(), 0, core::ptr::null());
    let mut buf = [0u8; 128];
    let n = sys_read(fd as u64, buf.as_mut_ptr(), buf.len() as u64);
    let w = sys_write(fd as u64, msg.as_ptr(), msg.len() as u64);
    let mut attr = MqAttr::default();
    sys_mq_getsetattr(fd, core::ptr::null(), &mut attr);
    sys_close(fd as u64);
    sys_mq_unlink(name.as_ptr());
    let line = &buf[..n.max(0) as usize];
    if line.starts_with(b"QSIZE:5 ") && line.ends_with(b"\n") && w == EINVAL && attr.mq_curmsgs == 1
    {
        pass(b"MQ_READ_STATUS");
    } else {
        print(b"MQ_READ_STATUS:FAIL read ");
        print_num(n);
        print(b" write ");
        print_num(w);
        print(b" curmsgs ");
        print_num(attr.mq_curmsgs);
        println(b"");
    }
}

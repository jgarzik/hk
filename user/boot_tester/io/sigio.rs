//! O_ASYNC / SIGIO (Linux fasync_helper, kill_fasync, send_sigio)
//!
//! - SIGIO_PIPE: a pipe with O_ASYNC and an owner raises SIGIO when data
//!   arrives
//! - SIGIO_SETSIG: with F_SETSIG the chosen signal comes with POLL_IN,
//!   si_band, si_fd
//! - SIGIO_FIOASYNC: FIOASYNC sets O_ASYNC and arms the file
//! - SIGIO_WRITER: a read makes room: the writer gets POLL_OUT
//! - SIGIO_FIFO: an O_RDWR FIFO raises SIGIO on input
//! - SIGIO_CLOSE: a dup keeps the entry (si_fd stays the armed fd); the
//!   last close removes it
//! - SIGIO_PGRP: F_SETOWN -pgrp signals every process of the group
//! - SIGIO_PERM: an unprivileged owner setter cannot signal a root
//!   process (sigio_perm), but can signal itself
//! - SIGIO_SOCKET: a socketpair end raises SIGIO on input
//! - SIGIO_SOCK_OUT: room in the send buffer signals POLL_OUT only after
//!   a send found none (SOCKWQ_ASYNC_NOSPACE)
//! - SIGIO_TCP: a listener gets POLL_IN for a connection, a nonblocking
//!   connect POLL_OUT once established, the accepted socket POLL_IN
//! - SIGIO_TTY: FIOASYNC on a tty sets O_ASYNC and, with no owner,
//!   makes the caller's process (or the tty's foreground group) owner
//! - SIGIO_NOTIFY: an inotify file keeps O_ASYNC (fsnotify_fasync), a
//!   fanotify file does not (no fasync)
//! - SIGIO_NO_FASYNC: a file without fasync: FIOASYNC is ENOTTY, F_SETFL
//!   keeps no O_ASYNC
//! - SIGIO_OWNER_EX: F_SETOWN_EX / F_GETOWN_EX round trip a thread owner

use crate::helpers::{print, print_num, println};
use hk_syscall::{
    AF_INET, AF_UNIX, FIOASYNC, O_CREAT, O_NONBLOCK, O_RDWR, SOCK_STREAM, SigInfo, SockAddrIn,
    htonl, make_ipv4, sys_accept, sys_bind, sys_close, sys_connect, sys_dup, sys_exit,
    sys_fanotify_init, sys_fcntl, sys_fork, sys_getpid, sys_getsockname, sys_gettid,
    sys_inotify_init1, sys_ioctl, sys_listen, sys_mknod, sys_open, sys_pipe2, sys_read,
    sys_rt_sigprocmask, sys_rt_sigtimedwait, sys_setpgid, sys_setresuid, sys_setsid, sys_socket,
    sys_socketpair, sys_unlink, sys_wait4, sys_write,
};

const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;
const F_SETOWN: i32 = 8;
const F_GETOWN: i32 = 9;
const F_SETSIG: i32 = 10;
const F_SETOWN_EX: i32 = 15;
const F_GETOWN_EX: i32 = 16;
const F_OWNER_TID: i32 = 0;
const O_ASYNC: u64 = 0o20000;
const O_NOCTTY: u32 = 0o400;
const SIG_BLOCK: i32 = 0;
const SIG_SETMASK: i32 = 2;
const SIGPIPE: u32 = 13;
const SIGIO: u32 = 29;
const SIGRT: u32 = 41;
const POLL_IN: i32 = 1;
const POLL_OUT: i32 = 2;
const ENOTTY: i64 = -25;
const EAGAIN: i64 = -11;
const S_IFIFO: u32 = 0o010000;

pub fn run_tests() {
    test_pipe_sigio();
    test_setsig_info();
    test_fioasync();
    test_writer();
    test_fifo();
    test_close();
    test_pgrp();
    test_perm();
    test_socket_sigio();
    test_sock_out();
    test_tcp();
    test_tty();
    test_notify();
    test_no_fasync();
    test_owner_ex();
}

fn bit(sig: u32) -> u64 {
    1 << (sig - 1)
}

fn block(mask: u64) -> u64 {
    let mut old = 0u64;
    sys_rt_sigprocmask(
        SIG_BLOCK,
        &mask as *const u64 as u64,
        &mut old as *mut u64 as u64,
        8,
    );
    old
}

fn setmask(mask: u64) {
    sys_rt_sigprocmask(SIG_SETMASK, &mask as *const u64 as u64, 0, 8);
}

fn zeroed() -> SigInfo {
    // SAFETY: SigInfo is plain integers
    unsafe { core::mem::zeroed() }
}

/// sigtimedwait with a timeout in seconds; the signal or -errno
fn wait_sig(mask: u64, secs: i64, info: &mut SigInfo) -> i64 {
    let ts = [secs, 0i64];
    sys_rt_sigtimedwait(
        &mask as *const u64 as u64,
        info as *mut SigInfo as u64,
        ts.as_ptr() as u64,
        8,
    )
}

/// `sig` within `secs` seconds: the signal or -errno
fn take_wait(sig: u32, secs: i64) -> i64 {
    let mut info = zeroed();
    wait_sig(bit(sig), secs, &mut info)
}

/// A pending `sig`, without waiting: the signal or -errno
fn take(sig: u32) -> i64 {
    take_wait(sig, 0)
}

/// O_ASYNC with owner `who` (F_SETOWN)
fn arm_to(fd: i32, who: i64) -> i64 {
    let r = sys_fcntl(fd, F_SETOWN, who as u64);
    if r != 0 {
        return r;
    }
    let fl = sys_fcntl(fd, F_GETFL, 0) as u64;
    sys_fcntl(fd, F_SETFL, fl | O_ASYNC)
}

/// O_ASYNC with this process as owner
fn arm(fd: i32) -> i64 {
    arm_to(fd, sys_getpid())
}

fn report(name: &[u8], ok: bool, vals: &[(&[u8], i64)]) {
    print(name);
    if ok {
        println(b":OK");
        return;
    }
    print(b":FAIL");
    for (k, v) in vals {
        print(b" ");
        print(k);
        print(b"=");
        print_num(*v);
    }
    println(b"");
}

/// Run `f` in a forked child: its exit code (-1 if fork/wait failed or
/// it was killed)
fn in_child(f: fn() -> i32) -> i64 {
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(f() as u64)
    }
    if pid < 0 {
        return -1;
    }
    let mut st = 0i32;
    if sys_wait4(pid, &mut st, 0, 0) != pid || st & 0x7f != 0 {
        return -1;
    }
    ((st >> 8) & 0xff) as i64
}

fn pipe() -> [i32; 2] {
    let mut p = [0i32; 2];
    sys_pipe2(p.as_mut_ptr(), 0);
    p
}

fn close2(p: [i32; 2]) {
    sys_close(p[0] as u64);
    sys_close(p[1] as u64);
}

fn test_pipe_sigio() {
    let old = block(bit(SIGIO));
    let p = pipe();
    let armed = arm(p[0]);
    let flag = sys_fcntl(p[0], F_GETFL, 0) as u64 & O_ASYNC;
    sys_write(p[1] as u64, b"x".as_ptr(), 1);
    let got = take_wait(SIGIO, 2);
    close2(p);
    setmask(old);
    let ok = armed == 0 && flag != 0 && got == SIGIO as i64;
    report(
        b"SIGIO_PIPE",
        ok,
        &[(b"armed", armed), (b"flag", flag as i64), (b"got", got)],
    );
}

/// F_SETSIG: the signal carries POLL_IN, si_band POLLIN|POLLRDNORM and
/// si_fd (struct _sigpoll: si_band at 16, si_fd at 24)
fn test_setsig_info() {
    let old = block(bit(SIGRT) | bit(SIGIO));
    let p = pipe();
    arm(p[0]);
    let set = sys_fcntl(p[0], F_SETSIG, SIGRT as u64);
    sys_write(p[1] as u64, b"x".as_ptr(), 1);
    let mut info = zeroed();
    let got = wait_sig(bit(SIGRT), 2, &mut info);
    let plain = take(SIGIO);
    close2(p);
    setmask(old);
    let band = info.si_pid as i64;
    let fd = info.si_status;
    let ok = set == 0
        && got == SIGRT as i64
        && info.si_code == POLL_IN
        && band == 0x41
        && fd == p[0]
        && plain == EAGAIN;
    report(
        b"SIGIO_SETSIG",
        ok,
        &[
            (b"got", got),
            (b"code", info.si_code as i64),
            (b"band", band),
            (b"fd", fd as i64),
            (b"plain", plain),
        ],
    );
}

/// FIOASYNC turns O_ASYNC on (and off) through ->fasync
fn test_fioasync() {
    let old = block(bit(SIGIO));
    let p = pipe();
    sys_fcntl(p[0], F_SETOWN, sys_getpid() as u64);
    let on = 1i32;
    let ioc = sys_ioctl(p[0], FIOASYNC as u64, &on as *const i32 as u64);
    let flag = sys_fcntl(p[0], F_GETFL, 0) as u64 & O_ASYNC;
    sys_write(p[1] as u64, b"x".as_ptr(), 1);
    let got = take(SIGIO);
    let off = 0i32;
    let ioc2 = sys_ioctl(p[0], FIOASYNC as u64, &off as *const i32 as u64);
    let flag2 = sys_fcntl(p[0], F_GETFL, 0) as u64 & O_ASYNC;
    sys_write(p[1] as u64, b"x".as_ptr(), 1);
    let none = take(SIGIO);
    close2(p);
    setmask(old);
    let ok = ioc == 0 && flag != 0 && got == SIGIO as i64 && ioc2 == 0 && flag2 == 0;
    let ok = ok && none == EAGAIN;
    report(
        b"SIGIO_FIOASYNC",
        ok,
        &[
            (b"ioc", ioc),
            (b"flag", flag as i64),
            (b"got", got),
            (b"off", ioc2),
            (b"flag2", flag2 as i64),
            (b"none", none),
        ],
    );
}

/// The write end armed: a read of the pipe signals POLL_OUT
fn test_writer() {
    let old = block(bit(SIGRT) | bit(SIGIO));
    let p = pipe();
    arm(p[1]);
    sys_fcntl(p[1], F_SETSIG, SIGRT as u64);
    sys_write(p[1] as u64, b"x".as_ptr(), 1);
    let mut b = [0u8; 1];
    sys_read(p[0] as u64, b.as_mut_ptr(), 1);
    let mut info = zeroed();
    let got = wait_sig(bit(SIGRT), 2, &mut info);
    close2(p);
    setmask(old);
    let band = info.si_pid as i64;
    // POLLOUT | POLLWRNORM | POLLWRBAND
    let ok = got == SIGRT as i64 && info.si_code == POLL_OUT && band == 0x304;
    report(
        b"SIGIO_WRITER",
        ok,
        &[
            (b"got", got),
            (b"code", info.si_code as i64),
            (b"band", band),
        ],
    );
}

fn test_fifo() {
    const PATH: &[u8] = b"/tmp/sigio_fifo\0";
    sys_unlink(PATH.as_ptr());
    let mk = sys_mknod(PATH.as_ptr(), S_IFIFO | 0o666, 0);
    let fd = sys_open(PATH.as_ptr(), O_RDWR | O_NONBLOCK, 0) as i32;
    let old = block(bit(SIGIO));
    let armed = arm(fd);
    sys_write(fd as u64, b"x".as_ptr(), 1);
    let got = take(SIGIO);
    sys_close(fd as u64);
    sys_unlink(PATH.as_ptr());
    setmask(old);
    let ok = mk == 0 && armed == 0 && got == SIGIO as i64;
    report(
        b"SIGIO_FIFO",
        ok,
        &[(b"mknod", mk), (b"armed", armed), (b"got", got)],
    );
}

/// A dup keeps the entry, which still names the armed fd; once the last
/// descriptor is closed nothing is signalled (the write then finds no
/// reader: EPIPE and a blocked SIGPIPE)
fn test_close() {
    let old = block(bit(SIGRT) | bit(SIGIO) | bit(SIGPIPE));
    let p = pipe();
    arm(p[0]);
    sys_fcntl(p[0], F_SETSIG, SIGRT as u64);
    let d = sys_dup(p[0]);
    sys_close(p[0] as u64);
    sys_write(p[1] as u64, b"x".as_ptr(), 1);
    let mut info = zeroed();
    let got = wait_sig(bit(SIGRT), 0, &mut info);
    sys_close(d as u64);
    sys_write(p[1] as u64, b"x".as_ptr(), 1);
    let after = take(SIGRT);
    let plain = take(SIGIO);
    take(SIGPIPE);
    sys_close(p[1] as u64);
    setmask(old);
    let fd = info.si_status;
    let ok = got == SIGRT as i64 && fd == p[0] && after == EAGAIN && plain == EAGAIN;
    report(
        b"SIGIO_CLOSE",
        ok,
        &[
            (b"got", got),
            (b"fd", fd as i64),
            (b"after", after),
            (b"plain", plain),
        ],
    );
}

/// The group's other member: SIGIO arrives (exit 0)
fn pgrp_member() -> i32 {
    if take_wait(SIGIO, 3) == SIGIO as i64 {
        0
    } else {
        1
    }
}

/// In a new group: owner -pgrp; a second member of the group and this
/// process both get SIGIO
fn pgrp_leader() -> i32 {
    let me = sys_getpid();
    if sys_setpgid(0, 0) != 0 {
        return 10;
    }
    block(bit(SIGIO));
    let p = pipe();
    if arm_to(p[0], -me) != 0 {
        return 11;
    }
    if sys_fcntl(p[0], F_GETOWN, 0) != -me {
        return 12;
    }
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(pgrp_member() as u64)
    }
    sys_write(p[1] as u64, b"x".as_ptr(), 1);
    let mine = take(SIGIO);
    let mut st = 0i32;
    if sys_wait4(pid, &mut st, 0, 0) != pid || st != 0 {
        return 13;
    }
    if mine != SIGIO as i64 {
        return 14;
    }
    0
}

fn test_pgrp() {
    let r = in_child(pgrp_leader);
    report(b"SIGIO_PGRP", r == 0, &[(b"exit", r)]);
}

/// A root child waits for the go byte, then checks no SIGIO came (exit 0)
fn perm_target(go: i32) -> i32 {
    let mut b = [0u8; 1];
    sys_read(go as u64, b.as_mut_ptr(), 1);
    if take(SIGIO) == EAGAIN { 0 } else { 1 }
}

/// Unprivileged, set a root process as owner: sigio_perm refuses it;
/// owning it ourselves works
fn perm_setter() -> i32 {
    block(bit(SIGIO));
    let go = pipe();
    let p = pipe();
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(perm_target(go[0]) as u64)
    }
    if sys_setresuid(1000, 1000, 1000) != 0 {
        return 20;
    }
    if arm_to(p[0], pid) != 0 {
        return 21;
    }
    sys_write(p[1] as u64, b"x".as_ptr(), 1);
    sys_write(go[1] as u64, b"g".as_ptr(), 1);
    let mut st = 0i32;
    if sys_wait4(pid, &mut st, 0, 0) != pid || st != 0 {
        return 22;
    }
    if arm_to(p[0], sys_getpid()) != 0 {
        return 23;
    }
    sys_write(p[1] as u64, b"x".as_ptr(), 1);
    if take(SIGIO) != SIGIO as i64 {
        return 24;
    }
    0
}

fn test_perm() {
    let r = in_child(perm_setter);
    report(b"SIGIO_PERM", r == 0, &[(b"exit", r)]);
}

fn test_socket_sigio() {
    let old = block(bit(SIGIO));
    let mut sv = [0i32; 2];
    sys_socketpair(AF_UNIX, SOCK_STREAM, 0, &mut sv);
    let armed = arm(sv[0]);
    sys_write(sv[1] as u64, b"x".as_ptr(), 1);
    let got = take_wait(SIGIO, 2);
    sys_close(sv[0] as u64);
    sys_close(sv[1] as u64);
    setmask(old);
    report(
        b"SIGIO_SOCKET",
        armed == 0 && got == SIGIO as i64,
        &[(b"armed", armed), (b"got", got)],
    );
}

/// Every queued `sig` taken (0 left)
fn drain_sig(sig: u32) {
    while take(sig) == sig as i64 {}
}

fn set_nonblock(fd: i32) {
    let fl = sys_fcntl(fd, F_GETFL, 0) as u64;
    sys_fcntl(fd, F_SETFL, fl | O_NONBLOCK as u64);
}

/// A reader freeing room raises no POLL_OUT until a send hit a full
/// buffer; then the drain does
fn test_sock_out() {
    let old = block(bit(SIGRT) | bit(SIGIO));
    let mut sv = [0i32; 2];
    sys_socketpair(AF_UNIX, SOCK_STREAM, 0, &mut sv);
    arm(sv[0]);
    sys_fcntl(sv[0], F_SETSIG, SIGRT as u64);
    let mut buf = [0u8; 1024];
    sys_write(sv[0] as u64, buf.as_ptr(), 1);
    sys_read(sv[1] as u64, buf.as_mut_ptr(), 1);
    let early = take(SIGRT);
    set_nonblock(sv[0]);
    set_nonblock(sv[1]);
    let mut full = 0;
    for _ in 0..4096 {
        full = sys_write(sv[0] as u64, buf.as_ptr(), buf.len() as u64);
        if full < 0 {
            break;
        }
    }
    while sys_read(sv[1] as u64, buf.as_mut_ptr(), buf.len() as u64) > 0 {}
    let mut info = zeroed();
    let got = wait_sig(bit(SIGRT), 2, &mut info);
    drain_sig(SIGRT);
    sys_close(sv[0] as u64);
    sys_close(sv[1] as u64);
    setmask(old);
    let band = info.si_pid as i64;
    let ok = early == EAGAIN
        && full == EAGAIN
        && got == SIGRT as i64
        && info.si_code == POLL_OUT
        && band == 0x304
        && info.si_status == sv[0];
    report(
        b"SIGIO_SOCK_OUT",
        ok,
        &[
            (b"early", early),
            (b"full", full),
            (b"got", got),
            (b"code", info.si_code as i64),
            (b"band", band),
        ],
    );
}

/// Wait up to 2 s for SIGRT with `code` from `fd`
fn wait_from(fd: i32, code: i32) -> bool {
    for _ in 0..8 {
        let mut info = zeroed();
        let ts = [0i64, 250_000_000];
        let m = bit(SIGRT);
        let r = sys_rt_sigtimedwait(
            &m as *const u64 as u64,
            &mut info as *mut SigInfo as u64,
            ts.as_ptr() as u64,
            8,
        );
        if r == SIGRT as i64 && info.si_status == fd && info.si_code == code {
            return true;
        }
    }
    false
}

/// O_ASYNC with SIGRT
fn arm_rt(fd: i32) {
    arm(fd);
    sys_fcntl(fd, F_SETSIG, SIGRT as u64);
}

fn test_tcp() {
    let old = block(bit(SIGRT) | bit(SIGIO));
    let l = sys_socket(AF_INET, SOCK_STREAM, 0) as i32;
    let mut a = SockAddrIn::new(AF_INET as u16, 0, htonl(make_ipv4(127, 0, 0, 1)));
    let alen = core::mem::size_of::<SockAddrIn>() as u32;
    sys_bind(l, &a as *const SockAddrIn as *const u8, alen);
    sys_listen(l, 4);
    let mut n = alen;
    sys_getsockname(l, &mut a as *mut SockAddrIn as *mut u8, &mut n);
    arm_rt(l);
    let c = sys_socket(AF_INET, SOCK_STREAM, 0) as i32;
    set_nonblock(c);
    arm_rt(c);
    sys_connect(c, &a as *const SockAddrIn as *const u8, alen);
    // Either order: the listener's POLL_IN, the client's POLL_OUT
    let mut lis = false;
    let mut conn = false;
    for _ in 0..16 {
        let mut info = zeroed();
        let ts = [0i64, 250_000_000];
        let m = bit(SIGRT);
        let r = sys_rt_sigtimedwait(
            &m as *const u64 as u64,
            &mut info as *mut SigInfo as u64,
            ts.as_ptr() as u64,
            8,
        );
        if r == SIGRT as i64 {
            lis |= info.si_status == l && info.si_code == POLL_IN;
            conn |= info.si_status == c && info.si_code == POLL_OUT;
        }
        if lis && conn {
            break;
        }
    }
    let s = sys_accept(l, core::ptr::null_mut(), core::ptr::null_mut()) as i32;
    arm_rt(s);
    sys_write(c as u64, b"x".as_ptr(), 1);
    let data = wait_from(s, POLL_IN);
    drain_sig(SIGRT);
    sys_close(s as u64);
    sys_close(c as u64);
    sys_close(l as u64);
    drain_sig(SIGRT);
    setmask(old);
    report(
        b"SIGIO_TCP",
        lis && conn && data,
        &[
            (b"listener", lis as i64),
            (b"connect", conn as i64),
            (b"data", data as i64),
        ],
    );
}

/// The serial tty (ttyS0 on x86, ttyAMA0 on arm64)
fn open_serial() -> i32 {
    let fl = O_RDWR | O_NOCTTY | O_NONBLOCK;
    let fd = sys_open(b"/dev/ttyS0\0".as_ptr(), fl, 0);
    if fd >= 0 {
        return fd as i32;
    }
    sys_open(b"/dev/ttyAMA0\0".as_ptr(), fl, 0) as i32
}

/// In a new session (no controlling tty): exit 0 if FIOASYNC armed the
/// tty with an owner, and disarming cleared the flag
fn tty_child() -> i32 {
    sys_setsid();
    let fd = open_serial();
    if fd < 0 {
        return 30;
    }
    let on = 1i32;
    if sys_ioctl(fd, FIOASYNC as u64, &on as *const i32 as u64) != 0 {
        return 31;
    }
    if sys_fcntl(fd, F_GETFL, 0) as u64 & O_ASYNC == 0 {
        return 32;
    }
    let own = sys_fcntl(fd, F_GETOWN, 0);
    if own != sys_getpid() && own >= 0 {
        return 33;
    }
    let off = 0i32;
    sys_ioctl(fd, FIOASYNC as u64, &off as *const i32 as u64);
    if sys_fcntl(fd, F_GETFL, 0) as u64 & O_ASYNC != 0 {
        return 34;
    }
    sys_close(fd as u64);
    0
}

fn test_tty() {
    let r = in_child(tty_child);
    report(b"SIGIO_TTY", r == 0, &[(b"exit", r)]);
}

/// F_SETFL O_ASYNC sticks on `fd` (it has fasync)
fn keeps_async(fd: i32) -> bool {
    let fl = sys_fcntl(fd, F_GETFL, 0) as u64;
    sys_fcntl(fd, F_SETFL, fl | O_ASYNC);
    let on = sys_fcntl(fd, F_GETFL, 0) as u64 & O_ASYNC != 0;
    sys_close(fd as u64);
    on
}

fn test_notify() {
    let ino = keeps_async(sys_inotify_init1(0) as i32);
    let fan = keeps_async(sys_fanotify_init(0, 0) as i32);
    report(
        b"SIGIO_NOTIFY",
        ino && !fan,
        &[(b"inotify", ino as i64), (b"fanotify", fan as i64)],
    );
}

/// A regular tmpfs file has no fasync
fn test_no_fasync() {
    let fd = sys_open(b"/tmp/sigio_file\0".as_ptr(), O_RDWR | O_CREAT, 0o644) as i32;
    let on = 1i32;
    let ioc = sys_ioctl(fd, FIOASYNC as u64, &on as *const i32 as u64);
    let fl = sys_fcntl(fd, F_GETFL, 0) as u64;
    let set = sys_fcntl(fd, F_SETFL, fl | O_ASYNC);
    let after = sys_fcntl(fd, F_GETFL, 0) as u64 & O_ASYNC;
    sys_close(fd as u64);
    sys_unlink(b"/tmp/sigio_file\0".as_ptr());
    let ok = ioc == ENOTTY && set == 0 && after == 0;
    report(
        b"SIGIO_NO_FASYNC",
        ok,
        &[(b"fioasync", ioc), (b"setfl", set), (b"flag", after as i64)],
    );
}

#[repr(C)]
struct FOwnerEx {
    kind: i32,
    pid: i32,
}

fn test_owner_ex() {
    let p = pipe();
    let tid = sys_gettid() as i32;
    let set = FOwnerEx {
        kind: F_OWNER_TID,
        pid: tid,
    };
    let r = sys_fcntl(p[0], F_SETOWN_EX, &set as *const FOwnerEx as u64);
    let mut get = FOwnerEx { kind: -1, pid: -1 };
    let g = sys_fcntl(p[0], F_GETOWN_EX, &mut get as *mut FOwnerEx as u64);
    close2(p);
    let ok = r == 0 && g == 0 && get.kind == F_OWNER_TID && get.pid == tid;
    report(
        b"SIGIO_OWNER_EX",
        ok,
        &[
            (b"set", r),
            (b"get", g),
            (b"kind", get.kind as i64),
            (b"pid", get.pid as i64),
        ],
    );
}

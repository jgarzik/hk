//! Socket test helpers (shared by udp, sockopts, nonblock, sockcore):
//! IPv4 addresses, option access, polling, timing, verdict printing.

#![allow(dead_code)]

use hk_syscall::{
    AF_INET, CLOCK_MONOTONIC, IoVec, MsgHdr, PollFd, SOCK_DGRAM, SOCK_STREAM, SockAddrIn, Timespec,
    sys_bind, sys_clock_gettime, sys_close, sys_connect, sys_getsockname, sys_getsockopt, sys_poll,
    sys_recvfrom, sys_recvmsg, sys_sendto, sys_setsockopt, sys_socket,
};

use super::helpers::{print, print_num, println};

pub const LO: [u8; 4] = [127, 0, 0, 1];
pub const ANY: [u8; 4] = [0, 0, 0, 0];

pub const SOL_SOCKET: i32 = 1;
pub const SOL_IP: i32 = 0;
pub const IPPROTO_TCP: i32 = 6;
pub const SOL_UDP: i32 = 17;

pub const SO_REUSEADDR: i32 = 2;
pub const SO_TYPE: i32 = 3;
pub const SO_ERROR: i32 = 4;
pub const SO_BROADCAST: i32 = 6;
pub const SO_SNDBUF: i32 = 7;
pub const SO_RCVBUF: i32 = 8;
pub const SO_KEEPALIVE: i32 = 9;
pub const SO_LINGER: i32 = 13;
pub const SO_REUSEPORT: i32 = 15;
pub const SO_RCVLOWAT: i32 = 18;
pub const SO_SNDLOWAT: i32 = 19;
pub const SO_RCVTIMEO: i32 = 20;
pub const SO_SNDTIMEO: i32 = 21;
pub const SO_BINDTODEVICE: i32 = 25;
pub const SO_TIMESTAMP: i32 = 29;
pub const SO_ACCEPTCONN: i32 = 30;
pub const SO_RCVBUFFORCE: i32 = 33;
pub const SO_PROTOCOL: i32 = 38;
pub const SO_DOMAIN: i32 = 39;
pub const SO_RXQ_OVFL: i32 = 40;

pub const IP_TOS: i32 = 1;
pub const IP_TTL: i32 = 2;
pub const IP_PKTINFO: i32 = 8;
pub const IP_RECVERR: i32 = 11;
pub const IP_RECVTTL: i32 = 12;
pub const IP_RECVTOS: i32 = 13;

pub const MSG_OOB: i32 = 0x01;
pub const MSG_PEEK: i32 = 0x02;
pub const MSG_CTRUNC: i32 = 0x08;
pub const MSG_TRUNC: i32 = 0x20;
pub const MSG_DONTWAIT: i32 = 0x40;
pub const MSG_WAITALL: i32 = 0x100;
pub const MSG_ERRQUEUE: i32 = 0x2000;
pub const MSG_NOSIGNAL: i32 = 0x4000;

pub const EPERM: i64 = -1;
pub const ESRCH: i64 = -3;
pub const EINTR: i64 = -4;
pub const EBADF: i64 = -9;
pub const EAGAIN: i64 = -11;
pub const EACCES: i64 = -13;
pub const EFAULT: i64 = -14;
pub const EINVAL: i64 = -22;
pub const EPIPE: i64 = -32;
pub const EDOM: i64 = -33;
pub const ESPIPE: i64 = -29;
pub const ENOTSOCK: i64 = -88;
pub const EDESTADDRREQ: i64 = -89;
pub const EMSGSIZE: i64 = -90;
pub const ENOPROTOOPT: i64 = -92;
pub const EPROTONOSUPPORT: i64 = -93;
pub const ESOCKTNOSUPPORT: i64 = -94;
pub const EOPNOTSUPP: i64 = -95;
pub const EAFNOSUPPORT: i64 = -97;
pub const EADDRINUSE: i64 = -98;
pub const EADDRNOTAVAIL: i64 = -99;
pub const ENETUNREACH: i64 = -101;
pub const EISCONN: i64 = -106;
pub const ENOTCONN: i64 = -107;
pub const ECONNREFUSED: i64 = -111;
pub const EALREADY: i64 = -114;
pub const EINPROGRESS: i64 = -115;

/// An unmapped user address (EFAULT everywhere)
pub const BAD: u64 = 0x10;

/// Network-order sockaddr_in
pub fn sin(ip: [u8; 4], port: u16) -> SockAddrIn {
    SockAddrIn::new(AF_INET as u16, port.to_be(), u32::from_ne_bytes(ip))
}

pub fn sa(a: &SockAddrIn) -> *const u8 {
    a as *const SockAddrIn as *const u8
}

pub fn udp() -> i32 {
    sys_socket(AF_INET, SOCK_DGRAM, 0) as i32
}

pub fn tcp() -> i32 {
    sys_socket(AF_INET, SOCK_STREAM, 0) as i32
}

pub fn close(fd: i32) {
    if fd >= 0 {
        sys_close(fd as u64);
    }
}

pub fn bind(fd: i32, ip: [u8; 4], port: u16) -> i64 {
    sys_bind(fd, sa(&sin(ip, port)), 16)
}

pub fn connect(fd: i32, ip: [u8; 4], port: u16) -> i64 {
    sys_connect(fd, sa(&sin(ip, port)), 16)
}

/// Local (address, port) of `fd`
pub fn name(fd: i32) -> ([u8; 4], u16) {
    let mut a = sin(ANY, 0);
    let mut len = 16u32;
    sys_getsockname(fd, &mut a as *mut SockAddrIn as *mut u8, &mut len);
    (a.sin_addr.to_ne_bytes(), u16::from_be(a.sin_port))
}

pub fn port(fd: i32) -> u16 {
    name(fd).1
}

pub fn setint(fd: i32, level: i32, opt: i32, v: i32) -> i64 {
    sys_setsockopt(fd, level, opt, &v as *const i32 as *const u8, 4)
}

/// (return, value) of an int option
pub fn getint(fd: i32, level: i32, opt: i32) -> (i64, i32) {
    let mut v: i32 = -12345;
    let mut len = 4u32;
    let r = sys_getsockopt(fd, level, opt, &mut v as *mut i32 as *mut u8, &mut len);
    (r, v)
}

pub fn send_to(fd: i32, data: &[u8], ip: [u8; 4], port: u16, flags: i32) -> i64 {
    sys_sendto(fd, data.as_ptr(), data.len(), flags, sa(&sin(ip, port)), 16)
}

pub fn send(fd: i32, data: &[u8], flags: i32) -> i64 {
    sys_sendto(fd, data.as_ptr(), data.len(), flags, core::ptr::null(), 0)
}

pub fn recv(fd: i32, buf: &mut [u8], flags: i32) -> i64 {
    sys_recvfrom(
        fd,
        buf.as_mut_ptr(),
        buf.len(),
        flags,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    )
}

/// recvfrom with the source: (return, address, port)
pub fn recv_from(fd: i32, buf: &mut [u8], flags: i32) -> (i64, [u8; 4], u16) {
    let mut a = sin(ANY, 0);
    let mut len = 16u32;
    let r = sys_recvfrom(
        fd,
        buf.as_mut_ptr(),
        buf.len(),
        flags,
        &mut a as *mut SockAddrIn as *mut u8,
        &mut len,
    );
    (r, a.sin_addr.to_ne_bytes(), u16::from_be(a.sin_port))
}

/// recvmsg with a control buffer: (return, msg_flags, control length)
pub fn recv_msg(fd: i32, buf: &mut [u8], ctl: &mut [u8], flags: i32) -> (i64, i32, usize) {
    let mut iov = IoVec {
        iov_base: buf.as_mut_ptr(),
        iov_len: buf.len(),
    };
    let mut m = MsgHdr::new(&mut iov, 1);
    m.msg_control = ctl.as_mut_ptr();
    m.msg_controllen = ctl.len();
    let r = sys_recvmsg(fd, &mut m, flags);
    (r, m.msg_flags, m.msg_controllen)
}

/// Find control message (level, type) in `ctl[..len]`: its data
pub fn cmsg_find(ctl: &[u8], len: usize, level: i32, ty: i32) -> Option<&[u8]> {
    let mut off = 0;
    while off + 16 <= len {
        let l = u64::from_ne_bytes(ctl[off..off + 8].try_into().unwrap()) as usize;
        if l < 16 || off + l > len {
            return None;
        }
        let lv = i32::from_ne_bytes(ctl[off + 8..off + 12].try_into().unwrap());
        let t = i32::from_ne_bytes(ctl[off + 12..off + 16].try_into().unwrap());
        if lv == level && t == ty {
            return Some(&ctl[off + 16..off + l]);
        }
        off += (l + 7) & !7;
    }
    None
}

/// poll one fd: (return, revents)
pub fn poll1(fd: i32, events: i16, ms: i32) -> (i64, i16) {
    let mut p = PollFd {
        fd,
        events,
        revents: 0,
    };
    let r = sys_poll(&mut p, 1, ms);
    (r, p.revents)
}

pub fn now_ms() -> u64 {
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    sys_clock_gettime(CLOCK_MONOTONIC, &mut ts);
    ts.tv_sec as u64 * 1000 + ts.tv_nsec as u64 / 1_000_000
}

/// A bound UDP socket on 127.0.0.1 (ephemeral port)
pub fn udp_lo() -> (i32, u16) {
    let fd = udp();
    bind(fd, LO, 0);
    (fd, port(fd))
}

/// Print NAME:OK or NAME:FAIL why value
pub struct T {
    name: &'static [u8],
    failed: bool,
}

impl T {
    pub fn new(name: &'static [u8]) -> Self {
        Self {
            name,
            failed: false,
        }
    }

    /// Record `got == want` (first failure is printed)
    pub fn eq(&mut self, why: &[u8], got: i64, want: i64) -> bool {
        self.ok(why, got == want, got)
    }

    /// Record a condition; prints `got` on the first failure
    pub fn ok(&mut self, why: &[u8], cond: bool, got: i64) -> bool {
        if !cond && !self.failed {
            self.failed = true;
            print(self.name);
            print(b":FAIL ");
            print(why);
            print(b" got ");
            print_num(got);
            println(b"");
        }
        cond
    }

    pub fn done(self) {
        if !self.failed {
            print(self.name);
            println(b":OK");
        }
    }
}

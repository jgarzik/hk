//! Socket system calls (Linux net/socket.c)
//!
//! Thin entry points: resolve the descriptor (EBADF / ENOTSOCK), copy
//! arguments in with uaccess, call the protocol, copy results out. The
//! file's O_NONBLOCK is read at every call.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::arch::Uaccess;
use crate::error::KernelError;
use crate::fs::file::File;
use crate::net::msg::{
    self, Dst, Iov, MSG_CMSG_CLOEXEC, MSG_CTRUNC, MSG_DONTWAIT, MSG_WAITFORONE, MsgHdr, RecvMsg,
    SendMsg, Src, addr_in, addr_out,
};
use crate::net::socket::{
    OptIn, ProtoOps, SOCK_CLOEXEC, SOCK_NONBLOCK, SOCK_TYPE_MASK, SOL_SOCKET, file_nb, put_opt,
    sock_alloc_file, sock_create, sock_getsockopt, sock_of, sock_sendmsg, sock_setsockopt,
};
use crate::uaccess::{copy_to_user, get_user, put_user};

fn ret(r: Result<i64, KernelError>) -> i64 {
    r.unwrap_or_else(|e| e.sysret())
}

/// The socket behind `fd`: EBADF, or ENOTSOCK for other files
fn sockfd(fd: i32) -> Result<(Arc<File>, Arc<dyn ProtoOps>), KernelError> {
    let table = crate::task::fdtable::get_task_fd(crate::task::percpu::current_tid())
        .ok_or(KernelError::BadFd)?;
    let file = table.lock().get(fd).ok_or(KernelError::BadFd)?;
    let s = sock_of(&file).ok_or(KernelError::NotSocket)?;
    Ok((file, s))
}

fn nofile() -> u64 {
    let l = crate::rlimit::rlimit(crate::rlimit::RLIMIT_NOFILE);
    if l == crate::rlimit::RLIM_INFINITY {
        u64::MAX
    } else {
        l
    }
}

/// Install `file` in a new descriptor (EMFILE at the limit)
pub fn fd_install(file: Arc<File>, cloexec: bool) -> Result<i64, KernelError> {
    let table = crate::task::fdtable::get_task_fd(crate::task::percpu::current_tid())
        .ok_or(KernelError::BadFd)?;
    let fl = if cloexec { crate::task::FD_CLOEXEC } else { 0 };
    let fd = table
        .lock()
        .alloc_with_flags(file, fl, nofile())
        .map_err(|_| KernelError::ProcessFileLimit)?;
    Ok(fd as i64)
}

/// SOCK_NONBLOCK / SOCK_CLOEXEC of a type or accept4 flags argument
fn type_flags(f: i32) -> Result<(bool, bool), KernelError> {
    if f & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return Err(KernelError::InvalidArgument);
    }
    Ok((f & SOCK_NONBLOCK != 0, f & SOCK_CLOEXEC != 0))
}

/// socket(domain, type, protocol)
pub fn sys_socket(domain: i32, stype: i32, protocol: i32) -> i64 {
    ret((|| {
        let (nb, cloexec) = type_flags(stype & !SOCK_TYPE_MASK)?;
        let s = sock_create(domain, stype & SOCK_TYPE_MASK, protocol)?;
        fd_install(sock_alloc_file(s, nb), cloexec)
    })())
}

/// socketpair(domain, type, protocol, sv) (Linux __sys_socketpair):
/// `sv` is checked first (EFAULT), families without pairs (AF_INET,
/// AF_NETLINK) are EOPNOTSUPP (sock_no_socketpair); both descriptors
/// are installed or neither (EMFILE)
pub fn sys_socketpair(domain: i32, stype: i32, protocol: i32, sv: u64) -> i64 {
    ret((|| {
        let (nb, cloexec) = type_flags(stype & !SOCK_TYPE_MASK)?;
        let cur = get_user::<Uaccess, [i32; 2]>(sv).map_err(|_| KernelError::BadAddress)?;
        put_user::<Uaccess, [i32; 2]>(sv, cur).map_err(|_| KernelError::BadAddress)?;
        let a = sock_create(domain, stype & SOCK_TYPE_MASK, protocol)?;
        let b = match sock_create(domain, stype & SOCK_TYPE_MASK, protocol) {
            Ok(b) => b,
            Err(e) => {
                a.release();
                return Err(e);
            }
        };
        if let Err(e) = a.socketpair(&*b) {
            a.release();
            b.release();
            return Err(e);
        }
        let fds = install_pair(sock_alloc_file(a, nb), sock_alloc_file(b, nb), cloexec)?;
        put_user::<Uaccess, [i32; 2]>(sv, fds).map_err(|_| KernelError::BadAddress)?;
        Ok(0)
    })())
}

/// Install two files in new descriptors, or neither (the table
/// releases undone and refused files after its lock is dropped)
fn install_pair(a: Arc<File>, b: Arc<File>, cloexec: bool) -> Result<[i32; 2], KernelError> {
    let table = crate::task::fdtable::get_task_fd(crate::task::percpu::current_tid())
        .ok_or(KernelError::BadFd)?;
    let fl = if cloexec { crate::task::FD_CLOEXEC } else { 0 };
    let mut t = table.lock();
    let fd1 = t
        .alloc_with_flags(a, fl, nofile())
        .map_err(|_| KernelError::ProcessFileLimit)?;
    match t.alloc_with_flags(b, fl, nofile()) {
        Ok(fd2) => Ok([fd1, fd2]),
        Err(_) => {
            t.close(fd1);
            Err(KernelError::ProcessFileLimit)
        }
    }
}

/// The address argument as bytes (empty when none)
fn addr_arg(addr: u64, len: u64) -> Result<Vec<u8>, KernelError> {
    if len > i32::MAX as u64 {
        return Err(KernelError::InvalidArgument);
    }
    Ok(addr_in(addr, len)?.unwrap_or_default())
}

/// bind(fd, addr, addrlen)
pub fn sys_bind(fd: i32, addr: u64, len: u64) -> i64 {
    ret((|| {
        let (_, s) = sockfd(fd)?;
        s.bind(&addr_arg(addr, len)?)?;
        Ok(0)
    })())
}

/// connect(fd, addr, addrlen)
pub fn sys_connect(fd: i32, addr: u64, len: u64) -> i64 {
    ret((|| {
        let (file, s) = sockfd(fd)?;
        let a = addr_arg(addr, len)?;
        let nb = file_nb(&file, 0) & MSG_DONTWAIT != 0;
        let r = s.connect(&a, nb);
        crate::net::dev::netif_rx_flush_local();
        r?;
        Ok(0)
    })())
}

/// listen(fd, backlog)
pub fn sys_listen(fd: i32, backlog: i32) -> i64 {
    ret((|| {
        let (_, s) = sockfd(fd)?;
        s.listen(backlog)?;
        Ok(0)
    })())
}

/// accept(fd, addr, addrlen)
pub fn sys_accept(fd: i32, addr: u64, lenp: u64) -> i64 {
    sys_accept4(fd, addr, lenp, 0)
}

/// accept4(fd, addr, addrlen, flags) (Linux do_accept: a fault copying
/// the peer address drops the new connection and returns EFAULT)
pub fn sys_accept4(fd: i32, addr: u64, lenp: u64, flags: i32) -> i64 {
    ret((|| {
        let (nb_new, cloexec) = type_flags(flags)?;
        let (file, s) = sockfd(fd)?;
        let nb = file_nb(&file, 0) & MSG_DONTWAIT != 0;
        let child = s.accept(nb)?;
        let peer = child.getname(true);
        let newfile = sock_alloc_file(child, nb_new);
        if addr != 0 {
            let a = peer.map_err(|_| KernelError::ConnectionAborted)?;
            addr_out(addr, lenp, &a)?;
        }
        fd_install(newfile, cloexec)
    })())
}

/// getsockname(fd, addr, addrlen)
pub fn sys_getsockname(fd: i32, addr: u64, lenp: u64) -> i64 {
    getname(fd, addr, lenp, false)
}

/// getpeername(fd, addr, addrlen)
pub fn sys_getpeername(fd: i32, addr: u64, lenp: u64) -> i64 {
    getname(fd, addr, lenp, true)
}

fn getname(fd: i32, addr: u64, lenp: u64, peer: bool) -> i64 {
    ret((|| {
        let (_, s) = sockfd(fd)?;
        addr_out(addr, lenp, &s.getname(peer)?)?;
        Ok(0)
    })())
}

/// shutdown(fd, how)
pub fn sys_shutdown(fd: i32, how: i32) -> i64 {
    ret((|| {
        let (_, s) = sockfd(fd)?;
        let r = s.shutdown(how);
        crate::net::dev::netif_rx_flush_local();
        r?;
        Ok(0)
    })())
}

/// setsockopt(fd, level, optname, optval, optlen)
pub fn sys_setsockopt(fd: i32, level: i32, opt: i32, val: u64, len: u64) -> i64 {
    ret((|| {
        let len = len as i32;
        if len < 0 {
            return Err(KernelError::InvalidArgument);
        }
        let (_, s) = sockfd(fd)?;
        let v = OptIn {
            ptr: val,
            len: len as usize,
        };
        match s.setsockopt(level, opt, v) {
            Some(r) => r?,
            None if level == SOL_SOCKET => sock_setsockopt(&*s, opt, v)?,
            None => return Err(KernelError::NoProtocolOption),
        }
        Ok(0)
    })())
}

/// getsockopt(fd, level, optname, optval, optlen)
pub fn sys_getsockopt(fd: i32, level: i32, opt: i32, val: u64, lenp: u64) -> i64 {
    ret((|| {
        let (_, s) = sockfd(fd)?;
        let len = get_user::<Uaccess, i32>(lenp).map_err(|_| KernelError::BadAddress)?;
        if len < 0 {
            return Err(KernelError::InvalidArgument);
        }
        let out = match s.getsockopt(level, opt) {
            Some(r) => r?,
            None if level == SOL_SOCKET => sock_getsockopt(&*s, opt)?,
            None => return Err(KernelError::NoProtocolOption),
        };
        put_opt(out, val, lenp, len)?;
        Ok(0)
    })())
}

/// sendto(fd, buf, len, flags, addr, addrlen)
pub fn sys_sendto(fd: i32, buf: u64, len: u64, flags: i32, addr: u64, alen: u64) -> i64 {
    ret((|| {
        let (file, s) = sockfd(fd)?;
        let data = Src::User(Iov::single(buf, len)?);
        let addr = if addr != 0 {
            addr_in(addr, alen)?
        } else {
            None
        };
        let mut m = SendMsg {
            addr,
            data,
            control: Vec::new(),
        };
        let r = sock_sendmsg(&*s, &mut m, file_nb(&file, flags));
        crate::net::dev::netif_rx_flush_local();
        Ok(r? as i64)
    })())
}

/// recvfrom(fd, buf, len, flags, addr, addrlen)
pub fn sys_recvfrom(fd: i32, buf: u64, len: u64, flags: i32, addr: u64, lenp: u64) -> i64 {
    ret((|| {
        let (file, s) = sockfd(fd)?;
        let mut m = RecvMsg::new(Dst::User(Iov::single(buf, len)?), addr != 0, 0);
        let n = s.recvmsg(&mut m, file_nb(&file, flags))?;
        if addr != 0 {
            addr_out(addr, lenp, m.name.as_deref().unwrap_or(&[]))?;
        }
        Ok(n as i64)
    })())
}

/// One sendmsg on an already resolved socket
fn sendmsg_one(file: &File, s: &dyn ProtoOps, msg: u64, flags: i32) -> Result<usize, KernelError> {
    let h = MsgHdr::read(msg)?;
    let data = Src::User(h.iov()?);
    let mut m = SendMsg {
        addr: h.addr()?,
        data,
        control: h.control_in()?,
    };
    let r = sock_sendmsg(s, &mut m, file_nb(file, flags));
    crate::net::dev::netif_rx_flush_local();
    r
}

/// sendmsg(fd, msg, flags)
pub fn sys_sendmsg(fd: i32, msg: u64, flags: i32) -> i64 {
    ret((|| {
        let (file, s) = sockfd(fd)?;
        Ok(sendmsg_one(&file, &*s, msg, flags)? as i64)
    })())
}

/// One recvmsg; writes msg_namelen/msg_controllen/msg_flags back
fn recvmsg_one(file: &File, s: &dyn ProtoOps, msg: u64, flags: i32) -> Result<usize, KernelError> {
    let h = MsgHdr::read(msg)?;
    let mut m = RecvMsg::new(Dst::User(h.iov()?), h.name != 0, h.controllen);
    m.flags = flags & MSG_CMSG_CLOEXEC;
    let n = s.recvmsg(&mut m, file_nb(file, flags))?;
    let mut namelen = 0;
    if let (Some(a), true) = (&m.name, h.name != 0) {
        let k = (h.namelen as usize).min(a.len());
        copy_to_user::<Uaccess>(h.name, &a[..k]).map_err(|_| KernelError::BadAddress)?;
        namelen = a.len() as u32;
    }
    if !m.cmsg.buf.is_empty() {
        copy_to_user::<Uaccess>(h.control, &m.cmsg.buf).map_err(|_| KernelError::BadAddress)?;
    }
    let mut fl = m.flags;
    if m.cmsg.trunc {
        fl |= MSG_CTRUNC;
    }
    msg::msghdr_out(msg, namelen, m.cmsg.buf.len(), fl)?;
    Ok(n)
}

/// recvmsg(fd, msg, flags)
pub fn sys_recvmsg(fd: i32, msg: u64, flags: i32) -> i64 {
    ret((|| {
        let (file, s) = sockfd(fd)?;
        Ok(recvmsg_one(&file, &*s, msg, flags)? as i64)
    })())
}

/// sizeof(struct mmsghdr) and the offset of msg_len
const MMSG_SIZE: u64 = 64;
const MMSG_LEN_OFF: u64 = 56;

/// sendmmsg(fd, msgvec, vlen, flags): the count sent, or the first
/// error if none was (vlen clamped to UIO_MAXIOV like Linux)
pub fn sys_sendmmsg(fd: i32, vec: u64, vlen: u32, flags: i32) -> i64 {
    ret((|| {
        let (file, s) = sockfd(fd)?;
        let mut n = 0u64;
        for i in 0..(vlen as u64).min(msg::UIO_MAXIOV as u64) {
            let at = vec.wrapping_add(i * MMSG_SIZE);
            match sendmsg_one(&file, &*s, at, flags) {
                Ok(k) => {
                    put_user::<Uaccess, u32>(at + MMSG_LEN_OFF, k as u32)
                        .map_err(|_| KernelError::BadAddress)?;
                    n += 1;
                }
                Err(e) if n == 0 => return Err(e),
                Err(_) => break,
            }
        }
        Ok(n as i64)
    })())
}

/// recvmmsg(fd, msgvec, vlen, flags, timeout): MSG_WAITFORONE makes all
/// but the first non-blocking; the timeout is checked after each
/// datagram (Linux do_recvmmsg)
pub fn sys_recvmmsg(fd: i32, vec: u64, vlen: u32, flags: i32, timeout: u64) -> i64 {
    ret((|| {
        let (file, s) = sockfd(fd)?;
        let deadline = mmsg_deadline(timeout)?;
        let mut flags = flags;
        let mut n = 0u64;
        for i in 0..(vlen as u64).min(msg::UIO_MAXIOV as u64) {
            let at = vec.wrapping_add(i * MMSG_SIZE);
            match recvmsg_one(&file, &*s, at, flags) {
                Ok(k) => {
                    put_user::<Uaccess, u32>(at + MMSG_LEN_OFF, k as u32)
                        .map_err(|_| KernelError::BadAddress)?;
                    n += 1;
                }
                Err(e) if n == 0 => return Err(e),
                Err(_) => break,
            }
            if flags & MSG_WAITFORONE != 0 {
                flags |= MSG_DONTWAIT;
            }
            if deadline.is_some_and(|d| crate::time::monotonic_ns() >= d) {
                break;
            }
        }
        Ok(n as i64)
    })())
}

/// CLOCK_MONOTONIC deadline of a recvmmsg timeout (struct timespec *)
fn mmsg_deadline(ts: u64) -> Result<Option<u64>, KernelError> {
    if ts == 0 {
        return Ok(None);
    }
    let sec = get_user::<Uaccess, i64>(ts).map_err(|_| KernelError::BadAddress)?;
    let nsec = get_user::<Uaccess, i64>(ts + 8).map_err(|_| KernelError::BadAddress)?;
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        return Err(KernelError::InvalidArgument);
    }
    let d = (sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(nsec as u64);
    Ok(Some(crate::time::monotonic_ns().saturating_add(d)))
}

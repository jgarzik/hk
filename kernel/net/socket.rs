//! BSD socket layer (Linux net/socket.c, net/core/sock.c sk_setsockopt)
//!
//! A socket is a sockfs inode (S_IFSOCK, `socket:[ino]`) whose private
//! data is the protocol socket, an `Arc<dyn ProtoOps>` (Linux struct
//! socket + proto_ops). All socket files share `SOCK_FOPS`; nothing is
//! leaked: the protocol socket lives as long as its inode, and
//! `ProtoOps::release` (last close) unregisters it from every table.
//!
//! Families register a create function (`FAMILIES`, Linux
//! net_families[]); AF_INET dispatches on (type, protocol) itself (Linux
//! inetsw), so AF_INET6 can reuse the TCP/UDP cores later.
//!
//! Blocking follows the file's O_NONBLOCK at every call (fcntl/FIONBIO
//! take effect immediately) plus MSG_DONTWAIT; timeouts and signal
//! rules are in `Sock::wait`.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::Uaccess;
use crate::error::KernelError;
use crate::fs::dentry::Dentry;
use crate::fs::file::{File, FileOps, flags as fflags};
use crate::fs::inode::{AsAny, Inode, InodeData, InodeMode, NULL_INODE_OPS};
use crate::net::msg::{Dst, MSG_DONTWAIT, MSG_NOSIGNAL, RecvMsg, SendMsg, Src};
use crate::net::sock::{Sock, TIMEO_FOREVER, sf};
use crate::poll::PollTable;
use crate::uaccess::{copy_from_user, copy_to_user, get_user, put_user};

/// Address families
pub const AF_UNSPEC: u16 = 0;
pub const AF_UNIX: u16 = 1;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;
pub const AF_NETLINK: u16 = 16;
pub const AF_PACKET: u16 = 17;
/// Linux AF_MAX / NPROTO
pub const AF_MAX: i32 = 46;

/// Socket types
pub const SOCK_STREAM: i32 = 1;
pub const SOCK_DGRAM: i32 = 2;
pub const SOCK_RAW: i32 = 3;
pub const SOCK_SEQPACKET: i32 = 5;
/// Linux SOCK_MAX (SOCK_PACKET + 1)
pub const SOCK_MAX: i32 = 11;
pub const SOCK_TYPE_MASK: i32 = 0xf;
pub const SOCK_NONBLOCK: i32 = 0o4000;
pub const SOCK_CLOEXEC: i32 = 0o2000000;

/// shutdown(2) how
pub const SHUT_RD: i32 = 0;
pub const SHUT_WR: i32 = 1;
pub const SHUT_RDWR: i32 = 2;

/// A user option buffer (setsockopt)
#[derive(Clone, Copy, Debug)]
pub struct OptIn {
    pub ptr: u64,
    pub len: usize,
}

impl OptIn {
    /// int option (Linux: EINVAL if shorter than an int)
    pub fn int(&self) -> Result<i32, KernelError> {
        if self.len < 4 {
            return Err(KernelError::InvalidArgument);
        }
        get_user::<Uaccess, i32>(self.ptr).map_err(|_| KernelError::BadAddress)
    }

    /// int or (shorter) single byte option (Linux do_ip_setsockopt)
    pub fn int_or_byte(&self) -> Result<i32, KernelError> {
        match self.len {
            0 => Err(KernelError::InvalidArgument),
            1..=3 => get_user::<Uaccess, u8>(self.ptr)
                .map(|v| v as i32)
                .map_err(|_| KernelError::BadAddress),
            _ => self.int(),
        }
    }

    /// The first `max` bytes
    pub fn bytes(&self, max: usize) -> Result<Vec<u8>, KernelError> {
        let n = self.len.min(max);
        let mut v = alloc::vec![0u8; n];
        if n > 0 {
            copy_from_user::<Uaccess>(&mut v, self.ptr, n).map_err(|_| KernelError::BadAddress)?;
        }
        Ok(v)
    }
}

/// A getsockopt result: copied out truncated to the user's length,
/// which is then set to the bytes written (Linux sk_getsockopt)
pub enum OptOut {
    Int(i32),
    Bytes(Vec<u8>),
}

/// Protocol operations of a socket (Linux proto_ops + the parts of
/// struct proto it calls). Defaults are the Linux sock_no_* errors.
pub trait ProtoOps: Send + Sync {
    fn as_any(&self) -> &dyn Any;
    /// Common state
    fn sk(&self) -> &Sock;
    /// Last close: unregister from all tables, wake waiters
    fn release(&self);

    fn bind(&self, _addr: &[u8]) -> Result<(), KernelError> {
        Err(KernelError::OperationNotSupported)
    }
    fn connect(&self, _addr: &[u8], _nonblock: bool) -> Result<(), KernelError> {
        Err(KernelError::OperationNotSupported)
    }
    fn listen(&self, _backlog: i32) -> Result<(), KernelError> {
        Err(KernelError::OperationNotSupported)
    }
    fn accept(&self, _nonblock: bool) -> Result<Arc<dyn ProtoOps>, KernelError> {
        Err(KernelError::OperationNotSupported)
    }
    /// Local (`peer` false) or remote address
    fn getname(&self, peer: bool) -> Result<Vec<u8>, KernelError>;
    /// Ready mask (the socket layer registers on `sk().wq`)
    fn poll(&self) -> u16;
    /// Protocol ioctl; `NotTty` falls back to the interface ioctls
    fn ioctl(&self, _cmd: u32, _arg: u64) -> Result<i64, KernelError> {
        Err(KernelError::NotTty)
    }
    fn shutdown(&self, _how: i32) -> Result<(), KernelError> {
        Err(KernelError::OperationNotSupported)
    }
    /// Options of levels other than SOL_SOCKET (and SOL_SOCKET options
    /// the protocol overrides: return `None` to use the generic code)
    fn setsockopt(&self, _level: i32, _opt: i32, _v: OptIn) -> Option<Result<(), KernelError>> {
        None
    }
    fn getsockopt(&self, _level: i32, _opt: i32) -> Option<Result<OptOut, KernelError>> {
        None
    }
    /// `flags` includes MSG_DONTWAIT for non-blocking files
    fn sendmsg(&self, m: &mut SendMsg, flags: i32) -> Result<usize, KernelError>;
    fn recvmsg(&self, m: &mut RecvMsg, flags: i32) -> Result<usize, KernelError>;
    /// Bytes queued for reading / not yet sent (FIONREAD, SIOCOUTQ)
    fn inq(&self) -> usize {
        0
    }
    /// Join this new socket and `other` (same family and type) back to
    /// back (Linux proto_ops.socketpair; sock_no_socketpair default)
    fn socketpair(&self, _other: &dyn ProtoOps) -> Result<(), KernelError> {
        Err(KernelError::OperationNotSupported)
    }
    /// Whether EPIPE from sendmsg raises SIGPIPE (Linux: stream
    /// protocols send it; AF_UNIX datagram/seqpacket sockets do not)
    fn sigpipe(&self) -> bool {
        true
    }
}

/// Inode private data: the protocol socket (Linux SOCKET_I)
struct SockInode(Arc<dyn ProtoOps>);

impl AsAny for SockInode {
    fn as_any(&self) -> &dyn Any {
        self
    }
}
impl InodeData for SockInode {}

/// Next sockfs inode number (Linux get_next_ino)
static NEXT_INO: AtomicU64 = AtomicU64::new(1);

/// The protocol socket behind a file, if it is a socket
pub fn sock_of(file: &File) -> Option<Arc<dyn ProtoOps>> {
    let inode = file.get_inode()?;
    if !inode.mode().is_socket() {
        return None;
    }
    let p = inode.get_private()?;
    Some(p.as_any().downcast_ref::<SockInode>()?.0.clone())
}

/// Wrap a protocol socket in a new sockfs file (Linux sock_alloc_file)
pub fn sock_alloc_file(sock: Arc<dyn ProtoOps>, nonblock: bool) -> Arc<File> {
    let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
    sock.sk().ino.store(ino, Ordering::Release);
    let cred = &sock.sk().cred;
    let now = crate::time::TIMEKEEPER.current_time();
    let inode = Arc::new(Inode::new(
        ino,
        InodeMode::socket(0o777),
        cred.fsuid,
        cred.fsgid,
        0,
        now,
        alloc::sync::Weak::new(),
        &NULL_INODE_OPS,
    ));
    inode.set_private(Arc::new(SockInode(sock)));
    let name = alloc::format!("socket:[{}]", ino);
    let dentry = Arc::new(Dentry::new_anonymous(
        String::from(name.as_str()),
        Some(inode),
    ));
    let mut flags = fflags::O_RDWR;
    if nonblock {
        flags |= fflags::O_NONBLOCK;
    }
    Arc::new(File::new(dentry, flags, &SOCK_FOPS))
}

/// Create a protocol socket (Linux __sock_create)
pub fn sock_create(
    family: i32,
    stype: i32,
    protocol: i32,
) -> Result<Arc<dyn ProtoOps>, KernelError> {
    if !(0..AF_MAX).contains(&family) {
        return Err(KernelError::AddressFamilyNotSupported);
    }
    if !(0..SOCK_MAX).contains(&stype) {
        return Err(KernelError::InvalidArgument);
    }
    let create = FAMILIES
        .iter()
        .find(|(f, _)| *f as i32 == family)
        .map(|(_, c)| c)
        .ok_or(KernelError::AddressFamilyNotSupported)?;
    create(stype, protocol)
}

type CreateFn = fn(i32, i32) -> Result<Arc<dyn ProtoOps>, KernelError>;

/// Registered families (AF_INET6 joins with IPv6, AF_PACKET in P9;
/// until then socket() is EAFNOSUPPORT for them)
static FAMILIES: &[(u16, CreateFn)] = &[
    (AF_UNIX, crate::net::unix::create),
    (AF_INET, crate::net::af_inet::create),
    (AF_NETLINK, crate::net::netlink::create),
];

/// File operations shared by all sockets (Linux socket_file_ops)
pub struct SockFile;
pub static SOCK_FOPS: SockFile = SockFile;

/// MSG_DONTWAIT when the file is non-blocking (checked per call)
pub fn file_nb(file: &File, flags: i32) -> i32 {
    if file.get_flags() & fflags::O_NONBLOCK != 0 {
        flags | MSG_DONTWAIT
    } else {
        flags
    }
}

/// Send with the socket-layer EPIPE rule: SIGPIPE unless MSG_NOSIGNAL
/// (Linux sock_sendmsg callers / sk_stream_error)
pub fn sock_sendmsg(s: &dyn ProtoOps, m: &mut SendMsg, flags: i32) -> Result<usize, KernelError> {
    let r = s.sendmsg(m, flags);
    if r == Err(KernelError::BrokenPipe) && flags & MSG_NOSIGNAL == 0 && s.sigpipe() {
        let tid = crate::task::percpu::current_tid();
        crate::signal::send_signal(tid, crate::signal::SIGPIPE);
    }
    r
}

impl FileOps for SockFile {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize, KernelError> {
        let s = sock_of(file).ok_or(KernelError::NotSocket)?;
        let mut m = RecvMsg::new(Dst::Kern(buf), false, 0);
        s.recvmsg(&mut m, file_nb(file, 0))
    }

    fn write(&self, file: &File, buf: &[u8]) -> Result<usize, KernelError> {
        let s = sock_of(file).ok_or(KernelError::NotSocket)?;
        let mut m = SendMsg {
            addr: None,
            data: Src::Kern(buf),
            control: Vec::new(),
        };
        let r = sock_sendmsg(&*s, &mut m, file_nb(file, 0));
        crate::net::dev::netif_rx_flush_local();
        r
    }

    fn llseek(&self, _file: &File, _offset: i64, _whence: i32) -> Result<u64, KernelError> {
        Err(KernelError::IllegalSeek)
    }

    fn poll(&self, file: &File, pt: Option<&mut PollTable>) -> u16 {
        let Some(s) = sock_of(file) else {
            return crate::poll::POLLNVAL;
        };
        if let Some(pt) = pt {
            pt.poll_wait(&s.sk().wq);
        }
        s.poll()
    }

    fn ioctl(&self, file: &File, cmd: u32, arg: u64) -> Result<i64, KernelError> {
        let s = sock_of(file).ok_or(KernelError::NotSocket)?;
        sock_ioctl(&*s, file, cmd, arg)
    }

    fn release(&self, file: &File) -> Result<(), KernelError> {
        if let Some(s) = sock_of(file) {
            s.release();
        }
        Ok(())
    }
}

/// ioctl constants
pub const FIONREAD: u32 = 0x541B;
pub const SIOCINQ: u32 = FIONREAD;
pub const SIOCOUTQ: u32 = 0x5411;
const FIOSETOWN: u32 = 0x8901;
const SIOCSPGRP: u32 = 0x8902;
const FIOGETOWN: u32 = 0x8903;
const SIOCGPGRP: u32 = 0x8904;

/// Linux sock_ioctl: owner commands, then the protocol, then the
/// interface ioctls of the socket's namespace
fn sock_ioctl(s: &dyn ProtoOps, file: &File, cmd: u32, arg: u64) -> Result<i64, KernelError> {
    match cmd {
        FIOSETOWN | SIOCSPGRP => {
            let who = get_user::<Uaccess, i32>(arg).map_err(|_| KernelError::BadAddress)?;
            crate::fs::fd::f_setown(file, who)?;
            return Ok(0);
        }
        FIOGETOWN | SIOCGPGRP => {
            put_user::<Uaccess, i32>(arg, file.get_owner()).map_err(|_| KernelError::BadAddress)?;
            return Ok(0);
        }
        _ => {}
    }
    match s.ioctl(cmd, arg) {
        Err(KernelError::NotTty) => {
            let inet = s.sk().family == AF_INET;
            crate::net::devioctl::ioctl(&s.sk().net, inet, cmd, arg)
        }
        r => r,
    }
}

// ============================================================================
// SOL_SOCKET options (Linux sk_setsockopt / sk_getsockopt)
// ============================================================================

pub const SOL_SOCKET: i32 = 1;
pub const SO_DEBUG: i32 = 1;
pub const SO_REUSEADDR: i32 = 2;
pub const SO_TYPE: i32 = 3;
pub const SO_ERROR: i32 = 4;
pub const SO_DONTROUTE: i32 = 5;
pub const SO_BROADCAST: i32 = 6;
pub const SO_SNDBUF: i32 = 7;
pub const SO_RCVBUF: i32 = 8;
pub const SO_KEEPALIVE: i32 = 9;
pub const SO_OOBINLINE: i32 = 10;
pub const SO_NO_CHECK: i32 = 11;
pub const SO_PRIORITY: i32 = 12;
pub const SO_LINGER: i32 = 13;
pub const SO_REUSEPORT: i32 = 15;
pub const SO_PASSCRED: i32 = 16;
pub const SO_PEERCRED: i32 = 17;
pub const SO_RCVLOWAT: i32 = 18;
pub const SO_SNDLOWAT: i32 = 19;
pub const SO_RCVTIMEO_OLD: i32 = 20;
pub const SO_SNDTIMEO_OLD: i32 = 21;
pub const SO_BINDTODEVICE: i32 = 25;
pub const SO_TIMESTAMP_OLD: i32 = 29;
pub const SO_ACCEPTCONN: i32 = 30;
pub const SO_SNDBUFFORCE: i32 = 32;
pub const SO_RCVBUFFORCE: i32 = 33;
pub const SO_PASSSEC: i32 = 34;
pub const SO_TIMESTAMPNS_OLD: i32 = 35;
pub const SO_MARK: i32 = 36;
pub const SO_PROTOCOL: i32 = 38;
pub const SO_DOMAIN: i32 = 39;
pub const SO_RXQ_OVFL: i32 = 40;
pub const SO_PEEK_OFF: i32 = 42;
pub const SO_COOKIE: i32 = 57;
pub const SO_BINDTOIFINDEX: i32 = 62;
pub const SO_RCVTIMEO_NEW: i32 = 66;
pub const SO_SNDTIMEO_NEW: i32 = 67;

/// Boolean SOL_SOCKET options and their flag
fn bool_opt(opt: i32) -> Option<u32> {
    Some(match opt {
        SO_REUSEADDR => sf::REUSEADDR,
        SO_KEEPALIVE => sf::KEEPALIVE,
        SO_BROADCAST => sf::BROADCAST,
        SO_DONTROUTE => sf::DONTROUTE,
        SO_OOBINLINE => sf::OOBINLINE,
        SO_TIMESTAMP_OLD => sf::TIMESTAMP,
        SO_TIMESTAMPNS_OLD => sf::TIMESTAMPNS,
        SO_PASSCRED => sf::PASSCRED,
        SO_RXQ_OVFL => sf::RXQ_OVFL,
        SO_NO_CHECK => sf::NO_CHECK,
        SO_PASSSEC => sf::PASSSEC,
        _ => return None,
    })
}

fn cap(c: u32) -> bool {
    crate::task::capable(c)
}

/// setsockopt(SOL_SOCKET)
pub fn sock_setsockopt(s: &dyn ProtoOps, opt: i32, v: OptIn) -> Result<(), KernelError> {
    let sk = s.sk();
    if opt == SO_BINDTODEVICE {
        return bindtodevice(sk, v);
    }
    let val = v.int()?;
    match opt {
        SO_DEBUG => {
            if val != 0 && !cap(crate::task::CAP_NET_ADMIN) {
                return Err(KernelError::PermissionDenied);
            }
            sk.set_flag(sf::DEBUG, val != 0);
        }
        SO_REUSEPORT => {
            if val != 0 && sk.family != AF_INET && sk.family != AF_INET6 {
                return Err(KernelError::OperationNotSupported);
            }
            sk.set_flag(sf::REUSEPORT, val != 0);
        }
        SO_SNDBUF | SO_SNDBUFFORCE | SO_RCVBUF | SO_RCVBUFFORCE => {
            let force = opt == SO_SNDBUFFORCE || opt == SO_RCVBUFFORCE;
            if force && !cap(crate::task::CAP_NET_ADMIN) {
                return Err(KernelError::NotPermitted);
            }
            if opt == SO_SNDBUF || opt == SO_SNDBUFFORCE {
                sk.set_sndbuf(val, force);
            } else {
                sk.set_rcvbuf(val, force);
            }
        }
        SO_PRIORITY => {
            if !(0..=6).contains(&val) && !cap(crate::task::CAP_NET_ADMIN) {
                return Err(KernelError::NotPermitted);
            }
            sk.priority.store(val as u32, Ordering::Release);
        }
        SO_LINGER => {
            if v.len < 8 {
                return Err(KernelError::InvalidArgument);
            }
            let secs = get_user::<Uaccess, i32>(v.ptr + 4).map_err(|_| KernelError::BadAddress)?;
            sk.set_linger(val != 0, secs.max(0) as u32);
        }
        SO_RCVLOWAT => sk.set_rcvlowat(val),
        SO_RCVTIMEO_OLD | SO_RCVTIMEO_NEW | SO_SNDTIMEO_OLD | SO_SNDTIMEO_NEW => {
            let rcv = opt == SO_RCVTIMEO_OLD || opt == SO_RCVTIMEO_NEW;
            sk.set_timeo(rcv, read_timeval(v)?);
        }
        SO_MARK => {
            if !cap(crate::task::CAP_NET_RAW) && !cap(crate::task::CAP_NET_ADMIN) {
                return Err(KernelError::NotPermitted);
            }
            sk.mark.store(val as u32, Ordering::Release);
        }
        SO_BINDTOIFINDEX => bind_ifindex(sk, val)?,
        // Datagram peek offsets are not implemented (BUGS.md)
        SO_PEEK_OFF => return Err(KernelError::OperationNotSupported),
        o => {
            let f = bool_opt(o).ok_or(KernelError::NoProtocolOption)?;
            sk.set_flag(f, val != 0);
        }
    }
    Ok(())
}

/// struct timeval of SO_RCVTIMEO/SO_SNDTIMEO -> ns (Linux
/// sock_set_timeout: EDOM for bad usec, negative = 0, zero = forever)
fn read_timeval(v: OptIn) -> Result<u64, KernelError> {
    if v.len < 16 {
        return Err(KernelError::InvalidArgument);
    }
    let sec = get_user::<Uaccess, i64>(v.ptr).map_err(|_| KernelError::BadAddress)?;
    let usec = get_user::<Uaccess, i64>(v.ptr + 8).map_err(|_| KernelError::BadAddress)?;
    if !(0..1_000_000).contains(&usec) {
        return Err(KernelError::MathDomain);
    }
    if sec < 0 {
        return Ok(0);
    }
    if sec == 0 && usec == 0 {
        return Ok(TIMEO_FOREVER);
    }
    Ok((sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(usec as u64 * 1000)
        .min(TIMEO_FOREVER - 1))
}

fn timeval_bytes(ns: u64) -> Vec<u8> {
    let (sec, usec) = if ns == TIMEO_FOREVER {
        (0, 0)
    } else {
        (
            (ns / 1_000_000_000) as i64,
            ((ns % 1_000_000_000) / 1000) as i64,
        )
    };
    let mut b = Vec::with_capacity(16);
    b.extend_from_slice(&sec.to_ne_bytes());
    b.extend_from_slice(&usec.to_ne_bytes());
    b
}

/// SO_BINDTODEVICE: interface name; empty unbinds; changing an existing
/// binding needs CAP_NET_RAW (Linux sock_bindtoindex_locked)
fn bindtodevice(sk: &Sock, v: OptIn) -> Result<(), KernelError> {
    let b = v.bytes(crate::net::inet::ifaddr::IFNAMSIZ - 1)?;
    let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    let name = core::str::from_utf8(&b[..n]).map_err(|_| KernelError::NoDevice)?;
    let idx = if name.is_empty() {
        0
    } else {
        sk.net
            .get_device(name)
            .ok_or(KernelError::NoDevice)?
            .ifindex()
    };
    bind_ifindex(sk, idx as i32)
}

fn bind_ifindex(sk: &Sock, idx: i32) -> Result<(), KernelError> {
    if sk.bound_dev_if() != 0 && !cap(crate::task::CAP_NET_RAW) {
        return Err(KernelError::NotPermitted);
    }
    if idx < 0 {
        return Err(KernelError::InvalidArgument);
    }
    if idx != 0 && sk.net.dev_get_by_index(idx as u32).is_none() {
        return Err(KernelError::NoDevice);
    }
    sk.set_bound_dev_if(idx as u32);
    Ok(())
}

/// getsockopt(SOL_SOCKET)
pub fn sock_getsockopt(s: &dyn ProtoOps, opt: i32) -> Result<OptOut, KernelError> {
    let sk = s.sk();
    let int = |v: i32| Ok(OptOut::Int(v));
    match opt {
        SO_TYPE => int(sk.stype),
        SO_PROTOCOL => int(sk.protocol),
        SO_DOMAIN => int(sk.family as i32),
        SO_ERROR => int(sk.take_errno()),
        SO_ACCEPTCONN => int(sk.flag(sf::ACCEPTCONN) as i32),
        SO_REUSEPORT => int(sk.flag(sf::REUSEPORT) as i32),
        SO_DEBUG => int(sk.flag(sf::DEBUG) as i32),
        SO_SNDBUF => int(sk.sndbuf() as i32),
        SO_RCVBUF => int(sk.rcvbuf() as i32),
        SO_PRIORITY => int(sk.priority.load(Ordering::Acquire) as i32),
        SO_MARK => int(sk.mark.load(Ordering::Acquire) as i32),
        SO_RCVLOWAT => int(sk.rcvlowat()),
        SO_SNDLOWAT => int(1),
        SO_BINDTOIFINDEX => int(sk.bound_dev_if() as i32),
        SO_COOKIE => Ok(OptOut::Bytes(
            sk.ino.load(Ordering::Acquire).to_ne_bytes().to_vec(),
        )),
        SO_LINGER => {
            let mut b = Vec::with_capacity(8);
            b.extend_from_slice(&(sk.flag(sf::LINGER) as i32).to_ne_bytes());
            b.extend_from_slice(&(sk.linger_secs() as i32).to_ne_bytes());
            Ok(OptOut::Bytes(b))
        }
        SO_RCVTIMEO_OLD | SO_RCVTIMEO_NEW => Ok(OptOut::Bytes(timeval_bytes(sk.rcvtimeo()))),
        SO_SNDTIMEO_OLD | SO_SNDTIMEO_NEW => Ok(OptOut::Bytes(timeval_bytes(sk.sndtimeo()))),
        SO_PEERCRED => Ok(OptOut::Bytes(peercred_bytes(None))),
        SO_BINDTODEVICE => {
            let i = sk.bound_dev_if();
            let mut b = Vec::new();
            if let Some(d) = sk.net.dev_get_by_index(i) {
                b.extend_from_slice(d.name().as_bytes());
                b.push(0);
            }
            Ok(OptOut::Bytes(b))
        }
        o => {
            let f = bool_opt(o).ok_or(KernelError::NoProtocolOption)?;
            int(sk.flag(f) as i32)
        }
    }
}

/// struct ucred of SO_PEERCRED (Linux cred_to_ucred): without peer
/// credentials pid 0 and uid/gid -1
pub fn peercred_bytes(c: Option<(i32, u32, u32)>) -> Vec<u8> {
    let (pid, uid, gid) = c.unwrap_or((0, u32::MAX, u32::MAX));
    let mut b = Vec::with_capacity(12);
    b.extend_from_slice(&pid.to_ne_bytes());
    b.extend_from_slice(&uid.to_ne_bytes());
    b.extend_from_slice(&gid.to_ne_bytes());
    b
}

/// Copy a getsockopt result out: `len` is the user's (validated >= 0)
/// buffer size; ints shorter than 4 bytes are truncated like Linux
pub fn put_opt(out: OptOut, val: u64, lenp: u64, len: i32) -> Result<(), KernelError> {
    let b = match out {
        OptOut::Int(v) => v.to_ne_bytes().to_vec(),
        OptOut::Bytes(b) => b,
    };
    let n = (len as usize).min(b.len());
    if n > 0 {
        copy_to_user::<Uaccess>(val, &b[..n]).map_err(|_| KernelError::BadAddress)?;
    }
    put_user::<Uaccess, i32>(lenp, n as i32).map_err(|_| KernelError::BadAddress)
}

/// Read a shutdown(2) `how` into shutdown bits (EINVAL otherwise)
pub fn shut_bits(how: i32) -> Result<u8, KernelError> {
    use crate::net::sock::{RCV_SHUTDOWN, SEND_SHUTDOWN};
    match how {
        SHUT_RD => Ok(RCV_SHUTDOWN),
        SHUT_WR => Ok(SEND_SHUTDOWN),
        SHUT_RDWR => Ok(RCV_SHUTDOWN | SEND_SHUTDOWN),
        _ => Err(KernelError::InvalidArgument),
    }
}

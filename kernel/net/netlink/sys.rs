//! AF_NETLINK socket system calls and file operations (Linux
//! netlink_bind/connect/getname/sendmsg/recvmsg/setsockopt/getsockopt)
//!
//! Entered from `net::syscall` when the fd is a netlink socket. All user
//! memory goes through uaccess.

use alloc::boxed::Box;
use alloc::sync::Arc;

use super::*;
use crate::fs::file::{File, FileOps, flags as fflags};
use crate::net::syscall::{
    UserMsgHdr, copy_in, gather_iovec, install_file, put_addr, read_iovecs, read_msghdr,
    scatter_iovec, write_msghdr_out,
};
use crate::poll::{POLLERR, POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM, PollTable};
use crate::uaccess::{copy_to_user, get_user, put_user};

#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::uaccess::Aarch64Uaccess as Uaccess;
#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::uaccess::X86_64Uaccess as Uaccess;

const SOCK_DGRAM: i32 = 2;
const SOCK_RAW: i32 = 3;
const AF_UNSPEC: u16 = 0;

const MSG_PEEK: i32 = 0x02;
const MSG_CTRUNC: i32 = 0x08;
const MSG_TRUNC: i32 = 0x20;
const MSG_DONTWAIT: i32 = 0x40;

const SOL_SOCKET: i32 = 1;
const SO_TYPE: i32 = 3;
const SO_ERROR: i32 = 4;
const SO_SNDBUF: i32 = 7;
const SO_RCVBUF: i32 = 8;
const SO_DOMAIN: i32 = 39;
const SO_PROTOCOL: i32 = 38;
const SO_SNDBUFFORCE: i32 = 32;
const SO_RCVBUFFORCE: i32 = 33;
/// SOL_SOCKET options accepted without effect
const SO_IGNORED: &[i32] = &[
    2,  // SO_REUSEADDR
    6,  // SO_BROADCAST
    9,  // SO_KEEPALIVE
    12, // SO_PRIORITY
    15, // SO_REUSEPORT
    16, // SO_PASSCRED
    29, // SO_TIMESTAMP
    34, // SO_PASSSEC
    35, // SO_TIMESTAMPNS
];
/// Linux rmem_max / wmem_max
const BUF_MAX: u32 = 212_992;

/// File operations of a netlink socket
pub struct NlFile {
    pub sk: Arc<NlSock>,
}

impl FileOps for NlFile {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize, KernelError> {
        let skb = self.sk.recv(false, nonblock(file, 0))?;
        let n = skb.data.len().min(buf.len());
        buf[..n].copy_from_slice(&skb.data[..n]);
        Ok(n)
    }

    fn write(&self, _file: &File, buf: &[u8]) -> Result<usize, KernelError> {
        let (pid, group) = self.sk.dst();
        self.sk.send(buf, pid, group)
    }

    fn poll(&self, _file: &File, pt: Option<&mut PollTable>) -> u16 {
        if let Some(pt) = pt {
            pt.poll_wait(&self.sk.wq);
        }
        let mut mask = POLLOUT | POLLWRNORM;
        if self.sk.readable() {
            mask |= POLLIN | POLLRDNORM;
        }
        if self.sk.has_error() {
            mask |= POLLERR;
        }
        mask
    }

    fn ioctl(&self, _file: &File, cmd: u32, arg: u64) -> Result<i64, KernelError> {
        crate::net::devioctl::ioctl(&self.sk.net, false, cmd, arg)
    }

    fn release(&self, _file: &File) -> Result<(), KernelError> {
        self.sk.release();
        Ok(())
    }
}

fn nonblock(file: &File, flags: i32) -> bool {
    file.get_flags() & fflags::O_NONBLOCK != 0 || flags & MSG_DONTWAIT != 0
}

/// socket(AF_NETLINK, type, protocol)
pub fn socket(stype: i32, protocol: i32, file_flags: u32) -> i64 {
    if stype != SOCK_RAW && stype != SOCK_DGRAM {
        return KernelError::SocketTypeNotSupported.sysret();
    }
    if protocol != NETLINK_ROUTE {
        return KernelError::ProtocolNotSupported.sysret();
    }
    let sk = NlSock::new(protocol, stype);
    let ops: &'static dyn FileOps = Box::leak(Box::new(NlFile { sk }));
    install_file(ops, file_flags)
}

/// Read a struct sockaddr_nl: (family, pid, groups)
fn read_nladdr(addr: u64, len: u64) -> Result<(u16, u32, u32), KernelError> {
    if len < SOCKADDR_NL_LEN as u64 {
        return Err(KernelError::InvalidArgument);
    }
    let b = copy_in(addr, SOCKADDR_NL_LEN).map_err(|_| KernelError::BadAddress)?;
    let w = |o: usize| u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
    Ok((u16::from_ne_bytes([b[0], b[1]]), w(4), w(8)))
}

fn nladdr_bytes(pid: u32, groups: u32) -> [u8; SOCKADDR_NL_LEN] {
    let mut b = [0u8; SOCKADDR_NL_LEN];
    b[..2].copy_from_slice(&(AF_NETLINK as u16).to_ne_bytes());
    b[4..8].copy_from_slice(&pid.to_ne_bytes());
    b[8..12].copy_from_slice(&groups.to_ne_bytes());
    b
}

fn ret(r: Result<i64, KernelError>) -> i64 {
    r.unwrap_or_else(|e| e.sysret())
}

/// bind(2)
pub fn bind(sk: &Arc<NlSock>, addr: u64, len: u64) -> i64 {
    ret((|| {
        let (fam, pid, groups) = read_nladdr(addr, len)?;
        if fam != AF_NETLINK as u16 {
            return Err(KernelError::InvalidArgument);
        }
        sk.bind(pid, groups)?;
        Ok(0)
    })())
}

/// connect(2): AF_UNSPEC disconnects
pub fn connect(sk: &Arc<NlSock>, addr: u64, len: u64) -> i64 {
    ret((|| {
        if len < 2 {
            return Err(KernelError::InvalidArgument);
        }
        let fam = get_user::<Uaccess, u16>(addr).map_err(|_| KernelError::BadAddress)?;
        if fam == AF_UNSPEC {
            sk.disconnect();
            return Ok(0);
        }
        let (fam, pid, groups) = read_nladdr(addr, len)?;
        if fam != AF_NETLINK as u16 {
            return Err(KernelError::InvalidArgument);
        }
        if (pid != 0 || groups != 0) && !crate::task::capable(crate::task::CAP_NET_ADMIN) {
            return Err(KernelError::NotPermitted);
        }
        sk.connect(pid, groups)?;
        Ok(0)
    })())
}

/// getsockname(2) / getpeername(2)
pub fn getname(sk: &NlSock, addr: u64, len: u64, peer: bool) -> i64 {
    let b = if peer {
        let (pid, group) = sk.dst();
        let g = if group == 0 { 0 } else { 1u32 << (group - 1) };
        nladdr_bytes(pid, g)
    } else {
        nladdr_bytes(sk.portid(), sk.groups32())
    };
    put_addr(addr, len, &b)
}

/// Destination of a send: explicit sockaddr_nl or the connected one
fn dest(sk: &NlSock, name: u64, namelen: u64) -> Result<(u32, u32), KernelError> {
    if name == 0 {
        return Ok(sk.dst());
    }
    let (fam, pid, groups) = read_nladdr(name, namelen)?;
    if fam != AF_NETLINK as u16 {
        return Err(KernelError::InvalidArgument);
    }
    let group = if groups == 0 {
        0
    } else {
        groups.trailing_zeros() + 1
    };
    if (group != 0 || pid != 0) && !crate::task::capable(crate::task::CAP_NET_ADMIN) {
        return Err(KernelError::NotPermitted);
    }
    Ok((pid, group))
}

/// sendto(2)
pub fn sendto(sk: &Arc<NlSock>, buf: u64, len: u64, name: u64, namelen: u64) -> i64 {
    ret((|| {
        let (pid, group) = dest(sk, name, namelen)?;
        if len as usize + 32 > sk.sndbuf.load(core::sync::atomic::Ordering::Acquire) as usize {
            return Err(KernelError::MessageTooLong);
        }
        let data = copy_in(buf, len as usize).map_err(|_| KernelError::BadAddress)?;
        Ok(sk.send(&data, pid, group)? as i64)
    })())
}

/// sendmsg(2)
pub fn sendmsg(sk: &Arc<NlSock>, msg: u64) -> i64 {
    ret((|| {
        let h = read_msghdr(msg).map_err(|_| KernelError::BadAddress)?;
        let (pid, group) = dest(sk, h.msg_name, h.msg_namelen as u64)?;
        let data = gather_iovec(h.msg_iov, h.msg_iovlen).map_err(err_of)?;
        Ok(sk.send(&data, pid, group)? as i64)
    })())
}

fn err_of(e: i64) -> KernelError {
    if e == KernelError::InvalidArgument.sysret() {
        KernelError::InvalidArgument
    } else {
        KernelError::BadAddress
    }
}

/// recvfrom(2)
pub fn recvfrom(
    sk: &NlSock,
    file: &File,
    buf: u64,
    len: u64,
    flags: i32,
    name: u64,
    namelen: u64,
) -> i64 {
    ret((|| {
        let skb = sk.recv(flags & MSG_PEEK != 0, nonblock(file, flags))?;
        let n = skb.data.len().min(len as usize);
        copy_to_user::<Uaccess>(buf, &skb.data[..n]).map_err(|_| KernelError::BadAddress)?;
        if name != 0 && namelen != 0 {
            let r = put_addr(
                name,
                namelen,
                &nladdr_bytes(skb.portid, group_mask(skb.group)),
            );
            if r < 0 {
                return Err(KernelError::BadAddress);
            }
        }
        Ok(if flags & MSG_TRUNC != 0 {
            skb.data.len()
        } else {
            n
        } as i64)
    })())
}

fn group_mask(group: u32) -> u32 {
    if group == 0 || group > 32 {
        0
    } else {
        1 << (group - 1)
    }
}

/// recvmsg(2): datagram semantics (MSG_TRUNC in msg_flags when cut;
/// the MSG_TRUNC flag returns the real length), NETLINK_PKTINFO cmsg
pub fn recvmsg(sk: &NlSock, file: &File, msg: u64, flags: i32) -> i64 {
    ret((|| {
        let h: UserMsgHdr = read_msghdr(msg).map_err(|_| KernelError::BadAddress)?;
        let space = read_iovecs(h.msg_iov, h.msg_iovlen)
            .map_err(err_of)?
            .iter()
            .fold(0usize, |a, v| a.saturating_add(v.iov_len));
        let skb = sk.recv(flags & MSG_PEEK != 0, nonblock(file, flags))?;
        let n = skb.data.len().min(space);
        scatter_iovec(h.msg_iov, h.msg_iovlen, &skb.data[..n]);
        let mut oflags = 0;
        if n < skb.data.len() {
            oflags |= MSG_TRUNC;
        }
        let mut namelen = 0;
        if h.msg_name != 0 {
            let b = nladdr_bytes(skb.portid, group_mask(skb.group));
            let k = (h.msg_namelen as usize).min(b.len());
            copy_to_user::<Uaccess>(h.msg_name, &b[..k]).map_err(|_| KernelError::BadAddress)?;
            namelen = SOCKADDR_NL_LEN as u32;
        }
        let mut ctl = 0usize;
        if sk.has_flag(sflags::PKTINFO) && h.msg_control != 0 {
            // struct cmsghdr { u64 len; i32 level; i32 type } + u32 group
            const CMSG_LEN: usize = 20;
            if h.msg_controllen < CMSG_LEN {
                oflags |= MSG_CTRUNC;
            } else {
                let mut c = [0u8; 24];
                c[..8].copy_from_slice(&(CMSG_LEN as u64).to_ne_bytes());
                c[8..12].copy_from_slice(&SOL_NETLINK.to_ne_bytes());
                c[12..16].copy_from_slice(&NETLINK_PKTINFO.to_ne_bytes());
                c[16..20].copy_from_slice(&skb.group.to_ne_bytes());
                ctl = h.msg_controllen.min(24);
                copy_to_user::<Uaccess>(h.msg_control, &c[..ctl])
                    .map_err(|_| KernelError::BadAddress)?;
            }
        }
        write_msghdr_out(msg, namelen, oflags, ctl).map_err(|_| KernelError::BadAddress)?;
        Ok(if flags & MSG_TRUNC != 0 {
            skb.data.len()
        } else {
            n
        } as i64)
    })())
}

/// SOL_NETLINK option -> flag bit
fn opt_flag(opt: i32) -> Option<u32> {
    Some(match opt {
        NETLINK_PKTINFO => sflags::PKTINFO,
        NETLINK_BROADCAST_ERROR => sflags::BCAST_ERR,
        NETLINK_NO_ENOBUFS => sflags::NO_ENOBUFS,
        NETLINK_LISTEN_ALL_NSID => sflags::LISTEN_ALL,
        NETLINK_CAP_ACK => sflags::CAP_ACK,
        NETLINK_EXT_ACK => sflags::EXT_ACK,
        NETLINK_GET_STRICT_CHK => sflags::STRICT_CHK,
        _ => return None,
    })
}

/// setsockopt(2)
pub fn setsockopt(sk: &Arc<NlSock>, level: i32, opt: i32, val: u64, len: u64) -> i64 {
    ret((|| {
        let v = if len >= 4 {
            get_user::<Uaccess, i32>(val).map_err(|_| KernelError::BadAddress)?
        } else {
            0
        };
        match level {
            SOL_NETLINK => match opt {
                NETLINK_ADD_MEMBERSHIP | NETLINK_DROP_MEMBERSHIP => {
                    sk.membership(v as u32, opt == NETLINK_ADD_MEMBERSHIP)?;
                }
                _ => {
                    let f = opt_flag(opt).ok_or(KernelError::NoProtocolOption)?;
                    sk.set_flag(f, v != 0);
                }
            },
            SOL_SOCKET => {
                if len < 4 {
                    return Err(KernelError::InvalidArgument);
                }
                let force = opt == SO_RCVBUFFORCE || opt == SO_SNDBUFFORCE;
                if force && !crate::task::capable(crate::task::CAP_NET_ADMIN) {
                    return Err(KernelError::NotPermitted);
                }
                let size = |v: i32| {
                    let v = v.max(0) as u32;
                    let v = if force { v } else { v.min(BUF_MAX) };
                    v.min(i32::MAX as u32 / 2).saturating_mul(2).max(SK_BUF_MIN)
                };
                use core::sync::atomic::Ordering::Release;
                match opt {
                    SO_RCVBUF | SO_RCVBUFFORCE => sk.rcvbuf.store(size(v), Release),
                    SO_SNDBUF | SO_SNDBUFFORCE => sk.sndbuf.store(size(v), Release),
                    o if SO_IGNORED.contains(&o) => {}
                    _ => return Err(KernelError::NoProtocolOption),
                }
            }
            _ => return Err(KernelError::NoProtocolOption),
        }
        Ok(0)
    })())
}

/// getsockopt(2)
pub fn getsockopt(sk: &NlSock, level: i32, opt: i32, val: u64, lenp: u64) -> i64 {
    ret((|| {
        let len = get_user::<Uaccess, i32>(lenp).map_err(|_| KernelError::BadAddress)?;
        if len < 0 {
            return Err(KernelError::InvalidArgument);
        }
        use core::sync::atomic::Ordering::Acquire;
        let int = match (level, opt) {
            (SOL_SOCKET, SO_TYPE) => sk.stype,
            (SOL_SOCKET, SO_DOMAIN) => AF_NETLINK,
            (SOL_SOCKET, SO_PROTOCOL) => sk.protocol,
            (SOL_SOCKET, SO_RCVBUF) => sk.rcvbuf.load(Acquire) as i32,
            (SOL_SOCKET, SO_SNDBUF) => sk.sndbuf.load(Acquire) as i32,
            (SOL_SOCKET, SO_ERROR) => sk.take_error(),
            (SOL_SOCKET, o) if SO_IGNORED.contains(&o) => 0,
            (SOL_NETLINK, NETLINK_LIST_MEMBERSHIPS) => {
                let g = sk.groups_all();
                let need = 8usize;
                let mut b = [0u8; 8];
                b[..4].copy_from_slice(&(g as u32).to_ne_bytes());
                b[4..].copy_from_slice(&((g >> 32) as u32).to_ne_bytes());
                let k = (len as usize / 4 * 4).min(need);
                copy_to_user::<Uaccess>(val, &b[..k]).map_err(|_| KernelError::BadAddress)?;
                put_user::<Uaccess, i32>(lenp, need as i32).map_err(|_| KernelError::BadAddress)?;
                return Ok(0);
            }
            (SOL_NETLINK, o) => {
                let f = opt_flag(o).ok_or(KernelError::NoProtocolOption)?;
                sk.has_flag(f) as i32
            }
            _ => return Err(KernelError::NoProtocolOption),
        };
        if len < 4 {
            return Err(KernelError::InvalidArgument);
        }
        put_user::<Uaccess, i32>(val, int).map_err(|_| KernelError::BadAddress)?;
        put_user::<Uaccess, i32>(lenp, 4).map_err(|_| KernelError::BadAddress)?;
        Ok(0)
    })())
}

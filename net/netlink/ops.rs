//! AF_NETLINK socket operations (Linux netlink_bind/connect/getname/
//! sendmsg/recvmsg/setsockopt/getsockopt)

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

use super::*;
use crate::net::msg::{MSG_DONTWAIT, MSG_PEEK, MSG_TRUNC, RecvMsg, SendMsg};
use crate::net::socket::{AF_UNSPEC, OptIn, OptOut, SOL_SOCKET};
use crate::poll::{POLLERR, POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM};

/// Parse a struct sockaddr_nl: (pid, groups); EINVAL if short or not
/// AF_NETLINK
fn nladdr(a: &[u8]) -> Result<(u32, u32), KernelError> {
    if a.len() < SOCKADDR_NL_LEN {
        return Err(KernelError::InvalidArgument);
    }
    if u16::from_ne_bytes([a[0], a[1]]) != AF_NETLINK as u16 {
        return Err(KernelError::InvalidArgument);
    }
    let w = |o: usize| u32::from_ne_bytes([a[o], a[o + 1], a[o + 2], a[o + 3]]);
    Ok((w(4), w(8)))
}

fn nladdr_bytes(pid: u32, groups: u32) -> Vec<u8> {
    let mut b = alloc::vec![0u8; SOCKADDR_NL_LEN];
    b[..2].copy_from_slice(&(AF_NETLINK as u16).to_ne_bytes());
    b[4..8].copy_from_slice(&pid.to_ne_bytes());
    b[8..12].copy_from_slice(&groups.to_ne_bytes());
    b
}

fn group_mask(group: u32) -> u32 {
    if group == 0 || group > 32 {
        0
    } else {
        1 << (group - 1)
    }
}

/// Sending to a port or group needs CAP_NET_ADMIN for NETLINK_ROUTE
/// (Linux netlink_allowed(NL_CFG_F_NONROOT_SEND))
fn may_send_to(pid: u32, group: u32) -> Result<(), KernelError> {
    if (pid != 0 || group != 0) && !crate::task::capable(crate::task::CAP_NET_ADMIN) {
        return Err(KernelError::NotPermitted);
    }
    Ok(())
}

impl NlSock {
    /// Destination of a send: explicit sockaddr_nl or the connected one
    fn dest(&self, m: &SendMsg) -> Result<NlDst, KernelError> {
        let Some(a) = &m.addr else {
            let (portid, group) = self.dst();
            return Ok(NlDst {
                portid,
                group,
                explicit: false,
            });
        };
        let (pid, groups) = nladdr(a)?;
        let group = if groups == 0 {
            0
        } else {
            groups.trailing_zeros() + 1
        };
        may_send_to(pid, group)?;
        Ok(NlDst {
            portid: pid,
            group,
            explicit: true,
        })
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

    fn set_nl_opt(self: &Arc<Self>, opt: i32, v: OptIn) -> Result<(), KernelError> {
        let val = if v.len >= 4 { v.int()? } else { 0 };
        match opt {
            NETLINK_ADD_MEMBERSHIP | NETLINK_DROP_MEMBERSHIP => {
                self.membership(val as u32, opt == NETLINK_ADD_MEMBERSHIP)
            }
            _ => {
                let f = Self::opt_flag(opt).ok_or(KernelError::NoProtocolOption)?;
                self.set_flag(f, val != 0);
                Ok(())
            }
        }
    }

    fn get_nl_opt(&self, opt: i32) -> Result<OptOut, KernelError> {
        if opt == NETLINK_LIST_MEMBERSHIPS {
            let g = self.groups_all();
            let mut b = Vec::with_capacity(8);
            b.extend_from_slice(&(g as u32).to_ne_bytes());
            b.extend_from_slice(&((g >> 32) as u32).to_ne_bytes());
            return Ok(OptOut::Bytes(b));
        }
        let f = Self::opt_flag(opt).ok_or(KernelError::NoProtocolOption)?;
        Ok(OptOut::Int(self.has_flag(f) as i32))
    }

    fn arc(&self) -> Arc<NlSock> {
        self.me.upgrade().expect("netlink socket alive")
    }
}

impl ProtoOps for NlSock {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn sk(&self) -> &Sock {
        &self.sk
    }

    fn release(&self) {
        NlSock::release(self);
    }

    fn bind(&self, a: &[u8]) -> Result<(), KernelError> {
        let (pid, groups) = nladdr(a)?;
        NlSock::bind(&self.arc(), pid, groups)
    }

    /// connect(2): AF_UNSPEC disconnects
    fn connect(&self, a: &[u8], _nonblock: bool) -> Result<(), KernelError> {
        if crate::net::af_inet::sa_family(a)? == AF_UNSPEC {
            self.disconnect();
            return Ok(());
        }
        let (pid, groups) = nladdr(a)?;
        may_send_to(pid, groups)?;
        NlSock::connect(&self.arc(), pid, groups)
    }

    fn getname(&self, peer: bool) -> Result<Vec<u8>, KernelError> {
        Ok(if peer {
            let (pid, group) = self.dst();
            nladdr_bytes(pid, group_mask(group))
        } else {
            nladdr_bytes(self.portid(), self.groups32())
        })
    }

    fn poll(&self) -> u16 {
        let mut mask = POLLOUT | POLLWRNORM;
        if self.readable() {
            mask |= POLLIN | POLLRDNORM;
        }
        if self.has_error() {
            mask |= POLLERR;
        }
        mask
    }

    fn setsockopt(&self, level: i32, opt: i32, v: OptIn) -> Option<Result<(), KernelError>> {
        match level {
            SOL_SOCKET => None,
            SOL_NETLINK => Some(self.arc().set_nl_opt(opt, v)),
            _ => Some(Err(KernelError::NoProtocolOption)),
        }
    }

    fn getsockopt(&self, level: i32, opt: i32) -> Option<Result<OptOut, KernelError>> {
        match level {
            SOL_SOCKET => None,
            SOL_NETLINK => Some(self.get_nl_opt(opt)),
            _ => Some(Err(KernelError::NoProtocolOption)),
        }
    }

    /// Linux netlink_sendmsg: EMSGSIZE above sndbuf - 32 before copying
    fn sendmsg(&self, m: &mut SendMsg, flags: i32) -> Result<usize, KernelError> {
        let dst = self.dest(m)?;
        let len = m.data.len();
        if len > self.max_msg() {
            return Err(KernelError::MessageTooLong);
        }
        let data = m.data.take(len)?;
        self.arc().send(&data, dst, flags & MSG_DONTWAIT != 0)
    }

    /// Datagram semantics: MSG_TRUNC in msg_flags when cut (the flag
    /// returns the real length), NETLINK_PKTINFO control message
    fn recvmsg(&self, m: &mut RecvMsg, flags: i32) -> Result<usize, KernelError> {
        let skb = self.recv(flags & MSG_PEEK != 0, flags & MSG_DONTWAIT != 0)?;
        let n = m.data.put(0, &skb.data)?;
        if n < skb.data.len() {
            m.flags |= MSG_TRUNC;
        }
        if m.want_name {
            m.name = Some(nladdr_bytes(skb.portid, group_mask(skb.group)));
        }
        if self.has_flag(sflags::PKTINFO) {
            m.cmsg
                .put(SOL_NETLINK, NETLINK_PKTINFO, &skb.group.to_ne_bytes());
        }
        Ok(if flags & MSG_TRUNC != 0 {
            skb.data.len()
        } else {
            n
        })
    }
}

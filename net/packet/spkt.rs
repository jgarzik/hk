//! SOCK_PACKET: the obsolete packet socket (Linux af_packet.c
//! packet_ops_spkt: packet_bind_spkt, packet_getname_spkt,
//! packet_rcv_spkt, packet_sendmsg_spkt)
//!
//! Frames from the link header, addressed by device name (struct
//! sockaddr_pkt); no socket options of its own, no rings.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::net::dev::Tap;
use crate::net::ethernet::ETH_HLEN;
use crate::net::filter::Ctx;
use crate::net::msg::SendMsg;
use crate::net::skb::{NET_SKB_PAD, SkBuff};
use crate::net::socket::AF_PACKET;
use crate::util::error::KernelError;

use super::rcv::{PktCb, frame_skb};
use super::{PacketSock, VLAN_HLEN};

/// SOCK_PACKET
pub const SOCK_PACKET: i32 = 10;
/// sizeof(struct sockaddr), sizeof(struct sockaddr_pkt)
const SA_LEN: usize = 16;
pub const SPKT_LEN: usize = 18;
/// spkt_device / sa_data length
const DEV_LEN: usize = 14;

/// A device name, at most `DEV_LEN - 1` bytes kept, as text up to its
/// first NUL
fn name_of(b: &[u8]) -> &str {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    core::str::from_utf8(&b[..end]).unwrap_or("")
}

/// A device name zero-padded into `DEV_LEN` bytes (Linux strscpy: at
/// most 13 bytes and the NUL)
pub fn dev_name(name: &str) -> [u8; DEV_LEN] {
    let mut b = [0u8; DEV_LEN];
    let n = name.len().min(DEV_LEN - 1);
    b[..n].copy_from_slice(&name.as_bytes()[..n]);
    b
}

impl PacketSock {
    pub(super) fn spkt(&self) -> bool {
        self.sk.stype == SOCK_PACKET
    }

    /// Linux packet_bind_spkt: a struct sockaddr naming the device in
    /// sa_data (EINVAL for another length, ENODEV for an unknown name;
    /// the family not checked)
    pub(super) fn bind_spkt(&self, a: &[u8]) -> Result<(), KernelError> {
        if a.len() != SA_LEN {
            return Err(KernelError::InvalidArgument);
        }
        let name = name_of(&a[2..2 + DEV_LEN]);
        let net = self.sk.net.clone();
        self.do_bind_dev(
            || net.get_device(name).map(Some).ok_or(KernelError::NoDevice),
            0,
        )
    }

    /// Linux packet_getname_spkt: AF_PACKET and the bound device's name
    pub(super) fn getname_spkt(&self, peer: bool) -> Result<Vec<u8>, KernelError> {
        if peer {
            return Err(KernelError::OperationNotSupported);
        }
        let mut b = alloc::vec![0u8; SA_LEN];
        b[0..2].copy_from_slice(&AF_PACKET.to_ne_bytes());
        if let Some(d) = self.dev(self.bound().1) {
            b[2..2 + DEV_LEN].copy_from_slice(&dev_name(d.name()));
        }
        Ok(b)
    }

    /// Linux packet_rcv_spkt: every frame from its link header, queued
    /// as sock_queue_rcv_skb (the socket filter, SO_RCVBUF)
    pub(super) fn rcv_spkt(&self, t: &Tap<'_>, proto: u16) {
        let mut snap = t.frame.len();
        let filter = self.filter.read().clone();
        if let Some(f) = filter {
            let res = f.run(&Ctx {
                data: t.frame,
                frame: t.frame,
                net_off: ETH_HLEN,
                protocol: proto,
                pkt_type: t.pkt_type.num(),
                ifindex: t.dev.ifindex(),
                hatype: t.dev.link().dev_type,
                mark: 0,
            });
            if res == 0 {
                return;
            }
            snap = snap.min(res as usize);
        }
        if !self.rxq.has_room(&self.sk) {
            self.sk.drops.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let cb = PktCb::spkt(
            t.dev.link().dev_type,
            proto,
            dev_name(t.dev.name()),
            t.frame.len(),
        );
        let Some(skb) = frame_skb(&t.frame[..snap], cb, self.sk.drops.load(Ordering::Relaxed))
        else {
            self.sk.drops.fetch_add(1, Ordering::Relaxed);
            return;
        };
        self.rxq.enqueue(&self.sk, skb);
    }

    /// Linux packet_sendmsg_spkt: a whole frame to the device named in
    /// the struct sockaddr_pkt (ENOTCONN without one); its spkt_protocol
    /// is Linux's skb->protocol, which hk's transmit does not keep
    pub(super) fn sendmsg_spkt(&self, m: &mut SendMsg<'_>) -> Result<usize, KernelError> {
        let a = m.addr.as_ref().ok_or(KernelError::NotConnected)?;
        if a.len() < SA_LEN {
            return Err(KernelError::InvalidArgument);
        }
        // spkt_device's last byte forced to NUL
        let name = name_of(&a[2..2 + DEV_LEN - 1]);
        let dev = self.sk.net.get_device(name).ok_or(KernelError::NoDevice)?;
        if !dev.is_up() {
            return Err(KernelError::NetworkDown);
        }
        let len = m.data.len();
        let mtu = dev.mtu() as usize;
        if len > mtu + ETH_HLEN + VLAN_HLEN {
            return Err(KernelError::MessageTooLong);
        }
        let data = m.data.take(len)?;
        // dev_validate_header: a whole Ethernet header
        if len < ETH_HLEN {
            return Err(KernelError::InvalidArgument);
        }
        if len > mtu + ETH_HLEN && !super::extra_vlan_allowed(&data) {
            return Err(KernelError::MessageTooLong);
        }
        let mut skb = SkBuff::alloc(NET_SKB_PAD, len, crate::mm::page_alloc::Gfp::KERNEL)
            .ok_or(KernelError::NoBufferSpace)?;
        skb.put_slice(&data).ok_or(KernelError::NoBufferSpace)?;
        skb.dev = Some(Arc::clone(&dev));
        skb.owner = self.id();
        crate::net::dev::dev_queue_xmit(skb)?;
        Ok(len)
    }
}

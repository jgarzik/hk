//! AF_PACKET transmit ring (Linux af_packet.c tpacket_snd,
//! tpacket_parse_header, tpacket_fill_skb)
//!
//! User space fills frames and marks them TP_STATUS_SEND_REQUEST; a
//! send(2) walks the ring from its head, sends each such frame and
//! hands it back TP_STATUS_AVAILABLE. A malformed frame stops the walk
//! as TP_STATUS_WRONG_FORMAT with the error, or with PACKET_LOSS is
//! skipped (made available).
//!
//! Locking: `pg_vec_lock` is held across the walk (Linux); the ring's
//! head is under `PacketSock.tx` (spin leaf), the frames are read
//! through the ring's `Arc`.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::net::ethernet::ETH_HLEN;
use crate::net::msg::{MSG_DONTWAIT, SendMsg};
use crate::net::skb::SkBuff;
use crate::net::socket::{SOCK_DGRAM, SOCK_RAW};
use crate::util::error::KernelError;

use super::ring::{Frame, PgRing, TPACKET_V2, TPACKET_V3};
use super::vnet::{VNET_HDR_LEN, VnetHdr};
use super::{Dest, PacketSock, SLL_LEN, VLAN_HLEN, pf};

/// Frame header status words (transmit)
pub const TP_STATUS_AVAILABLE: u32 = 0;
pub const TP_STATUS_SEND_REQUEST: u32 = 1 << 0;
pub const TP_STATUS_SENDING: u32 = 1 << 1;
pub const TP_STATUS_WRONG_FORMAT: u32 = 1 << 2;

/// The transmit ring's state (Linux po->tx_ring)
#[derive(Default)]
pub struct TxRing {
    pub ring: Option<Arc<PgRing>>,
    /// Next frame to send
    pub head: u32,
}

impl PacketSock {
    /// (tp_len, its offset in the frame) of a frame to send, or the
    /// frame's error (Linux tpacket_parse_header: EMSGSIZE over
    /// `size_max`, EINVAL for a V3 frame with tp_next_offset or, with
    /// PACKET_TX_HAS_OFF, an offset out of the frame)
    fn parse_header(
        &self,
        f: &Frame<'_>,
        frame_size: usize,
        size_max: usize,
    ) -> Result<(usize, usize), KernelError> {
        let version = self.version();
        let tp_len = match version {
            TPACKET_V3 => {
                if f.get32(0) != 0 {
                    return Err(KernelError::InvalidArgument);
                }
                f.get32(16)
            }
            TPACKET_V2 => f.get32(4),
            _ => f.get32(8),
        } as usize;
        if tp_len > size_max {
            return Err(KernelError::MessageTooLong);
        }
        let hdrlen = self.tp_hdrlen.load(Ordering::Acquire) as usize;
        let off_min = hdrlen - SLL_LEN;
        if !self.flag(pf::TX_HAS_OFF) {
            return Ok((tp_len, off_min));
        }
        // tp_net for SOCK_DGRAM, tp_mac for SOCK_RAW
        let dgram = self.sk.stype == SOCK_DGRAM;
        let o = match version {
            TPACKET_V3 => 24,
            TPACKET_V2 => 12,
            _ => 16,
        } + if dgram { 2 } else { 0 };
        let off = usize::from(f.get16(o));
        if off < off_min || frame_size - tp_len < off {
            return Err(KernelError::InvalidArgument);
        }
        Ok((tp_len, off))
    }

    /// The frame at the head if it is `status` (Linux
    /// packet_current_frame)
    fn tx_current(&self, ring: &PgRing, status: u32) -> Option<u32> {
        let head = self.tx.lock().head;
        (ring.frame(head).status(self.version()) == u64::from(status)).then_some(head)
    }

    fn tx_increment_head(&self, ring: &PgRing) {
        let mut tx = self.tx.lock();
        tx.head = if tx.head != ring.frame_max {
            tx.head + 1
        } else {
            0
        };
    }

    /// The skb of one frame's `tp_len` bytes at `off`, copied from the
    /// ring (Linux tpacket_fill_skb, which maps the ring pages instead):
    /// EINVAL short of an Ethernet header (dev_validate_header),
    /// EMSGSIZE over the MTU unless VLAN-tagged
    /// With PACKET_VNET_HDR the frame starts with a struct
    /// virtio_net_hdr (Linux tpacket_snd). The skb and its tp_len.
    fn tx_skb(
        &self,
        d: &Dest,
        f: &Frame<'_>,
        off: usize,
        tp_len: usize,
    ) -> Result<(Box<SkBuff>, usize), KernelError> {
        let raw = self.sk.stype == SOCK_RAW;
        let vnet = self.vnet_hdr_len();
        let (mut off, mut tp_len, mut hdr) = (off, tp_len, None);
        if vnet != 0 {
            tp_len = tp_len
                .checked_sub(vnet)
                .ok_or(KernelError::InvalidArgument)?;
            let mut b = [0u8; VNET_HDR_LEN];
            f.r.copy_out(f.off + off, &mut b);
            let mut h = VnetHdr::parse(&b);
            super::vnet::snd_parse(&mut h, tp_len)?;
            hdr = Some(h);
            off += vnet;
        }
        if raw && tp_len < ETH_HLEN {
            return Err(KernelError::InvalidArgument);
        }
        let mut data = crate::util::kmem::try_vec(tp_len, 0u8)?;
        f.r.copy_out(f.off + off, &mut data);
        if let Some(h) = &hdr {
            super::vnet::to_frame(h, &mut data)?;
        }
        let mut skb = self.build(&d.dev, d.proto, d.addr, &data)?;
        let reserve = if raw { ETH_HLEN } else { 0 };
        if tp_len > d.dev.mtu() as usize + reserve
            && vnet == 0
            && !super::extra_vlan_allowed(skb.data())
        {
            return Err(KernelError::MessageTooLong);
        }
        skb.dev = Some(d.dev.clone());
        skb.owner = self.id();
        Ok((skb, tp_len))
    }
}

/// Linux tpacket_snd: send the frames marked TP_STATUS_SEND_REQUEST
/// from the head on; the bytes sent, or the first error
pub fn tpacket_snd(s: &PacketSock, m: &SendMsg<'_>, flags: i32) -> Result<usize, KernelError> {
    let _pg = s.pg_vec_lock.lock();
    // The lockless check in sendmsg, confirmed under pg_vec_lock
    let ring = s.tx.lock().ring.clone().ok_or(KernelError::Busy)?;
    let d = s.dest(m)?;
    if !d.dev.is_up() {
        return Err(KernelError::NetworkDown);
    }
    let version = s.version();
    let hdrlen = s.tp_hdrlen.load(Ordering::Acquire) as usize;
    let frame_size = ring.frame_size as usize;
    let reserve = if s.sk.stype == SOCK_RAW { ETH_HLEN } else { 0 };
    let mut size_max = frame_size - (hdrlen - SLL_LEN);
    if s.vnet_hdr_len() == 0 {
        size_max = size_max.min(d.dev.mtu() as usize + reserve + VLAN_HLEN);
    }
    let need_wait = flags & MSG_DONTWAIT == 0;
    let mut len_sum: usize = 0;
    // Linux skb != NULL: this pass built an skb
    let mut skb_made = false;
    s.tx_done.store(0, Ordering::Release);
    loop {
        let Some(head) = s.tx_current(&ring, TP_STATUS_SEND_REQUEST) else {
            if need_wait && skb_made {
                // Linux wait_for_completion_interruptible_timeout on
                // po->skb_completion
                let timeo = s.sk.snd_timeo(false);
                let consume = || {
                    s.tx_done
                        .try_update(Ordering::AcqRel, Ordering::Acquire, |d| d.checked_sub(1))
                        .is_ok()
                };
                match crate::net::sock::wait_on(&s.tx_wq, timeo, consume) {
                    Ok(_) => {}
                    Err(KernelError::WouldBlock) => return Err(KernelError::TimedOut),
                    Err(_) => return Err(KernelError::RestartSys),
                }
            }
            // Check for more frames while some are still in flight
            if need_wait && s.tx_pending.load(Ordering::Acquire) != 0 {
                continue;
            }
            break;
        };
        let f = ring.frame(head);
        skb_made = false;
        let r = s
            .parse_header(&f, frame_size, size_max)
            .and_then(|(tp_len, off)| {
                if tp_len > i32::MAX as usize - len_sum {
                    return Ok(None);
                }
                skb_made = true;
                s.tx_skb(&d, &f, off, tp_len).map(Some)
            });
        match r {
            Ok(Some((mut skb, tp_len))) => {
                let done = crate::util::kalloc::try_box(TxDone {
                    sk: s.me.get().and_then(alloc::sync::Weak::upgrade),
                    ring: ring.clone(),
                    frame: head,
                });
                // Linux tpacket_snd's failed uarg allocation: what was
                // sent so far, else ENOMEM; the frame stays requested
                let Ok(done) = done else {
                    return if len_sum > 0 {
                        Ok(len_sum)
                    } else {
                        Err(KernelError::OutOfMemory)
                    };
                };
                skb.destructor = Some(done);
                f.set_status(version, TP_STATUS_SENDING);
                s.tx_pending.fetch_add(1, Ordering::AcqRel);
                if let Err(e) = crate::net::dev::dev_queue_xmit(skb) {
                    // The skb went already: its frame is available;
                    // Linux puts it back as requested and reports
                    if f.status(version) == u64::from(TP_STATUS_AVAILABLE) {
                        f.set_status(version, TP_STATUS_SEND_REQUEST);
                        return Err(e);
                    }
                }
                s.tx_increment_head(&ring);
                len_sum += tp_len;
            }
            // The byte count would wrap into an errno
            Ok(None) => break,
            Err(_) if s.flag(pf::TP_LOSS) => {
                f.set_status(version, TP_STATUS_AVAILABLE);
                s.tx_increment_head(&ring);
            }
            Err(e) => {
                f.set_status(version, TP_STATUS_WRONG_FORMAT);
                return Err(e);
            }
        }
    }
    Ok(len_sum)
}

/// A sent frame's completion, run when its skb is freed or orphaned
/// (Linux tpacket_destruct_skb, 6.8): the frame available again, the
/// pending count down, a blocked sender woken once none is pending.
/// Nothing is written once the ring was replaced.
struct TxDone {
    sk: Option<Arc<PacketSock>>,
    ring: Arc<PgRing>,
    frame: u32,
}

impl crate::net::skb::SkbDestructor for TxDone {}

impl Drop for TxDone {
    fn drop(&mut self) {
        let Some(s) = &self.sk else { return };
        if !s
            .tx
            .lock()
            .ring
            .as_ref()
            .is_some_and(|r| Arc::ptr_eq(r, &self.ring))
        {
            return;
        }
        let left = s.tx_pending.fetch_sub(1, Ordering::AcqRel) - 1;
        self.ring
            .frame(self.frame)
            .set_status(s.version(), TP_STATUS_AVAILABLE);
        if left == 0 {
            s.tx_done.fetch_add(1, Ordering::AcqRel);
            s.tx_wq.wake_all();
        }
    }
}

/// Linux packet_poll: writable when the head frame is available
pub fn tx_writable(s: &PacketSock) -> bool {
    let tx = s.tx.lock();
    let Some(ring) = &tx.ring else {
        return false;
    };
    ring.frame(tx.head).status(s.version()) == u64::from(TP_STATUS_AVAILABLE)
}

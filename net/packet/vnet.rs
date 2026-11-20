//! PACKET_VNET_HDR: a struct virtio_net_hdr before each frame (Linux
//! af_packet.c packet_rcv_vnet, packet_snd_vnet_parse,
//! include/linux/virtio_net.h virtio_net_hdr_to_skb / _from_skb)
//!
//! Received frames get a header describing their checksum state;
//! sent frames bring one, validated as Linux. hk has no GSO and no
//! checksum offload: a NEEDS_CSUM checksum is completed in software
//! before transmit (Linux skb_checksum_help, what a device without
//! checksum offload gets), and a GSO frame longer than one segment is
//! refused (logged in BUGS.md).

use crate::net::ethernet::ETH_HLEN;
use crate::util::error::KernelError;

use super::ring::{TP_STATUS_CSUM_VALID, TP_STATUS_CSUMNOTREADY};

/// sizeof(struct virtio_net_hdr), sizeof(struct
/// virtio_net_hdr_mrg_rxbuf)
pub const VNET_HDR_LEN: usize = 10;
pub const VNET_HDR_MRG_LEN: usize = 12;

const F_NEEDS_CSUM: u8 = 1;
const F_DATA_VALID: u8 = 2;
const GSO_NONE: u8 = 0;
const GSO_TCPV4: u8 = 1;
const GSO_UDP: u8 = 3;
const GSO_TCPV6: u8 = 4;
const GSO_UDP_L4: u8 = 5;
const GSO_ECN: u8 = 0x80;
/// Linux GSO_BY_FRAGS, UDP_MAX_SEGMENTS
const GSO_BY_FRAGS: u16 = 0xffff;
const UDP_MAX_SEGMENTS: usize = 128;

/// struct virtio_net_hdr (little-endian fields: virtio 1.0, and
/// Linux's legacy endianness on x86-64 and arm64)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VnetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
}

impl VnetHdr {
    pub fn parse(b: &[u8]) -> Self {
        let w = |o: usize| u16::from_le_bytes([b[o], b[o + 1]]);
        Self {
            flags: b[0],
            gso_type: b[1],
            hdr_len: w(2),
            gso_size: w(4),
            csum_start: w(6),
            csum_offset: w(8),
        }
    }

    /// The header and, for the 12-byte form, num_buffers 0
    pub fn bytes(&self) -> [u8; VNET_HDR_MRG_LEN] {
        let mut b = [0u8; VNET_HDR_MRG_LEN];
        b[0] = self.flags;
        b[1] = self.gso_type;
        b[2..4].copy_from_slice(&self.hdr_len.to_le_bytes());
        b[4..6].copy_from_slice(&self.gso_size.to_le_bytes());
        b[6..8].copy_from_slice(&self.csum_start.to_le_bytes());
        b[8..10].copy_from_slice(&self.csum_offset.to_le_bytes());
        b
    }
}

/// Where a TCP/UDP checksum of an IPv4 frame lives: (start, offset)
/// from the link header (Linux skb_checksum_start_offset, csum_offset
/// of a CHECKSUM_PARTIAL skb)
pub fn csum_loc(frame: &[u8]) -> Option<(u16, u16)> {
    let ip = frame.get(ETH_HLEN..)?;
    if frame.get(12..14)? != [0x08, 0x00] || ip.len() < 20 {
        return None;
    }
    let start = (ETH_HLEN + usize::from(ip[0] & 0xf) * 4) as u16;
    match ip[9] {
        6 => Some((start, 16)),
        17 => Some((start, 6)),
        _ => None,
    }
}

/// Linux virtio_net_hdr_from_skb (no GSO, has_data_valid): from a
/// frame's tp_status checksum bits
pub fn from_frame(csum: u32, frame: &[u8]) -> VnetHdr {
    let mut h = VnetHdr::default();
    if csum & TP_STATUS_CSUMNOTREADY != 0 {
        if let Some((start, off)) = csum_loc(frame) {
            h.flags = F_NEEDS_CSUM;
            h.csum_start = start;
            h.csum_offset = off;
        }
    } else if csum & TP_STATUS_CSUM_VALID != 0 {
        h.flags = F_DATA_VALID;
    }
    h
}

/// Linux __packet_snd_vnet_parse: hdr_len covers the checksum field;
/// EINVAL past the frame of `len` bytes
pub fn snd_parse(h: &mut VnetHdr, len: usize) -> Result<(), KernelError> {
    let csum_end = u32::from(h.csum_start) + u32::from(h.csum_offset) + 2;
    if h.flags & F_NEEDS_CSUM != 0 && csum_end > u32::from(h.hdr_len) {
        // Linux __cpu_to_virtio16: truncated to 16 bits
        h.hdr_len = csum_end as u16;
    }
    if usize::from(h.hdr_len) > len {
        return Err(KernelError::InvalidArgument);
    }
    Ok(())
}

/// The IPv4 transport header offset and protocol of a frame
fn ipv4_thoff(frame: &[u8]) -> Option<(usize, u8)> {
    let ip = frame.get(ETH_HLEN..)?;
    if frame.get(12..14)? != [0x08, 0x00] || ip.len() < 20 || ip[0] >> 4 != 4 {
        return None;
    }
    Some((ETH_HLEN + usize::from(ip[0] & 0xf) * 4, ip[9]))
}

/// Linux virtio_net_hdr_to_skb on a frame from its link header,
/// EINVAL for what Linux refuses; a NEEDS_CSUM checksum is completed
/// (skb_checksum_help: the sum from csum_start, the field included,
/// folded, 0 sent as 0xffff). A GSO header on a frame longer than one
/// segment is EINVAL: hk cannot segment.
pub fn to_frame(h: &VnetHdr, frame: &mut [u8]) -> Result<(), KernelError> {
    let inval = Err(KernelError::InvalidArgument);
    let len = frame.len();
    let mut nh_min_len = 20usize;
    let (mut thlen, mut ip_proto) = (0usize, 0u8);
    if h.gso_type != GSO_NONE {
        (thlen, ip_proto) = match h.gso_type & !GSO_ECN {
            GSO_TCPV4 => (20, 6),
            GSO_TCPV6 => {
                nh_min_len = 40;
                (20, 6)
            }
            GSO_UDP | GSO_UDP_L4 => (8, 17),
            _ => return inval,
        };
        if h.gso_size == 0 {
            return inval;
        }
    }
    let mut p_off = 0;
    let mut partial = None;
    if h.flags & F_NEEDS_CSUM != 0 {
        let start = usize::from(h.csum_start);
        let off = usize::from(h.csum_offset);
        let needed = start + thlen.max(off + 2);
        // pskb_may_pull, skb_partial_csum_set
        if needed > len || start > len || start + off > len - 2 {
            return inval;
        }
        p_off = nh_min_len.max(start) + thlen;
        if p_off > len {
            return inval;
        }
        partial = Some((start, off));
    } else if h.gso_type != GSO_NONE {
        // Linux probes the flow (skb_flow_dissect_flow_keys_basic)
        let Some((thoff, proto)) = ipv4_thoff(frame) else {
            return inval;
        };
        p_off = thoff + thlen;
        if p_off > len || proto != ip_proto {
            return inval;
        }
    }
    if h.gso_type != GSO_NONE {
        let gso_size = usize::from(h.gso_size);
        let mut nh_off = p_off;
        match h.gso_type & !GSO_ECN {
            GSO_UDP => nh_off -= thlen,
            GSO_UDP_L4
                if h.flags & F_NEEDS_CSUM == 0
                    || h.csum_offset != 6
                    || len - p_off > gso_size * UDP_MAX_SEGMENTS
                    || h.gso_type & GSO_ECN != 0 =>
            {
                return inval;
            }
            _ => {}
        }
        if h.gso_size == GSO_BY_FRAGS {
            return inval;
        }
        // Linux marks a longer one GSO and segments it
        if len - nh_off > gso_size {
            return inval;
        }
    }
    if let Some((start, off)) = partial {
        let c = crate::net::ipv4::ip_checksum(&frame[start..]);
        let c = if c == 0 { 0xffff } else { c };
        frame[start + off..start + off + 2].copy_from_slice(&c.to_be_bytes());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(flags: u8, gso: u8, hdr_len: u16, gso_size: u16, start: u16, off: u16) -> VnetHdr {
        VnetHdr {
            flags,
            gso_type: gso,
            hdr_len,
            gso_size,
            csum_start: start,
            csum_offset: off,
        }
    }

    #[test]
    fn parse_bytes() {
        let h = hdr(1, 0, 34, 0, 34, 6);
        assert_eq!(VnetHdr::parse(&h.bytes()), h);
    }

    #[test]
    fn snd_parse_rules() {
        let mut h = hdr(F_NEEDS_CSUM, 0, 0, 0, 34, 6);
        assert_eq!(snd_parse(&mut h, 60), Ok(()));
        assert_eq!(h.hdr_len, 42);
        let mut h = hdr(F_NEEDS_CSUM, 0, 0, 0, 34, 6);
        assert_eq!(snd_parse(&mut h, 41), Err(KernelError::InvalidArgument));
        let mut h = hdr(0, 0, 61, 0, 0, 0);
        assert_eq!(snd_parse(&mut h, 60), Err(KernelError::InvalidArgument));
    }

    /// An Ethernet + IPv4 + UDP frame with `n` payload bytes
    fn udp_frame(n: usize) -> alloc::vec::Vec<u8> {
        let mut f = alloc::vec![0u8; 42 + n];
        f[12] = 8;
        f[14] = 0x45;
        f[23] = 17;
        f
    }

    #[test]
    fn to_frame_rules() {
        let e = Err(KernelError::InvalidArgument);
        let mut f = udp_frame(10);
        assert_eq!(to_frame(&hdr(0, 9, 0, 100, 0, 0), &mut f), e);
        assert_eq!(to_frame(&hdr(0, GSO_UDP_L4, 0, 0, 0, 0), &mut f), e);
        // checksum field past the frame
        assert_eq!(to_frame(&hdr(F_NEEDS_CSUM, 0, 0, 0, 34, 50), &mut f), e);
        // a UDP checksum completed in software
        assert_eq!(to_frame(&hdr(F_NEEDS_CSUM, 0, 0, 0, 34, 6), &mut f), Ok(()));
        assert_eq!(f[40..42], [0xff, 0xff]);
        // GSO within one segment passes; beyond, no segmentation
        let mut f = udp_frame(100);
        let g = hdr(F_NEEDS_CSUM, GSO_UDP_L4, 0, 1000, 34, 6);
        assert_eq!(to_frame(&g, &mut f), Ok(()));
        let g = hdr(F_NEEDS_CSUM, GSO_UDP_L4, 0, 50, 34, 6);
        assert_eq!(to_frame(&g, &mut f), e);
        // TCPV4 without NEEDS_CSUM: the protocol must match
        assert_eq!(to_frame(&hdr(0, GSO_TCPV4, 0, 1000, 0, 0), &mut f), e);
    }
}

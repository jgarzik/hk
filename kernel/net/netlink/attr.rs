//! netlink message and attribute encoding (Linux include/net/netlink.h,
//! lib/nlattr.c)
//!
//! `Msg` builds one message (header, fixed family header, attributes,
//! nests); `parse` splits a request's attributes into a table indexed by
//! type, rejecting malformed ones like Linux's deprecated (liberal)
//! validation.

use alloc::vec::Vec;

use crate::error::KernelError;

/// struct nlmsghdr size
pub const NLMSG_HDRLEN: usize = 16;
/// struct nlattr size
pub const NLA_HDRLEN: usize = 4;
/// Nested attribute flag in nla_type
pub const NLA_F_NESTED: u16 = 1 << 15;
const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | (1 << 14));

/// NLMSG_ALIGN / NLA_ALIGN (4 bytes)
pub const fn align(n: usize) -> usize {
    (n + 3) & !3
}

/// A parsed struct nlmsghdr
#[derive(Clone, Copy, Debug, Default)]
pub struct Hdr {
    pub len: u32,
    pub ty: u16,
    pub flags: u16,
    pub seq: u32,
    pub pid: u32,
}

impl Hdr {
    /// Decode the header at the start of `b`
    pub fn parse(b: &[u8]) -> Option<Self> {
        if b.len() < NLMSG_HDRLEN {
            return None;
        }
        let u32_at = |o: usize| u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let u16_at = |o: usize| u16::from_ne_bytes([b[o], b[o + 1]]);
        Some(Self {
            len: u32_at(0),
            ty: u16_at(4),
            flags: u16_at(6),
            seq: u32_at(8),
            pid: u32_at(12),
        })
    }
}

/// One message under construction
pub struct Msg {
    buf: Vec<u8>,
}

impl Msg {
    /// Start a message: header with the given type/flags/seq/portid
    pub fn new(ty: u16, flags: u16, seq: u32, pid: u32) -> Self {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.extend_from_slice(&ty.to_ne_bytes());
        buf.extend_from_slice(&flags.to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&pid.to_ne_bytes());
        Self { buf }
    }

    /// Append raw bytes (fixed headers), padded to 4
    pub fn put(&mut self, data: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(data);
        self.pad();
        self
    }

    fn pad(&mut self) {
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
    }

    /// Attribute with a raw payload
    pub fn attr(&mut self, ty: u16, data: &[u8]) -> &mut Self {
        let len = (NLA_HDRLEN + data.len()) as u16;
        self.buf.extend_from_slice(&len.to_ne_bytes());
        self.buf.extend_from_slice(&ty.to_ne_bytes());
        self.put(data)
    }

    pub fn u8(&mut self, ty: u16, v: u8) -> &mut Self {
        self.attr(ty, &[v])
    }

    pub fn u32(&mut self, ty: u16, v: u32) -> &mut Self {
        self.attr(ty, &v.to_ne_bytes())
    }

    /// NUL-terminated string attribute
    pub fn str(&mut self, ty: u16, s: &str) -> &mut Self {
        let mut v = Vec::with_capacity(s.len() + 1);
        v.extend_from_slice(s.as_bytes());
        v.push(0);
        self.attr(ty, &v)
    }

    /// Open a nested attribute; returns its offset for `nest_end`
    pub fn nest_start(&mut self, ty: u16) -> usize {
        let off = self.buf.len();
        self.attr(ty | NLA_F_NESTED, &[]);
        off
    }

    /// Close a nest opened at `off`
    pub fn nest_end(&mut self, off: usize) {
        let len = (self.buf.len() - off) as u16;
        self.buf[off..off + 2].copy_from_slice(&len.to_ne_bytes());
    }

    /// Finish: set nlmsg_len and return the bytes (length 4-aligned)
    pub fn finish(mut self) -> Vec<u8> {
        let len = self.buf.len() as u32;
        self.buf[..4].copy_from_slice(&len.to_ne_bytes());
        self.buf
    }
}

/// Attribute table: `tb[type]` = payload of the last attribute of that type
pub struct Attrs<'a> {
    tb: Vec<Option<&'a [u8]>>,
}

impl<'a> Attrs<'a> {
    /// Parse attributes in `b` (types above `max` are ignored). A
    /// malformed attribute header is EINVAL; trailing bytes too short
    /// for a header are ignored (Linux liberal validation).
    pub fn parse(mut b: &'a [u8], max: u16) -> Result<Self, KernelError> {
        let mut tb = alloc::vec![None; max as usize + 1];
        while b.len() >= NLA_HDRLEN {
            let len = u16::from_ne_bytes([b[0], b[1]]) as usize;
            let ty = u16::from_ne_bytes([b[2], b[3]]) & NLA_TYPE_MASK;
            if len < NLA_HDRLEN || len > b.len() {
                return Err(KernelError::InvalidArgument);
            }
            if ty <= max {
                tb[ty as usize] = Some(&b[NLA_HDRLEN..len]);
            }
            b = &b[align(len).min(b.len())..];
        }
        Ok(Self { tb })
    }

    /// Raw payload of attribute `ty`
    pub fn get(&self, ty: u16) -> Option<&'a [u8]> {
        self.tb.get(ty as usize).copied().flatten()
    }

    pub fn has(&self, ty: u16) -> bool {
        self.get(ty).is_some()
    }

    /// u32 attribute; EINVAL if present but too short
    pub fn u32(&self, ty: u16) -> Result<Option<u32>, KernelError> {
        match self.get(ty) {
            None => Ok(None),
            Some(p) if p.len() >= 4 => Ok(Some(u32::from_ne_bytes([p[0], p[1], p[2], p[3]]))),
            Some(_) => Err(KernelError::InvalidArgument),
        }
    }

    /// u8 attribute; EINVAL if empty
    pub fn u8(&self, ty: u16) -> Result<Option<u8>, KernelError> {
        match self.get(ty) {
            None => Ok(None),
            Some(p) if !p.is_empty() => Ok(Some(p[0])),
            Some(_) => Err(KernelError::InvalidArgument),
        }
    }

    /// IPv4 address attribute (network order bytes)
    pub fn in_addr(&self, ty: u16) -> Result<Option<crate::net::Ipv4Addr>, KernelError> {
        match self.get(ty) {
            None => Ok(None),
            Some(p) if p.len() >= 4 => Ok(Some(crate::net::Ipv4Addr::from_be_bytes([
                p[0], p[1], p[2], p[3],
            ]))),
            Some(_) => Err(KernelError::InvalidArgument),
        }
    }

    /// String attribute up to the first NUL (EINVAL if not UTF-8 or
    /// `max` bytes or longer, like NLA_STRING with a length limit)
    pub fn str(&self, ty: u16, max: usize) -> Result<Option<&'a str>, KernelError> {
        let Some(p) = self.get(ty) else {
            return Ok(None);
        };
        let n = p.iter().position(|&c| c == 0).unwrap_or(p.len());
        if n >= max {
            return Err(KernelError::InvalidArgument);
        }
        core::str::from_utf8(&p[..n])
            .map(Some)
            .map_err(|_| KernelError::InvalidArgument)
    }
}

/// Read a plain-old-data family header (zero-filled if `b` is short)
pub fn header<const N: usize>(b: &[u8]) -> [u8; N] {
    let mut h = [0u8; N];
    let n = b.len().min(N);
    h[..n].copy_from_slice(&b[..n]);
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_parse() {
        let mut m = Msg::new(16, 2, 7, 9);
        m.put(&[1, 2, 3]).u32(4, 1500).str(3, "eth0");
        let n = m.nest_start(26);
        m.u8(1, 5);
        m.nest_end(n);
        let b = m.finish();
        assert_eq!(b.len() % 4, 0);
        let h = Hdr::parse(&b).unwrap();
        assert_eq!(h.len as usize, b.len());
        assert_eq!((h.ty, h.flags, h.seq, h.pid), (16, 2, 7, 9));
        let a = Attrs::parse(&b[NLMSG_HDRLEN + 4..], 30).unwrap();
        assert_eq!(a.u32(4).unwrap(), Some(1500));
        assert_eq!(a.str(3, 16).unwrap(), Some("eth0"));
        let nest = Attrs::parse(a.get(26).unwrap(), 2).unwrap();
        assert_eq!(nest.u8(1).unwrap(), Some(5));
    }

    #[test]
    fn malformed() {
        // nla_len 2 (< header)
        assert!(Attrs::parse(&[2, 0, 1, 0], 4).is_err());
        // nla_len beyond buffer
        assert!(Attrs::parse(&[12, 0, 1, 0, 0, 0], 4).is_err());
        // short u32
        let a = Attrs::parse(&[6, 0, 1, 0, 1, 2, 0, 0], 4).unwrap();
        assert!(a.u32(1).is_err());
    }
}

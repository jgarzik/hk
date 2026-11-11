//! netlink message and attribute encoding (Linux include/net/netlink.h,
//! lib/nlattr.c)
//!
//! `Msg` builds one message (header, fixed family header, attributes,
//! nests); `NlBuf` appends messages to a buffer allocated beforehand,
//! EMSGSIZE when full (nlmsg_put/nla_put into an skb); `parse` splits a request's attributes into a table indexed by
//! type, rejecting malformed ones like Linux's deprecated (liberal)
//! validation.

use alloc::vec::Vec;

use crate::util::error::KernelError;

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

    /// Attribute with a raw payload (skipped if it cannot be encoded,
    /// like nla_put's EMSGSIZE)
    pub fn attr(&mut self, ty: u16, data: &[u8]) -> &mut Self {
        if self.hdr(ty, data.len()) {
            self.put(data);
        }
        self
    }

    /// Attribute header for a `len`-byte payload; false (nothing
    /// written) if nla_len cannot hold it
    fn hdr(&mut self, ty: u16, len: usize) -> bool {
        let Ok(len) = u16::try_from(NLA_HDRLEN + len) else {
            return false;
        };
        self.buf.extend_from_slice(&len.to_ne_bytes());
        self.buf.extend_from_slice(&ty.to_ne_bytes());
        true
    }

    pub fn u8(&mut self, ty: u16, v: u8) -> &mut Self {
        self.attr(ty, &[v])
    }

    pub fn u32(&mut self, ty: u16, v: u32) -> &mut Self {
        self.attr(ty, &v.to_ne_bytes())
    }

    /// NUL-terminated string attribute
    pub fn str(&mut self, ty: u16, s: &str) -> &mut Self {
        if self.hdr(ty, s.len() + 1) {
            self.buf.extend_from_slice(s.as_bytes());
            self.put(&[0]);
        }
        self
    }

    /// Open a nested attribute; returns its offset for `nest_end`
    pub fn nest_start(&mut self, ty: u16) -> usize {
        let off = self.buf.len();
        self.attr(ty | NLA_F_NESTED, &[]);
        off
    }

    /// Close a nest opened at `off`. A nest past nla_len's 16 bits is
    /// cancelled (trimmed off) and EMSGSIZE (Linux nla_nest_end_safe,
    /// then nla_nest_cancel), never written with a truncated length.
    pub fn nest_end(&mut self, off: usize) -> Result<(), KernelError> {
        let Ok(len) = u16::try_from(self.buf.len() - off) else {
            self.buf.truncate(off);
            return Err(KernelError::MessageTooLong);
        };
        self.buf[off..off + 2].copy_from_slice(&len.to_ne_bytes());
        Ok(())
    }

    /// Finish: set nlmsg_len and return the bytes (length 4-aligned)
    pub fn finish(mut self) -> Vec<u8> {
        let len = self.buf.len() as u32;
        self.buf[..4].copy_from_slice(&len.to_ne_bytes());
        self.buf
    }
}

/// `nlmsg_total_size`: a message with a `payload`-byte body, aligned
pub const fn msg_size(payload: usize) -> usize {
    align(NLMSG_HDRLEN + payload)
}

/// `nla_total_size`: an attribute with a `payload`-byte body, aligned
pub const fn attr_size(payload: usize) -> usize {
    align(NLA_HDRLEN + payload)
}

/// An empty buffer with room for `size` bytes of messages, allocated
/// now (Linux nlmsg_new): fill it with an [`NlBuf`], which never grows
/// it
pub fn nlmsg_new(size: usize) -> Result<Vec<u8>, KernelError> {
    let mut v = Vec::new();
    v.try_reserve_exact(size)
        .map_err(|_| KernelError::OutOfMemory)?;
    Ok(v)
}

/// A message begun in an [`NlBuf`] (its offset), to end or cancel
#[must_use]
pub struct NlMsg(usize);

/// Netlink messages appended to a buffer allocated beforehand (Linux
/// an skb's tailroom, filled with nlmsg_put/nla_put): nothing
/// allocates, so a dump may fill it under a lock or an RCU guard. A
/// message or attribute that does not fit is EMSGSIZE, and the caller
/// cancels the message it began (nlmsg_cancel); a dump then ends its
/// part there and resumes from that object in the next.
///
/// # Invariants
/// `buf.len() <= limit <= buf.capacity()`, so an append never
/// reallocates.
pub struct NlBuf<'a> {
    buf: &'a mut Vec<u8>,
    limit: usize,
}

impl<'a> NlBuf<'a> {
    /// Append to `buf`, up to `limit` bytes in all (at most its
    /// capacity)
    pub fn new(buf: &'a mut Vec<u8>, limit: usize) -> Self {
        // INVARIANT: clamped to the capacity, which holds the length
        let limit = limit.min(buf.capacity()).max(buf.len());
        Self { buf, limit }
    }

    /// Bytes written (the part's length)
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Room for `n` more bytes, or EMSGSIZE
    fn room(&self, n: usize) -> Result<(), KernelError> {
        match self.buf.len().checked_add(n) {
            Some(end) if end <= self.limit => Ok(()),
            _ => Err(KernelError::MessageTooLong),
        }
    }

    /// `data`, zero-padded to 4 bytes (room checked by the caller)
    fn append(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
        let pad = align(data.len()) - data.len();
        self.buf.extend_from_slice(&[0; 3][..pad]);
    }

    /// Begin a message: its header and the family header `hdr`, padded
    /// (Linux nlmsg_put); EMSGSIZE if they do not fit
    pub fn msg_put(
        &mut self,
        ty: u16,
        flags: u16,
        seq: u32,
        pid: u32,
        hdr: &[u8],
    ) -> Result<NlMsg, KernelError> {
        self.room(msg_size(hdr.len()))?;
        let at = self.buf.len();
        let mut h = [0u8; NLMSG_HDRLEN];
        h[4..6].copy_from_slice(&ty.to_ne_bytes());
        h[6..8].copy_from_slice(&flags.to_ne_bytes());
        h[8..12].copy_from_slice(&seq.to_ne_bytes());
        h[12..16].copy_from_slice(&pid.to_ne_bytes());
        self.buf.extend_from_slice(&h);
        self.append(hdr);
        Ok(NlMsg(at))
    }

    /// An attribute (Linux nla_put); EMSGSIZE if it does not fit, or
    /// if nla_len cannot hold it
    pub fn put(&mut self, ty: u16, data: &[u8]) -> Result<(), KernelError> {
        let len =
            u16::try_from(NLA_HDRLEN + data.len()).map_err(|_| KernelError::MessageTooLong)?;
        self.room(attr_size(data.len()))?;
        self.buf.extend_from_slice(&len.to_ne_bytes());
        self.buf.extend_from_slice(&ty.to_ne_bytes());
        self.append(data);
        Ok(())
    }

    /// A u32 attribute (Linux nla_put_u32)
    pub fn put_u32(&mut self, ty: u16, v: u32) -> Result<(), KernelError> {
        self.put(ty, &v.to_ne_bytes())
    }

    /// Finish message `m`: its nlmsg_len (Linux nlmsg_end)
    pub fn msg_end(&mut self, m: NlMsg) {
        let len = u32::try_from(self.buf.len() - m.0).unwrap_or(u32::MAX);
        self.buf[m.0..m.0 + 4].copy_from_slice(&len.to_ne_bytes());
    }

    /// Drop message `m` and everything after it (Linux nlmsg_cancel)
    pub fn msg_cancel(&mut self, m: NlMsg) {
        self.buf.truncate(m.0);
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
        m.nest_end(n).unwrap();
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
    fn nest_overflow_cancels() {
        let mut m = Msg::new(16, 0, 0, 0);
        m.u32(4, 1);
        let before = m.buf.len();
        let n = m.nest_start(26);
        let big = alloc::vec![0u8; 60_000];
        m.attr(1, &big).attr(2, &big);
        assert_eq!(m.nest_end(n), Err(KernelError::MessageTooLong));
        assert_eq!(m.buf.len(), before);
        let b = m.finish();
        let a = Attrs::parse(&b[NLMSG_HDRLEN..], 30).unwrap();
        assert_eq!(a.u32(4).unwrap(), Some(1));
        assert!(a.get(26).is_none());
    }

    /// Messages fill the buffer up to its limit; what does not fit is
    /// EMSGSIZE, and a cancelled message leaves no trace
    #[test]
    fn nlbuf_fills_and_cancels() {
        let mut v = nlmsg_new(64).unwrap();
        let mut nb = NlBuf::new(&mut v, 64);
        let m = nb.msg_put(28, 2, 7, 9, &[1, 2, 3]).unwrap();
        nb.put_u32(4, 1500).unwrap();
        nb.put(1, b"ab").unwrap();
        nb.msg_end(m);
        let one = nb.len();
        assert_eq!(one, msg_size(3) + attr_size(4) + attr_size(2));
        let m = nb.msg_put(28, 2, 8, 9, &[0; 4]).unwrap();
        assert_eq!(nb.put(1, &[0; 40]), Err(KernelError::MessageTooLong));
        nb.msg_cancel(m);
        assert_eq!(nb.len(), one);
        assert!(nb.msg_put(28, 0, 0, 0, &[0; 64]).is_err());
        assert_eq!(v.capacity(), 64);
        let h = Hdr::parse(&v).unwrap();
        assert_eq!((h.len as usize, h.ty, h.seq), (one, 28, 7));
        let a = Attrs::parse(&v[NLMSG_HDRLEN + 4..one], 4).unwrap();
        assert_eq!(a.u32(4).unwrap(), Some(1500));
        assert_eq!(a.get(1), Some(&b"ab"[..]));
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

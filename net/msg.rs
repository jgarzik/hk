//! User I/O vectors of socket calls (Linux lib/iov_iter.c import_iovec /
//! import_ubuf as used by net/socket.c)
//!
//! An `Iov` is validated once when imported: at most `UIO_MAXIOV`
//! segments (EINVAL), every segment inside user space (EFAULT), and the
//! total clamped to `MAX_RW_COUNT` like Linux, so no length arithmetic
//! on it can overflow. Data is then copied with uaccess only.

use alloc::vec::Vec;

use crate::arch::Uaccess;
use crate::fs::iov_iter::{IovDest, IovSource};
use crate::uaccess::{UserPtr, access_ok, copy_from_user, copy_to_user, get_user};
use crate::util::error::KernelError;
use core::mem::{offset_of, size_of};

/// Most segments in one iovec array (Linux UIO_MAXIOV)
pub const UIO_MAXIOV: usize = 1024;
/// Largest single transfer (Linux MAX_RW_COUNT = INT_MAX & PAGE_MASK)
pub const MAX_RW_COUNT: usize = 0x7fff_f000;

/// One user segment
#[derive(Clone, Copy, Debug, Default)]
pub struct IoVec {
    pub base: u64,
    pub len: usize,
}

/// A validated user I/O vector
#[derive(Clone, Debug, Default)]
pub struct Iov {
    segs: Vec<IoVec>,
    /// Sum of the (clamped) segment lengths, <= MAX_RW_COUNT
    pub total: usize,
}

impl Iov {
    /// One buffer (send/recv; Linux import_ubuf clamps before access_ok)
    pub fn single(base: u64, len: u64) -> Result<Self, KernelError> {
        let mut v = Self::default();
        v.push(base, len.min(MAX_RW_COUNT as u64))?;
        Ok(v)
    }

    /// The iovec of a user msghdr (Linux __copy_msghdr: EMSGSIZE above
    /// UIO_MAXIOV segments)
    pub fn from_msg(ptr: u64, n: usize) -> Result<Self, KernelError> {
        if n > UIO_MAXIOV {
            return Err(KernelError::MessageTooLong);
        }
        Self::import(ptr, n)
    }

    /// A user `struct iovec[n]` at `ptr` (readv-style: EINVAL above
    /// UIO_MAXIOV)
    pub fn import(ptr: u64, n: usize) -> Result<Self, KernelError> {
        if n > UIO_MAXIOV {
            return Err(KernelError::InvalidArgument);
        }
        let mut v = Self {
            segs: Vec::with_capacity(n),
            total: 0,
        };
        for i in 0..n as u64 {
            let at = ptr.checked_add(i * 16).ok_or(KernelError::BadAddress)?;
            let base = get_user::<Uaccess, u64>(at).map_err(|_| KernelError::BadAddress)?;
            let at8 = at.checked_add(8).ok_or(KernelError::BadAddress)?;
            let len = get_user::<Uaccess, u64>(at8).map_err(|_| KernelError::BadAddress)?;
            v.push(base, len)?;
        }
        Ok(v)
    }

    fn push(&mut self, base: u64, len: u64) -> Result<(), KernelError> {
        // Like Linux access_ok, an empty segment is never checked
        if len > isize::MAX as u64 || (len != 0 && !access_ok(base, len as usize)) {
            return Err(KernelError::BadAddress);
        }
        let len = (len as usize).min(MAX_RW_COUNT - self.total);
        self.total += len;
        self.segs.push(IoVec { base, len });
        Ok(())
    }

    /// Copy in the first `min(total, max)` bytes
    pub fn gather(&self, max: usize) -> Result<Vec<u8>, KernelError> {
        self.gather_at(0, max)
    }

    /// Copy in up to `max` bytes starting `skip` bytes into the vector
    pub fn gather_at(&self, mut skip: usize, max: usize) -> Result<Vec<u8>, KernelError> {
        let want = self.total.saturating_sub(skip).min(max);
        let mut out = crate::util::kmem::try_vec(want, 0u8)?;
        let mut off = 0;
        for s in &self.segs {
            if off == want {
                break;
            }
            if skip >= s.len {
                skip -= s.len;
                continue;
            }
            let n = (s.len - skip).min(want - off);
            copy_from_user::<Uaccess>(&mut out[off..off + n], s.base + skip as u64, n)
                .map_err(|_| KernelError::BadAddress)?;
            skip = 0;
            off += n;
        }
        Ok(out)
    }

    /// Copy `data` out starting `skip` bytes into the vector; returns the
    /// bytes copied (stops at the end of the vector)
    pub fn scatter(&self, mut skip: usize, data: &[u8]) -> Result<usize, KernelError> {
        let mut done = 0;
        for s in &self.segs {
            if done == data.len() {
                break;
            }
            if skip >= s.len {
                skip -= s.len;
                continue;
            }
            let n = (s.len - skip).min(data.len() - done);
            copy_to_user::<Uaccess>(s.base + skip as u64, &data[done..done + n])
                .map_err(|_| KernelError::BadAddress)?;
            skip = 0;
            done += n;
        }
        Ok(done)
    }
}

// ============================================================================
// msghdr, socket addresses, control messages (Linux net/socket.c,
// net/core/scm.c put_cmsg)
// ============================================================================

/// Largest socket address (sizeof(struct sockaddr_storage))
pub const SOCKADDR_MAX: usize = 128;
/// Largest control buffer accepted from sendmsg (Linux optmem_max)
pub const OPTMEM_MAX: usize = 20480;

/// recv/send flags
pub const MSG_OOB: i32 = 0x01;
pub const MSG_PEEK: i32 = 0x02;
pub const MSG_DONTROUTE: i32 = 0x04;
pub const MSG_CTRUNC: i32 = 0x08;
pub const MSG_TRUNC: i32 = 0x20;
pub const MSG_DONTWAIT: i32 = 0x40;
pub const MSG_EOR: i32 = 0x80;
pub const MSG_WAITALL: i32 = 0x100;
pub const MSG_CONFIRM: i32 = 0x800;
pub const MSG_ERRQUEUE: i32 = 0x2000;
pub const MSG_NOSIGNAL: i32 = 0x4000;
pub const MSG_MORE: i32 = 0x8000;
pub const MSG_WAITFORONE: i32 = 0x10000;
pub const MSG_CMSG_CLOEXEC: i32 = 0x4000_0000;

/// The user struct msghdr (64-bit layout)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UserMsgHdr {
    name: u64,
    namelen: i32,
    _pad0: u32,
    iov: u64,
    iovlen: u64,
    control: u64,
    controllen: u64,
    flags: i32,
    _pad1: u32,
}
crate::pod!(UserMsgHdr {
    name,
    namelen,
    _pad0,
    iov,
    iovlen,
    control,
    controllen,
    flags,
    _pad1
});

/// The user struct mmsghdr (sendmmsg/recvmmsg vector element)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MMsgHdr {
    hdr: UserMsgHdr,
    len: u32,
    _pad: u32,
}
crate::pod!(MMsgHdr { hdr, len, _pad });
const _: () = assert!(size_of::<UserMsgHdr>() == 56 && size_of::<MMsgHdr>() == 64);

impl MMsgHdr {
    /// Element `i` of the vector at `vec` (an address that wraps faults)
    pub fn at(vec: UserPtr<Self>, i: usize) -> UserPtr<Self> {
        UserPtr::new(vec.addr().wrapping_add((i * size_of::<Self>()) as u64))
    }

    /// Its msg_hdr
    pub fn hdr(p: UserPtr<Self>) -> UserPtr<UserMsgHdr> {
        p.cast()
    }

    /// Store msg_len
    pub fn set_len(p: UserPtr<Self>, n: u32) -> Result<(), KernelError> {
        field::<u32>(p.addr(), offset_of!(Self, len)).write(&n)?;
        Ok(())
    }
}

/// The field at `off` of the user struct at `base`
fn field<T>(base: u64, off: usize) -> UserPtr<T> {
    UserPtr::new(base.wrapping_add(off as u64))
}

/// A user struct msghdr, copied in
#[derive(Clone, Copy, Debug)]
pub struct MsgHdr {
    pub name: UserPtr<u8>,
    pub namelen: u32,
    pub iov: u64,
    pub iovlen: usize,
    pub control: UserPtr<u8>,
    pub controllen: usize,
}

impl MsgHdr {
    /// Copy in (Linux __copy_msghdr: msg_namelen clamped to
    /// sockaddr_storage, negative is EINVAL, no name means length 0)
    pub fn read(p: UserPtr<UserMsgHdr>) -> Result<Self, KernelError> {
        let u = p.read()?;
        if u.namelen < 0 {
            return Err(KernelError::InvalidArgument);
        }
        let name = UserPtr::new(u.name);
        Ok(Self {
            name,
            namelen: if name.is_null() {
                0
            } else {
                (u.namelen as u32).min(SOCKADDR_MAX as u32)
            },
            iov: u.iov,
            iovlen: u.iovlen as usize,
            control: UserPtr::new(u.control),
            controllen: u.controllen as usize,
        })
    }

    /// The data vector (EMSGSIZE above UIO_MAXIOV)
    pub fn iov(&self) -> Result<Iov, KernelError> {
        Iov::from_msg(self.iov, self.iovlen)
    }

    /// Destination/source address for sendmsg, if any
    pub fn addr(&self) -> Result<Option<Vec<u8>>, KernelError> {
        addr_in(self.name, u64::from(self.namelen))
    }

    /// Control data for sendmsg (ENOBUFS above optmem_max)
    pub fn control_in(&self) -> Result<Vec<u8>, KernelError> {
        if self.controllen == 0 {
            return Ok(Vec::new());
        }
        if self.controllen > OPTMEM_MAX {
            return Err(KernelError::NoBufferSpace);
        }
        let mut v = alloc::vec![0u8; self.controllen];
        copy_from_user::<Uaccess>(&mut v, self.control.addr(), self.controllen)?;
        Ok(v)
    }
}

/// Write back recvmsg results into the user msghdr at `p`
pub fn msghdr_out(
    p: UserPtr<UserMsgHdr>,
    namelen: u32,
    controllen: usize,
    flags: i32,
) -> Result<(), KernelError> {
    let a = p.addr();
    field::<u32>(a, offset_of!(UserMsgHdr, namelen)).write(&namelen)?;
    field::<u64>(a, offset_of!(UserMsgHdr, controllen)).write(&(controllen as u64))?;
    field::<i32>(a, offset_of!(UserMsgHdr, flags)).write(&flags)?;
    Ok(())
}

/// Copy in a socket address (Linux move_addr_to_kernel): `None` for no
/// address; EINVAL if longer than sockaddr_storage
pub fn addr_in(addr: UserPtr<u8>, len: u64) -> Result<Option<Vec<u8>>, KernelError> {
    if addr.is_null() || len == 0 {
        return Ok(None);
    }
    if len > SOCKADDR_MAX as u64 {
        return Err(KernelError::InvalidArgument);
    }
    let mut v = alloc::vec![0u8; len as usize];
    copy_from_user::<Uaccess>(&mut v, addr.addr(), len as usize)?;
    Ok(Some(v))
}

/// Copy out a socket address (Linux move_addr_to_user): reads *lenp,
/// copies min(*lenp, real) bytes and stores the real length
pub fn addr_out(addr: UserPtr<u8>, lenp: UserPtr<u32>, a: &[u8]) -> Result<(), KernelError> {
    let ulen = lenp.read()? as i32;
    if ulen < 0 {
        return Err(KernelError::InvalidArgument);
    }
    let n = (ulen as usize).min(a.len());
    if n > 0 {
        copy_to_user::<Uaccess>(addr.addr(), &a[..n])?;
    }
    lenp.write(&(a.len() as u32))?;
    Ok(())
}

/// Data source of a send: a user vector (the send calls) or the
/// iterator of a write(), which moves forward only: its bytes are taken
/// in order
pub enum Src<'a> {
    User(Iov),
    Iter { from: IovSource<'a>, total: usize },
}

impl<'a> Src<'a> {
    /// Take over `from` until [`Src::restore`]
    pub fn iter(from: &mut IovSource<'a>) -> Self {
        let from = core::mem::replace(from, IovSource::kernel(&[]));
        let total = from.len();
        Self::Iter { from, total }
    }

    /// Put a taken-over iterator back, advanced past the bytes taken
    pub fn restore(self, from: &mut IovSource<'a>) {
        if let Src::Iter { from: f, .. } = self {
            *from = f;
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Src::User(v) => v.total,
            Src::Iter { total, .. } => *total,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Copy in the first `n` bytes
    pub fn take(&mut self, n: usize) -> Result<Vec<u8>, KernelError> {
        self.take_at(0, n)
    }

    /// Copy in up to `n` bytes starting at `off` (for an iterator, `off`
    /// is the bytes already taken); EFAULT if a fault cuts it short
    pub fn take_at(&mut self, off: usize, n: usize) -> Result<Vec<u8>, KernelError> {
        match self {
            Src::User(v) => v.gather_at(off, n),
            Src::Iter { from, total } => {
                debug_assert_eq!(off, *total - from.len());
                let mut out = crate::util::kmem::try_vec(n.min(from.len()), 0u8)?;
                from.copy_from_full(&mut out)?;
                Ok(out)
            }
        }
    }
}

/// Data destination of a receive: a user vector (the recv calls) or the
/// iterator of a read(), which moves forward only: its bytes are put in
/// order
pub enum Dst<'a> {
    User(Iov),
    Iter { to: IovDest<'a>, total: usize },
}

impl<'a> Dst<'a> {
    /// Take over `to` until [`Dst::restore`]
    pub fn iter(to: &mut IovDest<'a>) -> Self {
        let to = core::mem::replace(to, IovDest::kernel(&mut []));
        let total = to.len();
        Self::Iter { to, total }
    }

    /// Put a taken-over iterator back, advanced past the bytes put
    pub fn restore(self, to: &mut IovDest<'a>) {
        if let Dst::Iter { to: t, .. } = self {
            *to = t;
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Dst::User(v) => v.total,
            Dst::Iter { total, .. } => *total,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Copy `data` out at offset `off` (for an iterator, `off` is the
    /// bytes already put); returns the bytes stored (up to the end),
    /// EFAULT if a fault cuts it short
    pub fn put(&mut self, off: usize, data: &[u8]) -> Result<usize, KernelError> {
        match self {
            Dst::User(v) => v.scatter(off, data),
            Dst::Iter { to, total } => {
                debug_assert_eq!(off, *total - to.len());
                let n = data.len().min(to.len());
                to.copy_to_full(&data[..n])?;
                Ok(n)
            }
        }
    }
}

/// A send request
pub struct SendMsg<'a> {
    /// Destination address (msg_name / sendto), if given
    pub addr: Option<Vec<u8>>,
    pub data: Src<'a>,
    /// Raw control messages
    pub control: Vec<u8>,
}

/// A receive request; the protocol fills `name`, `cmsg` and `flags`
pub struct RecvMsg<'a> {
    pub data: Dst<'a>,
    /// Caller wants the source address
    pub want_name: bool,
    pub name: Option<Vec<u8>>,
    pub cmsg: Cmsg,
    /// msg_flags out (MSG_TRUNC, MSG_CTRUNC, MSG_EOR, ...)
    pub flags: i32,
}

impl<'a> RecvMsg<'a> {
    pub fn new(data: Dst<'a>, want_name: bool, controllen: usize) -> Self {
        Self {
            data,
            want_name,
            name: None,
            cmsg: Cmsg::new(controllen),
            flags: 0,
        }
    }
}

/// struct cmsghdr size and alignment (64-bit)
const CMSG_HDR: usize = 16;
fn cmsg_align(n: usize) -> usize {
    (n + 7) & !7
}

/// Control messages produced by recvmsg (Linux put_cmsg semantics:
/// what does not fit is truncated and flagged MSG_CTRUNC)
pub struct Cmsg {
    cap: usize,
    pub buf: Vec<u8>,
    pub trunc: bool,
}

impl Cmsg {
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            buf: Vec::new(),
            trunc: false,
        }
    }

    /// The caller's control buffer size (0: no control buffer)
    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// Bytes still free in the control buffer
    pub fn room(&self) -> usize {
        self.cap - self.buf.len()
    }

    /// Append one control message
    pub fn put(&mut self, level: i32, ty: i32, data: &[u8]) {
        let room = self.cap - self.buf.len();
        if room < CMSG_HDR {
            self.trunc = true;
            return;
        }
        let mut len = CMSG_HDR + data.len();
        if room < len {
            self.trunc = true;
            len = room;
        }
        self.buf.extend_from_slice(&(len as u64).to_ne_bytes());
        self.buf.extend_from_slice(&level.to_ne_bytes());
        self.buf.extend_from_slice(&ty.to_ne_bytes());
        self.buf.extend_from_slice(&data[..len - CMSG_HDR]);
        let space = cmsg_align(CMSG_HDR + data.len()).min(room);
        self.buf.resize(self.buf.len() - len + space, 0);
    }
}

/// Iterate the control messages of a send: (level, type, data)
pub fn cmsgs(c: &[u8]) -> impl Iterator<Item = Result<(i32, i32, &[u8]), KernelError>> {
    let mut off = 0;
    core::iter::from_fn(move || {
        if c.len() - off < CMSG_HDR {
            return None;
        }
        let len = u64::from_ne_bytes(c[off..off + 8].try_into().unwrap()) as usize;
        if len < CMSG_HDR || len > c.len() - off {
            off = c.len();
            return Some(Err(KernelError::InvalidArgument));
        }
        let level = i32::from_ne_bytes(c[off + 8..off + 12].try_into().unwrap());
        let ty = i32::from_ne_bytes(c[off + 12..off + 16].try_into().unwrap());
        let data = &c[off + CMSG_HDR..off + len];
        off = (off + cmsg_align(len)).min(c.len());
        Some(Ok((level, ty, data)))
    })
}

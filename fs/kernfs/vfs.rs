//! kernfs VFS glue (Linux fs/kernfs/{inode,dir,file,symlink}.c)
//!
//! Inodes are made on lookup and carry their `KNode`; a cached dentry
//! stays valid until the node is removed. Attribute files follow sysfs
//! seq_file semantics: a read that does not continue where the last one
//! ended (the first, one at offset 0, one after a seek) runs show() into
//! a per-open buffer that continuing reads slice;
//! one write() is one store() of at most `ATTR_MAX` bytes (E2BIG past
//! it, Linux atomic_write_len), copied in before the lock. poll()
//! reports POLLERR|POLLPRI once the node was notified since the file
//! last read it. Binary attributes read and write at the file offset,
//! below their size, at most a page per call (Linux
//! kernfs_file_read_iter / kernfs_fop_write_iter).
//!
//! ## Locking
//!
//! `OpenAttr.buf` (sleeping `Mutex`, Linux kernfs_open_file.mutex) is
//! held across show()/store(), under an active reference, and across a
//! read's copy to the caller (it may fault: -> mmap_lock), with no
//! active reference held then.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use super::{ATTR_MAX, AttrNode, BinAttr, KNode, Kind, SysBuf};
use crate::fs::KernelError;
use crate::fs::file::{DirContext, DirEntry, File, FileOps, RwFlags, generic_llseek};
use crate::fs::inode::{AsAny, FileType, Inode, InodeAttr, InodeData, InodeMode, InodeOps};
use crate::fs::iov_iter::{IovDest, IovSource};
use crate::fs::superblock::SuperBlock;
use crate::io::poll::{DEFAULT_POLLMASK, POLLERR, POLLPRI, PollTable};
use crate::mm::filemap::PAGE_SIZE;
use crate::sync::Mutex;
use crate::sync::spin::Mutex as SpinMutex;
use crate::util::kalloc::try_arc;
use crate::util::kmem::try_vec;

/// Inode private data: the node
pub struct KfInode(pub Arc<KNode>);

impl AsAny for KfInode {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

impl InodeData for KfInode {}

/// A kernfs superblock's namespace: the network namespace whose tagged
/// nodes its mount shows (Linux kernfs_super_info.ns)
pub struct KfSuper {
    pub ns: u64,
}

impl AsAny for KfSuper {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

impl crate::fs::superblock::SuperBlockData for KfSuper {}

/// The namespace of `inode`'s mount
fn sb_ns(inode: &Inode) -> u64 {
    let Some(sb) = inode.superblock() else {
        return 0;
    };
    let Some(p) = sb.get_private() else { return 0 };
    p.as_any().downcast_ref::<KfSuper>().map_or(0, |k| k.ns)
}

/// The node behind `inode`
pub fn knode(inode: &Inode) -> Option<Arc<KNode>> {
    let p = inode.get_private()?;
    Some(p.as_any().downcast_ref::<KfInode>()?.0.clone())
}

/// A new inode for `kn` on `sb` (Linux kernfs_init_inode)
pub fn inode(sb: &Arc<SuperBlock>, kn: &Arc<KNode>) -> Result<Arc<Inode>, KernelError> {
    let (mode, size) = match &kn.kind {
        Kind::Dir(_) => (InodeMode::directory(kn.mode), 0),
        Kind::Attr(_) => (InodeMode::regular(kn.mode), ATTR_MAX as u64),
        Kind::Bin(b) => (InodeMode::regular(kn.mode), b.ops().map_or(0, |o| o.size())),
        Kind::Link(_) => (InodeMode::symlink(), 0),
    };
    let now = crate::time::TIMEKEEPER.current_time();
    let i = try_arc(Inode::new(
        kn.ino,
        mode,
        0,
        0,
        size,
        now,
        Arc::downgrade(sb),
        &KERNFS_IOPS,
    ))?;
    i.set_private(try_arc(KfInode(kn.clone()))?);
    let saved = *kn.iattr.lock();
    if let Some(a) = saved {
        i.set_mode_perm(a.perm);
        i.set_uid(a.uid);
        i.set_gid(a.gid);
        i.set_atime(a.atime);
        i.set_mtime(a.mtime);
        i.set_ctime(a.ctime);
    }
    Ok(i)
}

pub struct KernfsIops;

impl InodeOps for KernfsIops {
    fn lookup(&self, dir: &Inode, name: &[u8]) -> Result<Arc<Inode>, KernelError> {
        let d = knode(dir).ok_or(KernelError::Io)?;
        let kn = d.find_ns(name, sb_ns(dir)).ok_or(KernelError::NotFound)?;
        if kn.removed() {
            return Err(KernelError::NotFound);
        }
        let sb = dir.superblock().ok_or(KernelError::Io)?;
        inode(&sb, &kn)
    }

    /// Linux kernfs_iop_setattr: the node keeps the attributes, so an
    /// inode made after this one is dropped shows them too
    fn setattr_done(&self, inode: &Inode) {
        let Some(kn) = knode(inode) else { return };
        *kn.iattr.lock() = Some(super::Iattr {
            perm: inode.mode().perm(),
            uid: inode.uid(),
            gid: inode.gid(),
            atime: inode.atime(),
            mtime: inode.mtime(),
            ctime: inode.ctime(),
        });
    }

    /// Linux kernfs_dop_revalidate: a removed node's dentry is stale
    fn revalidate(&self, inode: &Inode) -> bool {
        knode(inode).is_some_and(|kn| !kn.removed())
    }

    fn readlink(&self, inode: &Inode) -> Result<Vec<u8>, KernelError> {
        let kn = knode(inode).ok_or(KernelError::Io)?;
        let Kind::Link(t) = &kn.kind else {
            return Err(KernelError::InvalidArgument);
        };
        let target = t.upgrade().filter(|t| !t.removed());
        let target = target.ok_or(KernelError::NotFound)?;
        let dir = kn.parent().ok_or(KernelError::NotFound)?;
        Ok(dir.rel_path(&target))
    }

    /// st_nlink of a directory: subdirectories + 2
    fn getattr(&self, inode: &Inode) -> InodeAttr {
        let nlink = match knode(inode) {
            Some(kn) if kn.is_dir() => kn.subdirs(sb_ns(inode)) + 2,
            _ => 1,
        };
        InodeAttr {
            ino: inode.ino,
            mode: inode.mode(),
            uid: inode.uid(),
            gid: inode.gid(),
            size: inode.get_size(),
            nlink,
            rdev: inode.rdev,
            atime: inode.atime(),
            mtime: inode.mtime(),
            ctime: inode.ctime(),
        }
    }
}

pub static KERNFS_IOPS: KernfsIops = KernfsIops;

/// show() output of an open file and where the last read ended (Linux
/// seq_file buf and read_pos)
struct SeqBuf {
    data: Vec<u8>,
    read_pos: u64,
}

/// An open directory: the key of the last entry readdir returned
/// (spin leaf)
struct OpenDir {
    last: SpinMutex<Option<(u32, u64, Vec<u8>)>>,
}

/// An open attribute (Linux kernfs_open_file)
struct OpenAttr {
    buf: Mutex<Option<SeqBuf>>,
    /// Node event count seen by the last show() (poll compares)
    event: AtomicU32,
}

fn attr_of(file: &File) -> Result<(Arc<KNode>, Arc<OpenAttr>), KernelError> {
    let inode = file.get_inode().ok_or(KernelError::BadFd)?;
    let kn = knode(&inode).ok_or(KernelError::Io)?;
    let of = file
        .private_arc::<OpenAttr>()
        .ok_or(KernelError::IsDirectory)?;
    Ok((kn, of))
}

fn attr_node(kn: &KNode) -> &AttrNode {
    match &kn.kind {
        Kind::Attr(a) => a,
        _ => unreachable!("attribute file on a non-attribute node"),
    }
}

impl OpenAttr {
    /// Linux sysfs_kf_seq_show into a fresh buffer, cut at ATTR_MAX - 1
    fn fill(&self, kn: &KNode, a: &AttrNode) -> Result<Vec<u8>, KernelError> {
        let _act = kn.get_active().ok_or(KernelError::NoDevice)?;
        self.event
            .store(a.event.load(Ordering::Acquire), Ordering::Release);
        let mut out = SysBuf::default();
        a.ops().ok_or(KernelError::NoDevice)?.show(&mut out)?;
        out.0.truncate(ATTR_MAX - 1);
        Ok(out.0)
    }
}

pub struct KernfsFops;

/// An open binary attribute: its node and operations
type BinFile = (Arc<KNode>, Arc<dyn BinAttr>);

/// The node of an open binary attribute and its operations (ENODEV
/// once it is removed); None for any other file
fn bin_of(file: &File) -> Option<Result<BinFile, KernelError>> {
    let kn = knode(&*file.get_inode()?)?;
    let b = match &kn.kind {
        Kind::Bin(b) => b.ops().ok_or(KernelError::NoDevice),
        _ => return None,
    };
    Some(b.map(|b| (kn, b)))
}

/// Linux sysfs_kf_bin_read/write: clipped to the size, EOF past it
fn bin_io(
    kn: &KNode,
    b: &dyn BinAttr,
    off: u64,
    len: usize,
    io: impl FnOnce(usize) -> Result<usize, KernelError>,
) -> Result<usize, KernelError> {
    let _act = kn.get_active().ok_or(KernelError::NoDevice)?;
    let size = b.size();
    if off >= size {
        return Ok(0);
    }
    io(len.min((size - off) as usize))
}

/// Linux kernfs_file_read_iter of a binary attribute: at most a page,
/// read into a kernel buffer under an active reference, copied out
/// after it
fn bin_read(
    kn: &KNode,
    b: &dyn BinAttr,
    to: &mut IovDest<'_>,
    off: u64,
) -> Result<usize, KernelError> {
    let mut buf = try_vec(to.len().min(PAGE_SIZE), 0u8)?;
    let n = bin_io(kn, b, off, buf.len(), |n| b.read(off, &mut buf[..n]))?;
    to.copy_to(&buf[..n])
}

/// Linux kernfs_fop_write_iter of a binary attribute: at most a page,
/// copied in before the active reference is taken
fn bin_write(
    kn: &KNode,
    b: &dyn BinAttr,
    from: &mut IovSource<'_>,
    off: u64,
) -> Result<usize, KernelError> {
    let room = usize::try_from(b.size().saturating_sub(off)).unwrap_or(usize::MAX);
    let mut buf = try_vec(from.len().min(PAGE_SIZE).min(room), 0u8)?;
    // Whole or EFAULT (Linux kernfs_fop_write_iter)
    from.copy_from_full(&mut buf)?;
    bin_io(kn, b, off, buf.len(), |n| b.write(off, &buf[..n]))
}

impl KernfsFops {
    /// Read at `off`: an attribute from its show() buffer, filled again
    /// unless this read continues the last; the copy runs under
    /// `OpenAttr.buf` (Linux seq_read_iter under m->lock)
    fn read_at(&self, file: &File, to: &mut IovDest<'_>, off: u64) -> Result<usize, KernelError> {
        if let Some(r) = bin_of(file) {
            let (kn, b) = r?;
            return bin_read(&kn, &*b, to, off);
        }
        let (kn, of) = attr_of(file)?;
        let a = attr_node(&kn);
        let mut b = of.buf.lock();
        let sb = match b.take() {
            Some(sb) if sb.read_pos == off => sb,
            _ => SeqBuf {
                data: of.fill(&kn, a)?,
                read_pos: off,
            },
        };
        let start = usize::try_from(off).map_or(sb.data.len(), |o| o.min(sb.data.len()));
        let r = match &sb.data[start..] {
            [] => Ok(0),
            rest => to.copy_to(rest),
        };
        let n = r.as_ref().map_or(0, |&n| n);
        *b = Some(SeqBuf {
            read_pos: off + n as u64,
            ..sb
        });
        r
    }

    /// Write at `off`: one store() of the whole write (E2BIG past
    /// `ATTR_MAX`), from a kernel copy taken before the lock
    fn write_any(
        &self,
        file: &File,
        from: &mut IovSource<'_>,
        off: u64,
    ) -> Result<usize, KernelError> {
        if let Some(r) = bin_of(file) {
            let (kn, b) = r?;
            return bin_write(&kn, &*b, from, off);
        }
        let (kn, of) = attr_of(file)?;
        if from.len() > ATTR_MAX {
            return Err(KernelError::ArgListTooLong);
        }
        if from.is_empty() {
            return Ok(0);
        }
        let mut data = try_vec(from.len(), 0u8)?;
        // Whole or EFAULT (Linux kernfs_fop_write_iter)
        from.copy_from_full(&mut data)?;
        let _b = of.buf.lock();
        let _act = kn.get_active().ok_or(KernelError::NoDevice)?;
        attr_node(&kn)
            .ops()
            .ok_or(KernelError::NoDevice)?
            .store(&data)
    }
}

impl FileOps for KernfsFops {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    /// Linux kernfs_fop_open: EACCES when the mode refuses the access
    /// (even for root)
    fn open(&self, file: &File) -> Result<(), KernelError> {
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        let kn = knode(&inode).ok_or(KernelError::Io)?;
        if kn.is_dir() {
            let od = try_arc(OpenDir {
                last: SpinMutex::new(None),
            })?;
            file.private.call_once(|| od);
            return Ok(());
        }
        if !matches!(kn.kind, Kind::Attr(_) | Kind::Bin(_)) {
            return Ok(());
        }
        // The inode's mode as chmod left it, and the node's own (its
        // creation mode stands for has_read/has_write: no write bit, no
        // store)
        let (im, km) = (inode.mode().perm(), kn.mode);
        let refused = |bits: u16| im & bits == 0 || km & bits == 0;
        if (file.is_writable() && refused(0o222)) || (file.is_readable() && refused(0o444)) {
            return Err(KernelError::PermissionDenied);
        }
        if matches!(kn.kind, Kind::Bin(_)) {
            return Ok(());
        }
        let _act = kn.get_active().ok_or(KernelError::NoDevice)?;
        let of = OpenAttr {
            buf: Mutex::new(None),
            event: AtomicU32::new(attr_node(&kn).event.load(Ordering::Acquire)),
        };
        let of = try_arc(of)?;
        file.private.call_once(|| of);
        Ok(())
    }

    /// No FMODE_NOWAIT: RWF_NOWAIT is EOPNOTSUPP
    fn read_iter(
        &self,
        file: &File,
        to: &mut IovDest<'_>,
        at: Option<u64>,
        rw: RwFlags,
    ) -> Result<usize, KernelError> {
        if rw.nowait {
            return Err(KernelError::OperationNotSupported);
        }
        let off = at.unwrap_or_else(|| file.get_pos());
        let n = self.read_at(file, to, off)?;
        if at.is_none() {
            file.set_pos(off + n as u64);
        }
        Ok(n)
    }

    fn write_iter(
        &self,
        file: &File,
        from: &mut IovSource<'_>,
        at: Option<u64>,
        rw: RwFlags,
    ) -> Result<usize, KernelError> {
        if rw.nowait {
            return Err(KernelError::OperationNotSupported);
        }
        let off = at.unwrap_or_else(|| file.get_pos());
        let n = self.write_any(file, from, off)?;
        if at.is_none() {
            file.set_pos(off + n as u64);
        }
        Ok(n)
    }

    /// Linux kernfs_fop_llseek: generic_file_llseek (SEEK_END is
    /// relative to the 4096-byte size), ENODEV once removed
    fn llseek(&self, file: &File, offset: i64, whence: i32) -> Result<u64, KernelError> {
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        let kn = knode(&inode).ok_or(KernelError::Io)?;
        let _act = kn.get_active().ok_or(KernelError::NoDevice)?;
        generic_llseek(file, inode.get_size(), offset, whence)
    }

    /// Linux kernfs_fop_readdir: ".", "..", then children by hash
    fn readdir(&self, file: &File, ctx: &mut DirContext<'_>) -> Result<(), KernelError> {
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        let kn = knode(&inode).ok_or(KernelError::Io)?;
        if !kn.is_dir() {
            return Err(KernelError::NotDirectory);
        }
        let parent_ino = kn.parent().map_or(kn.ino, |p| p.ino);
        for (at, ino, name) in [(0, kn.ino, &b"."[..]), (1, parent_ino, &b".."[..])] {
            let e = DirEntry {
                ino,
                file_type: FileType::Directory,
                name: name.to_vec(),
            };
            if !ctx.emit_at(at, e) {
                return Ok(());
            }
        }
        let from = ctx.pos.clamp(2, i32::MAX as u64) as u32;
        let od = file.private_arc::<OpenDir>();
        // Continuing right after the last entry this file returned: the
        // rest of its hash too (Linux kernfs_dir_pos with the node kept
        // in private_data), so entries sharing a hash are not skipped
        let last = od
            .as_ref()
            .and_then(|o| o.last.lock().clone())
            .filter(|l| l.0 + 1 == from);
        let start = last.as_ref().map_or(from, |l| l.0);
        for (h, n) in kn.list_from(start, sb_ns(&inode)) {
            if n.removed() {
                continue;
            }
            let name = n.name();
            if let Some(l) = &last
                && h == l.0
            {
                if (n.ns, &name) <= (l.1, &l.2) {
                    continue;
                }
                ctx.pos = u64::from(h);
            }
            let file_type = match n.kind {
                Kind::Dir(_) => FileType::Directory,
                Kind::Attr(_) | Kind::Bin(_) => FileType::Regular,
                Kind::Link(_) => FileType::Symlink,
            };
            let e = DirEntry {
                ino: n.ino,
                file_type,
                name: name.clone(),
            };
            if !ctx.emit_at(u64::from(h), e) {
                return Ok(());
            }
            if let Some(o) = &od {
                *o.last.lock() = Some((h, n.ns, name));
            }
        }
        // Past the last entry (Linux INT_MAX)
        ctx.pos = ctx.pos.max(i32::MAX as u64);
        Ok(())
    }

    /// Linux kernfs_generic_poll
    fn poll(&self, file: &File, pt: Option<&mut PollTable<'_>>) -> u16 {
        let Ok((kn, of)) = attr_of(file) else {
            return DEFAULT_POLLMASK;
        };
        let a = attr_node(&kn);
        if let Some(pt) = pt {
            pt.poll_wait(&a.poll);
        }
        if of.event.load(Ordering::Acquire) != a.event.load(Ordering::Acquire) {
            DEFAULT_POLLMASK | POLLERR | POLLPRI
        } else {
            DEFAULT_POLLMASK
        }
    }

    /// Attributes poll (kernfs_file_fops), directories do not
    /// (kernfs_dir_fops)
    fn can_poll(&self, file: &File) -> bool {
        file.get_inode().is_some_and(|i| !i.mode().is_dir())
    }
}

pub static KERNFS_FOPS: KernfsFops = KernfsFops;

//! kernfs VFS glue (Linux fs/kernfs/{inode,dir,file,symlink}.c)
//!
//! Inodes are made on lookup and carry their `KNode`; a cached dentry
//! stays valid until the node is removed. Attribute files follow sysfs
//! seq_file semantics: a read that does not continue where the last one
//! ended (the first, one at offset 0, one after a seek) runs show() into
//! a per-open buffer that continuing reads slice;
//! one write() is one store() of at most `ATTR_MAX` bytes (E2BIG past
//! it, Linux atomic_write_len). poll() reports POLLERR|POLLPRI once the
//! node was notified since the file last read it. Binary attributes
//! read and write at the file offset, below their size.
//!
//! ## Locking
//!
//! `OpenAttr.buf` (sleeping `Mutex`, Linux kernfs_open_file.mutex) is
//! held across show()/store(), under an active reference.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use super::{ATTR_MAX, AttrNode, BinAttr, KNode, Kind, SysBuf};
use crate::fs::KernelError;
use crate::fs::file::{DirContext, DirEntry, File, FileOps, generic_llseek};
use crate::fs::inode::{AsAny, FileType, Inode, InodeAttr, InodeData, InodeMode, InodeOps};
use crate::fs::superblock::SuperBlock;
use crate::io::poll::{DEFAULT_POLLMASK, POLLERR, POLLPRI, PollTable};
use crate::sync::Mutex;

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
pub fn inode(sb: &Arc<SuperBlock>, kn: &Arc<KNode>) -> Arc<Inode> {
    let (mode, size) = match &kn.kind {
        Kind::Dir(_) => (InodeMode::directory(kn.mode), 0),
        Kind::Attr(_) => (InodeMode::regular(kn.mode), ATTR_MAX as u64),
        Kind::Bin(b) => (InodeMode::regular(kn.mode), b.size()),
        Kind::Link(_) => (InodeMode::symlink(), 0),
    };
    let now = crate::time::TIMEKEEPER.current_time();
    let i = Arc::new(Inode::new(
        kn.ino,
        mode,
        0,
        0,
        size,
        now,
        Arc::downgrade(sb),
        &KERNFS_IOPS,
    ));
    i.set_private(Arc::new(KfInode(kn.clone())));
    i
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
        Ok(inode(&sb, &kn))
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
            size: inode.size.load(Ordering::Relaxed),
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

/// The node of an open binary attribute
fn bin_of(file: &File) -> Option<(Arc<KNode>, Arc<dyn BinAttr>)> {
    let kn = knode(&*file.get_inode()?)?;
    match &kn.kind {
        Kind::Bin(b) => {
            let b = b.clone();
            Some((kn, b))
        }
        _ => None,
    }
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

impl KernfsFops {
    fn read_at(&self, file: &File, buf: &mut [u8], off: u64) -> Result<usize, KernelError> {
        if let Some((kn, b)) = bin_of(file) {
            return bin_io(&kn, &*b, off, buf.len(), |n| b.read(off, &mut buf[..n]));
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
        let start = (off as usize).min(sb.data.len());
        let n = (sb.data.len() - start).min(buf.len());
        buf[..n].copy_from_slice(&sb.data[start..start + n]);
        *b = Some(SeqBuf {
            read_pos: off + n as u64,
            ..sb
        });
        Ok(n)
    }

    fn write_any(&self, file: &File, data: &[u8], off: u64) -> Result<usize, KernelError> {
        if let Some((kn, b)) = bin_of(file) {
            return bin_io(&kn, &*b, off, data.len(), |n| b.write(off, &data[..n]));
        }
        let (kn, of) = attr_of(file)?;
        if data.len() > ATTR_MAX {
            return Err(KernelError::ArgListTooLong);
        }
        if data.is_empty() {
            return Ok(0);
        }
        let _b = of.buf.lock();
        let _act = kn.get_active().ok_or(KernelError::NoDevice)?;
        attr_node(&kn)
            .ops()
            .ok_or(KernelError::NoDevice)?
            .store(data)
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
        if !matches!(kn.kind, Kind::Attr(_) | Kind::Bin(_)) {
            return Ok(());
        }
        if (file.is_writable() && kn.mode & 0o222 == 0)
            || (file.is_readable() && kn.mode & 0o444 == 0)
        {
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
        file.private.call_once(|| Arc::new(of));
        Ok(())
    }

    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize, KernelError> {
        let pos = file.get_pos();
        let n = self.read_at(file, buf, pos)?;
        file.set_pos(pos + n as u64);
        Ok(n)
    }

    fn pread(&self, file: &File, buf: &mut [u8], off: u64) -> Result<usize, KernelError> {
        self.read_at(file, buf, off)
    }

    fn write(&self, file: &File, data: &[u8]) -> Result<usize, KernelError> {
        let pos = file.get_pos();
        let n = self.write_any(file, data, pos)?;
        file.set_pos(pos + n as u64);
        Ok(n)
    }

    fn pwrite(&self, file: &File, data: &[u8], off: u64) -> Result<usize, KernelError> {
        self.write_any(file, data, off)
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
    fn readdir(&self, file: &File, ctx: &mut DirContext) -> Result<(), KernelError> {
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
        for (h, n) in kn.list_from(from, sb_ns(&inode)) {
            if n.removed() {
                continue;
            }
            let file_type = match n.kind {
                Kind::Dir(_) => FileType::Directory,
                Kind::Attr(_) | Kind::Bin(_) => FileType::Regular,
                Kind::Link(_) => FileType::Symlink,
            };
            let e = DirEntry {
                ino: n.ino,
                file_type,
                name: n.name(),
            };
            if !ctx.emit_at(h as u64, e) {
                return Ok(());
            }
        }
        // Past the last entry (Linux INT_MAX)
        ctx.pos = ctx.pos.max(i32::MAX as u64);
        Ok(())
    }

    /// Linux kernfs_generic_poll
    fn poll(&self, file: &File, pt: Option<&mut PollTable>) -> u16 {
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
}

pub static KERNFS_FOPS: KernfsFops = KernfsFops;

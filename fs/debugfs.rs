//! debugfs (Linux fs/debugfs/inode.c, file.c)
//!
//! A simple filesystem whose dentries are its directories: kernel code
//! makes each file and directory with [`create_file`] / [`create_dir`]
//! (and the typed [`create_bool`], [`create_u32`]), a dentry
//! instantiated under the parent's i_rwsem and kept for good (nothing
//! here removes one); a lookup of any other name finds nothing
//! (simple_lookup) and its negative dentry goes at its last put. One
//! superblock, held by a kernel mount from the first file on
//! (simple_pin_fs) and shown by every mount (get_tree_single), at
//! /sys/kernel/debug.
//!
//! ## Locking
//!
//! Entries are made under their directory's i_rwsem (`fs::libfs`); the
//! kernel mount's hold count is `PIN`, a spin leaf. A file's operations
//! run with no debugfs lock held; the typed files' values are atomics
//! (Linux plain bool/u32 read and written without a lock).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::fs::KernelError;
use crate::fs::dentry::{Dentry, DentryOps, DentryRef};
use crate::fs::file::{DirContext, File, FileOps, RwFlags};
use crate::fs::inode::{AsAny, Inode, InodeData, InodeMode, InodeOps, InodeRef};
use crate::fs::iov_iter::{IovDest, IovSource};
use crate::fs::kernfs::sysfs;
use crate::fs::libfs::{self, PinnedFs};
use crate::fs::superblock::{FileSystemType, StatFs, SuperBlock, SuperOps, fs_flags};
use crate::sync::spin::Mutex as SpinMutex;
use crate::util::kalloc::try_arc;

/// Linux DEBUGFS_MAGIC
pub const DEBUGFS_MAGIC: u64 = 0x6462_6720;

/// The root's mode without a mode= option (Linux DEBUGFS_DEFAULT_MODE)
const DEBUGFS_DEFAULT_MODE: u16 = 0o700;

/// A debugfs file's operations (Linux the file_operations and data
/// given to debugfs_create_file); a read or write moves `pos` as Linux
/// ->read / ->write move *ppos
pub trait DebugFops: Send + Sync {
    /// Read into `to` at `*pos`
    fn read(&self, to: &mut IovDest<'_>, pos: &mut u64) -> Result<usize, KernelError>;

    /// Write from `from` at `*pos`: the bytes taken
    fn write(&self, from: &mut IovSource<'_>, pos: &mut u64) -> Result<usize, KernelError>;
}

/// An inode's debugfs data: a file's operations (Linux i_fop and
/// i_private); None for a directory
struct DebugfsInode {
    fops: Option<Arc<dyn DebugFops>>,
}

impl AsAny for DebugfsInode {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

impl InodeData for DebugfsInode {}

/// The operations of an open file's inode; None for a directory
fn fops(file: &File) -> Option<Arc<dyn DebugFops>> {
    let inode = file.get_inode()?;
    let d = inode
        .private_rcu()?
        .as_any()
        .downcast_ref::<DebugfsInode>()?;
    d.fops.clone()
}

/// Linux simple_dir_inode_operations / the files' default inode
/// operations
struct DebugfsIops;

impl InodeOps for DebugfsIops {
    /// Linux simple_lookup: every entry is in the dcache
    fn lookup(&self, _dir: &Inode, _name: &[u8]) -> Result<InodeRef, KernelError> {
        Err(KernelError::NotFound)
    }
}

static DEBUGFS_IOPS: DebugfsIops = DebugfsIops;

/// A new inode of `sb` (Linux debugfs_get_inode: the next pseudo inode
/// number, the times now, owned by root)
fn new_inode(
    sb: Option<&Arc<SuperBlock>>,
    ino: u64,
    mode: InodeMode,
    fops: Option<Arc<dyn DebugFops>>,
) -> Result<InodeRef, KernelError> {
    let now = crate::time::TIMEKEEPER.current_time();
    let i = Inode::alloc(Inode::new(ino, mode, 0, 0, 0, now, sb, &DEBUGFS_IOPS))?;
    i.set_private_rcu(try_arc(DebugfsInode { fops })?);
    // Directory inodes start with 2 links, for "." (Linux inc_nlink)
    if mode.is_dir() {
        i.inc_nlink();
    }
    Ok(i)
}

/// The kernel mount's holds (Linux debugfs_mount, debugfs_mount_count)
static PIN: PinnedFs = PinnedFs::new();

/// Make `name` in `parent` (None: the root) with the kernel mount held
/// for it, given back if that fails (Linux start_creating,
/// failed_creating, then __debugfs_create_file / debugfs_create_dir)
fn create_in(
    parent: Option<&DentryRef>,
    name: &[u8],
    mode: InodeMode,
    f: Option<Arc<dyn DebugFops>>,
) -> Result<DentryRef, KernelError> {
    let m = libfs::simple_pin_fs(&DEBUGFS_TYPE, &PIN)?;
    let p = parent.cloned().unwrap_or_else(|| m.root.clone());
    libfs::simple_create(&p, name, |dir| {
        let ino = crate::fs::anon_inodes::get_next_ino();
        let i = new_inode(dir.superblock(), ino, mode, f)?;
        if mode.is_dir() {
            dir.inc_nlink();
        }
        Ok(i)
    })
    .inspect_err(|_| libfs::simple_release_fs(&PIN))
}

/// A file `name` with permissions `perm` and operations `f` in `parent`
/// (None: the root) (Linux debugfs_create_file)
pub fn create_file(
    name: &[u8],
    perm: u16,
    parent: Option<&DentryRef>,
    f: Arc<dyn DebugFops>,
) -> Result<DentryRef, KernelError> {
    create_in(parent, name, InodeMode::regular(perm), Some(f))
}

/// A directory `name` in `parent` (None: the root), mode 0755 (Linux
/// debugfs_create_dir: S_IFDIR | S_IRWXU | S_IRUGO | S_IXUGO)
pub fn create_dir(name: &[u8], parent: Option<&DentryRef>) -> Result<DentryRef, KernelError> {
    create_in(parent, name, InodeMode::directory(0o755), None)
}

/// A bool's file: "Y\n" or "N\n"; a write takes kstrtobool's forms
/// (Linux fops_bool, debugfs_read_file_bool / debugfs_write_file_bool)
struct DebugBool(&'static AtomicBool);

impl DebugFops for DebugBool {
    fn read(&self, to: &mut IovDest<'_>, pos: &mut u64) -> Result<usize, KernelError> {
        let s: &[u8] = if self.0.load(Ordering::Relaxed) {
            b"Y\n"
        } else {
            b"N\n"
        };
        libfs::simple_read_from_buffer(to, pos, s)
    }

    /// Linux debugfs_write_file_bool: the whole write is taken, the
    /// value changed only if it parses (kstrtobool_from_user)
    fn write(&self, from: &mut IovSource<'_>, _pos: &mut u64) -> Result<usize, KernelError> {
        let len = from.len();
        let mut buf = [0u8; 3];
        let n = len.min(buf.len());
        from.copy_from_full(&mut buf[..n])?;
        if let Some(v) = kstrtobool(&buf[..n]) {
            self.0.store(v, Ordering::Relaxed);
        }
        Ok(len)
    }
}

/// Linux kstrtobool: y/Y/t/T/1 true, n/N/f/F/0 false, "on" / "off"
pub fn kstrtobool(s: &[u8]) -> Option<bool> {
    match s.first()? {
        b'y' | b'Y' | b't' | b'T' | b'1' => Some(true),
        b'n' | b'N' | b'f' | b'F' | b'0' => Some(false),
        b'o' | b'O' => match s.get(1)? {
            b'n' | b'N' => Some(true),
            b'f' | b'F' => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// A u32's file: "%llu\n"; a write is a number in any base kstrtoull
/// takes (Linux fops_u32: simple_attr_read / simple_attr_write)
struct DebugU32(&'static AtomicU32);

impl DebugFops for DebugU32 {
    fn read(&self, to: &mut IovDest<'_>, pos: &mut u64) -> Result<usize, KernelError> {
        let mut s = alloc::string::String::new();
        let _ = writeln!(s, "{}", self.0.load(Ordering::Relaxed));
        libfs::simple_read_from_buffer(to, pos, s.as_bytes())
    }

    /// Linux simple_attr_write: up to 23 bytes parsed (kstrtoull base
    /// 0), the value truncated to 32 bits (debugfs_u32_set); the whole
    /// write claimed on success
    fn write(&self, from: &mut IovSource<'_>, _pos: &mut u64) -> Result<usize, KernelError> {
        let len = from.len();
        let mut buf = [0u8; 23];
        let n = len.min(buf.len());
        from.copy_from_full(&mut buf[..n])?;
        let s = buf[..n].split(|&c| c == 0).next().unwrap_or(b"");
        let v = crate::util::kstrtox::kstrtoull(s, 0)?;
        // Truncated on purpose (Linux *(u32 *)data = val)
        self.0.store(v as u32, Ordering::Relaxed);
        Ok(len)
    }
}

/// A file reading and writing `v` as Y/N (Linux debugfs_create_bool)
pub fn create_bool(
    name: &[u8],
    perm: u16,
    parent: Option<&DentryRef>,
    v: &'static AtomicBool,
) -> Result<DentryRef, KernelError> {
    create_file(name, perm, parent, try_arc(DebugBool(v))?)
}

/// A file reading and writing `v` in decimal (Linux debugfs_create_u32)
pub fn create_u32(
    name: &[u8],
    perm: u16,
    parent: Option<&DentryRef>,
    v: &'static AtomicU32,
) -> Result<DentryRef, KernelError> {
    create_file(name, perm, parent, try_arc(DebugU32(v))?)
}

/// Linux the debugfs files' f_op, and simple_dir_operations for
/// directories
struct DebugfsFops;

impl FileOps for DebugfsFops {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    /// A directory gets its reader's cursor (Linux dcache_dir_open)
    fn open(&self, file: &File) -> Result<(), KernelError> {
        match fops(file) {
            Some(_) => Ok(()),
            None => libfs::dcache_dir_open(file),
        }
    }

    fn release(&self, file: &File) -> Result<(), KernelError> {
        if fops(file).is_none() {
            libfs::dcache_dir_close(file);
        }
        Ok(())
    }

    /// Linux dcache_dir_lseek for a directory, default_llseek for a file
    fn llseek(&self, file: &File, offset: i64, whence: i32) -> Result<u64, KernelError> {
        if fops(file).is_none() {
            return libfs::dcache_dir_lseek(file, offset, whence);
        }
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        crate::fs::file::generic_llseek(file, inode.get_size(), offset, whence)
    }

    /// No FMODE_NOWAIT: RWF_NOWAIT is EOPNOTSUPP
    fn read_iter(
        &self,
        file: &File,
        to: &mut IovDest<'_>,
        at: Option<u64>,
        rw: RwFlags,
    ) -> Result<usize, KernelError> {
        if rw.nowait() {
            return Err(KernelError::OperationNotSupported);
        }
        let f = fops(file).ok_or(KernelError::IsDirectory)?;
        let mut pos = at.unwrap_or_else(|| file.get_pos());
        let n = f.read(to, &mut pos)?;
        if at.is_none() {
            file.set_pos(pos);
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
        if rw.nowait() {
            return Err(KernelError::OperationNotSupported);
        }
        let f = fops(file).ok_or(KernelError::IsDirectory)?;
        let mut pos = at.unwrap_or_else(|| file.get_pos());
        let n = f.write(from, &mut pos)?;
        if at.is_none() {
            file.set_pos(pos);
        }
        Ok(n)
    }

    fn readdir(&self, file: &File, ctx: &mut DirContext<'_>) -> Result<(), KernelError> {
        libfs::dcache_readdir(file, ctx)
    }

    fn can_poll(&self, _file: &File) -> bool {
        false
    }
}

static DEBUGFS_FOPS: DebugfsFops = DebugfsFops;

/// The superblock's mount options (Linux debugfs_fs_info: uid, gid,
/// mode), a spin leaf: replaced by each mount or remount, read by
/// show_options
struct FsInfo(SpinMutex<(u32, u32, u16)>);

impl crate::fs::superblock::SuperBlockData for FsInfo {}

/// debugfs's mount options, each set if given (Linux debugfs_fs_info's
/// fields and its `opts` bits)
#[derive(Default)]
struct DebugOpts {
    uid: Option<u32>,
    gid: Option<u32>,
    mode: Option<u16>,
}

/// Linux debugfs_parse_param: uid=, gid=, mode= (octal), source=;
/// anything else ignored ("traditionally debugfs has ignored all mount
/// options"), a bad value EINVAL
fn parse_opts(data: &[u8]) -> Result<DebugOpts, KernelError> {
    let mut o = DebugOpts::default();
    let num = |v: &[u8], radix: u32| {
        core::str::from_utf8(v)
            .ok()
            .and_then(|s| u32::from_str_radix(s, radix).ok())
            .ok_or(KernelError::InvalidArgument)
    };
    let data = data.split(|&c| c == 0).next().unwrap_or(b"");
    for w in data.split(|&c| c == b',').filter(|w| !w.is_empty()) {
        let Some(i) = w.iter().position(|&c| c == b'=') else {
            continue;
        };
        let (k, v) = (&w[..i], &w[i + 1..]);
        match k {
            b"uid" => o.uid = Some(num(v, 10)?),
            b"gid" => o.gid = Some(num(v, 10)?),
            b"mode" => o.mode = Some((num(v, 8)? & 0o7777) as u16),
            _ => {}
        }
    }
    Ok(o)
}

/// Linux _debugfs_apply_options(sb, true): the root's mode, owner and
/// group, only those given
fn apply_options(sb: &SuperBlock, o: &DebugOpts) -> Result<(), KernelError> {
    let root = sb
        .get_root()
        .and_then(|r| r.get_inode())
        .ok_or(KernelError::Io)?;
    if let Some(m) = o.mode {
        root.set_mode_perm(m);
    }
    if let Some(u) = o.uid {
        root.set_uid(u);
    }
    if let Some(g) = o.gid {
        root.set_gid(g);
    }
    Ok(())
}

struct DebugfsSops;

impl SuperOps for DebugfsSops {
    fn d_persistent(&self) -> bool {
        true
    }

    fn alloc_inode(
        &self,
        _sb: &Arc<SuperBlock>,
        _mode: InodeMode,
        _i_op: &'static dyn InodeOps,
    ) -> Result<InodeRef, KernelError> {
        Err(KernelError::OperationNotSupported)
    }

    fn statfs(&self, _sb: &SuperBlock) -> Result<StatFs, KernelError> {
        Ok(StatFs {
            f_type: DEBUGFS_MAGIC,
            f_bsize: 4096,
            f_namelen: 255,
            ..StatFs::default()
        })
    }

    /// Linux debugfs_reconfigure: the superblock's options are the new
    /// ones (structure copy), then those given applied
    fn remount(&self, sb: &SuperBlock, data: &[u8]) -> Result<(), KernelError> {
        let o = parse_opts(data)?;
        let new = (
            o.uid.unwrap_or(0),
            o.gid.unwrap_or(0),
            o.mode.unwrap_or(DEBUGFS_DEFAULT_MODE),
        );
        if let Some(f) = sb.fs_info::<FsInfo>() {
            *f.0.lock() = new;
        }
        apply_options(sb, &o)
    }

    /// Linux debugfs_show_options: uid, gid when not 0, mode when not
    /// the default
    fn show_options(&self, sb: &SuperBlock, out: &mut Vec<u8>) {
        let Some((uid, gid, mode)) = sb.fs_info::<FsInfo>().map(|f| *f.0.lock()) else {
            return;
        };
        let mut s = alloc::string::String::new();
        if uid != 0 {
            let _ = write!(s, ",uid={uid}");
        }
        if gid != 0 {
            let _ = write!(s, ",gid={gid}");
        }
        if mode != DEBUGFS_DEFAULT_MODE {
            let _ = write!(s, ",mode={mode:o}");
        }
        out.extend_from_slice(s.as_bytes());
    }
}

static DEBUGFS_SOPS: DebugfsSops = DebugfsSops;

/// Linux debugfs_dops: d_delete always_delete_dentry (no
/// d_automount: hk has no debugfs automount points)
static DEBUGFS_DOPS: DentryOps = DentryOps {
    d_delete: Some(always_delete),
    ..DentryOps::NONE
};

fn always_delete(d: &Dentry) -> bool {
    d.is_negative()
}

/// Linux debugfs_fill_super: simple_fill_super's root directory (inode
/// 1), then debugfs_apply_options: the default mode, owned by root
fn fill_super(sb: &Arc<SuperBlock>) -> Result<(), KernelError> {
    sb.set_d_op(&DEBUGFS_DOPS);
    let fsi = FsInfo(SpinMutex::new((0, 0, DEBUGFS_DEFAULT_MODE)));
    sb.set_fs_info(crate::fs::superblock::FsInfo::new(try_arc(fsi)?)?);
    let ri = new_inode(
        Some(sb),
        1,
        InodeMode::directory(DEBUGFS_DEFAULT_MODE),
        None,
    )?;
    sb.set_root(DentryRef::new(Dentry::new_root(ri, Arc::downgrade(sb)))?);
    Ok(())
}

/// One superblock for every mount (Linux debugfs_get_tree:
/// get_tree_single, then debugfs_reconfigure)
fn mount(
    fc: &crate::fs::superblock::FsContext<'_>,
) -> Result<crate::fs::superblock::SbLocked, KernelError> {
    let sb = crate::fs::superblock::get_tree_single(fc, &DEBUGFS_SOPS, fill_super)?;
    sb.s_op.remount(&sb, fc.data)?;
    Ok(sb)
}

/// debugfs's kill_sb (Linux debugfs_kill_sb: kill_anon_super, then its
/// options freed)
fn kill_sb(sb: &SuperBlock, g: crate::fs::superblock::SbUmount<'_>) {
    crate::fs::superblock::kill_anon_super(sb, g);
    sb.kill_fs_info();
}

pub static DEBUGFS_TYPE: FileSystemType = FileSystemType {
    name: "debugfs",
    fs_flags: fs_flags::FS_PSEUDO,
    mount,
    kill_sb,
    file_ops: &DEBUGFS_FOPS,
    next: crate::fs::superblock::FsNext::new(None),
    fs_supers: crate::fs::superblock::FsSupers::new(crate::util::list::WeakList::new()),
};

/// Linux debugfs_init (a core initcall): /sys/kernel/debug to mount it
/// on, the type
pub fn init() {
    sysfs::mount_point(&sysfs::top_dir(b"kernel"), b"debug");
    crate::fs::superblock::register_filesystem(&DEBUGFS_TYPE).expect("debugfs type");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kstrtobool_forms() {
        for (s, v) in [
            (&b"Y\n"[..], Some(true)),
            (b"1", Some(true)),
            (b"on", Some(true)),
            (b"N", Some(false)),
            (b"0\n", Some(false)),
            (b"off", Some(false)),
            (b"o", None),
            (b"x", None),
            (b"", None),
        ] {
            assert_eq!(kstrtobool(s), v);
        }
    }

    #[test]
    fn options() {
        let o = parse_opts(b"uid=5,mode=750,bogus,x=y\0").unwrap();
        assert_eq!((o.uid, o.gid, o.mode), (Some(5), None, Some(0o750)));
        assert!(parse_opts(b"gid=abc").is_err());
    }
}

//! tracefs (Linux fs/tracefs/inode.c)
//!
//! A simple filesystem whose dentries are its directories: the tracing
//! code makes each file and directory with [`create_file`] /
//! [`create_dir`], a dentry instantiated under the parent's i_rwsem and
//! kept until [`remove`] takes it and what is below it away
//! (simple_recursive_removal); a lookup of any other name finds nothing
//! (simple_lookup) and its negative dentry goes at its last put
//! (tracefs_d_delete), so no cached dentry is ever stale and there is
//! no d_revalidate (Linux's is eventfs's alone). One superblock, held by
//! a kernel mount from the first file on (simple_pin_fs) and shown by
//! every mount (get_tree_single), at /sys/kernel/tracing.
//!
//! ## Locking
//!
//! Entries are made and removed under their directory's i_rwsem
//! (`fs::libfs`); the kernel mount's hold count is `PIN`, a spin leaf.
//! A file's operations run with no tracefs lock held (a write under
//! the file's i_rwsem, as every regular file's).

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::fs::KernelError;
use crate::fs::dentry::{Dentry, DentryOps, DentryRef};
use crate::fs::file::{DirContext, File, FileOps, RwFlags};
use crate::fs::inode::{AsAny, Inode, InodeAttr, InodeData, InodeMode, InodeOps, InodeRef};
use crate::fs::iov_iter::{IovDest, IovSource};
use crate::fs::kernfs::sysfs;
use crate::fs::libfs::{self, PinnedFs};
use crate::fs::superblock::{FileSystemType, StatFs, SuperBlock, SuperOps, fs_flags};
use crate::sync::spin::Mutex as SpinMutex;
use crate::task::Cred;
use crate::util::kalloc::try_arc;

/// Linux TRACEFS_MAGIC
pub const TRACEFS_MAGIC: u64 = 0x7472_6163;

/// The root's mode without a mode= option (Linux TRACEFS_DEFAULT_MODE)
const TRACEFS_DEFAULT_MODE: u16 = 0o700;

/// A tracefs file's operations (Linux the file_operations and i_private
/// given to tracefs_create_file); a read or write moves `pos` as Linux
/// ->read / ->write move *ppos
pub trait TraceFops: Send + Sync {
    /// Linux ->open: for writing or not, the open's flags
    fn open(&self, writable: bool, flags: u32) -> Result<(), KernelError> {
        let _ = (writable, flags);
        Ok(())
    }

    /// Read into `to` at `*pos`
    fn read(&self, to: &mut IovDest<'_>, pos: &mut u64) -> Result<usize, KernelError>;

    /// Write from `from` at `*pos`: the bytes taken
    fn write(&self, from: &mut IovSource<'_>, pos: &mut u64) -> Result<usize, KernelError>;
}

/// chown set the inode's owner, which then no longer follows the
/// root's (Linux TRACEFS_UID_PERM_SET)
const UID_PERM_SET: u32 = 1 << 0;
/// The same for its group (Linux TRACEFS_GID_PERM_SET)
const GID_PERM_SET: u32 = 1 << 1;

/// An inode's tracefs data (Linux tracefs_inode): a file's operations
/// (i_fop, i_private), the root whose owner it takes (ti->private; None
/// for the root itself), the PERM_SET flags. RCU-readable
/// (`Inode::private_rcu`), so a permission check in an RCU walk reads
/// it.
struct TracefsInode {
    fops: Option<Arc<dyn TraceFops>>,
    root: Option<InodeRef>,
    flags: AtomicU32,
}

impl AsAny for TracefsInode {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

impl InodeData for TracefsInode {}

/// The tracefs data of `inode`
fn ti(inode: &Inode) -> Option<&TracefsInode> {
    inode.private_rcu()?.as_any().downcast_ref::<TracefsInode>()
}

/// The operations of an open file's inode; None for a directory
fn fops(file: &File) -> Option<Arc<dyn TraceFops>> {
    ti(&*file.get_inode()?)?.fops.clone()
}

/// Linux set_tracefs_inode_owner: an inode whose owner or group chown
/// never set takes the root's (no instances here: the root is the
/// mount's)
fn set_owner(inode: &Inode) {
    let Some(t) = ti(inode) else { return };
    let Some(root) = &t.root else { return };
    let flags = t.flags.load(Ordering::Acquire);
    if flags & UID_PERM_SET == 0 {
        inode.set_uid(root.uid());
    }
    if flags & GID_PERM_SET == 0 {
        inode.set_gid(root.gid());
    }
}

/// Linux tracefs_dir_inode_operations and tracefs_file_inode_operations
struct TracefsIops;

impl InodeOps for TracefsIops {
    /// Linux simple_lookup: every entry is in the dcache, so a name
    /// that is not is not there
    fn lookup(&self, _dir: &Inode, _name: &[u8]) -> Result<InodeRef, KernelError> {
        Err(KernelError::NotFound)
    }

    /// Linux tracefs_permission: the owner brought up to date, then
    /// generic_permission (an RCU walk's too: atomics only)
    fn permission(&self, inode: &Inode, cred: &Cred, mask: u32) -> Result<(), KernelError> {
        set_owner(inode);
        crate::fs::dac::generic_permission(cred, inode, mask)
    }

    /// Linux tracefs_getattr
    fn getattr(&self, inode: &Inode) -> InodeAttr {
        set_owner(inode);
        crate::fs::inode::generic_fillattr(inode)
    }

    /// Linux tracefs_setattr: ATTR_UID / ATTR_GID pin the inode's own
    fn setattr_ids(&self, inode: &Inode, uid: bool, gid: bool) {
        let Some(t) = ti(inode) else { return };
        let f = if uid { UID_PERM_SET } else { 0 } | if gid { GID_PERM_SET } else { 0 };
        t.flags.fetch_or(f, Ordering::AcqRel);
    }
}

static TRACEFS_IOPS: TracefsIops = TracefsIops;

/// A new inode of the superblock `sb` (Linux tracefs_get_inode: the
/// next pseudo inode number, the times now)
fn new_inode(
    sb: Weak<SuperBlock>,
    ino: u64,
    mode: InodeMode,
    (uid, gid): (u32, u32),
    (fops, root): (Option<Arc<dyn TraceFops>>, Option<InodeRef>),
) -> Result<InodeRef, KernelError> {
    let now = crate::time::TIMEKEEPER.current_time();
    let i = Inode::alloc(Inode::new(ino, mode, uid, gid, 0, now, sb, &TRACEFS_IOPS))?;
    let flags = AtomicU32::new(0);
    i.set_private_rcu(try_arc(TracefsInode { fops, root, flags })?);
    // Directory inodes start with 2 links, for "." (Linux inc_nlink)
    if mode.is_dir() {
        i.inc_nlink();
    }
    Ok(i)
}

/// `name` in `parent`, a file with operations `f` or a directory
/// (Linux tracefs_create_file / __create_dir from
/// tracefs_start_creating's dentry on): owned like its directory, its
/// owner following the root's (instance_inode)
fn create(
    parent: &DentryRef,
    name: &[u8],
    mode: InodeMode,
    f: Option<Arc<dyn TraceFops>>,
) -> Result<DentryRef, KernelError> {
    libfs::simple_create(parent, name, |dir| {
        let ino = crate::fs::anon_inodes::get_next_ino();
        // The root: the directory's, or the directory itself
        let root = match ti(dir).and_then(|t| t.root.clone()) {
            Some(r) => r,
            None => Inode::igrab(dir).ok_or(KernelError::NotFound)?,
        };
        let ids = (dir.uid(), dir.gid());
        let i = new_inode((*dir.sb).clone(), ino, mode, ids, (f, Some(root)))?;
        if mode.is_dir() {
            dir.inc_nlink();
        }
        Ok(i)
    })
}

/// The kernel mount's holds (Linux tracefs_mount, tracefs_mount_count)
static PIN: PinnedFs = PinnedFs::new();

/// The directory a new entry goes in (Linux tracefs_start_creating:
/// the kernel mount held, `parent` or else the root)
fn start_creating(parent: Option<&DentryRef>) -> Result<DentryRef, KernelError> {
    let m = libfs::simple_pin_fs(&TRACEFS_TYPE, &PIN)?;
    Ok(parent.cloned().unwrap_or_else(|| m.root.clone()))
}

/// Make `name` in `parent` (None: the root) with the kernel mount held
/// for it, given back if that fails (Linux tracefs_failed_creating)
fn create_in(
    parent: Option<&DentryRef>,
    name: &[u8],
    mode: InodeMode,
    f: Option<Arc<dyn TraceFops>>,
) -> Result<DentryRef, KernelError> {
    let p = start_creating(parent)?;
    create(&p, name, mode, f).inspect_err(|_| libfs::simple_release_fs(&PIN))
}

/// A file `name` with permissions `perm` and operations `f` in `parent`
/// (None: the root) (Linux tracefs_create_file); to go with [`remove`]
pub fn create_file(
    name: &[u8],
    perm: u16,
    parent: Option<&DentryRef>,
    f: Arc<dyn TraceFops>,
) -> Result<DentryRef, KernelError> {
    create_in(parent, name, InodeMode::regular(perm), Some(f))
}

/// A directory `name` in `parent` (None: the root), mode 0750 (Linux
/// tracefs_create_dir: no bits for others); to go with [`remove`]
pub fn create_dir(name: &[u8], parent: Option<&DentryRef>) -> Result<DentryRef, KernelError> {
    create_in(parent, name, InodeMode::directory(0o750), None)
}

/// Remove `d` and what is below it (Linux tracefs_remove:
/// simple_recursive_removal, each entry giving back its hold on the
/// kernel mount, remove_one)
pub fn remove(d: &DentryRef) {
    if libfs::simple_pin_fs(&TRACEFS_TYPE, &PIN).is_err() {
        return;
    }
    libfs::simple_recursive_removal(d, Some(&|_| libfs::simple_release_fs(&PIN)));
    libfs::simple_release_fs(&PIN);
}

/// Linux the tracefs files' f_op as each sets it, and
/// simple_dir_operations for directories
struct TracefsFops;

impl FileOps for TracefsFops {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn open(&self, file: &File) -> Result<(), KernelError> {
        match fops(file) {
            Some(f) => f.open(file.is_writable(), file.get_flags()),
            None => Ok(()),
        }
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

    /// No ->poll in any tracefs file here
    fn can_poll(&self, _file: &File) -> bool {
        false
    }
}

static TRACEFS_FOPS: TracefsFops = TracefsFops;

struct TracefsSops;

impl SuperOps for TracefsSops {
    /// Linux d_make_persistent of every entry made
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
            f_type: TRACEFS_MAGIC,
            f_bsize: 4096,
            f_namelen: 255,
            ..StatFs::default()
        })
    }

    /// Linux tracefs_parse_param + tracefs_apply_options(remount): uid=,
    /// gid=, mode= (octal) set the root's, only those given; any other
    /// option is EINVAL (vfs_parse_fs_param: "Unknown parameter")
    fn remount(&self, sb: &SuperBlock, data: &[u8]) -> Result<(), KernelError> {
        let o = parse_opts(data)?;
        // tracefs_reconfigure: the superblock's options are the new ones,
        // all of them (structure copy), then those given applied
        let new = (
            o.uid.unwrap_or(0),
            o.gid.unwrap_or(0),
            o.mode.unwrap_or(TRACEFS_DEFAULT_MODE),
        );
        with_fsi(sb, |f| *f.0.lock() = new);
        apply_options(sb, &o)
    }

    /// Linux tracefs_show_options: uid, gid when not 0, mode when not
    /// the default
    fn show_options(&self, sb: &SuperBlock, out: &mut Vec<u8>) {
        let Some((uid, gid, mode)) = with_fsi(sb, |f| *f.0.lock()) else {
            return;
        };
        let mut s = alloc::string::String::new();
        if uid != 0 {
            let _ = write!(s, ",uid={uid}");
        }
        if gid != 0 {
            let _ = write!(s, ",gid={gid}");
        }
        if mode != TRACEFS_DEFAULT_MODE {
            let _ = write!(s, ",mode={mode:o}");
        }
        out.extend_from_slice(s.as_bytes());
    }
}

/// The superblock's mount options (Linux tracefs_fs_info in s_fs_info:
/// uid, gid, mode), a spin leaf: replaced by each mount or remount,
/// read by show_options
struct FsInfo(SpinMutex<(u32, u32, u16)>);

impl AsAny for FsInfo {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

impl crate::fs::superblock::SuperBlockData for FsInfo {}

/// `f` on the superblock's options
fn with_fsi<R>(sb: &SuperBlock, f: impl FnOnce(&FsInfo) -> R) -> Option<R> {
    let p = sb.get_private()?;
    p.as_any().downcast_ref::<FsInfo>().map(f)
}

/// Linux tracefs_apply_options(sb, true): the root's mode, owner and
/// group as given; a new owner or group goes to every inode, which
/// follows the root's again (its PERM_SET flag cleared)
fn apply_options(sb: &SuperBlock, o: &TraceOpts) -> Result<(), KernelError> {
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
    if o.uid.is_none() && o.gid.is_none() {
        return Ok(());
    }
    crate::fs::inode::for_each_sb_inode(sb, &mut |i| {
        if let Some(t) = ti(i) {
            if let Some(u) = o.uid {
                t.flags.fetch_and(!UID_PERM_SET, Ordering::AcqRel);
                i.set_uid(u);
            }
            if let Some(g) = o.gid {
                t.flags.fetch_and(!GID_PERM_SET, Ordering::AcqRel);
                i.set_gid(g);
            }
        }
        true
    });
    Ok(())
}

/// tracefs's mount options (Linux tracefs_fs_info: each set if given)
#[derive(Default)]
struct TraceOpts {
    uid: Option<u32>,
    gid: Option<u32>,
    mode: Option<u16>,
}

/// Linux tracefs_param_specs (fsparam_uid, fsparam_gid, fsparam_u32oct)
fn parse_opts(data: &[u8]) -> Result<TraceOpts, KernelError> {
    let mut o = TraceOpts::default();
    let num = |v: &[u8], radix: u32| {
        core::str::from_utf8(v)
            .ok()
            .and_then(|s| u32::from_str_radix(s, radix).ok())
            .ok_or(KernelError::InvalidArgument)
    };
    let data = data.split(|&c| c == 0).next().unwrap_or(b"");
    for w in data.split(|&c| c == b',').filter(|w| !w.is_empty()) {
        if crate::fs::superblock::sb_flag_word(w) {
            continue;
        }
        let (k, v) = match w.iter().position(|&c| c == b'=') {
            Some(i) => (&w[..i], &w[i + 1..]),
            None => return Err(KernelError::InvalidArgument),
        };
        match k {
            b"uid" => o.uid = Some(num(v, 10)?),
            b"gid" => o.gid = Some(num(v, 10)?),
            b"mode" => o.mode = Some((num(v, 8)? & 0o7777) as u16),
            _ => return Err(KernelError::InvalidArgument),
        }
    }
    Ok(o)
}

static TRACEFS_SOPS: TracefsSops = TracefsSops;

/// Linux tracefs_dentry_operations, eventfs's part left out (hk has no
/// eventfs): no d_revalidate, and every dentry goes at its last put
/// (tracefs_d_delete: no d_fsdata) unless pinned as an entry
static TRACEFS_DOPS: DentryOps = DentryOps {
    d_delete: Some(tracefs_d_delete),
    ..DentryOps::NONE
};

/// Linux tracefs_d_delete: a dentry with no eventfs data goes at its
/// last put
fn tracefs_d_delete(_: &Dentry) -> bool {
    true
}

/// Linux tracefs_fill_super: simple_fill_super's root directory (inode
/// 1), then tracefs_apply_options(sb, false): the default mode
fn fill_super(sb: &Arc<SuperBlock>) -> Result<(), KernelError> {
    sb.set_d_op(&TRACEFS_DOPS);
    let fsi = FsInfo(SpinMutex::new((0, 0, TRACEFS_DEFAULT_MODE)));
    sb.set_private(try_arc(fsi)?);
    let mode = InodeMode::directory(TRACEFS_DEFAULT_MODE);
    let ri = new_inode(Arc::downgrade(sb), 1, mode, (0, 0), (None, None))?;
    sb.set_root(DentryRef::new(Dentry::new_root(ri, Arc::downgrade(sb)))?);
    Ok(())
}

/// One superblock for every mount (Linux tracefs_get_tree:
/// get_tree_single, then the options applied, tracefs_reconfigure)
fn mount(
    fc: &crate::fs::superblock::FsContext<'_>,
) -> Result<crate::fs::superblock::SbLocked, KernelError> {
    let sb = crate::fs::superblock::get_tree_single(fc, &TRACEFS_SOPS, fill_super)?;
    sb.s_op.remount(&sb, fc.data)?;
    Ok(sb)
}

pub static TRACEFS_TYPE: FileSystemType = FileSystemType {
    name: "tracefs",
    fs_flags: fs_flags::FS_PSEUDO,
    mount,
    kill_sb: crate::fs::superblock::kill_anon_super,
    file_ops: &TRACEFS_FOPS,
    next: crate::fs::superblock::FsNext::new(None),
    fs_supers: crate::fs::superblock::FsSupers::new(crate::util::list::WeakList::new()),
};

/// Linux tracefs_init: /sys/kernel/tracing to mount it on, the type
pub fn init() {
    sysfs::mount_point(&sysfs::top_dir(b"kernel"), b"tracing");
    crate::fs::superblock::register_filesystem(&TRACEFS_TYPE).expect("tracefs type");
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Nop;

    impl TraceFops for Nop {
        fn read(&self, _: &mut IovDest<'_>, _: &mut u64) -> Result<usize, KernelError> {
            Ok(0)
        }

        fn write(&self, from: &mut IovSource<'_>, _: &mut u64) -> Result<usize, KernelError> {
            Ok(from.len())
        }
    }

    /// The positive children's names, in readdir order
    fn names(d: &DentryRef) -> Vec<Vec<u8>> {
        (0..)
            .map_while(|n| d.nth_positive_child(n))
            .map(|c| c.name().to_vec())
            .collect()
    }

    /// Entries are the dcache's: made under the directory (EEXIST for a
    /// taken name), and removed with what is below them
    /// (simple_recursive_removal): out of the tree, unlinked, the
    /// directories dead, the parent's link count back; a held dentry
    /// stays usable, unhashed
    #[test]
    // The i_rwsem reads the current task, an aarch64 per-CPU register a
    // host (EL0) test cannot read
    #[cfg_attr(target_arch = "aarch64", ignore)]
    fn create_and_remove() {
        let ri = new_inode(
            Weak::new(),
            1,
            InodeMode::directory(0o700),
            (0, 0),
            (None, None),
        )
        .unwrap();
        let root = DentryRef::new(Dentry::new_root(ri.clone(), Weak::new())).unwrap();
        let nop: Arc<dyn TraceFops> = Arc::new(Nop);
        let reg = InodeMode::regular(0o640);
        let dir = InodeMode::directory(0o750);
        let _t = create(&root, b"trace", reg, Some(nop.clone())).unwrap();
        let ev = create(&root, b"events", dir, None).unwrap();
        let sys = create(&ev, b"sys", dir, None).unwrap();
        let en = create(&sys, b"enable", reg, Some(nop.clone())).unwrap();
        let dup = create(&root, b"events", dir, None);
        assert!(matches!(dup, Err(KernelError::AlreadyExists)));
        assert_eq!(names(&root), [b"trace".to_vec(), b"events".to_vec()]);
        assert_eq!(ri.get_nlink(), 3);
        let (evi, eni) = (ev.get_inode().unwrap(), en.get_inode().unwrap());
        libfs::simple_recursive_removal(&ev, None);
        assert!(root.lookup_child(b"events").is_none());
        assert_eq!(names(&root), [b"trace".to_vec()]);
        assert!(ev.d_unhashed() && sys.d_unhashed() && en.d_unhashed());
        assert!(evi.is_dead() && sys.get_inode().unwrap().is_dead());
        assert_eq!(
            (evi.get_nlink(), eni.get_nlink(), ri.get_nlink()),
            (0, 0, 2)
        );
        // A removed directory takes no new entries
        let late = create(&ev, b"x", reg, Some(nop));
        assert!(matches!(late, Err(KernelError::NotFound)));
        // The name may be made again
        assert!(create(&root, b"events", dir, None).is_ok());
    }
}

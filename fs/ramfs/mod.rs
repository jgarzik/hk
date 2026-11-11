//! Ramfs - simple in-memory filesystem
//!
//! Ramfs stores file contents entirely in memory, with no limit and no
//! xattrs (Linux fs/ramfs). Its inodes, directories and page-cache files
//! are also tmpfs's (`fs::ramfs::tmpfs`), which adds the limits and xattrs.
//!
//! ## Locking Model
//!
//! Directory operations (create, mkdir, unlink, rmdir, symlink, link, rename)
//! are serialized by the VFS layer via `inode_lock()`/`inode_unlock()` on the
//! parent directory's inode. For rename operations involving two directories,
//! VFS uses `lock_rename()`/`unlock_rename()` with proper ancestor-first ordering.
//!
//! `RamfsInodeData.children` is a sleeping `RwSem` (Linux ramfs keeps a
//! directory's entries in the dcache under the directory's i_rwsem,
//! which every change here also holds): taken inside i_rwsem, in thread
//! context, so entries and their names are added under no spin lock.
//! Complex lock ordering is unnecessary since VFS guarantees no
//! concurrent directory modifications.
//!
//! File data (`RamfsInodeData.data`) uses RwLock independently for concurrent
//! read access and exclusive write access during file I/O.

pub mod cpio;
pub mod devtmpfs;
pub mod tmpfs;

use alloc::collections::BTreeMap;

use super::name::FileName;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::sync::RwSem;
use crate::sync::spin::RwLock;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::mm::filemap::{self, Aops};

use super::KernelError;
use super::dentry::Dentry;
use super::file::{DirContext, DirEntry, File, FileOps, RwFlags};
use super::inode::{AsAny, DevId, FileType, Inode, InodeData, InodeMode, InodeOps, Timespec};
use super::iov_iter::{IovDest, IovSource};
use super::superblock::{FileSystemType, RAMFS_MAGIC, StatFs, SuperBlock, SuperOps};
use crate::util::kalloc::try_arc;

// ============================================================================
// Ramfs Address Space Operations
// ============================================================================

/// Ramfs page I/O: there is no backing store, so a page not in the
/// cache is a hole and reads as zeros (Linux ramfs simple_read_folio)
pub struct RamfsAops;

impl Aops for RamfsAops {
    fn read_folio(&self, _inode: &Inode, phys: u64, _index: u64) -> Result<(), KernelError> {
        filemap::zero_page(phys, 0);
        filemap::set_uptodate(phys);
        Ok(())
    }

    /// The cache is the only copy: nothing to write back
    fn can_dirty(&self) -> bool {
        false
    }
}

/// Page-cache errors of ramfs and tmpfs writes: no memory for a new
/// page is ENOMEM, a full tmpfs ENOSPC (Linux shmem_get_folio_gfp), a
/// sealed one EPERM; a fault on the caller's buffer stays EFAULT
fn page_err(e: KernelError) -> KernelError {
    match e {
        KernelError::OutOfMemory => KernelError::OutOfMemory,
        KernelError::NoSpace => KernelError::NoSpace,
        KernelError::BadAddress => KernelError::BadAddress,
        // A sealed tmpfs file (shmem_write_begin)
        KernelError::NotPermitted => KernelError::NotPermitted,
        _ => KernelError::Io,
    }
}

/// Page-cache errors of ramfs reads (a hole needs a zeroed page): ENOMEM;
/// a fault on the caller's buffer stays EFAULT
fn read_err(e: KernelError) -> KernelError {
    match e {
        KernelError::OutOfMemory | KernelError::NoSpace => KernelError::OutOfMemory,
        KernelError::BadAddress => KernelError::BadAddress,
        _ => KernelError::Io,
    }
}

pub static RAMFS_AOPS: RamfsAops = RamfsAops;

/// tmpfs page I/O: ramfs's, with the write seals (Linux
/// shmem_write_begin: F_SEAL_WRITE / FUTURE_WRITE refuse a write,
/// F_SEAL_GROW one past i_size, EPERM)
pub struct TmpfsAops;

impl Aops for TmpfsAops {
    fn read_folio(&self, inode: &Inode, phys: u64, index: u64) -> Result<(), KernelError> {
        RAMFS_AOPS.read_folio(inode, phys, index)
    }

    fn write_begin(&self, inode: &Inode, pos: u64, len: usize) -> Result<u64, KernelError> {
        use crate::mm::memfd::{F_SEAL_FUTURE_WRITE, F_SEAL_GROW, F_SEAL_WRITE};
        let sl = seals(inode);
        if sl & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) != 0
            || (sl & F_SEAL_GROW != 0 && pos + len as u64 > inode.get_size())
        {
            return Err(KernelError::NotPermitted);
        }
        filemap::simple_write_begin(inode, pos, len)
    }

    fn can_dirty(&self) -> bool {
        false
    }
}

static TMPFS_AOPS: TmpfsAops = TmpfsAops;

/// A new regular file's mapping: ramfs operations, never evicted (the
/// cache is the only copy; Linux ramfs mapping_set_unevictable and
/// tmpfs, which has no swap here)
fn file_mapping(sb: &SuperBlock, inode: &Inode) {
    inode.i_data.set_flags(filemap::AS_UNEVICTABLE);
    // tmpfs charges its pages (Linux shmem_inode_acct_blocks)
    if let Some(a) = tmpfs::with(sb, |t| t.page_acct()) {
        inode.i_data.set_aops(&TMPFS_AOPS, None);
        inode.i_data.set_acct(a);
        // Every tmpfs file starts sealed against sealing (Linux
        // shmem_get_inode); memfd_create may clear it
        inode
            .i_data
            .seals
            .store(crate::mm::memfd::F_SEAL_SEAL, Ordering::Relaxed);
    } else {
        inode.i_data.set_aops(&RAMFS_AOPS, None);
    }
}

/// Get current timestamp for new inodes
/// Returns current wall-clock time from TIMEKEEPER if available, otherwise zero
fn current_time() -> Timespec {
    use crate::time::TIMEKEEPER;
    TIMEKEEPER.current_time()
}

/// Ramfs inode private data
pub struct RamfsInodeData {
    /// Children (for directories) - maps name to inode
    pub children: RwSem<Children>,

    /// Symlink target (symlinks only - stored inline, not in page cache)
    /// Symlinks are typically small, so inline storage is more efficient.
    pub symlink_target: Option<FileName>,

    /// Extended attributes (name -> value)
    pub xattrs: Xattrs,

    /// The superblock's xattr space this inode's attributes are charged
    /// to (set by the first charge) and how much they hold, returned
    /// when the inode is freed (Linux shmem_evict_inode)
    xattr_pool: spin::Once<Arc<tmpfs::Acct>>,
    xattr_bytes: AtomicU64,
}

impl Drop for RamfsInodeData {
    fn drop(&mut self) {
        if let Some(pool) = self.xattr_pool.get() {
            pool.give_ispace(*self.xattr_bytes.get_mut());
        }
    }
}

/// One extended attribute (Linux struct simple_xattr)
struct Xattr {
    name: Vec<u8>,
    value: Vec<u8>,
}

/// An inode's extended attributes, sorted by name (Linux simple_xattrs:
/// an rbtree by name). Everything an attribute needs is allocated
/// before the spin lock (Linux simple_xattr_alloc), and the list grows
/// with it released (`kmem::spare`): nothing allocates under it.
#[derive(Default)]
pub struct Xattrs(RwLock<Vec<Xattr>>);

impl Xattrs {
    fn find(v: &[Xattr], name: &[u8]) -> Result<usize, usize> {
        v.binary_search_by(|x| x.name.as_slice().cmp(name))
    }

    /// `f` on the value of `name`, if it has one
    fn get<R>(&self, name: &[u8], f: impl FnOnce(&[u8]) -> R) -> Option<R> {
        let v = self.0.read();
        Self::find(&v, name).ok().map(|i| f(&v[i].value))
    }

    /// Set `name` to `value` (a copy the caller made): EEXIST with
    /// XATTR_CREATE if it has one, ENODATA with XATTR_REPLACE if not,
    /// ENOMEM; the value replaced (Linux simple_xattr_set)
    fn set(&self, name: &[u8], value: Vec<u8>, flags: u32) -> Result<Option<Vec<u8>>, KernelError> {
        let new = Xattr {
            name: crate::util::kmem::try_to_vec(name)?,
            value,
        };
        // Whatever is left of `new` and the replaced value are freed
        // after the guard (declared later, dropped first)
        loop {
            let mut v = self.0.write();
            match Self::find(&v, name) {
                Ok(_) if flags & XATTR_CREATE != 0 => return Err(KernelError::AlreadyExists),
                Err(_) if flags & XATTR_REPLACE != 0 => return Err(KernelError::NoData),
                Ok(i) => return Ok(Some(core::mem::replace(&mut v[i].value, new.value))),
                Err(i) if v.len() < v.capacity() => {
                    v.insert(i, new);
                    return Ok(None);
                }
                Err(_) => {}
            }
            let cap = v.capacity();
            drop(v);
            let bigger = crate::util::kmem::spare(cap)?;
            let old = crate::util::kmem::adopt(&mut self.0.write(), bigger);
            drop(old);
        }
    }

    /// Remove `name`: its value, ENODATA if it has none
    fn remove(&self, name: &[u8]) -> Result<Xattr, KernelError> {
        let mut v = self.0.write();
        let i = Self::find(&v, name).map_err(|_| KernelError::NoData)?;
        Ok(v.remove(i))
    }

    /// The names, each NUL-terminated, into `list` (Linux
    /// simple_xattr_list): their length; with an empty `list` only the
    /// length, ERANGE if `list` is too short
    fn list(&self, list: &mut [u8]) -> Result<usize, KernelError> {
        let v = self.0.read();
        let total: usize = v.iter().map(|x| x.name.len() + 1).sum();
        if list.is_empty() {
            return Ok(total);
        }
        if list.len() < total {
            return Err(KernelError::Range);
        }
        let mut off = 0;
        for x in v.iter() {
            list[off..off + x.name.len()].copy_from_slice(&x.name);
            off += x.name.len();
            list[off] = 0;
            off += 1;
        }
        Ok(total)
    }
}

/// setxattr flags (Linux XATTR_CREATE, XATTR_REPLACE)
const XATTR_CREATE: u32 = 0x1;
const XATTR_REPLACE: u32 = 0x2;

/// Space a user.* attribute takes from its file system (Linux
/// simple_xattr_space: 40 + size + name length)
fn xattr_space(name: &[u8], size: usize) -> u64 {
    (40 + size + name.len()) as u64
}

/// Directory entries with stable readdir positions (Linux
/// simple_offset, as in tmpfs): an entry gets its directory's next
/// position when it is added, so a d_off cookie keeps its meaning while
/// other entries come and go (an `rm -r` that unlinks as it reads sees
/// every entry once). Positions 0 and 1 are "." and "..".
pub struct Children {
    by_name: BTreeMap<FileName, (u64, Arc<Inode>)>,
    by_pos: BTreeMap<u64, FileName>,
    next: u64,
}

impl Children {
    /// Empty directory
    pub const fn new() -> Self {
        Self {
            by_name: BTreeMap::new(),
            by_pos: BTreeMap::new(),
            next: 2,
        }
    }

    /// Inode of entry `name`
    pub fn get(&self, name: &[u8]) -> Option<&Arc<Inode>> {
        self.by_name.get(name).map(|(_, i)| i)
    }

    /// True if entry `name` exists
    pub fn contains_key(&self, name: &[u8]) -> bool {
        self.by_name.contains_key(name)
    }

    /// True if the directory has no entries
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    /// Add (or replace) entry `name` at the next position
    pub fn insert(&mut self, name: FileName, inode: Arc<Inode>) -> Option<Arc<Inode>> {
        let old = self.remove(&name);
        let pos = self.next;
        self.next += 1;
        self.by_pos.insert(pos, name.clone());
        self.by_name.insert(name, (pos, inode));
        old
    }

    /// Remove entry `name`
    pub fn remove(&mut self, name: &[u8]) -> Option<Arc<Inode>> {
        let (pos, inode) = self.by_name.remove(name)?;
        self.by_pos.remove(&pos);
        Some(inode)
    }

    /// Entries at position `pos` or later, in position order
    pub fn from_pos(&self, pos: u64) -> impl Iterator<Item = (u64, &[u8], &Arc<Inode>)> {
        self.by_pos.range(pos..).filter_map(|(&p, name)| {
            self.by_name
                .get(name)
                .map(|(_, inode)| (p, name.as_bytes(), inode))
        })
    }
}

impl RamfsInodeData {
    /// Create empty file data (the data lives in the inode's mapping)
    pub fn new_file() -> Self {
        Self {
            children: RwSem::new(Children::new()),
            symlink_target: None,
            xattrs: Xattrs::default(),
            xattr_pool: spin::Once::new(),
            xattr_bytes: AtomicU64::new(0),
        }
    }

    /// Create directory data
    pub fn new_dir() -> Self {
        Self {
            children: RwSem::new(Children::new()),
            symlink_target: None,
            xattrs: Xattrs::default(),
            xattr_pool: spin::Once::new(),
            xattr_bytes: AtomicU64::new(0),
        }
    }

    /// Create symlink data (target stored inline)
    pub fn new_symlink(target: FileName) -> Self {
        Self {
            children: RwSem::new(Children::new()),
            symlink_target: Some(target),
            xattrs: Xattrs::default(),
            xattr_pool: spin::Once::new(),
            xattr_bytes: AtomicU64::new(0),
        }
    }
}

impl AsAny for RamfsInodeData {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

impl InodeData for RamfsInodeData {}

/// The xattr space of `inode`'s file system (None: not counted)
fn xattr_pool(inode: &Inode) -> Option<Arc<tmpfs::Acct>> {
    let sb = inode.superblock()?;
    tmpfs::with(&sb, |t| t.xattr_pool())?
}

/// The inode's file system has user.* xattrs: tmpfs does (Linux
/// CONFIG_TMPFS_XATTR), ramfs has no xattr handlers (EOPNOTSUPP)
fn has_xattrs(inode: &Inode) -> bool {
    inode
        .superblock()
        .is_some_and(|sb| tmpfs::with(&sb, |_| ()).is_some())
}

/// Take one of the file system's inodes (tmpfs: ENOSPC when none is
/// left, Linux shmem_reserve_inode; ramfs counts none)
fn reserve_inode(sb: &SuperBlock) -> Result<(), KernelError> {
    tmpfs::with(sb, |t| t.reserve_inode()).unwrap_or(Ok(()))
}

/// Give one back (Linux shmem_free_inode)
fn free_inode(sb: &SuperBlock) {
    tmpfs::with(sb, |t| t.free_inode());
}

/// `f` on the seals of `inode` if it is a tmpfs regular file (Linux
/// memfd_file_seals_ptr: shmem files only), else None
pub fn with_seals<R>(
    inode: &Inode,
    f: impl FnOnce(&core::sync::atomic::AtomicU32) -> R,
) -> Option<R> {
    (inode.mode().is_file() && inode.i_data.charged()).then(|| f(&inode.i_data.seals))
}

/// The seals of `inode` (0 for any but a tmpfs file): one load
fn seals(inode: &Inode) -> u32 {
    inode.i_data.seals.load(Ordering::Acquire)
}

/// One name of `inode` goes (Linux shmem_unlink): on tmpfs a name
/// beyond the first gives back the inode it took
fn drop_link(inode: &Inode) {
    if inode.get_nlink() > 1
        && !inode.mode().is_dir()
        && let Some(sb) = inode.superblock()
    {
        free_inode(&sb);
    }
    inode.dec_nlink();
}

/// fallocate's allocation on tmpfs (Linux shmem_fallocate), the file
/// system's block limit `max` (0: none): the pages of [start, end),
/// ENOSPC at once if more than the whole limit
fn shmem_falloc(inode: &Inode, start: u64, end: u64, max: u64) -> Result<(), KernelError> {
    let ps = filemap::PAGE_SIZE as u64;
    let aligned = end.checked_add(ps - 1).ok_or(KernelError::FileTooLarge)?;
    if max != 0 && aligned / ps - start / ps > max {
        return Err(KernelError::NoSpace);
    }
    filemap::falloc_range(inode, start, end)
}

/// Ramfs inode operations
pub struct RamfsInodeOps;

impl RamfsInodeOps {
    /// Helper for cross-directory rename operations
    fn do_cross_dir_rename(
        old_children: &mut Children,
        old_name: &[u8],
        new_children: &mut Children,
        new_name: &[u8],
        flags: u32,
    ) -> Result<(), KernelError> {
        const RENAME_NOREPLACE: u32 = 1;
        const RENAME_EXCHANGE: u32 = 2;

        let noreplace = flags & RENAME_NOREPLACE != 0;
        let exchange = flags & RENAME_EXCHANGE != 0;

        // Get source inode
        let source_inode = old_children
            .get(old_name)
            .cloned()
            .ok_or(KernelError::NotFound)?;

        if exchange {
            // Exchange requires both to exist
            let target_inode = new_children
                .get(new_name)
                .cloned()
                .ok_or(KernelError::NotFound)?;

            // Move source to new location, target to old location
            old_children.remove(old_name);
            new_children.remove(new_name);
            old_children.insert(FileName::from(old_name), target_inode);
            new_children.insert(FileName::from(new_name), source_inode);
        } else {
            // Check if target exists
            let target_exists = new_children.contains_key(new_name);

            if noreplace && target_exists {
                return Err(KernelError::AlreadyExists);
            }

            // Remove source
            old_children.remove(old_name);

            // Handle any existing target
            if let Some(old_target) = new_children.remove(new_name) {
                // If replacing a directory, it must be empty
                if old_target.mode().is_dir() {
                    let target_private = old_target.get_private().ok_or(KernelError::Io)?;
                    let target_data = target_private
                        .as_ref()
                        .as_any()
                        .downcast_ref::<RamfsInodeData>()
                        .ok_or(KernelError::Io)?;
                    if !target_data.children.read().is_empty() {
                        // Restore source and target
                        old_children.insert(FileName::from(old_name), source_inode);
                        new_children.insert(FileName::from(new_name), old_target);
                        return Err(KernelError::DirectoryNotEmpty);
                    }
                }
                drop_link(&old_target);
            }

            // Insert at new location
            new_children.insert(FileName::from(new_name), source_inode);
        }

        Ok(())
    }
}

impl InodeOps for RamfsInodeOps {
    fn lookup(&self, dir: &Inode, name: &[u8]) -> Result<Arc<Inode>, KernelError> {
        let private = dir.get_private().ok_or(KernelError::Io)?;
        let ramfs_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(KernelError::Io)?;

        ramfs_data
            .children
            .read()
            .get(name)
            .cloned()
            .ok_or(KernelError::NotFound)
    }

    fn create(&self, dir: &Inode, name: &[u8], mode: InodeMode) -> Result<Arc<Inode>, KernelError> {
        // Owner from the caller's fs ids (inode_init_owner)
        let (uid, gid, mode) = super::dac::init_owner(dir, mode);
        add_new(dir, name, Kind::File, mode, uid, gid, current_time())
    }

    fn mknod(
        &self,
        dir: &Inode,
        name: &[u8],
        mode: InodeMode,
        rdev: DevId,
    ) -> Result<Arc<Inode>, KernelError> {
        let (uid, gid, mode) = super::dac::init_owner(dir, mode);
        add_new(dir, name, Kind::Dev(rdev), mode, uid, gid, current_time())
    }

    /// Linux ramfs_tmpfile, shmem_tmpfile (d_tmpfile drops the link);
    /// on tmpfs it takes an inode like any file
    fn tmpfile(&self, dir: &Inode, mode: InodeMode) -> Result<Arc<Inode>, KernelError> {
        let sb = dir.superblock().ok_or(KernelError::Io)?;
        let (uid, gid, mode) = super::dac::init_owner(dir, mode);
        let inode = new_inode(&sb, Kind::File, mode, uid, gid, current_time())?;
        inode.dec_nlink();
        Ok(inode)
    }

    fn mkdir(&self, dir: &Inode, name: &[u8], mode: InodeMode) -> Result<Arc<Inode>, KernelError> {
        let (uid, gid, mode) = super::dac::init_owner(dir, mode);
        add_new(dir, name, Kind::Dir, mode, uid, gid, current_time())
    }

    fn maps_cache(&self) -> bool {
        true
    }

    /// F_SEAL_EXEC keeps the exec bits (Linux shmem_setattr)
    fn chmod_ok(&self, inode: &Inode, perm: u16) -> Result<(), KernelError> {
        if seals(inode) & crate::mm::memfd::F_SEAL_EXEC != 0
            && (inode.mode().perm() ^ perm) & 0o111 != 0
        {
            return Err(KernelError::NotPermitted);
        }
        Ok(())
    }

    /// tmpfs gets the inode back (Linux shmem_evict_inode ->
    /// shmem_free_inode); a superblock already gone counts nothing
    fn evict_inode(&self, inode: &Inode) {
        if let Some(sb) = inode.superblock() {
            free_inode(&sb);
        }
    }

    fn readlink(&self, inode: &Inode) -> Result<Vec<u8>, KernelError> {
        // Must be a symlink
        if !inode.mode().is_symlink() {
            return Err(KernelError::InvalidArgument);
        }

        let private = inode.get_private().ok_or(KernelError::Io)?;
        let ramfs_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(KernelError::Io)?;

        // Symlink target is stored inline
        ramfs_data
            .symlink_target
            .clone()
            .map(FileName::into_vec)
            .ok_or(KernelError::InvalidArgument)
    }

    fn symlink(&self, dir: &Inode, name: &[u8], target: &[u8]) -> Result<Arc<Inode>, KernelError> {
        // S_IFLNK | 0777, the target inline (not in the page cache)
        let (uid, gid, mode) = super::dac::init_owner(dir, InodeMode::symlink());
        let kind = Kind::Symlink(FileName::from(target));
        add_new(dir, name, kind, mode, uid, gid, current_time())
    }

    fn link(&self, dir: &Inode, name: &[u8], target_inode: &Arc<Inode>) -> Result<(), KernelError> {
        // Cannot hard link directories
        if target_inode.mode().is_dir() {
            return Err(KernelError::PermissionDenied); // EPERM
        }

        let private = dir.get_private().ok_or(KernelError::Io)?;
        let dir_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(KernelError::Io)?;

        // Check if name already exists
        if dir_data.children.read().contains_key(name) {
            return Err(KernelError::AlreadyExists);
        }

        // tmpfs counts each extra name as an inode (Linux shmem_link:
        // tmpfs dentries pin memory until unlinked); an O_TMPFILE file's
        // first name took its inode at creation
        if target_inode.get_nlink() > 0
            && let Some(sb) = dir.superblock()
        {
            reserve_inode(&sb)?;
        }
        target_inode.inc_nlink();

        // Add new directory entry pointing to existing inode
        dir_data
            .children
            .write()
            .insert(FileName::from(name), target_inode.clone());

        Ok(())
    }

    fn truncate(&self, inode: &Arc<Inode>, length: u64) -> Result<(), KernelError> {
        if inode.mode().is_dir() {
            return Err(KernelError::IsDirectory);
        }
        // Linux shmem_setattr: a sealed size (EPERM)
        let (old, sl) = (inode.get_size(), seals(inode));
        if (length < old && sl & crate::mm::memfd::F_SEAL_SHRINK != 0)
            || (length > old && sl & crate::mm::memfd::F_SEAL_GROW != 0)
        {
            return Err(KernelError::NotPermitted);
        }
        filemap::truncate_setsize(inode, length);
        Ok(())
    }

    /// tmpfs's, as Linux shmem_fallocate: allocate (and charge) the
    /// pages, KEEP_SIZE and PUNCH_HOLE only; the cache is the only copy,
    /// so a hole reads back as zeroes. On success the file counts as
    /// modified (Linux file_modified). ramfs: EOPNOTSUPP.
    fn fallocate(
        &self,
        inode: &Arc<Inode>,
        mode: i32,
        offset: u64,
        len: u64,
    ) -> Result<(), KernelError> {
        use super::misc::falloc_mode::{FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE};
        // ramfs has no fallocate (Linux ramfs_file_operations)
        let max = inode.superblock().and_then(|sb| tmpfs::max_blocks(&sb));
        let Some(max) = max else {
            return Err(KernelError::OperationNotSupported);
        };
        if mode & !(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE) != 0 {
            return Err(KernelError::OperationNotSupported);
        }
        let end = offset + len;
        let sl = seals(inode);
        if mode & FALLOC_FL_PUNCH_HOLE != 0 {
            // Linux shmem_fallocate: a write seal keeps the data
            use crate::mm::memfd::{F_SEAL_FUTURE_WRITE, F_SEAL_WRITE};
            if sl & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) != 0 {
                return Err(KernelError::NotPermitted);
            }
            // The whole range: pages fallocated with KEEP_SIZE may lie
            // past i_size (Linux shmem_truncate_range ignores it)
            filemap::punch_range(inode, offset, end);
        } else {
            inode.newsize_ok(end)?;
            if sl & crate::mm::memfd::F_SEAL_GROW != 0 && end > inode.get_size() {
                return Err(KernelError::NotPermitted);
            }
            shmem_falloc(inode, offset, end, max)?;
            if mode & FALLOC_FL_KEEP_SIZE == 0 && end > inode.get_size() {
                inode.set_size(end);
            }
        }
        super::dac::remove_privs(inode);
        let now = current_time();
        inode.set_mtime(now);
        inode.set_ctime(now);
        Ok(())
    }

    fn unlink(&self, dir: &Inode, name: &[u8]) -> Result<(), KernelError> {
        let private = dir.get_private().ok_or(KernelError::Io)?;
        let dir_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(KernelError::Io)?;

        // Remove from directory
        let removed_inode = {
            let mut children = dir_data.children.write();
            children.remove(name).ok_or(KernelError::NotFound)?
        };

        // The inode goes with its last reference (Arc drop)
        drop_link(&removed_inode);

        Ok(())
    }

    fn rename(
        &self,
        old_dir: &Inode,
        old_name: &[u8],
        new_dir: &Arc<Inode>,
        new_name: &[u8],
        flags: u32,
    ) -> Result<(), KernelError> {
        // RENAME_NOREPLACE = 1, RENAME_EXCHANGE = 2
        const RENAME_NOREPLACE: u32 = 1;
        const RENAME_EXCHANGE: u32 = 2;

        let noreplace = flags & RENAME_NOREPLACE != 0;
        let exchange = flags & RENAME_EXCHANGE != 0;

        // No whiteouts (Linux simple_rename); NOREPLACE and EXCHANGE are
        // mutually exclusive
        if flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE) != 0 || (noreplace && exchange) {
            return Err(KernelError::InvalidArgument);
        }

        // Get old directory's data
        let old_private = old_dir.get_private().ok_or(KernelError::Io)?;
        let old_dir_data = old_private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(KernelError::Io)?;

        // Get new directory's data
        let new_private = new_dir.get_private().ok_or(KernelError::Io)?;
        let new_dir_data = new_private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(KernelError::Io)?;

        // Check if same directory (optimization for simple renames)
        let same_dir = core::ptr::eq(
            core::ptr::from_ref::<RamfsInodeData>(old_dir_data),
            core::ptr::from_ref::<RamfsInodeData>(new_dir_data),
        );

        if same_dir {
            // Same directory: just rename the entry
            let mut children = old_dir_data.children.write();

            // Get the source inode
            let source_inode = children
                .get(old_name)
                .cloned()
                .ok_or(KernelError::NotFound)?;

            // Check target exists
            let target_exists = children.contains_key(new_name);

            if exchange {
                // Exchange requires both to exist
                let target_inode = children
                    .get(new_name)
                    .cloned()
                    .ok_or(KernelError::NotFound)?;

                // Swap the entries
                children.insert(FileName::from(old_name), target_inode);
                children.insert(FileName::from(new_name), source_inode);
            } else if noreplace && target_exists {
                return Err(KernelError::AlreadyExists);
            } else {
                // Remove old entry
                children.remove(old_name);

                // If target exists, handle replacement
                if let Some(old_target) = children.remove(new_name) {
                    // If replacing a directory, it must be empty
                    if old_target.mode().is_dir() {
                        let target_private = old_target.get_private().ok_or(KernelError::Io)?;
                        let target_data = target_private
                            .as_ref()
                            .as_any()
                            .downcast_ref::<RamfsInodeData>()
                            .ok_or(KernelError::Io)?;
                        if !target_data.children.read().is_empty() {
                            // Restore the source
                            children.insert(FileName::from(old_name), source_inode);
                            return Err(KernelError::DirectoryNotEmpty);
                        }
                    }
                    drop_link(&old_target);
                }

                // Insert at new name
                children.insert(FileName::from(new_name), source_inode);
            }
        } else {
            // Different directories: VFS layer has already acquired inode locks
            // via lock_rename() with proper ancestor-first ordering. This serializes
            // all directory operations, so we can safely acquire children locks
            // in any order without deadlock risk.
            let mut old_children = old_dir_data.children.write();
            let mut new_children = new_dir_data.children.write();

            Self::do_cross_dir_rename(
                &mut old_children,
                old_name,
                &mut new_children,
                new_name,
                flags,
            )?;
        }

        Ok(())
    }

    fn rmdir(&self, dir: &Inode, name: &[u8]) -> Result<(), KernelError> {
        let private = dir.get_private().ok_or(KernelError::Io)?;
        let dir_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(KernelError::Io)?;

        // First, look up the target to check it's a directory and empty
        let target_inode = {
            let children = dir_data.children.read();
            children.get(name).cloned().ok_or(KernelError::NotFound)?
        };

        // Must be a directory
        if !target_inode.mode().is_dir() {
            return Err(KernelError::NotDirectory);
        }

        // Check if directory is empty
        let target_private = target_inode.get_private().ok_or(KernelError::Io)?;
        let target_data = target_private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(KernelError::Io)?;

        if !target_data.children.read().is_empty() {
            return Err(KernelError::DirectoryNotEmpty);
        }

        // Remove from parent directory
        let removed_inode = {
            let mut children = dir_data.children.write();
            children.remove(name).ok_or(KernelError::NotFound)?
        };

        // Decrement link count
        removed_inode.dec_nlink();

        Ok(())
    }

    // =========================================================================
    // Extended attribute operations
    // =========================================================================

    fn getxattr(&self, inode: &Inode, name: &[u8], value: &mut [u8]) -> Result<usize, KernelError> {
        if !has_xattrs(inode) {
            return Err(KernelError::OperationNotSupported);
        }
        // Validate namespace - only user.* is supported for regular files/dirs
        if !name.starts_with(b"user.") {
            return Err(KernelError::OperationNotSupported);
        }

        // user.* namespace only allowed on regular files and directories
        let mode = inode.mode();
        if !mode.is_file() && !mode.is_dir() {
            return Err(KernelError::OperationNotSupported);
        }

        let private = inode.get_private().ok_or(KernelError::Io)?;
        let ramfs_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(KernelError::Io)?;

        // An empty buffer asks for the size; ERANGE if it is too short
        ramfs_data
            .xattrs
            .get(name, |a| {
                if value.is_empty() {
                    Ok(a.len())
                } else if value.len() < a.len() {
                    Err(KernelError::Range)
                } else {
                    value[..a.len()].copy_from_slice(a);
                    Ok(a.len())
                }
            })
            .ok_or(KernelError::NoData)?
    }

    fn setxattr(
        &self,
        inode: &Inode,
        name: &[u8],
        value: &[u8],
        flags: u32,
    ) -> Result<(), KernelError> {
        if !has_xattrs(inode) {
            return Err(KernelError::OperationNotSupported);
        }
        // Validate namespace - only user.* is supported for regular files/dirs
        if !name.starts_with(b"user.") {
            return Err(KernelError::OperationNotSupported);
        }

        // user.* namespace only allowed on regular files and directories
        let mode = inode.mode();
        if !mode.is_file() && !mode.is_dir() {
            return Err(KernelError::OperationNotSupported);
        }

        let private = inode.get_private().ok_or(KernelError::Io)?;
        let ramfs_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(KernelError::Io)?;

        // The value is copied before the lock, fallibly; its space is
        // taken from the file system's first (Linux
        // shmem_xattr_handler_set: ENOSPC), the replaced value's
        // returned after
        let v = crate::util::kmem::try_to_vec(value)?;
        let need = xattr_space(name, value.len());
        let pool = xattr_pool(inode);
        if let Some(p) = &pool {
            p.take_ispace(need)?;
            ramfs_data.xattr_pool.call_once(|| p.clone());
        }
        let r = ramfs_data.xattrs.set(name, v, flags);
        let back = match &r {
            Ok(old) => old.as_ref().map_or(0, |o| xattr_space(name, o.len())),
            Err(_) => need,
        };
        if let Some(p) = &pool {
            if r.is_ok() {
                ramfs_data.xattr_bytes.fetch_add(need, Ordering::Relaxed);
                ramfs_data.xattr_bytes.fetch_sub(back, Ordering::Relaxed);
            }
            p.give_ispace(back);
        }
        r.map(|_| ())
    }

    fn listxattr(&self, inode: &Inode, list: &mut [u8]) -> Result<usize, KernelError> {
        // No xattrs on ramfs: an empty list (Linux vfs_listxattr with
        // no ->listxattr)
        if !has_xattrs(inode) {
            return Ok(0);
        }
        let private = inode.get_private().ok_or(KernelError::Io)?;
        let ramfs_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(KernelError::Io)?;

        ramfs_data.xattrs.list(list)
    }

    fn removexattr(&self, inode: &Inode, name: &[u8]) -> Result<(), KernelError> {
        if !has_xattrs(inode) {
            return Err(KernelError::OperationNotSupported);
        }
        // Validate namespace - only user.* is supported for regular files/dirs
        if !name.starts_with(b"user.") {
            return Err(KernelError::OperationNotSupported);
        }

        // user.* namespace only allowed on regular files and directories
        let mode = inode.mode();
        if !mode.is_file() && !mode.is_dir() {
            return Err(KernelError::OperationNotSupported);
        }

        let private = inode.get_private().ok_or(KernelError::Io)?;
        let ramfs_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(KernelError::Io)?;

        let old = ramfs_data.xattrs.remove(name)?;
        if let Some(p) = ramfs_data.xattr_pool.get() {
            let n = xattr_space(name, old.value.len());
            ramfs_data.xattr_bytes.fetch_sub(n, Ordering::Relaxed);
            p.give_ispace(n);
        }
        Ok(())
    }
}

/// Static ramfs inode ops
pub static RAMFS_INODE_OPS: RamfsInodeOps = RamfsInodeOps;

/// Ramfs file operations; tmpfs's (Linux shmem) read a hole without
/// caching a page and take O_DIRECT
pub struct RamfsFileOps {
    shmem: bool,
}

impl FileOps for RamfsFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    /// No poll (Linux ramfs/shmem file and dir operations)
    fn can_poll(&self, _file: &File) -> bool {
        false
    }

    /// A tmpfs regular file (Linux shmem_file_open sets
    /// FMODE_CAN_ODIRECT; shmem_dir_operations and ramfs have no such
    /// open, ramfs_aops no ->direct_IO)
    fn can_odirect(&self, file: &File) -> bool {
        self.shmem && file.get_inode().is_some_and(|i| i.mode().is_file())
    }

    /// Regular files map their data (Linux generic_file_mmap);
    /// directories have no mmap
    fn mmap(&self, file: &File, _shared: bool) -> Result<(), KernelError> {
        match file.get_inode() {
            Some(i) if i.mode().is_dir() => Err(KernelError::NoDevice),
            _ => Ok(()),
        }
    }

    /// Straight from the page cache (Linux filemap_read; tmpfs
    /// shmem_file_read_iter). No RWF_NOWAIT
    /// (EOPNOTSUPP): like Linux ramfs/tmpfs, no FMODE_NOWAIT.
    fn read_iter(
        &self,
        file: &File,
        to: &mut IovDest<'_>,
        at: Option<u64>,
        flags: RwFlags,
    ) -> Result<usize, KernelError> {
        if flags.nowait() {
            return Err(KernelError::OperationNotSupported);
        }
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        let pos = at.unwrap_or_else(|| file.get_pos());
        let n = if self.shmem {
            filemap::read_iter_holes(&inode, to, pos)
        } else {
            filemap::read_iter(&inode, to, pos)
        }
        .map_err(read_err)?;
        if at.is_none() {
            file.advance_pos(n as u64);
        }
        Ok(n)
    }

    /// Linux generic_perform_write; the VFS holds i_rwsem. Out of
    /// memory after some bytes is a short write. No RWF_NOWAIT.
    fn write_iter(
        &self,
        file: &File,
        from: &mut IovSource<'_>,
        at: Option<u64>,
        flags: RwFlags,
    ) -> Result<usize, KernelError> {
        if flags.nowait() {
            return Err(KernelError::OperationNotSupported);
        }
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        let pos = at.unwrap_or_else(|| file.get_pos());
        let n = filemap::write_iter(&inode, from, pos).map_err(page_err)?;
        if at.is_none() {
            file.advance_pos(n as u64);
        }
        Ok(n)
    }

    fn readdir(&self, file: &File, ctx: &mut DirContext<'_>) -> Result<(), KernelError> {
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        if !inode.mode().is_dir() {
            return Err(KernelError::NotDirectory);
        }
        let private = inode.get_private().ok_or(KernelError::Io)?;
        let ramfs_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(KernelError::Io)?;

        // Parent directory (use same inode for root)
        let parent_ino = file
            .dentry
            .get_parent()
            .and_then(|p| p.get_inode())
            .map(|i| i.ino)
            .unwrap_or(inode.ino);
        if !ctx.emit_at(0, dot(b".", inode.ino)) || !ctx.emit_at(1, dot(b"..", parent_ino)) {
            return Ok(());
        }

        let children = ramfs_data.children.read();
        for (pos, name, child) in children.from_pos(ctx.pos) {
            let file_type = child.mode().file_type().unwrap_or(FileType::Regular);
            let e = DirEntry {
                ino: child.ino,
                file_type,
                name: name.to_vec(),
            };
            if !ctx.emit_at(pos, e) {
                break;
            }
        }
        Ok(())
    }
}

/// "." or ".." directory entry
fn dot(name: &[u8], ino: u64) -> DirEntry {
    DirEntry {
        ino,
        file_type: FileType::Directory,
        name: name.to_vec(),
    }
}

/// Static ramfs file ops
pub static RAMFS_FILE_OPS: RamfsFileOps = RamfsFileOps { shmem: false };

/// tmpfs file ops (Linux shmem_file_operations: shmem_file_read_iter
/// reads a hole as zeros)
pub static TMPFS_FILE_OPS: RamfsFileOps = RamfsFileOps { shmem: true };

/// Ramfs superblock operations
pub struct RamfsSuperOps;

impl SuperOps for RamfsSuperOps {
    fn statfs(&self, _sb: &SuperBlock) -> StatFs {
        StatFs {
            f_type: RAMFS_MAGIC,
            f_bsize: 4096,
            f_namelen: 255,
            ..StatFs::default()
        }
    }

    fn alloc_inode(
        &self,
        sb: &Arc<SuperBlock>,
        mode: InodeMode,
        _i_op: &'static dyn InodeOps,
    ) -> Result<Arc<Inode>, KernelError> {
        new_inode(sb, Kind::of(mode), mode, 0, 0, current_time())
    }
}

/// Static ramfs super ops
pub static RAMFS_SUPER_OPS: RamfsSuperOps = RamfsSuperOps;

/// Mount function for ramfs
pub(crate) fn ramfs_mount(
    fs_type: &'static FileSystemType,
    opts: &[u8],
) -> Result<Arc<SuperBlock>, KernelError> {
    let mode = root_mode(opts)?;
    let sb = SuperBlock::new(fs_type, &RAMFS_SUPER_OPS, 0)?;
    fill_root(&sb, mode, 0, 0)?;
    Ok(sb)
}

/// Give a new superblock its root directory (Linux ramfs_fill_super,
/// shmem_fill_super: d_make_root of a new directory inode)
pub(crate) fn fill_root(
    sb: &Arc<SuperBlock>,
    mode: u16,
    uid: Uid,
    gid: Gid,
) -> Result<(), KernelError> {
    let inode = new_inode(
        sb,
        Kind::Dir,
        InodeMode::directory(mode),
        uid,
        gid,
        current_time(),
    )?;
    sb.set_root(try_arc(Dentry::new_root(inode, Arc::downgrade(sb)))?);
    Ok(())
}

/// Ramfs filesystem type
pub static RAMFS_TYPE: FileSystemType = FileSystemType {
    name: "ramfs",
    fs_flags: 0,
    mount: ramfs_mount,
    mount_dev: None, // Ramfs doesn't use a backing device
    file_ops: &RAMFS_FILE_OPS,
    next: crate::fs::superblock::FsNext::new(None),
    fs_supers: crate::fs::superblock::FsSupers::new(crate::util::list::WeakList::new()),
};

use super::inode::{Gid, Uid};

/// What a new ramfs inode is
enum Kind {
    File,
    Dir,
    /// The target, stored inline
    Symlink(FileName),
    /// A device, FIFO or socket node
    Dev(DevId),
}

impl Kind {
    /// The kind of an inode of `mode` (no symlink target yet)
    fn of(mode: InodeMode) -> Self {
        if mode.is_dir() {
            Self::Dir
        } else if mode.is_symlink() {
            Self::Symlink(FileName::default())
        } else if mode.is_file() {
            Self::File
        } else {
            Self::Dev(DevId::null())
        }
    }
}

/// A new inode of `sb` (Linux ramfs_get_inode, shmem_get_inode): on
/// tmpfs one of its inodes is taken first (ENOSPC), given back when the
/// inode goes (`evict_inode`)
fn new_inode(
    sb: &Arc<SuperBlock>,
    kind: Kind,
    mode: InodeMode,
    uid: Uid,
    gid: Gid,
    time: Timespec,
) -> Result<Arc<Inode>, KernelError> {
    reserve_inode(sb)?;
    let (ino, w) = (sb.alloc_ino(), Arc::downgrade(sb));
    let ops = &RAMFS_INODE_OPS;
    let inode = match &kind {
        Kind::Dev(rdev) => {
            Inode::alloc(Inode::new_device(ino, mode, uid, gid, *rdev, time, w, ops))
        }
        Kind::Symlink(t) => Inode::alloc(Inode::new(
            ino,
            mode,
            uid,
            gid,
            t.len() as u64,
            time,
            w,
            ops,
        )),
        _ => Inode::alloc(Inode::new(ino, mode, uid, gid, 0, time, w, ops)),
    }
    .inspect_err(|_| free_inode(sb))?;
    // From here the inode's drop gives the reservation back
    match kind {
        Kind::File => {
            inode.set_private(try_arc(RamfsInodeData::new_file())?);
            file_mapping(sb, &inode);
        }
        Kind::Dir => inode.set_private(try_arc(RamfsInodeData::new_dir())?),
        Kind::Symlink(t) => inode.set_private(try_arc(RamfsInodeData::new_symlink(t))?),
        // Devices use the block or char layer, no ramfs data
        Kind::Dev(_) => {}
    }
    Ok(inode)
}

/// A new regular file of `sb` with permissions `perm`, in no directory,
/// owned by the caller's fsuid and fsgid (Linux shmem_get_inode for
/// shmem_file_setup: inode_init_owner with no directory)
pub fn new_file(sb: &Arc<SuperBlock>, perm: u16) -> Result<Arc<Inode>, KernelError> {
    let c = crate::task::current_cred();
    let mode = InodeMode::regular(perm);
    new_inode(sb, Kind::File, mode, c.fsuid, c.fsgid, current_time())
}

/// Make a new inode and enter it in `dir` as `name` (EEXIST if taken):
/// the common part of create, mkdir, mknod, symlink. The caller holds
/// `dir`'s i_rwsem (or owns a directory nobody else sees yet).
fn add_new(
    dir: &Inode,
    name: &[u8],
    kind: Kind,
    mode: InodeMode,
    uid: Uid,
    gid: Gid,
    time: Timespec,
) -> Result<Arc<Inode>, KernelError> {
    let sb = dir.superblock().ok_or(KernelError::Io)?;
    let private = dir.get_private().ok_or(KernelError::Io)?;
    let dir_data = private
        .as_ref()
        .as_any()
        .downcast_ref::<RamfsInodeData>()
        .ok_or(KernelError::Io)?;
    if dir_data.children.read().contains_key(name) {
        return Err(KernelError::AlreadyExists);
    }
    let inode = new_inode(&sb, kind, mode, uid, gid, time)?;
    dir_data
        .children
        .write()
        .insert(FileName::from(name), inode.clone());
    Ok(inode)
}

/// `add_new` under the dentry `parent`, with the new child's dentry
fn add_dentry(
    parent: &Arc<Dentry>,
    name: &[u8],
    kind: Kind,
    mode: InodeMode,
    uid: Uid,
    gid: Gid,
    time: Timespec,
) -> Result<Arc<Dentry>, KernelError> {
    let dir = parent.get_inode().ok_or(KernelError::NotFound)?;
    let inode = add_new(&dir, name, kind, mode, uid, gid, time)?;
    Dentry::alloc(parent, name, Some(inode))
}

/// The root's mode from ramfs options (Linux ramfs_parse_param):
/// `mode=` in octal (default 0755, EINVAL if not octal); other options
/// are ignored, as Linux ramfs does
fn root_mode(opts: &[u8]) -> Result<u16, KernelError> {
    let mut mode = 0o755;
    for o in opts.split(|&c| c == b',') {
        if let Some(v) = o.strip_prefix(b"mode=") {
            mode = parse_octal(v).ok_or(KernelError::InvalidArgument)? & 0o7777;
        }
    }
    Ok(mode)
}

/// An octal number (mount option values)
pub(crate) fn parse_octal(v: &[u8]) -> Option<u16> {
    if v.is_empty() {
        return None;
    }
    v.iter().try_fold(0u16, |n, &c| match c {
        b'0'..=b'7' => n.checked_mul(8)?.checked_add(u16::from(c - b'0')),
        _ => None,
    })
}

/// Create a directory in ramfs with default ownership (root:root, mode 0755)
pub fn ramfs_create_dir(parent: &Arc<Dentry>, name: &[u8]) -> Result<Arc<Dentry>, KernelError> {
    let mode = InodeMode::directory(0o755);
    add_dentry(parent, name, Kind::Dir, mode, 0, 0, current_time())
}

/// Create a file in ramfs with initial content, ownership, and explicit timestamp
pub fn ramfs_create_file_with_timestamp(
    parent: &Arc<Dentry>,
    name: &[u8],
    content: &[u8],
    mode: InodeMode,
    uid: Uid,
    gid: Gid,
    mtime: Timespec,
) -> Result<Arc<Dentry>, KernelError> {
    let dir = parent.get_inode().ok_or(KernelError::NotFound)?;
    let private = dir.get_private().ok_or(KernelError::Io)?;
    let dir_data = private
        .as_ref()
        .as_any()
        .downcast_ref::<RamfsInodeData>()
        .ok_or(KernelError::Io)?;
    if dir_data.children.read().contains_key(name) {
        return Err(KernelError::AlreadyExists);
    }
    // Filled before it is entered: a failure leaves no partial file
    let sb = dir.superblock().ok_or(KernelError::Io)?;
    let inode = new_inode(&sb, Kind::File, mode, uid, gid, mtime)?;
    fill_pages(&inode, content)?;
    inode.set_size(content.len() as u64);
    dir_data
        .children
        .write()
        .insert(FileName::from(name), inode.clone());
    Dentry::alloc(parent, name, Some(inode))
}

/// Write `content` at offset 0 of a ramfs file's pages
fn fill_pages(inode: &Inode, content: &[u8]) -> Result<(), KernelError> {
    let n = filemap::perform_write(inode, content, 0).map_err(page_err)?;
    if n < content.len() {
        return Err(KernelError::NoSpace);
    }
    Ok(())
}

/// Give an existing (empty) ramfs regular file `content`: the body a
/// hard-linked initramfs entry brings after its first name was made
pub fn ramfs_fill_file(inode: &Inode, content: &[u8]) -> Result<(), KernelError> {
    let private = inode.get_private().ok_or(KernelError::Io)?;
    let data = private
        .as_ref()
        .as_any()
        .downcast_ref::<RamfsInodeData>()
        .ok_or(KernelError::Io)?;
    if data.symlink_target.is_some() || inode.mode().is_dir() {
        return Err(KernelError::InvalidArgument);
    }
    fill_pages(inode, content)?;
    inode.set_size(content.len() as u64);
    Ok(())
}

/// Create a directory in ramfs with ownership and explicit timestamp
pub fn ramfs_create_dir_with_timestamp(
    parent: &Arc<Dentry>,
    name: &[u8],
    mode: InodeMode,
    uid: Uid,
    gid: Gid,
    mtime: Timespec,
) -> Result<Arc<Dentry>, KernelError> {
    add_dentry(parent, name, Kind::Dir, mode, uid, gid, mtime)
}

/// Create nested directory path in ramfs with specified ownership and timestamp.
pub fn ramfs_mkpath_with_timestamp(
    root: &Arc<Dentry>,
    path: &[u8],
    uid: Uid,
    gid: Gid,
    mtime: Timespec,
) -> Result<Arc<Dentry>, KernelError> {
    let mut current = root.clone();

    for component in path.split(|&c| c == b'/').filter(|s| !s.is_empty()) {
        // An existing component, found by the file system (the dcache
        // may hold a negative dentry or none): must be a directory
        if let Ok(child) = super::namei::lookup_one(&current, component) {
            if child.get_inode().is_some_and(|i| !i.mode().is_dir()) {
                return Err(KernelError::NotDirectory);
            }
            current = child;
        } else {
            // Create the directory with specified ownership and timestamp
            current = ramfs_create_dir_with_timestamp(
                &current,
                component,
                InodeMode::directory(0o755),
                uid,
                gid,
                mtime,
            )?;
        }
    }

    Ok(current)
}

/// Create a symlink in ramfs with ownership and explicit timestamp
pub fn ramfs_create_symlink_with_timestamp(
    parent: &Arc<Dentry>,
    name: &[u8],
    target: &[u8],
    uid: Uid,
    gid: Gid,
    mtime: Timespec,
) -> Result<Arc<Dentry>, KernelError> {
    let kind = Kind::Symlink(FileName::from(target));
    add_dentry(parent, name, kind, InodeMode::symlink(), uid, gid, mtime)
}

/// Create the block device node `name` (device `rdev`, permissions
/// `mode`, owned by root) in `parent`
pub fn ramfs_create_blkdev(
    parent: &Arc<Dentry>,
    name: &[u8],
    rdev: DevId,
    mode: u16,
) -> Result<Arc<Dentry>, KernelError> {
    let mode = InodeMode::blockdev(mode);
    add_dentry(parent, name, Kind::Dev(rdev), mode, 0, 0, current_time())
}

/// Create the character device node `name` (device `rdev`, permissions
/// `mode`, owned by root) in `parent`
pub fn ramfs_create_chrdev(
    parent: &Arc<Dentry>,
    name: &[u8],
    rdev: DevId,
    mode: u16,
) -> Result<Arc<Dentry>, KernelError> {
    let mode = InodeMode::chardev(mode);
    add_dentry(parent, name, Kind::Dev(rdev), mode, 0, 0, current_time())
}

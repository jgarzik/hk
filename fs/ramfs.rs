//! Ramfs - simple in-memory filesystem
//!
//! Ramfs stores file contents entirely in memory. It serves as the
//! default root filesystem at boot.
//!
//! ## Locking Model
//!
//! Directory operations (create, mkdir, unlink, rmdir, symlink, link, rename)
//! are serialized by the VFS layer via `inode_lock()`/`inode_unlock()` on the
//! parent directory's inode. For rename operations involving two directories,
//! VFS uses `lock_rename()`/`unlock_rename()` with proper ancestor-first ordering.
//!
//! The `RamfsInodeData.children` RwLock is still used for interior mutability
//! (required for `Sync`), but complex lock ordering is unnecessary since VFS
//! guarantees no concurrent directory modifications.
//!
//! File data (`RamfsInodeData.data`) uses RwLock independently for concurrent
//! read access and exclusive write access during file I/O.

use alloc::collections::BTreeMap;
use alloc::string::String;

use super::name::FileName;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use crate::sync::spin::RwLock;

use crate::mm::filemap::{self, Aops};

use super::KernelError;
use super::dentry::Dentry;
use super::file::{DirContext, DirEntry, File, FileOps, RwFlags};
use super::inode::{AsAny, DevId, FileType, Inode, InodeData, InodeMode, InodeOps, Timespec};
use super::iov_iter::{IovDest, IovSource};
use super::superblock::{
    FileSystemType, RAMFS_MAGIC, StatFs, SuperBlock, SuperBlockData, SuperOps,
};
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

/// Page-cache errors of ramfs writes: no memory for a new page is
/// ENOSPC (like a full tmpfs; the frame reserve is kept for the kernel);
/// a fault on the caller's buffer stays EFAULT
fn page_err(e: KernelError) -> KernelError {
    match e {
        KernelError::OutOfMemory | KernelError::NoSpace => KernelError::NoSpace,
        KernelError::BadAddress => KernelError::BadAddress,
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

/// A new regular file's mapping: ramfs operations, never evicted (the
/// cache is the only copy; Linux ramfs mapping_set_unevictable)
fn file_mapping(inode: &Inode) {
    inode.i_data.set_aops(&RAMFS_AOPS);
    inode.i_data.set_flags(filemap::AS_UNEVICTABLE);
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
    pub children: RwLock<Children>,

    /// Symlink target (symlinks only - stored inline, not in page cache)
    /// Symlinks are typically small, so inline storage is more efficient.
    pub symlink_target: Option<FileName>,

    /// Extended attributes (name -> value)
    pub xattrs: RwLock<BTreeMap<String, Vec<u8>>>,
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

impl Default for Children {
    fn default() -> Self {
        Self::new()
    }
}

impl RamfsInodeData {
    /// Create empty file data (the data lives in the inode's mapping)
    pub fn new_file() -> Self {
        Self {
            children: RwLock::new(Children::new()),
            symlink_target: None,
            xattrs: RwLock::new(BTreeMap::new()),
        }
    }

    /// Create directory data
    pub fn new_dir() -> Self {
        Self {
            children: RwLock::new(Children::new()),
            symlink_target: None,
            xattrs: RwLock::new(BTreeMap::new()),
        }
    }

    /// Create symlink data (target stored inline)
    pub fn new_symlink(target: FileName) -> Self {
        Self {
            children: RwLock::new(Children::new()),
            symlink_target: Some(target),
            xattrs: RwLock::new(BTreeMap::new()),
        }
    }
}

impl AsAny for RamfsInodeData {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

impl InodeData for RamfsInodeData {}

/// Ramfs superblock private data
pub struct RamfsSbData {
    /// Weak reference to superblock for creating inodes
    pub sb: RwLock<Option<Weak<SuperBlock>>>,
}

impl SuperBlockData for RamfsSbData {}

impl AsAny for RamfsSbData {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
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
                old_target.dec_nlink();
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
        let sb = dir.superblock().ok_or(KernelError::Io)?;
        let private = dir.get_private().ok_or(KernelError::Io)?;
        let dir_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(KernelError::Io)?;

        // Check if already exists
        if dir_data.children.read().contains_key(name) {
            return Err(KernelError::AlreadyExists);
        }

        // Owner from the caller's fs ids (inode_init_owner)
        let ino = sb.alloc_ino();
        let (uid, gid, mode) = super::dac::init_owner(dir, mode);

        let new_inode = try_arc(Inode::new(
            ino,
            mode,
            uid,
            gid,
            0,
            current_time(),
            Arc::downgrade(&sb),
            &RAMFS_INODE_OPS,
        ))?;
        new_inode.set_private(try_arc(RamfsInodeData::new_file())?);
        file_mapping(&new_inode);

        // Add to directory
        dir_data
            .children
            .write()
            .insert(FileName::from(name), new_inode.clone());

        Ok(new_inode)
    }

    fn mknod(
        &self,
        dir: &Inode,
        name: &[u8],
        mode: InodeMode,
        rdev: DevId,
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
        let (uid, gid, mode) = super::dac::init_owner(dir, mode);
        let inode = try_arc(Inode::new_device(
            sb.alloc_ino(),
            mode,
            uid,
            gid,
            rdev,
            current_time(),
            Arc::downgrade(&sb),
            &RAMFS_INODE_OPS,
        ))?;
        dir_data
            .children
            .write()
            .insert(FileName::from(name), inode.clone());
        Ok(inode)
    }

    fn mkdir(&self, dir: &Inode, name: &[u8], mode: InodeMode) -> Result<Arc<Inode>, KernelError> {
        let sb = dir.superblock().ok_or(KernelError::Io)?;
        let private = dir.get_private().ok_or(KernelError::Io)?;
        let dir_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(KernelError::Io)?;

        // Check if already exists
        if dir_data.children.read().contains_key(name) {
            return Err(KernelError::AlreadyExists);
        }

        // Owner from the caller's fs ids (inode_init_owner)
        let (uid, gid, mode) = super::dac::init_owner(dir, mode);
        let new_inode = try_arc(Inode::new(
            sb.alloc_ino(),
            mode,
            uid,
            gid,
            0,
            current_time(),
            Arc::downgrade(&sb),
            &RAMFS_INODE_OPS,
        ))?;
        new_inode.set_private(try_arc(RamfsInodeData::new_dir())?);

        // Add to parent directory
        dir_data
            .children
            .write()
            .insert(FileName::from(name), new_inode.clone());

        Ok(new_inode)
    }

    fn maps_cache(&self) -> bool {
        true
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
        let sb = dir.superblock().ok_or(KernelError::Io)?;
        let private = dir.get_private().ok_or(KernelError::Io)?;
        let dir_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(KernelError::Io)?;

        // Check if already exists
        if dir_data.children.read().contains_key(name) {
            return Err(KernelError::AlreadyExists);
        }

        // Create symlink inode (mode = S_IFLNK | 0777)
        let (uid, gid, mode) = super::dac::init_owner(dir, InodeMode::symlink());
        let new_inode = try_arc(Inode::new(
            sb.alloc_ino(),
            mode,
            uid,
            gid,
            target.len() as u64, // size = target length
            current_time(),
            Arc::downgrade(&sb),
            &RAMFS_INODE_OPS,
        ))?;

        // Store target inline (not in page cache)
        new_inode.set_private(try_arc(RamfsInodeData::new_symlink(FileName::from(
            target,
        )))?);

        // Add to directory
        dir_data
            .children
            .write()
            .insert(FileName::from(name), new_inode.clone());

        Ok(new_inode)
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

        // Increment link count on target
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
        filemap::truncate_setsize(inode, length);
        Ok(())
    }

    /// As Linux shmem_fallocate (hk's ramfs stands in for tmpfs, the
    /// Linux rootfs): allocate, KEEP_SIZE and PUNCH_HOLE only; the cache
    /// is the only copy, so a hole reads back as zeroes. On success the
    /// file counts as modified (Linux file_modified).
    fn fallocate(
        &self,
        inode: &Arc<Inode>,
        mode: i32,
        offset: u64,
        len: u64,
    ) -> Result<(), KernelError> {
        use super::misc::falloc_mode::{FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE};
        if mode & !(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE) != 0 {
            return Err(KernelError::OperationNotSupported);
        }
        let end = offset + len;
        if mode & FALLOC_FL_PUNCH_HOLE != 0 {
            // Nothing is cached past i_size: only the part of the hole
            // below it (a hole wholly past EOF changes nothing)
            filemap::punch_range(inode, offset, end.min(inode.get_size()));
        } else {
            inode.newsize_ok(end)?;
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

        // Decrement link count
        // Note: actual file deletion happens when Arc refcount reaches 0
        // and nlink is 0 (handled automatically by Arc drop)
        removed_inode.dec_nlink();

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
                    old_target.dec_nlink();
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

    fn getxattr(&self, inode: &Inode, name: &str, value: &mut [u8]) -> Result<usize, KernelError> {
        // Validate namespace - only user.* is supported for regular files/dirs
        if !name.starts_with("user.") {
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

        let xattrs = ramfs_data.xattrs.read();
        let attr_value = xattrs.get(name).ok_or(KernelError::NoData)?;

        // If value buffer is empty, return the size needed
        if value.is_empty() {
            return Ok(attr_value.len());
        }

        // Check if buffer is large enough
        if value.len() < attr_value.len() {
            return Err(KernelError::Range);
        }

        // Copy value to buffer
        value[..attr_value.len()].copy_from_slice(attr_value);
        Ok(attr_value.len())
    }

    fn setxattr(
        &self,
        inode: &Inode,
        name: &str,
        value: &[u8],
        flags: u32,
    ) -> Result<(), KernelError> {
        // Constants for xattr flags
        const XATTR_CREATE: u32 = 0x1;
        const XATTR_REPLACE: u32 = 0x2;

        // Validate namespace - only user.* is supported for regular files/dirs
        if !name.starts_with("user.") {
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

        let mut xattrs = ramfs_data.xattrs.write();

        let exists = xattrs.contains_key(name);

        // Check XATTR_CREATE flag - fail if exists
        if (flags & XATTR_CREATE) != 0 && exists {
            return Err(KernelError::AlreadyExists);
        }

        // Check XATTR_REPLACE flag - fail if doesn't exist
        if (flags & XATTR_REPLACE) != 0 && !exists {
            return Err(KernelError::NoData);
        }

        // Set the attribute
        xattrs.insert(String::from(name), value.to_vec());
        Ok(())
    }

    fn listxattr(&self, inode: &Inode, list: &mut [u8]) -> Result<usize, KernelError> {
        let private = inode.get_private().ok_or(KernelError::Io)?;
        let ramfs_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(KernelError::Io)?;

        let xattrs = ramfs_data.xattrs.read();

        // Calculate total size needed (each name + null terminator)
        let total_size: usize = xattrs.keys().map(|k| k.len() + 1).sum();

        // If list buffer is empty, return the size needed
        if list.is_empty() {
            return Ok(total_size);
        }

        // Check if buffer is large enough
        if list.len() < total_size {
            return Err(KernelError::Range);
        }

        // Build the null-separated list of attribute names
        let mut offset = 0;
        for name in xattrs.keys() {
            let name_bytes = name.as_bytes();
            list[offset..offset + name_bytes.len()].copy_from_slice(name_bytes);
            offset += name_bytes.len();
            list[offset] = 0; // null terminator
            offset += 1;
        }

        Ok(total_size)
    }

    fn removexattr(&self, inode: &Inode, name: &str) -> Result<(), KernelError> {
        // Validate namespace - only user.* is supported for regular files/dirs
        if !name.starts_with("user.") {
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

        let mut xattrs = ramfs_data.xattrs.write();

        if xattrs.remove(name).is_none() {
            return Err(KernelError::NoData);
        }

        Ok(())
    }
}

/// Static ramfs inode ops
pub static RAMFS_INODE_OPS: RamfsInodeOps = RamfsInodeOps;

/// Ramfs file operations
pub struct RamfsFileOps;

impl FileOps for RamfsFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    /// No poll (Linux ramfs/shmem file and dir operations)
    fn can_poll(&self, _file: &File) -> bool {
        false
    }

    /// Regular files map their data (Linux generic_file_mmap);
    /// directories have no mmap
    fn mmap(&self, file: &File, _shared: bool) -> Result<(), KernelError> {
        match file.get_inode() {
            Some(i) if i.mode().is_dir() => Err(KernelError::NoDevice),
            _ => Ok(()),
        }
    }

    /// Straight from the page cache (Linux filemap_read). No RWF_NOWAIT
    /// (EOPNOTSUPP): like Linux ramfs/tmpfs, no FMODE_NOWAIT.
    fn read_iter(
        &self,
        file: &File,
        to: &mut IovDest<'_>,
        at: Option<u64>,
        flags: RwFlags,
    ) -> Result<usize, KernelError> {
        if flags.nowait {
            return Err(KernelError::OperationNotSupported);
        }
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        let pos = at.unwrap_or_else(|| file.get_pos());
        let n = filemap::read_iter(&inode, to, pos).map_err(read_err)?;
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
        if flags.nowait {
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
pub static RAMFS_FILE_OPS: RamfsFileOps = RamfsFileOps;

/// Ramfs superblock operations
pub struct RamfsSuperOps;

impl SuperOps for RamfsSuperOps {
    fn statfs(&self) -> StatFs {
        StatFs {
            f_type: RAMFS_MAGIC,
            f_bsize: 4096,
            f_blocks: 0, // Unlimited (in-memory filesystem)
            f_bfree: 0,
            f_bavail: 0,
            f_files: 0, // Unlimited inodes
            f_ffree: 0,
            f_namelen: 255,
        }
    }

    fn alloc_inode(
        &self,
        sb: &Arc<SuperBlock>,
        mode: InodeMode,
        i_op: &'static dyn InodeOps,
    ) -> Result<Arc<Inode>, KernelError> {
        let ino = sb.alloc_ino();

        let inode = try_arc(Inode::new(
            ino,
            mode,
            0, // uid: default to root
            0, // gid: default to root
            0,
            current_time(),
            Arc::downgrade(sb),
            i_op,
        ))?;

        // Set up private data based on file type
        if mode.is_dir() {
            inode.set_private(try_arc(RamfsInodeData::new_dir())?);
        } else if mode.is_symlink() {
            // Symlinks need to be set up with a target later
            inode.set_private(try_arc(RamfsInodeData::new_symlink(FileName::default()))?);
        } else {
            inode.set_private(try_arc(RamfsInodeData::new_file())?);
            file_mapping(&inode);
        }

        Ok(inode)
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
    // Create superblock
    let sb = SuperBlock::new(fs_type, &RAMFS_SUPER_OPS, 0)?;

    // Create root inode (directory)
    let root_inode = try_arc(Inode::new(
        sb.alloc_ino(),
        InodeMode::directory(mode),
        0, // uid: root
        0, // gid: root
        0,
        current_time(),
        Arc::downgrade(&sb),
        &RAMFS_INODE_OPS,
    ))?;
    root_inode.set_private(try_arc(RamfsInodeData::new_dir())?);

    // Create root dentry
    let root_dentry = try_arc(Dentry::new_root(root_inode, Arc::downgrade(&sb)))?;

    // Set root in superblock
    sb.set_root(root_dentry);

    Ok(sb)
}

/// Ramfs filesystem type
pub static RAMFS_TYPE: FileSystemType = FileSystemType {
    name: "ramfs",
    fs_flags: 0,
    mount: ramfs_mount,
    mount_dev: None, // Ramfs doesn't use a backing device
    file_ops: &RAMFS_FILE_OPS,
};

/// The rootfs filesystem type (Linux init/do_mounts.c rootfs_fs_type):
/// the initramfs's, mounted on the nullfs root by init_mount_tree. A
/// ramfs under its own name, which mountinfo and statfs callers see;
/// Linux fills it as tmpfs when it has one, hk has only ramfs. Not
/// registered, as Linux: mount(2) cannot name it.
pub static ROOTFS_TYPE: FileSystemType = FileSystemType {
    name: "rootfs",
    fs_flags: 0,
    mount: ramfs_mount,
    mount_dev: None,
    file_ops: &RAMFS_FILE_OPS,
};

use super::inode::{Gid, Uid};

/// Create a directory in ramfs with ownership
pub fn ramfs_create_dir_with_owner(
    parent: &Arc<Dentry>,
    name: &[u8],
    mode: InodeMode,
    uid: Uid,
    gid: Gid,
) -> Result<Arc<Dentry>, KernelError> {
    let parent_inode = parent.get_inode().ok_or(KernelError::NotFound)?;
    let sb = parent_inode.superblock().ok_or(KernelError::Io)?;

    // Get parent's ramfs data
    let private = parent_inode.get_private().ok_or(KernelError::Io)?;
    let parent_data = private
        .as_ref()
        .as_any()
        .downcast_ref::<RamfsInodeData>()
        .ok_or(KernelError::Io)?;

    // Check if already exists
    if parent_data.children.read().contains_key(name) {
        return Err(KernelError::AlreadyExists);
    }

    // Create new directory inode
    let new_inode = try_arc(Inode::new(
        sb.alloc_ino(),
        mode,
        uid,
        gid,
        0,
        current_time(),
        Arc::downgrade(&sb),
        &RAMFS_INODE_OPS,
    ))?;
    new_inode.set_private(try_arc(RamfsInodeData::new_dir())?);

    // Add to parent directory
    parent_data
        .children
        .write()
        .insert(FileName::from(name), new_inode.clone());

    // Create dentry
    let new_dentry = Dentry::alloc(parent, name, Some(new_inode))?;

    Ok(new_dentry)
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
    ramfs_create_dir_with_owner(parent, name, InodeMode::directory(0o755), 0, 0)
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
    let parent_inode = parent.get_inode().ok_or(KernelError::NotFound)?;
    let sb = parent_inode.superblock().ok_or(KernelError::Io)?;

    // Get parent's ramfs data
    let private = parent_inode.get_private().ok_or(KernelError::Io)?;
    let parent_data = private
        .as_ref()
        .as_any()
        .downcast_ref::<RamfsInodeData>()
        .ok_or(KernelError::Io)?;

    // Check if already exists
    if parent_data.children.read().contains_key(name) {
        return Err(KernelError::AlreadyExists);
    }

    // Create new file inode with content and explicit timestamp
    let ino = sb.alloc_ino();

    let new_inode = try_arc(Inode::new(
        ino,
        mode,
        uid,
        gid,
        content.len() as u64,
        mtime,
        Arc::downgrade(&sb),
        &RAMFS_INODE_OPS,
    ))?;
    new_inode.set_private(try_arc(RamfsInodeData::new_file())?);
    file_mapping(&new_inode);
    fill_pages(&new_inode, content)?;

    // Add to parent directory
    parent_data
        .children
        .write()
        .insert(FileName::from(name), new_inode.clone());

    // Create dentry
    let new_dentry = Dentry::alloc(parent, name, Some(new_inode))?;

    Ok(new_dentry)
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
    let parent_inode = parent.get_inode().ok_or(KernelError::NotFound)?;
    let sb = parent_inode.superblock().ok_or(KernelError::Io)?;

    // Get parent's ramfs data
    let private = parent_inode.get_private().ok_or(KernelError::Io)?;
    let parent_data = private
        .as_ref()
        .as_any()
        .downcast_ref::<RamfsInodeData>()
        .ok_or(KernelError::Io)?;

    // Check if already exists
    if parent_data.children.read().contains_key(name) {
        return Err(KernelError::AlreadyExists);
    }

    // Create new directory inode with explicit timestamp
    let new_inode = try_arc(Inode::new(
        sb.alloc_ino(),
        mode,
        uid,
        gid,
        0,
        mtime,
        Arc::downgrade(&sb),
        &RAMFS_INODE_OPS,
    ))?;
    new_inode.set_private(try_arc(RamfsInodeData::new_dir())?);

    // Add to parent directory
    parent_data
        .children
        .write()
        .insert(FileName::from(name), new_inode.clone());

    // Create dentry
    let new_dentry = Dentry::alloc(parent, name, Some(new_inode))?;

    Ok(new_dentry)
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
    let parent_inode = parent.get_inode().ok_or(KernelError::NotFound)?;
    let sb = parent_inode.superblock().ok_or(KernelError::Io)?;

    // Get parent's ramfs data
    let private = parent_inode.get_private().ok_or(KernelError::Io)?;
    let parent_data = private
        .as_ref()
        .as_any()
        .downcast_ref::<RamfsInodeData>()
        .ok_or(KernelError::Io)?;

    // Check if already exists
    if parent_data.children.read().contains_key(name) {
        return Err(KernelError::AlreadyExists);
    }

    // Create symlink inode (mode = S_IFLNK | 0777)
    let new_inode = try_arc(Inode::new(
        sb.alloc_ino(),
        InodeMode::symlink(),
        uid,
        gid,
        target.len() as u64, // size = target length
        mtime,
        Arc::downgrade(&sb),
        &RAMFS_INODE_OPS,
    ))?;

    // Store target inline (not in page cache)
    new_inode.set_private(try_arc(RamfsInodeData::new_symlink(FileName::from(
        target,
    )))?);

    // Add to parent directory
    parent_data
        .children
        .write()
        .insert(FileName::from(name), new_inode.clone());

    // Create dentry
    let new_dentry = Dentry::alloc(parent, name, Some(new_inode))?;

    Ok(new_dentry)
}

/// Create a block device node in ramfs
///
/// Creates a block device special file in the given parent directory.
///
/// # Arguments
/// * `parent` - Parent directory dentry
/// * `name` - Name of the device node
/// * `rdev` - Device ID (major/minor)
/// * `mode` - Permission bits (e.g., 0o660)
///
/// # Returns
/// The dentry of the created block device node on success.
pub fn ramfs_create_blkdev(
    parent: &Arc<Dentry>,
    name: &[u8],
    rdev: DevId,
    mode: u16,
) -> Result<Arc<Dentry>, KernelError> {
    let parent_inode = parent.get_inode().ok_or(KernelError::NotFound)?;
    let sb = parent_inode.superblock().ok_or(KernelError::Io)?;

    // Get parent's ramfs data
    let private = parent_inode.get_private().ok_or(KernelError::Io)?;
    let parent_data = private
        .as_ref()
        .as_any()
        .downcast_ref::<RamfsInodeData>()
        .ok_or(KernelError::Io)?;

    // Check if already exists
    if parent_data.children.read().contains_key(name) {
        return Err(KernelError::AlreadyExists);
    }

    // Create new block device inode
    let new_inode = try_arc(Inode::new_device(
        sb.alloc_ino(),
        InodeMode::blockdev(mode),
        0, // uid = root
        0, // gid = root
        rdev,
        current_time(),
        Arc::downgrade(&sb),
        &RAMFS_INODE_OPS,
    ))?;
    // Block devices don't need RamfsInodeData - they use the block layer

    // Add to parent directory
    parent_data
        .children
        .write()
        .insert(FileName::from(name), new_inode.clone());

    // Create dentry
    let new_dentry = Dentry::alloc(parent, name, Some(new_inode))?;

    Ok(new_dentry)
}

/// Create a character device node in ramfs
///
/// Creates a character device special file in the given parent directory.
///
/// # Arguments
/// * `parent` - Parent directory dentry
/// * `name` - Name of the device node
/// * `rdev` - Device ID (major/minor)
/// * `mode` - Permission bits (e.g., 0o666)
///
/// # Returns
/// The dentry of the created character device node on success.
pub fn ramfs_create_chrdev(
    parent: &Arc<Dentry>,
    name: &[u8],
    rdev: DevId,
    mode: u16,
) -> Result<Arc<Dentry>, KernelError> {
    let parent_inode = parent.get_inode().ok_or(KernelError::NotFound)?;
    let sb = parent_inode.superblock().ok_or(KernelError::Io)?;

    // Get parent's ramfs data
    let private = parent_inode.get_private().ok_or(KernelError::Io)?;
    let parent_data = private
        .as_ref()
        .as_any()
        .downcast_ref::<RamfsInodeData>()
        .ok_or(KernelError::Io)?;

    // Check if already exists
    if parent_data.children.read().contains_key(name) {
        return Err(KernelError::AlreadyExists);
    }

    // Create new character device inode
    let new_inode = try_arc(Inode::new_device(
        sb.alloc_ino(),
        InodeMode::chardev(mode),
        0, // uid = root
        0, // gid = root
        rdev,
        current_time(),
        Arc::downgrade(&sb),
        &RAMFS_INODE_OPS,
    ))?;
    // Character devices don't need RamfsInodeData - they use the chardev layer

    // Add to parent directory
    parent_data
        .children
        .write()
        .insert(FileName::from(name), new_inode.clone());

    // Create dentry
    let new_dentry = Dentry::alloc(parent, name, Some(new_inode))?;

    Ok(new_dentry)
}

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
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use ::core::cmp::min;
use spin::RwLock;

use crate::mm::page_cache::{AddressSpaceOps, FileId, PAGE_SIZE};

use super::FsError;
use super::dentry::Dentry;
use super::file::{DirEntry, File, FileOps, RwFlags};
use super::inode::{AsAny, DevId, FileType, Inode, InodeData, InodeMode, InodeOps, Timespec};
use super::superblock::{FileSystemType, SuperBlock, SuperBlockData, SuperOps};

// ============================================================================
// Ramfs Address Space Operations
// ============================================================================

/// Ramfs address space operations for page cache integration.
///
/// Ramfs stores file data in the page cache with `unevictable = true`.
/// - `readpage`: Returns zeros for new pages (ramfs has no backing store)
/// - `writepage`: Returns error - should never be called since pages are unevictable
pub struct RamfsAddressSpaceOps;

impl AddressSpaceOps for RamfsAddressSpaceOps {
    fn readpage(&self, _file_id: FileId, _page_offset: u64, buf: &mut [u8]) -> Result<usize, i32> {
        // New pages in ramfs start as zeros
        buf.fill(0);
        Ok(buf.len())
    }

    fn writepage(&self, _file_id: FileId, _page_offset: u64, _buf: &[u8]) -> Result<usize, i32> {
        // Ramfs pages are unevictable - writepage should never be called
        Err(-5) // EIO
    }
}

/// Global ramfs address space ops instance
pub static RAMFS_AOPS: RamfsAddressSpaceOps = RamfsAddressSpaceOps;

/// Get current timestamp for new inodes
/// Returns current wall-clock time from TIMEKEEPER if available, otherwise zero
fn current_time() -> Timespec {
    use crate::time::TIMEKEEPER;
    TIMEKEEPER.current_time()
}

/// Ramfs inode private data
pub struct RamfsInodeData {
    /// FileId for page cache lookup (regular files only)
    /// Used to identify this file's pages in the global page cache.
    pub file_id: Option<FileId>,

    /// Children (for directories) - maps name to inode
    pub children: RwLock<BTreeMap<String, Arc<Inode>>>,

    /// Symlink target (symlinks only - stored inline, not in page cache)
    /// Symlinks are typically small, so inline storage is more efficient.
    pub symlink_target: Option<String>,
}

/// Generate a FileId for a ramfs inode
///
/// The FileId is derived from the superblock device ID and inode number,
/// ensuring uniqueness across different ramfs mounts.
pub fn ramfs_file_id(sb: &SuperBlock, ino: u64) -> FileId {
    // Use high bit to distinguish ramfs files from other FileIds
    // Format: 0x4000_0000_0000_0000 | (dev_id << 32) | (ino & 0xFFFFFFFF)
    let dev_id = sb.dev_id;
    FileId::new(0x4000_0000_0000_0000 | (dev_id << 32) | (ino & 0xFFFF_FFFF))
}

impl RamfsInodeData {
    /// Create empty file data with the given FileId
    pub fn new_file(file_id: FileId) -> Self {
        Self {
            file_id: Some(file_id),
            children: RwLock::new(BTreeMap::new()),
            symlink_target: None,
        }
    }

    /// Create directory data (no FileId, no page cache)
    pub fn new_dir() -> Self {
        Self {
            file_id: None,
            children: RwLock::new(BTreeMap::new()),
            symlink_target: None,
        }
    }

    /// Create symlink data (target stored inline)
    pub fn new_symlink(target: String) -> Self {
        Self {
            file_id: None,
            children: RwLock::new(BTreeMap::new()),
            symlink_target: Some(target),
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
        old_children: &mut BTreeMap<String, Arc<Inode>>,
        old_name: &str,
        new_children: &mut BTreeMap<String, Arc<Inode>>,
        new_name: &str,
        flags: u32,
    ) -> Result<(), FsError> {
        const RENAME_NOREPLACE: u32 = 1;
        const RENAME_EXCHANGE: u32 = 2;

        let noreplace = flags & RENAME_NOREPLACE != 0;
        let exchange = flags & RENAME_EXCHANGE != 0;

        // Get source inode
        let source_inode = old_children
            .get(old_name)
            .cloned()
            .ok_or(FsError::NotFound)?;

        if exchange {
            // Exchange requires both to exist
            let target_inode = new_children
                .get(new_name)
                .cloned()
                .ok_or(FsError::NotFound)?;

            // Move source to new location, target to old location
            old_children.remove(old_name);
            new_children.remove(new_name);
            old_children.insert(String::from(old_name), target_inode);
            new_children.insert(String::from(new_name), source_inode);
        } else {
            // Check if target exists
            let target_exists = new_children.contains_key(new_name);

            if noreplace && target_exists {
                return Err(FsError::AlreadyExists);
            }

            // Remove source
            old_children.remove(old_name);

            // Handle any existing target
            if let Some(old_target) = new_children.remove(new_name) {
                // If replacing a directory, it must be empty
                if old_target.mode().is_dir() {
                    let target_private = old_target.get_private().ok_or(FsError::IoError)?;
                    let target_data = target_private
                        .as_ref()
                        .as_any()
                        .downcast_ref::<RamfsInodeData>()
                        .ok_or(FsError::IoError)?;
                    if !target_data.children.read().is_empty() {
                        // Restore source and target
                        old_children.insert(String::from(old_name), source_inode);
                        new_children.insert(String::from(new_name), old_target);
                        return Err(FsError::DirectoryNotEmpty);
                    }
                }
                old_target.dec_nlink();
            }

            // Insert at new location
            new_children.insert(String::from(new_name), source_inode);
        }

        Ok(())
    }
}

impl InodeOps for RamfsInodeOps {
    fn lookup(&self, dir: &Inode, name: &str) -> Result<Arc<Inode>, FsError> {
        let private = dir.get_private().ok_or(FsError::IoError)?;
        let ramfs_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(FsError::IoError)?;

        ramfs_data
            .children
            .read()
            .get(name)
            .cloned()
            .ok_or(FsError::NotFound)
    }

    fn create(&self, dir: &Inode, name: &str, mode: InodeMode) -> Result<Arc<Inode>, FsError> {
        let sb = dir.superblock().ok_or(FsError::IoError)?;
        let private = dir.get_private().ok_or(FsError::IoError)?;
        let dir_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(FsError::IoError)?;

        // Check if already exists
        if dir_data.children.read().contains_key(name) {
            return Err(FsError::AlreadyExists);
        }

        // Create new inode (inherit uid/gid from parent directory for now)
        let ino = sb.alloc_ino();
        let file_id = ramfs_file_id(&sb, ino);

        let new_inode = Arc::new(Inode::new(
            ino,
            mode,
            dir.uid(),
            dir.gid(),
            0,
            current_time(),
            Arc::downgrade(&sb),
            &RAMFS_INODE_OPS,
        ));
        new_inode.set_private(Arc::new(RamfsInodeData::new_file(file_id)));

        // Add to directory
        dir_data
            .children
            .write()
            .insert(String::from(name), new_inode.clone());

        Ok(new_inode)
    }

    fn mkdir(&self, dir: &Inode, name: &str, mode: InodeMode) -> Result<Arc<Inode>, FsError> {
        let sb = dir.superblock().ok_or(FsError::IoError)?;
        let private = dir.get_private().ok_or(FsError::IoError)?;
        let dir_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(FsError::IoError)?;

        // Check if already exists
        if dir_data.children.read().contains_key(name) {
            return Err(FsError::AlreadyExists);
        }

        // Create new directory inode (inherit uid/gid from parent)
        let new_inode = Arc::new(Inode::new(
            sb.alloc_ino(),
            mode,
            dir.uid(),
            dir.gid(),
            0,
            current_time(),
            Arc::downgrade(&sb),
            &RAMFS_INODE_OPS,
        ));
        new_inode.set_private(Arc::new(RamfsInodeData::new_dir()));

        // Add to parent directory
        dir_data
            .children
            .write()
            .insert(String::from(name), new_inode.clone());

        Ok(new_inode)
    }

    fn readpage(&self, inode: &Inode, page_offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        // Ramfs uses page cache via AddressSpaceOps (RAMFS_AOPS).
        // This InodeOps::readpage is deprecated for ramfs - use the page cache directly.
        use crate::frame_alloc::FrameAllocRef;
        use crate::{FRAME_ALLOCATOR, PAGE_CACHE};

        let private = inode.get_private().ok_or(FsError::IoError)?;
        let ramfs_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(FsError::IoError)?;

        let file_id = ramfs_data.file_id.ok_or(FsError::IoError)?;
        let file_size = inode.get_size();

        // Get the page from cache
        let page = {
            let mut cache = PAGE_CACHE.lock();
            let mut frame_alloc = FrameAllocRef(&FRAME_ALLOCATOR);

            let (page, _) = cache
                .find_or_create_page(
                    file_id,
                    page_offset,
                    file_size,
                    &mut frame_alloc,
                    false, // can_writeback
                    true,  // unevictable
                    &RAMFS_AOPS,
                )
                .map_err(|_| FsError::IoError)?;
            page
        };

        // Copy from page to buffer
        let page_size = buf.len();
        unsafe {
            core::ptr::copy_nonoverlapping(page.frame as *const u8, buf.as_mut_ptr(), page_size);
        }

        Ok(page_size)
    }

    fn writepage(&self, inode: &Inode, page_offset: u64, buf: &[u8]) -> Result<usize, FsError> {
        // Ramfs uses page cache via AddressSpaceOps (RAMFS_AOPS).
        // This InodeOps::writepage is deprecated for ramfs - use the page cache directly.
        use crate::frame_alloc::FrameAllocRef;
        use crate::{FRAME_ALLOCATOR, PAGE_CACHE};

        let private = inode.get_private().ok_or(FsError::IoError)?;
        let ramfs_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(FsError::IoError)?;

        let file_id = ramfs_data.file_id.ok_or(FsError::IoError)?;
        let file_size = inode.get_size();
        let page_size = buf.len();

        // Get or create the page
        let page = {
            let mut cache = PAGE_CACHE.lock();
            let mut frame_alloc = FrameAllocRef(&FRAME_ALLOCATOR);

            let (page, _) = cache
                .find_or_create_page(
                    file_id,
                    page_offset,
                    file_size,
                    &mut frame_alloc,
                    false, // can_writeback
                    true,  // unevictable
                    &RAMFS_AOPS,
                )
                .map_err(|_| FsError::IoError)?;
            page
        };

        // Copy from buffer to page
        unsafe {
            core::ptr::copy_nonoverlapping(buf.as_ptr(), page.frame as *mut u8, page_size);
        }
        page.mark_dirty();

        Ok(page_size)
    }

    fn readlink(&self, inode: &Inode) -> Result<String, FsError> {
        // Must be a symlink
        if !inode.mode().is_symlink() {
            return Err(FsError::InvalidArgument);
        }

        let private = inode.get_private().ok_or(FsError::IoError)?;
        let ramfs_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(FsError::IoError)?;

        // Symlink target is stored inline
        ramfs_data
            .symlink_target
            .clone()
            .ok_or(FsError::InvalidArgument)
    }

    fn symlink(&self, dir: &Inode, name: &str, target: &str) -> Result<Arc<Inode>, FsError> {
        let sb = dir.superblock().ok_or(FsError::IoError)?;
        let private = dir.get_private().ok_or(FsError::IoError)?;
        let dir_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(FsError::IoError)?;

        // Check if already exists
        if dir_data.children.read().contains_key(name) {
            return Err(FsError::AlreadyExists);
        }

        // Create symlink inode (mode = S_IFLNK | 0777)
        let new_inode = Arc::new(Inode::new(
            sb.alloc_ino(),
            InodeMode::symlink(),
            dir.uid(),
            dir.gid(),
            target.len() as u64, // size = target length
            current_time(),
            Arc::downgrade(&sb),
            &RAMFS_INODE_OPS,
        ));

        // Store target inline (not in page cache)
        new_inode.set_private(Arc::new(RamfsInodeData::new_symlink(String::from(target))));

        // Add to directory
        dir_data
            .children
            .write()
            .insert(String::from(name), new_inode.clone());

        Ok(new_inode)
    }

    fn link(&self, dir: &Inode, name: &str, target_inode: &Arc<Inode>) -> Result<(), FsError> {
        // Cannot hard link directories
        if target_inode.mode().is_dir() {
            return Err(FsError::PermissionDenied); // EPERM
        }

        let private = dir.get_private().ok_or(FsError::IoError)?;
        let dir_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(FsError::IoError)?;

        // Check if name already exists
        if dir_data.children.read().contains_key(name) {
            return Err(FsError::AlreadyExists);
        }

        // Increment link count on target
        target_inode.inc_nlink();

        // Add new directory entry pointing to existing inode
        dir_data
            .children
            .write()
            .insert(String::from(name), target_inode.clone());

        Ok(())
    }

    fn truncate(&self, inode: &Inode, length: u64) -> Result<(), FsError> {
        use crate::frame_alloc::FrameAllocRef;
        use crate::{FRAME_ALLOCATOR, PAGE_CACHE};

        // Cannot truncate directories
        if inode.mode().is_dir() {
            return Err(FsError::IsADirectory);
        }

        let private = inode.get_private().ok_or(FsError::IoError)?;
        let ramfs_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(FsError::IoError)?;

        let file_id = ramfs_data.file_id.ok_or(FsError::IoError)?;
        let old_size = inode.get_size();

        // If shrinking, free pages beyond the new size
        if length < old_size {
            // Calculate the first page offset that should be freed
            // We need to keep partial pages, so round up
            let from_page_offset = length.div_ceil(PAGE_SIZE as u64);

            let mut cache = PAGE_CACHE.lock();
            let mut frame_alloc = FrameAllocRef(&FRAME_ALLOCATOR);
            cache.truncate_pages(file_id, from_page_offset, &mut frame_alloc);

            // Zero the partial page content beyond the new size
            // (handled by page cache - new reads will see zeros)
        }

        // Update inode size (pages are allocated lazily for extensions)
        inode.set_size(length);

        Ok(())
    }

    fn unlink(&self, dir: &Inode, name: &str) -> Result<(), FsError> {
        let private = dir.get_private().ok_or(FsError::IoError)?;
        let dir_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(FsError::IoError)?;

        // Remove from directory
        let removed_inode = {
            let mut children = dir_data.children.write();
            children.remove(name).ok_or(FsError::NotFound)?
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
        old_name: &str,
        new_dir: &Arc<Inode>,
        new_name: &str,
        flags: u32,
    ) -> Result<(), FsError> {
        // RENAME_NOREPLACE = 1, RENAME_EXCHANGE = 2
        const RENAME_NOREPLACE: u32 = 1;
        const RENAME_EXCHANGE: u32 = 2;

        let noreplace = flags & RENAME_NOREPLACE != 0;
        let exchange = flags & RENAME_EXCHANGE != 0;

        // NOREPLACE and EXCHANGE are mutually exclusive
        if noreplace && exchange {
            return Err(FsError::InvalidArgument);
        }

        // Get old directory's data
        let old_private = old_dir.get_private().ok_or(FsError::IoError)?;
        let old_dir_data = old_private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(FsError::IoError)?;

        // Get new directory's data
        let new_private = new_dir.get_private().ok_or(FsError::IoError)?;
        let new_dir_data = new_private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(FsError::IoError)?;

        // Check if same directory (optimization for simple renames)
        let same_dir = core::ptr::eq(
            old_dir_data as *const RamfsInodeData,
            new_dir_data as *const RamfsInodeData,
        );

        if same_dir {
            // Same directory: just rename the entry
            let mut children = old_dir_data.children.write();

            // Get the source inode
            let source_inode = children.get(old_name).cloned().ok_or(FsError::NotFound)?;

            // Check target exists
            let target_exists = children.contains_key(new_name);

            if exchange {
                // Exchange requires both to exist
                let target_inode = children.get(new_name).cloned().ok_or(FsError::NotFound)?;

                // Swap the entries
                children.insert(String::from(old_name), target_inode);
                children.insert(String::from(new_name), source_inode);
            } else if noreplace && target_exists {
                return Err(FsError::AlreadyExists);
            } else {
                // Remove old entry
                children.remove(old_name);

                // If target exists, handle replacement
                if let Some(old_target) = children.remove(new_name) {
                    // If replacing a directory, it must be empty
                    if old_target.mode().is_dir() {
                        let target_private = old_target.get_private().ok_or(FsError::IoError)?;
                        let target_data = target_private
                            .as_ref()
                            .as_any()
                            .downcast_ref::<RamfsInodeData>()
                            .ok_or(FsError::IoError)?;
                        if !target_data.children.read().is_empty() {
                            // Restore the source
                            children.insert(String::from(old_name), source_inode);
                            return Err(FsError::DirectoryNotEmpty);
                        }
                    }
                    old_target.dec_nlink();
                }

                // Insert at new name
                children.insert(String::from(new_name), source_inode);
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

    fn rmdir(&self, dir: &Inode, name: &str) -> Result<(), FsError> {
        let private = dir.get_private().ok_or(FsError::IoError)?;
        let dir_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(FsError::IoError)?;

        // First, look up the target to check it's a directory and empty
        let target_inode = {
            let children = dir_data.children.read();
            children.get(name).cloned().ok_or(FsError::NotFound)?
        };

        // Must be a directory
        if !target_inode.mode().is_dir() {
            return Err(FsError::NotADirectory);
        }

        // Check if directory is empty
        let target_private = target_inode.get_private().ok_or(FsError::IoError)?;
        let target_data = target_private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(FsError::IoError)?;

        if !target_data.children.read().is_empty() {
            return Err(FsError::DirectoryNotEmpty);
        }

        // Remove from parent directory
        let removed_inode = {
            let mut children = dir_data.children.write();
            children.remove(name).ok_or(FsError::NotFound)?
        };

        // Decrement link count
        removed_inode.dec_nlink();

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

    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize, FsError> {
        use crate::frame_alloc::FrameAllocRef;
        use crate::{FRAME_ALLOCATOR, PAGE_CACHE};

        let inode = file.get_inode().ok_or(FsError::InvalidFile)?;
        let private = inode.get_private().ok_or(FsError::IoError)?;
        let ramfs_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(FsError::IoError)?;

        let file_id = ramfs_data.file_id.ok_or(FsError::IoError)?;
        let file_size = inode.get_size();
        let pos = file.get_pos();

        // EOF check
        if pos >= file_size {
            return Ok(0);
        }

        let available = (file_size - pos) as usize;
        let to_read = min(buf.len(), available);

        if to_read == 0 {
            return Ok(0);
        }

        let mut bytes_read = 0;

        while bytes_read < to_read {
            let current_pos = pos + bytes_read as u64;
            let page_offset = current_pos / PAGE_SIZE as u64;
            let offset_in_page = (current_pos % PAGE_SIZE as u64) as usize;
            let chunk_size = min(PAGE_SIZE - offset_in_page, to_read - bytes_read);

            // Get or create page from cache (unevictable for ramfs)
            let page = {
                let mut cache = PAGE_CACHE.lock();
                let mut frame_alloc = FrameAllocRef(&FRAME_ALLOCATOR);

                let (page, _is_new) = cache
                    .find_or_create_page(
                        file_id,
                        page_offset,
                        file_size,
                        &mut frame_alloc,
                        false, // can_writeback: false for ramfs
                        true,  // unevictable: true for ramfs
                        &RAMFS_AOPS,
                    )
                    .map_err(|_| FsError::IoError)?;
                page
            };

            // Copy data from page to user buffer
            unsafe {
                let src = (page.frame as *const u8).add(offset_in_page);
                core::ptr::copy_nonoverlapping(src, buf[bytes_read..].as_mut_ptr(), chunk_size);
            }

            bytes_read += chunk_size;
        }

        file.advance_pos(bytes_read as u64);
        Ok(bytes_read)
    }

    fn write(&self, file: &File, buf: &[u8]) -> Result<usize, FsError> {
        use crate::frame_alloc::FrameAllocRef;
        use crate::{FRAME_ALLOCATOR, PAGE_CACHE};

        let inode = file.get_inode().ok_or(FsError::InvalidFile)?;
        let private = inode.get_private().ok_or(FsError::IoError)?;
        let ramfs_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(FsError::IoError)?;

        let file_id = ramfs_data.file_id.ok_or(FsError::IoError)?;
        let pos = file.get_pos();

        if buf.is_empty() {
            return Ok(0);
        }

        // Calculate new file size if write extends file
        let new_size = pos + buf.len() as u64;
        let file_size = core::cmp::max(inode.get_size(), new_size);

        let mut bytes_written = 0;

        while bytes_written < buf.len() {
            let current_pos = pos + bytes_written as u64;
            let page_offset = current_pos / PAGE_SIZE as u64;
            let offset_in_page = (current_pos % PAGE_SIZE as u64) as usize;
            let chunk_size = min(PAGE_SIZE - offset_in_page, buf.len() - bytes_written);

            // Get or create page from cache (unevictable for ramfs)
            let page = {
                let mut cache = PAGE_CACHE.lock();
                let mut frame_alloc = FrameAllocRef(&FRAME_ALLOCATOR);

                let (page, _is_new) = cache
                    .find_or_create_page(
                        file_id,
                        page_offset,
                        file_size,
                        &mut frame_alloc,
                        false, // can_writeback: false for ramfs
                        true,  // unevictable: true for ramfs
                        &RAMFS_AOPS,
                    )
                    .map_err(|_| FsError::IoError)?;
                page
            };

            // Copy data from user buffer to page
            unsafe {
                let dst = (page.frame as *mut u8).add(offset_in_page);
                core::ptr::copy_nonoverlapping(buf[bytes_written..].as_ptr(), dst, chunk_size);
            }

            // Mark page as dirty (needed for proper reference counting)
            page.mark_dirty();

            bytes_written += chunk_size;
        }

        // Update file size if it grew
        if new_size > inode.get_size() {
            inode.set_size(new_size);
        }

        file.advance_pos(bytes_written as u64);
        Ok(bytes_written)
    }

    fn pread(&self, file: &File, buf: &mut [u8], offset: u64) -> Result<usize, FsError> {
        use crate::frame_alloc::FrameAllocRef;
        use crate::{FRAME_ALLOCATOR, PAGE_CACHE};

        let inode = file.get_inode().ok_or(FsError::InvalidFile)?;
        let private = inode.get_private().ok_or(FsError::IoError)?;
        let ramfs_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(FsError::IoError)?;

        let file_id = ramfs_data.file_id.ok_or(FsError::IoError)?;
        let file_size = inode.get_size();
        let pos = offset;

        // EOF check
        if pos >= file_size {
            return Ok(0);
        }

        let available = (file_size - pos) as usize;
        let to_read = min(buf.len(), available);

        if to_read == 0 {
            return Ok(0);
        }

        let mut bytes_read = 0;

        while bytes_read < to_read {
            let current_pos = pos + bytes_read as u64;
            let page_offset = current_pos / PAGE_SIZE as u64;
            let offset_in_page = (current_pos % PAGE_SIZE as u64) as usize;
            let chunk_size = min(PAGE_SIZE - offset_in_page, to_read - bytes_read);

            // Get or create page from cache (unevictable for ramfs)
            let page = {
                let mut cache = PAGE_CACHE.lock();
                let mut frame_alloc = FrameAllocRef(&FRAME_ALLOCATOR);

                let (page, _is_new) = cache
                    .find_or_create_page(
                        file_id,
                        page_offset,
                        file_size,
                        &mut frame_alloc,
                        false, // can_writeback: false for ramfs
                        true,  // unevictable: true for ramfs
                        &RAMFS_AOPS,
                    )
                    .map_err(|_| FsError::IoError)?;
                page
            };

            // Copy data from page to user buffer
            unsafe {
                let src = (page.frame as *const u8).add(offset_in_page);
                core::ptr::copy_nonoverlapping(src, buf[bytes_read..].as_mut_ptr(), chunk_size);
            }

            bytes_read += chunk_size;
        }

        // NOTE: Unlike read(), we do NOT advance file position
        Ok(bytes_read)
    }

    fn pwrite(&self, file: &File, buf: &[u8], offset: u64) -> Result<usize, FsError> {
        use crate::frame_alloc::FrameAllocRef;
        use crate::{FRAME_ALLOCATOR, PAGE_CACHE};

        let inode = file.get_inode().ok_or(FsError::InvalidFile)?;
        let private = inode.get_private().ok_or(FsError::IoError)?;
        let ramfs_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(FsError::IoError)?;

        let file_id = ramfs_data.file_id.ok_or(FsError::IoError)?;
        let pos = offset;

        if buf.is_empty() {
            return Ok(0);
        }

        // Calculate new file size if write extends file
        let new_size = pos + buf.len() as u64;
        let file_size = core::cmp::max(inode.get_size(), new_size);

        let mut bytes_written = 0;

        while bytes_written < buf.len() {
            let current_pos = pos + bytes_written as u64;
            let page_offset = current_pos / PAGE_SIZE as u64;
            let offset_in_page = (current_pos % PAGE_SIZE as u64) as usize;
            let chunk_size = min(PAGE_SIZE - offset_in_page, buf.len() - bytes_written);

            // Get or create page from cache (unevictable for ramfs)
            let page = {
                let mut cache = PAGE_CACHE.lock();
                let mut frame_alloc = FrameAllocRef(&FRAME_ALLOCATOR);

                let (page, _is_new) = cache
                    .find_or_create_page(
                        file_id,
                        page_offset,
                        file_size,
                        &mut frame_alloc,
                        false, // can_writeback: false for ramfs
                        true,  // unevictable: true for ramfs
                        &RAMFS_AOPS,
                    )
                    .map_err(|_| FsError::IoError)?;
                page
            };

            // Copy data from user buffer to page
            unsafe {
                let dst = (page.frame as *mut u8).add(offset_in_page);
                core::ptr::copy_nonoverlapping(buf[bytes_written..].as_ptr(), dst, chunk_size);
            }

            // Mark page as dirty (needed for proper reference counting)
            page.mark_dirty();

            bytes_written += chunk_size;
        }

        // Update file size if it grew
        if new_size > inode.get_size() {
            inode.set_size(new_size);
        }

        // NOTE: Unlike write(), we do NOT advance file position
        Ok(bytes_written)
    }

    fn readdir(
        &self,
        file: &File,
        callback: &mut dyn FnMut(DirEntry) -> bool,
    ) -> Result<(), FsError> {
        let inode = file.get_inode().ok_or(FsError::InvalidFile)?;

        if !inode.mode().is_dir() {
            return Err(FsError::NotADirectory);
        }

        let private = inode.get_private().ok_or(FsError::IoError)?;
        let ramfs_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<RamfsInodeData>()
            .ok_or(FsError::IoError)?;

        // First, emit "." and ".."
        let should_continue = callback(DirEntry {
            ino: inode.ino,
            file_type: FileType::Directory,
            name: Vec::from(b"."),
        });

        if !should_continue {
            return Ok(());
        }

        // Parent directory (use same inode for root)
        let parent_ino = file
            .dentry
            .get_parent()
            .and_then(|p| p.get_inode())
            .map(|i| i.ino)
            .unwrap_or(inode.ino);

        let should_continue = callback(DirEntry {
            ino: parent_ino,
            file_type: FileType::Directory,
            name: Vec::from(b".."),
        });

        if !should_continue {
            return Ok(());
        }

        // Now emit children
        let children = ramfs_data.children.read();
        for (name, child_inode) in children.iter() {
            let file_type = child_inode.mode().file_type().unwrap_or(FileType::Regular);

            let should_continue = callback(DirEntry {
                ino: child_inode.ino,
                file_type,
                name: name.as_bytes().to_vec(),
            });

            if !should_continue {
                break;
            }
        }

        Ok(())
    }

    // RWF_NOWAIT support: ramfs is in-memory and never blocks

    fn read_with_flags(
        &self,
        file: &File,
        buf: &mut [u8],
        _flags: RwFlags,
    ) -> Result<usize, FsError> {
        // In-memory filesystem never blocks
        self.read(file, buf)
    }

    fn pread_with_flags(
        &self,
        file: &File,
        buf: &mut [u8],
        offset: u64,
        _flags: RwFlags,
    ) -> Result<usize, FsError> {
        // In-memory filesystem never blocks
        self.pread(file, buf, offset)
    }

    fn write_with_flags(
        &self,
        file: &File,
        buf: &[u8],
        _flags: RwFlags,
    ) -> Result<usize, FsError> {
        // In-memory filesystem never blocks
        self.write(file, buf)
    }

    fn pwrite_with_flags(
        &self,
        file: &File,
        buf: &[u8],
        offset: u64,
        _flags: RwFlags,
    ) -> Result<usize, FsError> {
        // In-memory filesystem never blocks
        self.pwrite(file, buf, offset)
    }
}

/// Static ramfs file ops
pub static RAMFS_FILE_OPS: RamfsFileOps = RamfsFileOps;

/// Ramfs superblock operations
pub struct RamfsSuperOps;

impl SuperOps for RamfsSuperOps {
    fn alloc_inode(
        &self,
        sb: &Arc<SuperBlock>,
        mode: InodeMode,
        i_op: &'static dyn InodeOps,
    ) -> Result<Arc<Inode>, FsError> {
        let ino = sb.alloc_ino();

        let inode = Arc::new(Inode::new(
            ino,
            mode,
            0, // uid: default to root
            0, // gid: default to root
            0,
            current_time(),
            Arc::downgrade(sb),
            i_op,
        ));

        // Set up private data based on file type
        if mode.is_dir() {
            inode.set_private(Arc::new(RamfsInodeData::new_dir()));
        } else if mode.is_symlink() {
            // Symlinks need to be set up with a target later
            inode.set_private(Arc::new(RamfsInodeData::new_symlink(String::new())));
        } else {
            // Regular file - needs FileId for page cache
            let file_id = ramfs_file_id(sb, ino);
            inode.set_private(Arc::new(RamfsInodeData::new_file(file_id)));
        }

        Ok(inode)
    }
}

/// Static ramfs super ops
pub static RAMFS_SUPER_OPS: RamfsSuperOps = RamfsSuperOps;

/// Mount function for ramfs
fn ramfs_mount(fs_type: &'static FileSystemType) -> Result<Arc<SuperBlock>, FsError> {
    // Create superblock
    let sb = SuperBlock::new(fs_type, &RAMFS_SUPER_OPS, 0);

    // Create root inode (directory)
    let root_inode = Arc::new(Inode::new(
        sb.alloc_ino(),
        InodeMode::directory(0o755),
        0, // uid: root
        0, // gid: root
        0,
        current_time(),
        Arc::downgrade(&sb),
        &RAMFS_INODE_OPS,
    ));
    root_inode.set_private(Arc::new(RamfsInodeData::new_dir()));

    // Create root dentry
    let root_dentry = Arc::new(Dentry::new_root(root_inode, Arc::downgrade(&sb)));

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

use super::inode::{Gid, Uid};

/// Create a directory in ramfs with ownership
pub fn ramfs_create_dir_with_owner(
    parent: &Arc<Dentry>,
    name: &str,
    mode: InodeMode,
    uid: Uid,
    gid: Gid,
) -> Result<Arc<Dentry>, FsError> {
    let parent_inode = parent.get_inode().ok_or(FsError::NotFound)?;
    let sb = parent_inode.superblock().ok_or(FsError::IoError)?;

    // Get parent's ramfs data
    let private = parent_inode.get_private().ok_or(FsError::IoError)?;
    let parent_data = private
        .as_ref()
        .as_any()
        .downcast_ref::<RamfsInodeData>()
        .ok_or(FsError::IoError)?;

    // Check if already exists
    if parent_data.children.read().contains_key(name) {
        return Err(FsError::AlreadyExists);
    }

    // Create new directory inode
    let new_inode = Arc::new(Inode::new(
        sb.alloc_ino(),
        mode,
        uid,
        gid,
        0,
        current_time(),
        Arc::downgrade(&sb),
        &RAMFS_INODE_OPS,
    ));
    new_inode.set_private(Arc::new(RamfsInodeData::new_dir()));

    // Add to parent directory
    parent_data
        .children
        .write()
        .insert(String::from(name), new_inode.clone());

    // Create dentry
    let new_dentry = Arc::new(Dentry::new(
        String::from(name),
        Some(new_inode),
        Arc::downgrade(&sb),
    ));
    new_dentry.set_parent(parent);
    parent.add_child(new_dentry.clone());

    Ok(new_dentry)
}

/// Create a directory in ramfs with default ownership (root:root, mode 0755)
pub fn ramfs_create_dir(parent: &Arc<Dentry>, name: &str) -> Result<Arc<Dentry>, FsError> {
    ramfs_create_dir_with_owner(parent, name, InodeMode::directory(0o755), 0, 0)
}

/// Create a file in ramfs with initial content, ownership, and explicit timestamp
pub fn ramfs_create_file_with_timestamp(
    parent: &Arc<Dentry>,
    name: &str,
    content: &[u8],
    mode: InodeMode,
    uid: Uid,
    gid: Gid,
    mtime: Timespec,
) -> Result<Arc<Dentry>, FsError> {
    use crate::frame_alloc::FrameAllocRef;
    use crate::{FRAME_ALLOCATOR, PAGE_CACHE};

    let parent_inode = parent.get_inode().ok_or(FsError::NotFound)?;
    let sb = parent_inode.superblock().ok_or(FsError::IoError)?;

    // Get parent's ramfs data
    let private = parent_inode.get_private().ok_or(FsError::IoError)?;
    let parent_data = private
        .as_ref()
        .as_any()
        .downcast_ref::<RamfsInodeData>()
        .ok_or(FsError::IoError)?;

    // Check if already exists
    if parent_data.children.read().contains_key(name) {
        return Err(FsError::AlreadyExists);
    }

    // Create new file inode with content and explicit timestamp
    let ino = sb.alloc_ino();
    let file_id = ramfs_file_id(&sb, ino);

    let new_inode = Arc::new(Inode::new(
        ino,
        mode,
        uid,
        gid,
        content.len() as u64,
        mtime,
        Arc::downgrade(&sb),
        &RAMFS_INODE_OPS,
    ));
    new_inode.set_private(Arc::new(RamfsInodeData::new_file(file_id)));

    // Write initial content to page cache
    if !content.is_empty() {
        let file_size = content.len() as u64;
        let mut bytes_written = 0;

        while bytes_written < content.len() {
            let page_offset = bytes_written / PAGE_SIZE;
            let offset_in_page = bytes_written % PAGE_SIZE;
            let chunk_size = min(PAGE_SIZE - offset_in_page, content.len() - bytes_written);

            // Get or create page
            let page = {
                let mut cache = PAGE_CACHE.lock();
                let mut frame_alloc = FrameAllocRef(&FRAME_ALLOCATOR);

                let (page, _) = cache
                    .find_or_create_page(
                        file_id,
                        page_offset as u64,
                        file_size,
                        &mut frame_alloc,
                        false, // can_writeback
                        true,  // unevictable
                        &RAMFS_AOPS,
                    )
                    .map_err(|_| FsError::IoError)?;
                page
            };

            // Copy content to page
            unsafe {
                let dst = (page.frame as *mut u8).add(offset_in_page);
                core::ptr::copy_nonoverlapping(content[bytes_written..].as_ptr(), dst, chunk_size);
            }
            page.mark_dirty();

            bytes_written += chunk_size;
        }
    }

    // Add to parent directory
    parent_data
        .children
        .write()
        .insert(String::from(name), new_inode.clone());

    // Create dentry
    let new_dentry = Arc::new(Dentry::new(
        String::from(name),
        Some(new_inode),
        Arc::downgrade(&sb),
    ));
    new_dentry.set_parent(parent);
    parent.add_child(new_dentry.clone());

    Ok(new_dentry)
}

/// Create a directory in ramfs with ownership and explicit timestamp
pub fn ramfs_create_dir_with_timestamp(
    parent: &Arc<Dentry>,
    name: &str,
    mode: InodeMode,
    uid: Uid,
    gid: Gid,
    mtime: Timespec,
) -> Result<Arc<Dentry>, FsError> {
    let parent_inode = parent.get_inode().ok_or(FsError::NotFound)?;
    let sb = parent_inode.superblock().ok_or(FsError::IoError)?;

    // Get parent's ramfs data
    let private = parent_inode.get_private().ok_or(FsError::IoError)?;
    let parent_data = private
        .as_ref()
        .as_any()
        .downcast_ref::<RamfsInodeData>()
        .ok_or(FsError::IoError)?;

    // Check if already exists
    if parent_data.children.read().contains_key(name) {
        return Err(FsError::AlreadyExists);
    }

    // Create new directory inode with explicit timestamp
    let new_inode = Arc::new(Inode::new(
        sb.alloc_ino(),
        mode,
        uid,
        gid,
        0,
        mtime,
        Arc::downgrade(&sb),
        &RAMFS_INODE_OPS,
    ));
    new_inode.set_private(Arc::new(RamfsInodeData::new_dir()));

    // Add to parent directory
    parent_data
        .children
        .write()
        .insert(String::from(name), new_inode.clone());

    // Create dentry
    let new_dentry = Arc::new(Dentry::new(
        String::from(name),
        Some(new_inode),
        Arc::downgrade(&sb),
    ));
    new_dentry.set_parent(parent);
    parent.add_child(new_dentry.clone());

    Ok(new_dentry)
}

/// Create nested directory path in ramfs with specified ownership and timestamp.
pub fn ramfs_mkpath_with_timestamp(
    root: &Arc<Dentry>,
    path: &str,
    uid: Uid,
    gid: Gid,
    mtime: Timespec,
) -> Result<Arc<Dentry>, FsError> {
    let mut current = root.clone();

    for component in path.split('/').filter(|s| !s.is_empty()) {
        // Check if this component already exists
        if let Some(child) = current.lookup_child(component) {
            // Verify it's a directory
            if let Some(inode) = child.get_inode()
                && !inode.mode().is_dir()
            {
                return Err(FsError::NotADirectory);
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
    name: &str,
    target: &str,
    uid: Uid,
    gid: Gid,
    mtime: Timespec,
) -> Result<Arc<Dentry>, FsError> {
    let parent_inode = parent.get_inode().ok_or(FsError::NotFound)?;
    let sb = parent_inode.superblock().ok_or(FsError::IoError)?;

    // Get parent's ramfs data
    let private = parent_inode.get_private().ok_or(FsError::IoError)?;
    let parent_data = private
        .as_ref()
        .as_any()
        .downcast_ref::<RamfsInodeData>()
        .ok_or(FsError::IoError)?;

    // Check if already exists
    if parent_data.children.read().contains_key(name) {
        return Err(FsError::AlreadyExists);
    }

    // Create symlink inode (mode = S_IFLNK | 0777)
    let new_inode = Arc::new(Inode::new(
        sb.alloc_ino(),
        InodeMode::symlink(),
        uid,
        gid,
        target.len() as u64, // size = target length
        mtime,
        Arc::downgrade(&sb),
        &RAMFS_INODE_OPS,
    ));

    // Store target inline (not in page cache)
    new_inode.set_private(Arc::new(RamfsInodeData::new_symlink(String::from(target))));

    // Add to parent directory
    parent_data
        .children
        .write()
        .insert(String::from(name), new_inode.clone());

    // Create dentry
    let new_dentry = Arc::new(Dentry::new(
        String::from(name),
        Some(new_inode),
        Arc::downgrade(&sb),
    ));
    new_dentry.set_parent(parent);
    parent.add_child(new_dentry.clone());

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
    name: &str,
    rdev: DevId,
    mode: u16,
) -> Result<Arc<Dentry>, FsError> {
    let parent_inode = parent.get_inode().ok_or(FsError::NotFound)?;
    let sb = parent_inode.superblock().ok_or(FsError::IoError)?;

    // Get parent's ramfs data
    let private = parent_inode.get_private().ok_or(FsError::IoError)?;
    let parent_data = private
        .as_ref()
        .as_any()
        .downcast_ref::<RamfsInodeData>()
        .ok_or(FsError::IoError)?;

    // Check if already exists
    if parent_data.children.read().contains_key(name) {
        return Err(FsError::AlreadyExists);
    }

    // Create new block device inode
    let new_inode = Arc::new(Inode::new_device(
        sb.alloc_ino(),
        InodeMode::blockdev(mode),
        0, // uid = root
        0, // gid = root
        rdev,
        current_time(),
        Arc::downgrade(&sb),
        &RAMFS_INODE_OPS,
    ));
    // Block devices don't need RamfsInodeData - they use the block layer

    // Add to parent directory
    parent_data
        .children
        .write()
        .insert(String::from(name), new_inode.clone());

    // Create dentry
    let new_dentry = Arc::new(Dentry::new(
        String::from(name),
        Some(new_inode),
        Arc::downgrade(&sb),
    ));
    new_dentry.set_parent(parent);
    parent.add_child(new_dentry.clone());

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
    name: &str,
    rdev: DevId,
    mode: u16,
) -> Result<Arc<Dentry>, FsError> {
    let parent_inode = parent.get_inode().ok_or(FsError::NotFound)?;
    let sb = parent_inode.superblock().ok_or(FsError::IoError)?;

    // Get parent's ramfs data
    let private = parent_inode.get_private().ok_or(FsError::IoError)?;
    let parent_data = private
        .as_ref()
        .as_any()
        .downcast_ref::<RamfsInodeData>()
        .ok_or(FsError::IoError)?;

    // Check if already exists
    if parent_data.children.read().contains_key(name) {
        return Err(FsError::AlreadyExists);
    }

    // Create new character device inode
    let new_inode = Arc::new(Inode::new_device(
        sb.alloc_ino(),
        InodeMode::chardev(mode),
        0, // uid = root
        0, // gid = root
        rdev,
        current_time(),
        Arc::downgrade(&sb),
        &RAMFS_INODE_OPS,
    ));
    // Character devices don't need RamfsInodeData - they use the chardev layer

    // Add to parent directory
    parent_data
        .children
        .write()
        .insert(String::from(name), new_inode.clone());

    // Create dentry
    let new_dentry = Arc::new(Dentry::new(
        String::from(name),
        Some(new_inode),
        Arc::downgrade(&sb),
    ));
    new_dentry.set_parent(parent);
    parent.add_child(new_dentry.clone());

    Ok(new_dentry)
}

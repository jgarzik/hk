//! CPIO archive unpacker (newc format)
//!
//! Unpacks CPIO archives directly into ramfs.

use alloc::sync::Arc;

use super::dentry::Dentry;
use super::inode::{Gid, InodeMode, Timespec, Uid};
use super::ramfs::{
    ramfs_create_file_with_timestamp, ramfs_create_symlink_with_timestamp,
    ramfs_mkpath_with_timestamp,
};

/// CPIO newc format magic
const CPIO_MAGIC: &[u8; 6] = b"070701";

/// CPIO parsing/unpacking error
#[derive(Debug)]
pub enum CpioError {
    /// Invalid magic number
    InvalidMagic,
    /// Buffer too small
    BufferTooSmall,
    /// Invalid header field
    InvalidHeader,
    /// Filesystem error during unpacking
    FsError,
}

/// Unpack a CPIO archive into a ramfs directory.
///
/// Iterates through the CPIO entries and creates files/directories in ramfs.
/// Returns the number of files unpacked.
///
/// # Arguments
/// * `data` - The raw CPIO archive data
/// * `root` - The root dentry to unpack into (should be ramfs)
pub fn unpack_cpio(data: &[u8], root: &Arc<Dentry>) -> Result<usize, CpioError> {
    let mut offset = 0;
    let mut file_count = 0;

    while offset + 110 <= data.len() {
        // Check magic
        if &data[offset..offset + 6] != CPIO_MAGIC {
            return Err(CpioError::InvalidMagic);
        }

        // Parse header fields (all in ASCII hex)
        // CPIO newc format header layout:
        //   0-5:   magic "070701"
        //   6-13:  ino
        //  14-21:  mode
        //  22-29:  uid
        //  30-37:  gid
        //  38-45:  nlink
        //  46-53:  mtime
        //  54-61:  filesize
        //  62-69:  devmajor
        //  70-77:  devminor
        //  78-85:  rdevmajor
        //  86-93:  rdevminor
        //  94-101: namesize
        // 102-109: check
        let mode = parse_hex(&data[offset + 14..offset + 22])? as u16;
        let uid = parse_hex(&data[offset + 22..offset + 30])? as Uid;
        let gid = parse_hex(&data[offset + 30..offset + 38])? as Gid;
        let mtime_secs = parse_hex(&data[offset + 46..offset + 54])? as i64;
        let mtime = Timespec::from_secs(mtime_secs);
        let namesize = parse_hex(&data[offset + 94..offset + 102])? as usize;
        let filesize = parse_hex(&data[offset + 54..offset + 62])? as usize;

        // Calculate name start (header is 110 bytes)
        let name_start = offset + 110;
        let name_end = name_start + namesize - 1; // -1 to exclude null terminator

        if name_end > data.len() {
            return Err(CpioError::BufferTooSmall);
        }

        let name = core::str::from_utf8(&data[name_start..name_end])
            .map_err(|_| CpioError::InvalidHeader)?;

        // TRAILER!!! marks end of archive
        if name == "TRAILER!!!" {
            break;
        }

        // Calculate file data start (aligned to 4 bytes)
        let data_start = align_up(name_start + namesize, 4);
        let data_end = data_start + filesize;

        if data_end > data.len() {
            return Err(CpioError::BufferTooSmall);
        }

        // Skip "." (root directory entry)
        if name != "." {
            // Check file type (S_IFMT mask = 0o170000)
            let file_type = mode & 0o170000;
            let is_dir = file_type == 0o040000; // S_IFDIR
            let is_symlink = file_type == 0o120000; // S_IFLNK

            if is_dir {
                // Create directory path with ownership and timestamp from CPIO
                ramfs_mkpath_with_timestamp(root, name, uid, gid, mtime)
                    .map_err(|_| CpioError::FsError)?;
            } else if is_symlink && filesize > 0 {
                // Symlink: data contains the target path
                let target = core::str::from_utf8(&data[data_start..data_end])
                    .map_err(|_| CpioError::InvalidHeader)?;

                // Get parent directory path and filename
                let (parent_path, filename) = match name.rfind('/') {
                    Some(pos) => (&name[..pos], &name[pos + 1..]),
                    None => ("", name),
                };

                // Ensure parent directory exists
                let parent = if parent_path.is_empty() {
                    root.clone()
                } else {
                    ramfs_mkpath_with_timestamp(root, parent_path, uid, gid, mtime)
                        .map_err(|_| CpioError::FsError)?
                };

                // Create symlink
                ramfs_create_symlink_with_timestamp(&parent, filename, target, uid, gid, mtime)
                    .map_err(|_| CpioError::FsError)?;

                file_count += 1;
            } else if filesize > 0 {
                // Regular file with content
                let file_data = &data[data_start..data_end];

                // Get parent directory path and filename
                let (parent_path, filename) = match name.rfind('/') {
                    Some(pos) => (&name[..pos], &name[pos + 1..]),
                    None => ("", name),
                };

                // Ensure parent directory exists (inherit uid/gid/mtime from file)
                let parent = if parent_path.is_empty() {
                    root.clone()
                } else {
                    ramfs_mkpath_with_timestamp(root, parent_path, uid, gid, mtime)
                        .map_err(|_| CpioError::FsError)?
                };

                // Create the file with mode, ownership, and timestamp from CPIO
                let inode_mode = InodeMode(mode);
                ramfs_create_file_with_timestamp(
                    &parent, filename, file_data, inode_mode, uid, gid, mtime,
                )
                .map_err(|_| CpioError::FsError)?;

                file_count += 1;
            }
        }

        // Move to next entry (aligned to 4 bytes)
        offset = align_up(data_end, 4);
    }

    Ok(file_count)
}

/// Parse an 8-character ASCII hex string
fn parse_hex(data: &[u8]) -> Result<u64, CpioError> {
    if data.len() != 8 {
        return Err(CpioError::InvalidHeader);
    }

    let s = core::str::from_utf8(data).map_err(|_| CpioError::InvalidHeader)?;
    u64::from_str_radix(s, 16).map_err(|_| CpioError::InvalidHeader)
}

/// Align a value up to the given alignment
fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

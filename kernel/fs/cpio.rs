//! Initramfs unpacker: cpio newc archives into ramfs (Linux
//! init/initramfs.c)
//!
//! Like Linux:
//! - every entry type: directories, regular files (empty ones too),
//!   symlinks, and character/block devices, FIFOs and sockets
//! - hard links: a regular file with nlink >= 2 is remembered by
//!   (dev, ino); a later entry with the same key becomes a link to it,
//!   and its body (GNU cpio stores it with the last name) fills the
//!   shared inode
//! - concatenated archives: after a TRAILER!!! entry, zero padding is
//!   skipped and another archive may follow (the link table resets)
//! - both newc magics, 070701 and 070702 (with checksum, not checked)

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::dentry::Dentry;
use super::inode::{Gid, Inode, InodeMode, Timespec, Uid};
use super::ramfs::{
    ramfs_create_file_with_timestamp, ramfs_create_symlink_with_timestamp, ramfs_fill_file,
    ramfs_mkpath_with_timestamp,
};
use crate::chardev::DevId;

/// newc header length
const HDR: usize = 110;

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;
const S_IFCHR: u32 = 0o020000;
const S_IFBLK: u32 = 0o060000;
const S_IFIFO: u32 = 0o010000;
const S_IFSOCK: u32 = 0o140000;

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
    KernelError,
}

/// One parsed newc header
struct Entry<'a> {
    ino: u32,
    mode: u32,
    uid: Uid,
    gid: Gid,
    nlink: u32,
    mtime: Timespec,
    dev: (u32, u32),
    rdev: (u32, u32),
    name: &'a str,
    body: &'a [u8],
    /// Offset of the next entry
    next: usize,
}

/// The header at `off`
fn parse(data: &[u8], off: usize) -> Result<Entry<'_>, CpioError> {
    let h = data.get(off..off + HDR).ok_or(CpioError::BufferTooSmall)?;
    if &h[..6] != b"070701" && &h[..6] != b"070702" {
        return Err(CpioError::InvalidMagic);
    }
    let f = |i: usize| parse_hex(&h[6 + 8 * i..14 + 8 * i]);
    let namesize = f(11)? as usize;
    let filesize = f(6)? as usize;
    if namesize == 0 {
        return Err(CpioError::InvalidHeader);
    }
    let name_start = off + HDR;
    let name_bytes = data
        .get(name_start..name_start + namesize - 1)
        .ok_or(CpioError::BufferTooSmall)?;
    let name = core::str::from_utf8(name_bytes).map_err(|_| CpioError::InvalidHeader)?;
    let body_start = align_up(name_start + namesize, 4);
    let body = data
        .get(body_start..body_start + filesize)
        .ok_or(CpioError::BufferTooSmall)?;
    Ok(Entry {
        ino: f(0)?,
        mode: f(1)?,
        uid: f(2)?,
        gid: f(3)?,
        nlink: f(4)?,
        mtime: Timespec::from_secs(f(5)? as i64),
        dev: (f(7)?, f(8)?),
        rdev: (f(9)?, f(10)?),
        name,
        body,
        next: align_up(body_start + filesize, 4),
    })
}

/// Hard-link table of one archive: (dev, ino) -> the first name's inode
type Links = Vec<((u32, u32, u32), Arc<Inode>)>;

/// Unpack an initramfs (one or more concatenated cpio newc archives)
/// into a ramfs directory. Returns the number of non-directory entries
/// made.
pub fn unpack_cpio(data: &[u8], root: &Arc<Dentry>) -> Result<usize, CpioError> {
    let mut off = 0;
    let mut count = 0;
    let mut links: Links = Vec::new();
    while off < data.len() {
        // Zero padding between archives (Linux skips it in 4-byte steps)
        if data[off] == 0 {
            off += 4;
            continue;
        }
        let e = parse(data, off)?;
        off = e.next;
        if e.name == "TRAILER!!!" {
            links.clear();
            continue;
        }
        if e.name == "." || e.name.is_empty() {
            continue;
        }
        // One bad entry does not stop the rest (Linux logs and goes on)
        match do_entry(root, &e, &mut links) {
            Ok(true) => count += 1,
            Ok(false) => {}
            Err(err) => crate::printkln!("initramfs: {}: not unpacked ({:?})", e.name, err),
        }
    }
    Ok(count)
}

/// Make one entry; true unless it is a directory
fn do_entry(root: &Arc<Dentry>, e: &Entry<'_>, links: &mut Links) -> Result<bool, CpioError> {
    let fs_err = |_| CpioError::KernelError;
    let ty = e.mode & S_IFMT;
    if ty == S_IFDIR {
        ramfs_mkpath_with_timestamp(root, e.name, e.uid, e.gid, e.mtime).map_err(fs_err)?;
        return Ok(false);
    }
    let (parent_path, name) = match e.name.rfind('/') {
        Some(pos) => (&e.name[..pos], &e.name[pos + 1..]),
        None => ("", e.name),
    };
    let parent = if parent_path.is_empty() {
        root.clone()
    } else {
        ramfs_mkpath_with_timestamp(root, parent_path, e.uid, e.gid, e.mtime).map_err(fs_err)?
    };
    let dir = parent.get_inode().ok_or(CpioError::KernelError)?;
    match ty {
        S_IFREG => {
            let key = (e.dev.0, e.dev.1, e.ino);
            if e.nlink >= 2
                && let Some((_, inode)) = links.iter().find(|(k, _)| *k == key)
            {
                // A later name of a hard-linked file
                dir.i_op.link(&dir, name, inode).map_err(fs_err)?;
                if !e.body.is_empty() {
                    ramfs_fill_file(inode, e.body).map_err(fs_err)?;
                }
                return Ok(true);
            }
            let mode = InodeMode(e.mode as u16);
            let d = ramfs_create_file_with_timestamp(
                &parent, name, e.body, mode, e.uid, e.gid, e.mtime,
            )
            .map_err(fs_err)?;
            if e.nlink >= 2
                && let Some(inode) = d.get_inode()
            {
                links.push((key, inode));
            }
        }
        S_IFLNK => {
            let target = core::str::from_utf8(e.body).map_err(|_| CpioError::InvalidHeader)?;
            ramfs_create_symlink_with_timestamp(&parent, name, target, e.uid, e.gid, e.mtime)
                .map_err(fs_err)?;
        }
        S_IFCHR | S_IFBLK | S_IFIFO | S_IFSOCK => {
            let rdev = if ty == S_IFCHR || ty == S_IFBLK {
                DevId::new(e.rdev.0 as u16, e.rdev.1 as u16)
            } else {
                DevId::new(0, 0)
            };
            let inode = dir
                .i_op
                .mknod(&dir, name, InodeMode(e.mode as u16), rdev)
                .map_err(fs_err)?;
            inode.set_uid(e.uid);
            inode.set_gid(e.gid);
            inode.set_mtime(e.mtime);
        }
        _ => return Err(CpioError::InvalidHeader),
    }
    Ok(true)
}

/// Parse an 8-character ASCII hex field
fn parse_hex(data: &[u8]) -> Result<u32, CpioError> {
    let s = core::str::from_utf8(data).map_err(|_| CpioError::InvalidHeader)?;
    u32::from_str_radix(s, 16).map_err(|_| CpioError::InvalidHeader)
}

/// Align a value up to the given alignment
fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

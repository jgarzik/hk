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
use crate::fs::chardev::DevId;

/// The initramfs image (Linux __initramfs_start or initrd_start)
pub struct Initrd(Image);

enum Image {
    /// Built into the kernel image, which stays
    Builtin(&'static [u8]),
    /// Pages the boot loader filled, reserved since boot: physical
    /// [start, end)
    Loaded { start: u64, end: u64 },
}

impl Initrd {
    /// An image built into the kernel
    pub const fn builtin(data: &'static [u8]) -> Self {
        Self(Image::Builtin(data))
    }

    /// The boot loader's image at physical [start, end)
    ///
    /// # Safety
    /// [start, end) is RAM in the direct map, reserved from the page
    /// allocator since boot, which nothing else reads or writes: its
    /// whole pages go to the allocator at `free`.
    pub const unsafe fn loaded(start: u64, end: u64) -> Self {
        Self(Image::Loaded { start, end })
    }

    /// The archive's bytes, while the image is held
    pub fn data(&self) -> &[u8] {
        match self.0 {
            Image::Builtin(d) => d,
            Image::Loaded { start, end } => {
                let p = crate::arch::phys_to_virt(start).cast_const();
                // SAFETY: `loaded`'s contract: mapped, reserved, ours
                // until `free` consumes `self`, which ends this borrow
                unsafe { core::slice::from_raw_parts(p, (end - start) as usize) }
            }
        }
    }

    /// Done with it (Linux do_populate_rootfs -> free_initrd_mem): the
    /// boot loader's pages go to the page allocator, a built-in image
    /// stays with the kernel image
    pub fn free(self) {
        if let Image::Loaded { start, end } = self.0 {
            let pages = crate::FRAME_ALLOCATOR.free_reserved(start, end);
            crate::printkln!("Freeing initrd memory: {}K", pages * 4);
        }
    }
}

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
    name: &'a [u8],
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
    let name = name_bytes;
    let body_start = (name_start + namesize).next_multiple_of(4);
    let body = data
        .get(body_start..body_start + filesize)
        .ok_or(CpioError::BufferTooSmall)?;
    Ok(Entry {
        ino: f(0)?,
        mode: f(1)?,
        uid: f(2)?,
        gid: f(3)?,
        nlink: f(4)?,
        mtime: Timespec::from_secs(i64::from(f(5)?)),
        dev: (f(7)?, f(8)?),
        rdev: (f(9)?, f(10)?),
        name,
        body,
        next: (body_start + filesize).next_multiple_of(4),
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
        if e.name == b"TRAILER!!!" {
            links.clear();
            continue;
        }
        if e.name == b"." || e.name.is_empty() {
            continue;
        }
        // One bad entry does not stop the rest (Linux logs and goes on)
        match do_entry(root, &e, &mut links) {
            Ok(true) => count += 1,
            Ok(false) => {}
            Err(err) => crate::printkln!(
                "initramfs: {}: not unpacked ({:?})",
                crate::fs::name::Escaped(e.name),
                err
            ),
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
    let (parent_path, name): (&[u8], &[u8]) = match e.name.iter().rposition(|&c| c == b'/') {
        Some(pos) => (&e.name[..pos], &e.name[pos + 1..]),
        None => (b"", e.name),
    };
    let parent = if parent_path.is_empty() {
        root.clone()
    } else {
        ramfs_mkpath_with_timestamp(root, parent_path, e.uid, e.gid, e.mtime).map_err(fs_err)?
    };
    let dir = parent.get_inode().ok_or(CpioError::KernelError)?;
    // Linux maybe_link: a later name of a hard-linked file replaces
    // whatever has that name (clean_path(collected, 0)) and links to
    // the first; the body, if this name carries it, goes to the file
    let key = (e.dev.0, e.dev.1, e.ino);
    if ty == S_IFREG
        && e.nlink >= 2
        && let Some((_, inode)) = links.iter().find(|(k, _)| *k == key)
    {
        let inode = inode.clone();
        clean_path(&parent, &dir, name, u32::MAX);
        dir.i_op.link(&dir, name, &inode).map_err(fs_err)?;
        if !e.body.is_empty() {
            ramfs_fill_file(&inode, e.body).map_err(fs_err)?;
        }
        return Ok(true);
    }
    let existing = clean_path(&parent, &dir, name, ty);
    match ty {
        S_IFREG if existing.is_some() => {
            // Linux opens an existing file O_TRUNC and writes the body:
            // a later archive (an overlay) replaces it
            let old = existing.ok_or(CpioError::KernelError)?;
            old.i_op.truncate(&old, 0).map_err(fs_err)?;
            ramfs_fill_file(&old, e.body).map_err(fs_err)?;
            old.set_mode_perm((e.mode & 0o7777) as u16);
            old.set_uid(e.uid);
            old.set_gid(e.gid);
            old.set_mtime(e.mtime);
            if e.nlink >= 2 {
                links.push((key, old));
            }
        }
        // Another entry of the same type stays (Linux: mknod/symlink
        // fail with EEXIST and are skipped)
        _ if existing.is_some() => {}
        S_IFREG => {
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
            ramfs_create_symlink_with_timestamp(&parent, name, e.body, e.uid, e.gid, e.mtime)
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

/// Linux clean_path: an existing entry of another type is removed
/// (rmdir for a directory); one of the same type is returned
fn clean_path(parent: &Arc<Dentry>, dir: &Inode, name: &[u8], ty: u32) -> Option<Arc<Inode>> {
    let old = dir.i_op.lookup(dir, name).ok()?;
    if u32::from(old.mode().0) & S_IFMT == ty {
        return Some(old);
    }
    let gone = if old.mode().is_dir() {
        dir.i_op.rmdir(dir, name)
    } else {
        dir.i_op.unlink(dir, name)
    };
    if gone.is_ok() {
        parent.remove_child(name);
    }
    None
}

/// Parse an 8-character ASCII hex field
fn parse_hex(data: &[u8]) -> Result<u32, CpioError> {
    let s = core::str::from_utf8(data).map_err(|_| CpioError::InvalidHeader)?;
    u32::from_str_radix(s, 16).map_err(|_| CpioError::InvalidHeader)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A newc header for `name` with `body`, padded as the format pads
    fn entry(mode: u32, name: &[u8], body: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"070701");
        let fields = [
            7,
            mode,
            1000,
            100,
            1,
            12345,
            body.len() as u32,
            0,
            1,
            0,
            0,
            name.len() as u32 + 1,
            0,
        ];
        for f in fields {
            v.extend_from_slice(alloc::format!("{f:08X}").as_bytes());
        }
        v.extend_from_slice(name);
        v.push(0);
        v.resize(v.len().next_multiple_of(4), 0);
        v.extend_from_slice(body);
        v.resize(v.len().next_multiple_of(4), 0);
        v
    }

    /// Header fields, name, body and the 4-byte aligned next entry
    #[test]
    fn parses_newc() {
        let mut a = entry(0o100644, b"etc/hosts", b"127.0.0.1 x\n");
        let second = a.len();
        a.extend(entry(0o040755, b"dir", b""));
        let e = parse(&a, 0).unwrap();
        assert_eq!(
            (e.ino, e.mode, e.uid, e.gid, e.nlink),
            (7, 0o100644, 1000, 100, 1)
        );
        assert_eq!(e.name, b"etc/hosts");
        assert_eq!(e.body, b"127.0.0.1 x\n");
        assert_eq!(e.next, second);
        let d = parse(&a, e.next).unwrap();
        assert_eq!((d.name, d.body.len()), (&b"dir"[..], 0));
        assert_eq!(d.next, a.len());
    }

    /// Bad magic, a zero name size, a header, name or body running past
    /// the archive, and non-hex fields are errors, never a panic
    #[test]
    fn rejects_bad_input() {
        let good = entry(0o100644, b"f", b"data");
        let mut bad = good.clone();
        bad[..6].copy_from_slice(b"070707");
        assert!(matches!(parse(&bad, 0), Err(CpioError::InvalidMagic)));
        assert!(matches!(
            parse(&good[..100], 0),
            Err(CpioError::BufferTooSmall)
        ));
        assert!(matches!(
            parse(&good[..good.len() - 4], 0),
            Err(CpioError::BufferTooSmall)
        ));
        let mut huge = good.clone();
        huge[6 + 8 * 6..14 + 8 * 6].copy_from_slice(b"FFFFFFFF");
        assert!(matches!(parse(&huge, 0), Err(CpioError::BufferTooSmall)));
        let mut noname = good.clone();
        noname[6 + 8 * 11..14 + 8 * 11].copy_from_slice(b"00000000");
        assert!(matches!(parse(&noname, 0), Err(CpioError::InvalidHeader)));
        let mut nothex = good;
        nothex[6..14].copy_from_slice(b"0000000G");
        assert!(matches!(parse(&nothex, 0), Err(CpioError::InvalidHeader)));
        assert!(matches!(parse(b"", 0), Err(CpioError::BufferTooSmall)));
    }
}

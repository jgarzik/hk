//! Library routines for simple filesystems (Linux fs/libfs.c)
//!
//! For a filesystem whose dentries are its directories (the dcache is
//! the only copy, its positive dentries kept until removed:
//! `SuperOps::d_persistent`, Linux d_make_persistent): an entry is made
//! under its parent's i_rwsem ([`simple_create`]), a subtree removed
//! with [`simple_recursive_removal`], a directory read from the dcache
//! ([`dcache_readdir`]); a lookup of any other name finds nothing
//! (simple_lookup). The filesystem's kernel mount is made by its first
//! user and kept while it has any ([`simple_pin_fs`]).
//!
//! ## Locking
//!
//! A create holds the parent's i_rwsem across the lookup of the name and
//! the new dentry's instantiation (Linux simple_start_creating ..
//! simple_done_creating). A recursive removal holds one directory's
//! i_rwsem at a time on its way down, and on its way up the victim's
//! parent's (taken after the victim's is released, Linux
//! __simple_recursive_removal), across `d_invalidate` (which may take
//! NAMESPACE_SEM) and the callback. `PinnedFs` is a spin leaf (Linux
//! pin_fs_lock): the kernel mount is made and put with it released.

use crate::fs::KernelError;
use crate::fs::dentry::{Dentry, DentryRef, LookupBits, d_invalidate};
use crate::fs::file::{DirContext, DirEntry, File};
use crate::fs::inode::{FileType, Inode, InodeRef};
use crate::fs::iov_iter::IovDest;
use crate::fs::mount::{Mount, MountRef};
use crate::fs::superblock::{FileSystemType, FsContext, vfs_get_tree};
use crate::sync::spin::Mutex as SpinMutex;
use crate::util::kalloc::try_arc;

/// Linux simple_unlink's and simple_link's times: the inode's ctime,
/// the directory's ctime and mtime, all one `now`
pub fn simple_link_times(dir: &Inode, inode: &Inode) {
    let now = crate::time::TIMEKEEPER.current_time();
    inode.set_ctime(now);
    dir.set_ctime(now);
    dir.set_mtime(now);
}

/// Linux simple_rename_timestamp: both directories' ctime and mtime,
/// the moved inode's ctime and the replaced (or exchanged) one's, all
/// one `now`
pub fn simple_rename_timestamp(old_dir: &Inode, new_dir: &Inode, old: &Inode, new: Option<&Inode>) {
    let now = crate::time::TIMEKEEPER.current_time();
    for d in [old_dir, new_dir] {
        d.set_ctime(now);
        d.set_mtime(now);
    }
    old.set_ctime(now);
    if let Some(n) = new {
        n.set_ctime(now);
    }
}

/// Linux lookup_noperm_common: a kernel-made name is one component,
/// not "." or ".." (EACCES)
fn name_ok(name: &[u8]) -> Result<(), KernelError> {
    if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') {
        return Err(KernelError::PermissionDenied);
    }
    if name.contains(&0) {
        return Err(KernelError::PermissionDenied);
    }
    Ok(())
}

/// Make `name` in `parent` (Linux simple_start_creating, the
/// filesystem's d_instantiate, simple_done_creating): under the
/// parent's i_rwsem, ENOENT in a removed directory, EEXIST if the name
/// is taken, else the inode `make` gives (asked with the directory's)
/// in a new dentry, allocated before it so nothing is half made
pub fn simple_create(
    parent: &DentryRef,
    name: &[u8],
    make: impl FnOnce(&Inode) -> Result<InodeRef, KernelError>,
) -> Result<DentryRef, KernelError> {
    name_ok(name)?;
    let dir = parent.get_inode().ok_or(KernelError::NotFound)?;
    let _g = dir.lock();
    // start_dirop: lookup_one_qstr_excl with LOOKUP_CREATE | LOOKUP_EXCL
    if dir.is_dead() {
        return Err(KernelError::NotFound);
    }
    match crate::fs::lookup_one(parent, name, LookupBits::CREATE | LookupBits::EXCL) {
        Ok(_) => return Err(KernelError::AlreadyExists),
        Err(KernelError::NotFound) => {}
        Err(e) => return Err(e),
    }
    let d = Dentry::prealloc(parent, name)?;
    let inode = make(&dir)?;
    Ok(Dentry::add(parent, d, Some(inode)))
}

/// Remove `dentry` and everything below it (Linux
/// simple_recursive_removal): depth first, each directory marked dead
/// (S_DEAD) as it is entered; on the way up each victim, once its own
/// lock is released, loses its link count and leaves the tree under its
/// parent's lock (d_invalidate, which also detaches what is mounted on
/// it), then `callback` sees it. `dentry`'s parent's times and, for a
/// directory, link count change last. Open files keep their dentries,
/// unhashed.
pub fn simple_recursive_removal(dentry: &DentryRef, callback: Option<&dyn Fn(&DentryRef)>) {
    let mut this = dentry.clone();
    let Some(mut inode) = this.get_inode() else {
        return;
    };
    let mut g = inode.lock_arc();
    loop {
        if inode.mode().is_dir() {
            inode.set_dead();
        }
        if let Some(child) = this.first_positive_child() {
            let Some(ci) = child.get_inode() else {
                continue;
            };
            drop(g);
            (this, inode) = (child, ci);
            g = inode.lock_arc();
            continue;
        }
        // Kill and ascend: the metadata while it is still locked
        inode.touch_c();
        inode.nlink.store(0, core::sync::atomic::Ordering::Relaxed);
        drop(g);
        let Some(parent) = this.get_parent() else {
            return;
        };
        let Some(pi) = parent.get_inode() else {
            return;
        };
        let victim = core::mem::replace(&mut this, parent);
        let was_dir = inode.mode().is_dir();
        inode = pi;
        g = inode.lock_arc();
        if !victim.is_negative() {
            // Lost mounts avoided (Linux: d_invalidate)
            d_invalidate(&victim);
            if let Some(f) = callback {
                f(&victim);
            }
        }
        if DentryRef::ptr_eq(&victim, dentry) {
            inode.touch_mc();
            if was_dir {
                inode.dec_nlink();
            }
            return;
        }
    }
}

/// The reader's cursor of an open directory (Linux file->private_data
/// of dcache_dir_open)
fn cursor(file: &File) -> Result<alloc::sync::Arc<DentryRef>, KernelError> {
    file.private_arc::<DentryRef>().ok_or(KernelError::BadFd)
}

/// Linux dcache_dir_open: the file's cursor, off the list (before the
/// first entry)
pub fn dcache_dir_open(file: &File) -> Result<(), KernelError> {
    let c = try_arc(Dentry::alloc_cursor(&file.dentry)?)?;
    file.private.call_once(|| c);
    Ok(())
}

/// Linux dcache_dir_close: the cursor leaves the children list
pub fn dcache_dir_close(file: &File) {
    if let Ok(c) = cursor(file) {
        file.dentry.cursor_move(&c, None);
    }
}

/// Linux dcache_dir_lseek: SEEK_SET or SEEK_CUR to a position at or
/// past 0 (else EINVAL); a new position puts the cursor after the
/// positive child before it (none for "." and ".."), under the
/// directory's shared lock
pub fn dcache_dir_lseek(file: &File, offset: i64, whence: i32) -> Result<u64, KernelError> {
    use crate::fs::file::seek;
    let off = match whence {
        seek::SEEK_SET => offset,
        seek::SEEK_CUR => offset
            .checked_add(file.get_pos() as i64)
            .ok_or(KernelError::InvalidArgument)?,
        _ => return Err(KernelError::InvalidArgument),
    };
    let off = u64::try_from(off).map_err(|_| KernelError::InvalidArgument)?;
    if off != file.get_pos() {
        let d = &file.dentry;
        let c = cursor(file)?;
        let dir = d.get_inode().ok_or(KernelError::BadFd)?;
        let _l = dir.lock_shared();
        let n = usize::try_from(off.saturating_sub(2)).unwrap_or(usize::MAX);
        let to = (off > 2).then(|| d.scan_positives(&c, true, n)).flatten();
        d.cursor_move(&c, to.as_deref());
        file.set_pos(off);
    }
    Ok(off)
}

/// Linux dcache_readdir: ".", "..", then the directory's positive
/// dentries in the order of its children list, each one position on;
/// the file's cursor keeps its place between calls, so entries removed
/// or added meanwhile shift nothing
pub fn dcache_readdir(file: &File, ctx: &mut DirContext<'_>) -> Result<(), KernelError> {
    dcache_readdir_at(&file.dentry, &*cursor(file)?, ctx)
}

/// [`dcache_readdir`] of directory `d` with the reader's cursor `c`
fn dcache_readdir_at(
    d: &DentryRef,
    c: &DentryRef,
    ctx: &mut DirContext<'_>,
) -> Result<(), KernelError> {
    let inode = d.get_inode().ok_or(KernelError::BadFd)?;
    let up = d.get_parent().and_then(|p| p.get_inode());
    let parent_ino = up.map_or(inode.ino, |p| p.ino);
    for (at, ino, name) in [(0, inode.ino, &b"."[..]), (1, parent_ino, &b".."[..])] {
        let e = DirEntry {
            ino,
            file_type: FileType::Directory,
            name: name.to_vec(),
        };
        if !ctx.emit_at(at, e) {
            return Ok(());
        }
    }
    // From the first child at position 2, else from the cursor
    let mut from_head = ctx.pos == 2;
    loop {
        // Linux scan_positives(cursor, p, 1, next)
        let Some(next) = d.scan_positives(c, from_head, 1) else {
            // The end: the cursor off the list (hlist_del_init)
            d.cursor_move(c, None);
            return Ok(());
        };
        // Positive under the reader's shared lock (no removal meanwhile)
        let Some(ni) = next.get_inode() else {
            return Ok(());
        };
        let e = DirEntry {
            ino: ni.ino,
            file_type: ni.mode().file_type().unwrap_or(FileType::Regular),
            name: next.name().to_vec(),
        };
        if !ctx.emit_at(ctx.pos, e) {
            // The cursor stays just before `next`
            return Ok(());
        }
        d.cursor_move(c, Some(&next));
        from_head = false;
    }
}

/// Copy `from` at `*pos` out to `to` (Linux simple_read_from_buffer):
/// nothing at or past its end; the position moves by what was copied
pub fn simple_read_from_buffer(
    to: &mut IovDest<'_>,
    pos: &mut u64,
    from: &[u8],
) -> Result<usize, KernelError> {
    let at = usize::try_from(*pos).unwrap_or(usize::MAX);
    if at >= from.len() || to.is_empty() {
        return Ok(0);
    }
    let n = to.copy_to(&from[at..])?;
    *pos += n as u64;
    Ok(n)
}

/// A filesystem's kernel mount and how many hold it (Linux
/// simple_pin_fs's `mount` and `count`, under pin_fs_lock)
pub struct PinnedFs(SpinMutex<(Option<MountRef>, usize)>);

impl PinnedFs {
    pub const fn new() -> Self {
        Self(SpinMutex::new((None, 0)))
    }
}

impl Default for PinnedFs {
    fn default() -> Self {
        Self::new()
    }
}

/// A kernel mount of `ty` (Linux vfs_kern_mount): its superblock's
/// root, in no namespace
fn kern_mount(ty: &'static FileSystemType) -> Result<MountRef, KernelError> {
    let sb = vfs_get_tree(&FsContext::new(ty, b""))?.unlock();
    let root = sb.get_root().ok_or(KernelError::Io)?;
    let m = Mount::alloc(sb, root, 0, ty.name.as_bytes().into())?;
    m.set_internal();
    Ok(m)
}

/// Hold `ty`'s kernel mount, made if no one holds it (Linux
/// simple_pin_fs); a reference to it for the caller's use. The check,
/// the mount's install and the count are one lock section; the lock is
/// dropped only to make the mount, and a racing maker's is put after
/// it. Each hold is given back with [`simple_release_fs`].
pub fn simple_pin_fs(ty: &'static FileSystemType, p: &PinnedFs) -> Result<MountRef, KernelError> {
    let mut made = None;
    let mut g = p.0.lock();
    if g.0.is_none() {
        drop(g);
        made = Some(kern_mount(ty)?);
        g = p.0.lock();
        if g.0.is_none() {
            g.0 = made.take();
        }
    }
    g.1 += 1;
    let m = g.0.clone();
    drop(g);
    drop(made);
    // Installed above if it was not there: always set here
    m.ok_or(KernelError::Io)
}

/// Give back a hold [`simple_pin_fs`] took (Linux simple_release_fs):
/// the last one puts the mount, with the lock released
pub fn simple_release_fs(p: &PinnedFs) {
    let mut g = p.0.lock();
    g.1 = g.1.saturating_sub(1);
    let last = if g.1 == 0 { g.0.take() } else { None };
    drop(g);
    drop(last);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::inode::{InodeMode, NULL_INODE_OPS, Timespec};
    use alloc::sync::Weak;
    use alloc::vec::Vec;

    fn inode(ino: u64, mode: InodeMode) -> InodeRef {
        let t = Timespec::from_secs(0);
        let i = Inode::new(ino, mode, 0, 0, 0, t, Weak::new(), &NULL_INODE_OPS);
        Inode::alloc(i).unwrap()
    }

    /// One readdir call with room for `room` entries from `*pos`: the
    /// names returned, `*pos` moved on
    fn read(d: &DentryRef, c: &DentryRef, pos: &mut u64, room: usize) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut actor = |e: &DirEntry, _: u64| {
            if out.len() == room {
                return false;
            }
            out.push(e.name.clone());
            true
        };
        let mut ctx = DirContext::new(*pos, &mut actor);
        dcache_readdir_at(d, c, &mut ctx).unwrap();
        *pos = ctx.pos;
        out
    }

    /// The reader's cursor keeps its place (Linux dcache_readdir): an
    /// entry already returned that goes between two calls shifts
    /// nothing, so the next call starts at the next entry, neither
    /// repeating nor skipping one; at the end the cursor leaves the
    /// list and a walk of the children never sees it
    #[test]
    fn cursor_keeps_place() {
        let root = DentryRef::new(Dentry::new_root(
            inode(1, InodeMode::directory(0o755)),
            Weak::new(),
        ))
        .unwrap();
        let kids: Vec<DentryRef> = (b'a'..=b'e')
            .map(|c| {
                let i = inode(u64::from(c), InodeMode::regular(0o644));
                Dentry::alloc(&root, &[c], Some(i)).unwrap()
            })
            .collect();
        let cur = Dentry::alloc_cursor(&root).unwrap();
        let mut pos = 0;
        let first = read(&root, &cur, &mut pos, 4);
        assert_eq!(first, [&b"."[..], b"..", b"a", b"b"].map(<[u8]>::to_vec));
        // The cursor sits among the children, not counted as one
        assert_eq!(root.num_children(), 5);
        assert!(root.remove_child(b"a").is_some());
        let rest = read(&root, &cur, &mut pos, 16);
        assert_eq!(rest, [&b"c"[..], b"d", b"e"].map(<[u8]>::to_vec));
        assert_eq!(pos, 7);
        assert!(read(&root, &cur, &mut pos, 16).is_empty());
        // A seek back to the start reads from the first again
        let mut zero = 0;
        let again = read(&root, &cur, &mut zero, 3);
        assert_eq!(again, [&b"."[..], b"..", b"b"].map(<[u8]>::to_vec));
        root.cursor_move(&cur, None);
        drop(kids);
    }
}

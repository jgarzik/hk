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
        if let Some(child) = this.nth_positive_child(0) {
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

/// Linux dcache_readdir: ".", "..", then the directory's positive
/// dentries in the order of its children list, the `n`th at position
/// `n + 2`
pub fn dcache_readdir(file: &File, ctx: &mut DirContext<'_>) -> Result<(), KernelError> {
    let d = &file.dentry;
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
    let mut pos = ctx.pos.max(2);
    while let Some(c) = d.nth_positive_child(usize::try_from(pos - 2).unwrap_or(usize::MAX)) {
        // Gone negative since: the next one is at this position now
        let Some(ci) = c.get_inode() else {
            continue;
        };
        let e = DirEntry {
            ino: ci.ino,
            file_type: ci.mode().file_type().unwrap_or(FileType::Regular),
            name: c.name().to_vec(),
        };
        if !ctx.emit_at(pos, e) {
            break;
        }
        pos += 1;
    }
    Ok(())
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

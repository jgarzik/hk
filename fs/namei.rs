//! Path names and their resolution (Linux fs/namei.c)
//!
//! A user path is copied in once ([`getname`]) and resolved from its
//! start ([`path_start`]: root, cwd or dirfd) by walking the directory
//! tree. Every directory a name is looked up in needs search (MAY_EXEC)
//! permission for the caller (Linux may_lookup), including for "." and
//! "..". Creating and removing calls split off the last component
//! instead ([`filename_parentat`]).

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::KernelError;
use super::dac::{MAY_EXEC, cred, permission_as};
use super::dentry::Dentry;
use super::file::flags::{AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_NOFOLLOW};
use super::inode::Inode;
use super::mount::follow_mount;
use super::path_ref::Path;
use crate::fs::syscall::PATH_MAX;
use crate::ns::current_mnt_ns;
use crate::task::Cred;

/// Maximum number of symlinks to follow (prevent infinite loops)
const MAX_SYMLINK_DEPTH: usize = 40;

/// Path lookup flags
#[derive(Debug, Clone, Copy, Default)]
pub struct LookupFlags {
    /// Follow symlinks in the final component
    pub follow: bool,
    /// The final component must be a directory
    pub directory: bool,
    /// Create the final component if it doesn't exist
    pub create: bool,
    /// Don't cross mount points
    pub no_xdev: bool,
}

impl LookupFlags {
    /// Default flags for open()
    pub fn open() -> Self {
        Self {
            follow: true,
            directory: false,
            create: false,
            no_xdev: false,
        }
    }

    /// Flags for opendir()
    pub fn opendir() -> Self {
        Self {
            follow: true,
            directory: true,
            create: false,
            no_xdev: false,
        }
    }

    /// Flags of an *at() call: a final symlink is followed unless
    /// AT_SYMLINK_NOFOLLOW
    pub fn at(at: i32) -> Self {
        Self {
            follow: at & AT_SYMLINK_NOFOLLOW == 0,
            ..Self::open()
        }
    }
}

/// Look up an absolute path, or a path relative to the current directory
pub fn lookup_path(path: &[u8]) -> Result<Arc<Dentry>, KernelError> {
    lookup_path_flags(path, LookupFlags::open())
}

/// Look up a path relative to the current directory with specific flags
pub fn lookup_path_flags(path: &[u8], flags: LookupFlags) -> Result<Arc<Dentry>, KernelError> {
    lookup_path_at(crate::task::percpu::current_cwd(), path, flags)
}

/// Look up a path relative to a starting path
///
/// The core of open() and the *at() syscalls: relative paths start at
/// `start` (root when None), absolute paths at the namespace root.
pub fn lookup_path_at(
    start: Option<Path>,
    path: &[u8],
    flags: LookupFlags,
) -> Result<Arc<Dentry>, KernelError> {
    walk(&cred(), start, path, flags, 0)
}

/// Child `name` of directory `parent`: the dcache, else the file system
/// (the new dentry is cached). Permission is the caller's business.
pub fn lookup_one(parent: &Arc<Dentry>, name: &[u8]) -> Result<Arc<Dentry>, KernelError> {
    // No file system here has longer names (Linux simple_lookup and the
    // disk file systems' lookups: ENAMETOOLONG)
    if name.len() > NAME_MAX {
        return Err(KernelError::NameTooLong);
    }
    if let Some(child) = parent.lookup_child(name) {
        return Ok(child);
    }
    let dir = parent.get_inode().ok_or(KernelError::NotFound)?;
    let inode = dir.i_op.lookup(&dir, name)?;
    let child = Arc::new(Dentry::new(name.into(), Some(inode), parent.sb.clone()));
    child.set_parent(parent);
    parent.add_child(child.clone());
    Ok(child)
}

/// Longest name of one path component (Linux NAME_MAX)
pub const NAME_MAX: usize = 255;

/// Path-walk lookup (Linux lookup_fast + lookup_slow): a dcache hit
/// needs no lock; a miss asks the file system under the directory's
/// shared inode lock, so it cannot race a create/unlink/rename there
fn lookup_slow(parent: &Arc<Dentry>, name: &[u8]) -> Result<Arc<Dentry>, KernelError> {
    if name.len() > NAME_MAX {
        return Err(KernelError::NameTooLong);
    }
    if let Some(child) = parent.lookup_child(name) {
        return Ok(child);
    }
    let dir = parent.get_inode().ok_or(KernelError::NotFound)?;
    let _lock = dir.lock_shared();
    lookup_one(parent, name)
}

/// may_lookup: `dir` must be a searchable directory
fn may_lookup(c: &Cred, dir: &Dentry) -> Result<(), KernelError> {
    let inode = dir.get_inode().ok_or(KernelError::NotFound)?;
    if !inode.mode().is_dir() {
        return Err(KernelError::NotDirectory);
    }
    permission_as(c, &inode, MAY_EXEC)
}

fn walk(
    c: &Cred,
    start: Option<Path>,
    path: &[u8],
    mut flags: LookupFlags,
    depth: usize,
) -> Result<Arc<Dentry>, KernelError> {
    if depth > MAX_SYMLINK_DEPTH {
        return Err(KernelError::TooManySymlinks);
    }
    // A trailing slash asks for a directory, through a final symlink
    // (Linux link_path_walk: LOOKUP_FOLLOW | LOOKUP_DIRECTORY)
    if path.ends_with(b"/") {
        flags.follow = true;
        flags.directory = true;
    }
    let mnt_ns = current_mnt_ns();
    let mut cur = match start {
        Some(p) if !path.starts_with(b"/") => p.dentry.clone(),
        _ => mnt_ns.get_root_dentry().ok_or(KernelError::NotFound)?,
    };
    let comps: Vec<&[u8]> = path
        .split(|&c| c == b'/')
        .filter(|s| !s.is_empty())
        .collect();
    for (i, name) in comps.iter().enumerate() {
        may_lookup(c, &cur)?;
        match *name {
            b"." => continue,
            b".." => {
                // At the root, ".." stays at the root
                if let Some(parent) = cur.get_parent() {
                    cur = parent;
                }
                continue;
            }
            _ => {}
        }
        let child = lookup_slow(&cur, name)?;
        let child = if flags.no_xdev {
            child
        } else {
            follow_mount(&child)
        };
        let last = i + 1 == comps.len();
        if (!last || flags.follow) && child.get_inode().is_some_and(|n| n.mode().is_symlink()) {
            return follow_link(c, &cur, &child, &comps[i + 1..], flags, depth);
        }
        cur = child;
    }
    if flags.directory && cur.get_inode().is_some_and(|n| !n.mode().is_dir()) {
        return Err(KernelError::NotDirectory);
    }
    Ok(cur)
}

/// Continue a walk through symlink `link` found in `dir`, with the
/// components `rest` still to resolve after it
fn follow_link(
    c: &Cred,
    dir: &Arc<Dentry>,
    link: &Dentry,
    rest: &[&[u8]],
    flags: LookupFlags,
    depth: usize,
) -> Result<Arc<Dentry>, KernelError> {
    let inode = link.get_inode().ok_or(KernelError::NotFound)?;
    let target = inode.i_op.readlink(&inode)?;
    let mut path = target;
    for comp in rest {
        path.push(b'/');
        path.extend_from_slice(comp);
    }
    walk(c, Path::from_dentry(dir.clone()), &path, flags, depth + 1)
}

/// Create the entry `p` names (Linux filename_create +
/// vfs_mkdir/mknod/symlink/link) under the parent's lock: EEXIST first,
/// ENOENT for a name with a trailing slash that is not a directory to
/// make, then may_create (write+search), then `make` builds the inode
/// with the caller's credentials; the new dentry is cached
pub fn create_entry(
    p: &Parent,
    make: impl FnOnce(&Arc<Inode>, &Cred) -> Result<Arc<Inode>, KernelError>,
) -> Result<Arc<Dentry>, KernelError> {
    let (parent, name) = (&p.dir, p.name.as_slice());
    let dir = parent.get_inode().ok_or(KernelError::NotFound)?;
    if !dir.mode().is_dir() {
        return Err(KernelError::NotDirectory);
    }
    let c = cred();
    // filename_create: write access first, its EROFS reported after EEXIST
    let w = super::dac::want_write(&dir);
    let _dir_lock = dir.lock();
    (|| {
        if lookup_one(parent, name).is_ok() {
            return Err(KernelError::AlreadyExists);
        }
        if p.slash {
            return Err(KernelError::NotFound);
        }
        let _w = w?;
        super::dac::may_create(&c, &dir)?;
        let inode = make(&dir, &c)?;
        let d = Arc::new(Dentry::new(name.into(), Some(inode), parent.sb.clone()));
        d.set_parent(parent);
        parent.add_child(d.clone());
        Ok(d)
    })()
}

/// Remove the entry `p` names (Linux vfs_unlink / vfs_rmdir) under the
/// parent's lock: an unlink through a trailing slash is EISDIR or
/// ENOTDIR, then may_delete (write+search, sticky rule, type vs
/// `isdir`), then the file system's unlink or rmdir with the victim's
/// lock held too
pub fn delete_entry(p: &Parent, isdir: bool) -> Result<(), KernelError> {
    let (parent, name) = (&p.dir, p.name.as_slice());
    let dir = parent.get_inode().ok_or(KernelError::NotFound)?;
    let _w = super::dac::want_write(&dir)?;
    let c = cred();
    let _dir_lock = dir.lock();
    (|| {
        let victim = lookup_one(parent, name)?;
        let inode = victim.get_inode().ok_or(KernelError::NotFound)?;
        if p.slash && !isdir {
            return Err(if inode.mode().is_dir() {
                KernelError::IsDirectory
            } else {
                KernelError::NotDirectory
            });
        }
        super::dac::may_delete(&c, &dir, &inode, isdir)?;
        // The victim's lock, inside the parent's (Linux vfs_unlink /
        // vfs_rmdir): its link count never drops under a link of it, and
        // a mount on it (attach takes it too) is either seen here or
        // refused for the dead directory
        let victim_lock = inode.lock();
        let r = if super::mount::is_local_mountpoint(&victim) {
            Err(KernelError::Busy)
        } else if isdir {
            dir.i_op.rmdir(&dir, name).inspect(|_| inode.set_dead())
        } else {
            dir.i_op.unlink(&dir, name)
        };
        drop(victim_lock);
        r?;
        parent.remove_child(name);
        Ok(())
    })()
}

// ---------------------------------------------------------------------------
// User path names (Linux getname, path_init, filename_lookup,
// filename_parentat, filename_create)
// ---------------------------------------------------------------------------

/// Copy a path name in (Linux getname_flags): EFAULT for a bad pointer,
/// ENAMETOOLONG without a NUL in PATH_MAX bytes, ENOENT for an empty name
/// unless `empty_ok` (AT_EMPTY_PATH)
pub fn getname(ptr: u64, empty_ok: bool) -> Result<Vec<u8>, KernelError> {
    use crate::uaccess::{UaccessError, strndup_user_bytes};
    let name = strndup_user_bytes::<crate::arch::Uaccess>(ptr, PATH_MAX).map_err(|e| match e {
        UaccessError::TooLong => KernelError::NameTooLong,
        _ => KernelError::BadAddress,
    })?;
    if name.is_empty() && !empty_ok {
        return Err(KernelError::NotFound);
    }
    Ok(name)
}

/// getname for the calls where AT_EMPTY_PATH also takes a NULL name
/// (Linux getname_maybe_null: statx, fstatat)
pub fn getname_maybe_null(ptr: u64, at: i32) -> Result<Vec<u8>, KernelError> {
    let empty_ok = at & AT_EMPTY_PATH != 0;
    if ptr == 0 && empty_ok {
        return Ok(Vec::new());
    }
    getname(ptr, empty_ok)
}

/// Where a walk of `path` starts (Linux path_init): an absolute path at
/// the root (dirfd unused), else the cwd or `dirfd`, which must be open
/// (EBADF) and, unless the path is empty, a directory (ENOTDIR)
pub fn path_start(dirfd: i32, path: &[u8]) -> Result<Option<Path>, KernelError> {
    if path.starts_with(b"/") {
        return Ok(None);
    }
    if dirfd == AT_FDCWD {
        return Ok(crate::task::percpu::current_cwd());
    }
    let file = crate::fs::syscall::current_fd_table()
        .lock()
        .get(dirfd)
        .ok_or(KernelError::BadFd)?;
    if !path.is_empty() && !file.is_dir() {
        return Err(KernelError::NotDirectory);
    }
    Ok(Path::from_dentry(file.dentry.clone()))
}

/// Resolve `path` relative to `dirfd` (Linux filename_lookup); an empty
/// path (getname let it through: AT_EMPTY_PATH) names dirfd itself
pub fn filename_lookup(
    dirfd: i32,
    path: &[u8],
    flags: LookupFlags,
) -> Result<Arc<Dentry>, KernelError> {
    let start = path_start(dirfd, path)?;
    if path.is_empty() {
        return match start {
            Some(p) => Ok(p.dentry.clone()),
            None => current_mnt_ns()
                .get_root_dentry()
                .ok_or(KernelError::NotFound),
        };
    }
    lookup_path_at(start, path, flags)
}

/// Copy in and resolve a path argument (Linux user_path_at)
pub fn user_path_at(
    dirfd: i32,
    ptr: u64,
    flags: LookupFlags,
    empty_ok: bool,
) -> Result<Arc<Dentry>, KernelError> {
    filename_lookup(dirfd, &getname(ptr, empty_ok)?, flags)
}

/// What the last component of a path is (Linux enum last_type)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Last {
    Norm,
    Dot,
    DotDot,
    /// No component at all: "/" (or "///")
    Root,
}

/// A path split into its walked parent and its last component (Linux
/// filename_parentat)
pub struct Parent {
    pub dir: Arc<Dentry>,
    pub name: Vec<u8>,
    pub last: Last,
    /// The path ended in '/' after the last component
    pub slash: bool,
}

/// Walk all but the last component of `path` (Linux filename_parentat):
/// the parent must be a searchable directory; the last name is not
/// looked up, only classified
pub fn filename_parentat(dirfd: i32, path: &[u8]) -> Result<Parent, KernelError> {
    let start = path_start(dirfd, path)?;
    let end = path.iter().rposition(|&c| c != b'/').map_or(0, |i| i + 1);
    let slash = end < path.len();
    let trimmed = &path[..end];
    if trimmed.is_empty() {
        // Only slashes: the root, no last component
        let dir = lookup_path_at(None, b"/", LookupFlags::opendir())?;
        return Ok(Parent {
            dir,
            name: Vec::new(),
            last: Last::Root,
            slash: false,
        });
    }
    let (dir_path, name): (&[u8], &[u8]) = match trimmed.iter().rposition(|&c| c == b'/') {
        Some(i) => (&path[..=i], &trimmed[i + 1..]),
        None => (b"", trimmed),
    };
    let dir = match (dir_path.is_empty(), &start) {
        (true, Some(p)) => p.dentry.clone(),
        _ => lookup_path_at(start, dir_path, LookupFlags::opendir())?,
    };
    // link_path_walk: search permission before the last component too
    may_lookup(&cred(), &dir)?;
    let last = match name {
        b"." => Last::Dot,
        b".." => Last::DotDot,
        _ => Last::Norm,
    };
    Ok(Parent {
        dir,
        name: name.to_vec(),
        last,
        slash,
    })
}

/// The parent and new name for mkdir/mknod/symlink/link/bind (Linux
/// filename_create): "/", "." and ".." name nothing new (EEXIST); a
/// trailing slash is allowed only for a directory (`want_dir`)
pub fn filename_create(dirfd: i32, path: &[u8], want_dir: bool) -> Result<Parent, KernelError> {
    let mut p = filename_parentat(dirfd, path)?;
    if p.last != Last::Norm {
        return Err(KernelError::AlreadyExists);
    }
    if want_dir {
        p.slash = false;
    }
    Ok(p)
}

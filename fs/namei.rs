//! Path names and their resolution (Linux fs/namei.c)
//!
//! A user path is copied in once ([`getname`]) and resolved from its
//! start ([`path_start`]: root, cwd or dirfd) by walking the directory
//! tree. Every directory a name is looked up in needs search (MAY_EXEC)
//! permission for the caller (Linux may_lookup), including for "." and
//! "..". Creating and removing calls split off the last component
//! instead ([`filename_parentat`]).
//!
//! What stays fixed along one lookup, symlinks included, is its [`Nd`]
//! (Linux struct nameidata): the root and, for openat2's RESOLVE_*
//! restrictions, the scoped lookup's sequences.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::KernelError;
use super::dac::{MAY_EXEC, cred, permission_as};
use super::dentry::Dentry;
use super::file::flags::{AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_NOFOLLOW};
use super::inode::Inode;
use super::mount::{MOUNT_LOCK, Mount, follow_mount, is_path_reachable};
use super::path_ref::Path;
use crate::fs::syscall::PATH_MAX;
use crate::ns::current_mnt_ns;
use crate::task::Cred;
use crate::uaccess::UserPtr;

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
    /// linkat AT_EMPTY_PATH (Linux LOOKUP_LINKAT_EMPTY): a walk from
    /// `dirfd` needs the opener's creds or CAP_DAC_READ_SEARCH
    pub linkat_empty: bool,
    /// A magic link is ELOOP (Linux LOOKUP_NO_MAGICLINKS)
    pub no_magiclinks: bool,
    /// Any symlink is ELOOP (Linux LOOKUP_NO_SYMLINKS)
    pub no_symlinks: bool,
    /// The walk never leaves its start: EXDEV (Linux LOOKUP_BENEATH)
    pub beneath: bool,
    /// The start is the root (Linux LOOKUP_IN_ROOT)
    pub in_root: bool,
    /// The dcache alone, else EAGAIN (Linux LOOKUP_CACHED)
    pub cached: bool,
}

impl LookupFlags {
    /// Default flags for open()
    pub fn open() -> Self {
        Self {
            follow: true,
            ..Default::default()
        }
    }

    /// Flags for opendir()
    pub fn opendir() -> Self {
        Self {
            follow: true,
            directory: true,
            ..Default::default()
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

    /// Scoped to the start (Linux LOOKUP_IS_SCOPED)
    pub fn scoped(&self) -> bool {
        self.beneath || self.in_root
    }

    /// The RESOLVE_* restrictions alone, for the walk of another part
    /// of the same lookup (a parent, a symlink's target)
    fn resolve(self) -> Self {
        Self {
            no_xdev: self.no_xdev,
            no_magiclinks: self.no_magiclinks,
            no_symlinks: self.no_symlinks,
            beneath: self.beneath,
            in_root: self.in_root,
            cached: self.cached,
            ..Self::default()
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
    path_lookupat(start, path, flags).map(|p| p.dentry.clone())
}

/// As [`lookup_path_at`], the mount too (Linux path_lookupat)
pub fn path_lookupat(
    start: Option<Path>,
    path: &[u8],
    flags: LookupFlags,
) -> Result<Path, KernelError> {
    Nd::new(&start, flags)?.lookup(start, path, flags)
}

/// Child `name` of directory `parent`: the dcache, else the file system
/// (the new dentry is cached). A cached negative dentry is ENOENT; a
/// miss is cached as one (Linux d_add(dentry, NULL)) only on in-memory
/// filesystems (ramfs, devtmpfs), where a name is its exact bytes:
/// procfs and cgroupfs compute their entries behind the dcache, and
/// vfat matches other spellings (case, trailing dots), which Linux
/// handles with d_revalidate. Permission is the caller's business.
pub fn lookup_one(parent: &Arc<Dentry>, name: &[u8]) -> Result<Arc<Dentry>, KernelError> {
    // No file system here has longer names (Linux simple_lookup and the
    // disk file systems' lookups: ENAMETOOLONG)
    if name.len() > NAME_MAX {
        return Err(KernelError::NameTooLong);
    }
    if let Some(child) = cached(parent, name) {
        return if child.is_negative() {
            Err(KernelError::NotFound)
        } else {
            Ok(child)
        };
    }
    let dir = parent.get_inode().ok_or(KernelError::NotFound)?;
    match dir.i_op.lookup(&dir, name) {
        Ok(inode) => Dentry::alloc(parent, name, Some(inode)),
        Err(KernelError::NotFound) => {
            let in_memory = dir
                .superblock()
                .is_some_and(|sb| sb.fs_type.fs_flags == super::superblock::fs_flags::FS_IN_MEMORY);
            if in_memory {
                // A negative dentry is only a cache: none on ENOMEM
                let _ = Dentry::alloc(parent, name, None);
            }
            Err(KernelError::NotFound)
        }
        Err(e) => Err(e),
    }
}

/// The dcache's child `name` of `parent` if it is still valid (Linux
/// d_revalidate); an invalid one is dropped from the tree
fn cached(parent: &Arc<Dentry>, name: &[u8]) -> Option<Arc<Dentry>> {
    let child = parent.lookup_child(name)?;
    match child.get_inode() {
        Some(i) if !i.i_op.revalidate(&i) => {
            parent.remove_child(name);
            None
        }
        _ => Some(child),
    }
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
    if let Some(child) = cached(parent, name) {
        return if child.is_negative() {
            Err(KernelError::NotFound)
        } else {
            Ok(child)
        };
    }
    let dir = parent.get_inode().ok_or(KernelError::NotFound)?;
    let _lock = dir.lock_shared();
    lookup_one(parent, name)
}

/// Child `name` from the dcache alone (Linux lookup_fast in an RCU walk
/// with LOOKUP_CACHED): a miss, or an entry whose revalidation needs
/// the ref-walk, is EAGAIN. hk caches a miss (a negative entry) only on
/// in-memory filesystems, where Linux drops one at once
/// (always_delete_dentry), so it is a miss here too.
fn lookup_cached(parent: &Arc<Dentry>, name: &[u8]) -> Result<Arc<Dentry>, KernelError> {
    let child = parent.lookup_child(name).ok_or(KernelError::WouldBlock)?;
    match child.get_inode() {
        Some(i) if !i.i_op.revalidate_blocks(&i) && i.i_op.revalidate(&i) => Ok(child),
        _ => Err(KernelError::WouldBlock),
    }
}

/// may_lookup: `dir` must be a searchable directory
fn may_lookup(c: &Cred, dir: &Dentry) -> Result<(), KernelError> {
    let inode = dir.get_inode().ok_or(KernelError::NotFound)?;
    if !inode.mode().is_dir() {
        return Err(KernelError::NotDirectory);
    }
    permission_as(c, &inode, MAY_EXEC)
}

/// What is mounted on `p` (Linux handle_mounts): crossed, or EXDEV for
/// a no-xdev walk
fn step_mounts(p: Path, f: LookupFlags) -> Result<Path, KernelError> {
    if !f.no_xdev {
        return Ok(follow_mount(p));
    }
    let q = follow_mount(p.clone());
    if q.same(&p) {
        Ok(q)
    } else {
        Err(KernelError::CrossDevice)
    }
}

/// What stays fixed along one lookup, symlinks included (Linux struct
/// nameidata's root, m_seq and r_seq): the root absolute paths and ".."
/// stop at (a scoped lookup's own start), and for a scoped lookup the
/// mount and rename sequences sampled at its start
pub struct Nd {
    c: Cred,
    root: Path,
    seq: Option<(u32, u32)>,
}

impl Nd {
    /// Linux path_init's root and sequences: a scoped lookup's root is
    /// its start (dirfd or the cwd), any other the task's root
    pub fn new(start: &Option<Path>, f: LookupFlags) -> Result<Self, KernelError> {
        let seq = f
            .scoped()
            .then(|| (MOUNT_LOCK.read_begin(), super::dentry::rename_seq_begin()));
        let root = match start {
            Some(p) if f.scoped() => p.clone(),
            _ => nd_root()?,
        };
        Ok(Self {
            c: cred(),
            root,
            seq,
        })
    }

    /// Walk `path` from `start` (Linux path_lookupat + complete_walk)
    pub fn lookup(
        &self,
        start: Option<Path>,
        path: &[u8],
        f: LookupFlags,
    ) -> Result<Path, KernelError> {
        let p = self.walk(start, path, f, 0)?;
        self.complete(p)
    }

    /// A scoped lookup's result must still be under its root, whatever
    /// raced it (Linux complete_walk: path_is_under, EXDEV)
    fn complete(&self, p: Path) -> Result<Path, KernelError> {
        if self.seq.is_some() && !is_path_reachable(&p, &self.root) {
            return Err(KernelError::CrossDevice);
        }
        Ok(p)
    }

    /// A scoped lookup's ".." raced a mount change or a rename, so it
    /// may have left the root (Linux handle_dots: EAGAIN, for user space
    /// to retry)
    fn recheck(&self) -> Result<(), KernelError> {
        if let Some((m, r)) = self.seq
            && (MOUNT_LOCK.read_retry(m) || super::dentry::rename_seq_retry(r))
        {
            return Err(KernelError::WouldBlock);
        }
        Ok(())
    }

    /// An absolute symlink restarts at the root from `at` (Linux
    /// nd_jump_root): EXDEV beneath, and for a no-xdev walk off the
    /// root's mount
    fn jump_root(&self, at: &Path, f: LookupFlags) -> Result<(), KernelError> {
        if f.beneath || (f.no_xdev && !Arc::ptr_eq(&at.mnt, &self.root.mnt)) {
            return Err(KernelError::CrossDevice);
        }
        Ok(())
    }

    /// A magic link's jump from `dir` to `to` (Linux nd_jump_link):
    /// ELOOP under no-magiclinks; EXDEV to another mount under no-xdev,
    /// and always for a scoped lookup
    fn may_jump(&self, dir: &Path, to: Option<&Path>, f: LookupFlags) -> Result<(), KernelError> {
        if f.no_magiclinks {
            return Err(KernelError::TooManySymlinks);
        }
        let other = to.is_some_and(|p| !Arc::ptr_eq(&p.mnt, &dir.mnt));
        if (f.no_xdev && other) || f.scoped() {
            return Err(KernelError::CrossDevice);
        }
        Ok(())
    }

    fn walk(
        &self,
        start: Option<Path>,
        path: &[u8],
        mut f: LookupFlags,
        depth: usize,
    ) -> Result<Path, KernelError> {
        if depth > MAX_SYMLINK_DEPTH {
            return Err(KernelError::TooManySymlinks);
        }
        // A trailing slash asks for a directory, through a final symlink
        // (Linux link_path_walk: LOOKUP_FOLLOW | LOOKUP_DIRECTORY)
        if path.ends_with(b"/") {
            f.follow = true;
            f.directory = true;
        }
        // An absolute path starts at the root (nd_jump_root): never
        // beneath dirfd
        let abs = path.starts_with(b"/");
        if abs && f.beneath {
            return Err(KernelError::CrossDevice);
        }
        let mut cur = match start {
            Some(p) if !abs => p,
            _ => self.root.clone(),
        };
        let mut next = next_comp(path);
        while let Some((name, rest)) = next {
            next = next_comp(rest);
            may_lookup(&self.c, &cur.dentry)?;
            match name {
                b"." => continue,
                b".." => {
                    cur = follow_dotdot(cur, &self.root, f)?;
                    self.recheck()?;
                    continue;
                }
                _ => {}
            }
            let d = if f.cached {
                lookup_cached(&cur.dentry, name)?
            } else {
                lookup_slow(&cur.dentry, name)?
            };
            let child = step_mounts(Path::new(cur.mnt.clone(), d), f)?;
            let last = next.is_none();
            if (!last || f.follow) && child.get_inode().is_some_and(|n| n.mode().is_symlink()) {
                return self.follow_link(&cur, &child, rest, f, depth);
            }
            cur = child;
        }
        if f.directory && cur.get_inode().is_some_and(|n| !n.mode().is_dir()) {
            return Err(KernelError::NotDirectory);
        }
        Ok(cur)
    }

    /// Continue a walk through symlink `link` found in `dir`, with the
    /// components `rest` still to resolve after it (Linux pick_link)
    fn follow_link(
        &self,
        dir: &Path,
        link: &Path,
        rest: &[u8],
        f: LookupFlags,
        depth: usize,
    ) -> Result<Path, KernelError> {
        let inode = link.get_inode().ok_or(KernelError::NotFound)?;
        // fs.protected_symlinks first, then RESOLVE_NO_SYMLINKS or a
        // nosymfollow mount (Linux pick_link: may_follow_link, then
        // LOOKUP_NO_SYMLINKS / MNT_NOSYMFOLLOW on the link's mount)
        if let Some(d) = dir.dentry.get_inode() {
            super::dac::may_follow_link(&self.c, &d, &inode)?;
        }
        if f.no_symlinks || link.mnt.flags() & super::mount::MNT_NOSYMFOLLOW != 0 {
            return Err(KernelError::TooManySymlinks);
        }
        // An atime update or a magic link's get_link leaves the RCU
        // walk, which LOOKUP_CACHED forbids (try_to_unlazy fails: EAGAIN)
        let magic = inode.i_op.magic_link(&inode);
        if f.cached && (magic || inode.atime_needs_update(&link.mnt)) {
            return Err(KernelError::WouldBlock);
        }
        // A magic link jumps to its object (Linux nd_jump_link), after
        // its own access check; one that cannot is followed by its text
        let jump = inode.i_op.jump_link(&inode, &dir.mnt).transpose()?;
        let target = match jump {
            Some(_) => None,
            None => Some(inode.i_op.readlink(&inode)?),
        };
        inode.touch_atime(&link.mnt);
        if magic {
            self.may_jump(dir, jump.as_ref(), f)?;
        }
        if let Some(p) = jump {
            return self.walk_on(p, rest, f, depth);
        }
        let mut path = target.unwrap_or_default();
        if path.starts_with(b"/") {
            self.jump_root(dir, f)?;
        }
        // `rest` is empty or starts at a slash: the walk goes on through it
        path.extend_from_slice(rest);
        self.walk(Some(dir.clone()), &path, f, depth + 1)
    }

    /// Go on from a magic link's object `p` with what followed the link:
    /// a component after a non-directory is ENOTDIR, as is a trailing
    /// slash
    fn walk_on(
        &self,
        p: Path,
        rest: &[u8],
        mut f: LookupFlags,
        depth: usize,
    ) -> Result<Path, KernelError> {
        let from = rest.iter().position(|&c| c != b'/').unwrap_or(rest.len());
        if from == rest.len() && !rest.is_empty() {
            f.directory = true;
        }
        self.walk(Some(p), &rest[from..], f, depth + 1)
    }

    /// Walk all but the last component of `path` from `start` (Linux
    /// path_parentat): the parent must be a searchable directory; the
    /// last name is not looked up, only classified
    pub fn parentat(
        &self,
        start: Option<Path>,
        path: &[u8],
        f: LookupFlags,
    ) -> Result<Parent, KernelError> {
        let end = path.iter().rposition(|&c| c != b'/').map_or(0, |i| i + 1);
        let slash = end < path.len();
        let trimmed = &path[..end];
        if trimmed.is_empty() {
            // Only slashes: the root, no last component
            let (mnt, dir) = self.root.clone().into_parts();
            return Ok(Parent {
                dir,
                mnt,
                name: Vec::new(),
                last: Last::Root,
                slash: false,
            });
        }
        let (dir_path, name): (&[u8], &[u8]) = match trimmed.iter().rposition(|&c| c == b'/') {
            Some(i) => (&path[..=i], &trimmed[i + 1..]),
            None => (b"", trimmed),
        };
        let dirf = LookupFlags {
            follow: true,
            directory: true,
            ..f.resolve()
        };
        let (mnt, dir) = match (dir_path.is_empty(), start) {
            (true, Some(p)) => p,
            (_, start) => self.lookup(start, dir_path, dirf)?,
        }
        .into_parts();
        // link_path_walk: search permission before the last component too
        may_lookup(&self.c, &dir)?;
        let last = match name {
            b"." => Last::Dot,
            b".." => Last::DotDot,
            _ => Last::Norm,
        };
        Ok(Parent {
            dir,
            mnt,
            name: name.to_vec(),
            last,
            slash,
        })
    }

    /// Where an O_CREAT open of `p` lands (Linux open_last_lookups +
    /// step_into on the last component): while the last name is a
    /// symlink, its target's parent and last name, each link checked as
    /// a walk checks it (fs.protected_symlinks, then RESOLVE_NO_SYMLINKS
    /// or nosymfollow, then a magic link's and an absolute target's
    /// jump); ELOOP past MAX_SYMLINKS. A target ending in '/', "." or
    /// ".." is EISDIR.
    pub fn last_links(&self, mut p: Parent, f: LookupFlags) -> Result<Parent, KernelError> {
        const MAX_SYMLINKS: usize = 40;
        for _ in 0..MAX_SYMLINKS {
            let dir = Path::new(p.mnt.clone(), p.dir.clone());
            let nofollow = LookupFlags {
                follow: false,
                ..f.resolve()
            };
            let found = match self.walk(Some(dir.clone()), &p.name, nofollow, 0) {
                Ok(f) => f,
                Err(KernelError::NotFound) => return Ok(p),
                Err(e) => return Err(e),
            };
            let Some(inode) = found.get_inode().filter(|i| i.mode().is_symlink()) else {
                return Ok(p);
            };
            if let Some(d) = p.dir.get_inode() {
                super::dac::may_follow_link(&self.c, &d, &inode)?;
            }
            if f.no_symlinks || found.mnt.flags() & super::mount::MNT_NOSYMFOLLOW != 0 {
                return Err(KernelError::TooManySymlinks);
            }
            let target = inode.i_op.readlink(&inode)?;
            inode.touch_atime(&found.mnt);
            if inode.i_op.magic_link(&inode) {
                self.may_jump(&dir, None, f)?;
            }
            let start = if target.starts_with(b"/") {
                self.jump_root(&dir, f)?;
                None
            } else {
                Some(dir)
            };
            p = self.parentat(start, &target, f)?;
            if p.last != Last::Norm || p.slash {
                return Err(KernelError::IsDirectory);
            }
        }
        Err(KernelError::TooManySymlinks)
    }
}

/// The next component of `p` and what follows it, skipping slashes
/// (no allocation: the walk steps through the path in place)
fn next_comp(p: &[u8]) -> Option<(&[u8], &[u8])> {
    let start = p.iter().position(|&c| c != b'/')?;
    let p = &p[start..];
    let end = p.iter().position(|&c| c == b'/').unwrap_or(p.len());
    Some(p.split_at(end))
}

/// The root absolute paths start at and ".." stops at (Linux nd->root):
/// the task's fs root (chroot), else, for boot code with no fs yet,
/// where "/" lands in the namespace (the rootfs, not its nullfs root)
pub fn nd_root() -> Result<Path, KernelError> {
    if let Some(fs) = crate::task::percpu::current_fs() {
        return Ok(fs.get_root());
    }
    current_mnt_ns().root_path().ok_or(KernelError::NotFound)
}

/// ".." from `p` (Linux follow_dotdot): the root stays (EXDEV beneath);
/// at a mount's root, climb to its mountpoint (repeatedly, through
/// stacked mounts; EXDEV for a no-xdev walk) and take that one's
/// parent; a detached or namespace root stays like the root. Whatever
/// is mounted on the result is crossed (EXDEV for a no-xdev walk).
fn follow_dotdot(p: Path, root: &Path, f: LookupFlags) -> Result<Path, KernelError> {
    let in_root = |p: Path| {
        if f.beneath {
            Err(KernelError::CrossDevice)
        } else {
            Ok(p)
        }
    };
    let mut p = p;
    let mut climbed = false;
    loop {
        if p.same(root) {
            return in_root(p);
        }
        if !Arc::ptr_eq(&p.dentry, &p.mnt.root) {
            break;
        }
        match (p.mnt.get_parent(), p.mnt.get_mountpoint()) {
            (Some(m), Some(mp)) => p = Path::new(m, mp),
            _ => return in_root(p),
        }
        climbed = true;
    }
    if climbed && f.no_xdev {
        return Err(KernelError::CrossDevice);
    }
    match p.dentry.get_parent() {
        Some(parent) => step_mounts(Path::new(p.mnt.clone(), parent), f),
        None => Ok(p),
    }
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
    let w = p.mnt.want_write();
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
        // The dentry first, so an ENOMEM leaves no entry made
        let d = Dentry::prealloc(parent, name)?;
        let inode = make(&dir, &c)?;
        dir.touch_mc();
        Ok(Dentry::add(parent, d, Some(inode)))
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
    let _w = p.mnt.want_write()?;
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
            dir.i_op.rmdir(&dir, name).inspect(|()| inode.set_dead())
        } else {
            dir.i_op.unlink(&dir, name)
        };
        // The parent's mtime and ctime, the victim's ctime
        // (simple_unlink)
        if r.is_ok() {
            dir.touch_mc();
            inode.touch_c();
        }
        drop(victim_lock);
        r?;
        // A dentry no one else holds becomes negative in place; a held
        // one (a cwd, an open file) leaves the tree
        parent.d_delete(name, 1);
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
pub fn getname(ptr: UserPtr<u8>, empty_ok: bool) -> Result<Vec<u8>, KernelError> {
    use crate::uaccess::{UaccessError, strndup_user_bytes};
    let name = strndup_user_bytes(ptr.addr(), PATH_MAX).map_err(|e| match e {
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
pub fn getname_maybe_null(ptr: UserPtr<u8>, at: i32) -> Result<Vec<u8>, KernelError> {
    let empty_ok = at & AT_EMPTY_PATH != 0;
    if ptr.is_null() && empty_ok {
        return Ok(Vec::new());
    }
    getname(ptr, empty_ok)
}

/// Where a walk of `path` starts (Linux path_init): an absolute path at
/// the root (dirfd unused; EXDEV beneath), else, and for an in-root
/// lookup always, the cwd or `dirfd`, which must be open (EBADF), pass
/// the `linkat_empty` check (ENOENT) and, unless the path is empty, be a
/// directory (ENOTDIR)
pub fn path_start(dirfd: i32, path: &[u8], f: LookupFlags) -> Result<Option<Path>, KernelError> {
    if path.starts_with(b"/") && !f.in_root {
        if f.beneath {
            return Err(KernelError::CrossDevice);
        }
        return Ok(None);
    }
    if dirfd == AT_FDCWD {
        return Ok(crate::task::percpu::current_cwd());
    }
    let file = crate::fs::syscall::current_fd_table()
        .lock()
        .get(dirfd)
        .ok_or(KernelError::BadFd)?;
    if f.linkat_empty && !may_linkat_empty(&file) {
        return Err(KernelError::NotFound);
    }
    if !path.is_empty() && !file.is_dir() {
        return Err(KernelError::NotDirectory);
    }
    Ok(file.f_path())
}

/// Whether linkat may link `file` (Linux path_init LOOKUP_LINKAT_EMPTY):
/// its opener creds are the caller's, or the caller has
/// CAP_DAC_READ_SEARCH, so a descriptor passed to a less privileged
/// process cannot be linked back into the tree. Checked on the same fd
/// lookup the walk starts from. Linux compares cred pointers and uses
/// ns_capable(f_cred->user_ns); hk compares values (BUGS.md) and has
/// one user namespace.
fn may_linkat_empty(file: &crate::fs::File) -> bool {
    file.f_cred == crate::task::current_cred()
        || crate::task::capable(crate::task::CAP_DAC_READ_SEARCH)
}

/// Resolve `path` relative to `dirfd` (Linux filename_lookup); an empty
/// path (getname let it through: AT_EMPTY_PATH, O_EMPTYPATH) names
/// dirfd itself
pub fn filename_lookup(dirfd: i32, path: &[u8], flags: LookupFlags) -> Result<Path, KernelError> {
    let start = path_start(dirfd, path, flags)?;
    if path.is_empty() {
        let p = match start {
            Some(p) => p,
            None => nd_root()?,
        };
        // Linux path_lookupat's LOOKUP_DIRECTORY check, walk or not
        if flags.directory && p.get_inode().is_some_and(|n| !n.mode().is_dir()) {
            return Err(KernelError::NotDirectory);
        }
        return Ok(p);
    }
    path_lookupat(start, path, flags)
}

/// Copy in and resolve a path argument (Linux user_path_at)
pub fn user_path_at(
    dirfd: i32,
    ptr: UserPtr<u8>,
    flags: LookupFlags,
    empty_ok: bool,
) -> Result<Path, KernelError> {
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
    /// The mount `dir` is in
    pub mnt: Arc<Mount>,
    pub name: Vec<u8>,
    pub last: Last,
    /// The path ended in '/' after the last component
    pub slash: bool,
}

/// Walk all but the last component of `path` (Linux filename_parentat):
/// see [`Nd::parentat`]
pub fn filename_parentat(dirfd: i32, path: &[u8]) -> Result<Parent, KernelError> {
    let f = LookupFlags::default();
    let start = path_start(dirfd, path, f)?;
    Nd::new(&start, f)?.parentat(start, path, f)
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

#[cfg(test)]
mod tests {
    use super::next_comp;

    #[test]
    fn components() {
        assert_eq!(next_comp(b"//a//b/"), Some((&b"a"[..], &b"//b/"[..])));
        assert_eq!(next_comp(b"//b/"), Some((&b"b"[..], &b"/"[..])));
        assert_eq!(next_comp(b"/"), None);
        assert_eq!(next_comp(b""), None);
    }
}

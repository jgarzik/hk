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
//!
//! A lookup walks in RCU mode first ([`rcu`]: no reference, no lock, no
//! store to a shared dentry), going on in ref mode where it must; if it
//! cannot, it is ECHILD and done again in ref mode from the start
//! (Linux filename_lookup's retry without LOOKUP_RCU).

mod rcu;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::Cell;

use self::rcu::Lazy;

use crate::fs::KernelError;
use crate::fs::dac::{MAY_EXEC, cred, permission_as};
use crate::fs::dentry::{Dentry, DentryRef, d_invalidate};
use crate::fs::file::flags::{AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_NOFOLLOW};
use crate::fs::inode::{Inode, Link};
use crate::fs::mount::{
    MOUNT_LOCK, MountRef, choose_mountpoint, follow_mount, is_path_reachable, path_connected,
};
use crate::fs::path_ref::Path;
use crate::fs::syscall::PATH_MAX;
use crate::ns::current_mnt_ns;
use crate::task::Cred;
use crate::uaccess::UserPtr;

/// Maximum number of symlinks to follow (prevent infinite loops)
const MAX_SYMLINK_DEPTH: usize = 40;

/// An RCU walk cannot go on (Linux -ECHILD): its lookup is done again
/// in ref mode; never reaches user space
const ECHILD: KernelError = KernelError::NoChild;

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
pub fn lookup_path(path: &[u8]) -> Result<DentryRef, KernelError> {
    lookup_path_flags(path, LookupFlags::open())
}

/// Look up a path relative to the current directory with specific flags
pub fn lookup_path_flags(path: &[u8], flags: LookupFlags) -> Result<DentryRef, KernelError> {
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
) -> Result<DentryRef, KernelError> {
    path_lookupat(start, path, flags).map(|p| p.dentry.clone())
}

/// As [`lookup_path_at`], the mount too (Linux filename_lookup's
/// path_lookupat: in RCU mode, again in ref mode if that is ECHILD)
pub fn path_lookupat(
    start: Option<Path>,
    path: &[u8],
    flags: LookupFlags,
) -> Result<Path, KernelError> {
    let s = start.as_ref();
    match Nd::new(s, flags, true)?.lookup(s, path, flags) {
        Err(ECHILD) => Nd::new(s, flags, false)?.lookup(s, path, flags),
        r => r,
    }
}

/// Child `name` of directory `parent`: the dcache, else the file system
/// (the new dentry is cached). A cached negative dentry is ENOENT; a
/// miss is cached as one (Linux d_add(dentry, NULL)) only on in-memory
/// filesystems (ramfs, devtmpfs), where a name is its exact bytes:
/// procfs and cgroupfs compute their entries behind the dcache, and
/// vfat matches other spellings (case, trailing dots), which Linux
/// handles with d_revalidate. Permission is the caller's business.
pub fn lookup_one(parent: &DentryRef, name: &[u8]) -> Result<DentryRef, KernelError> {
    // No file system here has longer names (Linux simple_lookup and the
    // disk file systems' lookups: ENAMETOOLONG)
    if name.len() > NAME_MAX {
        return Err(KernelError::NameTooLong);
    }
    if let Some(child) = cached(parent, name)? {
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
/// lookup_dcache): a stale one is invalidated and None, a revalidation
/// error returned
fn cached(parent: &DentryRef, name: &[u8]) -> Result<Option<DentryRef>, KernelError> {
    match parent.lookup_child(name) {
        Some(child) => d_revalidate(child, None),
        None => Ok(None),
    }
}

/// Linux d_revalidate in ref mode and its callers' handling (`status
/// <= 0`): `child` if valid; if stale, that dentry invalidated
/// (d_invalidate) and None; an error returned, nothing invalidated.
/// `rcu`: what an RCU walk's revalidation said (Linux lookup_fast: a
/// stale or failed answer stands, ECHILD asks again in ref mode).
fn d_revalidate(
    child: DentryRef,
    rcu: Option<Result<bool, KernelError>>,
) -> Result<Option<DentryRef>, KernelError> {
    // Only a positive dentry has a revalidation (its inode's operations)
    let Some(i) = child.get_inode() else {
        return Ok(Some(child));
    };
    let valid = match rcu {
        Some(Err(ECHILD)) | None => i.i_op.revalidate(&i, false),
        Some(s) => s,
    }?;
    if valid {
        return Ok(Some(child));
    }
    d_invalidate(&child);
    Ok(None)
}

/// Longest name of one path component (Linux NAME_MAX)
pub const NAME_MAX: usize = 255;

/// Path-walk lookup (Linux lookup_fast + lookup_slow): a dcache hit
/// needs no lock; a miss asks the file system under the directory's
/// shared inode lock, so it cannot race a create/unlink/rename there
fn lookup_slow(parent: &DentryRef, name: &[u8]) -> Result<DentryRef, KernelError> {
    if name.len() > NAME_MAX {
        return Err(KernelError::NameTooLong);
    }
    if let Some(child) = cached(parent, name)? {
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

/// The ref-mode half of lookup_fast after try_to_unlazy_next: `child`,
/// found for `name` in `parent` by an RCU walk whose revalidation said
/// `rcu` (Linux: ECHILD revalidated again without LOOKUP_RCU); a stale
/// one is invalidated and the name looked up again (d_invalidate, then
/// lookup_slow), an error returned
fn lookup_fast_ref(
    parent: &DentryRef,
    child: DentryRef,
    name: &[u8],
    rcu: Result<bool, KernelError>,
) -> Result<DentryRef, KernelError> {
    if child.is_negative() {
        return Err(KernelError::NotFound);
    }
    match d_revalidate(child, Some(rcu))? {
        Some(c) => Ok(c),
        None => lookup_slow(parent, name),
    }
}

/// What a ref-mode step gives: the walk goes on from it, or it was a
/// symlink whose walk ended the lookup
enum Walked {
    On(Path),
    Done(Path),
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
/// nameidata's root, m_seq and r_seq, and LOOKUP_RCU): the root
/// absolute paths and ".." stop at (a scoped lookup's own start), the
/// mount and rename sequences sampled at its start (path_init), and
/// whether its walks still start in RCU mode
pub struct Nd {
    c: Cred,
    root: Path,
    /// LOOKUP_RCU: a walk tries RCU mode first (`rcu::walk_rcu`);
    /// cleared once one left it (leave_rcu), so the rest of the lookup
    /// runs in ref mode
    rcu: Cell<bool>,
    /// MOUNT_LOCK's sequence at the start (nd->m_seq): an RCU walk's
    /// legitimize checks it; a scoped lookup's ".." too
    m_seq: u32,
    /// RENAME_LOCK's sequence at the start (nd->r_seq), for a scoped
    /// lookup's ".."
    r_seq: u32,
    /// LOOKUP_IS_SCOPED
    scoped: bool,
}

impl Nd {
    /// Linux path_init's root and sequences: a scoped lookup's root is
    /// its start (dirfd or the cwd), any other the task's root. `rcu`:
    /// LOOKUP_RCU, which LOOKUP_CACHED needs (EAGAIN without: the
    /// retry of a walk that had to leave RCU mode).
    pub fn new(start: Option<&Path>, f: LookupFlags, rcu: bool) -> Result<Self, KernelError> {
        if f.cached && !rcu {
            return Err(KernelError::WouldBlock);
        }
        let m_seq = MOUNT_LOCK.read_begin();
        let r_seq = super::dentry::rename_seq_begin();
        let root = match start {
            Some(p) if f.scoped() => p.clone(),
            _ => nd_root()?,
        };
        Ok(Self {
            c: cred(),
            root,
            rcu: Cell::new(rcu),
            m_seq,
            r_seq,
            scoped: f.scoped(),
        })
    }

    /// Walk `path` from `start` (Linux path_lookupat + complete_walk)
    pub fn lookup(
        &self,
        start: Option<&Path>,
        path: &[u8],
        f: LookupFlags,
    ) -> Result<Path, KernelError> {
        let p = self.walk(start, path, f, 0)?;
        self.complete(p)
    }

    /// A scoped lookup's result must still be under its root, whatever
    /// raced it (Linux complete_walk: path_is_under, EXDEV)
    fn complete(&self, p: Path) -> Result<Path, KernelError> {
        if self.scoped && !is_path_reachable(&p, &self.root) {
            return Err(KernelError::CrossDevice);
        }
        Ok(p)
    }

    /// A scoped lookup's ".." raced a mount change or a rename, so it
    /// may have left the root (Linux handle_dots: EAGAIN, for user space
    /// to retry)
    fn recheck(&self) -> Result<(), KernelError> {
        if self.scoped
            && (MOUNT_LOCK.read_retry(self.m_seq) || super::dentry::rename_seq_retry(self.r_seq))
        {
            return Err(KernelError::WouldBlock);
        }
        Ok(())
    }

    /// An absolute symlink restarts at the root from `at` (Linux
    /// nd_jump_root): EXDEV beneath, and for a no-xdev walk off the
    /// root's mount
    fn jump_root(&self, at: &Path, f: LookupFlags) -> Result<(), KernelError> {
        if f.beneath || (f.no_xdev && !MountRef::ptr_eq(&at.mnt, &self.root.mnt)) {
            return Err(KernelError::CrossDevice);
        }
        Ok(())
    }

    /// A magic link's jump from `dir` to `to` (Linux nd_jump_link):
    /// ELOOP under no-magiclinks; EXDEV to another mount under no-xdev,
    /// and always for a scoped lookup
    fn may_jump(&self, dir: &Path, to: &Path, f: LookupFlags) -> Result<(), KernelError> {
        if f.no_magiclinks {
            return Err(KernelError::TooManySymlinks);
        }
        let other = !MountRef::ptr_eq(&to.mnt, &dir.mnt);
        if (f.no_xdev && other) || f.scoped() {
            return Err(KernelError::CrossDevice);
        }
        Ok(())
    }

    /// link_path_walk + lookup_last from `start` (the root for an
    /// absolute path): in RCU mode while the lookup is still in it
    /// (depth 0: RCU mode is left before any symlink's body), else in
    /// ref mode
    fn walk(
        &self,
        start: Option<&Path>,
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
        let start = match start {
            Some(p) if !abs => p,
            _ => &self.root,
        };
        if self.rcu.get() {
            return self.walk_rcu(start, path, f);
        }
        self.walk_ref(start.clone(), path, f, depth)
    }

    /// The walk's loop in ref mode, from `cur` (Linux link_path_walk
    /// without LOOKUP_RCU)
    fn walk_ref(
        &self,
        mut cur: Path,
        path: &[u8],
        f: LookupFlags,
        depth: usize,
    ) -> Result<Path, KernelError> {
        let mut next = next_comp(path);
        while let Some((name, rest)) = next {
            next = next_comp(rest);
            may_lookup(&self.c, &cur.dentry)?;
            cur = match name {
                b"." => cur,
                b".." => {
                    let p = follow_dotdot(cur, &self.root, f)?;
                    self.recheck()?;
                    p
                }
                _ => {
                    let d = lookup_slow(&cur.dentry, name)?;
                    match self.step(cur, d, rest, f, depth)? {
                        Walked::On(p) => p,
                        Walked::Done(p) => return Ok(p),
                    }
                }
            };
        }
        self.finish(cur, f)
    }

    /// The end of a walk: LOOKUP_DIRECTORY's check (Linux
    /// path_lookupat: ENOTDIR)
    fn finish(&self, p: Path, f: LookupFlags) -> Result<Path, KernelError> {
        if f.directory && p.get_inode().is_some_and(|n| !n.mode().is_dir()) {
            return Err(KernelError::NotDirectory);
        }
        Ok(p)
    }

    /// step_into in ref mode: onto `d`, found in `cur`, with `rest` to
    /// walk after it: what is mounted on it crossed, a symlink to follow
    /// followed (its walk is the rest of this one)
    fn step(
        &self,
        cur: Path,
        d: DentryRef,
        rest: &[u8],
        f: LookupFlags,
        depth: usize,
    ) -> Result<Walked, KernelError> {
        let last = next_comp(rest).is_none();
        let child = step_mounts(Path::new(cur.mnt.clone(), d), f)?;
        if (!last || f.follow) && child.get_inode().is_some_and(|n| n.mode().is_symlink()) {
            self.pick_link(&cur, &child, last, f)?;
            return self
                .get_link(&cur, &child, rest, f, depth)
                .map(Walked::Done);
        }
        Ok(Walked::On(child))
    }

    /// Go on in ref mode from where an RCU walk left RCU mode (Linux:
    /// the same loop after try_to_unlazy)
    fn unlazied(&self, l: Lazy<'_>, f: LookupFlags) -> Result<Path, KernelError> {
        let (cur, d, rest) = match l {
            Lazy::Done(p) => return self.finish(p, f),
            Lazy::Comp(cur, path) => return self.walk_ref(cur, path, f, 0),
            Lazy::Link { cur, link, rest } => return self.get_link(&cur, &link, rest, f, 0),
            Lazy::Lookup(cur, name, rest) => {
                let d = lookup_slow(&cur.dentry, name)?;
                (cur, d, rest)
            }
            Lazy::Child {
                cur,
                child,
                rest,
                dots: true,
                ..
            } => {
                let p = step_mounts(Path::new(cur.mnt.clone(), child), f)?;
                self.recheck()?;
                return self.walk_ref(p, rest, f, 0);
            }
            Lazy::Child {
                cur,
                child,
                name,
                rest,
                reval,
                dots: false,
            } => {
                let d = match reval {
                    Some(s) => lookup_fast_ref(&cur.dentry, child, name, s)?,
                    None => child,
                };
                (cur, d, rest)
            }
        };
        match self.step(cur, d, rest, f, 0)? {
            Walked::On(p) => self.walk_ref(p, rest, f, 0),
            Walked::Done(p) => Ok(p),
        }
    }

    /// pick_link's checks of symlink `link` found in `dir`:
    /// fs.protected_symlinks for the trailing link only (`last`:
    /// WALK_TRAILING), then RESOLVE_NO_SYMLINKS or a nosymfollow mount
    /// (LOOKUP_NO_SYMLINKS / MNT_NOSYMFOLLOW on the link's mount)
    fn pick_link(
        &self,
        dir: &Path,
        link: &Path,
        last: bool,
        f: LookupFlags,
    ) -> Result<(), KernelError> {
        let inode = link.get_inode().ok_or(KernelError::NotFound)?;
        if last && let Some(d) = dir.dentry.get_inode() {
            super::dac::may_follow_link(&self.c, &d, &inode)?;
        }
        if f.no_symlinks || link.mnt.flags() & super::mount::MNT_NOSYMFOLLOW != 0 {
            return Err(KernelError::TooManySymlinks);
        }
        Ok(())
    }

    /// The rest of pick_link, in ref mode: continue the walk through
    /// symlink `link` found in `dir`, with the components `rest` still
    /// to resolve after it (its atime touched, its ->get_link)
    fn get_link(
        &self,
        dir: &Path,
        link: &Path,
        rest: &[u8],
        f: LookupFlags,
        depth: usize,
    ) -> Result<Path, KernelError> {
        let inode = link.get_inode().ok_or(KernelError::NotFound)?;
        let got = inode.i_op.get_link(&inode)?;
        inode.touch_atime(&link.mnt);
        let mut path = match got {
            // A magic link: the walk goes on from its object
            Link::Jump(p) => {
                self.may_jump(dir, &p, f)?;
                return self.walk_on(p, rest, f, depth);
            }
            Link::Text(t) => t,
        };
        if path.starts_with(b"/") {
            self.jump_root(dir, f)?;
        }
        // `rest` is empty or starts at a slash: the walk goes on through it
        path.extend_from_slice(rest);
        self.walk(Some(dir), &path, f, depth + 1)
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
        self.walk(Some(&p), &rest[from..], f, depth + 1)
    }

    /// Walk all but the last component of `path` from `start` (Linux
    /// path_parentat): the parent must be a searchable directory; the
    /// last name is not looked up, only classified
    pub fn parentat(
        &self,
        start: Option<&Path>,
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
            (true, Some(p)) => p.clone(),
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
    /// or nosymfollow, then an absolute target's jump); a magic link's
    /// object itself (nd_jump_link: there is no name left to create);
    /// ELOOP past MAX_SYMLINKS. A target ending in '/', "." or ".." is
    /// EISDIR.
    pub fn last_links(&self, mut p: Parent, f: LookupFlags) -> Result<CreateAt, KernelError> {
        const MAX_SYMLINKS: usize = 40;
        for _ in 0..MAX_SYMLINKS {
            let dir = Path::new(p.mnt.clone(), p.dir.clone());
            let nofollow = LookupFlags {
                follow: false,
                ..f.resolve()
            };
            let found = match self.walk(Some(&dir), &p.name, nofollow, 0) {
                Ok(f) => f,
                Err(KernelError::NotFound) => return Ok(CreateAt::Name(p)),
                Err(e) => return Err(e),
            };
            let Some(inode) = found.get_inode().filter(|i| i.mode().is_symlink()) else {
                return Ok(CreateAt::Name(p));
            };
            if let Some(d) = p.dir.get_inode() {
                super::dac::may_follow_link(&self.c, &d, &inode)?;
            }
            if f.no_symlinks || found.mnt.flags() & super::mount::MNT_NOSYMFOLLOW != 0 {
                return Err(KernelError::TooManySymlinks);
            }
            let got = inode.i_op.get_link(&inode)?;
            inode.touch_atime(&found.mnt);
            let target = match got {
                Link::Jump(o) => {
                    self.may_jump(&dir, &o, f)?;
                    return Ok(CreateAt::Object(o));
                }
                Link::Text(t) => t,
            };
            let start = if target.starts_with(b"/") {
                self.jump_root(&dir, f)?;
                None
            } else {
                Some(dir)
            };
            p = self.parentat(start.as_ref(), &target, f)?;
            if p.last != Last::Norm || p.slash {
                return Err(KernelError::IsDirectory);
            }
        }
        Err(KernelError::TooManySymlinks)
    }
}

/// Where an O_CREAT open lands ([`Nd::last_links`])
pub enum CreateAt {
    /// A name to look up or create in its parent
    Name(Parent),
    /// An existing object a magic link jumped to
    Object(Path),
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
/// at a mount's root, climb to its mountpoint (`choose_mountpoint`:
/// through mounts stacked on their parent's root; EXDEV for a no-xdev
/// walk) and take that one's parent; a climb that meets the root, or a
/// detached or namespace root, stays like the root. A parent a rename
/// left outside the mount's root is ENOENT (path_connected). Whatever
/// is mounted on the result is crossed, the root's included (EXDEV for
/// a no-xdev walk).
fn follow_dotdot(p: Path, root: &Path, f: LookupFlags) -> Result<Path, KernelError> {
    // Where ".." stays put, it still lands on what is mounted there
    // (Linux in_root, then step_into's handle_mounts)
    let in_root = |p: Path| {
        if f.beneath {
            Err(KernelError::CrossDevice)
        } else {
            step_mounts(p, f)
        }
    };
    if p.same(root) {
        return in_root(p);
    }
    let mut p = p;
    if DentryRef::ptr_eq(&p.dentry, &p.mnt.root) {
        let Some(up) = choose_mountpoint(&p.mnt, root) else {
            return in_root(p);
        };
        p = up;
        if f.no_xdev {
            return Err(KernelError::CrossDevice);
        }
    }
    // A root dentry is its own parent (Linux dget_parent of IS_ROOT)
    let parent = p.dentry.get_parent().unwrap_or_else(|| p.dentry.clone());
    if !path_connected(&p.mnt, &parent, &crate::sync::rcu::read_lock()) {
        return Err(KernelError::NotFound);
    }
    step_mounts(Path::new(p.mnt.clone(), parent), f)
}

/// Create the entry `p` names (Linux filename_create +
/// vfs_mkdir/mknod/symlink/link) under the parent's lock: EEXIST first,
/// ENOENT for a name with a trailing slash that is not a directory to
/// make, then may_create (write+search), then `make` builds the inode
/// with the caller's credentials; the new dentry is cached
pub fn create_entry(
    p: &Parent,
    make: impl FnOnce(&Arc<Inode>, &Cred) -> Result<Arc<Inode>, KernelError>,
) -> Result<DentryRef, KernelError> {
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
            // What is cached below goes first (Linux vfs_rmdir:
            // shrink_dcache_parent, then S_DEAD)
            dir.i_op.rmdir(&dir, name).inspect(|()| {
                super::dentry::d_drop_tree(&victim);
                inode.set_dead();
            })
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
    filename_lookup_from(path_start(dirfd, path, flags)?, path, flags)
}

/// Resolve `path` from `start` (None: the root), an empty path naming
/// `start` itself: [`filename_lookup`]'s walk, also for a start that is
/// no descriptor (Linux LOOKUP_ROOT: file_open_root)
pub fn filename_lookup_from(
    start: Option<Path>,
    path: &[u8],
    flags: LookupFlags,
) -> Result<Path, KernelError> {
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
    pub dir: DentryRef,
    /// The mount `dir` is in
    pub mnt: MountRef,
    pub name: Vec<u8>,
    pub last: Last,
    /// The path ended in '/' after the last component
    pub slash: bool,
}

/// Walk all but the last component of `path` (Linux filename_parentat):
/// see [`Nd::parentat`]; in RCU mode, again in ref mode if that is
/// ECHILD
pub fn filename_parentat(dirfd: i32, path: &[u8]) -> Result<Parent, KernelError> {
    let f = LookupFlags::default();
    let start = path_start(dirfd, path, f)?;
    let s = start.as_ref();
    match Nd::new(s, f, true)?.parentat(s, path, f) {
        Err(ECHILD) => Nd::new(s, f, false)?.parentat(s, path, f),
        r => r,
    }
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
    use super::*;
    use crate::fs::inode::{InodeMode, InodeOps, NULL_INODE_OPS, Timespec};
    use alloc::sync::Weak;

    /// Revalidation says `R`: Ok(false) stale, Err(EIO) an error
    struct Reval(Result<bool, KernelError>);

    impl InodeOps for Reval {
        fn lookup(&self, _: &Inode, _: &[u8]) -> Result<Arc<Inode>, KernelError> {
            Err(KernelError::NotFound)
        }
        fn revalidate(&self, _: &Inode, _: bool) -> Result<bool, KernelError> {
            self.0
        }
    }

    static STALE: Reval = Reval(Ok(false));
    static BROKEN: Reval = Reval(Err(KernelError::Io));

    fn inode(ops: &'static dyn InodeOps) -> Arc<Inode> {
        let m = InodeMode::directory(0o755);
        let t = Timespec::from_secs(0);
        Inode::alloc(Inode::new(1, m, 0, 0, 0, t, Weak::new(), ops)).unwrap()
    }

    fn root() -> DentryRef {
        DentryRef::new(Dentry::new_root(inode(&NULL_INODE_OPS), Weak::new())).unwrap()
    }

    /// A stale child is invalidated itself (Linux d_invalidate(dentry)):
    /// a dentry that took its name since stays cached, and is the answer
    #[test]
    fn stale_invalidates_only_itself() {
        let r = root();
        let a = Dentry::alloc(&r, b"x", Some(inode(&STALE))).unwrap();
        drop(r.remove_child(b"x"));
        let b = Dentry::alloc(&r, b"x", Some(inode(&NULL_INODE_OPS))).unwrap();
        let d = lookup_fast_ref(&r, a, b"x", Err(ECHILD)).unwrap();
        assert!(DentryRef::ptr_eq(&d, &b) && !b.d_unhashed());
    }

    /// A stale cached child leaves the tree and the name is asked again
    #[test]
    fn stale_is_dropped() {
        let r = root();
        let a = Dentry::alloc(&r, b"x", Some(inode(&STALE))).unwrap();
        assert!(cached(&r, b"x").unwrap().is_none());
        assert!(a.d_unhashed() && r.lookup_child(b"x").is_none());
    }

    /// A revalidation error is the lookup's (Linux lookup_fast and
    /// lookup_dcache: ERR_PTR(status)), and the dentry stays cached; an
    /// RCU walk's stale answer stands without being asked again
    #[test]
    fn reval_error_returned() {
        let r = root();
        let a = Dentry::alloc(&r, b"x", Some(inode(&BROKEN))).unwrap();
        let e = lookup_fast_ref(&r, a.clone(), b"x", Err(ECHILD));
        assert_eq!(e.err(), Some(KernelError::Io));
        assert_eq!(cached(&r, b"x").err(), Some(KernelError::Io));
        assert!(!a.d_unhashed());
        let _ = lookup_fast_ref(&r, a.clone(), b"x", Ok(false));
        assert!(a.d_unhashed());
    }

    #[test]
    fn components() {
        assert_eq!(next_comp(b"//a//b/"), Some((&b"a"[..], &b"//b/"[..])));
        assert_eq!(next_comp(b"//b/"), Some((&b"b"[..], &b"/"[..])));
        assert_eq!(next_comp(b"/"), None);
        assert_eq!(next_comp(b""), None);
    }
}

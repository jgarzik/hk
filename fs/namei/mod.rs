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

use alloc::vec::Vec;
use core::cell::{Cell, OnceCell};

use self::rcu::{Held, HeldFrame, Lazy, To};

use crate::fs::File;
use crate::fs::KernelError;
use crate::fs::dac::{MAY_EXEC, permission_as};
use crate::fs::dentry::{Dentry, DentryRef, LookupBits, d_invalidate};
use crate::fs::file::flags::{AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_NOFOLLOW};
use crate::fs::fsstruct::FsStruct;
use crate::fs::inode::{Inode, InodeMode, InodeRef, Link, Uid};
use crate::fs::mount::{
    MOUNT_LOCK, MountRef, choose_mountpoint, follow_mount, is_path_reachable, path_connected,
};
use crate::fs::path_ref::Path;
use crate::fs::syscall::PATH_MAX;
use crate::ns::current_mnt_ns;
use crate::task::Cred;
use crate::task::fdtable::FdRef;
use crate::task::percpu::Cur;
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
    /// An open's intent (Linux op->intent: LOOKUP_OPEN, LOOKUP_CREATE,
    /// LOOKUP_EXCL), which the last component's lookup carries (Linux
    /// open_last_lookups: nd->flags |= op->intent, cleared again when
    /// it is a symlink to follow)
    pub intent: LookupBits,
    /// The walk is of a parent's name only, every component one on the
    /// way (Linux path_parentat: link_path_walk's LOOKUP_PARENT
    /// throughout, the last name not walked)
    pub parent: bool,
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

    /// What a d_revalidate sees of them when it is asked for a component
    /// (Linux nd->flags then): the RESOLVE_* restrictions and
    /// LOOKUP_LINKAT_EMPTY always; on the way (LOOKUP_PARENT: any
    /// component but the walk's `last`, every one of a parent's walk),
    /// the caller's FOLLOW and DIRECTORY; on the last, those and an
    /// open's intent (LOOKUP_PARENT cleared, op->intent added)
    pub fn bits(&self, last: bool) -> LookupBits {
        let mut b = LookupBits::empty();
        b.set(LookupBits::LINKAT_EMPTY, self.linkat_empty);
        b.set(LookupBits::CACHED, self.cached);
        b.set(LookupBits::NO_SYMLINKS, self.no_symlinks);
        b.set(LookupBits::NO_MAGICLINKS, self.no_magiclinks);
        b.set(LookupBits::NO_XDEV, self.no_xdev);
        b.set(LookupBits::BENEATH, self.beneath);
        b.set(LookupBits::IN_ROOT, self.in_root);
        // A parent's walk follows and wants directories by itself; its
        // caller asked for neither (Linux path_parentat's flags)
        if self.parent {
            return b | LookupBits::PARENT;
        }
        b.set(LookupBits::FOLLOW, self.follow);
        b.set(LookupBits::DIRECTORY, self.directory);
        if last {
            b | self.intent
        } else {
            b | LookupBits::PARENT
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
    path_lookup(Start::Cwd, path, flags).map(|p| p.dentry.clone())
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
    match &start {
        Some(p) => path_lookup(Start::path(p), path, flags),
        None => path_lookup(Start::Root, path, flags),
    }
}

/// [`path_lookupat`] from `start` (Linux filename_lookup's
/// path_lookupat: in RCU mode, again in ref mode if that is ECHILD)
pub fn path_lookup(start: Start<'_>, path: &[u8], flags: LookupFlags) -> Result<Path, KernelError> {
    match Nd::new(start, flags, true)?.lookup(start, path, flags) {
        Err(ECHILD) => Nd::new(start, flags, false)?.lookup(start, path, flags),
        r => r,
    }
}

/// Where a walk starts (Linux path_init: nd->dfd, or a path the caller
/// holds): the cwd is read by the walk itself, under the fs_struct's
/// sequence with no reference in RCU mode
#[derive(Clone, Copy)]
pub enum Start<'a> {
    /// The root
    Root,
    /// The cwd (AT_FDCWD); the root for boot code, which has none
    Cwd,
    /// A path the caller holds for the lookup (a dirfd's file, a
    /// parent already walked)
    At(&'a MountRef, &'a DentryRef),
    /// file_open_root's root (Linux ND_ROOT_PRESET): the walk starts
    /// there, and absolute names, absolute symlink bodies and ".." stop
    /// there; held by the caller
    Preset(&'a Path),
}

impl<'a> Start<'a> {
    /// A held path
    pub fn path(p: &'a Path) -> Self {
        Self::At(&p.mnt, &p.dentry)
    }
}

/// What a user path's walk starts from, held for the lookup (Linux
/// path_init's fdget_raw: the dirfd's file, whose f_path the walk
/// borrows with no path reference)
pub enum Dfd {
    Root,
    Cwd,
    /// A dirfd's file, which has a mount: with no reference from a
    /// table no other task uses (`fdget_raw`)
    File(FdRef),
    /// A path (an internal file's, or one the caller gave)
    Path(Path),
    /// file_open_root's root (`Start::Preset`)
    Preset(Path),
}

impl Dfd {
    /// The walk's start, borrowed from this
    pub fn start(&self) -> Start<'_> {
        match self {
            Self::Root => Start::Root,
            Self::Cwd => Start::Cwd,
            Self::File(f) => match f.mnt() {
                Some(m) => Start::At(m, &f.dentry),
                None => Start::Root,
            },
            Self::Path(p) => Start::path(p),
            Self::Preset(p) => Start::Preset(p),
        }
    }
}

/// The current task's fs_struct, borrowed (Linux current->fs): None for
/// boot code before pid 1 has one; a kernel thread's is the shared one
fn fs_of(me: &Cur) -> Option<&FsStruct> {
    if me.tid() == 0 {
        return None;
    }
    // SAFETY: the current task, which replaces its fs_struct only
    // itself (unshare, setns, exit), never while it walks a path
    match unsafe { crate::task::Task::fs(me) } {
        Some(fs) => Some(fs),
        None => crate::fs::fsstruct::kthread_fs_ref(me),
    }
}

/// `start` as a path, a reference (Linux get_fs_pwd, path_get): an
/// empty name's result, a ref-mode walk's start
fn start_path(start: Start<'_>) -> Result<Path, KernelError> {
    match start {
        Start::Root => nd_root(),
        Start::Cwd => match fs_of(&crate::task::percpu::current()) {
            Some(fs) => Ok(fs.get_pwd()),
            None => nd_root(),
        },
        Start::At(m, d) => Ok(Path::new(m.clone(), d.clone())),
        Start::Preset(p) => Ok(p.clone()),
    }
}

/// Child `name` of directory `parent`, whose lock the caller holds for
/// writing (Linux lookup_one_qstr_excl), for a lookup with `flags`: the
/// dcache, else, unless the directory is dead (ENOENT), the file system
/// ([`d_alloc_lookup`]). A negative dentry is ENOENT. Permission is the
/// caller's business.
pub fn lookup_one(
    parent: &DentryRef,
    name: &[u8],
    flags: LookupBits,
) -> Result<DentryRef, KernelError> {
    name_ok(name)?;
    let dir = parent.get_inode().ok_or(KernelError::NotFound)?;
    let d = match lookup_dcache(parent, &dir, name, flags)? {
        Some(d) => d,
        None if dir.is_dead() => return Err(KernelError::NotFound),
        None => d_alloc_lookup(parent, &dir, name)?,
    };
    positive(d)
}

/// No file system here has longer names (Linux simple_lookup and the
/// disk file systems' lookups: ENAMETOOLONG)
fn name_ok(name: &[u8]) -> Result<(), KernelError> {
    if name.len() > NAME_MAX {
        return Err(KernelError::NameTooLong);
    }
    Ok(())
}

/// A lookup's answer as a walk takes it: a negative dentry is ENOENT
/// (Linux step_into, lookup_one_qstr_excl without LOOKUP_CREATE)
fn positive(d: DentryRef) -> Result<DentryRef, KernelError> {
    if d.is_negative() {
        return Err(KernelError::NotFound);
    }
    Ok(d)
}

/// Ask the file system for `name` in `dir`, `parent`'s inode, whose
/// lock the caller holds (Linux d_alloc + ->lookup + d_splice_alias):
/// the new dentry is cached, negative where the file system keeps one
/// (`InodeOps::lookup_neg`: vfat, kernfs, cgroupfs; one killed at its
/// last put, as ramfs's always_delete_dentry, is gone at once), else
/// none (procfs: ENOENT)
fn d_alloc_lookup(parent: &DentryRef, dir: &Inode, name: &[u8]) -> Result<DentryRef, KernelError> {
    let found = dir.i_op.lookup_neg(dir, name)?;
    // Stamped before it is hashed (Linux vfat_d_version_set,
    // kernfs_set_rev before d_splice_alias)
    let d = Dentry::prealloc(parent, name)?;
    d.set_d_time(found.d_time);
    Ok(Dentry::add(parent, d, found.inode))
}

/// The dcache's child `name` of `parent` (whose inode is `dir`) if it
/// is still valid for a lookup with `flags` (Linux lookup_dcache, and
/// lookup_fast without LOOKUP_RCU): a stale one is invalidated and
/// None, a revalidation error returned
fn lookup_dcache(
    parent: &DentryRef,
    dir: &Inode,
    name: &[u8],
    flags: LookupBits,
) -> Result<Option<DentryRef>, KernelError> {
    match parent.lookup_child(name) {
        Some(child) => d_revalidate(dir, child, None, flags),
        None => Ok(None),
    }
}

/// Linux d_revalidate in ref mode and its callers' handling (`status
/// <= 0`): `child` of directory `dir` if valid for a lookup with
/// `flags`; if stale, that dentry invalidated (d_invalidate) and None;
/// an error returned, nothing invalidated. `rcu`: what an RCU walk's
/// revalidation said (Linux lookup_fast: a stale or failed answer
/// stands, ECHILD asks again in ref mode).
fn d_revalidate(
    dir: &Inode,
    child: DentryRef,
    rcu: Option<Result<bool, KernelError>>,
    flags: LookupBits,
) -> Result<Option<DentryRef>, KernelError> {
    // Positive or negative: its filesystem's d_revalidate sees both
    let valid = match rcu {
        Some(Err(ECHILD)) | None => child.revalidate(dir, child.get_inode().as_deref(), flags),
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

/// Linux lookup_slow: [`__lookup_slow`] under the directory's shared
/// inode lock, so it cannot race a create, unlink or rename there
fn lookup_slow(
    parent: &DentryRef,
    dir: &Inode,
    name: &[u8],
    flags: LookupBits,
) -> Result<DentryRef, KernelError> {
    let _lock = dir.lock_shared();
    __lookup_slow(parent, dir, name, flags)
}

/// Linux __lookup_slow: ENOENT in a dead directory (IS_DEADDIR); else
/// the dcache once more, now under the lock (d_alloc_parallel's find:
/// a stale entry is invalidated and the file system asked), else the
/// file system ([`d_alloc_lookup`]); the answer may be negative
fn __lookup_slow(
    parent: &DentryRef,
    dir: &Inode,
    name: &[u8],
    flags: LookupBits,
) -> Result<DentryRef, KernelError> {
    if dir.is_dead() {
        return Err(KernelError::NotFound);
    }
    match lookup_dcache(parent, dir, name, flags)? {
        Some(d) => Ok(d),
        None => d_alloc_lookup(parent, dir, name),
    }
}

/// What a component's lookup gives a ref-mode walk: a child to step
/// into, or the file an O_CREAT open made there, which is not stepped
/// into (Linux open_last_lookups: FMODE_CREATED, no step_into)
enum Found {
    Child(DentryRef),
    Made(DentryRef),
}

/// A symlink's body as ref mode takes it (Linux pick_link's body): the
/// inode's `i_link`, read in place through the held inode, else what
/// ->get_link gives
enum Body {
    /// `i_link`
    Kept,
    /// ->get_link's text
    Made(Vec<u8>),
    /// ->get_link's object: a magic link (nd_jump_link)
    Jump(Path),
}

/// A symlink's body in ref mode (Linux pick_link: READ_ONCE(i_link),
/// else ->get_link with the dentry)
fn link_body(inode: &Inode) -> Result<Body, KernelError> {
    if inode.i_link().is_some() {
        return Ok(Body::Kept);
    }
    Ok(match inode.i_op.get_link(inode, false)? {
        Link::Text(t) => Body::Made(t),
        Link::Jump(p) => Body::Jump(p),
    })
}

/// A ref-mode walk's name and link stack (Linux nameidata's nd->stack
/// and the name it walks, LOOKUP_RCU clear): the current text is the
/// top body's rest, else the caller's path; each link stays held until
/// its body is walked (put_link), so no body is copied
struct RefWalk<'p> {
    stack: Held,
    user: &'p [u8],
    f: LookupFlags,
    /// Symlinks followed so far (nd->total_link_count)
    total: usize,
}

/// A component of the current text: the name's offsets, whether it is
/// the walk's last, whether another follows in this text (Linux
/// WALK_MORE), and whether a slash follows it (Linux trailing_slashes)
struct Comp {
    at: usize,
    end: usize,
    last: bool,
    more: bool,
    slash: bool,
}

impl<'p> RefWalk<'p> {
    fn new(
        mut stack: Held,
        user: &'p [u8],
        f: LookupFlags,
        total: usize,
    ) -> Result<Self, KernelError> {
        stack.prepare()?;
        Ok(Self {
            stack,
            user,
            f,
            total,
        })
    }

    /// The current text, and whether nothing follows it below; ECHILD
    /// for a level whose body cannot be read ([`HeldFrame::rest`])
    fn text(&self) -> Result<(&[u8], bool), KernelError> {
        match self.stack.top() {
            Some(fr) => Ok((fr.rest()?, fr.tail_empty)),
            None => Ok((self.user, true)),
        }
    }

    /// The next component, None at the end of the caller's path; a
    /// slash after the last name asks for a directory, through a final
    /// symlink ([`trailing_slash`]). A body is put with its last
    /// component ([`RefWalk::advance`]): one left on the stack with
    /// nothing in it is a broken stack (ECHILD), never a shorter name.
    fn next(&mut self) -> Result<Option<Comp>, KernelError> {
        let (t, tail_empty) = self.text()?;
        let Some((name, after)) = next_comp(t) else {
            if self.stack.len() > 0 {
                return Err(ECHILD);
            }
            return Ok(None);
        };
        let at = t.len() - name.len() - after.len();
        let end = t.len() - after.len();
        let more = next_comp(after).is_some();
        let last = tail_empty && !more;
        let slash = !after.is_empty();
        let f = if last && slash {
            trailing_slash(self.f, name)
        } else {
            self.f
        };
        self.f = f;
        Ok(Some(Comp {
            at,
            end,
            last,
            more,
            slash,
        }))
    }

    /// The name of `c`
    fn name(&self, c: &Comp) -> Result<&[u8], KernelError> {
        Ok(&self.text()?.0[c.at..c.end])
    }

    /// Past `c`, once it is looked up and before it is stepped into: a
    /// body whose last component `c` is goes, its link put (Linux
    /// walk_component: put_link unless WALK_MORE), so a link whose
    /// body ends in another link is gone before that one is picked and
    /// a chain of links holds one, not one per level; the name below
    /// it was moved past the link when it was picked
    fn advance(&mut self, c: &Comp) {
        if !c.more && self.stack.pop() {
            return;
        }
        match self.stack.top_mut() {
            Some(fr) => fr.pos += c.end,
            None => self.user = &self.user[c.end..],
        }
    }
}

/// A slash after the walk's last name `name` asks for a directory,
/// through a final symlink, unless it is "." or ".." (Linux lookup_last
/// and lookup_fast_for_open: LAST_NORM with trailing_slashes,
/// LOOKUP_FOLLOW | LOOKUP_DIRECTORY): only that name's lookup sees
/// them, none on the way
fn trailing_slash(f: LookupFlags, name: &[u8]) -> LookupFlags {
    if name == b"." || name == b".." {
        return f;
    }
    LookupFlags {
        follow: true,
        directory: true,
        ..f
    }
}

/// may_lookup: `dir` must be a searchable directory; its inode, which
/// the walk looks the next component up in (Linux nd->inode)
fn may_lookup(c: &Cred, dir: &Dentry) -> Result<InodeRef, KernelError> {
    let inode = dir.get_inode().ok_or(KernelError::NotFound)?;
    if !inode.mode().is_dir() {
        return Err(KernelError::NotDirectory);
    }
    permission_as(c, &inode, MAY_EXEC)?;
    Ok(inode)
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
/// whether its walks still start in RCU mode. The caller's credentials
/// are borrowed from it (Linux current_cred), not copied.
pub struct Nd<'a> {
    /// The current task, whose credentials and fs_struct the lookup
    /// borrows
    me: Cur,
    /// The lookup's start (a scoped lookup's root)
    top: Start<'a>,
    /// The root, a reference, for the ref-mode walks: taken when one
    /// first needs it (Linux set_root, get_fs_root), or from an RCU
    /// walk that left RCU mode (legitimize_root); an RCU walk reads it
    /// with none
    root: OnceCell<Path>,
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
    /// The permission bits an O_CREAT open's file is made with (Linux
    /// op->mode)
    mode: u32,
    /// The open made its file (Linux FMODE_CREATED)
    created: Cell<bool>,
    /// The mode and owner of the directory the last name was looked up
    /// in (Linux nd->dir_mode, nd->dir_vfsuid): 0 if there was none
    dir: Cell<(u16, Uid)>,
}

impl<'a> Nd<'a> {
    /// Linux path_init's sequences: a scoped lookup's root is its start
    /// (dirfd or the cwd), any other the task's root, taken (ref mode)
    /// or read (RCU mode) when a walk needs it. `rcu`: LOOKUP_RCU,
    /// which LOOKUP_CACHED needs (EAGAIN without: the retry of a walk
    /// that had to leave RCU mode).
    pub fn new(start: Start<'a>, f: LookupFlags, rcu: bool) -> Result<Self, KernelError> {
        if f.cached && !rcu {
            return Err(KernelError::WouldBlock);
        }
        let m_seq = MOUNT_LOCK.read_begin();
        let r_seq = super::dentry::rename_seq_begin();
        Ok(Self {
            me: crate::task::percpu::current(),
            top: start,
            root: OnceCell::new(),
            rcu: Cell::new(rcu),
            m_seq,
            r_seq,
            scoped: f.scoped(),
            mode: 0,
            created: Cell::new(false),
            dir: Cell::new((0, 0)),
        })
    }

    /// An O_CREAT open's lookup, its file made with permission bits
    /// `mode` (Linux op->mode)
    pub fn create_mode(self, mode: u32) -> Self {
        Self { mode, ..self }
    }

    /// The lookup's open made its file (Linux FMODE_CREATED)
    pub fn created(&self) -> bool {
        self.created.get()
    }

    /// The mode and owner of the directory the last name was looked up
    /// in (Linux nd->dir_mode, nd->dir_vfsuid)
    pub fn dir(&self) -> (u16, Uid) {
        self.dir.get()
    }

    /// The last name is looked up in `dir` (Linux link_path_walk's end:
    /// nd->dir_mode, nd->dir_vfsuid); its mode and owner are atomics,
    /// read in RCU mode too
    fn set_dir(&self, dir: &Inode) {
        self.dir.set((dir.mode().raw(), dir.uid()));
    }

    /// The caller's credentials (Linux current_cred), borrowed
    fn cred(&self) -> &Cred {
        // SAFETY: the current task, which changes its credentials only
        // itself, never while it walks a path
        unsafe { self.me.subj_cred_ref() }
    }

    /// The current task's fs_struct, borrowed
    fn fs(&self) -> Option<&FsStruct> {
        fs_of(&self.me)
    }

    /// The root for a ref-mode walk (Linux nd->root, set_root when it
    /// is not set yet): a scoped lookup's start, else the task's root
    fn root(&self) -> Result<&Path, KernelError> {
        // file_open_root's, held by the caller (Linux ND_ROOT_PRESET:
        // nd->root set before path_init, never taken or put)
        if let Start::Preset(p) = self.top {
            return Ok(p);
        }
        if let Some(r) = self.root.get() {
            return Ok(r);
        }
        let r = match (self.scoped, self.top) {
            (true, Start::Cwd) => start_path(Start::Cwd)?,
            (true, Start::At(m, d)) => Path::new(m.clone(), d.clone()),
            _ => nd_root()?,
        };
        Ok(self.root.get_or_init(|| r))
    }

    /// Where a ref-mode walk from `start` begins: a scoped lookup's
    /// cwd is its root, read once
    fn start_ref(&self, start: Start<'_>) -> Result<Path, KernelError> {
        match start {
            Start::Root => self.root().cloned(),
            Start::Cwd if self.scoped => self.root().cloned(),
            s => start_path(s),
        }
    }

    /// Walk `path` from `start` (Linux path_lookupat + complete_walk;
    /// for an open, path_openat's link_path_walk + open_last_lookups
    /// loop: the last name with the open's intent, an O_CREAT open's
    /// made under the parent's lock, and complete_walk unless it was:
    /// do_open)
    pub fn lookup(
        &self,
        start: Start<'_>,
        path: &[u8],
        f: LookupFlags,
    ) -> Result<Path, KernelError> {
        let p = self.walk(start, path, f)?;
        if self.created.get() {
            return Ok(p);
        }
        self.complete(p)
    }

    /// A scoped lookup's result must still be under its root, whatever
    /// raced it (Linux complete_walk: path_is_under, EXDEV)
    fn complete(&self, p: Path) -> Result<Path, KernelError> {
        if self.scoped && !is_path_reachable(&p, self.root()?) {
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
        if f.beneath || (f.no_xdev && !MountRef::ptr_eq(&at.mnt, &self.root()?.mnt)) {
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
    /// (only its first walk; a later walk starts in ref mode), else in
    /// ref mode, each following symlinks on its own link stack
    fn walk(&self, start: Start<'_>, path: &[u8], f: LookupFlags) -> Result<Path, KernelError> {
        // An absolute path starts at the root (nd_jump_root): never
        // beneath dirfd
        let abs = path.starts_with(b"/");
        if abs && f.beneath {
            return Err(KernelError::CrossDevice);
        }
        if self.rcu.get() {
            let l = self.walk_rcu(start, abs, path, f)?;
            return self.unlazied(l);
        }
        self.walk_ref_from(start, abs, path, f)
    }

    /// A walk in ref mode from its start (Linux link_path_walk without
    /// LOOKUP_RCU); out of line, as [`Nd::unlazied`], so that their
    /// frames are not under the RCU walk's
    #[inline(never)]
    fn walk_ref_from(
        &self,
        start: Start<'_>,
        abs: bool,
        path: &[u8],
        f: LookupFlags,
    ) -> Result<Path, KernelError> {
        let start = if abs {
            self.root()?.clone()
        } else {
            self.start_ref(start)?
        };
        let mut w = RefWalk::new(Held::default(), path, f, 0)?;
        self.walk_ref(start, &mut w)
    }

    /// The walk's loop in ref mode, from `cur` (Linux link_path_walk
    /// without LOOKUP_RCU, then lookup_last): a symlink's body is walked
    /// from the link stack, the link held meanwhile
    fn walk_ref(&self, mut cur: Path, w: &mut RefWalk<'_>) -> Result<Path, KernelError> {
        while let Some(c) = w.next()? {
            let dir = may_lookup(self.cred(), &cur.dentry)?;
            if c.last {
                self.set_dir(&dir);
            }
            let found = match w.name(&c)? {
                b"." => None,
                b".." => {
                    cur = follow_dotdot(cur, self.root()?, w.f)?;
                    self.recheck()?;
                    None
                }
                name => Some(self.walk_comp(&cur, &dir, name, &c, w.f)?),
            };
            w.advance(&c);
            if let Some(found) = found {
                cur = self.found(cur, found, c.last, w)?;
            }
        }
        self.finish(cur, w.f)
    }

    /// The lookup of component `c`, `name` in `cur` (whose inode is
    /// `dir`), in ref mode: walk_component's lookup_fast (the dcache
    /// with no lock), or, for an O_CREAT open's last name,
    /// open_last_lookups' (lookup_fast_for_open: a slash after it is
    /// EISDIR; O_EXCL does not look); then [`Nd::lookup_rest`]
    fn walk_comp(
        &self,
        cur: &Path,
        dir: &Inode,
        name: &[u8],
        c: &Comp,
        f: LookupFlags,
    ) -> Result<Found, KernelError> {
        let bits = f.bits(c.last);
        if bits.contains(LookupBits::CREATE) {
            if c.slash {
                return Err(KernelError::IsDirectory);
            }
            if bits.contains(LookupBits::EXCL) {
                return self.lookup_rest(cur, dir, name, bits, None);
            }
        }
        let fast = lookup_dcache(&cur.dentry, dir, name, bits)?;
        self.lookup_rest(cur, dir, name, bits, fast)
    }

    /// A component's lookup once lookup_fast gave `fast` (None: a miss
    /// or a stale entry), `bits` its nd->flags: walk_component's
    /// lookup_slow, or, for an O_CREAT open's last name (LOOKUP_CREATE:
    /// only there), open_last_lookups' lookup_open, a negative entry
    /// discarded (lookup_fast_for_open: the create needs the lock); a
    /// negative answer to step into is ENOENT (step_into). An open
    /// without O_CREAT takes walk_component's way: Linux's lookup_open
    /// without O_CREAT is lookup_slow's (the shared lock, the dcache,
    /// ->lookup).
    fn lookup_rest(
        &self,
        cur: &Path,
        dir: &Inode,
        name: &[u8],
        bits: LookupBits,
        fast: Option<DentryRef>,
    ) -> Result<Found, KernelError> {
        let open = bits.contains(LookupBits::CREATE);
        match fast.filter(|d| !(open && d.is_negative())) {
            Some(d) => Ok(Found::Child(positive(d)?)),
            None if open => self.lookup_open(cur, dir, name, bits),
            None => {
                name_ok(name)?;
                let d = lookup_slow(&cur.dentry, dir, name, bits)?;
                Ok(Found::Child(positive(d)?))
            }
        }
    }

    /// Linux lookup_open with O_CREAT (no ->atomic_open here): `name` in
    /// `cur` (whose inode is `dir`) under the directory's i_rwsem held
    /// for writing, write access asked before it and its error kept for
    /// a create (EROFS after EEXIST); ENOENT in a dead directory; the
    /// dcache under the lock (a stale entry invalidated), else the file
    /// system. A positive answer is the file to open; on a negative one
    /// the file is made (may_o_create: write and search on the
    /// directory; the mode with the umask and SGID stripping, the owner
    /// from init_owner) and its dentry cached, the dentry first so an
    /// ENOMEM leaves no file made.
    fn lookup_open(
        &self,
        cur: &Path,
        dir: &Inode,
        name: &[u8],
        bits: LookupBits,
    ) -> Result<Found, KernelError> {
        let parent = &cur.dentry;
        let w = cur.mnt.want_write();
        let _lock = dir.lock();
        if dir.is_dead() {
            return Err(KernelError::NotFound);
        }
        name_ok(name)?;
        // A file system that keeps no negative dentry answers ENOENT
        // (Linux ->lookup's NULL)
        let d = match lookup_dcache(parent, dir, name, bits)? {
            Some(d) => Some(d),
            None => match d_alloc_lookup(parent, dir, name) {
                Err(KernelError::NotFound) => None,
                r => Some(r?),
            },
        };
        // A negative one is not held while the made inode fills its name
        if let Some(d) = d.filter(|d| !d.is_negative()) {
            return Ok(Found::Child(d));
        }
        let _w = w?;
        let c = self.cred();
        super::dac::may_create(c, dir)?;
        let perm = super::dac::create_mode(c, dir, (self.mode & 0o7777) as u16);
        let d = Dentry::prealloc(parent, name)?;
        let inode = dir.i_op.create(dir, name, InodeMode::regular(perm))?;
        dir.touch_mc();
        self.created.set(true);
        Ok(Found::Made(Dentry::add(parent, d, Some(inode))))
    }

    /// Where the walk goes on from `cur` once a component's lookup gave
    /// `found`: step_into the child (`last`: the walk's last
    /// component), or the file an O_CREAT open made, as it is
    fn found(
        &self,
        cur: Path,
        found: Found,
        last: bool,
        w: &mut RefWalk<'_>,
    ) -> Result<Path, KernelError> {
        match found {
            Found::Child(d) => self.step(cur, d, last, w),
            Found::Made(d) => Ok(Path::new(cur.mnt.clone(), d)),
        }
    }

    /// The end of a walk: LOOKUP_DIRECTORY's check (Linux
    /// path_lookupat: ENOTDIR)
    fn finish(&self, p: Path, f: LookupFlags) -> Result<Path, KernelError> {
        if f.directory && p.get_inode().is_some_and(|n| !n.mode().is_dir()) {
            return Err(KernelError::NotDirectory);
        }
        Ok(p)
    }

    /// step_into in ref mode: onto `d`, found in `cur`: what is mounted
    /// on it crossed, a symlink to follow picked (`last`: the walk's
    /// last component); where the walk goes on
    fn step(
        &self,
        cur: Path,
        d: DentryRef,
        last: bool,
        w: &mut RefWalk<'_>,
    ) -> Result<Path, KernelError> {
        let child = step_mounts(Path::new(cur.mnt.clone(), d), w.f)?;
        if (!last || w.f.follow) && child.get_inode().is_some_and(|n| n.mode().is_symlink()) {
            return self.pick_link(cur, child, last, w);
        }
        Ok(child)
    }

    /// Go on in ref mode from where an RCU walk left RCU mode (Linux:
    /// the same loop after try_to_unlazy), with the link stack and the
    /// rest of the name it handed over and the symlinks it followed
    /// counted
    #[inline(never)]
    fn unlazied(&self, l: Lazy<'_>) -> Result<Path, KernelError> {
        let Lazy {
            to,
            stack,
            user,
            f,
            depth,
        } = l;
        let mut w = RefWalk::new(stack, user, f, depth)?;
        let cur = match to {
            To::Done(p) => return self.finish(p, w.f),
            To::Comp(cur) => cur,
            To::Link { cur, link, last } => self.get_link(cur, link, last, &mut w)?,
            // lookup_fast missed in RCU mode, or an O_CREAT open's last
            // name needs the lock: lookup_slow or lookup_open
            To::Lookup(cur) => {
                let c = w.next()?.ok_or(ECHILD)?;
                let dir = cur.dentry.get_inode().ok_or(KernelError::NotFound)?;
                let bits = w.f.bits(c.last);
                let found = self.lookup_rest(&cur, &dir, w.name(&c)?, bits, None)?;
                w.advance(&c);
                self.found(cur, found, c.last, &mut w)?
            }
            // lookup_fast after try_to_unlazy_next: ECHILD revalidated
            // again in ref mode, a stale entry invalidated and the name
            // looked up again
            To::Child { cur, child, reval } => {
                let c = w.next()?.ok_or(ECHILD)?;
                let dir = cur.dentry.get_inode().ok_or(KernelError::NotFound)?;
                let bits = w.f.bits(c.last);
                let fast = d_revalidate(&dir, child, Some(reval), bits)?;
                let found = self.lookup_rest(&cur, &dir, w.name(&c)?, bits, fast)?;
                w.advance(&c);
                self.found(cur, found, c.last, &mut w)?
            }
            // The component is behind: step_into goes on
            To::Step {
                cur,
                child,
                dots: true,
                ..
            } => {
                let p = step_mounts(Path::new(cur.mnt.clone(), child), w.f)?;
                self.recheck()?;
                p
            }
            To::Step {
                cur,
                child,
                last,
                dots: false,
            } => self.step(cur, child, last, &mut w)?,
        };
        self.walk_ref(cur, &mut w)
    }

    /// pick_link in ref mode: symlink `link` found in `dir` counted
    /// (reserve_stack: MAX_SYMLINK_DEPTH links in all, ELOOP) and
    /// checked ([`Nd::may_pick`]), then followed ([`Nd::get_link`])
    fn pick_link(
        &self,
        dir: Path,
        link: Path,
        last: bool,
        w: &mut RefWalk<'_>,
    ) -> Result<Path, KernelError> {
        if w.total >= MAX_SYMLINK_DEPTH {
            return Err(KernelError::TooManySymlinks);
        }
        w.total += 1;
        self.may_pick(&dir, &link, last, w.f)?;
        self.get_link(dir, link, last, w)
    }

    /// pick_link's checks of symlink `link` found in `dir`:
    /// fs.protected_symlinks for the trailing link only (`last`:
    /// WALK_TRAILING), then RESOLVE_NO_SYMLINKS or a nosymfollow mount
    /// (LOOKUP_NO_SYMLINKS / MNT_NOSYMFOLLOW on the link's mount)
    fn may_pick(
        &self,
        dir: &Path,
        link: &Path,
        last: bool,
        f: LookupFlags,
    ) -> Result<(), KernelError> {
        let inode = link.get_inode().ok_or(KernelError::NotFound)?;
        if last && let Some(d) = dir.dentry.get_inode() {
            super::dac::may_follow_link(self.cred(), &d, &inode)?;
        }
        if f.no_symlinks || link.mnt.flags() & super::mount::MNT_NOSYMFOLLOW != 0 {
            return Err(KernelError::TooManySymlinks);
        }
        Ok(())
    }

    /// The rest of pick_link, in ref mode: symlink `link` found in
    /// `dir` (counted and checked) is followed: its atime touched, its
    /// body (the inode's `i_link`, else ->get_link) pushed on the link
    /// stack with the link held, walked next; an absolute body starts
    /// at the root (nd_jump_root), a magic link at its object
    /// (nd_jump_link); a body of slashes alone, or a jump, pushes
    /// nothing (all_done). Where the walk goes on.
    fn get_link(
        &self,
        dir: Path,
        link: Path,
        last: bool,
        w: &mut RefWalk<'_>,
    ) -> Result<Path, KernelError> {
        let inode = link.get_inode().ok_or(KernelError::NotFound)?;
        inode.touch_atime(&link.mnt);
        // An i_link body is read through the held inode, not copied
        let body = match link_body(&inode)? {
            Body::Kept => None,
            Body::Made(t) => Some(t),
            Body::Jump(p) => {
                self.may_jump(&dir, &p, w.f)?;
                return Ok(p);
            }
        };
        let mut fr = HeldFrame {
            link,
            body,
            inode: Some(inode),
            pos: 0,
            tail_empty: last,
        };
        let b = fr.bytes()?;
        let abs = b.starts_with(b"/");
        let skip = b.iter().position(|&c| c != b'/').unwrap_or(b.len());
        let mut cur = dir;
        if abs {
            fr.pos = skip;
            self.jump_root(&cur, w.f)?;
            cur = self.root()?.clone();
        }
        if !fr.rest()?.is_empty() {
            w.stack.push(fr)?;
        }
        Ok(cur)
    }

    /// Walk all but the last component of `path` from `start` (Linux
    /// path_parentat): the parent must be a searchable directory; the
    /// last name is not looked up, only classified
    pub fn parentat(
        &self,
        start: Start<'_>,
        path: &[u8],
        f: LookupFlags,
    ) -> Result<Parent, KernelError> {
        let end = path.iter().rposition(|&c| c != b'/').map_or(0, |i| i + 1);
        let slash = end < path.len();
        let trimmed = &path[..end];
        if trimmed.is_empty() {
            // Only slashes: the root, no last component
            let (mnt, dir) = self.root()?.clone().into_parts();
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
            parent: true,
            ..f.resolve()
        };
        let (mnt, dir) = match (dir_path.is_empty(), start) {
            (true, s) => self.start_ref(s)?,
            (false, s) => self.lookup(s, dir_path, dirf)?,
        }
        .into_parts();
        // link_path_walk: search permission before the last component too
        may_lookup(self.cred(), &dir)?;
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
    make: impl FnOnce(&InodeRef, &Cred) -> Result<InodeRef, KernelError>,
) -> Result<DentryRef, KernelError> {
    let (parent, name) = (&p.dir, p.name.as_slice());
    let dir = parent.get_inode().ok_or(KernelError::NotFound)?;
    if !dir.mode().is_dir() {
        return Err(KernelError::NotDirectory);
    }
    let c = crate::fs::dac::cred();
    // filename_create: write access first, its EROFS reported after EEXIST
    let w = p.mnt.want_write();
    let _dir_lock = dir.lock();
    (|| {
        // LOOKUP_CREATE | LOOKUP_EXCL, but no create through a trailing
        // slash that does not make a directory
        let mut cf = LookupBits::CREATE | LookupBits::EXCL;
        cf.set(LookupBits::CREATE, !p.slash);
        if lookup_one(parent, name, cf).is_ok() {
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
    let c = crate::fs::dac::cred();
    let _dir_lock = dir.lock();
    (|| {
        let victim = lookup_one(parent, name, LookupBits::empty())?;
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
            dir.i_op.rmdir(&dir, name, &victim).inspect(|()| {
                super::dentry::d_drop_tree(&victim);
                inode.set_dead();
            })
        } else {
            dir.i_op.unlink(&dir, name, &victim)
        };
        // The parent's mtime and ctime, the victim's ctime
        // (simple_unlink)
        if r.is_ok() {
            dir.touch_mc();
            inode.touch_c();
            // What other namespaces mounted on it goes too, and nothing
            // is mounted there any more (Linux vfs_rmdir, vfs_unlink:
            // dont_mount, detach_mounts, under the victim's lock)
            victim.dont_mount();
            super::mount::detach_mounts(&victim);
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
pub fn path_start(dirfd: i32, path: &[u8], f: LookupFlags) -> Result<Dfd, KernelError> {
    if path.starts_with(b"/") && !f.in_root {
        if f.beneath {
            return Err(KernelError::CrossDevice);
        }
        return Ok(Dfd::Root);
    }
    if dirfd == AT_FDCWD {
        return Ok(Dfd::Cwd);
    }
    // SAFETY: a walk closes no descriptor and neither shares nor
    // changes the table; the `Dfd` is the calling syscall's, dropped
    // when its lookup is done
    let file = unsafe { crate::task::fdtable::fdget_raw(dirfd) }.ok_or(KernelError::BadFd)?;
    if f.linkat_empty && !may_linkat_empty(&file) {
        return Err(KernelError::NotFound);
    }
    if !path.is_empty() && !file.is_dir() {
        return Err(KernelError::NotDirectory);
    }
    if file.mnt().is_some() {
        return Ok(Dfd::File(file));
    }
    Ok(file.f_path().map_or(Dfd::Root, Dfd::Path))
}

/// Whether linkat may link `file` (Linux path_init LOOKUP_LINKAT_EMPTY):
/// its opener creds are the caller's, or the caller has
/// CAP_DAC_READ_SEARCH, so a descriptor passed to a less privileged
/// process cannot be linked back into the tree. Checked on the same fd
/// lookup the walk starts from. Linux compares cred pointers and uses
/// ns_capable(f_cred->user_ns); hk compares values (BUGS.md) and has
/// one user namespace.
fn may_linkat_empty(file: &File) -> bool {
    file.f_cred == crate::task::current_cred()
        || crate::task::capable(crate::task::CAP_DAC_READ_SEARCH)
}

/// Resolve `path` relative to `dirfd` (Linux filename_lookup); an empty
/// path (getname let it through: AT_EMPTY_PATH, O_EMPTYPATH) names
/// dirfd itself
pub fn filename_lookup(dirfd: i32, path: &[u8], flags: LookupFlags) -> Result<Path, KernelError> {
    filename_lookup_start(path_start(dirfd, path, flags)?.start(), path, flags)
}

/// Resolve `path` from `start` (None: the root), an empty path naming
/// `start` itself: [`filename_lookup`]'s walk, also for a start that is
/// no descriptor: `start` is the lookup's root too (Linux
/// ND_ROOT_PRESET: file_open_root)
pub fn filename_lookup_from(
    start: Option<Path>,
    path: &[u8],
    flags: LookupFlags,
) -> Result<Path, KernelError> {
    match &start {
        Some(p) => filename_lookup_start(Start::Preset(p), path, flags),
        None => filename_lookup_start(Start::Root, path, flags),
    }
}

/// [`filename_lookup`]'s walk from `start`
pub fn filename_lookup_start(
    start: Start<'_>,
    path: &[u8],
    flags: LookupFlags,
) -> Result<Path, KernelError> {
    if path.is_empty() {
        let p = start_path(start)?;
        // Linux path_lookupat's LOOKUP_DIRECTORY check, walk or not
        if flags.directory && p.get_inode().is_some_and(|n| !n.mode().is_dir()) {
            return Err(KernelError::NotDirectory);
        }
        return Ok(p);
    }
    path_lookup(start, path, flags)
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
    let s = start.start();
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
    use crate::fs::dentry::DentryOps;
    use crate::fs::inode::{InodeMode, NULL_INODE_OPS, Timespec};
    use alloc::sync::Weak;

    /// Inode numbers whose dentries revalidate stale, and with EIO
    const STALE: u64 = 2;
    const BROKEN: u64 = 3;
    const VALID: u64 = 4;

    /// The test filesystem's d_revalidate: by inode number; a negative
    /// dentry is stale
    fn reval(_: &Inode, _: &Dentry, i: Option<&Inode>, _: LookupBits) -> Result<bool, KernelError> {
        match i.map(|i| i.ino) {
            None | Some(STALE) => Ok(false),
            Some(BROKEN) => Err(KernelError::Io),
            Some(_) => Ok(true),
        }
    }

    static OPS: DentryOps = DentryOps {
        d_revalidate: Some(reval),
        ..DentryOps::NONE
    };

    fn inode(ino: u64) -> InodeRef {
        let m = InodeMode::directory(0o755);
        let t = Timespec::from_secs(0);
        Inode::alloc(Inode::new(ino, m, 0, 0, 0, t, Weak::new(), &NULL_INODE_OPS)).unwrap()
    }

    fn root() -> DentryRef {
        DentryRef::new(Dentry::new_root_op(inode(1), &OPS)).unwrap()
    }

    /// A negative dentry is revalidated too (Linux d_revalidate on a
    /// negative entry): a stale one leaves the tree and the name is
    /// asked again
    #[test]
    fn negative_is_revalidated() {
        let r = root();
        let n = Dentry::alloc(&r, b"n", None).unwrap();
        let dir = r.get_inode().unwrap();
        assert!(
            lookup_dcache(&r, &dir, b"n", LookupBits::empty())
                .unwrap()
                .is_none()
        );
        assert!(n.d_unhashed() && r.lookup_child(b"n").is_none());
    }

    /// A stale child is invalidated itself (Linux d_invalidate(dentry)):
    /// a dentry that took its name since stays cached, and is the answer
    #[test]
    fn stale_invalidates_only_itself() {
        let r = root();
        let a = Dentry::alloc(&r, b"x", Some(inode(STALE))).unwrap();
        drop(r.remove_child(b"x"));
        let b = Dentry::alloc(&r, b"x", Some(inode(VALID))).unwrap();
        let (dir, f) = (r.get_inode().unwrap(), LookupBits::empty());
        // lookup_fast's ref half after an RCU walk's ECHILD, then
        // lookup_slow
        assert!(
            d_revalidate(&dir, a, Some(Err(ECHILD)), f)
                .unwrap()
                .is_none()
        );
        let d = lookup_slow(&r, &dir, b"x", f).unwrap();
        assert!(DentryRef::ptr_eq(&d, &b) && !b.d_unhashed());
    }

    /// A stale cached child leaves the tree and the name is asked again
    #[test]
    fn stale_is_dropped() {
        let r = root();
        let a = Dentry::alloc(&r, b"x", Some(inode(STALE))).unwrap();
        let dir = r.get_inode().unwrap();
        assert!(
            lookup_dcache(&r, &dir, b"x", LookupBits::empty())
                .unwrap()
                .is_none()
        );
        assert!(a.d_unhashed() && r.lookup_child(b"x").is_none());
    }

    /// A revalidation error is the lookup's (Linux lookup_fast and
    /// lookup_dcache: ERR_PTR(status)), and the dentry stays cached; an
    /// RCU walk's stale answer stands without being asked again
    #[test]
    fn reval_error_returned() {
        let r = root();
        let a = Dentry::alloc(&r, b"x", Some(inode(BROKEN))).unwrap();
        let (dir, f) = (r.get_inode().unwrap(), LookupBits::empty());
        let e = d_revalidate(&dir, a.clone(), Some(Err(ECHILD)), f);
        assert_eq!(e.err(), Some(KernelError::Io));
        let c = lookup_dcache(&r, &dir, b"x", LookupBits::empty());
        assert_eq!(c.err(), Some(KernelError::Io));
        assert!(!a.d_unhashed());
        let _ = d_revalidate(&dir, a.clone(), Some(Ok(false)), f);
        assert!(a.d_unhashed());
    }

    /// A link-stack level whose body cannot be read (no body, an inode
    /// with no `i_link`; a position past its end) fails the walk with
    /// ECHILD, never walks on as if the body were empty: the name below
    /// it is not reached
    #[test]
    fn unreadable_body_is_echild() {
        let m = crate::fs::mount::test_mnt();
        let frame = |body: Option<&[u8]>, inode: Option<InodeRef>, pos| HeldFrame {
            link: Path::new(m.clone(), m.root.clone()),
            body: body.map(<[u8]>::to_vec),
            inode,
            pos,
            tail_empty: false,
        };
        for fr in [
            frame(None, Some(inode(VALID)), 0),
            frame(None, None, 0),
            frame(Some(b"ab"), None, 3),
        ] {
            let mut stack = Held::default();
            stack.push(fr).unwrap();
            let mut w = RefWalk {
                stack,
                user: b"x",
                f: LookupFlags::default(),
                total: 0,
            };
            assert_eq!(w.next().err(), Some(ECHILD));
        }
    }

    /// A body is put as soon as its last component is looked up, before
    /// the step into it (Linux walk_component: put_link unless
    /// WALK_MORE): a link there is picked with the walked one gone, and
    /// the name below goes on where the link left it
    #[test]
    fn body_put_before_its_last_step() {
        let m = crate::fs::mount::test_mnt();
        let mut stack = Held::default();
        stack
            .push(HeldFrame {
                link: Path::new(m.clone(), m.root.clone()),
                body: Some(b"a/c".to_vec()),
                inode: None,
                pos: 0,
                tail_empty: false,
            })
            .unwrap();
        let mut w = RefWalk {
            stack,
            user: b"x",
            f: LookupFlags::default(),
            total: 0,
        };
        let a = w.next().unwrap().unwrap();
        w.advance(&a);
        assert_eq!(w.stack.len(), 1);
        let c = w.next().unwrap().unwrap();
        assert_eq!(w.name(&c).unwrap(), b"c");
        w.advance(&c);
        assert_eq!(w.stack.len(), 0, "the walked body is still held");
        let x = w.next().unwrap().unwrap();
        assert_eq!(w.name(&x).unwrap(), b"x");
        assert!(x.last);
    }

    /// What d_revalidate sees of a walk (Linux nd->flags): LOOKUP_PARENT
    /// on the way, an open's intent on the last component only, a
    /// parent's walk LOOKUP_PARENT throughout with none of its own
    /// FOLLOW/DIRECTORY; RESOLVE_* always
    #[test]
    fn revalidate_sees_nd_flags() {
        let open = LookupFlags {
            follow: true,
            beneath: true,
            intent: LookupBits::OPEN | LookupBits::CREATE,
            ..LookupFlags::default()
        };
        let on_way = LookupBits::FOLLOW | LookupBits::BENEATH | LookupBits::PARENT;
        assert_eq!(open.bits(false), on_way);
        let at_last = LookupBits::FOLLOW | LookupBits::BENEATH | open.intent;
        assert_eq!(open.bits(true), at_last);
        let parent = LookupFlags {
            follow: true,
            directory: true,
            parent: true,
            ..open.resolve()
        };
        let p = LookupBits::PARENT | LookupBits::BENEATH;
        assert_eq!(parent.bits(false), p);
        assert_eq!(parent.bits(true), p);
    }

    #[test]
    fn components() {
        assert_eq!(next_comp(b"//a//b/"), Some((&b"a"[..], &b"//b/"[..])));
        assert_eq!(next_comp(b"//b/"), Some((&b"b"[..], &b"/"[..])));
        assert_eq!(next_comp(b"/"), None);
        assert_eq!(next_comp(b""), None);
    }
}

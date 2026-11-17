//! RCU path walk (Linux fs/namei.c in LOOKUP_RCU mode)
//!
//! A walk first runs under one RCU read guard, taking no reference and
//! no lock and storing nothing to a shared dentry, inode or lock word:
//! each component is found with `__d_lookup_rcu`, its inode borrowed
//! with `d_inode_rcu`, and what was read is confirmed by the dentry's
//! `d_seq` (Linux nd->seq, nd->next_seq); the search permission is
//! asked with MAY_NOT_BLOCK of fields an RCU reader may read; a
//! symlink's body, kept in its inode (`i_link`) or given by an RCU
//! ->get_link, is walked from the walk's own stack ([`Stack`], Linux
//! nd->stack). Where the walk cannot go on that way (a miss, a body or
//! an atime only ref mode can handle, a revalidation or permission
//! check the file system can only do with a reference), it takes
//! references to where it stands (try_to_unlazy
//! and try_to_unlazy_next: legitimize_path, a reference taken unless
//! the object died, its sequence checked after) and to the symlinks on
//! its stack (legitimize_links: a held link keeps its body), and goes
//! on in ref mode from that point ([`Lazy`]). If that fails, or a sequence moved, the
//! walk is ECHILD and its caller starts it over in ref mode (Linux
//! filename_lookup's retry without LOOKUP_RCU); a LOOKUP_CACHED walk
//! (RESOLVE_CACHED) never leaves RCU mode but at its end (EAGAIN
//! instead, from that retry's path_init). References a failed
//! legitimize took are put after the guard ([`Puts`], Linux
//! terminate_walk after leave_rcu).
//!
//! Linux runs one link_path_walk loop in both modes; here the RCU mode
//! has its own loop over borrowed places ([`RcuPath`]), which hands
//! its place over to the ref-mode loop where Linux's try_to_unlazy
//! returns to it.

use super::{ECHILD, LookupFlags, Nd, Start, next_comp};
use crate::fs::KernelError;
use crate::fs::dac::{MAY_EXEC, MAY_NOT_BLOCK, may_follow_link, permission_as};
use crate::fs::dentry::{__d_lookup_rcu, Dentry, DentryRef, LookupBits};
use crate::fs::fsstruct::PathRcu;
use crate::fs::inode::{Inode, InodeRef, Link};
use crate::fs::mount::{
    __lookup_mnt, MNT_NOSYMFOLLOW, MOUNT_LOCK, Mount, MountRef, choose_mountpoint_rcu,
    path_connected,
};
use crate::fs::path_ref::Path;
use crate::sync::rcu::RcuReadGuard;
use alloc::vec::Vec;

/// Where an RCU walk stands (Linux nameidata's path, inode and seq
/// under LOOKUP_RCU): borrowed for the guard with no reference; what
/// was read of the dentry holds while its `d_seq` is still `seq`
#[derive(Clone, Copy)]
struct RcuPath<'g> {
    mnt: &'g Mount,
    dentry: &'g Dentry,
    /// Its inode when `seq` was read (None: negative)
    inode: Option<&'g Inode>,
    seq: u32,
}

impl<'g> RcuPath<'g> {
    /// A path the caller holds, as where the walk starts (Linux
    /// path_init: nd->seq = read_seqcount_begin(&dentry->d_seq))
    fn at(mnt: &'g Mount, dentry: &'g Dentry, g: &'g RcuReadGuard) -> Self {
        let seq = dentry.d_seq_begin();
        Self {
            mnt,
            dentry,
            inode: dentry.d_inode_rcu(g),
            seq,
        }
    }

    /// The fs_struct's root or cwd, read under its sequence with its
    /// `d_seq` sample (Linux set_root, path_init's AT_FDCWD)
    fn fs(p: PathRcu<'g>, g: &'g RcuReadGuard) -> Self {
        let (mnt, dentry, seq) = p;
        Self {
            mnt,
            dentry,
            inode: dentry.d_inode_rcu(g),
            seq,
        }
    }

    /// Its mount and dentry
    fn pair(&self) -> (&'g Mount, &'g Dentry) {
        (self.mnt, self.dentry)
    }
}

/// What an RCU walk keeps for its whole length (Linux nameidata under
/// LOOKUP_RCU): the guard, and the root read at its start (nd->root,
/// nd->root_seq), with no reference: legitimized at the first unlazy
/// that needs it (legitimize_root)
struct Rcu<'g> {
    g: &'g RcuReadGuard,
    root: RcuPath<'g>,
    /// The root's path when the walk holds it already (boot code's
    /// namespace root, or one an earlier walk of the lookup took)
    held: Option<&'g Path>,
}

/// What a failed legitimize took, put by the caller after the RCU
/// guard (Linux terminate_walk's path_put after leave_rcu): a put may
/// be the last, which kills a dentry or tears a mount down
///
/// One slot per role, as Linux's terminate_walk puts a fixed set: the
/// walk's own place (nd->path), the symlink being picked (the top of
/// the link stack; the links below it in `links`), the root (ND_ROOT_GRABBED), a mount whose dentry
/// could not be taken (legitimize_mnt's put), and try_to_unlazy_next's
/// child. Each is
/// filled at most once: every fill is on a path that ends the RCU walk
/// with an error (`?` up to `walk_rcu`), and of the legitimizes one
/// walk step may run (`pick_link_rcu`: the link's, then the place's,
/// then the root's), each fills a slot only if it fails, and so ends
/// the step before the next, or its own slot (the root's leftover;
/// a mount alone only from the first that fails). A second fill would
/// drop a value under the guard; it panics instead (`put`), in every
/// build.
#[derive(Default)]
pub(super) struct Puts {
    path: Option<Path>,
    link: Option<Path>,
    root: Option<Path>,
    mnt: Option<MountRef>,
    dentry: Option<DentryRef>,
    /// The link stack, as far as a failed legitimize_links took it
    /// (Linux drop_links and terminate_walk's puts up to nd->depth),
    /// and the mount of the link it failed on
    links: Option<Held>,
    links_mnt: Option<MountRef>,
}

/// Which of `Puts`' path slots a legitimize's leftover goes to
#[derive(Clone, Copy)]
enum Role {
    /// nd->path: where the walk stood
    Path,
    /// The link stack's top: the symlink being picked
    Link,
    /// nd->root
    Root,
}

/// Fill a `Puts` slot, empty by construction (`Puts`)
fn put<T>(slot: &mut Option<T>, v: T) {
    assert!(slot.is_none(), "namei: a Puts slot filled twice");
    *slot = Some(v);
}

impl Puts {
    fn path(&mut self, r: Role, p: Path) {
        match r {
            Role::Path => put(&mut self.path, p),
            Role::Link => put(&mut self.link, p),
            Role::Root => put(&mut self.root, p),
        }
    }

    fn mnt(&mut self, m: Option<MountRef>) {
        if let Some(m) = m {
            put(&mut self.mnt, m);
        }
    }

    fn dentry(&mut self, d: DentryRef) {
        put(&mut self.dentry, d);
    }

    /// What a successful unlazy took, for a walk that cannot go on
    fn to(&mut self, to: To) {
        match to {
            To::Done(p) | To::Comp(p) | To::Lookup(p) => self.path(Role::Path, p),
            To::Child { cur, child, .. } => {
                self.path(Role::Path, cur);
                self.dentry(child);
            }
            To::Link { cur, link, .. } => {
                self.path(Role::Path, cur);
                self.path(Role::Link, link);
            }
        }
    }
}

/// Where a walk goes on in ref mode once it left RCU mode (Linux: the
/// same loop, LOOKUP_RCU cleared, from where try_to_unlazy returned):
/// what it stood on, the link stack with each link held
/// (legitimize_links), the rest of the caller's path below it, the
/// flags (a trailing slash a symlink's body ended in added:
/// lookup_last) and the symlinks followed so far (nd->total_link_count).
/// The current text (the top body's rest, else `user`) starts at the
/// component the walk stopped at (`Comp`, `Lookup`, `Child`), or after
/// the symlink (`Link`); empty for `Done`.
pub(super) struct Lazy<'p> {
    pub(super) to: To,
    pub(super) stack: Held,
    pub(super) user: &'p [u8],
    pub(super) f: LookupFlags,
    pub(super) depth: usize,
}

/// A level of the link stack in ref mode (Linux struct saved, its link
/// held): the link, the body (an `i_link` read through `inode`, the
/// link's inode, or one ->get_link made), where its rest begins, and
/// whether nothing follows it below (its last component is the walk's
/// last). The link is put as the level is popped (put_link).
pub(super) struct HeldFrame {
    pub(super) link: Path,
    pub(super) body: Option<Vec<u8>>,
    pub(super) inode: Option<InodeRef>,
    pub(super) pos: usize,
    pub(super) tail_empty: bool,
}

impl HeldFrame {
    /// The body: what ->get_link made, else the link inode's `i_link`;
    /// ECHILD for a level with neither (one [`HeldFrame::prepare`] did
    /// not take), never an empty body, which would walk a shorter name
    pub(super) fn bytes(&self) -> Result<&[u8], KernelError> {
        match (&self.body, &self.inode) {
            (Some(b), _) => Ok(b),
            (None, Some(i)) => i.i_link().ok_or(ECHILD),
            (None, None) => Err(ECHILD),
        }
    }

    /// The body from where the walk stands in it; ECHILD past its end
    pub(super) fn rest(&self) -> Result<&[u8], KernelError> {
        self.bytes()?.get(self.pos..).ok_or(ECHILD)
    }

    /// An RCU walk's level in ref mode: the held link's inode, whose
    /// `i_link` the walk read (its sequence was checked when the link
    /// was taken); ECHILD if it has none
    fn prepare(&mut self) -> Result<(), KernelError> {
        if self.body.is_some() || self.inode.is_some() {
            return Ok(());
        }
        let i = self.link.get_inode().ok_or(ECHILD)?;
        i.i_link().ok_or(ECHILD)?;
        self.inode = Some(i);
        Ok(())
    }
}

/// The link stack in ref mode (Linux nd->stack): legitimized from an
/// RCU walk's (its levels past the embedded ones in room reserved while
/// the RCU walk pushed them), or pushed by a ref-mode walk (room
/// allocated on first need, Linux nd_alloc_stack: ENOMEM), bottom first
#[derive(Default)]
pub(super) struct Held(EmbStack<HeldFrame>);

impl Held {
    pub(super) fn len(&self) -> usize {
        self.0.len()
    }

    pub(super) fn top(&self) -> Option<&HeldFrame> {
        self.0.top()
    }

    pub(super) fn top_mut(&mut self) -> Option<&mut HeldFrame> {
        self.0.top_mut()
    }

    /// Push a level, allocating room past the embedded ones (ENOMEM)
    pub(super) fn push(&mut self, f: HeldFrame) -> Result<(), KernelError> {
        if !self.0.has_room() && !self.0.reserve_more() {
            return Err(KernelError::OutOfMemory);
        }
        self.0.push(f);
        Ok(())
    }

    /// Pop the top level, its link put (put_link)
    pub(super) fn pop(&mut self) -> bool {
        self.0.pop()
    }

    /// Every level ready for ref mode ([`HeldFrame::prepare`])
    pub(super) fn prepare(&mut self) -> Result<(), KernelError> {
        for i in 0..self.0.len() {
            self.0.get_mut(i).prepare()?;
        }
        Ok(())
    }
}

/// What ref mode does first ([`Lazy`])
pub(super) enum To {
    /// The walk's end (complete_walk)
    Done(Path),
    /// may_lookup's ECHILD: the component asked again in ref mode
    Comp(Path),
    /// lookup_fast's miss: lookup_slow of the component
    Lookup(Path),
    /// try_to_unlazy_next with `child`, found for the component in
    /// `cur`: handled in ref mode as `reval` (what its revalidation
    /// under LOOKUP_RCU said, if it was not valid), then stepped into;
    /// `dots`: the parent ".." gave (WALK_NOFOLLOW, then handle_dots'
    /// scoped check)
    Child {
        cur: Path,
        child: DentryRef,
        reval: Option<Result<bool, KernelError>>,
        dots: bool,
    },
    /// pick_link: symlink `link` in `cur`, checked and counted; its
    /// body in ref mode; `last`: the walk's last component
    Link { cur: Path, link: Path, last: bool },
}

/// What one RCU step gives the loop: it stands on the child, it left
/// RCU mode, or the child is a symlink to pick
enum Step<'g> {
    On,
    Lazy(To),
    Link {
        mnt: &'g Mount,
        link: &'g Dentry,
        inode: &'g Inode,
        seq: u32,
        last: bool,
    },
}

/// A symlink body being walked (Linux struct saved's name): kept in the
/// inode (`i_link`), or made by an RCU ->get_link
enum Body<'g> {
    Ref(&'g [u8]),
    Own(Vec<u8>),
}

/// One level of the RCU walk's symlink stack (Linux nd->stack): the
/// body, where its rest begins, whether nothing follows it below (no
/// component in the texts under it: its last component is the walk's
/// last), and the link with its `d_seq` sample, borrowed (Linux
/// saved->link and seq), taken when the walk leaves RCU mode
struct Frame<'g> {
    body: Body<'g>,
    pos: usize,
    tail_empty: bool,
    mnt: &'g Mount,
    link: &'g Dentry,
    seq: u32,
}

impl Frame<'_> {
    fn bytes(&self) -> &[u8] {
        match &self.body {
            Body::Ref(b) => b,
            Body::Own(v) => v,
        }
    }

    fn rest(&self) -> &[u8] {
        &self.bytes()[self.pos..]
    }
}

/// Linux EMBEDDED_LEVELS: links nested this deep need no allocation
const EMBEDDED: usize = 2;

/// A stack of up to MAX_SYMLINK_DEPTH levels (Linux nd->stack over
/// nd->internal): EMBEDDED in place, the rest in `more`, whose room is
/// reserved before a push needs it, bottom first
struct EmbStack<T> {
    emb: [Option<T>; EMBEDDED],
    more: Vec<T>,
}

impl<T> Default for EmbStack<T> {
    fn default() -> Self {
        Self {
            emb: [None, None],
            more: Vec::new(),
        }
    }
}

impl<T> EmbStack<T> {
    fn len(&self) -> usize {
        self.emb.iter().filter(|f| f.is_some()).count() + self.more.len()
    }

    fn get(&self, i: usize) -> &T {
        match self.emb.get(i) {
            Some(f) => f.as_ref().expect("namei: a hole in the link stack"),
            None => &self.more[i - EMBEDDED],
        }
    }

    fn get_mut(&mut self, i: usize) -> &mut T {
        match self.emb.get_mut(i) {
            Some(f) => f.as_mut().expect("namei: a hole in the link stack"),
            None => &mut self.more[i - EMBEDDED],
        }
    }

    fn top(&self) -> Option<&T> {
        self.len().checked_sub(1).map(|i| self.get(i))
    }

    fn top_mut(&mut self) -> Option<&mut T> {
        if let Some(f) = self.more.last_mut() {
            return Some(f);
        }
        self.emb.iter_mut().rev().find_map(Option::as_mut)
    }

    /// Room for one more level without an allocation
    fn has_room(&self) -> bool {
        self.len() < EMBEDDED || self.more.capacity() > self.more.len()
    }

    /// Room for every level past the embedded ones; false on ENOMEM
    fn reserve_more(&mut self) -> bool {
        let n = super::MAX_SYMLINK_DEPTH - EMBEDDED;
        self.more.try_reserve_exact(n).is_ok()
    }

    /// Push a level, room reserved
    fn push(&mut self, f: T) {
        match self.emb.iter_mut().find(|s| s.is_none()) {
            Some(s) if self.more.is_empty() => *s = Some(f),
            _ => self.more.push(f),
        }
    }

    fn pop(&mut self) -> bool {
        if self.more.pop().is_some() {
            return true;
        }
        self.emb.iter_mut().rev().find_map(Option::take).is_some()
    }

    /// Its levels, bottom first
    fn into_levels(self) -> impl Iterator<Item = T> {
        self.emb.into_iter().flatten().chain(self.more)
    }
}

/// The RCU walk's symlink stack (Linux nd->stack, nd->internal): two
/// levels in place, the rest allocated GFP_ATOMIC on first need
/// (nd_alloc_stack under LOOKUP_RCU), MAX_SYMLINK_DEPTH levels at most;
/// with it, empty, the stack its levels become once legitimized, its
/// room reserved alongside (no allocation in legitimize_links)
struct Stack<'g> {
    frames: EmbStack<Frame<'g>>,
    held: Held,
}

impl<'g> Stack<'g> {
    fn new() -> Self {
        Self {
            frames: EmbStack::default(),
            held: Held::default(),
        }
    }

    fn depth(&self) -> usize {
        self.frames.len()
    }

    fn top(&self) -> Option<&Frame<'g>> {
        self.frames.top()
    }

    fn top_mut(&mut self) -> Option<&mut Frame<'g>> {
        self.frames.top_mut()
    }

    /// Room for one more level: false if the allocation an RCU walk may
    /// make failed (Linux reserve_stack: then try_to_unlazy)
    fn reserve(&mut self) -> bool {
        if self.frames.has_room() {
            return true;
        }
        crate::util::kalloc::with_gfp(crate::mm::page_alloc::Gfp::ATOMIC, || {
            self.frames.reserve_more() && self.held.0.reserve_more()
        })
    }

    /// Push a level, room reserved
    fn push(&mut self, f: Frame<'g>) {
        self.frames.push(f);
    }

    fn pop(&mut self) -> bool {
        self.frames.pop()
    }
}

/// __legitimize_path: references to `mnt` and `d` if MOUNT_LOCK's
/// sequence is still `m_seq` and `d`'s `d_seq` still `seq`; what it
/// took anyway goes to `puts`, a path to its slot for `r`
fn legitimize_path(
    mnt: &Mount,
    d: &Dentry,
    seq: u32,
    m_seq: u32,
    puts: &mut Puts,
    r: Role,
) -> Option<Path> {
    let mnt = match MountRef::legitimize(mnt, m_seq) {
        Ok(m) => m,
        Err(m) => {
            puts.mnt(m);
            return None;
        }
    };
    let Some(dr) = DentryRef::try_get(d) else {
        puts.mnt(Some(mnt));
        return None;
    };
    let p = Path::new(mnt, dr);
    if d.d_seq_retry(seq) {
        puts.path(r, p);
        return None;
    }
    Some(p)
}

/// legitimize_links: a reference to each link on `stack`, bottom first,
/// unless one moved since it was picked (its `d_seq`, MOUNT_LOCK's
/// sequence `m_seq`); on a failure, what was taken (and the mount of
/// the link it failed on) goes to `puts`, put after the guard (Linux
/// drop_links, terminate_walk). No allocation: the levels past the
/// embedded ones go in room reserved with them.
fn legitimize_links(stack: Stack<'_>, m_seq: u32, puts: &mut Puts) -> Option<Held> {
    let Stack { frames, mut held } = stack;
    for fr in frames.into_levels() {
        let mnt = match MountRef::legitimize(fr.mnt, m_seq) {
            Ok(m) => m,
            Err(m) => {
                puts.links_mnt = m;
                puts.links = Some(held);
                return None;
            }
        };
        let Some(d) = DentryRef::try_get(fr.link) else {
            puts.links_mnt = Some(mnt);
            puts.links = Some(held);
            return None;
        };
        let moved = fr.link.d_seq_retry(fr.seq);
        held.0.push(HeldFrame {
            link: Path::new(mnt, d),
            body: match fr.body {
                Body::Ref(_) => None,
                Body::Own(v) => Some(v),
            },
            inode: None,
            pos: fr.pos,
            tail_empty: fr.tail_empty,
        });
        if moved {
            puts.links = Some(held);
            return None;
        }
    }
    Some(held)
}

/// The end of step_into under LOOKUP_RCU, onto `d` (on `mnt`, its
/// `d_seq` sampled as `seq` when `inode` was read): ECHILD if it moved
/// since; a negative entry is ENOENT, under LOOKUP_CACHED too (Linux
/// step_into: -ENOENT whatever nd->flags)
fn step_on<'g>(
    mnt: &'g Mount,
    d: &'g Dentry,
    inode: Option<&'g Inode>,
    seq: u32,
) -> Result<RcuPath<'g>, KernelError> {
    if d.d_seq_retry(seq) {
        return Err(ECHILD);
    }
    let inode = inode.ok_or(KernelError::NotFound)?;
    Ok(RcuPath {
        mnt,
        dentry: d,
        inode: Some(inode),
        seq,
    })
}

/// step_into's flags (Linux WALK_TRAILING, WALK_MORE, WALK_NOFOLLOW):
/// the last component, one more follows, never follow a symlink (".."
/// lands on a directory)
const WALK_TRAILING: u8 = 1;
const WALK_MORE: u8 = 2;
const WALK_NOFOLLOW: u8 = 4;

/// A symlink an RCU step found, for pick_link: its mount, dentry and
/// inode, the `d_seq` sample its inode was read under, whether it is
/// the walk's last component, and whether nothing follows it below
struct PickRcu<'g> {
    mnt: &'g Mount,
    link: &'g Dentry,
    inode: &'g Inode,
    seq: u32,
    last: bool,
    tail_empty: bool,
}

impl Nd<'_> {
    /// path_init, link_path_walk and complete_walk from `start` (the
    /// root if `abs`) in RCU mode: where the walk goes on in ref mode
    /// ([`Nd::unlazied`], called by the caller once this frame is gone:
    /// the ref walk may go deep); ECHILD if it could not leave RCU mode
    /// (the caller walks again in ref mode). The root and the cwd are
    /// read under the fs_struct's sequence with no reference, a held
    /// start borrowed (Linux path_init under LOOKUP_RCU).
    #[inline(never)]
    pub(super) fn walk_rcu<'p>(
        &self,
        start: Start<'_>,
        abs: bool,
        path: &'p [u8],
        f: LookupFlags,
    ) -> Result<Lazy<'p>, KernelError> {
        let fs = self.fs();
        // Boot code with no fs_struct: the namespace's root, held
        // file_open_root's root, held by the caller (ND_ROOT_PRESET)
        let preset = match self.top {
            Start::Preset(p) => Some(p),
            _ => self.root.get(),
        };
        let boot = match (fs, preset) {
            (None, None) => Some(super::nd_root()?),
            _ => None,
        };
        let mut puts = Puts::default();
        let g = crate::sync::rcu::read_lock();
        let held = preset.or(boot.as_ref());
        let root = match (held, fs) {
            (Some(p), _) => RcuPath::at(&p.mnt, &p.dentry, &g),
            (None, Some(fs)) => match self.top {
                // A scoped lookup's root is its start (Linux path_init:
                // nd->root = nd->path, root_seq = seq)
                Start::At(m, d) if self.scoped => RcuPath::at(m, d, &g),
                Start::Cwd if self.scoped => RcuPath::fs(fs.pwd_rcu(&g), &g),
                _ => RcuPath::fs(fs.root_rcu(&g), &g),
            },
            (None, None) => unreachable!("namei: no root"),
        };
        let at = match start {
            _ if abs => root,
            Start::Root => root,
            Start::Cwd => match fs {
                Some(_) if self.scoped => root,
                Some(fs) => RcuPath::fs(fs.pwd_rcu(&g), &g),
                None => root,
            },
            Start::At(m, d) => RcuPath::at(m, d, &g),
            Start::Preset(_) => root,
        };
        let rc = Rcu { g: &g, root, held };
        let r = self.link_path_walk_rcu(&rc, at, path, f, &mut puts);
        drop(g);
        // leave_rcu, whatever the outcome; then terminate_walk's puts
        self.rcu.set(false);
        drop(puts);
        drop(boot);
        r
    }

    /// link_path_walk under LOOKUP_RCU: every component that the dcache
    /// holds and needs nothing of ref mode, through the symlinks it can
    /// follow in RCU mode (their bodies on `stack`), then complete_walk
    #[inline(never)]
    fn link_path_walk_rcu<'g, 'p>(
        &self,
        rc: &Rcu<'g>,
        mut cur: RcuPath<'g>,
        path: &'p [u8],
        mut f: LookupFlags,
        puts: &mut Puts,
    ) -> Result<Lazy<'p>, KernelError> {
        let mut user = path;
        let mut stack = Stack::new();
        let mut total = 0;
        loop {
            // The current text: the top body's rest, else the path's
            let (text, tail_empty) = match stack.top() {
                Some(fr) => (fr.rest(), fr.tail_empty),
                None => (user, true),
            };
            let Some((name, after)) = next_comp(text) else {
                // A body walked to its end: what followed it goes on
                if stack.pop() {
                    continue;
                }
                break;
            };
            let at = text.len() - name.len() - after.len();
            let next = text.len() - after.len();
            let last = tail_empty && next_comp(after).is_none();
            // lookup_last of a body's last component: a slash after it
            // asks for a directory, through a final symlink
            if last && stack.depth() > 0 && !after.is_empty() {
                f.follow = true;
                f.directory = true;
            }
            if let Err(e) = self.may_lookup_rcu(&cur) {
                // Out of RCU mode to see it was not transient (Linux
                // may_lookup): a hard error stands, ECHILD asks again
                let p = self.try_to_unlazy(rc, &cur, f.cached, puts)?;
                if e != ECHILD {
                    puts.path(Role::Path, p);
                    return Err(e);
                }
                return self.lazy(To::Comp(p), stack, user, at, f, total, puts);
            }
            let step = match name {
                b"." => Step::On,
                b".." => {
                    // handle_dots: follow_dotdot_rcu, step_into with
                    // WALK_NOFOLLOW, then a scoped walk's check
                    let (d, seq) = self.follow_dotdot_rcu(rc, &mut cur, f)?;
                    let inode = d.d_inode_rcu(rc.g);
                    let s =
                        self.step_into_rcu(rc, &mut cur, d, inode, seq, WALK_NOFOLLOW, f, puts)?;
                    if matches!(s, Step::On) {
                        self.recheck()?;
                    }
                    s
                }
                _ => {
                    let flags = if last { WALK_TRAILING } else { WALK_MORE };
                    self.walk_component_rcu(rc, &mut cur, name, flags, f, puts)?
                }
            };
            let (mnt, link, inode, seq, last) = match step {
                Step::On => (None, None, None, 0, false),
                Step::Lazy(to) => return self.lazy(to, stack, user, at, f, total, puts),
                Step::Link {
                    mnt,
                    link,
                    inode,
                    seq,
                    last,
                } => (Some(mnt), Some(link), Some(inode), seq, last),
            };
            // Past the component
            let body_tail = tail_empty && next_comp(after).is_none();
            match stack.top_mut() {
                Some(fr) => fr.pos += next,
                None => user = &user[next..],
            }
            let (Some(mnt), Some(link), Some(inode)) = (mnt, link, inode) else {
                continue;
            };
            let l = PickRcu {
                mnt,
                link,
                inode,
                seq,
                last,
                tail_empty: body_tail,
            };
            if let Some(to) =
                self.pick_link_rcu(rc, &mut cur, &mut stack, l, &mut total, f, puts)?
            {
                return self.lazy(to, stack, user, 0, f, total, puts);
            }
        }
        // complete_walk: LOOKUP_CACHED is cleared for this last unlazy,
        // and only a scoped lookup keeps its root (Linux: nd->root.mnt =
        // NULL, so legitimize_root has nothing to do)
        let p = self.unlazy(rc, &cur, false, self.scoped, puts)?;
        Ok(Lazy {
            to: To::Done(p),
            stack: Held::default(),
            user: &[],
            f,
            depth: total,
        })
    }

    /// What ref mode goes on with: `to`, and the rest of the name from
    /// offset `from` of the current text (the top body's rest, else the
    /// path's), with the link stack held (Linux try_to_unlazy's
    /// legitimize_links; ECHILD if a link moved, and the lookup starts
    /// over in ref mode); no body is copied
    #[allow(clippy::too_many_arguments)]
    fn lazy<'p>(
        &self,
        to: To,
        stack: Stack<'_>,
        user: &'p [u8],
        from: usize,
        f: LookupFlags,
        depth: usize,
        puts: &mut Puts,
    ) -> Result<Lazy<'p>, KernelError> {
        if stack.depth() == 0 {
            return Ok(Lazy {
                to,
                stack: Held::default(),
                user: &user[from..],
                f,
                depth,
            });
        }
        let Some(mut held) = legitimize_links(stack, self.m_seq, puts) else {
            // `to`'s references go after the guard, with the walk's
            // other leftovers
            puts.to(to);
            return Err(ECHILD);
        };
        if let Some(top) = held.0.top_mut() {
            top.pos += from;
        }
        Ok(Lazy {
            to,
            stack: held,
            user,
            f,
            depth,
        })
    }

    /// may_lookup under LOOKUP_RCU: `cur` is a directory (link_path_walk's
    /// d_can_lookup) the caller may search, asked with MAY_NOT_BLOCK
    /// (Linux lookup_inode_permission_may_exec): ECHILD where only the
    /// ref-walk can tell, as for a negative start
    fn may_lookup_rcu(&self, cur: &RcuPath<'_>) -> Result<(), KernelError> {
        let inode = cur.inode.ok_or(ECHILD)?;
        if !inode.mode().is_dir() {
            return Err(KernelError::NotDirectory);
        }
        permission_as(self.cred(), inode, MAY_EXEC | MAY_NOT_BLOCK)
    }

    /// walk_component under LOOKUP_RCU: lookup_fast, then step_into
    #[allow(clippy::too_many_arguments)]
    fn walk_component_rcu<'g>(
        &self,
        rc: &Rcu<'g>,
        cur: &mut RcuPath<'g>,
        name: &[u8],
        flags: u8,
        f: LookupFlags,
        puts: &mut Puts,
    ) -> Result<Step<'g>, KernelError> {
        // A miss, maybe a rename's (no RENAME_LOCK check: lookup_slow
        // decides under the directory's lock)
        let Some((child, seq)) = __d_lookup_rcu(cur.dentry, name, rc.g) else {
            let at = self.try_to_unlazy(rc, cur, f.cached, puts)?;
            return Ok(Step::Lazy(To::Lookup(at)));
        };
        // The parent did not change during the lookup
        if cur.dentry.d_seq_retry(cur.seq) {
            return Err(ECHILD);
        }
        let inode = child.d_inode_rcu(rc.g);
        // d_revalidate under LOOKUP_RCU, a negative entry's too; anything
        // but "valid" is handled in ref mode (Linux lookup_fast:
        // try_to_unlazy_next, then d_invalidate if stale, the error if
        // one, ref-mode d_revalidate if ECHILD)
        // `cur` is a directory may_lookup let through
        let dir = cur.inode.ok_or(ECHILD)?;
        let status = child.revalidate(dir, inode, LookupBits::RCU | f.bits());
        if status != Ok(true) {
            let (at, c) = self.try_to_unlazy_next(rc, cur, child, seq, f.cached, puts)?;
            return Ok(Step::Lazy(To::Child {
                cur: at,
                child: c,
                reval: Some(status),
                dots: false,
            }));
        }
        self.step_into_rcu(rc, cur, child, inode, seq, flags, f, puts)
    }

    /// step_into under LOOKUP_RCU: onto `child` (its `d_seq` was
    /// `seq` when `inode` was read), across what is mounted on it,
    /// unless it is a symlink to follow (`flags`: WALK_*)
    #[allow(clippy::too_many_arguments)]
    fn step_into_rcu<'g>(
        &self,
        rc: &Rcu<'g>,
        cur: &mut RcuPath<'g>,
        child: &'g Dentry,
        inode: Option<&'g Inode>,
        seq: u32,
        flags: u8,
        f: LookupFlags,
        puts: &mut Puts,
    ) -> Result<Step<'g>, KernelError> {
        // handle_mounts: what is mounted on it crossed in RCU mode, else
        // try_to_unlazy_next and traverse_mounts in ref mode
        let (mut mnt, mut d, mut seq, mut inode) = (cur.mnt, child, seq, inode);
        if child.is_mountpoint() {
            let Some((m, r, s)) = self.follow_mount_rcu(rc.g, mnt, child, seq, f) else {
                let (at, c) = self.try_to_unlazy_next(rc, cur, child, seq, f.cached, puts)?;
                return Ok(Step::Lazy(To::Child {
                    cur: at,
                    child: c,
                    reval: None,
                    dots: flags & WALK_NOFOLLOW != 0,
                }));
            };
            (mnt, d, seq, inode) = (m, r, s, r.d_inode_rcu(rc.g));
        }
        let last = flags & WALK_TRAILING != 0;
        let follow = flags & WALK_NOFOLLOW == 0 && (!last || f.follow);
        if follow && let Some(i) = inode.filter(|i| i.mode().is_symlink()) {
            return Ok(Step::Link {
                mnt,
                link: d,
                inode: i,
                seq,
                last,
            });
        }
        *cur = step_on(mnt, d, inode, seq)?;
        Ok(Step::On)
    }

    /// follow_dotdot_rcu: the parent ".." lands on from `cur` and its
    /// `d_seq` sample. At the root it stays (EXDEV beneath: ECHILD, the
    /// ref walk reports it); at a mount's root `cur` climbs to the
    /// mountpoint first (choose_mountpoint_rcu; a no-xdev walk's EXDEV
    /// is the ref walk's too). Each step is checked against MOUNT_LOCK's
    /// sequence and `cur`'s `d_seq`; a parent a rename left outside a
    /// bind mount's root is ECHILD (path_connected, ENOENT in ref mode).
    fn follow_dotdot_rcu<'g>(
        &self,
        rc: &Rcu<'g>,
        cur: &mut RcuPath<'g>,
        f: LookupFlags,
    ) -> Result<(&'g Dentry, u32), KernelError> {
        let g = rc.g;
        let at_root =
            core::ptr::eq(cur.mnt, rc.root.mnt) && core::ptr::eq(cur.dentry, rc.root.dentry);
        if !at_root && core::ptr::eq(cur.dentry, cur.mnt.root_addr()) {
            match choose_mountpoint_rcu(cur.mnt, rc.root.pair(), g) {
                Some((m, mp)) => {
                    if f.no_xdev {
                        return Err(ECHILD);
                    }
                    let seq = mp.d_seq_begin();
                    *cur = RcuPath {
                        mnt: m,
                        dentry: mp,
                        inode: mp.d_inode_rcu(g),
                        seq,
                    };
                    // A ref walk could have reached this
                    if MOUNT_LOCK.read_retry(self.m_seq) {
                        return Err(ECHILD);
                    }
                }
                None => return self.in_root_rcu(cur, f),
            }
        } else if at_root {
            return self.in_root_rcu(cur, f);
        }
        let old = cur.dentry;
        // A root dentry is its own parent (IS_ROOT)
        let parent = old.parent_rcu(g).unwrap_or(old);
        let seq = parent.d_seq_begin();
        if old.d_seq_retry(cur.seq) || !path_connected(cur.mnt, parent, g) {
            return Err(ECHILD);
        }
        Ok((parent, seq))
    }

    /// follow_dotdot_rcu's in_root: ".." stays where it is
    fn in_root_rcu<'g>(
        &self,
        cur: &RcuPath<'g>,
        f: LookupFlags,
    ) -> Result<(&'g Dentry, u32), KernelError> {
        if MOUNT_LOCK.read_retry(self.m_seq) || f.beneath {
            return Err(ECHILD);
        }
        Ok((cur.dentry, cur.seq))
    }

    /// __follow_mount_rcu: from `d` in `mnt` (its `d_seq` sampled as
    /// `seq`) down the mounts stacked on it to the topmost one's root
    /// and that root's `d_seq` sample, each step checked against
    /// MOUNT_LOCK's sequence (a ref walk could have reached that
    /// state); None where ref mode must decide: a no-xdev walk (EXDEV
    /// there), or a mount change
    fn follow_mount_rcu<'g>(
        &self,
        g: &'g RcuReadGuard,
        mut mnt: &'g Mount,
        mut d: &'g Dentry,
        mut seq: u32,
        f: LookupFlags,
    ) -> Option<(&'g Mount, &'g Dentry, u32)> {
        if f.no_xdev {
            return None;
        }
        while d.is_mountpoint() {
            let m = __lookup_mnt(mnt, d, g);
            if MOUNT_LOCK.read_retry(self.m_seq) {
                return None;
            }
            let Some(m) = m else {
                break;
            };
            mnt = m;
            d = m.root_rcu(g);
            seq = d.d_seq_begin();
        }
        Some((mnt, d, seq))
    }

    /// pick_link under LOOKUP_RCU: symlink `l.link` in `cur`, its checks
    /// (MAX_SYMLINK_DEPTH links in all, ELOOP; fs.protected_symlinks for
    /// the trailing link, refused as ECHILD: the ref-walk reports it;
    /// RESOLVE_NO_SYMLINKS and nosymfollow: ELOOP), then its body: the
    /// inode's `i_link`, else ->get_link asked in RCU mode (a NULL
    /// dentry). An absolute body moves `cur` to the root (nd_jump_root);
    /// what is left of it is pushed on `stack`, walked next. None when
    /// the walk goes on in RCU mode; else where ref mode takes over,
    /// the link held (try_to_unlazy after legitimize_links): an atime
    /// to update, a body only ref mode can give (ECHILD), or a stack
    /// level that could not be allocated.
    #[allow(clippy::too_many_arguments)]
    fn pick_link_rcu<'g>(
        &self,
        rc: &Rcu<'g>,
        cur: &mut RcuPath<'g>,
        stack: &mut Stack<'g>,
        l: PickRcu<'g>,
        total: &mut usize,
        f: LookupFlags,
        puts: &mut Puts,
    ) -> Result<Option<To>, KernelError> {
        // What made it a symlink is still so
        if l.link.d_seq_retry(l.seq) {
            return Err(ECHILD);
        }
        // reserve_stack's count
        if *total >= super::MAX_SYMLINK_DEPTH {
            return Err(KernelError::TooManySymlinks);
        }
        *total += 1;
        if l.last
            && let Some(d) = cur.inode
            && may_follow_link(self.cred(), d, l.inode).is_err()
        {
            return Err(ECHILD);
        }
        if f.no_symlinks || l.mnt.flags() & MNT_NOSYMFOLLOW != 0 {
            return Err(KernelError::TooManySymlinks);
        }
        if l.inode.atime_needs_update(l.mnt) {
            return self.unlazy_link(rc, cur, &l, f, puts).map(Some);
        }
        let body = match l.inode.i_link() {
            Some(b) => Body::Ref(b),
            None => match l.inode.i_op.get_link(l.inode, true) {
                Ok(Link::Text(t)) => Body::Own(t),
                Ok(Link::Jump(p)) => {
                    // RCU mode never jumps (procfs's magic links are
                    // ECHILD there): put after the guard, ref mode asks
                    puts.path(Role::Link, p);
                    return Err(ECHILD);
                }
                Err(ECHILD) => return self.unlazy_link(rc, cur, &l, f, puts).map(Some),
                Err(e) => return Err(e),
            },
        };
        if !stack.reserve() {
            return self.unlazy_link(rc, cur, &l, f, puts).map(Some);
        }
        let b = match &body {
            Body::Ref(b) => *b,
            Body::Own(v) => v.as_slice(),
        };
        let mut pos = 0;
        if b.starts_with(b"/") {
            self.jump_root_rcu(rc, cur, f)?;
            pos = b.iter().position(|&c| c != b'/').unwrap_or(b.len());
        }
        // A body of slashes alone is a pure jump (Linux all_done)
        if pos < b.len() {
            stack.push(Frame {
                body,
                pos,
                tail_empty: l.tail_empty,
                mnt: l.mnt,
                link: l.link,
                seq: l.seq,
            });
        }
        Ok(None)
    }

    /// nd_jump_root under LOOKUP_RCU: EXDEV beneath, and for a no-xdev
    /// walk off the root's mount; `cur` becomes the root read at the
    /// walk's start, its `d_seq` checked
    fn jump_root_rcu<'g>(
        &self,
        rc: &Rcu<'g>,
        cur: &mut RcuPath<'g>,
        f: LookupFlags,
    ) -> Result<(), KernelError> {
        if f.beneath || (f.no_xdev && !core::ptr::eq(cur.mnt, rc.root.mnt)) {
            return Err(KernelError::CrossDevice);
        }
        if rc.root.dentry.d_seq_retry(rc.root.seq) {
            return Err(ECHILD);
        }
        *cur = rc.root;
        Ok(())
    }

    /// pick_link's try_to_unlazy with the link held (legitimize_links):
    /// ref mode follows it; LOOKUP_CACHED fails it before anything is
    /// taken
    fn unlazy_link(
        &self,
        rc: &Rcu<'_>,
        cur: &RcuPath<'_>,
        l: &PickRcu<'_>,
        f: LookupFlags,
        puts: &mut Puts,
    ) -> Result<To, KernelError> {
        if f.cached {
            return Err(ECHILD);
        }
        let link =
            legitimize_path(l.mnt, l.link, l.seq, self.m_seq, puts, Role::Link).ok_or(ECHILD)?;
        match self.try_to_unlazy(rc, cur, false, puts) {
            Ok(at) => Ok(To::Link {
                cur: at,
                link,
                last: l.last,
            }),
            Err(e) => {
                puts.path(Role::Link, link);
                Err(e)
            }
        }
    }

    /// try_to_unlazy: references to where the walk stands and to the
    /// root (legitimize_root), unless LOOKUP_CACHED forbids leaving RCU
    /// mode (`cached`) or something moved: ECHILD then
    fn try_to_unlazy(
        &self,
        rc: &Rcu<'_>,
        cur: &RcuPath<'_>,
        cached: bool,
        puts: &mut Puts,
    ) -> Result<Path, KernelError> {
        self.unlazy(rc, cur, cached, true, puts)
    }

    /// [`Nd::try_to_unlazy`], the root legitimized only if `root`
    fn unlazy(
        &self,
        rc: &Rcu<'_>,
        cur: &RcuPath<'_>,
        cached: bool,
        root: bool,
        puts: &mut Puts,
    ) -> Result<Path, KernelError> {
        if cached {
            return Err(ECHILD);
        }
        let at = legitimize_path(cur.mnt, cur.dentry, cur.seq, self.m_seq, puts, Role::Path)
            .ok_or(ECHILD)?;
        if root && !self.legitimize_root(rc, puts) {
            puts.path(Role::Path, at);
            return Err(ECHILD);
        }
        Ok(at)
    }

    /// legitimize_root: a reference to the root the walk read with
    /// none, for the rest of the lookup in ref mode, unless it has one
    /// (an earlier walk's, or a path the walk holds: a scoped lookup's
    /// start, boot code's namespace root); false if it moved
    fn legitimize_root(&self, rc: &Rcu<'_>, puts: &mut Puts) -> bool {
        // ND_ROOT_PRESET: the caller holds it
        if self.root.get().is_some() || matches!(self.top, Start::Preset(_)) {
            return true;
        }
        let p = match (rc.held, self.top) {
            (Some(p), _) => p.clone(),
            (None, Start::At(m, d)) if self.scoped => Path::new(m.clone(), d.clone()),
            _ => {
                let r = &rc.root;
                match legitimize_path(r.mnt, r.dentry, r.seq, self.m_seq, puts, Role::Root) {
                    Some(p) => p,
                    None => return false,
                }
            }
        };
        let _ = self.root.set(p);
        true
    }

    /// try_to_unlazy_next: [`Nd::try_to_unlazy`] and a reference to
    /// `child` too, whose `d_seq` still at `seq` vouches for both
    /// (it was read after the parent's was checked)
    fn try_to_unlazy_next(
        &self,
        rc: &Rcu<'_>,
        cur: &RcuPath<'_>,
        child: &Dentry,
        seq: u32,
        cached: bool,
        puts: &mut Puts,
    ) -> Result<(Path, DentryRef), KernelError> {
        if cached {
            return Err(ECHILD);
        }
        let mnt = match MountRef::legitimize(cur.mnt, self.m_seq) {
            Ok(m) => m,
            Err(m) => {
                puts.mnt(m);
                return Err(ECHILD);
            }
        };
        let Some(d) = DentryRef::try_get(cur.dentry) else {
            puts.mnt(Some(mnt));
            return Err(ECHILD);
        };
        let at = Path::new(mnt, d);
        let Some(c) = DentryRef::try_get(child) else {
            puts.path(Role::Path, at);
            return Err(ECHILD);
        };
        if child.d_seq_retry(seq) || !self.legitimize_root(rc, puts) {
            puts.path(Role::Path, at);
            puts.dentry(c);
            return Err(ECHILD);
        }
        Ok((at, c))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::dentry::d_move;
    use crate::fs::inode::{InodeMode, NULL_INODE_OPS, Timespec};
    use alloc::sync::{Arc, Weak};

    fn inode() -> InodeRef {
        Inode::alloc(Inode::new(
            1,
            InodeMode::directory(0o755),
            0,
            0,
            0,
            Timespec::from_secs(0),
            Weak::new(),
            &NULL_INODE_OPS,
        ))
        .unwrap()
    }

    /// legitimize_path: references while both sequences hold; a move of
    /// the dentry since its sample fails it, and what it took is handed
    /// to the caller to put (terminate_walk), not leaked; a mount change
    /// fails it before any reference
    #[test]
    fn legitimize_seq() {
        let m = crate::fs::mount::test_mnt();
        let a = Dentry::alloc(&m.root, b"a", Some(inode())).unwrap();
        let n = DentryRef::count(&a);
        // Other tests change mounts (MOUNT_LOCK's sequence): sample again
        let mut got = None;
        for _ in 0..1000 {
            let m_seq = crate::fs::mount::MOUNT_LOCK.read_begin();
            let seq = a.d_seq_begin();
            let mut puts = Puts::default();
            let g = crate::sync::rcu::read_lock();
            let p = legitimize_path(&m, &a, seq, m_seq, &mut puts, Role::Path);
            drop(g);
            if let Some(p) = p {
                assert!(puts.path.is_none() && puts.mnt.is_none());
                got = Some((p, m_seq, seq));
                break;
            }
        }
        let (p, m_seq, seq) = got.unwrap();
        assert!(DentryRef::ptr_eq(&p.dentry, &a));
        drop(p);
        assert_eq!(DentryRef::count(&a), n);
        let mut puts = Puts::default();
        let t = Dentry::prealloc(&m.root, b"b").unwrap();
        d_move(&a, &t);
        let g = crate::sync::rcu::read_lock();
        assert!(legitimize_path(&m, &a, seq, m_seq, &mut puts, Role::Path).is_none());
        drop(g);
        drop(puts);
        assert_eq!(DentryRef::count(&a), n);
        let mut puts = Puts::default();
        let seq = a.d_seq_begin();
        let g = crate::sync::rcu::read_lock();
        let stale = m_seq.wrapping_sub(2);
        assert!(legitimize_path(&m, &a, seq, stale, &mut puts, Role::Path).is_none());
        drop(g);
        assert!(puts.path.is_none() && puts.mnt.is_none());
        assert_eq!(DentryRef::count(&a), n);
    }

    /// A cached negative entry the RCU walk steps onto is ENOENT, under
    /// LOOKUP_CACHED too (Linux step_into), not ECHILD (EAGAIN); one
    /// that moved since its sample is ECHILD; a positive one is stood on
    #[test]
    fn step_onto_negative_is_enoent() {
        let m = crate::fs::mount::test_mnt();
        let n = Dentry::alloc(&m.root, b"neg", None).unwrap();
        let a = Dentry::alloc(&m.root, b"pos", Some(inode())).unwrap();
        let g = crate::sync::rcu::read_lock();
        let seq = n.d_seq_begin();
        let r = step_on(&m, &n, n.d_inode_rcu(&g), seq);
        assert_eq!(r.err(), Some(KernelError::NotFound));
        let seq = a.d_seq_begin();
        let p = step_on(&m, &a, a.d_inode_rcu(&g), seq).unwrap();
        assert!(core::ptr::eq(p.dentry, &*a) && p.inode.is_some());
        drop(g);
        let t = Dentry::prealloc(&m.root, b"moved").unwrap();
        d_move(&a, &t);
        let g = crate::sync::rcu::read_lock();
        let r = step_on(&m, &a, a.d_inode_rcu(&g), seq);
        assert_eq!(r.err(), Some(ECHILD));
        drop(g);
    }
}

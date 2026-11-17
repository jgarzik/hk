//! RCU path walk (Linux fs/namei.c in LOOKUP_RCU mode)
//!
//! A walk first runs under one RCU read guard, taking no reference and
//! no lock and storing nothing to a shared dentry, inode or lock word:
//! each component is found with `__d_lookup_rcu`, its inode borrowed
//! with `d_inode_rcu`, and what was read is confirmed by the dentry's
//! `d_seq` (Linux nd->seq, nd->next_seq); the search permission is
//! asked with MAY_NOT_BLOCK of fields an RCU reader may read. Where the
//! walk cannot go on that way (a miss, a symlink's body, a
//! revalidation or permission check the file system can only do with
//! a reference), it takes references to where it stands (try_to_unlazy
//! and try_to_unlazy_next: legitimize_path, a reference taken unless
//! the object died, its sequence checked after) and goes on in ref mode
//! from that point ([`Lazy`]). If that fails, or a sequence moved, the
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

use super::{ECHILD, LookupFlags, Nd, next_comp};
use crate::fs::KernelError;
use crate::fs::dac::{MAY_EXEC, MAY_NOT_BLOCK, may_follow_link, permission_as};
use crate::fs::dentry::{__d_lookup_rcu, Dentry, DentryRef};
use crate::fs::inode::Inode;
use crate::fs::mount::{__lookup_mnt, MNT_NOSYMFOLLOW, MOUNT_LOCK, Mount, MountRef};
use crate::fs::path_ref::Path;
use crate::sync::rcu::RcuReadGuard;

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
    fn held(p: &'g Path, g: &'g RcuReadGuard) -> Self {
        let dentry: &Dentry = &p.dentry;
        let seq = dentry.d_seq_begin();
        Self {
            mnt: &p.mnt,
            dentry,
            inode: dentry.d_inode_rcu(g),
            seq,
        }
    }
}

/// What a failed legitimize took, put by the caller after the RCU
/// guard (Linux terminate_walk's path_put after leave_rcu): a put may
/// be the last, which kills a dentry or tears a mount down
#[derive(Default)]
pub(super) struct Puts {
    paths: [Option<Path>; 2],
    mnt: Option<MountRef>,
    dentry: Option<DentryRef>,
}

impl Puts {
    fn path(&mut self, p: Path) {
        let slot = self.paths.iter_mut().find(|s| s.is_none());
        debug_assert!(
            slot.is_some(),
            "namei: more paths to put than an unlazy takes"
        );
        if let Some(s) = slot {
            *s = Some(p);
        }
    }
}

/// Where a walk goes on in ref mode once it left RCU mode (Linux: the
/// same loop, LOOKUP_RCU cleared, from where try_to_unlazy returned)
pub(super) enum Lazy<'p> {
    /// The walk's end (complete_walk)
    Done(Path),
    /// may_lookup's ECHILD: the component starting `path` again, its
    /// permission asked in ref mode
    Comp(Path, &'p [u8]),
    /// lookup_fast's miss of `name`: lookup_slow, then `rest`
    Lookup(Path, &'p [u8], &'p [u8]),
    /// try_to_unlazy_next with `child`, found for `name` in `cur`:
    /// revalidated in ref mode if `reval`, then stepped into, then
    /// `rest`
    Child {
        cur: Path,
        child: DentryRef,
        name: &'p [u8],
        rest: &'p [u8],
        reval: bool,
    },
    /// pick_link: symlink `link` in `cur`, checked; its body in ref
    /// mode, then `rest`
    Link {
        cur: Path,
        link: Path,
        rest: &'p [u8],
    },
}

/// __legitimize_path: references to `mnt` and `d` if MOUNT_LOCK's
/// sequence is still `m_seq` and `d`'s `d_seq` still `seq`; what it
/// took anyway goes to `puts`
fn legitimize_path(mnt: &Mount, d: &Dentry, seq: u32, m_seq: u32, puts: &mut Puts) -> Option<Path> {
    let mnt = match MountRef::legitimize(mnt, m_seq) {
        Ok(m) => m,
        Err(put) => {
            puts.mnt = put;
            return None;
        }
    };
    let Some(dr) = DentryRef::try_get(d) else {
        puts.mnt = Some(mnt);
        return None;
    };
    let p = Path::new(mnt, dr);
    if d.d_seq_retry(seq) {
        puts.path(p);
        return None;
    }
    Some(p)
}

impl Nd {
    /// link_path_walk and complete_walk from `start` in RCU mode,
    /// going on in ref mode where it must; ECHILD if it could not
    /// leave RCU mode (the caller walks again in ref mode)
    pub(super) fn walk_rcu(
        &self,
        start: &Path,
        path: &[u8],
        f: LookupFlags,
    ) -> Result<Path, KernelError> {
        let mut puts = Puts::default();
        let g = crate::sync::rcu::read_lock();
        let r = self.link_path_walk_rcu(&g, RcuPath::held(start, &g), path, f, &mut puts);
        drop(g);
        // leave_rcu, whatever the outcome; then terminate_walk's puts
        self.rcu.set(false);
        drop(puts);
        self.unlazied(r?, f)
    }

    /// link_path_walk under LOOKUP_RCU: every component that the dcache
    /// holds and needs nothing of ref mode, then complete_walk
    #[inline(never)]
    fn link_path_walk_rcu<'g, 'p>(
        &self,
        g: &'g RcuReadGuard,
        mut cur: RcuPath<'g>,
        path: &'p [u8],
        f: LookupFlags,
        puts: &mut Puts,
    ) -> Result<Lazy<'p>, KernelError> {
        let mut p = path;
        while let Some((name, rest)) = next_comp(p) {
            let last = next_comp(rest).is_none();
            if let Err(e) = self.may_lookup_rcu(&cur) {
                // Out of RCU mode to see it was not transient (Linux
                // may_lookup): a hard error stands, ECHILD asks again
                let at = self.try_to_unlazy(&cur, f.cached, puts)?;
                if e != ECHILD {
                    puts.path(at);
                    return Err(e);
                }
                return Ok(Lazy::Comp(at, p));
            }
            match name {
                b"." => {}
                b".." => {
                    // follow_dotdot needs the ref-walk here
                    return Ok(Lazy::Comp(self.try_to_unlazy(&cur, f.cached, puts)?, p));
                }
                _ => {
                    let step = self.walk_component_rcu(g, &mut cur, name, rest, last, f, puts)?;
                    if let Some(l) = step {
                        return Ok(l);
                    }
                }
            }
            p = rest;
        }
        // complete_walk: LOOKUP_CACHED is cleared for this last unlazy
        Ok(Lazy::Done(self.try_to_unlazy(&cur, false, puts)?))
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
        permission_as(&self.c, inode, MAY_EXEC | MAY_NOT_BLOCK)
    }

    /// walk_component under LOOKUP_RCU: lookup_fast, then step_into.
    /// None once `cur` is the child; else where the walk goes on in ref
    /// mode.
    #[allow(clippy::too_many_arguments)]
    fn walk_component_rcu<'g, 'p>(
        &self,
        g: &'g RcuReadGuard,
        cur: &mut RcuPath<'g>,
        name: &'p [u8],
        rest: &'p [u8],
        last: bool,
        f: LookupFlags,
        puts: &mut Puts,
    ) -> Result<Option<Lazy<'p>>, KernelError> {
        // A miss, maybe a rename's (no RENAME_LOCK check: lookup_slow
        // decides under the directory's lock)
        let Some((child, seq)) = __d_lookup_rcu(cur.dentry, name, g) else {
            let at = self.try_to_unlazy(cur, f.cached, puts)?;
            return Ok(Some(Lazy::Lookup(at, name, rest)));
        };
        // The parent did not change during the lookup
        if cur.dentry.d_seq_retry(cur.seq) {
            return Err(ECHILD);
        }
        let inode = child.d_inode_rcu(g);
        // d_revalidate under LOOKUP_RCU (only a positive entry has one,
        // as in ref mode); anything but "valid" is decided in ref mode
        if inode.is_some_and(|i| i.i_op.revalidate(i, true) != Ok(true)) {
            let (at, c) = self.try_to_unlazy_next(cur, child, seq, f.cached, puts)?;
            return Ok(Some(Lazy::Child {
                cur: at,
                child: c,
                name,
                rest,
                reval: true,
            }));
        }
        self.step_into_rcu(g, cur, child, inode, seq, name, rest, last, f, puts)
    }

    /// step_into under LOOKUP_RCU: onto `child` (its `d_seq` was
    /// `seq` when `inode` was read) unless it is mounted on or a
    /// symlink to follow
    #[allow(clippy::too_many_arguments)]
    fn step_into_rcu<'g, 'p>(
        &self,
        g: &'g RcuReadGuard,
        cur: &mut RcuPath<'g>,
        child: &'g Dentry,
        inode: Option<&'g Inode>,
        seq: u32,
        name: &'p [u8],
        rest: &'p [u8],
        last: bool,
        f: LookupFlags,
        puts: &mut Puts,
    ) -> Result<Option<Lazy<'p>>, KernelError> {
        // handle_mounts: what is mounted on it crossed in RCU mode, else
        // try_to_unlazy_next and traverse_mounts in ref mode
        let (mut mnt, mut d, mut seq, mut inode) = (cur.mnt, child, seq, inode);
        if child.is_mountpoint() {
            let Some((m, r, s)) = self.follow_mount_rcu(g, mnt, child, seq, f) else {
                let (at, c) = self.try_to_unlazy_next(cur, child, seq, f.cached, puts)?;
                return Ok(Some(Lazy::Child {
                    cur: at,
                    child: c,
                    name,
                    rest,
                    reval: false,
                }));
            };
            (mnt, d, seq, inode) = (m, r, s, r.d_inode_rcu(g));
        }
        let link = inode.is_some_and(|i| i.mode().is_symlink());
        if link && (!last || f.follow) {
            let l = self.pick_link_rcu(cur, mnt, d, inode, seq, rest, last, f, puts)?;
            return Ok(Some(l));
        }
        if d.d_seq_retry(seq) {
            return Err(ECHILD);
        }
        let Some(inode) = inode else {
            // A negative entry, cached only by in-memory filesystems,
            // where Linux keeps none (always_delete_dentry): ENOENT as
            // Linux's step_into, and under LOOKUP_CACHED a miss there
            return Err(if f.cached {
                ECHILD
            } else {
                KernelError::NotFound
            });
        };
        *cur = RcuPath {
            mnt,
            dentry: d,
            inode: Some(inode),
            seq,
        };
        Ok(None)
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

    /// pick_link under LOOKUP_RCU: symlink `link` on `mnt`, its checks
    /// (fs.protected_symlinks for the trailing link, refused as ECHILD:
    /// the ref-walk reports it; RESOLVE_NO_SYMLINKS and nosymfollow:
    /// ELOOP), then try_to_unlazy with the link held (legitimize_links),
    /// since its atime and body need ref mode (hk has no RCU
    /// ->get_link: Linux's get_link(NULL) -ECHILD)
    #[allow(clippy::too_many_arguments)]
    fn pick_link_rcu<'g, 'p>(
        &self,
        cur: &RcuPath<'g>,
        mnt: &'g Mount,
        link: &'g Dentry,
        inode: Option<&'g Inode>,
        seq: u32,
        rest: &'p [u8],
        last: bool,
        f: LookupFlags,
        puts: &mut Puts,
    ) -> Result<Lazy<'p>, KernelError> {
        // What made it a symlink is still so
        if link.d_seq_retry(seq) {
            return Err(ECHILD);
        }
        if last
            && let (Some(d), Some(i)) = (cur.inode, inode)
            && may_follow_link(&self.c, d, i).is_err()
        {
            return Err(ECHILD);
        }
        if f.no_symlinks || mnt.flags() & MNT_NOSYMFOLLOW != 0 {
            return Err(KernelError::TooManySymlinks);
        }
        // try_to_unlazy: LOOKUP_CACHED fails it before anything is taken
        if f.cached {
            return Err(ECHILD);
        }
        let link = legitimize_path(mnt, link, seq, self.m_seq, puts).ok_or(ECHILD)?;
        match self.try_to_unlazy(cur, false, puts) {
            Ok(at) => Ok(Lazy::Link {
                cur: at,
                link,
                rest,
            }),
            Err(e) => {
                puts.path(link);
                Err(e)
            }
        }
    }

    /// try_to_unlazy: references to where the walk stands, unless
    /// LOOKUP_CACHED forbids leaving RCU mode (`cached`) or something
    /// moved: ECHILD then. The root needs none (the walk holds it:
    /// legitimize_root of ND_ROOT_PRESET).
    fn try_to_unlazy(
        &self,
        cur: &RcuPath<'_>,
        cached: bool,
        puts: &mut Puts,
    ) -> Result<Path, KernelError> {
        if cached {
            return Err(ECHILD);
        }
        legitimize_path(cur.mnt, cur.dentry, cur.seq, self.m_seq, puts).ok_or(ECHILD)
    }

    /// try_to_unlazy_next: [`Nd::try_to_unlazy`] and a reference to
    /// `child` too, whose `d_seq` still at `seq` vouches for both
    /// (it was read after the parent's was checked)
    fn try_to_unlazy_next(
        &self,
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
            Err(put) => {
                puts.mnt = put;
                return Err(ECHILD);
            }
        };
        let Some(d) = DentryRef::try_get(cur.dentry) else {
            puts.mnt = Some(mnt);
            return Err(ECHILD);
        };
        let at = Path::new(mnt, d);
        let Some(c) = DentryRef::try_get(child) else {
            puts.path(at);
            return Err(ECHILD);
        };
        if child.d_seq_retry(seq) {
            puts.path(at);
            puts.dentry = Some(c);
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

    fn inode() -> Arc<Inode> {
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
            let p = legitimize_path(&m, &a, seq, m_seq, &mut puts);
            drop(g);
            if let Some(p) = p {
                assert!(puts.paths.iter().all(Option::is_none) && puts.mnt.is_none());
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
        assert!(legitimize_path(&m, &a, seq, m_seq, &mut puts).is_none());
        drop(g);
        drop(puts);
        assert_eq!(DentryRef::count(&a), n);
        let mut puts = Puts::default();
        let seq = a.d_seq_begin();
        let g = crate::sync::rcu::read_lock();
        let stale = m_seq.wrapping_sub(2);
        assert!(legitimize_path(&m, &a, seq, stale, &mut puts).is_none());
        drop(g);
        assert!(puts.paths.iter().all(Option::is_none) && puts.mnt.is_none());
        assert_eq!(DentryRef::count(&a), n);
    }
}

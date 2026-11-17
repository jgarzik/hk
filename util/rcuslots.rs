//! An array of RCU-readable owned references (Linux fdtable->fd: an
//! array of `struct file __rcu *` written with rcu_assign_pointer under
//! file_lock and read by __fget_files_rcu under rcu_read_lock)
//!
//! [`Slots`] is the array readers see: under an [`RcuReadGuard`] they
//! take a reference from a slot unless its target's last one went
//! ([`RcuRef::get_rcu`], Linux file_ref_get). [`SlotsOwner`] is its one
//! writer: slots change only through it, so whoever borrows it mutably
//! (the table's lock holder) is the only writer. A table that grows is
//! copied into a bigger array ([`SlotsOwner::grow`], Linux
//! copy_fdtable): the old one keeps its pointers as stale copies the new
//! one owns, so a reader still on it finds the same references, and it
//! is freed a grace period after the new one is published (Linux
//! free_fdtable_rcu).

use alloc::sync::Arc;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use crate::sync::rcu::{HasRcuHead, RcuHead, RcuReadGuard};
use crate::util::error::KernelResult;

/// A counted reference that a reader may take again from its target's
/// address under RCU (Linux a `struct file *`, its f_ref, and the
/// SLAB_TYPESAFE_BY_RCU file cache)
///
/// # Safety
/// - `into_raw` leaks one reference, which `from_raw` takes back.
/// - A target's memory stays allocated until a grace period after its
///   last reference went.
/// - `get_rcu` touches only interior-mutable bytes of the target, which
///   the last reference's release and drop never write through a
///   unique borrow.
pub unsafe trait RcuRef: Sized {
    type Target;

    /// Leak the reference, as its target's address
    fn into_raw(self) -> *const Self::Target;

    /// Take a leaked reference back
    ///
    /// # Safety
    /// `p` came from `into_raw`, and its reference is taken back once.
    unsafe fn from_raw(p: *const Self::Target) -> Self;

    /// A new reference to the target at `p`, unless its last one went
    /// (Linux file_ref_get)
    ///
    /// # Safety
    /// `p` came from `into_raw` and is still allocated.
    unsafe fn get_rcu(p: *const Self::Target) -> Option<Self>;
}

/// What a lookup in [`Slots`] found (Linux __fget_files_rcu's cases)
pub enum Lookup<R> {
    /// No reference there
    Empty,
    /// The slot changed or its target was going: look again
    Raced,
    /// A new reference to what the slot held
    Got(R),
}

/// The array readers see (Linux fdtable->fd and max_fds)
///
/// # Invariants
/// Until `retired` is set, each non-null slot holds one reference
/// (`RcuRef::into_raw`) the array owns, and slots are written only
/// through the array's one [`SlotsOwner`]; once set (by `grow`, which
/// moved them into the next array), slots are never written and own
/// nothing. A pointer a slot holds named a target with a reference at
/// some time after every reader that can reach the array began.
pub struct Slots<R: RcuRef> {
    s: alloc::boxed::Box<[AtomicPtr<R::Target>]>,
    retired: AtomicBool,
    rcu: RcuHead,
    /// Owns `R`s: Send and Sync as they are
    _r: PhantomData<R>,
}

// SAFETY: `rcu` is a field of the array, used only for its deferred
// free
unsafe impl<R: RcuRef> HasRcuHead for Slots<R> {
    fn rcu_head(&self) -> &RcuHead {
        &self.rcu
    }
}

impl<R: RcuRef> Slots<R> {
    /// Slots it has (Linux max_fds)
    pub fn len(&self) -> usize {
        self.s.len()
    }

    /// Whether it has none
    pub fn is_empty(&self) -> bool {
        self.s.is_empty()
    }

    /// A reference to what slot `i` holds (Linux __fget_files_rcu's
    /// load, file_ref_get and recheck of the slot): `Raced` when the
    /// target was going or the slot changed meanwhile
    pub fn get(&self, i: usize, _g: &RcuReadGuard) -> Lookup<R> {
        let Some(slot) = self.s.get(i) else {
            return Lookup::Empty;
        };
        let p = slot.load(Ordering::Acquire);
        if p.is_null() {
            return Lookup::Empty;
        }
        // SAFETY: `p` named a target with a reference after this reader
        // began (type invariant); its memory stays until a grace period
        // after its last reference went (RcuRef), which `_g` keeps from
        // ending
        let Some(r) = (unsafe { R::get_rcu(p) }) else {
            return Lookup::Raced;
        };
        if slot.load(Ordering::Acquire) != p {
            return Lookup::Raced;
        }
        Lookup::Got(r)
    }

    /// The address slot `i` holds, to compare or borrow only (Linux
    /// rcu_dereference_raw of an fd entry); null for none
    pub fn as_ptr(&self, i: usize) -> *const R::Target {
        self.s
            .get(i)
            .map_or(core::ptr::null(), |s| s.load(Ordering::Acquire))
    }
}

impl<R: RcuRef> Drop for Slots<R> {
    fn drop(&mut self) {
        if *self.retired.get_mut() {
            return;
        }
        for s in self.s.iter_mut() {
            let p = *s.get_mut();
            if !p.is_null() {
                // SAFETY: not retired: a reference the array owns (type
                // invariant), taken back once as the array goes
                drop(unsafe { R::from_raw(p) });
            }
        }
    }
}

/// The one writer of a [`Slots`] (Linux the file_lock holder's
/// rcu_assign_pointer on fdt->fd)
pub struct SlotsOwner<R: RcuRef>(Arc<Slots<R>>);

impl<R: RcuRef> SlotsOwner<R> {
    /// `n` empty slots; ENOMEM
    pub fn alloc(n: usize) -> KernelResult<Self> {
        let s = crate::util::kmem::try_vec_with(n, || AtomicPtr::new(core::ptr::null_mut()))?;
        // INVARIANT: no reference held, not retired; this is its owner
        let a = Slots {
            s: s.into_boxed_slice(),
            retired: AtomicBool::new(false),
            rcu: RcuHead::new(),
            _r: PhantomData,
        };
        Ok(Self(crate::util::kalloc::try_arc(a)?))
    }

    /// The array, for readers
    pub fn shared(&self) -> Arc<Slots<R>> {
        self.0.clone()
    }

    /// The array, borrowed
    pub fn slots(&self) -> &Slots<R> {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Slot `i` holds a reference
    pub fn is_some(&self, i: usize) -> bool {
        !self.0.as_ptr(i).is_null()
    }

    /// A reference to what slot `i` holds (Linux files_lookup_fd_locked
    /// and get_file)
    pub fn get(&self, i: usize) -> Option<R> {
        let p = self.0.as_ptr(i);
        if p.is_null() {
            return None;
        }
        // SAFETY: a reference the array owns (type invariant; it is not
        // retired while it has an owner), which no writer can drop while
        // `self` is borrowed: allocated, and the reference taken cannot
        // fail
        unsafe { R::get_rcu(p) }
    }

    /// Put `v` in slot `i` (below `len`), the reference there before
    /// handed back (Linux rcu_assign_pointer(fdt->fd[fd], file))
    pub fn replace(&mut self, i: usize, v: Option<R>) -> Option<R> {
        let new = v.map_or(core::ptr::null_mut(), |r| R::into_raw(r).cast_mut());
        // INVARIANT: the array owns `new`; the old one leaves below
        let old = self.0.s[i].swap(new, Ordering::AcqRel);
        // SAFETY: a reference the array owned (type invariant), which
        // the swap took out
        (!old.is_null()).then(|| unsafe { R::from_raw(old) })
    }

    /// Move every reference into `new`, empty and at least as long,
    /// which becomes the owned array (Linux copy_fdtable); the old one
    /// is handed back, its pointers left as stale copies for readers
    /// still on it, to be freed a grace period after `new` is published
    pub fn grow(&mut self, new: SlotsOwner<R>) -> Arc<Slots<R>> {
        assert!(new.len() >= self.len());
        for (d, s) in new.0.s.iter().zip(self.0.s.iter()) {
            let p = s.load(Ordering::Relaxed);
            debug_assert!(d.load(Ordering::Relaxed).is_null());
            // INVARIANT: the new array owns what the old one did
            d.store(p, Ordering::Relaxed);
        }
        // INVARIANT: the old array owns nothing from here on, and its
        // owner is gone: it is never written again
        self.0.retired.store(true, Ordering::Relaxed);
        core::mem::replace(&mut self.0, new.0)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A host test's reference: an `Arc` (no reader runs concurrently)
    pub struct TRef(pub Arc<u32>);

    // SAFETY: host tests have no RCU readers: a target is only reached
    // from a slot that holds a reference to it
    unsafe impl RcuRef for TRef {
        type Target = u32;
        fn into_raw(self) -> *const u32 {
            Arc::into_raw(self.0)
        }
        unsafe fn from_raw(p: *const u32) -> Self {
            // SAFETY: the caller's contract
            TRef(unsafe { Arc::from_raw(p) })
        }
        unsafe fn get_rcu(p: *const u32) -> Option<Self> {
            // SAFETY: a slot's reference keeps it (host tests)
            unsafe { Arc::increment_strong_count(p) };
            // SAFETY: the count just taken
            Some(TRef(unsafe { Arc::from_raw(p) }))
        }
    }

    impl Clone for TRef {
        fn clone(&self) -> Self {
            TRef(self.0.clone())
        }
    }

    #[test]
    fn grow_moves() {
        let f = Arc::new(5u32);
        let mut o = SlotsOwner::<TRef>::alloc(2).unwrap();
        assert!(o.replace(1, Some(TRef(f.clone()))).is_none());
        let old = o.grow(SlotsOwner::alloc(4).unwrap());
        assert_eq!(o.len(), 4);
        assert_eq!(old.as_ptr(1), Arc::as_ptr(&f));
        drop(old);
        assert_eq!(Arc::strong_count(&f), 2);
        assert!(o.get(1).is_some());
        assert!(o.replace(1, None).is_some());
        assert_eq!(Arc::strong_count(&f), 1);
        o.replace(3, Some(TRef(f.clone())));
        drop(o);
        assert_eq!(Arc::strong_count(&f), 1);
    }
}

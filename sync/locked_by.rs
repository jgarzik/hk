//! Data guarded by a lock it does not live in (Rust-for-Linux
//! `LockedBy`, kernel/sync/locked_by.rs).
//!
//! A field of a refcounted object (a task's tree links, a pid's task
//! lists) belongs to a global lock: the object is reachable without the
//! lock, its field only with it. `LockedBy<T, O>` hands out the field
//! only to whoever borrows the lock's data `O`: `&O` gives `&T`, `&mut O`
//! gives `&mut T`. RfL checks at run time that the borrowed owner is the
//! right one; here `O` is a [`UniqueOwner`] (one instance exists, inside
//! its lock), so the borrow alone proves the lock is held.

use core::cell::UnsafeCell;
use core::marker::PhantomData;

/// The data of a lock that `LockedBy` cells belong to
///
/// # Safety
/// At most one value of the type exists, and it is reachable only
/// through its lock's guards (a private constructor, called once for a
/// `static` lock).
pub unsafe trait UniqueOwner {}

/// A `T` reachable only through a borrow of the owner `O`
///
/// # Invariants
/// `data` is read only under a borrow of the one `O` and written only
/// under a mutable borrow of it (or through `&mut self`).
pub struct LockedBy<T, O: UniqueOwner> {
    data: UnsafeCell<T>,
    _owner: PhantomData<fn(&O)>,
}

// SAFETY: shared access hands `&T` to every thread borrowing `O` (T:
// Sync) and `&mut T` to the one thread borrowing it mutably (T: Send)
unsafe impl<T: Send + Sync, O: UniqueOwner> Sync for LockedBy<T, O> {}

impl<T, O: UniqueOwner> LockedBy<T, O> {
    pub const fn new(v: T) -> Self {
        Self {
            data: UnsafeCell::new(v),
            _owner: PhantomData,
        }
    }

    /// The data, under a shared borrow of the owner
    pub fn access<'a>(&'a self, _owner: &'a O) -> &'a T {
        // SAFETY: the one `O` is borrowed shared for 'a, so no `&mut T`
        // (which needs it borrowed mutably) is live meanwhile
        unsafe { &*self.data.get() }
    }

    /// The data, under a mutable borrow of the owner
    pub fn access_mut<'a>(&'a self, _owner: &'a mut O) -> &'a mut T {
        // SAFETY: the one `O` is borrowed mutably for 'a: no other
        // access to any cell it owns can start meanwhile
        unsafe { &mut *self.data.get() }
    }

    /// Two different cells at once, under a mutable borrow of the owner
    /// (panics if they are the same cell)
    pub fn access_pair_mut<'a>(
        &'a self,
        other: &'a Self,
        owner: &'a mut O,
    ) -> (&'a mut T, &'a mut T) {
        assert!(
            !core::ptr::eq(self, other),
            "LockedBy: one cell borrowed twice"
        );
        let _ = owner;
        // SAFETY: as in `access_mut`; the cells differ, so the two
        // references do not alias
        unsafe { (&mut *self.data.get(), &mut *other.data.get()) }
    }

    /// The data, writable, under a shared borrow of the owner
    ///
    /// # Safety
    /// The caller holds the owner exclusively (it derives `owner` from a
    /// mutable borrow), and no other reference to this cell's data is
    /// live for 'a. For iterators handing out each cell once.
    #[expect(clippy::mut_from_ref)]
    pub unsafe fn access_mut_unchecked<'a>(&'a self, _owner: &'a O) -> &'a mut T {
        // SAFETY: see above
        unsafe { &mut *self.data.get() }
    }

    /// The data, writable, through exclusive access to the cell (the
    /// object is not shared yet)
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }
}

/// A `T` that belongs to two locks (Linux data changed under both and
/// read under either: a mount's mnt_mounts, under namespace_sem and
/// mount_lock): `&A` or `&B` gives `&T`, `&mut A` and `&mut B` together
/// give `&mut T`
///
/// # Invariants
/// `data` is read only under a shared borrow of the one `A` or the one
/// `B`, and written only under mutable borrows of both (or through
/// `&mut self`).
pub struct LockedByEither<T, A: UniqueOwner, B: UniqueOwner> {
    data: UnsafeCell<T>,
    _owners: PhantomData<fn(&A, &B)>,
}

// SAFETY: as `LockedBy`: shared access hands `&T` to the threads
// borrowing `A` or `B` (T: Sync), `&mut T` to the one thread borrowing
// both mutably (T: Send)
unsafe impl<T: Send + Sync, A: UniqueOwner, B: UniqueOwner> Sync for LockedByEither<T, A, B> {}

impl<T, A: UniqueOwner, B: UniqueOwner> LockedByEither<T, A, B> {
    pub const fn new(v: T) -> Self {
        Self {
            data: UnsafeCell::new(v),
            _owners: PhantomData,
        }
    }

    /// The data, under a shared borrow of the first owner
    pub fn access_a<'a>(&'a self, _a: &'a A) -> &'a T {
        // SAFETY: the one `A` is borrowed shared for 'a, so no `&mut T`
        // (which needs it borrowed mutably) is live meanwhile
        unsafe { &*self.data.get() }
    }

    /// The data, under a shared borrow of the second owner
    pub fn access_b<'a>(&'a self, _b: &'a B) -> &'a T {
        // SAFETY: as in `access_a`, for the one `B`
        unsafe { &*self.data.get() }
    }

    /// The data, under mutable borrows of both owners
    pub fn access_mut<'a>(&'a self, _a: &'a mut A, _b: &'a mut B) -> &'a mut T {
        // SAFETY: both owners are borrowed mutably for 'a, so no shared
        // access (which borrows one of them) is live or can start
        unsafe { &mut *self.data.get() }
    }

    /// The data, writable, through exclusive access to the cell
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Owner;
    // SAFETY: the tests make one at a time per cell set
    unsafe impl UniqueOwner for Owner {}

    #[test]
    fn shared_and_mut_access() {
        let mut o = Owner;
        let c = LockedBy::<u32, Owner>::new(1);
        *c.access_mut(&mut o) += 1;
        assert_eq!(*c.access(&o), 2);
    }

    #[test]
    fn pair_of_cells() {
        let mut o = Owner;
        let (a, b) = (LockedBy::<u32, Owner>::new(1), LockedBy::new(2));
        let (x, y) = a.access_pair_mut(&b, &mut o);
        core::mem::swap(x, y);
        assert_eq!((*a.access(&o), *b.access(&o)), (2, 1));
    }

    #[test]
    #[should_panic(expected = "borrowed twice")]
    fn pair_of_one_cell_panics() {
        let mut o = Owner;
        let a = LockedBy::<u32, Owner>::new(1);
        let _ = a.access_pair_mut(&a, &mut o);
    }

    struct OwnerB;
    // SAFETY: as `Owner`
    unsafe impl UniqueOwner for OwnerB {}

    #[test]
    fn either_owner_reads_both_write() {
        let (mut a, mut b) = (Owner, OwnerB);
        let c = LockedByEither::<u32, Owner, OwnerB>::new(1);
        *c.access_mut(&mut a, &mut b) += 1;
        assert_eq!(*c.access_a(&a), 2);
        assert_eq!(*c.access_b(&b), 2);
    }
}

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

/// An object with a lock of its own that data elsewhere belongs to
/// (Linux sighand->siglock: a task's signal state and its group's
/// thread list are under the siglock of the table the task names), the
/// instance named at run time ([`InstanceGuard`], [`LockedByBoth`])
///
/// The lock may hold data of its own (`Data`: Linux sighand->action
/// beside siglock), which its guard hands out.
///
/// # Safety
/// `instance_lock` returns the same lock, owned by `self`, for its
/// whole life (implement it with [`instance_lock!`](crate::instance_lock)).
pub unsafe trait InstanceLock {
    type Data;
    fn instance_lock(&self) -> &crate::sync::spin::Mutex<Self::Data>;
}

/// Implement [`InstanceLock`] for a type through its field `$field`, a
/// `spin::Mutex<$data>`
#[macro_export]
macro_rules! instance_lock {
    ($t:ty, $field:ident, $data:ty) => {
        // SAFETY: a field of the object, fixed for its life
        unsafe impl $crate::sync::InstanceLock for $t {
            type Data = $data;
            fn instance_lock(&self) -> &$crate::sync::spin::Mutex<$data> {
                &self.$field
            }
        }
    };
}

/// `owner`'s [`InstanceLock`] held until dropped: the proof a
/// [`LockedByBoth`] cell owned by that instance checks
///
/// # Invariants
/// `_g` holds `owner.instance_lock()`.
#[must_use]
pub struct InstanceGuard<'a, B: InstanceLock> {
    owner: &'a B,
    _g: crate::sync::spin::MutexGuard<'a, B::Data>,
}

impl<'a, B: InstanceLock> InstanceGuard<'a, B> {
    /// Take `b`'s lock
    pub fn lock(b: &'a B) -> Self {
        // INVARIANT: the lock taken is `b`'s own
        Self {
            owner: b,
            _g: b.instance_lock().lock(),
        }
    }

    /// The instance whose lock is held
    pub fn owner(&self) -> &'a B {
        self.owner
    }
}

impl<B: InstanceLock> core::ops::Deref for InstanceGuard<'_, B> {
    type Target = B::Data;
    fn deref(&self) -> &B::Data {
        &self._g
    }
}

impl<B: InstanceLock> core::ops::DerefMut for InstanceGuard<'_, B> {
    fn deref_mut(&mut self) -> &mut B::Data {
        &mut self._g
    }
}

/// A `T` changed under two locks, a unique one (`A`) and one instance
/// of a lock of many (`B`, its owner named in the cell), and read under
/// either (Linux signal->thread_head: tasklist_lock and the group's
/// siglock): `&A` or a guard of the owner gives `&T`; `&mut A` and a
/// guard of the owner, borrowed mutably, give `&mut T`. The owner is
/// checked at run time (RfL `LockedBy`'s owner check).
///
/// # Invariants
/// `data` is read only under a shared borrow of the one `A` or while
/// the current thread holds the lock of the instance `owner` names (an
/// [`InstanceGuard`] of it borrowed), and written only under a mutable
/// borrow of `A` with such a guard borrowed mutably. `owner` is null
/// until set, and changes only under a mutable borrow of `A` with the
/// old owner's guard (if any) borrowed mutably.
pub struct LockedByBoth<T, A: UniqueOwner, B: InstanceLock> {
    owner: core::sync::atomic::AtomicPtr<B>,
    data: UnsafeCell<T>,
    _owners: PhantomData<fn(&A)>,
}

// SAFETY: shared access hands `&T` to the threads borrowing `A` or
// holding the owner's lock (T: Sync), `&mut T` to the one thread doing
// both mutably (T: Send); the owner is an address only compared
unsafe impl<T: Send + Sync, A: UniqueOwner, B: InstanceLock> Sync for LockedByBoth<T, A, B> {}
// SAFETY: as above; the owner pointer is never dereferenced
unsafe impl<T: Send, A: UniqueOwner, B: InstanceLock> Send for LockedByBoth<T, A, B> {}

impl<T, A: UniqueOwner, B: InstanceLock> LockedByBoth<T, A, B> {
    /// Owned by no instance yet
    pub const fn new(v: T) -> Self {
        // INVARIANT: no owner
        Self {
            owner: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
            data: UnsafeCell::new(v),
            _owners: PhantomData,
        }
    }

    /// `g` holds the owner's lock
    fn owned_by(&self, g: &InstanceGuard<'_, B>) -> bool {
        let o = self.owner.load(core::sync::atomic::Ordering::Acquire);
        core::ptr::eq(o, g.owner())
    }

    /// The data, under a shared borrow of `A`
    pub fn access_a<'a>(&'a self, _a: &'a A) -> &'a T {
        // SAFETY: the one `A` is borrowed shared for 'a, so no `&mut T`
        // (which needs it borrowed mutably) is live meanwhile (type
        // invariant)
        unsafe { &*self.data.get() }
    }

    /// The data, under the owner's lock (panics for another instance's
    /// guard)
    pub fn access_b<'a>(&'a self, g: &'a InstanceGuard<'_, B>) -> &'a T {
        assert!(self.owned_by(g), "LockedByBoth: not the owner's lock");
        // SAFETY: the owner's lock is held for 'a (`g`); a writer needs
        // it too, borrowed mutably, and it cannot change owner without
        // that (type invariant)
        unsafe { &*self.data.get() }
    }

    /// The data, under a mutable borrow of `A` and the owner's lock
    /// (panics for another instance's guard)
    pub fn access_mut<'a>(&'a self, _a: &'a mut A, g: &'a mut InstanceGuard<'_, B>) -> &'a mut T {
        assert!(self.owned_by(g), "LockedByBoth: not the owner's lock");
        // SAFETY: `A` is borrowed mutably (no `access_a`) and the
        // owner's lock is held with its guard borrowed mutably (no
        // `access_b` on this thread, none on another) for 'a
        unsafe { &mut *self.data.get() }
    }

    /// Hand the cell to instance `new`, under a mutable borrow of `A`
    /// and the current owner's guard (any guard while it has none);
    /// panics for another instance's guard
    pub fn set_owner(&self, _a: &mut A, g: &mut InstanceGuard<'_, B>, new: &B) {
        let o = self.owner.load(core::sync::atomic::Ordering::Acquire);
        assert!(
            o.is_null() || core::ptr::eq(o, g.owner()),
            "LockedByBoth: not the owner's lock"
        );
        // INVARIANT: changed with `A` and the old owner's guard borrowed
        // mutably, so no access under either is live
        self.owner.store(
            core::ptr::from_ref(new).cast_mut(),
            core::sync::atomic::Ordering::Release,
        );
    }
}

/// A `T` under one instance of a lock of many, its owner named in the
/// cell and checked at run time (RfL `LockedBy` with its owner check;
/// Linux task->blocked, ->pending, signal->shared_pending: no lock of
/// their own, under the siglock of the table the task names). Many
/// cells under one guard are borrowed at once, each once mutably or
/// many times shared (a `RefCell`'s rule, checked at run time: the
/// borrows are short, under a spin lock).
///
/// # Invariants
/// `data` is reached only through an [`InstanceRef`] or
/// [`InstanceRefMut`] made while the current thread holds the lock of
/// the instance `owner` names (an [`InstanceGuard`] of it borrowed, for
/// the borrow's life), `borrow` counting them: n > 0 shared, -1 one
/// mutable, 0 none (or through `&mut self`). `owner` is null until set
/// and changes only with the old owner's guard borrowed mutably (no
/// borrow of the cell live), with Release, so the next holder's Acquire
/// load sees the data as the old owner left it.
pub struct InstanceCell<T, B: InstanceLock> {
    owner: core::sync::atomic::AtomicPtr<B>,
    borrow: core::sync::atomic::AtomicIsize,
    data: UnsafeCell<T>,
}

// SAFETY: shared borrows hand `&T` to the threads holding the owner's
// lock (T: Sync), a mutable one `&mut T` to one thread at a time (T:
// Send), counted atomically; the owner is an address only compared
unsafe impl<T: Send + Sync, B: InstanceLock> Sync for InstanceCell<T, B> {}
// SAFETY: as above; the owner pointer is never dereferenced
unsafe impl<T: Send, B: InstanceLock> Send for InstanceCell<T, B> {}

impl<T, B: InstanceLock> InstanceCell<T, B> {
    /// Owned by no instance yet
    pub const fn new(v: T) -> Self {
        // INVARIANT: no owner, no borrow
        Self {
            owner: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
            borrow: core::sync::atomic::AtomicIsize::new(0),
            data: UnsafeCell::new(v),
        }
    }

    /// Panics unless `g` holds the owner's lock
    #[inline]
    fn check(&self, g: &InstanceGuard<'_, B>) {
        let o = self.owner.load(core::sync::atomic::Ordering::Acquire);
        assert!(
            core::ptr::eq(o, g.owner()),
            "InstanceCell: not the owner's lock"
        );
    }

    /// The data, shared, under the owner's lock (panics for another
    /// instance's guard or while borrowed mutably)
    #[inline]
    pub fn borrow<'a>(&'a self, g: &'a InstanceGuard<'_, B>) -> InstanceRef<'a, T> {
        use core::sync::atomic::Ordering;
        self.check(g);
        let n = self.borrow.fetch_add(1, Ordering::Acquire);
        assert!(n >= 0, "InstanceCell: borrowed mutably");
        // INVARIANT: counted as one more shared borrow, made under the
        // owner's lock (`g`, borrowed for 'a)
        InstanceRef {
            borrow: &self.borrow,
            // SAFETY: no mutable borrow is live (count was >= 0) or can
            // start while this one is counted
            data: unsafe { &*self.data.get() },
        }
    }

    /// The data, writable, under the owner's lock (panics for another
    /// instance's guard or while borrowed)
    #[inline]
    pub fn borrow_mut<'a>(&'a self, g: &'a InstanceGuard<'_, B>) -> InstanceRefMut<'a, T> {
        use core::sync::atomic::Ordering;
        self.check(g);
        let free = self
            .borrow
            .compare_exchange(0, -1, Ordering::Acquire, Ordering::Relaxed);
        assert!(free.is_ok(), "InstanceCell: already borrowed");
        // INVARIANT: counted as the one mutable borrow, made under the
        // owner's lock (`g`, borrowed for 'a)
        InstanceRefMut {
            borrow: &self.borrow,
            // SAFETY: no other borrow is live (count was 0) or can start
            // while this one is counted
            data: unsafe { &mut *self.data.get() },
        }
    }

    /// Hand the cell to instance `new`, under the current owner's guard
    /// (any guard while it has none); panics for another instance's
    /// guard
    pub fn set_owner(&self, g: &mut InstanceGuard<'_, B>, new: &B) {
        use core::sync::atomic::Ordering;
        let o = self.owner.load(Ordering::Acquire);
        assert!(
            o.is_null() || core::ptr::eq(o, g.owner()),
            "InstanceCell: not the owner's lock"
        );
        // INVARIANT: the old owner's guard is borrowed mutably, so no
        // borrow made under it is live, and no other thread holds that
        // lock
        debug_assert_eq!(self.borrow.load(Ordering::Relaxed), 0);
        self.owner
            .store(core::ptr::from_ref(new).cast_mut(), Ordering::Release);
    }

    /// The data, writable, through exclusive access to the cell (the
    /// object is not shared yet)
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }
}

/// A shared borrow of an [`InstanceCell`]
#[must_use]
pub struct InstanceRef<'a, T> {
    borrow: &'a core::sync::atomic::AtomicIsize,
    data: &'a T,
}

impl<T> core::ops::Deref for InstanceRef<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        self.data
    }
}

impl<T> Drop for InstanceRef<'_, T> {
    #[inline]
    fn drop(&mut self) {
        // INVARIANT: this shared borrow ends
        self.borrow
            .fetch_sub(1, core::sync::atomic::Ordering::Release);
    }
}

/// A mutable borrow of an [`InstanceCell`]
#[must_use]
pub struct InstanceRefMut<'a, T> {
    borrow: &'a core::sync::atomic::AtomicIsize,
    data: &'a mut T,
}

impl<T> core::ops::Deref for InstanceRefMut<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        self.data
    }
}

impl<T> core::ops::DerefMut for InstanceRefMut<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        self.data
    }
}

impl<T> Drop for InstanceRefMut<'_, T> {
    #[inline]
    fn drop(&mut self) {
        // INVARIANT: the mutable borrow ends
        self.borrow.store(0, core::sync::atomic::Ordering::Release);
    }
}

/// A `Copy` value owned by one of many instances of a lock (a timer's
/// expiry, owned by whichever per-CPU base it is on): the owner is not
/// unique, so the caller proves it holds the right one (RfL `LockedBy`
/// checks a stored owner; here the cell's owner is the lock its object
/// names, e.g. a timer's `base`, checked by the caller)
///
/// # Invariants
/// `data` is read only under a shared borrow of its lock's data and
/// written only under a mutable borrow of it; values are copied in and
/// out, so no reference into the cell outlives the borrow.
pub struct LockedCell<T>(UnsafeCell<T>);

// SAFETY: every access copies a value under its lock's data borrow
// (shared reads, one exclusive writer), so threads only exchange owned
// copies (T: Send)
unsafe impl<T: Copy + Send> Sync for LockedCell<T> {}

impl<T: Copy> LockedCell<T> {
    pub const fn new(v: T) -> Self {
        Self(UnsafeCell::new(v))
    }

    /// The value, under a shared borrow of its lock's data
    ///
    /// # Safety
    /// `owner` is the data of the lock this cell belongs to.
    pub unsafe fn get<O>(&self, owner: &O) -> T {
        let _ = owner;
        // SAFETY: the owner is borrowed shared, so no `set` (which
        // borrows it mutably) runs meanwhile; the read is a copy
        unsafe { *self.0.get() }
    }

    /// Replace the value, under a mutable borrow of its lock's data
    ///
    /// # Safety
    /// `owner` is the data of the lock this cell belongs to.
    pub unsafe fn set<O>(&self, owner: &mut O, v: T) {
        let _ = owner;
        // SAFETY: the owner is borrowed mutably, so no other access to
        // the cell runs meanwhile, and none holds a reference into it
        unsafe { *self.0.get() = v };
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

    struct Inst {
        lock: crate::sync::spin::Mutex<()>,
    }
    crate::instance_lock!(Inst, lock, ());

    fn inst() -> Inst {
        Inst {
            lock: crate::sync::spin::Mutex::new(()),
        }
    }

    #[test]
    fn both_owner_checked() {
        let mut a = Owner;
        let (x, y) = (inst(), inst());
        let c = LockedByBoth::<u32, Owner, Inst>::new(1);
        let mut gx = InstanceGuard::lock(&x);
        c.set_owner(&mut a, &mut gx, &x);
        *c.access_mut(&mut a, &mut gx) += 1;
        assert_eq!(*c.access_b(&gx), 2);
        assert_eq!(*c.access_a(&a), 2);
        c.set_owner(&mut a, &mut gx, &y);
        drop(gx);
        let gy = InstanceGuard::lock(&y);
        assert_eq!(*c.access_b(&gy), 2);
    }

    #[test]
    #[should_panic(expected = "not the owner's lock")]
    fn both_other_instance_panics() {
        let mut a = Owner;
        let (x, y) = (inst(), inst());
        let c = LockedByBoth::<u32, Owner, Inst>::new(1);
        let mut gx = InstanceGuard::lock(&x);
        c.set_owner(&mut a, &mut gx, &x);
        drop(gx);
        let gy = InstanceGuard::lock(&y);
        let _ = c.access_b(&gy);
    }

    #[test]
    fn instance_cell_follows_owner() {
        let (x, y) = (inst(), inst());
        let (a, b) = (
            InstanceCell::<u32, Inst>::new(1),
            InstanceCell::<u32, Inst>::new(2),
        );
        let mut gx = InstanceGuard::lock(&x);
        a.set_owner(&mut gx, &x);
        b.set_owner(&mut gx, &x);
        {
            let (mut ra, rb) = (a.borrow_mut(&gx), b.borrow(&gx));
            *ra += *rb;
        }
        assert_eq!(*a.borrow(&gx), 3);
        a.set_owner(&mut gx, &y);
        drop(gx);
        let gy = InstanceGuard::lock(&y);
        assert_eq!(*a.borrow(&gy), 3);
    }

    #[test]
    #[should_panic(expected = "not the owner's lock")]
    fn instance_cell_other_instance_panics() {
        let (x, y) = (inst(), inst());
        let a = InstanceCell::<u32, Inst>::new(1);
        let mut gx = InstanceGuard::lock(&x);
        a.set_owner(&mut gx, &x);
        drop(gx);
        let gy = InstanceGuard::lock(&y);
        let _ = a.borrow(&gy);
    }

    #[test]
    #[should_panic(expected = "already borrowed")]
    fn instance_cell_double_borrow_panics() {
        let x = inst();
        let a = InstanceCell::<u32, Inst>::new(1);
        let mut gx = InstanceGuard::lock(&x);
        a.set_owner(&mut gx, &x);
        let _r = a.borrow(&gx);
        let _w = a.borrow_mut(&gx);
    }

    #[test]
    fn cell_copies_under_owner() {
        let mut o = Owner;
        let c = LockedCell::new(1u64);
        // SAFETY: `o` is the one owner of the cell
        unsafe { c.set(&mut o, 5) };
        // SAFETY: as above
        assert_eq!(unsafe { c.get(&o) }, 5);
    }
}

//! The inode cache (Linux fs/inode.c: inode_hashtable, iget5_locked,
//! ilookup5, insert_inode_hash, remove_inode_hash, evict)
//!
//! Filesystems whose inodes stand for objects on a device (vfat by
//! directory-entry position) find the one in-memory inode of an object
//! here, so every lookup, open file and lock of it shares one `Inode`
//! (Linux iget5_locked). Pseudo filesystems and ramfs never hash their
//! inodes (their dentries hold them), like Linux new_inode without
//! insert_inode_hash; tmpfs hashes one by number and generation when a
//! file handle is first made of it, for open_by_handle_at's lookup
//! (Linux shmem_encode_fh, shmem_fh_to_dentry).
//!
//! An inode lives as long as someone holds a reference to it: a
//! dentry, an open file, a mapping. The hash holds none (an
//! `InodeList` per bucket, linked through the inode's own
//! `i_hash_node`: hashing allocates nothing). When the last reference
//! goes, its teardown (`inode::iput` -> `evict`) runs [`evict`]: it
//! unhashes the inode and calls the filesystem's `evict_inode`, which frees what an
//! unlinked object still owns (Linux iput_final -> evict ->
//! ->evict_inode). Deviation from Linux: no LRU of unused inodes (Linux
//! keeps an inode with i_count 0 cached until its superblock's shrinker
//! evicts it); here the dentry that references it is the cache, and the
//! dcache shrinker (`dentry::shrink_dcache`, no LRU order) frees both.
//!
//! An inode is built completely before it is hashed: [`iget5`] looks up,
//! builds outside the lock (which may do I/O) and inserts unless another
//! thread inserted the same object meanwhile (then the new one is
//! dropped, never seen). So there is no I_NEW state to wait on. A lookup
//! runs the filesystem's `test` on each candidate before taking a
//! reference (Linux find_inode). One whose last reference went (its
//! teardown writing it back or evicting it while still hashed: Linux
//! I_WILL_FREE, I_FREEING) cannot be grabbed: the lookup sleeps until
//! an eviction finishes and searches again (Linux
//! __wait_on_freeing_inode), so no second inode of the object is built
//! while the first may still write it or free its blocks.
//!
//! Locking: one `INODE_HASH_LOCK` (Linux inode_hash_lock), a spin leaf
//! apart from `test` (which may take `Inode.private` and the
//! filesystem's inode data lock), `Inode::igrab` (a candidate's
//! `i_lock`, Linux find_inode) and a hash or unhash (the inode's
//! `i_lock`, Linux __insert_inode_hash), thread context only: an inode's last
//! reference never goes in an interrupt handler (pinned pages and files
//! are released in thread context: `PinnedPages`, `fput`), and lockdep
//! reports a tracked spin lock taken in one. The table is sized from RAM
//! at first use.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use spin::Once;

use super::inode::{Inode, InodeList, InodeRef};
use super::superblock::SuperBlock;
use crate::sync::spin::Mutex;
use crate::sync::{LockedBy, UniqueOwner};
use crate::util::error::KernelError;

crate::adapter!(pub HashA, Inode, i_hash_node);

/// What `INODE_HASH_LOCK` guards: every bucket
pub struct InodeHash(());

// SAFETY: one instance, `INODE_HASH_LOCK`'s, made here (the field is
// private)
unsafe impl UniqueOwner for InodeHash {}

/// Linux inode_hash_lock
static INODE_HASH_LOCK: Mutex<InodeHash> = Mutex::new(InodeHash(()));

/// One bucket (Linux hlist_head): the hashed inodes, holding no
/// reference
type Bucket = LockedBy<InodeList<HashA>, InodeHash>;

static TABLE: Once<Box<[Bucket]>> = Once::new();

/// Buckets for this much RAM: one per MB, a power of two in [256, 65536]
/// (512MB: 512 buckets; 64GB and up: 65536)
fn table_size() -> usize {
    let mb = (crate::FRAME_ALLOCATOR.stats().total_bytes >> 20) as usize;
    mb.next_power_of_two().clamp(256, 65536)
}

fn table() -> &'static [Bucket] {
    TABLE.call_once(|| {
        (0..table_size())
            // SAFETY: an inode's eviction unhashes it under
            // INODE_HASH_LOCK (`evict`), as every other unhash does
            .map(|_| LockedBy::new(unsafe { InodeList::new() }))
            .collect()
    })
}

/// The bucket of (sb, hashval) (Linux hash())
fn bucket(sb: *const SuperBlock, hashval: u64) -> &'static Bucket {
    let t = table();
    let h = (hashval ^ (sb as usize as u64 >> 4)).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    &t[(h >> 32) as usize & (t.len() - 1)]
}

/// What a search found
enum Found {
    Live(InodeRef),
    /// Its inode, its last reference gone, is still hashed (Linux
    /// I_WILL_FREE / I_FREEING): its address, the key of its wait queue
    /// (never dereferenced once the lock is dropped)
    Dying(usize),
    None,
}

/// The inode of (sb, hashval) passing `test`, if hashed (Linux
/// find_inode): `test` runs before any reference is taken, which
/// `Inode::igrab` takes unless the last one went, so nothing
/// is dropped under the lock (the last reference's eviction takes it).
/// `b` is the bucket of (sb, hashval), found before the lock (the table
/// is allocated at first use).
fn find(
    l: &InodeHash,
    b: &Bucket,
    sb: *const SuperBlock,
    hashval: u64,
    test: &dyn Fn(&Inode) -> bool,
) -> Found {
    let mut dying = None;
    for i in b.access(l).iter() {
        if core::ptr::eq(i.sb_ptr(), sb) && i.i_hash.load(Ordering::Relaxed) == hashval && test(i) {
            match i.igrab() {
                Some(a) => return Found::Live(a),
                None => dying = Some(core::ptr::from_ref(i) as usize),
            }
        }
    }
    match dying {
        Some(a) => Found::Dying(a),
        None => Found::None,
    }
}

/// Sleep until the dying inode at `addr` is unhashed (Linux
/// __wait_on_freeing_inode): queued on its address's hashed queue under
/// `INODE_HASH_LOCK` (`l`, dropped here), so the eviction's wakeup after
/// its unhash under that lock is never missed; one sleep, then the
/// caller searches again (a shared queue's other wakeups included)
fn wait_freed(l: crate::sync::spin::MutexGuard<'_, InodeHash>, addr: usize) {
    use crate::sync::waitqueue::{WaitEntry, var_waitqueue};
    let q = var_waitqueue(addr);
    let w = core::pin::pin!(WaitEntry::new());
    q.prepare_to_wait(w.as_ref(), crate::task::percpu::SleepState::Uninterruptible);
    drop(l);
    crate::task::percpu::schedule();
    q.finish_wait(w.as_ref());
}

/// The cached inode of (sb, hashval) for which `test` holds (Linux
/// ilookup5): one being freed is waited for, then searched again.
/// `test` runs under a spinlock and must not sleep; this may sleep.
pub fn ilookup5(
    sb: &Arc<SuperBlock>,
    hashval: u64,
    test: &dyn Fn(&Inode) -> bool,
) -> Option<InodeRef> {
    let b = bucket(Arc::as_ptr(sb), hashval);
    loop {
        crate::sync::might_sleep();
        let l = INODE_HASH_LOCK.lock();
        match find(&l, b, Arc::as_ptr(sb), hashval, test) {
            Found::Live(i) => return Some(i),
            Found::None => return None,
            Found::Dying(addr) => wait_freed(l, addr),
        }
    }
}

/// The inode of (sb, hashval) for which `test` holds, building and
/// hashing it with `make` if none is cached (Linux iget5_locked plus
/// the filesystem's fill and unlock_new_inode). `make` runs with no lock
/// held and may sleep; if another thread hashed the object first, its
/// inode is returned and the new one dropped.
pub fn iget5(
    sb: &Arc<SuperBlock>,
    hashval: u64,
    test: &dyn Fn(&Inode) -> bool,
    make: impl FnOnce() -> Result<InodeRef, KernelError>,
) -> Result<InodeRef, KernelError> {
    if let Some(i) = ilookup5(sb, hashval, test) {
        return Ok(i);
    }
    let new = make()?;
    let b = bucket(Arc::as_ptr(sb), hashval);
    loop {
        crate::sync::might_sleep();
        let mut l = INODE_HASH_LOCK.lock();
        match find(&l, b, Arc::as_ptr(sb), hashval, test) {
            Found::Live(i) => {
                drop(l);
                // `new` is dropped unhashed, after the unlock
                return Ok(i);
            }
            Found::Dying(addr) => wait_freed(l, addr),
            Found::None => {
                hash_locked(&mut l, b, &new, hashval);
                drop(l);
                return Ok(new);
            }
        }
    }
}

/// Hash `i` under `hashval` on its bucket `b`, under its `i_lock` too
/// (Linux __insert_inode_hash: hlist_add_head under inode_hash_lock and
/// i_lock), so a test of its hashed state under `i_lock`
/// (`__mark_inode_dirty`) sees it whole
fn hash_locked(l: &mut InodeHash, b: &Bucket, i: &InodeRef, hashval: u64) {
    let _il = i.i_lock.lock();
    i.i_hash.store(hashval, Ordering::Relaxed);
    b.access_mut(l).push_front(i);
}

/// Unhash the hashed `inode` (Linux __remove_inode_hash: under
/// inode_hash_lock and its i_lock)
fn unhash_locked(l: &mut InodeHash, inode: &Inode) {
    let _il = inode.i_lock.lock();
    let b = bucket(inode.sb_ptr(), inode.i_hash.load(Ordering::Relaxed));
    // SAFETY: linked (the caller's check under this lock), so on the
    // bucket of its superblock and hash value (both unchanged while
    // hashed: `i_hash` is set before it is linked, under this lock)
    unsafe { b.access_mut(l).remove(inode) };
}

/// Hash a new inode under `hashval` (Linux insert_inode_hash): for an
/// object a create just made, which no lookup can have found yet
pub fn insert_inode_hash(inode: &InodeRef, hashval: u64) {
    if inode.superblock().is_none() {
        return;
    }
    let b = bucket(inode.sb_ptr(), hashval);
    hash_locked(&mut INODE_HASH_LOCK.lock(), b, inode, hashval);
}

/// Hash `inode` under `hashval` unless it is hashed (Linux
/// shmem_encode_fh: inode_unhashed, then __insert_inode_hash under a
/// lock of its own, here this lock): for a filesystem that hashes its
/// inodes only once some lookup may need them
pub fn insert_inode_hash_once(inode: &InodeRef, hashval: u64) {
    if inode.superblock().is_none() || inode.i_hash_node.is_linked() {
        return;
    }
    let b = bucket(inode.sb_ptr(), hashval);
    let mut l = INODE_HASH_LOCK.lock();
    if !inode.i_hash_node.is_linked() {
        hash_locked(&mut l, b, inode, hashval);
    }
}

/// Unhash `inode` (Linux remove_inode_hash): later lookups of its
/// object build a new inode (an unlinked or moved entry)
pub fn remove_inode_hash(inode: &Inode) {
    let _ = unhash(inode);
}

/// [`remove_inode_hash`]; true if it was hashed
fn unhash(inode: &Inode) -> bool {
    // Hashing and unhashing are the inode's owner's (create, rename,
    // unlink, eviction), never concurrent with this: unlocked, the link
    // reads its own last state
    if !inode.i_hash_node.is_linked() {
        return false;
    }
    let mut l = INODE_HASH_LOCK.lock();
    if !inode.i_hash_node.is_linked() {
        return false;
    }
    unhash_locked(&mut l, inode);
    true
}

/// Move `inode` to `hashval` (Linux fat_detach + fat_attach on rename,
/// which move it in fat's own position hash), in one hold of the lock
/// and its `i_lock` each, so it never looks unhashed meanwhile (Linux
/// leaves its VFS hash alone)
pub fn rehash(inode: &InodeRef, hashval: u64) {
    if inode.superblock().is_none() {
        return;
    }
    let mut l = INODE_HASH_LOCK.lock();
    if inode.i_hash_node.is_linked() {
        unhash_locked(&mut l, inode);
    }
    let b = bucket(inode.sb_ptr(), hashval);
    hash_locked(&mut l, b, inode, hashval);
}

/// The last reference to `inode` is gone (Linux iput_final -> evict):
/// its filesystem releases what it still owns while it is still hashed
/// (lookups of its object wait), then it is unhashed and the waiters
/// woken (Linux evict: ->evict_inode, remove_inode_hash, wake_up_bit).
/// Runs from the inode's teardown (`iput`) in a context that may sleep (Linux iput:
/// might_sleep): the filesystem may do I/O (vfat frees an unlinked
/// file's clusters).
pub fn evict(inode: &Inode) {
    inode.i_op.evict_inode(inode);
    if unhash(inode) {
        // Its waiters queued under the hash lock this unhash took (Linux
        // evict: wake_up_bit(__I_NEW) on the inode's hashed queue)
        crate::sync::waitqueue::var_waitqueue(core::ptr::from_ref(inode) as usize).wake_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::inode::{InodeMode, InodeOps, Timespec, istate};
    use crate::fs::superblock::{
        FileSystemType, FsContext, FsNext, FsSupers, NULL_SUPER_OPS, SbLocked, get_tree_nodev,
        kill_anon_super, vfs_get_tree,
    };
    use core::sync::atomic::AtomicUsize;

    /// Evictions `DyingOps` checked
    static SEEN: AtomicUsize = AtomicUsize::new(0);

    /// Looks itself up in the cache from its own eviction: the last
    /// reference went and it is still hashed (Linux evict before
    /// remove_inode_hash), so a lookup must find it dying, to wait for,
    /// and never take a new reference to it
    struct DyingOps;

    impl InodeOps for DyingOps {
        fn lookup(&self, _dir: &Inode, _name: &[u8]) -> Result<InodeRef, KernelError> {
            Err(KernelError::NotFound)
        }

        fn evict_inode(&self, inode: &Inode) {
            assert!(inode.state() & istate::I_FREEING != 0);
            let sb = inode.sb_ptr();
            let h = inode.i_hash.load(Ordering::Relaxed);
            let l = INODE_HASH_LOCK.lock();
            let me = core::ptr::from_ref(inode) as usize;
            let found = find(&l, bucket(sb, h), sb, h, &|i| core::ptr::eq(i, inode));
            assert!(matches!(found, Found::Dying(a) if a == me));
            SEEN.fetch_add(1, Ordering::Relaxed);
        }
    }

    static DYING_OPS: DyingOps = DyingOps;

    fn mount(fc: &FsContext<'_>) -> Result<SbLocked, KernelError> {
        get_tree_nodev(fc, &NULL_SUPER_OPS, |_| Ok(()))
    }

    static T: FileSystemType = FileSystemType {
        name: "icachetest",
        fs_flags: 0,
        mount,
        kill_sb: kill_anon_super,
        file_ops: &crate::fs::RAMFS_FILE_OPS,
        next: FsNext::new(None),
        fs_supers: FsSupers::new(crate::util::list::WeakList::new()),
    };

    /// A hashed inode is found with a new reference while held; once
    /// its last reference went, a lookup during its eviction finds it
    /// dying (Linux find_inode: I_FREEING, __wait_on_freeing_inode),
    /// and after its eviction finds nothing
    #[test]
    fn lookup_during_final_iput_waits() {
        let sb = vfs_get_tree(&FsContext::new(&T, b"")).unwrap().unlock();
        let i = Inode::alloc(Inode::new(
            7,
            InodeMode::regular(0o644),
            0,
            0,
            0,
            Timespec::ZERO,
            Some(&sb),
            &DYING_OPS,
        ))
        .unwrap();
        insert_inode_hash(&i, 7);
        let same = |x: &Inode| x.ino == 7;
        let got = ilookup5(&sb, 7, &same).unwrap();
        assert!(InodeRef::ptr_eq(&got, &i) && InodeRef::count(&i) == 2);
        drop(got);
        drop(i);
        assert_eq!(SEEN.load(Ordering::Relaxed), 1);
        assert!(ilookup5(&sb, 7, &same).is_none());
    }
}

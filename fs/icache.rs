//! The inode cache (Linux fs/inode.c: inode_hashtable, iget5_locked,
//! ilookup5, insert_inode_hash, remove_inode_hash, evict)
//!
//! Filesystems whose inodes stand for objects on a device (vfat by
//! directory-entry position) find the one in-memory inode of an object
//! here, so every lookup, open file and lock of it shares one `Inode`
//! (Linux iget5_locked). Pseudo filesystems and ramfs never hash their
//! inodes (their dentries hold them), like Linux new_inode without
//! insert_inode_hash.
//!
//! An inode lives as long as someone holds an `Arc` to it: a dentry, an
//! open file, a mapping, the writeback lists while it is dirty. The hash
//! holds a `Weak` only (a `WeakList` per bucket, linked through the
//! inode's own `i_hash_node`: hashing allocates nothing). When the last
//! `Arc` goes, `Drop for Inode` runs [`evict`]: it unhashes the inode
//! and calls the filesystem's `evict_inode`, which frees what an
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
//! reference (Linux find_inode); one racing the drop of the last
//! reference (still hashed, its eviction waiting for the lock: Linux
//! I_FREEING) cannot be upgraded and is treated as absent.
//!
//! Locking: one `INODE_HASH_LOCK` (Linux inode_hash_lock), a spin leaf
//! apart from `test` (which may take `Inode.private` and the
//! filesystem's inode data lock), thread context only: an inode's last
//! reference never goes in an interrupt handler (pinned pages and files
//! are released in thread context: `PinnedPages`, `fput`), and lockdep
//! reports a tracked spin lock taken in one. The table is sized from RAM
//! at first use.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use spin::Once;

use super::inode::Inode;
use super::superblock::SuperBlock;
use crate::sync::spin::Mutex;
use crate::sync::{LockedBy, UniqueOwner};
use crate::util::error::KernelError;
use crate::util::list::WeakList;

crate::adapter!(pub HashA, Inode, i_hash_node);

/// What `INODE_HASH_LOCK` guards: every bucket
pub struct InodeHash(());

// SAFETY: one instance, `INODE_HASH_LOCK`'s, made here (the field is
// private)
unsafe impl UniqueOwner for InodeHash {}

/// Linux inode_hash_lock
static INODE_HASH_LOCK: Mutex<InodeHash> = Mutex::new(InodeHash(()));

/// One bucket (Linux hlist_head): the hashed inodes, by `Weak`
type Bucket = LockedBy<WeakList<HashA>, InodeHash>;

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
            .map(|_| LockedBy::new(WeakList::new()))
            .collect()
    })
}

/// The bucket of (sb, hashval) (Linux hash())
fn bucket(sb: *const SuperBlock, hashval: u64) -> &'static Bucket {
    let t = table();
    let h = (hashval ^ (sb as usize as u64 >> 4)).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    &t[(h >> 32) as usize & (t.len() - 1)]
}

/// The live inode of (sb, hashval) passing `test`, if hashed (Linux
/// find_inode): `test` runs before any reference is taken, so nothing
/// is dropped under the lock (the last reference's eviction takes it).
/// `b` is the bucket of (sb, hashval), found before the lock (the table
/// is allocated at first use).
fn find(
    l: &InodeHash,
    b: &Bucket,
    sb: *const SuperBlock,
    hashval: u64,
    test: &dyn Fn(&Inode) -> bool,
) -> Option<Arc<Inode>> {
    b.access(l)
        .iter()
        .filter(|e| {
            let i = e.get();
            core::ptr::eq(i.sb.as_ptr(), sb)
                && i.i_hash.load(Ordering::Relaxed) == hashval
                && test(i)
        })
        .find_map(|e| e.upgrade())
}

/// The cached inode of (sb, hashval) for which `test` holds (Linux
/// ilookup5); `test` runs under a spinlock and must not sleep
pub fn ilookup5(
    sb: &Arc<SuperBlock>,
    hashval: u64,
    test: &dyn Fn(&Inode) -> bool,
) -> Option<Arc<Inode>> {
    let b = bucket(Arc::as_ptr(sb), hashval);
    let l = INODE_HASH_LOCK.lock();
    find(&l, b, Arc::as_ptr(sb), hashval, test)
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
    make: impl FnOnce() -> Result<Arc<Inode>, KernelError>,
) -> Result<Arc<Inode>, KernelError> {
    if let Some(i) = ilookup5(sb, hashval, test) {
        return Ok(i);
    }
    let new = make()?;
    let b = bucket(Arc::as_ptr(sb), hashval);
    let mut l = INODE_HASH_LOCK.lock();
    if let Some(i) = find(&l, b, Arc::as_ptr(sb), hashval, test) {
        drop(l);
        // `new` is dropped unhashed, after the unlock
        return Ok(i);
    }
    hash_locked(&mut l, b, &new, hashval);
    drop(l);
    Ok(new)
}

/// Hash `i` under `hashval` on its bucket `b` (Linux
/// __insert_inode_hash: hlist_add_head)
fn hash_locked(l: &mut InodeHash, b: &Bucket, i: &Arc<Inode>, hashval: u64) {
    i.i_hash.store(hashval, Ordering::Relaxed);
    b.access_mut(l).push_front(i);
}

/// Hash a new inode under `hashval` (Linux insert_inode_hash): for an
/// object a create just made, which no lookup can have found yet
pub fn insert_inode_hash(inode: &Arc<Inode>, hashval: u64) {
    if inode.superblock().is_none() {
        return;
    }
    let b = bucket(inode.sb.as_ptr(), hashval);
    hash_locked(&mut INODE_HASH_LOCK.lock(), b, inode, hashval);
}

/// Unhash `inode` (Linux remove_inode_hash): later lookups of its
/// object build a new inode (an unlinked or moved entry)
pub fn remove_inode_hash(inode: &Inode) {
    // Hashing and unhashing are the inode's owner's (create, rename,
    // unlink, eviction), never concurrent with this: unlocked, the link
    // reads its own last state
    if !inode.i_hash_node.is_linked() {
        return;
    }
    let weak = {
        let mut l = INODE_HASH_LOCK.lock();
        if !inode.i_hash_node.is_linked() {
            return;
        }
        let b = bucket(inode.sb.as_ptr(), inode.i_hash.load(Ordering::Relaxed));
        // SAFETY: linked, so on the bucket of its superblock and hash
        // value (both unchanged while hashed: `i_hash` is set before it
        // is linked, under this lock)
        unsafe { b.access_mut(&mut l).remove(inode) }
    };
    // Only the hash's weak reference goes: never the inode's Drop
    drop(weak);
}

/// Move `inode` to `hashval` (Linux fat_detach + fat_attach on rename)
pub fn rehash(inode: &Arc<Inode>, hashval: u64) {
    remove_inode_hash(inode);
    insert_inode_hash(inode, hashval);
}

/// The last reference to `inode` is gone (Linux iput_final -> evict):
/// unhash it and let its filesystem release what it still owns. Runs
/// from `Drop for Inode`, in whatever (thread) context the last
/// reference went: it must not sleep (filesystems defer I/O to a
/// workqueue)
pub fn evict(inode: &Inode) {
    remove_inode_hash(inode);
    inode.i_op.evict_inode(inode);
}

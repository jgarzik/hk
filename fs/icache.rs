//! The inode cache (Linux fs/inode.c: inode_hashtable, iget5_locked,
//! ilookup5, insert_inode_hash, remove_inode_hash, evict)
//!
//! Filesystems whose inodes stand for objects on a device (vfat by
//! directory-entry position, block devices by device number) find the
//! one in-memory inode of an object here, so every lookup, open file and
//! lock of it shares one `Inode` (Linux iget5_locked). Pseudo
//! filesystems and ramfs never hash their inodes (their dentries hold
//! them), like Linux new_inode without insert_inode_hash.
//!
//! An inode lives as long as someone holds an `Arc` to it: a dentry, an
//! open file, a mapping, the writeback list while it is dirty. The hash
//! holds a `Weak` only. When the last `Arc` goes, `Drop for Inode` runs
//! [`evict`]: it unhashes the inode and calls the filesystem's
//! `evict_inode`, which frees what an unlinked object still owns (Linux
//! iput_final -> evict -> ->evict_inode). Deviation from Linux: no LRU
//! of unused inodes (Linux keeps an inode with i_count 0 cached until
//! its superblock's shrinker evicts it); here the dentry that references
//! it is the cache, and the dcache shrinker (`dentry::shrink_dcache`,
//! no LRU order) frees both.
//!
//! An inode is built completely before it is hashed: [`iget5`] looks up,
//! builds outside the lock (which may do I/O) and inserts unless another
//! thread inserted the same object meanwhile (then the new one is
//! dropped, never seen). So there is no I_NEW state to wait on. A lookup
//! racing the drop of the last reference sees an entry it cannot upgrade
//! and treats it as absent.
//!
//! Locking: one IrqSpinlock per bucket, a leaf (under it only the
//! bucket's vector and `Weak` reference counts); IRQ-safe because an
//! inode's last reference could in principle go anywhere. The table is
//! sized from RAM at first use.

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use spin::Once;

use super::inode::Inode;
use super::superblock::SuperBlock;
use crate::arch::IrqSpinlock;
use crate::util::error::KernelError;

/// One bucket: (superblock address, hash value, inode)
type Bucket = IrqSpinlock<Vec<(usize, u64, Weak<Inode>)>>;

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
            .map(|_| IrqSpinlock::new(Vec::new()))
            .collect()
    })
}

/// The bucket of (sb, hashval) (Linux hash())
fn bucket(sb: usize, hashval: u64) -> &'static Bucket {
    let t = table();
    let h = (hashval ^ (sb as u64 >> 4)).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    &t[(h >> 32) as usize & (t.len() - 1)]
}

fn sb_key(sb: &Arc<SuperBlock>) -> usize {
    Arc::as_ptr(sb) as usize
}

/// The live inode of (sb, hashval) passing `test`, if cached. Every
/// inode upgraded under the lock is kept in `held` until the caller has
/// unlocked: dropping one there could be its last reference, whose
/// eviction takes this bucket's lock.
fn find_locked(
    list: &mut Vec<(usize, u64, Weak<Inode>)>,
    sb: usize,
    hashval: u64,
    test: &dyn Fn(&Inode) -> bool,
    held: &mut Vec<Arc<Inode>>,
) -> Option<Arc<Inode>> {
    // Entries whose inode is gone are left by a drop that raced a
    // rehash; drop them here (only the Weak goes: no inode is freed)
    list.retain(|(_, _, w)| w.strong_count() > 0);
    for (_, _, w) in list.iter().filter(|(s, h, _)| *s == sb && *h == hashval) {
        if let Some(i) = w.upgrade() {
            let hit = test(&i);
            held.push(i.clone());
            if hit {
                return Some(i);
            }
        }
    }
    None
}

fn find(b: &Bucket, sb: usize, hashval: u64, test: &dyn Fn(&Inode) -> bool) -> Option<Arc<Inode>> {
    let mut held = Vec::new();
    let mut list = b.lock();
    let r = find_locked(&mut list, sb, hashval, test, &mut held);
    drop(list);
    r
}

/// The cached inode of (sb, hashval) for which `test` holds (Linux
/// ilookup5); `test` runs under a spinlock and must not sleep
pub fn ilookup5(
    sb: &Arc<SuperBlock>,
    hashval: u64,
    test: &dyn Fn(&Inode) -> bool,
) -> Option<Arc<Inode>> {
    find(bucket(sb_key(sb), hashval), sb_key(sb), hashval, test)
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
    let (key, b) = (sb_key(sb), bucket(sb_key(sb), hashval));
    if let Some(i) = find(b, key, hashval, test) {
        return Ok(i);
    }
    let new = make()?;
    let mut held = Vec::new();
    let mut list = b.lock();
    if let Some(i) = find_locked(&mut list, key, hashval, test, &mut held) {
        drop(list);
        // `new` is dropped unhashed: its eviction takes no lock
        return Ok(i);
    }
    hash_locked(&mut list, key, hashval, &new);
    drop(list);
    Ok(new)
}

fn hash_locked(list: &mut Vec<(usize, u64, Weak<Inode>)>, sb: usize, hashval: u64, i: &Arc<Inode>) {
    i.i_hash.store(hashval, Ordering::Relaxed);
    i.i_hashed.store(true, Ordering::Release);
    list.push((sb, hashval, Arc::downgrade(i)));
}

/// Hash a new inode under `hashval` (Linux insert_inode_hash): for an
/// object a create just made, which no lookup can have found yet
pub fn insert_inode_hash(inode: &Arc<Inode>, hashval: u64) {
    let Some(sb) = inode.superblock() else {
        return;
    };
    let key = sb_key(&sb);
    hash_locked(&mut bucket(key, hashval).lock(), key, hashval, inode);
}

/// Unhash `inode` (Linux remove_inode_hash): later lookups of its
/// object build a new inode (an unlinked or moved entry)
pub fn remove_inode_hash(inode: &Inode) {
    if !inode.i_hashed.swap(false, Ordering::AcqRel) {
        return;
    }
    let me = core::ptr::from_ref::<Inode>(inode);
    let hashval = inode.i_hash.load(Ordering::Relaxed);
    let sb = inode.sb.as_ptr() as usize;
    bucket(sb, hashval)
        .lock()
        .retain(|(s, h, w)| !(*s == sb && *h == hashval && Weak::as_ptr(w) == me));
}

/// Move `inode` to `hashval` (Linux fat_detach + fat_attach on rename)
pub fn rehash(inode: &Arc<Inode>, hashval: u64) {
    remove_inode_hash(inode);
    insert_inode_hash(inode, hashval);
}

/// The last reference to `inode` is gone (Linux iput_final -> evict):
/// unhash it and let its filesystem release what it still owns. Runs
/// from `Drop for Inode`, in whatever context the last reference went:
/// it must not sleep (filesystems defer I/O to a workqueue)
pub fn evict(inode: &Inode) {
    remove_inode_hash(inode);
    inode.i_op.evict_inode(inode);
}

/// `f` on every hashed inode still alive until it returns false
/// (drop_caches, reclaim), allocating nothing: each inode's reference
/// is taken under its bucket's lock, `f` runs (and the reference goes)
/// with no lock held; a bucket is walked by position, so an inode
/// hashed or unhashed meanwhile may be seen twice or missed
pub fn for_each_inode(f: &mut dyn FnMut(&Arc<Inode>) -> bool) {
    for b in table() {
        let mut i = 0;
        loop {
            let inode = {
                let list = b.lock();
                list.iter().skip(i).find_map(|(_, _, w)| w.upgrade())
            };
            let Some(inode) = inode else {
                break;
            };
            if !f(&inode) {
                return;
            }
            i += 1;
        }
    }
}

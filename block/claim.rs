//! Exclusive claims of block devices (Linux block/bdev.c:
//! bd_may_claim, bd_prepare_to_claim, bd_finish_claiming,
//! bd_abort_claiming, bd_end_claim, under bdev_lock)
//!
//! A holder (a mounted superblock, a file opened O_EXCL, a swap area,
//! BLKBSZSET's temporary open, a partition scan) claims a device for
//! exclusive use; another holder's claim is EBUSY until the claim ends.
//! A claimed partition marks its whole disk as partly claimed, which
//! refuses a claim of the whole disk; a claimed whole disk refuses
//! claims of its partitions. The same holder may claim again (nested).
//!
//! Locking (doc/LOCKING.md, Block Device Subsystem): `BDEV_LOCK`
//! (sleeping, Linux bdev_lock) guards every disk's claims; a claim is
//! prepared under it alone, before the disk's `open_mutex` (waiting
//! there for another claim in progress, on its whole disk's
//! `bd_claiming`), and finished or ended under `open_mutex`:
//! open_mutex -> BDEV_LOCK.

use alloc::boxed::Box;

use super::blkdev::BlockDevice;
use crate::sync::waitqueue::{WaitEntry, var_waitqueue};
use crate::sync::{LockedBy, UniqueOwner};
use crate::util::error::KernelError;

/// A claim's owner (Linux void *holder): an address unique while the
/// claim lasts (a superblock, an open file's state, a swap slot, a
/// stack frame)
pub type Holder = usize;

/// Who holds a device (Linux bd_holder)
#[derive(Clone, Copy, PartialEq, Eq)]
enum BdHolder {
    Free,
    /// The whole disk's mark while only partitions are claimed (Linux
    /// whole->bd_holder = bd_may_claim)
    Parts,
    By(Holder),
}

/// One device's claim (Linux bd_holder, bd_holders)
#[derive(Clone, Copy)]
struct BdClaim {
    holder: BdHolder,
    holders: u32,
}

/// A disk's claims: its devices' by partition number, the whole disk
/// at 0 (Linux part0's fields), and the claim in progress (Linux
/// whole->bd_claiming)
pub struct Claims {
    claiming: Option<Holder>,
    parts: Box<[BdClaim]>,
}

impl Claims {
    /// For a disk of `minors` devices; ENOMEM
    pub(super) fn new(minors: usize) -> Result<Self, KernelError> {
        let free = BdClaim {
            holder: BdHolder::Free,
            holders: 0,
        };
        let parts = crate::util::kmem::try_vec(minors.max(1), free)?;
        Ok(Self {
            claiming: None,
            parts: parts.into_boxed_slice(),
        })
    }
}

/// What `BDEV_LOCK` owns: every disk's `Claims`
pub struct BdevLock(());

// SAFETY: one value, built here for BDEV_LOCK alone (private field)
// and reachable only through its guards
unsafe impl UniqueOwner for BdevLock {}

/// Every claim (Linux bdev_lock): a sleeping leaf under `open_mutex`
static BDEV_LOCK: crate::sync::Mutex<BdevLock> = crate::sync::Mutex::new(BdevLock(()));

/// A disk's claims, under `BDEV_LOCK`
pub type DiskClaims = LockedBy<Claims, BdevLock>;

fn claims_of(bdev: &BlockDevice) -> &DiskClaims {
    &bdev.disk.claims
}

/// Whether `holder` may claim device `partno` (Linux bd_may_claim)
fn may_claim(c: &Claims, partno: usize, holder: Holder) -> bool {
    match c.parts[partno].holder {
        // The same holder can always re-claim
        BdHolder::By(h) => h == holder,
        // A whole disk with a partition claimed
        BdHolder::Parts => false,
        // A partition of a whole disk claimed by someone
        BdHolder::Free => {
            partno == 0 || matches!(c.parts[0].holder, BdHolder::Free | BdHolder::Parts)
        }
    }
}

/// Start claiming `bdev` for `holder` (Linux bd_prepare_to_claim):
/// EBUSY if another holder has it; waits for a claim in progress on its
/// disk. On success the caller owns the disk's claiming and finishes
/// (`finish`) or abandons (`abort`) it.
pub fn prepare(bdev: &BlockDevice, holder: Holder) -> Result<(), KernelError> {
    let dc = claims_of(bdev);
    let partno = usize::from(bdev.partno);
    loop {
        let mut g = BDEV_LOCK.lock();
        let c = dc.access_mut(&mut g);
        if !may_claim(c, partno, holder) {
            return Err(KernelError::Busy);
        }
        if c.claiming.is_none() {
            c.claiming = Some(holder);
            return Ok(());
        }
        // A claim in progress: wait for it to finish, then retry
        let q = var_waitqueue(core::ptr::from_ref(dc) as usize);
        let w = core::pin::pin!(WaitEntry::new());
        q.prepare_to_wait(w.as_ref(), crate::task::percpu::SleepState::Uninterruptible);
        drop(g);
        crate::task::percpu::schedule();
        q.finish_wait(w.as_ref());
    }
}

/// Tell waiters the claim in progress is done (Linux bd_clear_claiming)
fn clear_claiming(dc: &DiskClaims, c: &mut Claims, holder: Holder) {
    assert_eq!(c.claiming, Some(holder), "bdev claim: not the claimer");
    c.claiming = None;
    var_waitqueue(core::ptr::from_ref(dc) as usize).wake_all();
}

/// Mark `bdev` claimed by `holder` after a successful open (Linux
/// bd_finish_claiming): under the disk's `open_mutex`
pub(super) fn finish(bdev: &BlockDevice, holder: Holder) {
    let dc = claims_of(bdev);
    let partno = usize::from(bdev.partno);
    let mut g = BDEV_LOCK.lock();
    let c = dc.access_mut(&mut g);
    assert!(may_claim(c, partno, holder), "bdev claim: lost");
    // A whole disk counts twice, and is marked partly claimed before it
    // is marked its holder's (Linux)
    c.parts[0].holders += 1;
    c.parts[0].holder = BdHolder::Parts;
    c.parts[partno].holders += 1;
    c.parts[partno].holder = BdHolder::By(holder);
    clear_claiming(dc, c, holder);
}

/// Abandon a prepared claim (Linux bd_abort_claiming): the open failed,
/// or the claim only kept other claimers out for a while
pub fn abort(bdev: &BlockDevice, holder: Holder) {
    let dc = claims_of(bdev);
    let mut g = BDEV_LOCK.lock();
    clear_claiming(dc, dc.access_mut(&mut g), holder);
}

/// Release `holder`'s claim of `bdev` (Linux bd_end_claim): under the
/// disk's `open_mutex`
pub(super) fn end(bdev: &BlockDevice, holder: Holder) {
    let dc = claims_of(bdev);
    let partno = usize::from(bdev.partno);
    let mut g = BDEV_LOCK.lock();
    let c = dc.access_mut(&mut g);
    let p = &mut c.parts[partno];
    debug_assert!(p.holder == BdHolder::By(holder) && p.holders > 0);
    p.holders -= 1;
    if p.holders == 0 {
        p.holder = BdHolder::Free;
    }
    let w = &mut c.parts[0];
    w.holders -= 1;
    if w.holders == 0 {
        w.holder = BdHolder::Free;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(c: &mut Claims, partno: usize, h: Holder) -> bool {
        if !may_claim(c, partno, h) {
            return false;
        }
        c.parts[0].holders += 1;
        c.parts[0].holder = BdHolder::Parts;
        c.parts[partno].holders += 1;
        c.parts[partno].holder = BdHolder::By(h);
        true
    }

    #[test]
    fn exclusive() {
        let mut c = Claims::new(4).unwrap();
        // A partition claimed: others refused, the same holder nests,
        // another partition free, the whole disk refused
        assert!(claim(&mut c, 1, 0x100));
        assert!(!may_claim(&c, 1, 0x200));
        assert!(may_claim(&c, 1, 0x100));
        assert!(may_claim(&c, 2, 0x200));
        assert!(!may_claim(&c, 0, 0x200));
        assert!(!may_claim(&c, 0, 0x100));
        // A whole disk claimed: its partitions refused, the holder nests
        let mut c = Claims::new(4).unwrap();
        assert!(claim(&mut c, 0, 0x300));
        assert!(!may_claim(&c, 1, 0x200));
        assert!(!may_claim(&c, 0, 0x200));
        assert!(may_claim(&c, 0, 0x300));
    }
}

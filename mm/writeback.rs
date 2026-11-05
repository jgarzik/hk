//! Per-device writeback (Linux mm/backing-dev.c, the flusher of
//! fs/fs-writeback.c)
//!
//! Each disk has a [`BdiWriteback`] (Linux bdi_writeback): the devices
//! (the disk or its partitions) with dirty data, and a delayed work item
//! on `BDI_WORKQUEUE` that writes them back about every 5 seconds (Linux
//! dirty_writeback_centisecs 500): first the dirty inodes of every
//! filesystem mounted from the device (`fs_writeback::writeback_dev`),
//! then the device's own cache (metadata, device-node writes).
//!
//! Locking: `BDI_REGISTRY`, `BdiWriteback.dirty` and the work item are
//! spin leaves; writeback runs in the worker thread with none held.

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::block::blkdev::DevId;
use crate::sync::spin::{Mutex, RwLock};
use crate::task::workqueue::{DelayedWork, Workqueue, wq_flags};

/// The periodic writeback's interval in scheduler ticks
/// (vm.dirty_writeback_centisecs)
fn interval() -> u64 {
    let cs = WRITEBACK_CS.load(Ordering::Relaxed).max(1);
    cs * 10 / crate::task::percpu::TICK_MS
}

/// The writeback workqueue (Linux bdi_wq: WQ_MEM_RECLAIM, so writeback
/// proceeds under memory pressure)
pub static BDI_WORKQUEUE: Workqueue =
    Workqueue::new("bdi", wq_flags::WQ_MEM_RECLAIM | wq_flags::WQ_UNBOUND);

/// Per-disk writeback state, by the disk's device number
static BDI_REGISTRY: RwLock<BTreeMap<DevId, Arc<BdiWriteback>>> = RwLock::new(BTreeMap::new());

/// One disk's writeback state (Linux bdi_writeback)
pub struct BdiWriteback {
    /// The disk's device number
    pub dev_id: DevId,
    /// Devices of the disk with dirty data
    dirty: Mutex<BTreeSet<DevId>>,
    /// The periodic writeback
    dwork: Arc<Mutex<DelayedWork>>,
}

impl BdiWriteback {
    fn new(dev_id: DevId) -> Self {
        let dwork = Arc::new(Mutex::new(DelayedWork::new(move || {
            do_device_writeback(dev_id);
        })));
        Self {
            dev_id,
            dirty: Mutex::new(BTreeSet::new()),
            dwork,
        }
    }

    /// Device `dev` (the disk or a partition) has dirty data: arm the
    /// periodic writeback (Linux wb_wakeup_delayed)
    pub fn kick(&self, dev: DevId) {
        let first = {
            let mut d = self.dirty.lock();
            let first = d.is_empty();
            d.insert(dev);
            first
        };
        if first {
            BDI_WORKQUEUE.queue_delayed_work(self.dwork.clone(), interval());
        }
    }

    /// Start writing `dev` back now (past the background limit; Linux
    /// wb_start_background_writeback)
    pub fn wakeup(&self, dev: DevId) {
        self.dirty.lock().insert(dev);
        BDI_WORKQUEUE.mod_delayed_work(&self.dwork, 0);
    }
}

/// The periodic writeback of one disk, in the worker thread
fn do_device_writeback(disk: DevId) {
    let Some(bdi) = get_bdi(disk) else {
        return;
    };
    let devs = core::mem::take(&mut *bdi.dirty.lock());
    for dev in devs {
        crate::fs::fs_writeback::writeback_dev(dev);
        if let Some(b) = crate::block::get_blkdev(dev) {
            let _ = crate::block::blkdev::sync_blockdev(&b);
        }
    }
}

// ============================================================================
// Dirty limits (Linux mm/page-writeback.c)
// ============================================================================

/// vm.dirty_background_ratio / _bytes, vm.dirty_ratio / _bytes: one of
/// each pair is in effect (writing one clears the other, as on Linux)
static BG_RATIO: AtomicU64 = AtomicU64::new(10);
static BG_BYTES: AtomicU64 = AtomicU64::new(0);
static DIRTY_RATIO: AtomicU64 = AtomicU64::new(20);
static DIRTY_BYTES: AtomicU64 = AtomicU64::new(0);
/// vm.dirty_expire_centisecs (stored; hk writes every dirty inode of a
/// device at each pass) and vm.dirty_writeback_centisecs
static EXPIRE_CS: AtomicU64 = AtomicU64::new(3000);
static WRITEBACK_CS: AtomicU64 = AtomicU64::new(500);

/// Pages a limit of `ratio` percent / `bytes` stands for, of the memory
/// the page allocator manages (Linux: of dirtyable memory)
fn limit(ratio: &AtomicU64, bytes: &AtomicU64) -> u64 {
    let b = bytes.load(Ordering::Relaxed);
    if b != 0 {
        return b / 4096;
    }
    let total = crate::FRAME_ALLOCATOR.stats().total_bytes / 4096;
    total * ratio.load(Ordering::Relaxed) / 100
}

/// After a write dirtied pages of `inode` (Linux
/// balance_dirty_pages_ratelimited): past the background limit its
/// device's writeback starts now; past the dirty limit the writer
/// writes the inode back itself (Linux throttles it until the flusher
/// catches up). Sleeps; no lock held.
pub fn balance_dirty_pages(inode: &crate::fs::Inode) {
    let dirty = crate::mm::filemap::nr_dirty();
    if dirty > limit(&DIRTY_RATIO, &DIRTY_BYTES) {
        let _ = crate::fs::fs_writeback::writeback_inode(inode);
    } else if dirty > limit(&BG_RATIO, &BG_BYTES)
        && let Some(b) = inode.superblock().and_then(|sb| sb.bdev().cloned())
    {
        b.disk.bdi.wakeup(b.dev_id());
    }
}

fn set_pair(
    on: &AtomicU64,
    off: &AtomicU64,
    v: i64,
    lo: i64,
    hi: i64,
) -> Result<(), crate::util::error::KernelError> {
    crate::sysctl::range(v, lo, hi)?;
    on.store(v as u64, Ordering::Relaxed);
    off.store(0, Ordering::Relaxed);
    Ok(())
}

/// vm.drop_caches: the last value written
static DROP_CACHES: AtomicU64 = AtomicU64::new(0);

/// /proc/sys/vm dirty limits and drop_caches (Linux vm_table)
pub static WB_CTLS: &[crate::sysctl::Ctl] = &[
    // Linux drop_caches_sysctl_handler: 1 drops clean page cache, 2
    // the reclaimable slab (unused dentries, and the inodes only they
    // held), 3 both; 4 only silences the log
    crate::sysctl::Ctl {
        path: "vm/drop_caches",
        mode: 0o200,
        show: || alloc::vec![DROP_CACHES.load(Ordering::Relaxed) as i64],
        store: |v| {
            crate::sysctl::range(v[0], 1, 4)?;
            DROP_CACHES.store(v[0] as u64, Ordering::Relaxed);
            if v[0] & 1 != 0 {
                crate::mm::filemap::drop_pagecache();
            }
            if v[0] & 2 != 0 {
                crate::fs::dentry::shrink_dcache(usize::MAX);
            }
            Ok(())
        },
        text: None,
    },
    crate::sysctl::Ctl {
        path: "vm/dirty_background_ratio",
        mode: 0o644,
        show: || alloc::vec![BG_RATIO.load(Ordering::Relaxed) as i64],
        store: |v| set_pair(&BG_RATIO, &BG_BYTES, v[0], 0, 100),
        text: None,
    },
    crate::sysctl::Ctl {
        path: "vm/dirty_background_bytes",
        mode: 0o644,
        show: || alloc::vec![BG_BYTES.load(Ordering::Relaxed) as i64],
        store: |v| set_pair(&BG_BYTES, &BG_RATIO, v[0], 1, i64::MAX),
        text: None,
    },
    crate::sysctl::Ctl {
        path: "vm/dirty_ratio",
        mode: 0o644,
        show: || alloc::vec![DIRTY_RATIO.load(Ordering::Relaxed) as i64],
        store: |v| set_pair(&DIRTY_RATIO, &DIRTY_BYTES, v[0], 0, 100),
        text: None,
    },
    crate::sysctl::Ctl {
        path: "vm/dirty_bytes",
        mode: 0o644,
        show: || alloc::vec![DIRTY_BYTES.load(Ordering::Relaxed) as i64],
        store: |v| set_pair(&DIRTY_BYTES, &DIRTY_RATIO, v[0], 2 * 4096, i64::MAX),
        text: None,
    },
    crate::sysctl::Ctl {
        path: "vm/dirty_expire_centisecs",
        mode: 0o644,
        show: || alloc::vec![EXPIRE_CS.load(Ordering::Relaxed) as i64],
        store: |v| {
            crate::sysctl::range(v[0], 0, i32::MAX as i64)?;
            EXPIRE_CS.store(v[0] as u64, Ordering::Relaxed);
            Ok(())
        },
        text: None,
    },
    crate::sysctl::Ctl {
        path: "vm/dirty_writeback_centisecs",
        mode: 0o644,
        show: || alloc::vec![WRITEBACK_CS.load(Ordering::Relaxed) as i64],
        store: |v| {
            crate::sysctl::range(v[0], 0, i32::MAX as i64)?;
            WRITEBACK_CS.store(v[0] as u64, Ordering::Relaxed);
            Ok(())
        },
        text: None,
    },
];

/// Write back everything (sync(2), Linux ksys_sync): every
/// filesystem's dirty inodes, then the devices' caches
pub fn sync_all() {
    crate::fs::fs_writeback::sync_all_sbs();
    crate::block::blkdev::sync_bdevs();
}

/// Register a disk's writeback state (Linux bdi_register)
pub fn bdi_register(dev_id: DevId) -> Arc<BdiWriteback> {
    let bdi = Arc::new(BdiWriteback::new(dev_id));
    BDI_REGISTRY.write().insert(dev_id, bdi.clone());
    bdi
}

/// Unregister it when the disk goes (Linux bdi_unregister)
pub fn bdi_unregister(dev_id: DevId) {
    // The registry guard is gone before the workqueue's locks are taken
    // (BDI_REGISTRY stays a leaf)
    let bdi = BDI_REGISTRY.write().remove(&dev_id);
    if let Some(bdi) = bdi {
        BDI_WORKQUEUE.cancel_delayed_work(&bdi.dwork);
    }
}

/// A disk's writeback state
pub fn get_bdi(dev_id: DevId) -> Option<Arc<BdiWriteback>> {
    BDI_REGISTRY.read().get(&dev_id).cloned()
}

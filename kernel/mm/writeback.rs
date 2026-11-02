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

use crate::storage::blkdev::DevId;
use crate::sync::spin::{Mutex, RwLock};
use crate::workqueue::{DelayedWork, Workqueue, wq_flags};

/// Writeback interval in timer ticks (500 ticks = ~5 seconds at 100Hz)
pub const WRITEBACK_INTERVAL_TICKS: u64 = 500;

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
            BDI_WORKQUEUE.queue_delayed_work(self.dwork.clone(), WRITEBACK_INTERVAL_TICKS);
        }
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
        if let Some(b) = crate::storage::get_blkdev(dev) {
            let _ = crate::storage::blkdev::sync_blockdev(&b);
        }
    }
}

/// Write back everything (sync(2), Linux ksys_sync): every
/// filesystem's dirty inodes, then the devices' caches
pub fn sync_all() {
    crate::fs::fs_writeback::sync_all_sbs();
    crate::storage::blkdev::sync_bdevs();
}

/// Register a disk's writeback state (Linux bdi_register)
pub fn bdi_register(dev_id: DevId) -> Arc<BdiWriteback> {
    let bdi = Arc::new(BdiWriteback::new(dev_id));
    BDI_REGISTRY.write().insert(dev_id, bdi.clone());
    bdi
}

/// Unregister it when the disk goes (Linux bdi_unregister)
pub fn bdi_unregister(dev_id: DevId) {
    if let Some(bdi) = BDI_REGISTRY.write().remove(&dev_id) {
        bdi.dwork.lock().cancel_timer();
    }
}

/// A disk's writeback state
pub fn get_bdi(dev_id: DevId) -> Option<Arc<BdiWriteback>> {
    BDI_REGISTRY.read().get(&dev_id).cloned()
}

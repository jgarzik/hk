//! Per-device writeback (Linux mm/backing-dev.c, the flusher of
//! fs/fs-writeback.c)
//!
//! Each disk has a [`BdiWriteback`] (Linux bdi_writeback): the dirty
//! inodes of the filesystems on it and of its block devices' caches
//! (`b_dirty`, `b_io`: `fs_writeback`), and a delayed work item on
//! `BDI_WORKQUEUE` that writes them back about every 5 seconds (Linux
//! dirty_writeback_centisecs 500): what became dirty over 30 seconds
//! before (dirty_expire_centisecs 3000; everything past the background
//! limit), oldest first; younger data re-arms the work.
//!
//! Locking: `BdiWriteback.list_lock` and the work item are spin leaves;
//! writeback runs in the worker thread with only `BdiWriteback.pass`
//! (sleeping) held.

extern crate alloc;

use crate::util::kalloc::{arc_cyclic_nofail, arc_nofail};
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::block::blkdev::DevId;
use crate::fs::fs_writeback::IoListA;
use crate::sync::spin::Mutex;
use crate::task::workqueue::{DelayedWork, Workqueue, wq_flags};
use crate::util::list::ArcList;

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

/// Start the writeback workqueue's worker (Linux default_bdi_init, a
/// subsys_initcall allocating bdi_wq): before any disk is registered,
/// after the workqueues can run
pub fn default_bdi_init() {
    if let Err(e) = BDI_WORKQUEUE.start(None) {
        crate::printkln!("writeback: no bdi worker ({:?}): no periodic writeback", e);
    }
}

/// One disk's writeback state (Linux bdi_writeback)
pub struct BdiWriteback {
    /// The disk's device number
    pub dev_id: DevId,
    /// Linux wb->list_lock and the inode lists it guards
    /// (`fs_writeback`): a spin leaf, thread context
    pub(crate) list_lock: Mutex<WbLists>,
    /// One writeback pass over the lists at a time (sleeping, held
    /// across the pass's I/O; Linux runs them one at a time from the
    /// wb's work list)
    pub(crate) pass: crate::sync::Mutex<()>,
    /// The periodic writeback
    dwork: Arc<crate::sync::IrqSpinlock<DelayedWork>>,
    /// The next pass writes everything, however young (background
    /// writeback past the background limit, Linux WB_REASON_BACKGROUND)
    background: AtomicBool,
}

/// A disk's dirty inodes, each list holding a reference per inode
/// (linked through `Inode.i_io_list`)
pub(crate) struct WbLists {
    /// Dirtied and not yet taken by a pass, oldest first (Linux b_dirty,
    /// which keeps them newest first)
    pub b_dirty: ArcList<IoListA>,
    /// Taken by the running pass, to write in order (Linux b_io)
    pub b_io: ArcList<IoListA>,
}

impl BdiWriteback {
    fn new(dev_id: DevId, me: &Weak<Self>) -> Self {
        let me = me.clone();
        // `bdi_register`'s: not plumbed
        let dwork = arc_nofail(crate::sync::IrqSpinlock::new(DelayedWork::new(move || {
            if let Some(wb) = me.upgrade() {
                wb_workfn(&wb);
            }
        })));
        Self {
            dev_id,
            list_lock: Mutex::new(WbLists {
                b_dirty: ArcList::new(),
                b_io: ArcList::new(),
            }),
            pass: crate::sync::Mutex::new(()),
            dwork,
            background: AtomicBool::new(false),
        }
    }

    /// The lists got their first dirty inode: arm the periodic writeback
    /// (Linux wb_wakeup_delayed)
    pub fn wakeup_delayed(&self) {
        BDI_WORKQUEUE.queue_delayed_work(self.dwork.clone(), interval());
    }

    /// Start writing back now, everything dirty (past the background
    /// limit; Linux wb_start_background_writeback)
    pub fn wakeup(&self) {
        self.background.store(true, Ordering::Release);
        BDI_WORKQUEUE.mod_delayed_work(&self.dwork, 0);
    }
}

/// The periodic writeback of one disk, in the worker thread (Linux
/// wb_workfn)
fn wb_workfn(wb: &BdiWriteback) {
    let cutoff = if wb.background.swap(false, Ordering::AcqRel) {
        u64::MAX
    } else {
        let expire_ns = EXPIRE_CS.load(Ordering::Relaxed).saturating_mul(10_000_000);
        crate::time::monotonic_ns().saturating_sub(expire_ns)
    };
    // Younger data waits for a later pass (Linux wb_workfn re-arms
    // while the wb has dirty I/O)
    if crate::fs::fs_writeback::wb_do_writeback(wb, cutoff) {
        wb.wakeup_delayed();
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
/// vm.dirty_expire_centisecs (the periodic writeback takes data older
/// than it) and vm.dirty_writeback_centisecs (its interval)
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
        b.disk.bdi.wakeup();
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
            crate::sysctl::range(v[0], 0, i64::from(i32::MAX))?;
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
            crate::sysctl::range(v[0], 0, i64::from(i32::MAX))?;
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

/// Make a disk's writeback state (Linux bdi_alloc + bdi_register): its
/// periodic work reaches it through a `Weak`
pub fn bdi_register(dev_id: DevId) -> Arc<BdiWriteback> {
    // Not plumbed: its caller, Disk::new, has no error path
    arc_cyclic_nofail(|me| BdiWriteback::new(dev_id, me))
}

/// Stop its periodic writeback when the disk goes (Linux
/// bdi_unregister)
pub fn bdi_unregister(bdi: &BdiWriteback) {
    BDI_WORKQUEUE.cancel_delayed_work(&bdi.dwork);
}

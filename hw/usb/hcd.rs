//! Host controller side of the USB core (Linux drivers/usb/core/hcd.c)
//!
//! A host controller driver implements `Hcd` (Linux struct hc_driver:
//! urb_enqueue, urb_dequeue) and owns a `GivebackBh`: URBs it is done
//! with are given back through `usb_hcd_giveback_urb` in any context
//! (its interrupt handler, under its own lock) and their completion
//! handlers run later from the bottom half (Linux HCD_BH, the
//! giveback_urb_bh work on system_bh_wq): the `usb_bh` workqueue's
//! thread here, as hk has no softirqs. Completion handlers keep
//! Linux's bottom-half rules: they must not sleep.
//!
//! Locking: `GivebackBh.list` is an `IrqSpinlock` leaf (Linux bh->lock),
//! taken under the HCD's lock (xHCI: `Xhci.lock` -> `GivebackBh.list`);
//! the work takes the whole list out under it and runs the handlers
//! with nothing held.

use alloc::sync::Arc;

use super::UsbError;
use super::urb::{Urb, UrbBhLink};
use crate::hw::dma::DmaCoherent;
use crate::sync::IrqSpinlock;
use crate::task::workqueue::{Work, Workqueue, wq_flags};
use crate::util::kalloc::try_arc;
use crate::util::list::ArcList;

/// A host controller driver (Linux struct hc_driver and the struct
/// usb_hcd it is reached through)
pub trait Hcd: Send + Sync {
    /// Queue `urb` on its endpoint (Linux hc_driver.urb_enqueue); the
    /// controller gives it back with `usb_hcd_giveback_urb`
    fn urb_enqueue(&self, urb: &Arc<Urb>) -> Result<(), UsbError>;

    /// Cancel `urb` with `status` (Linux hc_driver.urb_dequeue): given
    /// back once the controller let go of it; any context. Idle if not
    /// queued, Busy if being unlinked already
    fn urb_dequeue(&self, urb: &Arc<Urb>, status: UsbError) -> Result<(), UsbError>;

    /// The bottom half its URBs are given back through
    fn bh(&self) -> &GivebackBh;

    /// A transfer buffer of `size` bytes the controller can reach (Linux
    /// hcd_buffer_alloc); thread context
    fn buffer_alloc(&self, size: usize) -> Option<DmaCoherent>;

    /// Free a `buffer_alloc` buffer (Linux hcd_buffer_free)
    ///
    /// # Safety
    /// The device no longer accesses it.
    unsafe fn buffer_free(&self, buf: DmaCoherent);
}

/// A device's host controller (Linux usb_device.bus); none for the
/// root hub
#[derive(Clone, Default)]
pub struct HcdRef(Option<Arc<dyn Hcd>>);

impl HcdRef {
    pub fn new(hcd: Arc<dyn Hcd>) -> Self {
        Self(Some(hcd))
    }

    pub fn get(&self) -> Option<&Arc<dyn Hcd>> {
        self.0.as_ref()
    }
}

impl core::fmt::Debug for HcdRef {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(if self.0.is_some() { "HcdRef" } else { "None" })
    }
}

/// The giveback bottom half's thread (Linux system_bh_wq, which runs
/// in softirq context; hk has no softirqs): its work never sleeps, so
/// one worker serves every host controller
pub static USB_BH_WQ: Workqueue = Workqueue::new("usb_bh", wq_flags::WQ_HIGHPRI);

/// Start the bottom half's worker (usb_init)
pub fn usb_bh_init() {
    if let Err(e) = USB_BH_WQ.start(None) {
        crate::printkln!("usb: no giveback worker: {:?}", e);
    }
}

/// URBs waiting for their completion handlers (Linux struct
/// giveback_urb_bh)
pub struct GivebackBh {
    list: Arc<IrqSpinlock<ArcList<UrbBhLink>>>,
    work: Arc<IrqSpinlock<Work>>,
}

impl GivebackBh {
    /// A bottom half with its work item (Linux usb_add_hcd's
    /// init_giveback_urb_bh); thread context
    pub fn new() -> Result<Self, crate::util::error::KernelError> {
        let list = try_arc(IrqSpinlock::new(ArcList::new()))?;
        let l = list.clone();
        let work = try_arc(IrqSpinlock::new(Work::new(move || usb_giveback_urb_bh(&l))))?;
        Ok(Self { list, work })
    }
}

/// Queue `urb` for its completion handler and kick the work (Linux
/// usb_hcd_giveback_urb's BH half); any context. A work already
/// running runs again (WORK_RERUN), as Linux's re-queues itself
pub(super) fn giveback_queue(bh: &GivebackBh, urb: Arc<Urb>) {
    bh.list.lock().push_back(urb);
    USB_BH_WQ.queue_work(bh.work.clone());
}

/// Run the completion handlers of the URBs queued so far (Linux
/// usb_giveback_urb_bh): later ones wait for the next run
fn usb_giveback_urb_bh(list: &IrqSpinlock<ArcList<UrbBhLink>>) {
    let mut local = ArcList::<UrbBhLink>::new();
    {
        let mut l = list.lock();
        while let Some(u) = l.pop_front() {
            local.push_back(u);
        }
    }
    while let Some(urb) = local.pop_front() {
        urb.giveback();
    }
}

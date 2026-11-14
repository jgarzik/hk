//! USB Request Blocks (Linux drivers/usb/core/urb.c, struct urb)
//!
//! A driver allocates an URB for one endpoint of a device
//! (`Urb::new`), fills its transfer buffer and submits it
//! (`usb_submit_urb`): the host controller queues it on the endpoint
//! and gives it back once it completed, failed or was unlinked, calling
//! its completion handler from the giveback bottom half (`hcd.rs`).
//! The handler may resubmit it. `usb_unlink_urb` asks for an early
//! giveback; `usb_kill_urb` also waits for it.
//!
//! Its transfer buffer is coherent DMA memory allocated with the URB
//! (Linux usb_alloc_coherent with URB_NO_TRANSFER_DMA_MAP): submitting
//! maps nothing, and the CPU reads and writes it only while the URB is
//! not queued (`fill`, `copy_out`).
//!
//! Locking: `Urb.st` is an `IrqSpinlock` leaf (the HCD takes it under
//! its own lock: xHCI's `Xhci.lock` -> `Urb.st`). `use_count` and
//! `reject` are Linux's atomics; `usb_kill_urb` waits on
//! `USB_KILL_URB_QUEUE` for `use_count` to drop to 0.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering, fence};

use super::hcd::{self, Hcd};
use super::{EndpointType, SetupPacket, UsbDevice, UsbError};
use crate::hw::dma::DmaCoherent;
use crate::sync::IrqSpinlock;
use crate::sync::waitqueue::WaitQueue;
use crate::util::list::Link;

/// An endpoint of a device (Linux pipe): its type and address
/// (bEndpointAddress, bit 7 IN; 0 or 0x80 for the default control
/// endpoint)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pipe {
    pub ty: EndpointType,
    pub ep: u8,
}

impl Pipe {
    /// The default control endpoint (Linux usb_sndctrlpipe(dev, 0));
    /// the setup packet gives the direction
    pub const fn ctrl() -> Self {
        Self {
            ty: EndpointType::Control,
            ep: 0,
        }
    }

    /// Bulk IN endpoint `ep` (Linux usb_rcvbulkpipe)
    pub const fn bulk_in(ep: u8) -> Self {
        Self {
            ty: EndpointType::Bulk,
            ep: ep | 0x80,
        }
    }

    /// Bulk OUT endpoint `ep` (Linux usb_sndbulkpipe)
    pub const fn bulk_out(ep: u8) -> Self {
        Self {
            ty: EndpointType::Bulk,
            ep: ep & 0x0f,
        }
    }

    /// Device to host (Linux usb_pipein)
    pub fn is_in(&self) -> bool {
        self.ep & 0x80 != 0
    }
}

/// An URB's completion handler (Linux urb->complete with its context),
/// called from the giveback bottom half, which must not sleep
pub type UrbComplete = Box<dyn Fn(&Arc<Urb>) + Send + Sync>;

/// The fields the host controller and the submitter hand back and
/// forth (Linux urb->status, actual_length, unlinked, hcpriv)
struct UrbState {
    /// The last giveback's status (Linux urb->status)
    status: Result<(), UsbError>,
    /// Bytes transferred (Linux urb->actual_length)
    actual_length: usize,
    /// Bytes to transfer (Linux urb->transfer_buffer_length)
    len: usize,
    /// Unlinked with this status (Linux urb->unlinked)
    unlinked: Option<UsbError>,
    /// Queued at the host controller, from submission to giveback
    /// (Linux urb->hcpriv set): the buffer is the device's
    linked: bool,
}

/// A USB request (Linux struct urb)
pub struct Urb {
    /// On the giveback bottom half's list (Linux urb_list)
    pub(super) bh_link: Link,
    hcd: Arc<dyn Hcd>,
    slot_id: u8,
    pipe: Pipe,
    /// The setup packet of a control request (Linux setup_packet)
    setup: Option<SetupPacket>,
    /// Transfer buffer (None for a request without data)
    buf: Option<DmaCoherent>,
    complete: UrbComplete,
    st: IrqSpinlock<UrbState>,
    /// Submitted and not yet given back, completion handler included
    /// (Linux urb->use_count)
    use_count: AtomicU32,
    /// Being killed: submissions fail (Linux urb->reject)
    reject: AtomicU32,
}

crate::adapter!(pub(super) UrbBhLink, Urb, bh_link);

/// Waiters for killed URBs to be given back (Linux usb_kill_urb_queue)
static USB_KILL_URB_QUEUE: WaitQueue = WaitQueue::new();

impl Urb {
    /// An URB for `pipe` of `dev` with a transfer buffer of `size`
    /// bytes (Linux usb_alloc_urb, usb_alloc_coherent and the
    /// usb_fill_*_urb helpers); thread context. None without a host
    /// controller or memory
    pub fn new(
        dev: &UsbDevice,
        pipe: Pipe,
        setup: Option<SetupPacket>,
        size: usize,
        complete: UrbComplete,
    ) -> Option<Arc<Self>> {
        let hcd = dev.bus.get()?.clone();
        let buf = match size {
            0 => None,
            n => Some(hcd.buffer_alloc(n)?),
        };
        let urb = Self {
            bh_link: Link::new(),
            hcd,
            slot_id: dev.slot_id,
            pipe,
            setup,
            buf,
            complete,
            st: IrqSpinlock::new(UrbState {
                status: Ok(()),
                actual_length: 0,
                len: 0,
                unlinked: None,
                linked: false,
            }),
            use_count: AtomicU32::new(0),
            reject: AtomicU32::new(0),
        };
        // On failure the buffer goes back through the URB's drop
        crate::util::kalloc::try_arc(urb).ok()
    }

    pub fn slot_id(&self) -> u8 {
        self.slot_id
    }

    pub fn pipe(&self) -> Pipe {
        self.pipe
    }

    pub fn setup(&self) -> Option<&SetupPacket> {
        self.setup.as_ref()
    }

    /// The transfer buffer's size
    pub fn capacity(&self) -> usize {
        self.buf.as_ref().map_or(0, |b| b.size())
    }

    /// The transfer buffer's device address (the HCD, while queued)
    pub(super) fn dma_addr(&self) -> u64 {
        self.buf.as_ref().map_or(0, |b| b.dma_addr().as_u64())
    }

    /// Bytes to transfer (Linux transfer_buffer_length)
    pub fn len(&self) -> usize {
        self.st.lock().len
    }

    /// Nothing to transfer
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Set the transfer to `data` (OUT) or to `len` bytes (IN, `data`
    /// None), at most the buffer's size; Busy while queued
    pub fn fill(&self, data: Option<&[u8]>, len: usize) -> Result<usize, UsbError> {
        let mut st = self.st.lock();
        if st.linked {
            return Err(UsbError::Busy);
        }
        let n = data.map_or(len, <[u8]>::len).min(self.capacity());
        if let (Some(d), Some(b)) = (data, &self.buf) {
            // SAFETY: not queued (`linked` false under `st`): the
            // device does not access the buffer; `n` fits both
            unsafe { core::ptr::copy_nonoverlapping(d.as_ptr(), b.cpu_addr(), n) };
        }
        st.len = n;
        Ok(n)
    }

    /// Copy what the last transfer received into `out`: the bytes
    /// copied (Busy while queued)
    pub fn copy_out(&self, out: &mut [u8]) -> Result<usize, UsbError> {
        let st = self.st.lock();
        if st.linked {
            return Err(UsbError::Busy);
        }
        let n = st.actual_length.min(out.len()).min(self.capacity());
        if let Some(b) = &self.buf {
            // The device's writes before its completion event first
            fence(Ordering::Acquire);
            // SAFETY: given back (`linked` false under `st`): the
            // device is done with the buffer; `n` fits both
            unsafe { core::ptr::copy_nonoverlapping(b.cpu_addr(), out.as_mut_ptr(), n) };
        }
        Ok(n)
    }

    /// The last giveback's status (Linux urb->status)
    pub fn status(&self) -> Result<(), UsbError> {
        self.st.lock().status
    }

    /// Bytes the last transfer moved (Linux urb->actual_length)
    pub fn actual_length(&self) -> usize {
        self.st.lock().actual_length
    }

    /// Submitted and not yet given back (Linux urb->use_count)
    pub fn in_flight(&self) -> bool {
        self.use_count.load(Ordering::Acquire) != 0
    }

    /// Set the length the HCD measured (under the HCD's lock, queued)
    pub(super) fn set_actual_length(&self, n: usize) {
        self.st.lock().actual_length = n;
    }

    /// Linux usb_hcd_check_unlink_urb's URB half: mark it unlinked
    /// with `status` unless it was already (Busy)
    pub(super) fn mark_unlinked(&self, status: UsbError) -> Result<(), UsbError> {
        let mut st = self.st.lock();
        if st.unlinked.is_some() {
            return Err(UsbError::Busy);
        }
        st.unlinked = Some(status);
        Ok(())
    }

    /// Linux usb_hcd_giveback_urb: pass `status` on unless it was
    /// unlinked
    pub(super) fn set_giveback_status(&self, status: Result<(), UsbError>) {
        let mut st = self.st.lock();
        if st.unlinked.is_none()
            && let Err(e) = status
        {
            st.unlinked = Some(e);
        }
    }

    /// Linux __usb_hcd_giveback_urb: the URB back to its owner, its
    /// completion handler called (giveback bottom half)
    pub(super) fn giveback(self: &Arc<Self>) {
        {
            let mut st = self.st.lock();
            st.linked = false;
            st.status = st.unlinked.take().map_or(Ok(()), Err);
            if st.actual_length > st.len {
                st.actual_length = 0;
            }
        }
        (self.complete)(self);
        self.use_count.fetch_sub(1, Ordering::AcqRel);
        // The count's drop before the reject check (Linux
        // smp_mb__after_atomic; pairs with usb_kill_urb's)
        fence(Ordering::SeqCst);
        if self.reject.load(Ordering::Acquire) != 0 {
            USB_KILL_URB_QUEUE.wake_all();
        }
    }
}

impl Drop for Urb {
    fn drop(&mut self) {
        if let Some(b) = self.buf.take() {
            // SAFETY: the last reference: not queued (a queued URB is
            // referenced by its TD), so the device is done with it
            unsafe { self.hcd.buffer_free(b) };
        }
    }
}

/// Queue `urb` at its host controller (Linux usb_submit_urb, then
/// usb_hcd_submit_urb); its completion handler runs once it is given
/// back. Busy if queued already, Rejected while being killed
pub fn usb_submit_urb(urb: &Arc<Urb>) -> Result<(), UsbError> {
    {
        let mut st = urb.st.lock();
        if st.linked {
            return Err(UsbError::Busy);
        }
        if st.len > urb.capacity() {
            return Err(UsbError::InvalidParam);
        }
        st.linked = true;
        st.status = Err(UsbError::InProgress);
        st.actual_length = 0;
        st.unlinked = None;
    }
    urb.use_count.fetch_add(1, Ordering::AcqRel);
    // The count before the reject check (pairs with usb_kill_urb)
    fence(Ordering::SeqCst);
    let r = if urb.reject.load(Ordering::Acquire) != 0 {
        Err(UsbError::Rejected)
    } else {
        urb.hcd.urb_enqueue(urb)
    };
    if r.is_err() {
        urb.st.lock().linked = false;
        urb.use_count.fetch_sub(1, Ordering::AcqRel);
        fence(Ordering::SeqCst);
        if urb.reject.load(Ordering::Acquire) != 0 {
            USB_KILL_URB_QUEUE.wake_all();
        }
    }
    r
}

/// Ask for `urb` to be given back early with `status` (Linux
/// usb_hcd_unlink_urb); any context. Idle if it is not queued
fn usb_hcd_unlink_urb(urb: &Arc<Urb>, status: UsbError) -> Result<(), UsbError> {
    if urb.use_count.load(Ordering::Acquire) == 0 {
        return Err(UsbError::Idle);
    }
    urb.hcd.urb_dequeue(urb, status)
}

/// Cancel `urb` without waiting (Linux usb_unlink_urb): it is given
/// back with Unlinked once the controller let go of it. Ok when the
/// unlink is under way (Linux -EINPROGRESS); Idle if not queued, Busy
/// if being given back or unlinked already
pub fn usb_unlink_urb(urb: &Arc<Urb>) -> Result<(), UsbError> {
    usb_hcd_unlink_urb(urb, UsbError::Unlinked)
}

/// Cancel `urb` and wait until it is given back, its completion
/// handler done (status Killed unless it completed first); submissions
/// fail meanwhile (Linux usb_kill_urb). Thread context, no spinlock
pub fn usb_kill_urb(urb: &Arc<Urb>) {
    crate::sync::might_sleep();
    urb.reject.fetch_add(1, Ordering::AcqRel);
    // The reject before the count check (pairs with giveback and
    // submit)
    fence(Ordering::SeqCst);
    let _ = usb_hcd_unlink_urb(urb, UsbError::Killed);
    USB_KILL_URB_QUEUE.wait_event(|| urb.use_count.load(Ordering::Acquire) == 0);
    urb.reject.fetch_sub(1, Ordering::AcqRel);
}

/// Give `urb` back to its owner with `status` (Linux
/// usb_hcd_giveback_urb): queued for the giveback bottom half; any
/// context
pub(super) fn usb_hcd_giveback_urb(urb: Arc<Urb>, status: Result<(), UsbError>) {
    urb.set_giveback_status(status);
    let h = urb.hcd.clone();
    hcd::giveback_queue(h.bh(), urb);
}

/// Boot self-test of URB cancellation (`selftest.rs`) on IN `pipe` of
/// `dev`, an endpoint that NAKs while it has nothing to send (QEMU's
/// FT232 without input; a real one answers with its status bytes,
/// which ends the test unchecked): an unlinked URB is given back
/// Unlinked, a timed-out synchronous request is killed (Timeout) and
/// the endpoint keeps working after each, a killed URB is given back
/// Killed, and killing an idle one returns at once. The device going
/// away meanwhile (an unbind) ends it unchecked. Thread context
pub fn urb_selftest(dev: &UsbDevice, pipe: Pipe, check: &mut dyn FnMut(&str, bool, u64)) {
    use crate::sync::completion::Completion;
    use crate::task::percpu::ms_to_ticks;
    let code = |r: Result<(), UsbError>| r.err().map_or(0, err_code);
    let gone = |r: &Result<(), UsbError>| matches!(r, Err(UsbError::NoDevice | UsbError::Shutdown));
    let Ok(done) = crate::util::kalloc::try_arc(Completion::new()) else {
        return;
    };
    let d = done.clone();
    let Ok(complete) = crate::util::kalloc::try_box(move |_: &Arc<Urb>| d.complete()) else {
        return;
    };
    let Some(urb) = Urb::new(dev, pipe, None, 64, complete) else {
        return;
    };
    let _ = urb.fill(None, 64);
    // 1. Unlink: given back Unlinked once the endpoint stopped and the
    // TD is off the ring
    let r = usb_submit_urb(&urb);
    if gone(&r) {
        return;
    }
    check("urb_submit", r.is_ok(), code(r));
    if r.is_err() || done.wait_timeout(ms_to_ticks(50)) {
        // The device answered: nothing to cancel
        return;
    }
    let r = usb_unlink_urb(&urb);
    check("urb_unlink", r.is_ok() || gone(&r), code(r));
    let back = done.wait_timeout(ms_to_ticks(1000));
    check("urb_unlink_giveback", back, 0);
    if !back {
        // Still queued: a kill would never return
        return;
    }
    let s = urb.status();
    check(
        "urb_unlink_status",
        s == Err(UsbError::Unlinked) || gone(&s),
        code(s),
    );
    // 2. A timed-out request is killed; the endpoint restarts after
    // the Set TR Dequeue Pointer, so the next one runs (and times out)
    for i in 0..2 {
        let mut b = [0u8; 64];
        let r = super::usb_bulk_msg(dev, pipe, &mut b, 50).map(|_| ());
        if gone(&r) {
            return;
        }
        check("urb_timeout_killed", r == Err(UsbError::Timeout), i);
    }
    // 3. Kill: given back Killed, no longer in flight
    let r = usb_submit_urb(&urb);
    if gone(&r) {
        return;
    }
    check("urb_resubmit", r.is_ok(), code(r));
    if r.is_ok() {
        usb_kill_urb(&urb);
        let s = urb.status();
        check(
            "urb_kill_status",
            (s == Err(UsbError::Killed) || gone(&s)) && !urb.in_flight(),
            code(s),
        );
        done.reinit();
    }
    // 4. Killing an idle URB returns at once
    usb_kill_urb(&urb);
    check("urb_kill_idle", !urb.in_flight(), 0);
}

/// A self-test failure line's number for `e`: Linux's errno
fn err_code(e: UsbError) -> u64 {
    match e {
        UsbError::InProgress => 115,
        UsbError::Timeout => 110,
        UsbError::Killed => 2,
        UsbError::Unlinked => 104,
        UsbError::Shutdown => 108,
        UsbError::Stall => 32,
        UsbError::Overflow => 75,
        UsbError::BufferError => 63,
        UsbError::BusError => 71,
        UsbError::NoDevice => 19,
        UsbError::NoResources => 12,
        UsbError::InvalidParam => 22,
        UsbError::Busy => 16,
        UsbError::Idle => 43,
        UsbError::Rejected => 1,
        UsbError::TransferError(cc) => 0x100 | u64::from(cc),
    }
}

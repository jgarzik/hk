//! xHCI rings, commands and events (Linux drivers/usb/host/xhci-ring.c)
//!
//! Everything here runs under `Xhci.lock` (an `XhciState` borrow),
//! from URB submission, command queueing and the interrupt handler,
//! which consumes the event ring: transfer events finish TDs and give
//! their URBs back (`usb_hcd_giveback_urb`, to the bottom half),
//! command completion events complete the waiting commands. A halted
//! endpoint is reset and moved past the failed TD with commands queued
//! from the handler itself (Linux xhci_handle_halted_endpoint), whose
//! memory it allocates GFP_ATOMIC, as Linux.

use alloc::sync::Arc;

use super::context::ep_ctx_state;
use super::transfer::{CompletionCode as Cc, Trb, TrbType, bulk_trbs, td_remainder};
use super::urb::{Urb, usb_hcd_giveback_urb};
use super::xhci::{
    CmdRingState, Td, TdCancel, VirtEp, Xhci, XhciCommand, XhciState, ep_state, ir, op, slot_trb,
    trb_type, usbsts, xhc_state, xhci_trace,
};
use super::{EndpointType, UsbError};
use crate::irq::{IrqHandler, IrqReturn};
use crate::printkln;
use crate::sync::IrqSpinlockGuard;
use crate::task::percpu::ms_to_ticks;
use crate::task::workqueue::SYSTEM_WQ;
use crate::time::delay::poll_timeout;
use crate::util::kalloc::try_arc_gfp;

/// Command completion (Linux XHCI_CMD_DEFAULT_TIMEOUT, ms)
const XHCI_CMD_DEFAULT_TIMEOUT_MS: u64 = 5000;
/// CRCR: command abort, command ring running
const CMD_RING_ABORT: u64 = 1 << 2;
const CMD_RING_RUNNING: u32 = 1 << 3;

/// The interrupt handler (Linux xhci_irq, under the line's lock)
impl IrqHandler for Xhci {
    fn handle(&self, _irq: u32) -> IrqReturn {
        self.xhci_irq()
    }
}

/// An endpoint's DCI for `urb` (control: EP0, DCI 1)
fn urb_dci(urb: &Urb) -> u8 {
    let p = urb.pipe();
    match p.ty {
        EndpointType::Control => 1,
        _ => super::context::endpoint_to_dci(p.ep),
    }
}

/// The status a transfer event's completion code gives its TD (Linux
/// handle_tx_event); None for codes it ignores
fn tx_status(cc: u8) -> Option<Result<(), UsbError>> {
    Some(match cc {
        Cc::SUCCESS
        | Cc::SHORT_PACKET
        | Cc::STOPPED
        | Cc::STOPPED_LENGTH_INVALID
        | Cc::STOPPED_SHORT_PACKET => Ok(()),
        Cc::STALL_ERROR => Err(UsbError::Stall),
        Cc::USB_TRANSACTION_ERROR | Cc::TRB_ERROR | Cc::INCOMPATIBLE_DEVICE => {
            Err(UsbError::BusError)
        }
        Cc::BABBLE_DETECTED => Err(UsbError::Overflow),
        Cc::DATA_BUFFER_ERROR => Err(UsbError::BufferError),
        _ => return None,
    })
}

/// Whether the controller halted the endpoint (Linux
/// xhci_halted_host_endpoint): a stall always; transaction and babble
/// errors when the endpoint context says halted
fn halted_host_endpoint(ctx_state: u8, cc: u8) -> bool {
    cc == Cc::STALL_ERROR
        || (matches!(cc, Cc::USB_TRANSACTION_ERROR | Cc::BABBLE_DETECTED)
            && ctx_state == ep_ctx_state::HALTED)
}

/// A stopped completion code: the Stop Endpoint completion handles
/// the TD (Linux finish_td)
fn is_stopped(cc: u8) -> bool {
    matches!(
        cc,
        Cc::STOPPED | Cc::STOPPED_LENGTH_INVALID | Cc::STOPPED_SHORT_PACKET
    )
}

/// Give `td`'s URB back (Linux xhci_td_cleanup,
/// xhci_giveback_urb_in_irq)
fn td_cleanup(td: Td) {
    xhci_trace!(
        URB_GIVEBACK,
        "slot={} ep={:#04x} len={} status={:?}",
        td.urb.slot_id(),
        td.urb.pipe().ep,
        td.urb.actual_length(),
        td.status
    );
    usb_hcd_giveback_urb(td.urb, td.status);
}

/// Give back every TD of `ep` with `status` (Linux
/// xhci_kill_endpoint_urbs, xhci_kill_ring_urbs): the controller is
/// gone or the slot disabled
pub(super) fn kill_ep_tds(ep: &mut VirtEp, status: Result<(), UsbError>) {
    while let Some(mut td) = ep.tds.pop_front() {
        td.status = status;
        td_cleanup(td);
    }
    ep.ep_state = 0;
    ep.queued_deq = None;
}

impl Xhci {
    /// Linux xhci_irq: the controller's status checked, the interrupt
    /// acknowledged and the event ring consumed
    fn xhci_irq(&self) -> IrqReturn {
        let mut st = self.lock.lock();
        let status = self.read_op(op::USBSTS);
        if status == !0 {
            self.hc_died(&mut st);
            return IrqReturn::Handled;
        }
        if status & usbsts::EINT == 0 {
            return IrqReturn::None;
        }
        if status & (usbsts::HCE | usbsts::HSE) != 0 {
            printkln!("xHCI: WARNING: Host Controller Error, status {:#x}", status);
            let _ = self.halt();
            st.xhc_state |= xhc_state::HALTED;
            st.cmd_ring_state = CmdRingState::Stopped;
            return IrqReturn::Handled;
        }
        // USBSTS first, so a new event raises a new interrupt
        self.write_op(op::USBSTS, usbsts::EINT);
        self.handle_events(&mut st);
        IrqReturn::Handled
    }

    /// Process the events the controller handed over (Linux
    /// xhci_handle_events): interrupt pending cleared, every event
    /// handled, the dequeue pointer written back with Event Handler
    /// Busy cleared
    fn handle_events(&self, st: &mut XhciState) {
        let iman = self.regs.rt.read32(ir::IMAN);
        self.regs.rt.write32(ir::IMAN, iman | ir::IMAN_IP);
        if st.xhc_state & (xhc_state::DYING | xhc_state::HALTED) != 0 {
            let erdp = self.regs.rt.read64(ir::ERDP);
            self.regs.rt.write64(ir::ERDP, erdp | ir::ERDP_EHB);
            return;
        }
        let mut n = 0;
        while let Some(ev) = st.event_ring.dequeue() {
            self.handle_event_trb(st, &ev);
            // Half a segment handled: let the controller reuse it
            n += 1;
            if n > 32 {
                self.regs.rt.write64(ir::ERDP, st.event_ring.dequeue_phys());
                n = 0;
            }
        }
        self.regs
            .rt
            .write64(ir::ERDP, st.event_ring.dequeue_phys() | ir::ERDP_EHB);
    }

    /// One event (Linux xhci_handle_event_trb)
    fn handle_event_trb(&self, st: &mut XhciState, ev: &Trb) {
        let ty = ev.get_type();
        xhci_trace!(
            HANDLE_EVENT,
            "type={} ctrl=0x{:08x} status=0x{:08x}",
            ty,
            ev.control,
            ev.status
        );
        match ty {
            trb_type::TRANSFER_EVENT => self.handle_tx_event(st, ev),
            trb_type::COMMAND_COMPLETION => self.handle_cmd_completion(st, ev),
            // No hub driver yet (BUGS.md): connect changes are ignored
            trb_type::PORT_STATUS_CHANGE => {}
            _ => {}
        }
    }

    // ------------------------------------------------------------------
    // Commands
    // ------------------------------------------------------------------

    /// Queue `cmd` on the command ring and ring the host doorbell
    /// (Linux queue_command + xhci_ring_cmd_db); the first outstanding
    /// command starts the timer
    pub(super) fn queue_command(
        &self,
        st: &mut XhciState,
        cmd: Arc<XhciCommand>,
    ) -> Result<(), UsbError> {
        if st.xhc_state & (xhc_state::DYING | xhc_state::HALTED) != 0 {
            return Err(UsbError::Shutdown);
        }
        if !st.cmd_ring.has_room() || st.cmd_list.len() >= st.cmd_list.capacity() {
            return Err(UsbError::NoResources);
        }
        let dma = st.cmd_ring.enqueue(cmd.trb);
        cmd.trb_dma
            .store(dma, core::sync::atomic::Ordering::Release);
        let first = st.cmd_list.is_empty();
        st.cmd_list.push_back(cmd);
        if first {
            self.mod_cmd_timer(st);
        }
        self.ring_cmd_db(st);
        Ok(())
    }

    /// The host doorbell, unless the command ring is stopped or being
    /// aborted (Linux xhci_ring_cmd_db)
    fn ring_cmd_db(&self, st: &XhciState) {
        if st.cmd_ring_state == CmdRingState::Running {
            self.ring_doorbell(0, 0);
        }
    }

    /// Time the oldest command out in XHCI_CMD_DEFAULT_TIMEOUT (Linux
    /// xhci_mod_cmd_timer)
    fn mod_cmd_timer(&self, st: &XhciState) {
        let Some(c) = st.cmd_list.front() else {
            return;
        };
        let deadline = crate::time::monotonic_ns() + XHCI_CMD_DEFAULT_TIMEOUT_MS * 1_000_000;
        c.deadline
            .store(deadline, core::sync::atomic::Ordering::Release);
        if let Some(t) = self.cmd_timer.get() {
            SYSTEM_WQ.mod_delayed_work(t, ms_to_ticks(XHCI_CMD_DEFAULT_TIMEOUT_MS));
        }
    }

    /// A command finished: its waiter woken, or it is freed (Linux
    /// xhci_complete_del_and_free_cmd)
    fn complete_cmd(cmd: Arc<XhciCommand>, cc: u8) {
        cmd.status.store(cc, core::sync::atomic::Ordering::Release);
        if let Some(c) = &cmd.completion {
            c.complete();
        }
    }

    /// Complete every outstanding command as aborted (Linux
    /// xhci_cleanup_command_queue)
    fn cleanup_command_queue(st: &mut XhciState) {
        while let Some(c) = st.cmd_list.pop_front() {
            Self::complete_cmd(c, Cc::COMMAND_ABORTED);
        }
    }

    /// A command completion event (Linux handle_cmd_completion): it
    /// must be for the oldest outstanding command, matched by its TRB's
    /// address
    fn handle_cmd_completion(&self, st: &mut XhciState, ev: &Trb) {
        use core::sync::atomic::Ordering::Acquire;
        let slot_id = (ev.control >> 24) as u8;
        let mut cc = (ev.status >> 24) as u8;
        let cmd_dma = ev.parameter;
        // After an abort: the ring stopped, its TRBs are ours again
        if cc == Cc::COMMAND_RING_STOPPED {
            self.cmd_ring_stop.complete_all();
            return;
        }
        let (cmd_trb, deq_dma) = st.cmd_ring.dequeue_trb();
        if st.cmd_ring.is_empty() || cmd_dma != deq_dma {
            printkln!("xHCI: ERROR mismatched command completion event");
            return;
        }
        let Some(cmd) = st.cmd_list.front().cloned() else {
            return;
        };
        if cmd.trb_dma.load(Acquire) != cmd_dma {
            printkln!("xHCI: Command completion event does not match command");
            return;
        }
        if let Some(t) = self.cmd_timer.get() {
            SYSTEM_WQ.cancel_delayed_work(t);
        }
        let marked = cmd.status.load(Acquire) == Cc::COMMAND_ABORTED;
        if cc == Cc::COMMAND_ABORTED {
            st.cmd_ring_state = CmdRingState::Stopped;
        }
        if !(cc == Cc::COMMAND_ABORTED && marked) {
            match cmd_trb.get_type() {
                trb_type::ENABLE_SLOT => {
                    let s = if cc == Cc::SUCCESS { slot_id } else { 0 };
                    cmd.slot_id.store(s, core::sync::atomic::Ordering::Release);
                }
                trb_type::RESET_ENDPOINT => self.handle_cmd_reset_ep(st, &cmd_trb),
                trb_type::SET_TR_DEQUEUE => self.handle_cmd_set_deq(st, &cmd_trb, cc),
                trb_type::STOP_ENDPOINT if cmd.completion.is_none() => {
                    self.handle_cmd_stop_ep(st, &cmd_trb, cc)
                }
                // An aborted command turned No-op
                trb_type::CMD_NOOP if cmd.status.load(Acquire) == Cc::COMMAND_RING_STOPPED => {
                    cc = Cc::COMMAND_RING_STOPPED;
                }
                _ => {}
            }
        }
        st.cmd_list.pop_front();
        self.mod_cmd_timer(st);
        Self::complete_cmd(cmd, cc);
        st.cmd_ring.inc_deq();
    }

    /// The command timer fired (Linux xhci_handle_command_timeout):
    /// abort the command ring so the controller lets go of the command
    /// it sits on; thread context (the system workqueue)
    pub(super) fn handle_command_timeout(&self) {
        use core::sync::atomic::Ordering::{Acquire, Release};
        let mut st = self.lock.lock();
        let Some(cur) = st.cmd_list.front().cloned() else {
            return;
        };
        // Raced with its completion, or re-timed for a later command
        if crate::time::monotonic_ns() < cur.deadline.load(Acquire) {
            return;
        }
        if cur.ty() == trb_type::STOP_ENDPOINT {
            printkln!("xHCI: host not responding to stop endpoint command");
            let (slot, dci) = (
                (cur.trb.control >> 24) as u8,
                ((cur.trb.control >> 16) & 0x1f) as u8,
            );
            if let Some(ep) = st.ep(slot, dci) {
                ep.ep_state &= !ep_state::EP_STOP_CMD_PENDING;
            }
            let _ = self.halt();
            st.xhc_state |= xhc_state::HALTED;
            self.hc_died(&mut st);
            return;
        }
        cur.status.store(Cc::COMMAND_ABORTED, Release);
        let crcr = self.regs.op.read64(op::CRCR);
        if crcr == !0 {
            self.hc_died(&mut st);
            return;
        }
        if st.cmd_ring_state == CmdRingState::Running && crcr as u32 & CMD_RING_RUNNING != 0 {
            printkln!("xHCI: command timeout, aborting the command ring");
            st.cmd_ring_state = CmdRingState::Aborted;
            self.abort_cmd_ring(st);
            return;
        }
        if st.xhc_state & xhc_state::REMOVING != 0 {
            Self::cleanup_command_queue(&mut st);
            return;
        }
        self.handle_stopped_cmd_ring(&mut st);
    }

    /// Abort the command ring and wait for it to stop, the lock
    /// released meanwhile (Linux xhci_abort_cmd_ring): CRR must clear
    /// within 5 s, or the controller is dead
    fn abort_cmd_ring(&self, st: IrqSpinlockGuard<'_, XhciState>) {
        self.cmd_ring_stop.reinit();
        // All 64 bits, the high half pointing at the next command, as
        // some controllers want
        let crcr = st.cmd_ring.next_dma() | CMD_RING_ABORT;
        self.regs.op.write64(op::CRCR, crcr);
        drop(st);
        let stopped = poll_timeout(5_000_000, 100, || {
            self.read_op(op::CRCR) & CMD_RING_RUNNING == 0
        })
        .is_ok();
        // Some controllers clear CRR and never send the stop event
        let completed = stopped && self.cmd_ring_stop.wait_timeout(ms_to_ticks(2000));
        let mut st = self.lock.lock();
        if !stopped {
            printkln!("xHCI: Abort failed to stop command ring");
            let _ = self.halt();
            st.xhc_state |= xhc_state::HALTED;
            self.hc_died(&mut st);
        } else if !completed {
            Self::cleanup_command_queue(&mut st);
        } else {
            self.handle_stopped_cmd_ring(&mut st);
        }
    }

    /// The command ring stopped: aborted commands become No-ops (their
    /// waiters complete with their events), the ring restarts (Linux
    /// xhci_handle_stopped_cmd_ring)
    fn handle_stopped_cmd_ring(&self, st: &mut XhciState) {
        use core::sync::atomic::Ordering::{Acquire, Release};
        let XhciState {
            cmd_list, cmd_ring, ..
        } = st;
        for c in cmd_list.iter() {
            if c.status.load(Acquire) == Cc::COMMAND_ABORTED {
                c.status.store(Cc::COMMAND_RING_STOPPED, Release);
                cmd_ring.noop_at(c.trb_dma.load(Acquire));
            }
        }
        st.cmd_ring_state = CmdRingState::Running;
        if !st.cmd_ring.is_empty() && st.xhc_state & xhc_state::DYING == 0 {
            self.mod_cmd_timer(st);
            self.ring_cmd_db(st);
        }
    }

    /// The controller is dead or gone (Linux xhci_hc_died): every
    /// command completes aborted, every TD is given back (Shutdown)
    pub(super) fn hc_died(&self, st: &mut XhciState) {
        if st.xhc_state & xhc_state::DYING != 0 {
            return;
        }
        st.xhc_state |= xhc_state::DYING;
        Self::cleanup_command_queue(st);
        for dev in st.devs.iter_mut().flatten() {
            for ep in dev.eps.iter_mut() {
                kill_ep_tds(ep, Err(UsbError::Shutdown));
            }
        }
    }

    // ------------------------------------------------------------------
    // Transfers
    // ------------------------------------------------------------------

    /// Queue `urb`'s TD on its endpoint ring and ring the endpoint's
    /// doorbell (Linux xhci_urb_enqueue, xhci_queue_ctrl_tx,
    /// xhci_queue_bulk_tx)
    pub(super) fn xhci_urb_enqueue(&self, urb: &Arc<Urb>) -> Result<(), UsbError> {
        let (slot, dci, pipe) = (urb.slot_id(), urb_dci(urb), urb.pipe());
        let len = urb.len();
        xhci_trace!(
            URB_ENQUEUE,
            "slot={} ep={:#04x} dci={} len={}",
            slot,
            pipe.ep,
            dci,
            len
        );
        let maxp = self
            .lock
            .lock()
            .ep(slot, dci)
            .filter(|e| e.ring.is_some())
            .ok_or(UsbError::NoDevice)?
            .maxp;
        // Built with no lock held (it allocates)
        let trbs = match (pipe.ty, urb.setup()) {
            (EndpointType::Control, Some(setup)) => self.ctrl_trbs(urb, setup, len, maxp),
            (EndpointType::Bulk | EndpointType::Interrupt, None) => {
                bulk_trbs(urb.dma_addr(), len, pipe.is_in(), maxp, self.hci_version)
            }
            _ => return Err(UsbError::InvalidParam),
        }
        .ok_or(UsbError::NoResources)?;
        let mut st = self.lock.lock();
        if st.xhc_state & (xhc_state::DYING | xhc_state::HALTED) != 0 {
            return Err(UsbError::Shutdown);
        }
        let ep = st.ep(slot, dci).ok_or(UsbError::NoDevice)?;
        let ring = ep.ring.as_mut().ok_or(UsbError::NoDevice)?;
        // One segment, never expanded (BUGS.md)
        if ring.free_trbs() < trbs.len() || ep.tds.len() >= ep.tds.capacity() {
            return Err(UsbError::NoResources);
        }
        let span = ring.enqueue_td(&trbs);
        xhci_trace!(
            QUEUE_TRB,
            "slot={} dci={} trb@{:#x} n={}",
            slot,
            dci,
            ring.dma_of(span.start),
            span.n
        );
        ep.tds.push_back(Td {
            urb: urb.clone(),
            span,
            cancel: TdCancel::None,
            status: Ok(()),
            urb_length_set: false,
        });
        let ep_state = ep.ep_state;
        self.ring_ep_doorbell(ep_state, slot, dci);
        Ok(())
    }

    /// A control TD: Setup, optional Data and Status stages (Linux
    /// xhci_queue_ctrl_tx)
    fn ctrl_trbs(
        &self,
        urb: &Urb,
        setup: &super::SetupPacket,
        len: usize,
        maxp: u16,
    ) -> Option<alloc::vec::Vec<Trb>> {
        let is_in = setup.is_in();
        // Transfer type (TRT) from xHCI 1.0 on: 3 IN data, 2 OUT, 0 none
        let trt = match (self.hci_version >= 0x100, len > 0, is_in) {
            (true, true, true) => 3,
            (true, true, false) => 2,
            _ => 0,
        };
        let mut trbs = alloc::vec::Vec::new();
        trbs.try_reserve_exact(3).ok()?;
        trbs.push(Trb::setup_stage(&setup.bytes(), trt));
        if len > 0 {
            let mut d = Trb::data_stage(urb.dma_addr(), len as u32, is_in);
            d.set_td_size(td_remainder(self.hci_version, 0, len, len, maxp, true));
            trbs.push(d);
        }
        // Status in the opposite direction of the data, IN without any
        trbs.push(Trb::status_stage(!(len > 0 && is_in)));
        Some(trbs)
    }

    /// Ring endpoint `dci`'s doorbell unless a command for it is
    /// pending or it is halted (Linux xhci_ring_ep_doorbell)
    fn ring_ep_doorbell(&self, ep_state: u32, slot: u8, dci: u8) {
        let busy = ep_state::EP_STOP_CMD_PENDING | ep_state::SET_DEQ_PENDING | ep_state::EP_HALTED;
        if ep_state & busy == 0 {
            self.ring_doorbell(slot, dci);
        }
    }

    /// Restart endpoint `dci` if it has TDs (Linux
    /// xhci_ring_doorbell_for_active_rings)
    fn ring_doorbell_for_active_rings(&self, st: &mut XhciState, slot: u8, dci: u8) {
        if let Some(ep) = st.ep(slot, dci)
            && ep.ring.is_some()
            && !ep.tds.is_empty()
        {
            let s = ep.ep_state;
            self.ring_ep_doorbell(s, slot, dci);
        }
    }

    /// Cancel `urb` (Linux xhci_urb_dequeue): its TD is marked
    /// cancelled and the endpoint stopped with a Stop Endpoint command,
    /// whose completion takes the TD off the ring and gives the URB
    /// back. Idle if the URB is not queued here, Busy if being unlinked
    /// already
    pub(super) fn xhci_urb_dequeue(
        &self,
        urb: &Arc<Urb>,
        status: UsbError,
    ) -> Result<(), UsbError> {
        let (slot, dci) = (urb.slot_id(), urb_dci(urb));
        let mut st = self.lock.lock();
        let dying = st.xhc_state & (xhc_state::DYING | xhc_state::HALTED) != 0;
        let ep = st.ep(slot, dci).ok_or(UsbError::Idle)?;
        // Linux usb_hcd_check_unlink_urb: queued, not unlinked yet
        let ti = ep
            .tds
            .iter()
            .position(|t| Arc::ptr_eq(&t.urb, urb))
            .ok_or(UsbError::Idle)?;
        urb.mark_unlinked(status)?;
        if let Some(r) = ep.ring.as_ref() {
            xhci_trace!(
                DBG_CANCEL_URB,
                "Cancel URB slot {} ep {:#04x} at {:#x}",
                slot,
                urb.pipe().ep,
                r.dma_of(ep.tds[ti].span.start)
            );
        }
        if dying {
            // Linux: "HC halted, freeing TD manually"
            if let Some(td) = ep.tds.remove(ti) {
                td_cleanup(td);
            }
            return Ok(());
        }
        // A TD the endpoint halted on is being cancelled already
        if ep.tds[ti].cancel == TdCancel::None {
            ep.tds[ti].cancel = TdCancel::Dirty;
        }
        // Their completions sort the cancelled TDs out
        let busy = ep_state::EP_STOP_CMD_PENDING | ep_state::EP_HALTED | ep_state::SET_DEQ_PENDING;
        if ep.ep_state & busy != 0 {
            return Ok(());
        }
        self.queue_stop_endpoint(&mut st, slot, dci)
    }

    /// Queue a Stop Endpoint nobody waits for (Linux
    /// xhci_queue_stop_endpoint from xhci_urb_dequeue)
    fn queue_stop_endpoint(&self, st: &mut XhciState, slot: u8, dci: u8) -> Result<(), UsbError> {
        let trb = slot_trb(trb_type::STOP_ENDPOINT, slot, dci, 0);
        let cmd = try_arc_gfp(
            XhciCommand::new_nowait(trb),
            crate::mm::page_alloc::Gfp::ATOMIC,
        )
        .map_err(|_| UsbError::NoResources)?;
        self.queue_command(st, cmd)?;
        if let Some(ep) = st.ep(slot, dci) {
            ep.ep_state |= ep_state::EP_STOP_CMD_PENDING;
            ep.stop_time = crate::time::monotonic_ns();
        }
        Ok(())
    }

    /// Stop Endpoint completed (Linux xhci_handle_cmd_stop_ep): the
    /// cancelled TDs are taken off the stopped ring (No-ops, and a Set
    /// TR Dequeue Pointer past one the endpoint sat on), those clear of
    /// it given back, the endpoint restarted for what remains. A stop
    /// that raced with a halt resets the endpoint; one that raced with
    /// a restart is queued again
    fn handle_cmd_stop_ep(&self, st: &mut XhciState, trb: &Trb, cc: u8) {
        let (slot, dci) = (
            (trb.control >> 24) as u8,
            ((trb.control >> 16) & 0x1f) as u8,
        );
        let ctx_size = self.ctx_size;
        let Some(dev) = st.dev(slot) else {
            return;
        };
        let ctx_state = dev.out_ctx.ep_state(ctx_size, dci);
        let hw = dev.out_ctx.ep_deq(ctx_size, dci) & !0xf;
        let Some(ep) = usize::from(dci)
            .checked_sub(1)
            .and_then(|i| dev.eps.get_mut(i))
        else {
            return;
        };
        if cc == Cc::CONTEXT_STATE_ERROR {
            match ctx_state {
                ep_ctx_state::HALTED => {
                    // The halt's transfer event queued the reset, or
                    // this does: the TD it halted on fails (Linux -EPROTO)
                    if ep.ep_state & ep_state::EP_HALTED == 0 {
                        let ti = ep.ring.as_ref().and_then(|r| {
                            let h = r.index_of(hw)?;
                            let first = ep.tds.iter().position(Td::on_ring)?;
                            r.td_contains(ep.tds[first].span, h).then_some(first)
                        });
                        if let Some(i) = ti {
                            ep.tds[i].status = Err(UsbError::BusError);
                        }
                        self.handle_halted_endpoint(st, slot, dci, ti);
                    }
                    if let Some(ep) = st.ep(slot, dci) {
                        ep.ep_state &= !ep_state::EP_STOP_CMD_PENDING;
                    }
                    return;
                }
                // Stopped by now: unless a halt's reset is behind it,
                // some controllers report Stopped a while after a
                // doorbell; retry for up to 100 ms
                ep_ctx_state::STOPPED
                    if ep.ep_state & ep_state::EP_HALTED == 0
                        && crate::time::monotonic_ns() < ep.stop_time + 100_000_000 =>
                {
                    self.requeue_stop_endpoint(st, slot, dci);
                    return;
                }
                // Not stopped yet: the doorbell restarted it after the stop
                ep_ctx_state::RUNNING => {
                    self.requeue_stop_endpoint(st, slot, dci);
                    return;
                }
                _ => {}
            }
        }
        self.invalidate_cancelled_tds(st, slot, dci);
        if let Some(ep) = st.ep(slot, dci) {
            ep.ep_state &= !ep_state::EP_STOP_CMD_PENDING;
        }
        self.giveback_invalidated_tds(st, slot, dci);
        self.ring_doorbell_for_active_rings(st, slot, dci);
    }

    /// Queue the Stop Endpoint again; without memory, give up on it
    fn requeue_stop_endpoint(&self, st: &mut XhciState, slot: u8, dci: u8) {
        let trb = slot_trb(trb_type::STOP_ENDPOINT, slot, dci, 0);
        let queued = try_arc_gfp(
            XhciCommand::new_nowait(trb),
            crate::mm::page_alloc::Gfp::ATOMIC,
        )
        .map_err(|_| UsbError::NoResources)
        .and_then(|cmd| self.queue_command(st, cmd));
        if queued.is_err()
            && let Some(ep) = st.ep(slot, dci)
        {
            ep.ep_state &= !ep_state::EP_STOP_CMD_PENDING;
        }
    }

    /// A transfer event (Linux handle_tx_event): the TD whose TRB it
    /// names is finished, unless the endpoint stopped on it
    fn handle_tx_event(&self, st: &mut XhciState, ev: &Trb) {
        let slot = (ev.control >> 24) as u8;
        let dci = ((ev.control >> 16) & 0x1f) as u8;
        let mut cc = (ev.status >> 24) as u8;
        let remaining = (ev.status & 0xff_ffff) as usize;
        xhci_trace!(
            HANDLE_TRANSFER,
            "slot={} dci={} cc={} residue={} trb@{:#x}",
            slot,
            dci,
            cc,
            remaining,
            ev.parameter
        );
        let ctx_size = self.ctx_size;
        let Some(dev) = st.dev(slot) else {
            return;
        };
        let ctx_state = dev.out_ctx.ep_state(ctx_size, dci);
        if ctx_state == ep_ctx_state::DISABLED {
            return;
        }
        let Some(ep) = usize::from(dci)
            .checked_sub(1)
            .and_then(|i| dev.eps.get_mut(i))
        else {
            return;
        };
        let Some(ring) = ep.ring.as_ref() else {
            return;
        };
        let Some(status) = tx_status(cc) else {
            printkln!(
                "xHCI: unknown event condition {} for slot {} ep {}",
                cc,
                slot,
                dci
            );
            return;
        };
        if cc == Cc::SUCCESS && remaining != 0 {
            cc = Cc::SHORT_PACKET;
        }
        // An event naming no transfer TRB of the ring (xHCI 4.17.4)
        let Some(idx) = ring.index_of(ev.parameter) else {
            if halted_host_endpoint(ctx_state, cc) {
                self.handle_halted_endpoint(st, slot, dci, None);
            }
            return;
        };
        let found = ep
            .tds
            .iter()
            .position(|t| t.on_ring() && ring.td_contains(t.span, idx));
        let noop = ring.trb(idx).get_type() == TrbType::NO_OP;
        let Some(ti) = found else {
            // A Force Stopped event names the TRB before the TD the
            // endpoint stopped at; the Stop Endpoint completion handles it
            if !is_stopped(cc) && halted_host_endpoint(ctx_state, cc) {
                self.handle_halted_endpoint(st, slot, dci, None);
            } else if !is_stopped(cc) && ep.tds.iter().any(Td::on_ring) {
                printkln!(
                    "xHCI: event trb@{:#x} for slot {} ep {} not part of a TD",
                    ev.parameter,
                    slot,
                    dci
                );
            }
            return;
        };
        if noop {
            if halted_host_endpoint(ctx_state, cc) {
                self.handle_halted_endpoint(st, slot, dci, Some(ti));
            }
            return;
        }
        ep.tds[ti].status = status;
        let event = TxEvent {
            idx,
            cc,
            remaining,
            ctx_state,
        };
        let finish = if ep.tds[ti].urb.pipe().ty == EndpointType::Control {
            process_ctrl_td(ep, ti, &event)
        } else {
            process_bulk_intr_td(ep, ti, &event)
        };
        if finish {
            self.finish_td(st, slot, dci, ti, &event);
        }
    }

    /// The TD is done, unless stopped (the Stop Endpoint completion
    /// sees to it) or its endpoint halted (reset, then moved past it):
    /// given back and the ring's dequeue moved past it (Linux
    /// finish_td)
    fn finish_td(&self, st: &mut XhciState, slot: u8, dci: u8, ti: usize, ev: &TxEvent) {
        if is_stopped(ev.cc) {
            return;
        }
        if halted_host_endpoint(ev.ctx_state, ev.cc) {
            self.handle_halted_endpoint(st, slot, dci, Some(ti));
            return;
        }
        let Some(ep) = st.ep(slot, dci) else {
            return;
        };
        let Some(td) = ep.tds.remove(ti) else {
            return;
        };
        if let Some(r) = ep.ring.as_mut() {
            r.dequeue_past(td.span);
        }
        td_cleanup(td);
    }

    /// The endpoint halted: the TD it halted on is marked so, and a
    /// Reset Endpoint queued, whose completion moves the dequeue past
    /// it (Linux xhci_handle_halted_endpoint, EP_HARD_RESET)
    fn handle_halted_endpoint(&self, st: &mut XhciState, slot: u8, dci: u8, ti: Option<usize>) {
        let Some(ep) = st.ep(slot, dci) else {
            return;
        };
        if let Some(td) = ti.and_then(|i| ep.tds.get_mut(i))
            && td.cancel == TdCancel::None
        {
            td.cancel = TdCancel::Halted;
        }
        if ep.ep_state & ep_state::EP_HALTED != 0 {
            return;
        }
        let trb = slot_trb(trb_type::RESET_ENDPOINT, slot, dci, 0);
        let Ok(cmd) = try_arc_gfp(
            XhciCommand::new_nowait(trb),
            crate::mm::page_alloc::Gfp::ATOMIC,
        ) else {
            printkln!(
                "xHCI: ERROR queuing reset endpoint for slot {} ep {}",
                slot,
                dci
            );
            return;
        };
        if self.queue_command(st, cmd).is_ok()
            && let Some(ep) = st.ep(slot, dci)
        {
            ep.ep_state |= ep_state::EP_HALTED;
        }
    }

    /// Reset Endpoint completed (Linux xhci_handle_cmd_reset_ep): the
    /// cancelled and halted TDs are invalidated (a Set TR Dequeue
    /// Pointer queued for one the endpoint sits on) and those already
    /// clear given back
    fn handle_cmd_reset_ep(&self, st: &mut XhciState, trb: &Trb) {
        let (slot, dci) = (
            (trb.control >> 24) as u8,
            ((trb.control >> 16) & 0x1f) as u8,
        );
        self.invalidate_cancelled_tds(st, slot, dci);
        if let Some(ep) = st.ep(slot, dci) {
            ep.ep_state &= !ep_state::EP_HALTED;
        }
        self.giveback_invalidated_tds(st, slot, dci);
    }

    /// Take the cancelled TDs of a stopped endpoint off the ring (Linux
    /// xhci_invalidate_cancelled_tds): each becomes No-ops; one the
    /// controller sits on (or halted on) also needs a Set TR Dequeue
    /// Pointer past it to clear its cache, and is given back when that
    /// completes; the others are given back now
    pub(super) fn invalidate_cancelled_tds(&self, st: &mut XhciState, slot: u8, dci: u8) {
        let ctx_size = self.ctx_size;
        let Some(dev) = st.dev(slot) else {
            return;
        };
        let hw = dev.out_ctx.ep_deq(ctx_size, dci);
        let Some(ep) = usize::from(dci)
            .checked_sub(1)
            .and_then(|i| dev.eps.get_mut(i))
        else {
            return;
        };
        if ep.ep_state & ep_state::SET_DEQ_PENDING != 0 {
            return;
        }
        let Some(ring) = ep.ring.as_mut() else {
            return;
        };
        let hw_idx = ring.index_of(hw & !0xf);
        let mut cached: Option<usize> = None;
        for i in 0..ep.tds.len() {
            let (span, cancel) = (ep.tds[i].span, ep.tds[i].cancel);
            if !matches!(cancel, TdCancel::Dirty | TdCancel::Halted) {
                continue;
            }
            xhci_trace!(
                DBG_CANCEL_URB,
                "Removing canceled TD at {:#x} (slot {} ep {})",
                ring.dma_of(span.start),
                slot,
                dci
            );
            ring.td_to_noop(span);
            if cancel == TdCancel::Halted || hw_idx.is_some_and(|h| ring.td_contains(span, h)) {
                // Should never be two: clear the earlier one anyway
                if let Some(c) = cached.replace(i) {
                    ep.tds[c].cancel = TdCancel::Cleared;
                }
                ep.tds[i].cancel = TdCancel::ClearingCache;
            } else {
                ep.tds[i].cancel = TdCancel::Cleared;
            }
        }
        let Some(c) = cached else {
            return;
        };
        if self.move_dequeue_past_td(st, slot, dci, c, hw).is_err()
            && let Some(ep) = st.ep(slot, dci)
        {
            // Not moved past: the TD is No-ops, given back anyway
            for td in ep.tds.iter_mut() {
                if td.cancel == TdCancel::ClearingCache {
                    td.cancel = TdCancel::Cleared;
                }
            }
        }
    }

    /// Queue a Set TR Dequeue Pointer past TD `ti` (Linux
    /// xhci_move_dequeue_past_td): `hw` is the controller's dequeue
    /// with its cycle state
    fn move_dequeue_past_td(
        &self,
        st: &mut XhciState,
        slot: u8,
        dci: u8,
        ti: usize,
        hw: u64,
    ) -> Result<(), UsbError> {
        let ep = st.ep(slot, dci).ok_or(UsbError::NoDevice)?;
        let ring = ep.ring.as_ref().ok_or(UsbError::NoDevice)?;
        let span = ep.tds.get(ti).ok_or(UsbError::NoDevice)?.span;
        let (to, cycle) = ring
            .deq_past_td(span, ring.index_of(hw & !0xf), hw & 1 != 0)
            .ok_or_else(|| {
                printkln!("xHCI: Error: Failed finding new dequeue state");
                UsbError::InvalidParam
            })?;
        let addr = ring.dma_of(to) | u64::from(cycle);
        let trb = slot_trb(trb_type::SET_TR_DEQUEUE, slot, dci, addr);
        let cmd = try_arc_gfp(
            XhciCommand::new_nowait(trb),
            crate::mm::page_alloc::Gfp::ATOMIC,
        )
        .map_err(|_| UsbError::NoResources)?;
        xhci_trace!(
            DBG_CANCEL_URB,
            "Set TR Deq ptr slot {} ep {} to {:#x}",
            slot,
            dci,
            addr
        );
        self.queue_command(st, cmd)?;
        let ep = st.ep(slot, dci).ok_or(UsbError::NoDevice)?;
        ep.queued_deq = Some(to);
        ep.ep_state |= ep_state::SET_DEQ_PENDING;
        Ok(())
    }

    /// Give back the cancelled TDs that are clear of the controller
    /// (Linux xhci_giveback_invalidated_tds)
    pub(super) fn giveback_invalidated_tds(&self, st: &mut XhciState, slot: u8, dci: u8) {
        let Some(ep) = st.ep(slot, dci) else {
            return;
        };
        while let Some(i) = ep.tds.iter().position(|t| t.cancel == TdCancel::Cleared) {
            if let Some(td) = ep.tds.remove(i) {
                td_cleanup(td);
            }
        }
    }

    /// Set TR Dequeue Pointer completed (Linux xhci_handle_cmd_set_deq):
    /// the ring's dequeue follows, the TDs it cleared are given back,
    /// and cancellations that came meanwhile are handled before the
    /// endpoint restarts
    fn handle_cmd_set_deq(&self, st: &mut XhciState, trb: &Trb, cc: u8) {
        let (slot, dci) = (
            (trb.control >> 24) as u8,
            ((trb.control >> 16) & 0x1f) as u8,
        );
        let ctx_size = self.ctx_size;
        let Some(dev) = st.dev(slot) else {
            return;
        };
        let deq = dev.out_ctx.ep_deq(ctx_size, dci) & !0xf;
        let Some(ep) = usize::from(dci)
            .checked_sub(1)
            .and_then(|i| dev.eps.get_mut(i))
        else {
            return;
        };
        if cc != Cc::SUCCESS {
            printkln!(
                "xHCI: WARN Set TR Deq Ptr cmd failed for slot {} ep {}: code {}",
                slot,
                dci,
                cc
            );
        } else if let (Some(ring), Some(to)) = (ep.ring.as_mut(), ep.queued_deq) {
            if ring.dma_of(to) == deq {
                ring.set_dequeue(to);
            } else {
                printkln!(
                    "xHCI: Mismatch between completed Set TR Deq Ptr command & xHCI internal state."
                );
            }
        }
        for td in ep.tds.iter_mut() {
            if td.cancel == TdCancel::ClearingCache {
                td.cancel = TdCancel::Cleared;
            }
        }
        ep.ep_state &= !ep_state::SET_DEQ_PENDING;
        ep.queued_deq = None;
        let more = ep
            .tds
            .iter()
            .any(|t| matches!(t.cancel, TdCancel::Dirty | TdCancel::Halted));
        self.giveback_invalidated_tds(st, slot, dci);
        if more {
            self.invalidate_cancelled_tds(st, slot, dci);
            self.ring_doorbell_for_active_rings(st, slot, dci);
            self.giveback_invalidated_tds(st, slot, dci);
        } else {
            self.ring_doorbell_for_active_rings(st, slot, dci);
        }
    }
}

/// What a transfer event says about its TRB
struct TxEvent {
    /// The TRB's index on the ring
    idx: usize,
    cc: u8,
    /// Bytes not transferred (EVENT_TRB_LEN)
    remaining: usize,
    /// The endpoint context's state
    ctx_state: u8,
}

/// A control TD's event (Linux process_ctrl_td): the length from the
/// data stage, the TD finished at the status stage or on an error.
/// True to finish it
fn process_ctrl_td(ep: &mut VirtEp, ti: usize, ev: &TxEvent) -> bool {
    let Some(ring) = ep.ring.as_ref() else {
        return false;
    };
    let ty = ring.trb(ev.idx).get_type();
    let td = &mut ep.tds[ti];
    let requested = td.urb.len();
    let in_data = matches!(ty, TrbType::DATA_STAGE | TrbType::NORMAL);
    match ev.cc {
        Cc::SUCCESS if ty != TrbType::STATUS_STAGE => {
            td.status = Err(UsbError::Shutdown);
            return true;
        }
        Cc::SUCCESS | Cc::SHORT_PACKET => td.status = Ok(()),
        Cc::STOPPED_SHORT_PACKET => {
            if in_data {
                td.urb.set_actual_length(ev.remaining);
            }
            return true;
        }
        Cc::STOPPED => {
            let n = match ty {
                TrbType::SETUP_STAGE => 0,
                TrbType::STATUS_STAGE => requested,
                _ => requested.saturating_sub(ev.remaining),
            };
            td.urb.set_actual_length(n);
            return true;
        }
        Cc::STOPPED_LENGTH_INVALID => return true,
        cc if cc == Cc::STALL_ERROR || halted_host_endpoint(ev.ctx_state, cc) => {
            if in_data {
                td.urb
                    .set_actual_length(requested.saturating_sub(ev.remaining));
            } else if !td.urb_length_set {
                td.urb.set_actual_length(0);
            }
            return true;
        }
        _ => {}
    }
    if ty == TrbType::SETUP_STAGE {
        return true;
    }
    if in_data {
        // The status stage's event finishes the TD
        td.urb_length_set = true;
        td.urb
            .set_actual_length(requested.saturating_sub(ev.remaining));
        return false;
    }
    if !td.urb_length_set {
        td.urb.set_actual_length(requested);
    }
    true
}

/// A bulk or interrupt TD's event (Linux process_bulk_intr_td): the
/// length moved, up to and including the event's TRB. True to finish
fn process_bulk_intr_td(ep: &mut VirtEp, ti: usize, ev: &TxEvent) -> bool {
    let Some(ring) = ep.ring.as_ref() else {
        return false;
    };
    let td = &mut ep.tds[ti];
    let requested = td.urb.len();
    let trb_len = ring.trb(ev.idx).get_transfer_length() as usize;
    let n = match ev.cc {
        Cc::STOPPED_SHORT_PACKET => ev.remaining,
        Cc::STOPPED_LENGTH_INVALID => ring.sum_trb_lengths(td.span, ev.idx),
        _ if ev.idx == ring.td_end(td.span) => requested.saturating_sub(ev.remaining),
        _ => ring.sum_trb_lengths(td.span, ev.idx) + trb_len.saturating_sub(ev.remaining),
    };
    if matches!(ev.cc, Cc::SUCCESS | Cc::SHORT_PACKET) {
        td.status = Ok(());
    }
    td.urb
        .set_actual_length(if ev.remaining > requested { 0 } else { n });
    true
}

impl XhciCommand {
    /// A command nobody waits for, freed when it completes (Linux
    /// xhci_alloc_command without a completion)
    pub(super) fn new_nowait(trb: Trb) -> Self {
        Self::new_cmd(trb, false)
    }
}

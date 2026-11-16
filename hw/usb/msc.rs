//! USB Mass Storage Class Driver
//!
//! Implements the Bulk-Only Transport (BOT) protocol for USB mass storage devices.
//! This driver implements the ScsiHost trait to integrate with the SCSI layer.

use alloc::boxed::Box;
use alloc::sync::Arc;

use crate::sync::Mutex;
use core::any::Any;
use core::mem::MaybeUninit;

use crate::block::{DataDirection, ScsiCommand, ScsiError, ScsiHost, ScsiResult, SdDisk};
use crate::printkln;
use crate::util::error::KernelError;
use crate::util::kalloc::{try_arc, try_box};

use super::message::usb_bulk_msg_len;
use super::message::usb_control_msg;
use super::{Pipe, SetupPacket, UsbDevice, UsbDeviceId, UsbError, UsbIds};
use crate::sync::completion::Completion;
use crate::task::percpu::ms_to_ticks;

/// A bulk transfer's time limit (hk has no SCSI error handler to abort
/// a stuck one, as Linux usb_stor_msg_common's callers do)
const US_BULK_TIMEOUT_MS: u64 = 5000;

/// CBW signature "USBC"
const CBW_SIGNATURE: u32 = 0x43425355;

/// CSW signature "USBS"
const CSW_SIGNATURE: u32 = 0x53425355;

/// Command Block Wrapper (CBW) - 31 bytes
/// Sent before each SCSI command in BOT protocol
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct Cbw {
    /// Signature - must be CBW_SIGNATURE
    signature: u32,
    /// Tag - echoed in CSW
    tag: u32,
    /// Data transfer length
    data_transfer_length: u32,
    /// Flags (bit 7: direction, 0=OUT, 1=IN)
    flags: u8,
    /// LUN (bits 3:0)
    lun: u8,
    /// CDB length (bits 4:0, valid 1-16)
    cb_length: u8,
    /// Command Block (CDB) - 16 bytes max
    cb: [u8; 16],
}

impl Cbw {
    const SIZE: usize = 31;

    fn new(tag: u32, data_len: u32, direction: DataDirection, lun: u8, cdb: &[u8]) -> Self {
        let flags = match direction {
            DataDirection::FromDevice => 0x80,
            DataDirection::ToDevice | DataDirection::None => 0x00,
        };

        let mut cb = [0u8; 16];
        let cdb_len = cdb.len().min(16);
        cb[..cdb_len].copy_from_slice(&cdb[..cdb_len]);

        Self {
            signature: CBW_SIGNATURE,
            tag,
            data_transfer_length: data_len,
            flags,
            lun,
            cb_length: cdb_len as u8,
            cb,
        }
    }

    fn as_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[0..4].copy_from_slice(&self.signature.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.tag.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.data_transfer_length.to_le_bytes());
        bytes[12] = self.flags;
        bytes[13] = self.lun;
        bytes[14] = self.cb_length;
        bytes[15..31].copy_from_slice(&self.cb);
        bytes
    }
}

/// Command Status Wrapper (CSW) - 13 bytes
/// Received after each SCSI command in BOT protocol
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
struct Csw {
    /// Signature - must be CSW_SIGNATURE
    signature: u32,
    /// Tag - should match CBW tag
    tag: u32,
    /// Data residue - difference between requested and actual transfer
    data_residue: u32,
    /// Status: 0=Command Passed, 1=Command Failed, 2=Phase Error
    status: u8,
}

impl Csw {
    const SIZE: usize = 13;

    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Self {
        Self {
            signature: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            tag: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            data_residue: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            status: bytes[12],
        }
    }
}

/// USB Mass Storage device state, held across each BOT transaction
/// (Linux us->dev_mutex)
struct UsbMscState {
    /// Current CBW tag (incremented for each command)
    tag: u32,
    /// The driver was unbound: no more commands (Linux
    /// US_FLIDX_DISCONNECTING)
    gone: bool,
    /// The CSW signature the device sends, learnt from its first (Linux
    /// us->bcs_signature: some send a wrong one, consistently)
    csw_sig: u32,
    /// Its residues are bogus (Linux US_FL_IGNORE_RESIDUE, learnt)
    ignore_residue: bool,
}

/// What a bulk transfer came to (Linux USB_STOR_XFER_*)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Xfer {
    /// All of it
    Good,
    /// Less than asked
    Short,
    /// The endpoint stalled; its halt is cleared
    Stalled,
    /// The device sent more than asked (babble)
    Long,
    /// Failed (and why)
    Error(UsbError),
}

/// What a command came to (Linux USB_STOR_TRANSPORT_*)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    /// Done: the bytes of data moved
    Good(usize),
    /// The device failed the command, or (`invalid_cdb`) babbled
    Failed { invalid_cdb: bool },
    /// The protocol broke down: a reset is due (Linux invoke_transport)
    Error(UsbError),
}

/// A Bulk-Only device as the protocol uses it (a trait so the
/// transport is tested against a scripted device)
trait BotIo {
    /// A bulk transfer into (`is_in`) or out of `buf`: how it ended
    /// and the bytes moved, failed or not
    fn bulk(&self, is_in: bool, buf: &mut [u8]) -> (Result<(), UsbError>, usize);
    /// Clear a halt on the bulk endpoint (Linux usb_stor_clear_halt)
    fn clear_halt(&self, is_in: bool) -> Result<(), UsbError>;
    /// The Bulk-Only Mass Storage Reset class request
    fn reset_request(&self) -> Result<(), UsbError>;
    /// Wait for the device to recover from it: false if it was
    /// disconnected meanwhile
    fn reset_wait(&self) -> bool;
}

/// A bulk transfer, its result interpreted (Linux
/// usb_stor_bulk_transfer_buf, interpret_urb_result): a stall clears
/// the halt; the bytes moved
fn xfer(io: &impl BotIo, is_in: bool, buf: &mut [u8]) -> (Xfer, usize) {
    let (r, n) = io.bulk(is_in, buf);
    let x = match r {
        Ok(()) if n == buf.len() => Xfer::Good,
        Ok(()) => Xfer::Short,
        Err(UsbError::Stall) => match io.clear_halt(is_in) {
            Ok(()) => Xfer::Stalled,
            Err(e) => Xfer::Error(e),
        },
        Err(UsbError::Overflow) => Xfer::Long,
        Err(e) => Xfer::Error(e),
    };
    (x, n)
}

/// A transfer's error for the transport: why it failed, else a
/// protocol error
fn xfer_err(x: Xfer) -> UsbError {
    match x {
        Xfer::Error(e) => e,
        _ => UsbError::BusError,
    }
}

/// One Bulk-Only command: CBW, data, CSW (Linux usb_stor_Bulk_transport).
/// A stalled data phase still reads the CSW; a zero-length CSW is read
/// again, and so is a stalled one once its halt is cleared; a device
/// that skipped the data phase is caught by its CSW in the data
fn bulk_transport(
    io: &impl BotIo,
    st: &mut UsbMscState,
    tag: u32,
    lun: u8,
    cdb: &[u8],
    dir: DataDirection,
    data: Option<&mut [u8]>,
) -> Transport {
    let len = data.as_ref().map_or(0, |d| d.len());
    let mut cbw = Cbw::new(tag, len as u32, dir, lun, cdb).as_bytes();
    let (x, _) = xfer(io, false, &mut cbw);
    if x != Xfer::Good {
        return Transport::Error(xfer_err(x));
    }
    let mut csw = [0u8; Csw::SIZE];
    let mut got = 0;
    let mut fake_sense = false;
    let mut have_csw = false;
    if let Some(buf) = data.filter(|_| len > 0) {
        let is_in = dir == DataDirection::FromDevice;
        let (x, n) = xfer(io, is_in, buf);
        got = n;
        match x {
            Xfer::Error(e) => return Transport::Error(e),
            Xfer::Long => fake_sense = true,
            // A CSW where the data should be: the data phase skipped
            Xfer::Short if is_in && n == Csw::SIZE && buf[..4] == CSW_SIGNATURE.to_le_bytes() => {
                csw.copy_from_slice(&buf[..Csw::SIZE]);
                buf[..Csw::SIZE].fill(0);
                (got, have_csw) = (0, true);
            }
            _ => {}
        }
    }
    if !have_csw {
        let (mut x, mut n) = xfer(io, true, &mut csw);
        if x == Xfer::Short && n == 0 {
            (x, n) = xfer(io, true, &mut csw);
        }
        if x == Xfer::Stalled {
            (x, n) = xfer(io, true, &mut csw);
        }
        if x != Xfer::Good || n != Csw::SIZE {
            return Transport::Error(xfer_err(x));
        }
    }
    csw_status(st, &Csw::from_bytes(&csw), tag, cdb, len, got, fake_sense)
}

/// The command's outcome from its CSW (Linux usb_stor_Bulk_transport's
/// status checks): a wrong tag, a status past Phase Error, a signature
/// other than the device's or a Phase Error break the protocol; a
/// residue shortens the data moved, unless the device's are bogus
fn csw_status(
    st: &mut UsbMscState,
    csw: &Csw,
    tag: u32,
    cdb: &[u8],
    len: usize,
    got: usize,
    fake_sense: bool,
) -> Transport {
    const STAT_OK: u8 = 0;
    const STAT_FAIL: u8 = 1;
    const STAT_PHASE: u8 = 2;
    let (sig, ctag, residue) = ({ csw.signature }, { csw.tag }, { csw.data_residue }
        as usize);
    if ctag != tag || csw.status > STAT_PHASE {
        return Transport::Error(UsbError::BusError);
    }
    if st.csw_sig == 0 {
        st.csw_sig = sig;
    } else if sig != st.csw_sig {
        return Transport::Error(UsbError::BusError);
    }
    let mut got = got;
    if residue != 0 && !st.ignore_residue {
        // INQUIRY of 36 or READ CAPACITY of 8 all moved yet a residue:
        // the device's residues mean nothing
        let probe = matches!((cdb.first(), len), (Some(0x12), 36) | (Some(0x25), 8));
        if csw.status == STAT_OK && got == len && probe {
            st.ignore_residue = true;
        } else {
            got = got.min(len - residue.min(len));
        }
    }
    match csw.status {
        STAT_OK if fake_sense => Transport::Failed { invalid_cdb: true },
        STAT_OK => Transport::Good(got),
        STAT_FAIL => Transport::Failed { invalid_cdb: false },
        _ => Transport::Error(UsbError::BusError),
    }
}

/// Bulk-Only Mass Storage Reset (Linux usb_stor_Bulk_reset,
/// usb_stor_reset_common): the class request, up to 6 s for the device
/// to recover (cut short by a disconnect), then both bulk endpoints'
/// halts cleared
fn bulk_reset(io: &impl BotIo) -> Result<(), UsbError> {
    io.reset_request()?;
    if !io.reset_wait() {
        return Err(UsbError::NoDevice);
    }
    let r_in = io.clear_halt(true);
    let r_out = io.clear_halt(false);
    r_in.and(r_out)
}

/// The SCSI result of a command (Linux usb_stor_invoke_transport): a
/// broken protocol resets the device first, unless it is going away
fn invoke_transport(io: &impl BotIo, r: Transport) -> ScsiResult<usize> {
    match r {
        Transport::Good(n) => Ok(n),
        // Linux usb_stor_sense_invalidCDB: ILLEGAL REQUEST, INVALID
        // FIELD IN CDB; a failed command's sense is not fetched
        Transport::Failed { invalid_cdb } => Err(ScsiError::CheckCondition {
            sense_key: if invalid_cdb { 0x05 } else { 0 },
            asc: if invalid_cdb { 0x24 } else { 0 },
            ascq: 0,
        }),
        Transport::Error(UsbError::NoDevice) => Err(ScsiError::NoDevice),
        Transport::Error(e) => {
            if let Err(re) = bulk_reset(io) {
                printkln!("usb-storage: reset failed: {:?}", re);
            }
            Err(match e {
                UsbError::Timeout => ScsiError::Timeout,
                _ => ScsiError::IoError,
            })
        }
    }
}

/// USB Mass Storage Device
///
/// Implements ScsiHost to allow the SCSI layer to send commands. Its
/// bulk endpoints were added to the controller when the configuration
/// was set.
pub struct UsbMscDevice {
    /// Serializes the transactions (a BOT command is CBW, data, CSW)
    state: Mutex<UsbMscState>,
    /// The USB device (Linux us->pusb_dev)
    dev: UsbDevice,
    /// Its interface (Linux us->ifnum)
    ifnum: u8,
    /// Bulk IN endpoint address
    bulk_in_ep: u8,
    /// Bulk OUT endpoint address
    bulk_out_ep: u8,
    /// Completed at disconnect: a reset's recovery wait ends (Linux
    /// us->delay_wait with US_FLIDX_DISCONNECTING)
    dying: Completion,
}

impl BotIo for UsbMscDevice {
    fn bulk(&self, is_in: bool, buf: &mut [u8]) -> (Result<(), UsbError>, usize) {
        usb_bulk_msg_len(&self.dev, self.pipe(is_in), buf, US_BULK_TIMEOUT_MS)
    }

    fn clear_halt(&self, is_in: bool) -> Result<(), UsbError> {
        // Linux usb_stor_clear_halt: 3 s
        super::message::clear_halt(&self.dev, self.pipe(is_in), 3000)
    }

    fn reset_request(&self) -> Result<(), UsbError> {
        // Linux US_BULK_RESET_REQUEST
        let setup = SetupPacket::class_intf(0xff, self.ifnum);
        usb_control_msg(&self.dev, &setup, &mut [], 5000).map(|_| ())
    }

    fn reset_wait(&self) -> bool {
        !self.dying.wait_timeout(ms_to_ticks(6000))
    }
}

impl UsbMscDevice {
    /// Its bulk IN or OUT pipe
    fn pipe(&self, is_in: bool) -> Pipe {
        if is_in {
            Pipe::bulk_in(self.bulk_in_ep)
        } else {
            Pipe::bulk_out(self.bulk_out_ep)
        }
    }

    fn new(dev: UsbDevice, ifnum: u8, bulk_in_ep: u8, bulk_out_ep: u8) -> Self {
        Self {
            state: Mutex::new(UsbMscState {
                tag: 1,
                gone: false,
                csw_sig: 0,
                ignore_residue: false,
            }),
            dev,
            ifnum,
            bulk_in_ep,
            bulk_out_ep,
            dying: Completion::new(),
        }
    }

    /// No commands from now on; a reset's recovery wait ends, then the
    /// command in progress is waited for (Linux usb_stor_disconnect's
    /// US_FLIDX_DISCONNECTING and delay_wait wakeup under dev_mutex)
    fn disconnect(&self) {
        self.dying.complete_all();
        self.state.lock().gone = true;
    }

    /// Execute a BOT transaction. Its allocations (URBs, DMA buffers,
    /// TRB lists) do no reclaim I/O (Linux usb-storage's GFP_NOIO): a
    /// swap or page-cache write to this disk from inside it would wait
    /// for the `state` lock it holds
    fn bot_transfer(
        &self,
        lun: u8,
        cdb: &[u8],
        direction: DataDirection,
        data: Option<&mut [u8]>,
    ) -> ScsiResult<usize> {
        crate::mm::memalloc_scope(crate::task::pf::MEMALLOC_NOIO, || {
            // The whole transaction under the lock: another command's
            // CBW must not come between this one's phases
            let mut st = self.state.lock();
            if st.gone {
                return Err(ScsiError::NoDevice);
            }
            let tag = st.tag;
            st.tag = st.tag.wrapping_add(1);
            let r = bulk_transport(self, &mut st, tag, lun, cdb, direction, data);
            invoke_transport(self, r)
        })
    }
}

impl ScsiHost for UsbMscDevice {
    fn execute(&self, _target: u8, lun: u8, cmd: &ScsiCommand) -> ScsiResult<usize> {
        // Prepare data buffer reference
        let data_ptr = cmd.data;
        let data_len = cmd.data_len;

        // Create a mutable slice for data transfer
        let data_buf: Option<&mut [u8]> = match cmd.direction {
            DataDirection::None => None,
            DataDirection::FromDevice | DataDirection::ToDevice => {
                if let Some(ptr) = data_ptr {
                    // SAFETY: Caller ensures pointer is valid for data_len bytes
                    Some(unsafe { core::slice::from_raw_parts_mut(ptr, data_len) })
                } else {
                    None
                }
            }
        };

        self.bot_transfer(lun, &cmd.cdb.bytes[..cmd.cdb.len], cmd.direction, data_buf)
    }

    fn name(&self) -> &str {
        "usb-msc"
    }

    fn num_targets(&self) -> u8 {
        1 // USB MSC devices typically have 1 target
    }
}

/// Interfaces it drives (Linux usb-storage's usb_storage_usb_ids):
/// SCSI transparent command set over Bulk-Only Transport; the other
/// subclasses and the CB/CBI and UAS transports are not supported
/// (BUGS.md)
static STORAGE_IDS: [UsbDeviceId; 1] = [UsbDeviceId::interface_info(
    super::class::MASS_STORAGE,
    USB_SC_SCSI,
    USB_PR_BULK,
)];

/// bInterfaceSubClass: SCSI transparent command set
const USB_SC_SCSI: u8 = 0x06;
/// bInterfaceProtocol: Bulk-Only Transport
const USB_PR_BULK: u8 = 0x50;

/// The USB mass storage driver (Linux usb-storage): its SCSI disk is
/// scanned at probe
pub static USB_STORAGE_DRIVER: crate::base::Driver = crate::base::Driver::new(
    "usb-storage",
    &super::USB_BUS,
    Some("usb_storage"),
    &UsbIds::Interface(&STORAGE_IDS),
    usb_storage_probe,
);

fn usb_storage_probe(
    dev: &Arc<crate::base::Device>,
) -> Result<Box<dyn crate::base::Bound>, KernelError> {
    let (usb_dev, intf) = super::usb_intf(dev).ok_or(KernelError::NoDevice)?;
    // The binding's memory first: nothing to undo should it fail
    let slot = try_box(MaybeUninit::<UsbStorage>::uninit())?;
    let Some((bulk_in_ep, bulk_out_ep)) = intf.bulk_eps() else {
        printkln!("usb-storage {}: no bulk endpoints", dev.name());
        return Err(KernelError::NoDevice);
    };
    printkln!(
        "usb-storage {}: slot {}, bulk in {:#04x}, out {:#04x}",
        dev.name(),
        usb_dev.slot_id,
        bulk_in_ep,
        bulk_out_ep
    );
    let msc_dev = try_arc(UsbMscDevice::new(
        usb_dev.clone(),
        intf.number,
        bulk_in_ep,
        bulk_out_ep,
    ))?;
    let disk = crate::block::create_scsi_disk(msc_dev.clone(), 0, 0).inspect_err(|e| {
        printkln!("usb-storage {}: no disk: {:?}", dev.name(), e);
    })?;
    Ok(Box::write(
        slot,
        UsbStorage {
            device: msc_dev,
            disk,
        },
    ))
}

/// A bound mass-storage interface (Linux struct us_data): its
/// transport and the disk scanned on it
struct UsbStorage {
    device: Arc<UsbMscDevice>,
    disk: SdDisk,
}

impl crate::base::Bound for UsbStorage {
    fn as_any(&self) -> &dyn Any {
        self
    }

    /// Linux usb_stor_disconnect: the disk goes (scsi_remove_host),
    /// then the transport stops, after the command in progress
    fn remove(&self) {
        self.disk.remove();
        self.device.disconnect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::VecDeque;
    use alloc::vec::Vec;
    use core::cell::RefCell;

    /// What the scripted device does on a bulk transfer: IN data (or an
    /// OUT count), or an error after moving some
    type Step = Result<Vec<u8>, (UsbError, Vec<u8>)>;

    fn err(e: UsbError) -> Step {
        Err((e, Vec::new()))
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Call {
        Bulk(bool),
        ClearHalt(bool),
        Reset,
    }

    struct Dev {
        steps: RefCell<VecDeque<Step>>,
        calls: RefCell<Vec<Call>>,
    }

    impl Dev {
        fn new(steps: Vec<Step>) -> Self {
            Self {
                steps: RefCell::new(steps.into()),
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl BotIo for Dev {
        fn bulk(&self, is_in: bool, buf: &mut [u8]) -> (Result<(), UsbError>, usize) {
            self.calls.borrow_mut().push(Call::Bulk(is_in));
            let (r, d) = match self.steps.borrow_mut().pop_front().expect("unscripted") {
                Ok(d) => (Ok(()), d),
                Err((e, d)) => (Err(e), d),
            };
            let n = d.len().min(buf.len());
            if is_in {
                buf[..n].copy_from_slice(&d[..n]);
            }
            (r, n)
        }
        fn clear_halt(&self, is_in: bool) -> Result<(), UsbError> {
            self.calls.borrow_mut().push(Call::ClearHalt(is_in));
            Ok(())
        }
        fn reset_request(&self) -> Result<(), UsbError> {
            self.calls.borrow_mut().push(Call::Reset);
            Ok(())
        }
        fn reset_wait(&self) -> bool {
            true
        }
    }

    fn csw(tag: u32, residue: u32, status: u8) -> Step {
        let mut b = Vec::new();
        b.extend_from_slice(&CSW_SIGNATURE.to_le_bytes());
        b.extend_from_slice(&tag.to_le_bytes());
        b.extend_from_slice(&residue.to_le_bytes());
        b.push(status);
        Ok(b)
    }

    fn cbw() -> Step {
        Ok(alloc::vec![0; Cbw::SIZE])
    }

    fn state() -> UsbMscState {
        UsbMscState {
            tag: 1,
            gone: false,
            csw_sig: 0,
            ignore_residue: false,
        }
    }

    /// A READ(10)-like command of `len` bytes in
    fn read(dev: &Dev, st: &mut UsbMscState, cdb0: u8, len: usize) -> Transport {
        let mut buf = alloc::vec![0u8; len];
        bulk_transport(
            dev,
            st,
            7,
            0,
            &[cdb0],
            DataDirection::FromDevice,
            Some(&mut buf),
        )
    }

    #[test]
    fn good_read() {
        let d = Dev::new(alloc::vec![cbw(), Ok(alloc::vec![1; 512]), csw(7, 0, 0)]);
        assert_eq!(read(&d, &mut state(), 0x28, 512), Transport::Good(512));
    }

    /// Linux: a stalled data phase clears the halt and reads the CSW
    #[test]
    fn data_stall_reads_csw() {
        let d = Dev::new(alloc::vec![cbw(), err(UsbError::Stall), csw(7, 512, 1)]);
        let r = read(&d, &mut state(), 0x28, 512);
        assert_eq!(r, Transport::Failed { invalid_cdb: false });
        assert_eq!(
            *d.calls.borrow(),
            [
                Call::Bulk(false),
                Call::Bulk(true),
                Call::ClearHalt(true),
                Call::Bulk(true)
            ]
        );
    }

    /// A data phase that stalls part way keeps what it moved, less the
    /// residue (Linux urb->actual_length)
    #[test]
    fn partial_stall() {
        let d = Dev::new(alloc::vec![
            cbw(),
            Err((UsbError::Stall, alloc::vec![1; 256])),
            csw(7, 256, 0)
        ]);
        assert_eq!(read(&d, &mut state(), 0x28, 512), Transport::Good(256));
    }

    /// A zero-length CSW is read again; so is a stalled one
    #[test]
    fn csw_retries() {
        let d = Dev::new(alloc::vec![
            cbw(),
            Ok(alloc::vec![0; 8]),
            Ok(Vec::new()),
            csw(7, 0, 0)
        ]);
        assert_eq!(read(&d, &mut state(), 0x28, 8), Transport::Good(8));
        let d = Dev::new(alloc::vec![
            cbw(),
            Ok(alloc::vec![0; 8]),
            err(UsbError::Stall),
            csw(7, 0, 0)
        ]);
        assert_eq!(read(&d, &mut state(), 0x28, 8), Transport::Good(8));
        assert!(d.calls.borrow().contains(&Call::ClearHalt(true)));
    }

    /// A wrong tag breaks the protocol: the device is reset, both
    /// endpoints' halts cleared
    #[test]
    fn bad_tag_resets() {
        let d = Dev::new(alloc::vec![cbw(), Ok(alloc::vec![0; 8]), csw(6, 0, 0)]);
        let r = read(&d, &mut state(), 0x28, 8);
        assert_eq!(r, Transport::Error(UsbError::BusError));
        assert!(matches!(invoke_transport(&d, r), Err(ScsiError::IoError)));
        let calls = d.calls.borrow();
        assert_eq!(
            calls[calls.len() - 3..],
            [Call::Reset, Call::ClearHalt(true), Call::ClearHalt(false)]
        );
    }

    /// A CSW where the data should be: data phase skipped, CSW used
    #[test]
    fn skipped_data_phase() {
        let d = Dev::new(alloc::vec![cbw(), csw(7, 512, 0)]);
        assert_eq!(read(&d, &mut state(), 0x28, 512), Transport::Good(0));
        assert_eq!(d.calls.borrow().len(), 2, "no CSW read after it");
    }

    /// The residue shortens the data, unless the device's are bogus
    #[test]
    fn residue() {
        let d = Dev::new(alloc::vec![cbw(), Ok(alloc::vec![0; 512]), csw(7, 100, 0)]);
        assert_eq!(read(&d, &mut state(), 0x28, 512), Transport::Good(412));
        let mut st = state();
        let d = Dev::new(alloc::vec![
            cbw(),
            Ok(alloc::vec![0; 36]),
            csw(7, 36, 0),
            cbw(),
            Ok(alloc::vec![0; 512]),
            csw(7, 100, 0),
        ]);
        assert_eq!(read(&d, &mut st, 0x12, 36), Transport::Good(36));
        assert!(st.ignore_residue);
        assert_eq!(read(&d, &mut st, 0x28, 512), Transport::Good(512));
    }

    /// Babble: Linux's fake ILLEGAL REQUEST sense
    #[test]
    fn babble_fake_sense() {
        let d = Dev::new(alloc::vec![cbw(), err(UsbError::Overflow), csw(7, 0, 0)]);
        let r = read(&d, &mut state(), 0x28, 512);
        assert_eq!(r, Transport::Failed { invalid_cdb: true });
        let e = invoke_transport(&d, r);
        assert!(matches!(
            e,
            Err(ScsiError::CheckCondition {
                sense_key: 5,
                asc: 0x24,
                ascq: 0
            })
        ));
    }

    /// The first CSW's signature is learnt; another breaks the protocol
    #[test]
    fn learnt_signature() {
        let mut st = state();
        let mut odd = csw(7, 0, 0).unwrap();
        odd[0] = b'X';
        let d = Dev::new(alloc::vec![
            cbw(),
            Ok(alloc::vec![0; 8]),
            Ok(odd),
            cbw(),
            Ok(alloc::vec![0; 8]),
            csw(7, 0, 0)
        ]);
        assert_eq!(read(&d, &mut st, 0x28, 8), Transport::Good(8));
        assert_eq!(
            read(&d, &mut st, 0x28, 8),
            Transport::Error(UsbError::BusError)
        );
    }
}

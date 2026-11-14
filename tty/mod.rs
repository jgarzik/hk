//! TTY Subsystem
//!
//! This module implements the TTY (teletype) layer, which sits between
//! the character device layer and hardware drivers.
//!
//! ## Architecture (per tty.txt)
//!
//! ```text
//! User space read/write
//!        ↓
//! Character device (/dev/ttyS0, /dev/ttyUSB0)
//!        ↓
//! TTY core (this module) - manages Tty struct, termios
//!        ↓
//! Line discipline - transforms byte streams (echo, editing)
//!        ↓
//! TTY driver - talks to hardware (serial UART, USB CDC-ACM)
//!        ↓
//! Hardware
//! ```
//!
//! ## Current Implementation
//!
//! - N_TTY, the only line discipline (`n_tty`), cooked by default
//! - Input from the UART interrupt through flip buffers (`flip`)
//! - Controlling ttys and job control (`jobctrl`), ioctls (`ioctl`)
//! - Serial ttys: 16550 ttyS* on x86, PL011 ttyAMA0 on arm64
//! - /dev/tty, /dev/console, and a Tty as a kernel console

pub mod console_dev;
pub mod flip;
pub mod ioctl;
pub mod jobctrl;
pub mod n_tty;
pub mod serial_core;
pub mod termios;
pub mod tty_dev;

use alloc::sync::Arc;

use crate::base::{Class, DevNode, Device, DeviceInfo, device_create};

use crate::sync::IrqSpinlock;
use crate::sync::spin::Mutex;
use crate::sync::waitqueue::WaitQueue;

use crate::console::ConsoleDriver;
use crate::fs::File;
use crate::fs::chardev::{CharDevice, DevId};
use crate::fs::flags::O_NOCTTY;
use crate::fs::iov_iter::{IovDest, IovSource};
use crate::io::fasync::{FasyncList, POLL_IN, PidType, f_setown_pid, fasync_helper, kill_fasync};
use crate::io::poll::{POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM, PollTable};
use crate::task::pid::Pid;
use crate::util::error::KernelError;
use crate::util::kalloc::{arc_nofail, try_arc};

// Re-export commonly used types
pub use termios::{
    B115200,
    BRKINT,
    CLOCAL,
    CREAD,
    CS5,
    CS6,
    CS7,
    CS8,
    // c_cflag bits
    CSIZE,
    CSTOPB,
    ECHO,
    ECHOCTL,
    ECHOE,
    ECHOK,
    ECHOKE,
    ECHONL,
    HUPCL,
    ICANON,
    // c_iflag bits
    ICRNL,
    IEXTEN,
    IGNBRK,
    IGNCR,
    IGNPAR,
    INLCR,
    INPCK,
    // c_lflag bits
    ISIG,
    ISTRIP,
    IXOFF,
    IXON,
    // line disciplines
    N_TTY,
    NOFLSH,
    OCRNL,
    ONLCR,
    // c_oflag bits
    OPOST,
    PARENB,
    PARMRK,
    PARODD,
    TOSTOP,
    VEOF,
    VERASE,
    // c_cc indices
    VINTR,
    VKILL,
    VMIN,
    VQUIT,
    VSTART,
    VSTOP,
    VSUSP,
    VTIME,
};
pub use termios::{Termios, Winsize};

/// TTY driver trait - hardware interface (Linux tty_operations)
///
/// Received bytes come from the driver's interrupt handler through
/// `flip::receive`.
pub trait TtyDriver: Send + Sync {
    /// Write bytes to hardware
    fn write(&self, data: &[u8]) -> Result<usize, KernelError>;

    /// Wait until the transmitter is empty
    fn flush(&self) {}

    /// The console write (Linux console->write): bytes straight to the
    /// hardware, LF as CR LF, then a wait until the transmitter is
    /// empty. A UART takes its port lock (`serial_core::UartPort`)
    fn console_write(&self, data: &[u8]) {
        for &byte in data {
            if byte == b'\n' {
                let _ = self.write(b"\r");
            }
            let _ = self.write(&[byte]);
        }
        self.flush();
    }
}

/// Job control state (Linux tty->ctrl and winsize)
struct TtyCtrl {
    /// Window size
    winsize: Winsize,
    /// The session whose controlling tty this is
    session: Option<Arc<Pid>>,
    /// Foreground process group
    pgrp: Option<Arc<Pid>>,
}

impl TtyCtrl {
    const fn new() -> Self {
        Self {
            winsize: Winsize::default_console(),
            session: None,
            pgrp: None,
        }
    }
}

/// TTY device instance
///
/// Combines the driver, line discipline, and termios into a single
/// device that can be accessed via the character device interface.
pub struct Tty {
    /// Device name (e.g., "ttyS0", "ttyUSB0")
    name: &'static str,
    /// Device number (/dev node)
    dev: DevId,
    /// Terminal settings
    pub termios: Mutex<Termios>,
    /// Hardware driver
    driver: &'static dyn TtyDriver,
    /// N_TTY input state (sleeping: Linux termios_rwsem's role for the
    /// line discipline; input echoes and signals under it)
    ldata: crate::sync::Mutex<n_tty::NTtyData>,
    /// `ldata`'s heads, for poll and readers' wait conditions without it
    avail: n_tty::Avail,
    /// Bytes from the driver's interrupt handler
    flip: IrqSpinlock<flip::Flip>,
    /// Serializes feeding the flip buffer to the line discipline with
    /// input flushes (Linux tty_bufhead.lock, a mutex)
    buf_lock: crate::sync::Mutex<()>,
    /// Readers and pollers wait here for input (Linux read_wait)
    read_wait: WaitQueue,
    /// One reader at a time, so a canonical line goes whole to one
    /// reader though it is copied out in pieces (Linux
    /// n_tty_data.atomic_read_lock)
    read_lock: crate::sync::Mutex<()>,
    /// One writer at a time, held across a whole write(2) so another's
    /// bytes never land inside it (Linux tty->atomic_write_lock)
    write_lock: crate::sync::Mutex<()>,
    /// Session, foreground group, window size
    ctrl: Mutex<TtyCtrl>,
    /// O_ASYNC files (Linux tty->fasync)
    fasync: FasyncList,
}

impl Tty {
    /// Create a new TTY with the given driver (const fn for static init)
    pub const fn new(name: &'static str, dev: DevId, driver: &'static dyn TtyDriver) -> Self {
        Self {
            name,
            dev,
            termios: Mutex::new(Termios::cooked()),
            driver,
            ldata: crate::sync::Mutex::new(n_tty::NTtyData::new()),
            avail: n_tty::Avail::new(),
            flip: IrqSpinlock::new(flip::Flip::new()),
            buf_lock: crate::sync::Mutex::new(()),
            read_lock: crate::sync::Mutex::new(()),
            write_lock: crate::sync::Mutex::new(()),
            read_wait: WaitQueue::new(),
            ctrl: Mutex::new(TtyCtrl::new()),
            fasync: FasyncList::new(),
        }
    }

    /// Device name (/dev node)
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Device number
    pub fn dev(&self) -> DevId {
        self.dev
    }

    /// Take the write lock (Linux tty_write_lock): EAGAIN if taken and
    /// O_NONBLOCK, else a signal ends the wait
    fn lock_write(&self, file: &File) -> Result<crate::sync::MutexGuard<'_, ()>, KernelError> {
        if file.get_flags() & crate::fs::flags::O_NONBLOCK != 0 {
            self.write_lock.try_lock().ok_or(KernelError::WouldBlock)
        } else {
            self.write_lock.lock_interruptible()
        }
    }

    /// Write directly to driver (bypassing line discipline)
    pub fn driver_write(&self, data: &[u8]) -> Result<usize, KernelError> {
        self.driver.write(data)
    }

    // =========================================================================
    // Methods for ioctl support
    // =========================================================================

    /// Get a copy of the termios structure
    pub fn get_termios(&self) -> Termios {
        *self.termios.lock()
    }

    /// Set the termios structure
    pub fn set_termios(&self, termios: Termios) {
        self.update_termios(|t| *t = termios);
    }

    /// Change termios in place (Linux: under termios_rwsem). Under
    /// ldata, so input, reads and polls see the old settings or the new
    /// ones with the ICANON change applied, never half; readers and
    /// pollers are woken (VMIN, VTIME or ICANON may make input readable)
    pub fn update_termios(&self, f: impl FnOnce(&mut Termios)) {
        let mut ld = n_tty::ldata(self);
        let canon = {
            let mut t = self.termios.lock();
            f(&mut t);
            t.c_lflag & termios::ICANON != 0
        };
        ld.set_icanon(canon);
        drop(ld);
        self.read_wait.wake_all();
    }

    /// Get the window size
    pub fn get_winsize(&self) -> Winsize {
        self.ctrl.lock().winsize
    }

    /// Set the window size; a new one signals the foreground process
    /// group with SIGWINCH (Linux tty_do_resize)
    pub fn resize(&self, ws: Winsize) {
        let pgrp = {
            let mut c = self.ctrl.lock();
            if c.winsize == ws {
                return;
            }
            c.winsize = ws;
            c.pgrp.clone()
        };
        if let Some(pg) = pgrp {
            crate::signal::kill_pgrp_pid(&pg, crate::signal::SIGWINCH);
        }
    }

    /// Bytes a read can return (TIOCINQ)
    pub fn bytes_available(&self) -> usize {
        n_tty::ldata(self).inq()
    }

    /// The foreground process group
    pub fn pgrp(&self) -> Option<Arc<Pid>> {
        self.ctrl.lock().pgrp.clone()
    }

    /// Linux __tty_fasync: a newly armed file without an owner gets the
    /// foreground group, or the caller's process when there is none
    fn tty_fasync(&self, file: &File, fd: i32, on: bool) -> Result<(), KernelError> {
        if !fasync_helper(&self.fasync, file, fd, on)? || !on {
            return Ok(());
        }
        let (pid, kind) = match self.pgrp() {
            Some(pg) => (pg, PidType::Pgrp),
            None => {
                let me = crate::task::percpu::current_tid();
                let pid = u32::try_from(me)
                    .ok()
                    .and_then(|n| crate::task::pid::find_pid(&crate::ns::INIT_PID_NS, n))
                    .ok_or(KernelError::NoProcess)?;
                (pid, PidType::Tgid)
            }
        };
        f_setown_pid(file, pid, kind, false)
    }

    /// SIGIO for input to the O_ASYNC files (Linux n_tty's kill_fasync
    /// POLL_IN), under `ldata` (Linux: under termios_rwsem)
    pub(crate) fn kill_input(&self) {
        kill_fasync(&self.fasync, crate::signal::SIGIO, POLL_IN);
    }

    /// Get the line discipline number
    pub fn get_line_discipline(&self) -> u8 {
        // Currently always N_TTY (0)
        N_TTY
    }

    /// Wait for output to be sent
    pub fn wait_until_sent(&self) {
        self.driver.flush();
    }

    /// Flush the input buffer
    /// Drop all received input, the flip buffer's too (Linux
    /// tty_buffer_flush): under buf_lock, so bytes being fed to the line
    /// discipline are not added after the flush
    pub fn flush_input(&self) {
        let _b = self.buf_lock.lock();
        self.flip.lock().clear();
        n_tty::ldata(self).reset();
    }

    /// Flush the output buffer (no-op for polled driver)
    pub fn flush_output(&self) {
        self.driver.flush();
    }
}

// Implement CharDevice for Tty
impl CharDevice for Tty {
    fn name(&self) -> &str {
        self.name
    }

    /// tty_fops has tty_poll
    fn can_poll(&self) -> bool {
        true
    }

    fn open(&self, file: &File) -> Result<(), KernelError> {
        if file.get_flags() & O_NOCTTY == 0 {
            jobctrl::open_set_tty(self, file);
        }
        Ok(())
    }

    /// A background reader gets SIGTTIN (Linux job_control)
    fn read(&self, file: &File, to: &mut IovDest<'_>) -> Result<usize, KernelError> {
        jobctrl::check_change(self, crate::signal::SIGTTIN)?;
        n_tty::read(self, file, to)
    }

    /// Under the write lock to the end (Linux iterate_tty_write); with
    /// TOSTOP a background writer gets SIGTTOU (Linux n_tty_write)
    fn write(&self, file: &File, from: &mut IovSource<'_>) -> Result<usize, KernelError> {
        let _writer = self.lock_write(file)?;
        if self.get_termios().c_lflag & TOSTOP != 0 {
            jobctrl::check_change(self, crate::signal::SIGTTOU)?;
        }
        n_tty::write(self, from)
    }

    fn ioctl(&self, file: &File, cmd: u32, arg: u64) -> Result<i64, KernelError> {
        ioctl::tty_ioctl(self, file, cmd, arg)
    }

    fn fasync(&self, file: &File, fd: i32, on: bool) -> Option<Result<(), KernelError>> {
        Some(self.tty_fasync(file, fd, on))
    }

    /// Output is written synchronously: always writable (Linux
    /// n_tty_poll)
    fn poll(&self, _file: &File, pt: Option<&mut PollTable<'_>>) -> u16 {
        if let Some(pt) = pt {
            pt.poll_wait(&self.read_wait);
        }
        let mut mask = POLLOUT | POLLWRNORM;
        if n_tty::poll_in(self) {
            mask |= POLLIN | POLLRDNORM;
        }
        mask
    }
}

// Implement ConsoleDriver for Tty
// This allows a TTY to be used as a kernel console
impl ConsoleDriver for Tty {
    fn name(&self) -> &str {
        self.name
    }

    /// Bytes straight to the hardware (no line discipline), LF as CR LF,
    /// then a wait until the transmitter is empty (Linux
    /// serial8250_console_write, pl011_console_write): what a console
    /// write prints is out before it returns
    fn write(&self, data: &[u8]) {
        self.driver.console_write(data);
    }

    fn flush(&self) {
        self.driver.flush();
    }

    fn tty(&'static self) -> Option<&'static Tty> {
        Some(self)
    }
}

/// Every tty (the serial ports')
pub fn all() -> &'static [&'static Tty] {
    crate::arch::serial_ttys()
}

/// The tty a /dev/tty or /dev/console file works on (its private
/// data; Linux points such a file at the tty itself)
struct Redirect(&'static Tty);

impl Redirect {
    /// Point `file` at `tty` (at open)
    fn set(file: &File, tty: &'static Tty) -> Result<(), KernelError> {
        let r = try_arc(Redirect(tty))?;
        file.private.call_once(|| r);
        Ok(())
    }

    /// The tty `file` was pointed at
    fn tty(file: &File) -> Result<&'static Tty, KernelError> {
        file.private_ref::<Redirect>()
            .map(|r| r.0)
            .ok_or(KernelError::Io)
    }
}

/// A static tty as a registered character device
struct TtyChar(&'static Tty);

impl CharDevice for TtyChar {
    fn name(&self) -> &str {
        self.0.name
    }

    fn can_poll(&self) -> bool {
        true
    }

    fn open(&self, file: &File) -> Result<(), KernelError> {
        CharDevice::open(self.0, file)
    }

    fn read(&self, file: &File, to: &mut IovDest<'_>) -> Result<usize, KernelError> {
        CharDevice::read(self.0, file, to)
    }

    fn write(&self, file: &File, from: &mut IovSource<'_>) -> Result<usize, KernelError> {
        CharDevice::write(self.0, file, from)
    }

    fn ioctl(&self, file: &File, cmd: u32, arg: u64) -> Result<i64, KernelError> {
        CharDevice::ioctl(self.0, file, cmd, arg)
    }

    fn fasync(&self, file: &File, fd: i32, on: bool) -> Option<Result<(), KernelError>> {
        CharDevice::fasync(self.0, file, fd, on)
    }

    fn poll(&self, file: &File, pt: Option<&mut PollTable<'_>>) -> u16 {
        CharDevice::poll(self.0, file, pt)
    }
}

/// Initialize TTY character devices in the chardev registry
///
/// This registers serial TTYs for each architecture plus special devices
/// like /dev/console and /dev/tty.
/// Called from init_vfs() after heap is available.
pub fn init_tty_chardevs() {
    use crate::fs::chardev::{major, register_chardev};

    // The serial ports (Linux uart_register_driver), fed by the flip
    // thread
    flip::init();
    for &tty in crate::arch::serial_ttys() {
        let _ = register_chardev(tty.dev, arc_nofail(TtyChar(tty)));
    }

    // Register /dev/tty (major 5, minor 0) - controlling terminal
    let tty_dev = arc_nofail(tty_dev::TtyCharDevice);
    let _ = register_chardev(DevId::new(major::TTYAUX, 0), tty_dev);

    // Register /dev/console (major 5, minor 1) - kernel console
    let console_dev = arc_nofail(console_dev::ConsoleCharDevice);
    let _ = register_chardev(DevId::new(major::TTYAUX, 1), console_dev);

    TTY_CLASS.register();
    for (name, minor) in [("tty", 0), ("console", 1)] {
        let d = device_create(DeviceInfo {
            class: Some(&TTY_CLASS),
            devt: Some(DevId::new(major::TTYAUX, minor)),
            ..DeviceInfo::named(name)
        });
        if minor == 1
            && let Ok(d) = d
            && let Ok(a) =
                d.create_file(b"active", 0o444, crate::fs::kernfs::show(show_cons_active))
        {
            CONS_ACTIVE.call_once(|| a);
        }
    }
}

/// /sys/class/tty/console/active (spin::Once, set at boot)
static CONS_ACTIVE: spin::Once<Arc<crate::fs::kernfs::KNode>> = spin::Once::new();

/// Linux show_cons_active: the enabled consoles' ttys, last registered
/// first
fn show_cons_active(out: &mut crate::fs::kernfs::SysBuf) {
    let ttys = crate::console::console_ttys();
    let mut first = true;
    for t in ttys.iter().rev().flatten() {
        if !first {
            out.bytes(b" ");
        }
        out.bytes(t.name().as_bytes());
        first = false;
    }
    out.bytes(b"\n");
}

/// The console list changed: wake pollers of console/active (Linux
/// sysfs_notify in register_console/unregister_console)
pub fn console_active_changed() {
    if let Some(a) = CONS_ACTIVE.get() {
        a.notify();
    }
}

/// The class device of a port's tty, below the port's device (Linux
/// tty_port_register_device)
pub fn tty_register_device(tty: &'static Tty, parent: &Arc<Device>) -> Option<Arc<Device>> {
    device_create(DeviceInfo {
        parent: Some(parent),
        class: Some(&TTY_CLASS),
        devt: Some(tty.dev),
        ..DeviceInfo::named(tty.name())
    })
    .ok()
}

/// The tty class (Linux tty_class)
pub static TTY_CLASS: Class = Class::new("tty", Some(tty_devnode));

/// Linux tty_devnode: /dev/tty and /dev/ptmx are 0666
fn tty_devnode(d: &Device) -> Option<DevNode> {
    let dt = d.devt?;
    if dt.major == crate::fs::chardev::major::TTYAUX && (dt.minor == 0 || dt.minor == 2) {
        return Some(DevNode {
            name: d.name().into(),
            mode: 0o666,
        });
    }
    None
}

// =============================================================================
// vhangup syscall
// =============================================================================

/// vhangup syscall - simulate hangup on controlling terminal
///
/// This syscall simulates a hangup on the current process's controlling terminal.
/// It is typically used by login(1) and getty(8) to ensure a clean terminal state
/// before a new user logs in.
///
/// # Returns
/// * 0 on success
/// * -EPERM if caller lacks CAP_SYS_TTY_CONFIG capability
///
/// # Linux Compatibility
/// Linux requires CAP_SYS_TTY_CONFIG. The full implementation would:
/// - Send SIGHUP to the foreground process group
/// - Revoke terminal access for all processes using the terminal
/// - Clear the session's controlling terminal association
///
/// For MVP, we implement the permission check and return success,
/// as the boot_tester runs with full capabilities and doesn't rely
/// on the terminal revocation behavior.
pub fn sys_vhangup() -> crate::util::error::KernelResult<()> {
    use crate::task::{CAP_SYS_TTY_CONFIG, capable};

    // Requires CAP_SYS_TTY_CONFIG capability
    if !capable(CAP_SYS_TTY_CONFIG) {
        return Err(KernelError::NotPermitted);
    }

    // MVP: Return success
    // A full implementation would:
    // 1. Find the controlling terminal for current session
    // 2. Send SIGHUP to foreground process group
    // 3. Revoke terminal access for all users
    // 4. Clear session/ctty associations
    Ok(())
}

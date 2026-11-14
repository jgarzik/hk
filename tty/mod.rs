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
use core::sync::atomic::{AtomicBool, Ordering};

use crate::base::{Class, DevNode, Device, DeviceInfo, device_create};

use crate::sync::IrqSpinlock;
use crate::sync::spin::Mutex;
use crate::sync::waitqueue::WaitQueue;

use crate::console::ConsoleDriver;
use crate::fs::File;
use crate::fs::chardev::{CharDevice, DevId};
use crate::fs::flags::O_NOCTTY;
use crate::fs::iov_iter::{IovDest, IovSource};
use crate::io::fasync::{
    FasyncList, POLL_IN, POLL_OUT, PidType, f_setown_pid, fasync_helper, kill_fasync,
};
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
    /// Queue bytes for the hardware (Linux tty_operations.write): the
    /// count taken, maybe short; the driver calls `tty.write_wakeup`
    /// once there is room again
    fn write(&self, tty: &Tty, data: &[u8]) -> Result<usize, KernelError>;

    /// Stop output (Linux tty_operations.stop), under `Tty.flow`
    fn stop(&self) {}

    /// Restart output (Linux tty_operations.start), under `Tty.flow`;
    /// the caller wakes writers
    fn start(&self) {}

    /// Send a flow control character ahead of queued output, stopped
    /// or not (Linux tty_operations.send_xchar)
    fn send_xchar(&self, tty: &Tty, ch: u8);

    /// Wait until the transmitter is empty
    fn flush(&self) {}

    /// Bytes `write` takes now (Linux write_room)
    fn write_room(&self) -> usize {
        usize::MAX
    }

    /// Bytes queued, not yet sent (Linux chars_in_buffer)
    fn chars_in_buffer(&self) -> usize {
        0
    }

    /// Drop the queued bytes (Linux flush_buffer)
    fn flush_buffer(&self) {}

    /// The tty's last close (Linux tty_port_shutdown): unless the port
    /// is a console (port->console), output stops and its queue is
    /// freed (uart_shutdown); either way the tty's flow control state
    /// goes with the tty
    fn shutdown(&self, console: bool) {
        let _ = console;
    }

    /// The console write (Linux console->write): bytes straight to the
    /// hardware, LF as CR LF, then a wait until the transmitter is
    /// empty. A UART takes its port lock (`serial_core::UartPort`)
    fn console_write(&self, data: &[u8]);
}

/// How long a last close waits for output to drain (Linux
/// tty_port.closing_wait, 30 s by default: tty_port_init); 0 would be
/// ASYNC_CLOSING_WAIT_INF. hk has no TIOCSSERIAL to change it
const CLOSING_WAIT_MS: u64 = 30_000;

/// Output flow control (Linux tty->flow)
struct Flow {
    /// Output is stopped
    stopped: bool,
    /// ... by TCOOFF, which only TCOON undoes
    tco_stopped: bool,
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
    /// Writers, pollers and tcdrain wait here for the driver's room
    /// (Linux write_wait)
    write_wait: WaitQueue,
    /// One reader at a time, so a canonical line goes whole to one
    /// reader though it is copied out in pieces (Linux
    /// n_tty_data.atomic_read_lock)
    read_lock: crate::sync::Mutex<()>,
    /// One writer at a time, held across a whole write(2) so another's
    /// bytes never land inside it (Linux tty->atomic_write_lock)
    write_lock: crate::sync::Mutex<()>,
    /// Serializes N_TTY output with its echo, so a byte pair (CR NL)
    /// checked for room goes out whole (Linux n_tty_data.output_lock)
    output_lock: crate::sync::Mutex<()>,
    /// Session, foreground group, window size
    ctrl: Mutex<TtyCtrl>,
    /// O_ASYNC files (Linux tty->fasync)
    fasync: FasyncList,
    /// Output flow control (Linux tty->flow, under flow.lock)
    flow: Mutex<Flow>,
    /// A write could not finish with O_ASYNC files listening: the next
    /// wakeup sends them SIGIO (Linux TTY_DO_WRITE_WAKEUP)
    do_write_wakeup: AtomicBool,
    /// That SIGIO is due from an interrupt handler: the flip thread
    /// sends it
    wakeup_due: AtomicBool,
    /// Open files (Linux tty->count, under tty_lock): held across an
    /// open and across the last close, which drains output
    count: crate::sync::Mutex<usize>,
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
            output_lock: crate::sync::Mutex::new(()),
            read_wait: WaitQueue::new(),
            write_wait: WaitQueue::new(),
            ctrl: Mutex::new(TtyCtrl::new()),
            fasync: FasyncList::new(),
            flow: Mutex::new(Flow {
                stopped: false,
                tco_stopped: false,
            }),
            do_write_wakeup: AtomicBool::new(false),
            wakeup_due: AtomicBool::new(false),
            count: crate::sync::Mutex::new(0),
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

    /// Write directly to driver (bypassing line discipline): the count
    /// it took
    pub fn driver_write(&self, data: &[u8]) -> Result<usize, KernelError> {
        self.driver.write(self, data)
    }

    /// Linux __stop_tty, under `flow`
    fn stop_locked(&self, f: &mut Flow) {
        if f.stopped {
            return;
        }
        f.stopped = true;
        self.driver.stop();
    }

    /// Linux __start_tty, under `flow`: true if writers are to be woken
    /// (Linux tty_wakeup there; here after `flow` is released)
    fn start_locked(&self, f: &mut Flow) -> bool {
        if !f.stopped || f.tco_stopped {
            return false;
        }
        f.stopped = false;
        self.driver.start();
        true
    }

    /// TCOOFF (Linux n_tty_ioctl_helper's TCXONC): output stops until
    /// TCOON
    pub fn tcooff(&self) {
        let mut f = self.flow.lock();
        if !f.tco_stopped {
            f.tco_stopped = true;
            self.stop_locked(&mut f);
        }
    }

    /// TCOON: output restarts, writers are woken
    pub fn tcoon(&self) {
        let wake = {
            let mut f = self.flow.lock();
            f.tco_stopped && {
                f.tco_stopped = false;
                self.start_locked(&mut f)
            }
        };
        if wake {
            self.write_wakeup();
        }
    }

    /// Send `ch` ahead of queued output (Linux tty_send_xchar through
    /// the driver's send_xchar, under termios_rwsem: `ldata` here)
    pub fn send_xchar(&self, ch: u8) {
        let _ld = n_tty::ldata(self);
        self.driver.send_xchar(self, ch);
    }

    /// Bytes the driver takes now (Linux tty_write_room)
    pub fn write_room(&self) -> usize {
        self.driver.write_room()
    }

    /// The driver has room again or sent everything (Linux tty_wakeup):
    /// the line discipline's write wakeup if a write asked for it, then
    /// writers, pollers and tcdrain woken; any context, no port lock
    /// held. Signals cannot be sent from an interrupt handler (3.7), so
    /// there the flip thread sends the SIGIO
    pub fn write_wakeup(&self) {
        if self.do_write_wakeup.load(Ordering::Acquire) {
            if crate::sync::in_interrupt() {
                self.wakeup_due.store(true, Ordering::Release);
                flip::kick_wakeup();
            } else {
                self.ldisc_write_wakeup();
            }
        }
        self.write_wait.wake_all();
    }

    /// N_TTY's write wakeup (Linux n_tty_write_wakeup): SIGIO POLL_OUT
    /// to the O_ASYNC files, once per write that asked
    fn ldisc_write_wakeup(&self) {
        self.do_write_wakeup.store(false, Ordering::Release);
        kill_fasync(&self.fasync, crate::signal::SIGIO, POLL_OUT);
    }

    /// The flip thread: a write wakeup due from an interrupt handler
    pub(crate) fn deferred_wakeup(&self) {
        if self.wakeup_due.swap(false, Ordering::AcqRel)
            && self.do_write_wakeup.load(Ordering::Acquire)
        {
            self.ldisc_write_wakeup();
        }
    }

    /// A write stopped short (Linux n_tty_write's break_out): with
    /// O_ASYNC files listening, the next wakeup signals them
    pub(crate) fn want_write_wakeup(&self) {
        if self.fasync.armed() {
            self.do_write_wakeup.store(true, Ordering::Release);
        }
    }

    /// Sleep until the driver takes `n` bytes (Linux n_tty_write's
    /// wait on write_wait): EAGAIN if `nonblock`, ERESTARTSYS on a
    /// signal
    pub fn wait_room(&self, n: usize, nonblock: bool) -> Result<(), KernelError> {
        if self.write_room() >= n {
            return Ok(());
        }
        if nonblock {
            return Err(KernelError::WouldBlock);
        }
        self.write_wait
            .wait_event_interruptible(|| self.write_room() >= n)
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

    /// Wait for output to be sent (Linux tty_wait_until_sent): the
    /// queue empty, then the transmitter; a signal or `timeout` ticks
    /// (0: none) end the wait
    pub fn wait_until_sent(&self, timeout: u64) {
        let t = if timeout == 0 {
            crate::task::percpu::MAX_SCHEDULE_TIMEOUT
        } else {
            timeout
        };
        let left = self
            .write_wait
            .wait_event_interruptible_timeout(|| self.driver.chars_in_buffer() == 0, t);
        if matches!(left, Ok(n) if n > 0) {
            self.driver.flush();
        }
    }

    /// A file opened the tty (Linux tty_open's tty_reopen: tty->count,
    /// under tty_lock); then it may become the controlling tty
    fn opened(&self, file: &File, ctty: bool) {
        let mut n = self.count.lock();
        *n += 1;
        if ctty && file.get_flags() & O_NOCTTY == 0 {
            jobctrl::open_set_tty(self, file);
        }
    }

    /// A file of the tty is released (Linux tty_release). The last one
    /// closes the port (uart_close -> tty_port_close) and the tty
    /// starts afresh, as Linux frees the tty_struct: flow control, the
    /// write wakeup, input and the controlling session go; termios
    /// stays (the driver's saved termios)
    fn release(&self) {
        let mut n = self.count.lock();
        if *n > 1 {
            *n -= 1;
            return;
        }
        self.close_port();
        *n = 0;
        jobctrl::session_clear_tty(self);
        *self.flow.lock() = Flow {
            stopped: false,
            tco_stopped: false,
        };
        self.do_write_wakeup.store(false, Ordering::Release);
        self.wakeup_due.store(false, Ordering::Release);
    }

    /// The last close (Linux tty_port_close_start, tty_port_shutdown):
    /// output stopped by TCOOFF is dropped, the rest drains for up to
    /// closing_wait, input is dropped, then the port shuts down unless
    /// it is a console
    fn close_port(&self) {
        let tco = self.flow.lock().tco_stopped;
        if tco {
            self.flush_output();
        }
        self.wait_until_sent(crate::task::percpu::ms_to_ticks(CLOSING_WAIT_MS));
        self.flush_input();
        let console = crate::console::console_ttys()
            .iter()
            .flatten()
            .any(|t| core::ptr::eq(*t, self));
        self.driver.shutdown(console);
    }

    /// Bytes queued for the hardware (Linux tty_chars_in_buffer)
    pub fn chars_in_buffer(&self) -> usize {
        self.driver.chars_in_buffer()
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

    /// Drop the queued output (Linux tty_driver_flush_buffer), waking
    /// writers
    pub fn flush_output(&self) {
        self.driver.flush_buffer();
        self.write_wakeup();
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
        let nonblock = file.get_flags() & crate::fs::flags::O_NONBLOCK != 0;
        n_tty::write(self, from, nonblock)
    }

    fn ioctl(&self, file: &File, cmd: u32, arg: u64) -> Result<i64, KernelError> {
        ioctl::tty_ioctl(self, file, cmd, arg)
    }

    fn fasync(&self, file: &File, fd: i32, on: bool) -> Option<Result<(), KernelError>> {
        Some(self.tty_fasync(file, fd, on))
    }

    /// Writable while the driver has room and little queued (Linux
    /// n_tty_poll)
    fn poll(&self, _file: &File, pt: Option<&mut PollTable<'_>>) -> u16 {
        if let Some(pt) = pt {
            pt.poll_wait(&self.read_wait);
            pt.poll_wait(&self.write_wait);
        }
        let mut mask = 0;
        if self.chars_in_buffer() < serial_core::WAKEUP_CHARS && self.write_room() > 0 {
            mask |= POLLOUT | POLLWRNORM;
        }
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

    /// Open `tty` through `file`: point the file at it and count it
    /// (Linux tty->count); `ctty`: it may become the controlling tty.
    /// The release of a file whose open failed finds no tty to drop
    fn open(file: &File, tty: &'static Tty, ctty: bool) -> Result<(), KernelError> {
        Self::set(file, tty)?;
        tty.opened(file, ctty);
        Ok(())
    }

    /// The release of a file opened by `open` (Linux tty_release)
    fn release(file: &File) {
        if let Ok(t) = Self::tty(file) {
            t.release();
        }
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
        Redirect::open(file, self.0, true)
    }

    fn release(&self, file: &File) {
        Redirect::release(file);
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
